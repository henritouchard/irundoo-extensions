// Package web sert l'écran de la centralisatrice (rendu serveur, htmx embarqué, aucune ressource
// externe), le flot OIDC utilisateur et la santé.
//
// Le périmètre est celui du serveur : chaque rendu part de deux appels faits avec le jeton de
// l'utilisateur (`/instances`, source unique des lignes, puis `/hardware`). L'extension ne filtre
// jamais et n'ajoute jamais une ligne venue de sa base locale ; SQLite n'enrichit qu'une ligne rendue.
package web

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/henritouchard/irundoo-extensions/extensions/centralisation-materiel/internal/etat"
	"github.com/henritouchard/irundoo-extensions/extensions/centralisation-materiel/internal/irundoo"
	"github.com/henritouchard/irundoo-extensions/extensions/centralisation-materiel/internal/oidc"
	"github.com/henritouchard/irundoo-extensions/extensions/centralisation-materiel/internal/store"
)

//go:embed templates/*.html
var templatesFS embed.FS

//go:embed static
var staticFS embed.FS

// Cookies. En https, le cookie de session prend le préfixe `__Host-` (Secure, Path=/, sans Domain :
// aucun sous-domaine ne peut le poser) et les cookies de tentative `__Secure-`.
const (
	CookieSession          = "cm_session"
	CookieTentativePrefixe = "cm_t_"
)

// DelaiRequete : délai d'un rendu (deux appels d'API de 15 s au plus, ou Discovery + jeton + JWKS
// au retour d'autorisation). WriteTimeout du serveur HTTP doit le dépasser.
const DelaiRequete = 40 * time.Second

// FenetreRenouvellement : un 401 de l'API sur une session plus jeune que ce délai est un second
// échec consécutif (ré-autorisation qui vient de réussir) : page d'erreur, jamais de boucle.
const FenetreRenouvellement = 60 * time.Second

// API : les lectures (irundoo.Client).
type API interface {
	Instances(ctx context.Context, token string) (*irundoo.Instances, error)
	Hardware(ctx context.Context, token, instance string) (*irundoo.Hardware, error)
}

// Server : dépendances de l'écran.
type Server struct {
	OIDC          *oidc.Client
	API           API
	Store         *store.Store
	Log           *slog.Logger
	StaleAfter    time.Duration
	RetentionDays int
	SecureCookies bool
	// PublicURL : origine admise pour les POST (en-tête Origin) ; vide ⇒ non vérifiée.
	PublicURL string
	Version   string
	Now       func() time.Time
	// TentativesParMinute / TentativesRafale : limite de débit des tentatives de connexion par
	// adresse (0 ⇒ 10 par minute, rafale de 20).
	TentativesParMinute, TentativesRafale int

	tmpl    *template.Template
	limiteM sync.Mutex
	seaux   map[string]*seau
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Handler : toutes les routes, derrière les en-têtes de sécurité.
func (s *Server) Handler() http.Handler {
	s.tmpl = template.Must(template.New("").Funcs(template.FuncMap{
		"libelle": libelle,
		"depuis":  func(t time.Time) string { return depuis(s.now(), t) },
		"iso":     func(t time.Time) string { return t.UTC().Format(time.RFC3339) },
		"deref": func(p *string) string {
			if p == nil {
				return "—"
			}
			return *p
		},
	}).ParseFS(templatesFS, "templates/*.html"))
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.health) // GET couvre HEAD
	mux.HandleFunc("GET /{$}", s.page)
	mux.HandleFunc("GET /partials/liste", s.partial)
	mux.HandleFunc("GET /etablissements/{id}", s.detail)
	mux.HandleFunc("GET /oidc/login", s.login)
	mux.HandleFunc("GET /oidc/callback", s.callback)
	mux.HandleFunc("POST /logout", s.logout)
	static, _ := fs.Sub(staticFS, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))
	return s.securite(mux)
}

func (s *Server) securite(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		hd.Set("X-Frame-Options", "DENY")
		hd.Set("Referrer-Policy", "no-referrer")
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("Cache-Control", "no-store")
		if s.SecureCookies {
			hd.Set("Strict-Transport-Security", "max-age=31536000")
		}
		ctx, cancel := context.WithTimeout(r.Context(), DelaiRequete)
		defer cancel()
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

// ---- santé (C.5) ----

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 800*time.Millisecond)
	defer cancel()
	w.Header().Set("Content-Type", "application/json")
	body := map[string]string{"version": s.Version}
	status := http.StatusOK
	if err := s.Store.Healthy(ctx); err != nil {
		status = http.StatusServiceUnavailable
		body["error"] = "store"
		s.Log.Error("santé : magasin local indisponible", "err", err)
	}
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		_ = json.NewEncoder(w).Encode(body)
	}
}

// ---- session et flot OIDC ----

func (s *Server) cookie(name, value, path string, maxAge int) *http.Cookie {
	return &http.Cookie{Name: name, Value: value, Path: path, MaxAge: maxAge, HttpOnly: true,
		Secure: s.SecureCookies, SameSite: http.SameSiteLaxMode}
}

// nomSession : `__Host-cm_session` en https, `cm_session` en développement http.
func (s *Server) nomSession() string {
	if s.SecureCookies {
		return "__Host-" + CookieSession
	}
	return CookieSession
}

// nomTentative : un cookie par tentative, nommé d'après son `state` (deux onglets qui se
// renouvellent en même temps ne s'écrasent pas). Le nom ne révèle pas le state.
func (s *Server) nomTentative(state string) string {
	h := sha256.Sum256([]byte(state))
	n := CookieTentativePrefixe + hex.EncodeToString(h[:8])
	if s.SecureCookies {
		return "__Secure-" + n
	}
	return n
}

// csrf : jeton anti-CSRF de la session (dérivé de son identifiant, que seul le cookie HttpOnly
// porte : un site tiers ne peut pas le calculer).
func csrf(sessionID string) string {
	h := sha256.Sum256([]byte("centralisation-materiel/csrf\x00" + sessionID))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func (s *Server) session(r *http.Request) *store.Session {
	c, err := r.Cookie(s.nomSession())
	if err != nil || c.Value == "" {
		return nil
	}
	se, err := s.Store.GetSession(r.Context(), c.Value)
	if err != nil {
		s.Log.Error("lecture de session", "err", err)
		return nil
	}
	return se
}

func htmx(r *http.Request) bool { return r.Header.Get("HX-Request") == "true" }

// authentifier : sans session, ou jeton échu, relance l'autorisation (prompt=none si renouvellement).
func (s *Server) authentifier(w http.ResponseWriter, r *http.Request, renouvellement bool) {
	if htmx(r) {
		target := "/oidc/login"
		if renouvellement {
			target += "?silent=1"
		}
		w.Header().Set("HX-Redirect", target)
		w.WriteHeader(http.StatusOK)
		return
	}
	s.demarrer(w, r, renouvellement, false)
}

func (s *Server) demarrer(w http.ResponseWriter, r *http.Request, promptNone, relance bool) {
	if !s.autoriserTentative(clientIP(r)) {
		w.Header().Set("Retry-After", "60")
		s.erreur(w, http.StatusTooManyRequests, "Trop de tentatives de connexion", "Trop de tentatives de connexion depuis cette adresse : réessayez dans une minute.")
		return
	}
	t := oidc.NouvelleTentative(promptNone)
	id := oidc.Random()
	if err := s.Store.CreateAttempt(r.Context(), store.Attempt{ID: id, State: t.State, Nonce: t.Nonce, Verifier: t.Verifier, PromptNone: promptNone, Relance: relance}); err != nil {
		if errors.Is(err, store.ErrTropDeTentatives) {
			s.Log.Warn("plafond des tentatives de connexion en vol atteint")
			w.Header().Set("Retry-After", "60")
			s.erreur(w, http.StatusServiceUnavailable, "Trop de connexions en cours", "Trop de tentatives de connexion sont en cours : réessayez dans quelques minutes.")
			return
		}
		s.erreur(w, http.StatusInternalServerError, "Magasin local indisponible", "La tentative de connexion n'a pas pu être enregistrée.")
		return
	}
	u, err := s.OIDC.AuthURL(r.Context(), t)
	if err != nil {
		s.Log.Error("discovery d'IRUNDO", "err", err)
		s.erreur(w, http.StatusBadGateway, "IRUNDO injoignable", "La configuration OpenID d'IRUNDO n'a pas pu être lue.")
		return
	}
	http.SetCookie(w, s.cookie(s.nomTentative(t.State), id, "/oidc/", int(store.AttemptTTL.Seconds())))
	http.Redirect(w, r, u, http.StatusFound)
}

// ---- limite de débit des tentatives (sans authentification) ----

type seau struct {
	jetons float64
	vu     time.Time
}

// autoriserTentative : seau à jetons par adresse, en mémoire.
func (s *Server) autoriserTentative(ip string) bool {
	parMin, rafale := s.TentativesParMinute, s.TentativesRafale
	if parMin <= 0 {
		parMin = 10
	}
	if rafale <= 0 {
		rafale = 20
	}
	now := s.now()
	s.limiteM.Lock()
	defer s.limiteM.Unlock()
	if s.seaux == nil {
		s.seaux = map[string]*seau{}
	}
	if len(s.seaux) > 10000 { // borne la mémoire : on oublie les adresses dont le seau est plein
		for k, b := range s.seaux {
			if now.Sub(b.vu) > time.Duration(rafale)*time.Minute/time.Duration(parMin) {
				delete(s.seaux, k)
			}
		}
	}
	b, ok := s.seaux[ip]
	if !ok {
		b = &seau{jetons: float64(rafale), vu: now}
		s.seaux[ip] = b
	}
	b.jetons = min(float64(rafale), b.jetons+now.Sub(b.vu).Minutes()*float64(parMin))
	b.vu = now
	if b.jetons < 1 {
		return false
	}
	b.jetons--
	return true
}

// clientIP : l'adresse du pair ; derrière un proxy local (pair en loopback), la dernière adresse
// de X-Forwarded-For, celle que le proxy a vue (il l'ajoute en fin de liste). Ne sert qu'à la
// limite de débit, jamais à une décision d'autorisation.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		if xff := r.Header.Values("X-Forwarded-For"); len(xff) > 0 {
			parts := strings.Split(xff[len(xff)-1], ",")
			if fwd := net.ParseIP(strings.TrimSpace(parts[len(parts)-1])); fwd != nil {
				return fwd.String()
			}
		}
	}
	return host
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	s.demarrer(w, r, r.URL.Query().Get("silent") == "1", false)
}

func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	nom := s.nomTentative(r.URL.Query().Get("state"))
	c, err := r.Cookie(nom)
	if err == nil {
		http.SetCookie(w, s.cookie(nom, "", "/oidc/", -1))
	}
	var a *store.Attempt
	if err == nil {
		a, err = s.Store.TakeAttempt(r.Context(), c.Value)
	}
	if err != nil || a == nil {
		s.erreur(w, http.StatusBadRequest, "Tentative de connexion inconnue ou expirée", "Rouvrez l'application depuis IRUNDO.")
		return
	}
	t := oidc.Tentative{State: a.State, Nonce: a.Nonce, Verifier: a.Verifier, PromptNone: a.PromptNone}
	code, err := s.OIDC.CheckCallback(r.URL.Query(), t)
	var ea *oidc.ErrAuthorize
	switch {
	case errors.As(err, &ea) && ea.Code == "login_required" && a.PromptNone && !a.Relance:
		// Session IRUNDO fermée : une seule relance, sans prompt (page de connexion d'IRUNDO).
		s.demarrer(w, r, false, true)
		return
	case errors.As(err, &ea) && ea.Code == "access_denied":
		s.erreur(w, http.StatusForbidden, "Accès refusé", "Votre statut n'a pas accès à cette application (Visibilité de la tuile dans IRUNDO).")
		return
	case errors.As(err, &ea):
		s.erreur(w, http.StatusBadRequest, "Connexion impossible", "IRUNDO a refusé la demande de connexion : "+ea.Code+".")
		return
	case err != nil:
		s.Log.Warn("retour d'autorisation refusé", "err", err)
		s.erreur(w, http.StatusBadRequest, "Connexion impossible", "Le retour de connexion n'a pas pu être vérifié.")
		return
	}
	ut, err := s.OIDC.Exchange(r.Context(), code, t)
	var sng *oidc.ErrScopeNotGranted
	if errors.As(err, &sng) {
		s.erreur(w, http.StatusForbidden, "Droit non accordé", "Droit non accordé par l'administrateur : "+strings.Join(sng.Missing, ", ")+".")
		return
	}
	if err != nil {
		s.Log.Warn("échange du code refusé", "err", err)
		s.erreur(w, http.StatusBadGateway, "Connexion impossible", "L'échange du code de connexion a échoué. Rouvrez l'application depuis IRUNDO.")
		return
	}
	se := store.Session{ID: oidc.Random(), Sub: ut.Sub, Name: ut.Name, Roles: ut.Roles, AccessToken: ut.AccessToken, TokenExp: ut.Expiry, Scope: ut.Scope}
	if err := s.Store.CreateSession(r.Context(), se); err != nil {
		s.erreur(w, http.StatusInternalServerError, "Magasin local indisponible", "La session n'a pas pu être enregistrée.")
		return
	}
	// La session remplacée (renouvellement) n'est effacée qu'ici, une fois la nouvelle ouverte :
	// un autre onglet qui la porte encore n'est pas déconnecté pendant le renouvellement.
	if old, err := r.Cookie(s.nomSession()); err == nil && old.Value != "" {
		_ = s.Store.DeleteSession(r.Context(), old.Value)
	}
	s.Log.Info("session ouverte", "sub", ut.Sub)
	http.SetCookie(w, s.cookie(s.nomSession(), se.ID, "/", 0))
	http.Redirect(w, r, "/", http.StatusFound)
}

// logout : POST seulement, avec le jeton anti-CSRF de la session et, si le navigateur l'envoie, une
// origine égale à PUBLIC_URL.
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if o := r.Header.Get("Origin"); o != "" && s.PublicURL != "" && o != s.PublicURL {
		s.erreur(w, http.StatusForbidden, "Requête refusée", "Origine de la demande de déconnexion non reconnue.")
		return
	}
	c, err := r.Cookie(s.nomSession())
	if err == nil && c.Value != "" {
		if subtle.ConstantTimeCompare([]byte(r.PostFormValue("csrf")), []byte(csrf(c.Value))) != 1 {
			s.erreur(w, http.StatusForbidden, "Requête refusée", "Jeton de formulaire invalide : rechargez la page puis réessayez.")
			return
		}
		_ = s.Store.DeleteSession(r.Context(), c.Value)
	}
	http.SetCookie(w, s.cookie(s.nomSession(), "", "/", -1))
	s.render(w, http.StatusOK, "message", map[string]any{"Titre": "Déconnecté",
		"Texte": "La session de cette application est fermée. Votre session IRUNDO reste ouverte : fermez-la dans IRUNDO.", "Lien": "/"})
}

// ---- écran ----

// Ligne : un établissement rendu.
type Ligne struct {
	Instance irundoo.Instance
	Mesure   *irundoo.Measure
	Res      etat.Resultat
	Resume   []etat.Signal
}

// Vue : données de la page et du fragment de liste.
type Vue struct {
	Nom      string
	CSRF     string
	Lignes   []Ligne
	Reduced  bool
	Releve   *store.ReleveState
	Stale    time.Duration
	Compteur map[string]int
}

// sessionValide : session présente et jeton non échu ; sinon relance l'autorisation et rend nil.
func (s *Server) sessionValide(w http.ResponseWriter, r *http.Request) *store.Session {
	se := s.session(r)
	if se == nil {
		s.authentifier(w, r, false)
		return nil
	}
	// Une session qui vient d'être ouverte n'est jamais renouvelée aussitôt (un expires_in plus court
	// que la marge ne doit pas faire boucler) : si le jeton est vraiment échu, l'API répond 401 et
	// refusAPI affiche l'erreur. La session échue n'est pas effacée ici : le retour d'autorisation
	// la remplace (un autre onglet qui la porte n'est pas déconnecté entre-temps).
	if s.now().Sub(se.CreatedAt) >= FenetreRenouvellement && !s.now().Before(se.TokenExp.Add(-oidc.Marge)) {
		s.authentifier(w, r, true)
		return nil
	}
	return se
}

// refusAPI rend la page (ou le fragment) d'un refus de l'API. 401 : un renouvellement, sauf si la
// session vient d'être ouverte (second échec consécutif : erreur, jamais de boucle).
func (s *Server) refusAPI(w http.ResponseWriter, r *http.Request, se *store.Session, err error) {
	var sc *irundoo.ErrInsufficientScope
	var rl *irundoo.ErrRateLimited
	switch {
	case errors.Is(err, irundoo.ErrInvalidToken):
		if s.now().Sub(se.CreatedAt) < FenetreRenouvellement {
			s.erreur(w, http.StatusBadGateway, "Jeton refusé", "IRUNDO refuse le jeton qu'il vient de délivrer. Réessayez plus tard ; si cela persiste, l'application est peut-être révoquée.")
			return
		}
		s.authentifier(w, r, true)
	case errors.As(err, &sc):
		s.erreur(w, http.StatusForbidden, "Droit non accordé", "Droit non accordé par l'administrateur : "+sc.Scope+".")
	case errors.Is(err, irundoo.ErrPerimeterEmpty):
		s.render(w, http.StatusOK, "message", map[string]any{"Titre": "Aucun établissement accordé",
			"Texte": "L'administrateur d'IRUNDO n'a accordé aucun établissement à cette application (périmètre vide).", "Nom": se.Name})
	case errors.Is(err, irundoo.ErrUnavailable):
		s.erreur(w, http.StatusServiceUnavailable, "IRUNDO indisponible", "IRUNDO ne peut pas vérifier les jetons pour le moment. Réessayez plus tard.")
	case errors.As(err, &rl):
		w.Header().Set("Retry-After", fmt.Sprint(int(rl.RetryAfter.Seconds())))
		s.erreur(w, http.StatusTooManyRequests, "Trop de demandes", fmt.Sprintf("Quota de l'application atteint : réessayer dans %d s.", int(rl.RetryAfter.Seconds())))
	default:
		s.Log.Error("appel de l'API d'IRUNDO", "err", err)
		s.erreur(w, http.StatusBadGateway, "IRUNDO injoignable", "L'API d'IRUNDO n'a pas répondu comme prévu.")
	}
}

func (s *Server) vue(ctx context.Context, se *store.Session) (*Vue, error) {
	ins, err := s.API.Instances(ctx, se.AccessToken)
	if err != nil {
		return nil, err
	}
	hw, err := s.API.Hardware(ctx, se.AccessToken, "")
	if err != nil {
		return nil, err
	}
	derniere := map[string]*irundoo.Measure{}
	for i := range hw.Hardware {
		m := &hw.Hardware[i]
		if d, ok := derniere[m.InstanceID]; !ok || etat.PlusRecente(mesure(m), mesure(d)) {
			derniere[m.InstanceID] = m
		}
	}
	now := s.now()
	v := &Vue{Nom: se.Name, CSRF: csrf(se.ID), Reduced: ins.Reduced || hw.Reduced, Stale: s.StaleAfter, Compteur: map[string]int{}}
	// Source unique des lignes : /instances de ce rendu. Une mesure d'un id absent est ignorée.
	for _, in := range ins.Instances {
		l := Ligne{Instance: in, Mesure: derniere[in.Id]}
		var em *etat.Mesure
		if l.Mesure != nil {
			m := mesure(l.Mesure)
			em = &m
		}
		l.Res = etat.Compute(now, em, s.StaleAfter)
		l.Resume = l.Res.Signaux[:min(3, len(l.Res.Signaux))]
		v.Compteur[string(l.Res.Etat)]++
		v.Lignes = append(v.Lignes, l)
	}
	sort.SliceStable(v.Lignes, func(i, j int) bool {
		a, b := v.Lignes[i], v.Lignes[j]
		if a.Res.Etat.Rang() != b.Res.Etat.Rang() {
			return a.Res.Etat.Rang() < b.Res.Etat.Rang()
		}
		return strings.ToLower(a.Instance.Name) < strings.ToLower(b.Instance.Name)
	})
	v.Releve, err = s.Store.LastReleves(ctx)
	if err != nil {
		s.Log.Error("lecture des relèves", "err", err)
		v.Releve = &store.ReleveState{}
	}
	return v, nil
}

// mesure : ce dont internal/etat a besoin d'une entrée de /hardware.
func mesure(m *irundoo.Measure) etat.Mesure {
	return etat.Mesure{CollectedAt: m.CollectedAt, ReceivedAt: m.ReceivedAt, Payload: m.Payload}
}

func (s *Server) page(w http.ResponseWriter, r *http.Request) {
	se := s.sessionValide(w, r)
	if se == nil {
		return
	}
	v, err := s.vue(r.Context(), se)
	if err != nil {
		s.refusAPI(w, r, se, err)
		return
	}
	s.render(w, http.StatusOK, "page", v)
}

func (s *Server) partial(w http.ResponseWriter, r *http.Request) {
	se := s.sessionValide(w, r)
	if se == nil {
		return
	}
	v, err := s.vue(r.Context(), se)
	if err != nil {
		s.refusAPI(w, r, se, err)
		return
	}
	s.render(w, http.StatusOK, "liste", v)
}

// Detail : fragment d'un établissement.
type Detail struct {
	Ligne
	Sections   []Section
	Historique *store.History
	Retention  int
}

// Section : un bloc du détail, rendu en tableau.
type Section struct {
	Titre   string
	Entetes []string
	Lignes  [][]string
}

func (s *Server) detail(w http.ResponseWriter, r *http.Request) {
	se := s.sessionValide(w, r)
	if se == nil {
		return
	}
	id := r.PathValue("id")
	ins, err := s.API.Instances(r.Context(), se.AccessToken)
	if err != nil {
		s.refusAPI(w, r, se, err)
		return
	}
	i := slices.IndexFunc(ins.Instances, func(in irundoo.Instance) bool { return in.Id == id })
	if i < 0 {
		// Jamais de ?instance= avec un id que /instances n'a pas rendu à ce rendu.
		s.erreur(w, http.StatusNotFound, "Établissement inconnu", "Cet établissement n'est pas dans le périmètre de l'application.")
		return
	}
	hw, err := s.API.Hardware(r.Context(), se.AccessToken, id)
	if err != nil {
		s.refusAPI(w, r, se, err)
		return
	}
	d := Detail{Ligne: Ligne{Instance: ins.Instances[i]}, Retention: s.RetentionDays}
	for k := range hw.Hardware {
		m := &hw.Hardware[k]
		if m.InstanceID == id && (d.Mesure == nil || etat.PlusRecente(mesure(m), mesure(d.Mesure))) {
			d.Mesure = m
		}
	}
	var em *etat.Mesure
	if d.Mesure != nil {
		m := mesure(d.Mesure)
		em = &m
		d.Sections = sections(d.Mesure.Payload)
	}
	d.Res = etat.Compute(s.now(), em, s.StaleAfter)
	d.Historique, err = s.Store.History(r.Context(), id, s.now().AddDate(0, 0, -s.RetentionDays))
	if err != nil {
		s.Log.Error("historique local", "err", err)
	}
	s.render(w, http.StatusOK, "detail", d)
}

// ---- rendu ----

func (s *Server) render(w http.ResponseWriter, status int, name string, data any) {
	var b strings.Builder
	if err := s.tmpl.ExecuteTemplate(&b, name, data); err != nil {
		s.Log.Error("gabarit", "nom", name, "err", err)
		http.Error(w, "erreur de rendu", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(b.String()))
}

func (s *Server) erreur(w http.ResponseWriter, status int, titre, texte string) {
	s.render(w, status, "message", map[string]any{"Titre": titre, "Texte": texte, "Erreur": true, "Lien": "/"})
}

func libelle(e etat.Etat) string {
	switch e {
	case etat.Critique:
		return "critique"
	case etat.Attention:
		return "attention"
	case etat.PasDeNouvelle:
		return "pas de nouvelle"
	case etat.NonObserve:
		return "matériel non observé"
	default:
		return "sain"
	}
}

func depuis(now, t time.Time) string {
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return "à l'instant"
	case d < time.Hour:
		return fmt.Sprintf("il y a %d min", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("il y a %d h", int(d.Hours()))
	default:
		return fmt.Sprintf("il y a %d j", int(d.Hours()/24))
	}
}
