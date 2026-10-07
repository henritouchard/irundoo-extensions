package web

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/henritouchard/irundoo-extensions/extensions/centralisation-materiel/internal/fakeirundo"
	"github.com/henritouchard/irundoo-extensions/extensions/centralisation-materiel/internal/irundoo"
	"github.com/henritouchard/irundoo-extensions/extensions/centralisation-materiel/internal/oidc"
	"github.com/henritouchard/irundoo-extensions/extensions/centralisation-materiel/internal/store"
)

const (
	idA   = "11111111-1111-4111-8111-111111111111"
	idB   = "22222222-2222-4222-8222-222222222222"
	idC   = "33333333-3333-4333-8333-333333333333"
	msgA  = "6f1c2b7e-3a4d-4e5f-8a9b-0c1d2e3f4a5b"
	debut = "État matériel des établissements"
)

type env struct {
	f       *fakeirundo.Server
	s       *Server
	ts      *httptest.Server
	st      *store.Store
	browser *http.Client
	log     *syncBuf
	mu      sync.Mutex
	offset  time.Duration
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *syncBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *syncBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

func (e *env) avance(d time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.offset += d
}

func (e *env) now() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	return time.Now().Add(e.offset)
}

func setup(t *testing.T) *env {
	t.Helper()
	f := fakeirundo.New()
	t.Cleanup(f.Close)
	vm, _ := os.ReadFile("../../testdata/hardware/vm.json")
	f.Instances = []map[string]any{fakeirundo.Instance(idA, "Alpha", "0951234A", true), fakeirundo.Instance(idB, "Bravo", "0951234B", false)}
	f.Hardware = []map[string]any{fakeirundo.Measure(idA, msgA, time.Now().Add(-time.Minute), vm)}
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	e := &env{f: f, st: st, log: &syncBuf{}}
	hc := irundoo.NewHTTPClient()
	api, _ := irundoo.New(f.Issuer(), hc, "test")
	e.s = &Server{API: api, Store: st, Log: slog.New(slog.NewJSONHandler(e.log, &slog.HandlerOptions{Level: slog.LevelDebug})),
		StaleAfter: 30 * time.Minute, RetentionDays: 180, Version: "0.1.0", Now: e.now}
	e.ts = httptest.NewServer(e.s.Handler())
	t.Cleanup(e.ts.Close)
	e.s.PublicURL = e.ts.URL
	f.RedirectURIs = []string{e.ts.URL + "/oidc/callback"}
	oc := oidc.New(oidc.Config{Issuer: f.Issuer(), ClientID: f.ClientID, ClientSecret: f.ClientSecret, RedirectURL: e.ts.URL + "/oidc/callback", HTTPClient: hc})
	// Le client OIDC garde l'horloge réelle : les jetons du faux IRUNDO sont datés en temps réel.
	e.s.OIDC = oc
	st.Now = e.now
	jar, _ := cookiejar.New(nil)
	e.browser = &http.Client{Jar: jar, Timeout: 10 * time.Second}
	t.Cleanup(func() {
		out := e.log.String()
		if strings.Contains(out, f.ClientSecret) || strings.Contains(out, "eyJ") || strings.Contains(out, "Bearer") {
			t.Errorf("secret ou jeton dans le journal : %s", out)
		}
	})
	return e
}

func (e *env) get(t *testing.T, path string, hdr ...string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, e.ts.URL+path, nil)
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := e.browser.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func (e *env) authorizes() []url.Values {
	e.f.Mu.Lock()
	defer e.f.Mu.Unlock()
	return append([]url.Values(nil), e.f.AuthorizeQuery...)
}

func (e *env) calls(k string) int {
	e.f.Mu.Lock()
	defer e.f.Mu.Unlock()
	return e.f.Calls[k]
}

func TestListeNominale(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	// Une instance connue de SQLite (relève passée) mais absente de /instances : jamais affichée.
	_ = e.st.UpsertInstance(ctx, store.Instance{ID: idC, Name: "Charlie-hors-perimetre", Active: true})
	_, _ = e.st.Insert(ctx, store.Measure{InstanceID: idC, ExtensionKey: "k", MessageID: "m", Kind: "hardware/v1", CollectedAt: time.Now(), ReceivedAt: time.Now(), Payload: []byte(`{}`), Etat: "sain"})

	resp, body := e.get(t, "/")
	if resp.StatusCode != 200 || !strings.Contains(body, debut) {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	for _, want := range []string{"Alpha", "Bravo", "0951234A", "matériel non observé", "matériel non observé (VM, aucune source matérielle)",
		"pas de nouvelle", "aucune mesure reçue", "désactivé dans IRUNDO", "Ada Lovelace", `hx-get="/etablissements/` + idA + `"`,
		`hx-trigger="every 60s"`, "Aucune relève de fond encore effectuée"} {
		if !strings.Contains(body, want) {
			t.Errorf("absent de la page : %q", want)
		}
	}
	if strings.Contains(body, "Charlie") || strings.Contains(body, idC) {
		t.Fatal("une instance hors de /instances est affichée (périmètre complété localement)")
	}
	if strings.Contains(body, ">sain<") {
		t.Fatal("une VM sans source matérielle affichée « sain »")
	}
	// Ordre : pas de nouvelle (Bravo) avant non observé (Alpha).
	if strings.Index(body, "Bravo") > strings.Index(body, "Alpha") {
		t.Fatal("tri par état")
	}
	q := e.authorizes()
	if len(q) != 1 || q[0].Has("prompt") || q[0].Get("redirect_uri") != e.ts.URL+"/oidc/callback" {
		t.Fatalf("autorisation : %v", q)
	}
	for k, v := range map[string]string{"Content-Security-Policy": "default-src 'self'", "X-Frame-Options": "DENY",
		"Referrer-Policy": "no-referrer", "Cache-Control": "no-store"} {
		if !strings.Contains(resp.Header.Get(k), v) {
			t.Errorf("en-tête %s = %q", k, resp.Header.Get(k))
		}
	}
	// Le cookie de session : HttpOnly, SameSite=Lax, Path=/.
	u, _ := url.Parse(e.ts.URL)
	if len(e.browser.Jar.Cookies(u)) != 1 {
		t.Fatalf("cookies : %v", e.browser.Jar.Cookies(u))
	}
	// Deux appels d'API par rendu, avec le jeton utilisateur.
	if e.calls("instances") != 1 || e.calls("hardware") != 1 || e.calls("token:client_credentials") != 0 {
		t.Fatalf("%v", e.f.Calls)
	}
	// Fragment de liste (htmx).
	resp, body = e.get(t, "/partials/liste", "HX-Request", "true")
	if resp.StatusCode != 200 || strings.Contains(body, "<html") || !strings.Contains(body, `id="liste"`) {
		t.Fatalf("fragment : %d %s", resp.StatusCode, body)
	}
}

func TestCookieAttributs(t *testing.T) {
	e := setup(t)
	e.s.SecureCookies = true
	nojar := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := nojar.Get(e.ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	sc := resp.Header.Get("Set-Cookie")
	if resp.StatusCode != 302 || !strings.HasPrefix(resp.Header.Get("Location"), e.f.Issuer()+"/oidc/authorize?") ||
		!strings.Contains(sc, "HttpOnly") || !strings.Contains(sc, "Secure") || !strings.Contains(sc, "SameSite=Lax") {
		t.Fatalf("%d %q %q", resp.StatusCode, resp.Header.Get("Location"), sc)
	}
}

// mdDegrade : la charge physique de D.2 avec un RAID md dégradé (critique).
func mdDegrade(t *testing.T) []byte {
	t.Helper()
	b, _ := os.ReadFile("../../testdata/hardware/physical.json")
	var p map[string]any
	_ = json.Unmarshal(b, &p)
	p["md"] = []any{map[string]any{"name": "md0", "degraded": true, "array_state": "clean"}}
	return fakeirundo.MustJSON(p)
}

func TestEtatsEtBandeaux(t *testing.T) {
	e := setup(t)
	rf, _ := os.ReadFile("../../testdata/hardware/redfish.json")
	e.f.Mu.Lock()
	e.f.Instances = append(e.f.Instances, fakeirundo.Instance(idC, "Charlie", "0951234C", true))
	e.f.Hardware = append(e.f.Hardware, fakeirundo.Measure(idB, "0b8e7d6c-5f4a-4b3c-9d2e-1f0a9b8c7d6e", time.Now(), rf),
		fakeirundo.Measure(idC, "1c9f8e7d-6a5b-4c3d-8e2f-2a1b0c9d8e7f", time.Now(), mdDegrade(t)))
	e.f.Reduced = true
	e.f.Mu.Unlock()
	t0 := time.Now()
	_ = e.st.RecordReleve(context.Background(), store.Releve{StartedAt: t0, FinishedAt: t0, Status: "echec", HTTPStatus: 400, Motif: "scopes machine non accordés"})
	_, body := e.get(t, "/")
	for _, want := range []string{"Relève de fond en échec : scopes machine non accordés", "Périmètre réduit par l'administrateur",
		`badge critique">critique`, "RAID md0 dégradé", "critique : 1",
		// Bravo : carte Redfish de l'hôte de virtualisation — son critique reste visible, en mention.
		"matériel de l&#39;hôte de virtualisation (partagé) : critique — alimentation PS2 Status : Critical",
		"seule la carte de l&#39;hôte de virtualisation, partagée, est lue",
		// Alpha (VM) : les sources tentées sans résultat sont nommées sur la ligne.
		"source redfish : absent", "source pve : absent"} {
		if !strings.Contains(body, want) {
			t.Errorf("absent : %q", want)
		}
	}
	// Critique (Charlie) avant les non observés (Alpha, Bravo).
	if strings.Index(body, "Charlie") > strings.Index(body, "Alpha") || strings.Index(body, "Charlie") > strings.Index(body, "Bravo") {
		t.Fatal("tri par état")
	}
	// Le détail de Bravo range la carte sous l'hôte, non attribuée à l'établissement.
	_, det := e.get(t, "/etablissements/"+idB, "HX-Request", "true")
	for _, want := range []string{"Matériel de l&#39;hôte de virtualisation (partagé, Redfish) — non attribué à l&#39;établissement",
		"Matériel de l'hôte de virtualisation (partagé, non attribué à l'établissement)", "panne prédite"} {
		if !strings.Contains(det, want) {
			t.Errorf("absent du détail : %q", want)
		}
	}
	if strings.Contains(det, "Carte de gestion (Redfish)") {
		t.Error("carte de l'hôte présentée comme celle de l'établissement")
	}
	// La relève en échec ne rend pas les lignes « pas de nouvelle ».
	if strings.Contains(body, "aucune mesure reçue") {
		t.Fatal("ligne rendue « pas de nouvelle » à tort")
	}
}

func TestPasDeNouvelleParFraicheur(t *testing.T) {
	e := setup(t)
	e.get(t, "/")
	e.avance(2 * time.Minute)
	e.s.StaleAfter = 2 * time.Minute
	_, body := e.get(t, "/")
	if !strings.Contains(body, "dernière mesure il y a 3 min") || !strings.Contains(body, "collectée il y a 3 min") {
		t.Fatal(body)
	}
}

// Un critique devenu silencieux reste compté « critique » et le dit.
func TestCritiqueSilencieux(t *testing.T) {
	e := setup(t)
	e.f.Mu.Lock()
	e.f.Hardware = append(e.f.Hardware, fakeirundo.Measure(idB, "0b8e7d6c-5f4a-4b3c-9d2e-1f0a9b8c7d6e", time.Now().Add(-2*time.Hour), mdDegrade(t)))
	e.f.Mu.Unlock()
	_, body := e.get(t, "/")
	for _, want := range []string{"pas de nouvelle — dernier état connu : critique", "critique : 1", "pas de nouvelle : 0"} {
		if !strings.Contains(body, want) {
			t.Errorf("absent : %q", want)
		}
	}
	if strings.Index(body, "Bravo") > strings.Index(body, "Alpha") {
		t.Fatal("le critique silencieux n'est pas en tête")
	}
}

func TestScopeUtilisateurNonAccorde(t *testing.T) {
	e := setup(t)
	e.f.UserScopes = []string{"irundoo:instances:read"}
	resp, body := e.get(t, "/")
	if resp.StatusCode != 403 || !strings.Contains(body, "Droit non accordé par l&#39;administrateur : irundoo:hardware:read") {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	if len(e.authorizes()) != 1 {
		t.Fatal("boucle d'autorisation")
	}
}

func TestScopeRetireApresConnexion(t *testing.T) {
	e := setup(t)
	e.get(t, "/")
	e.f.Mu.Lock()
	e.f.UserScopes = []string{"irundoo:instances:read"} // retiré : le jeton reste valide, la route refuse
	e.f.Mu.Unlock()
	resp, body := e.get(t, "/")
	if resp.StatusCode != 403 || !strings.Contains(body, "irundoo:hardware:read") || len(e.authorizes()) != 1 {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
}

func TestPerimetreVide(t *testing.T) {
	e := setup(t)
	e.f.PerimeterGone = true
	resp, body := e.get(t, "/")
	if resp.StatusCode != 200 || !strings.Contains(body, "Aucun établissement accordé") {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
}

func TestErreursAPI(t *testing.T) {
	cas := []struct {
		forced fakeirundo.Forced
		status int
		texte  string
	}{
		{fakeirundo.Forced{Status: 503, Body: `{"error":"server_error","error_description":"x"}`}, 503, "IRUNDO indisponible"},
		{fakeirundo.Forced{Status: 429, Body: `{"error":"rate_limited","error_description":"x"}`, Headers: map[string]string{"Retry-After": "9"}}, 429, "réessayer dans 9 s"},
		{fakeirundo.Forced{Status: 500, Body: `{}`}, 502, "IRUNDO injoignable"},
	}
	for _, c := range cas {
		e := setup(t)
		e.get(t, "/")
		e.f.Mu.Lock()
		f := c.forced
		e.f.Force["hardware"] = &f
		e.f.Mu.Unlock()
		resp, body := e.get(t, "/")
		if resp.StatusCode != c.status || !strings.Contains(body, c.texte) {
			t.Fatalf("%d %s", resp.StatusCode, body)
		}
	}
}

func TestRenouvellementSilencieux(t *testing.T) {
	e := setup(t)
	e.get(t, "/")
	e.avance(15 * time.Minute) // exp atteint (marge 30 s)
	resp, body := e.get(t, "/")
	q := e.authorizes()
	if resp.StatusCode != 200 || !strings.Contains(body, "Alpha") || len(q) != 2 || q[1].Get("prompt") != "none" {
		t.Fatalf("%d %v", resp.StatusCode, q)
	}
	if q[0].Get("state") == q[1].Get("state") || q[0].Get("nonce") == q[1].Get("nonce") || q[0].Get("code_challenge") == q[1].Get("code_challenge") {
		t.Fatal("valeurs réutilisées au renouvellement")
	}
}

func TestLoginRequiredUneSeuleRelance(t *testing.T) {
	e := setup(t)
	e.get(t, "/")
	e.f.Mu.Lock()
	e.f.LoggedIn = false // session IRUNDO fermée ; la page de connexion d'IRUNDO s'affiche
	e.f.Mu.Unlock()
	e.avance(16 * time.Minute)
	resp, body := e.get(t, "/")
	q := e.authorizes()
	if resp.StatusCode != 200 || !strings.Contains(body, "page de connexion IRUNDO") || len(q) != 3 ||
		q[1].Get("prompt") != "none" || q[2].Has("prompt") {
		t.Fatalf("%d %s %v", resp.StatusCode, body, q)
	}
}

func TestSecondEchecPasDeTroisiemeTentative(t *testing.T) {
	e := setup(t)
	e.get(t, "/")
	e.f.Mu.Lock()
	e.f.LoginRequiredAlways = true
	e.f.Mu.Unlock()
	e.avance(16 * time.Minute)
	resp, body := e.get(t, "/")
	if resp.StatusCode != 400 || !strings.Contains(body, "login_required") || len(e.authorizes()) != 3 {
		t.Fatalf("%d %s %d", resp.StatusCode, body, len(e.authorizes()))
	}
}

func TestAccesRefuse(t *testing.T) {
	e := setup(t)
	e.f.AccessDenied = true
	resp, body := e.get(t, "/")
	if resp.StatusCode != 403 || !strings.Contains(body, "Votre statut n&#39;a pas accès à cette application") {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
}

func Test401SurSessionNeuveSansBoucle(t *testing.T) {
	e := setup(t)
	e.f.Force["instances"] = &fakeirundo.Forced{Status: 401, Body: `{"error":"invalid_token","error_description":"x"}`, Sticky: true}
	resp, body := e.get(t, "/")
	if resp.StatusCode != 502 || !strings.Contains(body, "Jeton refusé") || len(e.authorizes()) != 1 {
		t.Fatalf("%d %s %d", resp.StatusCode, body, len(e.authorizes()))
	}
}

func Test401SurSessionAncienneRenouvelle(t *testing.T) {
	e := setup(t)
	e.get(t, "/")
	e.avance(2 * time.Minute)
	e.f.Revoke()
	resp, body := e.get(t, "/")
	q := e.authorizes()
	if resp.StatusCode != 200 || !strings.Contains(body, "Alpha") || len(q) != 2 || q[1].Get("prompt") != "none" {
		t.Fatalf("%d %v", resp.StatusCode, q)
	}
}

func TestHTMXSansSession(t *testing.T) {
	e := setup(t)
	resp, _ := e.get(t, "/partials/liste", "HX-Request", "true")
	if resp.StatusCode != 200 || resp.Header.Get("HX-Redirect") != "/oidc/login" {
		t.Fatalf("%d %v", resp.StatusCode, resp.Header)
	}
	e.get(t, "/")
	e.avance(16 * time.Minute)
	resp, _ = e.get(t, "/etablissements/"+idA, "HX-Request", "true")
	if resp.Header.Get("HX-Redirect") != "/oidc/login?silent=1" {
		t.Fatalf("%v", resp.Header)
	}
	resp, body := e.get(t, "/oidc/login?silent=1")
	if resp.StatusCode != 200 || !strings.Contains(body, "Alpha") {
		t.Fatal(body)
	}
}

func TestDetail(t *testing.T) {
	e := setup(t)
	e.get(t, "/")
	ctx := context.Background()
	_, _ = e.st.Insert(ctx, store.Measure{InstanceID: idA, ExtensionKey: "collectrice-materiel", MessageID: "ancien", Kind: "hardware/v1",
		CollectedAt: time.Now().Add(-time.Hour), ReceivedAt: time.Now().Add(-time.Hour), Payload: []byte(`{}`), Etat: "sain", BootID: "autre-boot"})
	_, _ = e.st.Insert(ctx, store.Measure{InstanceID: idA, ExtensionKey: "collectrice-materiel", MessageID: msgA, Kind: "hardware/v1",
		CollectedAt: time.Now(), ReceivedAt: time.Now(), Payload: []byte(`{}`), Etat: "sain", BootID: "3f2a9c1e-5b7d-4e8a-9c0f-1d2e3f4a5b6c"})
	resp, body := e.get(t, "/etablissements/"+idA, "HX-Request", "true")
	if resp.StatusCode != 200 {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	for _, want := range []string{`id="detail-` + idA + `"`, "Sources", "Systèmes de fichiers", "Disques", "virtio_blk", "/var/sambaedu",
		"<meter", "depuis le démarrage du", "2 mesure(s) conservée(s)", "Redémarrages constatés", "collectrice-materiel 1.0.0"} {
		if !strings.Contains(body, want) {
			t.Errorf("absent du détail : %q", want)
		}
	}
	// Un id hors des ids rendus : 404, et jamais un appel ?instance= avec lui.
	hw := e.calls("hardware")
	resp, _ = e.get(t, "/etablissements/"+idC, "HX-Request", "true")
	if resp.StatusCode != 404 || e.calls("hardware") != hw {
		t.Fatalf("%d hardware %d → %d", resp.StatusCode, hw, e.calls("hardware"))
	}
	// Établissement sans mesure.
	resp, body = e.get(t, "/etablissements/"+idB, "HX-Request", "true")
	if resp.StatusCode != 200 || !strings.Contains(body, "aucune mesure reçue") || !strings.Contains(body, "Aucune mesure conservée") {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
}

func (e *env) post(t *testing.T, path string, form url.Values, hdr ...string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, e.ts.URL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := e.browser.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

var reCSRF = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func TestDeconnexion(t *testing.T) {
	e := setup(t)
	_, page := e.get(t, "/")
	m := reCSRF.FindStringSubmatch(page)
	if m == nil {
		t.Fatal("jeton CSRF absent de la page")
	}
	// GET : refusé (une image ou un lien tiers ne déconnecte pas).
	if resp, _ := e.get(t, "/logout"); resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatal(resp.StatusCode)
	}
	// POST sans jeton, ou d'une autre origine : refusé.
	if resp, _ := e.post(t, "/logout", url.Values{}); resp.StatusCode != 403 {
		t.Fatal(resp.StatusCode)
	}
	if resp, _ := e.post(t, "/logout", url.Values{"csrf": {m[1]}}, "Origin", "https://ailleurs.example.org"); resp.StatusCode != 403 {
		t.Fatal(resp.StatusCode)
	}
	e.get(t, "/")
	if len(e.authorizes()) != 1 {
		t.Fatal("session effacée par une déconnexion refusée")
	}
	resp, body := e.post(t, "/logout", url.Values{"csrf": {m[1]}}, "Origin", e.ts.URL)
	if resp.StatusCode != 200 || !strings.Contains(body, "Votre session IRUNDO reste ouverte") {
		t.Fatal(body)
	}
	e.get(t, "/")
	if len(e.authorizes()) != 2 {
		t.Fatal("la déconnexion locale n'a pas effacé la session")
	}
}

func TestCallbackInvalide(t *testing.T) {
	e := setup(t)
	resp, body := e.get(t, "/oidc/callback?code=x&state=y")
	if resp.StatusCode != 400 || !strings.Contains(body, "Tentative de connexion inconnue ou expirée") {
		t.Fatal(body)
	}
	// Tentative valide mais state falsifié.
	nojar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: nojar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	r1, _ := c.Get(e.ts.URL + "/oidc/login")
	r1.Body.Close()
	r2, _ := c.Get(e.ts.URL + "/oidc/callback?code=abc&state=faux&iss=" + url.QueryEscape(e.f.Issuer()))
	b, _ := io.ReadAll(r2.Body)
	r2.Body.Close()
	if r2.StatusCode != 400 || !strings.Contains(string(b), "Tentative de connexion inconnue") {
		t.Fatalf("%d %s", r2.StatusCode, b)
	}
	if e.calls("token:authorization_code") != 0 {
		t.Fatal("échange tenté sur un retour invalide")
	}
}

func TestDiscoveryInjoignable(t *testing.T) {
	e := setup(t)
	e.f.Close()
	resp, body := e.get(t, "/")
	if resp.StatusCode != 502 || !strings.Contains(body, "IRUNDO injoignable") {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
}

func TestSante(t *testing.T) {
	e := setup(t)
	nojar := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := nojar.Get(e.ts.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&body)
	resp.Body.Close()
	if resp.StatusCode != 200 || body["version"] != "0.1.0" || len(body) != 1 ||
		resp.Header.Get("Content-Type") != "application/json" || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("%d %v %v", resp.StatusCode, body, resp.Header)
	}
	resp, _ = nojar.Head(e.ts.URL + "/health")
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
	// Une relève en échec ne rend pas 503.
	_ = e.st.RecordReleve(context.Background(), store.Releve{StartedAt: time.Now(), FinishedAt: time.Now(), Status: "echec", Motif: "x"})
	resp, _ = nojar.Get(e.ts.URL + "/health")
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal("relève en échec ⇒ 503")
	}
	_ = e.st.Close()
	resp, _ = nojar.Get(e.ts.URL + "/health")
	_ = json.NewDecoder(resp.Body).Decode(&body)
	resp.Body.Close()
	if resp.StatusCode != 503 || body["error"] != "store" || body["version"] != "0.1.0" {
		t.Fatalf("%d %v", resp.StatusCode, body)
	}
}

func TestStatique(t *testing.T) {
	e := setup(t)
	resp, body := e.get(t, "/static/htmx.min.js")
	if resp.StatusCode != 200 || !strings.Contains(body, `version:"2.0.10"`) {
		t.Fatal(resp.StatusCode)
	}
	resp, _ = e.get(t, "/static/app.css")
	if resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
}

func TestSections(t *testing.T) {
	rf, _ := os.ReadFile("../../testdata/hardware/redfish.json")
	s := sections(rf)
	if len(s) == 0 || s[0].Titre != "Sources" {
		t.Fatalf("%+v", s)
	}
	if sections([]byte(`pas du json`)) != nil {
		t.Fatal()
	}
	s = sections([]byte(`{"inconnue":{"a":1.5,"b":true,"c":null},"md":[],"x":3}`))
	if len(s) != 3 || s[0].Titre != "RAID logiciel (md)" || s[1].Lignes[0][1] != "1.5" || s[1].Lignes[1][1] != "oui" || s[2].Lignes[0][0] != "3" {
		t.Fatalf("%+v", s)
	}
	if pourcent("x", 1.0) != "" || pourcent(1.0, 0.0) != "" || valeur([]any{1.0}) != "[1]" || valeur(false) != "non" {
		t.Fatal()
	}
	n := time.Now()
	if depuis(n, n) != "à l'instant" || depuis(n, n.Add(-3*time.Hour)) != "il y a 3 h" || depuis(n, n.Add(-72*time.Hour)) != "il y a 3 j" {
		t.Fatal()
	}
}

// nofollow : client sans bocal ni redirection suivie.
func nofollow() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func cookieNomme(t *testing.T, resp *http.Response, prefixe string) *http.Cookie {
	t.Helper()
	for _, c := range resp.Cookies() {
		if strings.HasPrefix(c.Name, prefixe) {
			return c
		}
	}
	t.Fatalf("cookie %s* absent : %v", prefixe, resp.Header.Values("Set-Cookie"))
	return nil
}

// En https (PUBLIC_URL), le cookie de session est `__Host-cm_session` : Secure, HttpOnly,
// SameSite=Lax, Path=/, sans Domain ; HSTS est posé.
func TestCookieSessionAttributs(t *testing.T) {
	e := setup(t)
	e.s.SecureCookies = true
	c := nofollow()
	r1, err := c.Get(e.ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	r1.Body.Close()
	if !strings.HasPrefix(r1.Header.Get("Strict-Transport-Security"), "max-age=") {
		t.Fatal("HSTS absent")
	}
	tc := cookieNomme(t, r1, "__Secure-cm_t_")
	r2, err := c.Get(r1.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	r2.Body.Close()
	req, _ := http.NewRequest(http.MethodGet, r2.Header.Get("Location"), nil)
	req.AddCookie(&http.Cookie{Name: tc.Name, Value: tc.Value})
	r3, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	r3.Body.Close()
	if r3.StatusCode != 302 || r3.Header.Get("Location") != "/" {
		t.Fatalf("%d %v", r3.StatusCode, r3.Header)
	}
	var brut string
	for _, v := range r3.Header.Values("Set-Cookie") {
		if strings.HasPrefix(v, "__Host-cm_session=") {
			brut = v
		}
	}
	for _, want := range []string{"Path=/", "HttpOnly", "Secure", "SameSite=Lax"} {
		if !strings.Contains(brut, want) {
			t.Errorf("%q absent de %q", want, brut)
		}
	}
	if strings.Contains(strings.ToLower(brut), "domain=") || strings.Contains(brut, "Max-Age") || strings.Contains(brut, "Expires") {
		t.Errorf("attributs : %q", brut)
	}
	sc := cookieNomme(t, r3, "__Host-cm_session")
	req, _ = http.NewRequest(http.MethodGet, e.ts.URL+"/", nil)
	req.AddCookie(&http.Cookie{Name: sc.Name, Value: sc.Value})
	r4, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	r4.Body.Close()
	if r4.StatusCode != 200 {
		t.Fatal(r4.StatusCode)
	}
	// En http (développement) : pas de préfixe, pas de HSTS.
	e.s.SecureCookies = false
	r5, _ := c.Get(e.ts.URL + "/")
	r5.Body.Close()
	if r5.Header.Get("Strict-Transport-Security") != "" || cookieNomme(t, r5, "cm_t_").Secure {
		t.Fatal("HSTS ou Secure en http")
	}
}

// Deux onglets qui se renouvellent en même temps : chaque tentative a son cookie (nommé d'après
// son state), aucune n'écrase l'autre.
func TestRenouvellementsConcurrents(t *testing.T) {
	e := setup(t)
	jar, _ := cookiejar.New(nil)
	b := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var auth []string
	for range 2 {
		r, err := b.Get(e.ts.URL + "/oidc/login?silent=1")
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		auth = append(auth, r.Header.Get("Location"))
	}
	u, _ := url.Parse(e.ts.URL + "/oidc/")
	if n := len(jar.Cookies(u)); n != 2 {
		t.Fatalf("cookies de tentative : %d", n)
	}
	for _, i := range []int{1, 0} { // le second onglet revient le premier
		r, err := nofollow().Get(auth[i])
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		cb, err := b.Get(r.Header.Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		cb.Body.Close()
		if cb.StatusCode != 302 || cb.Header.Get("Location") != "/" {
			t.Fatalf("onglet %d : %d", i, cb.StatusCode)
		}
	}
}

// Le renouvellement déclenché par un onglet n'efface pas la session : un autre onglet qui la porte
// n'est pas déconnecté ; elle n'est remplacée qu'au retour d'autorisation.
func TestRenouvellementNeDetruitPasLaSession(t *testing.T) {
	e := setup(t)
	e.get(t, "/")
	u, _ := url.Parse(e.ts.URL)
	old := e.browser.Jar.Cookies(u)[0].Value
	e.avance(16 * time.Minute)
	resp, _ := e.get(t, "/partials/liste", "HX-Request", "true")
	if resp.Header.Get("HX-Redirect") != "/oidc/login?silent=1" {
		t.Fatal(resp.Header)
	}
	if se, _ := e.st.GetSession(context.Background(), old); se == nil {
		t.Fatal("session effacée au début du renouvellement")
	}
	if resp, body := e.get(t, "/oidc/login?silent=1"); resp.StatusCode != 200 || !strings.Contains(body, "Alpha") {
		t.Fatal(resp.StatusCode)
	}
	if se, _ := e.st.GetSession(context.Background(), old); se != nil {
		t.Fatal("session remplacée non effacée au retour")
	}
}

func TestLimiteDeDebitDesTentatives(t *testing.T) {
	e := setup(t)
	e.s.TentativesRafale = 3
	c := nofollow()
	codes := []int{}
	for range 4 {
		r, err := c.Get(e.ts.URL + "/oidc/login")
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		codes = append(codes, r.StatusCode)
	}
	if codes[2] != 302 || codes[3] != 429 {
		t.Fatal(codes)
	}
	// Une autre adresse derrière le proxy local n'est pas limitée.
	req, _ := http.NewRequest(http.MethodGet, e.ts.URL+"/oidc/login", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	r, _ := c.Do(req)
	r.Body.Close()
	if r.StatusCode != 302 {
		t.Fatal(r.StatusCode)
	}
	// Le seau se remplit avec le temps.
	e.avance(time.Minute)
	r, _ = c.Get(e.ts.URL + "/oidc/login")
	r.Body.Close()
	if r.StatusCode != 302 {
		t.Fatal(r.StatusCode)
	}
}

func TestPlafondDesTentativesEnVol(t *testing.T) {
	e := setup(t)
	e.st.MaxAttempts = 1
	c := nofollow()
	r, _ := c.Get(e.ts.URL + "/oidc/login")
	r.Body.Close()
	r2, _ := c.Get(e.ts.URL + "/oidc/login")
	r2.Body.Close()
	if r.StatusCode != 302 || r2.StatusCode != 503 || r2.Header.Get("Retry-After") == "" {
		t.Fatal(r.StatusCode, r2.StatusCode)
	}
}

func TestClientIP(t *testing.T) {
	cas := []struct {
		remote, xff, want string
	}{
		{"203.0.113.1:5000", "198.51.100.7", "203.0.113.1"}, // pair public : X-Forwarded-For ignoré
		{"127.0.0.1:5000", "198.51.100.7, 203.0.113.4", "203.0.113.4"},
		{"127.0.0.1:5000", "pas une adresse", "127.0.0.1"},
		{"[::1]:5000", "", "::1"},
	}
	for _, c := range cas {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = c.remote
		if c.xff != "" {
			r.Header.Set("X-Forwarded-For", c.xff)
		}
		if got := clientIP(r); got != c.want {
			t.Errorf("%v : %s", c, got)
		}
	}
}

// Le rafraîchissement htmx garde un détail ouvert (hx-preserve sur la cellule du détail) et une
// erreur de requête htmx s'affiche (app.js, htmx:responseError).
func TestHTMXPreserveEtErreurs(t *testing.T) {
	e := setup(t)
	_, body := e.get(t, "/")
	for _, want := range []string{`id="detail-` + idA + `" hx-preserve="true"`, `id="erreur-htmx"`, `src="/static/app.js"`} {
		if !strings.Contains(body, want) {
			t.Errorf("absent : %q", want)
		}
	}
	_, det := e.get(t, "/etablissements/"+idA, "HX-Request", "true")
	if strings.Contains(det, "hx-preserve") {
		t.Fatal("le détail chargé ne doit pas porter hx-preserve (htmx le remplacerait par la cellule vide)")
	}
	resp, js := e.get(t, "/static/app.js")
	if resp.StatusCode != 200 || !strings.Contains(js, "htmx:responseError") || !strings.Contains(js, "htmx:sendError") {
		t.Fatal(resp.StatusCode)
	}
}

// Le corps d'un refus du token_endpoint à l'échange du code n'est jamais journalisé (FR21, n° 18).
func TestEchangeRefuseSansCorpsDansLeJournal(t *testing.T) {
	e := setup(t)
	e.f.Mu.Lock()
	e.f.Force["token"] = &fakeirundo.Forced{Status: 400,
		Body: `{"error":"invalid_grant","error_description":"` + e.f.ClientSecret + ` eyJhbGciOi Bearer x"}`}
	e.f.Mu.Unlock()
	resp, _ := e.get(t, "/")
	if resp.StatusCode != 502 {
		t.Fatal(resp.StatusCode)
	}
	out := e.log.String()
	if !strings.Contains(out, "invalid_grant") || strings.Contains(out, e.f.ClientSecret[:8]) {
		t.Fatal(out)
	}
}
