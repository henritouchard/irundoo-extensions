// Package fakeirundo est un faux IRUNDO pour les tests, construit d'après la documentation publique
// seule : Discovery et flots de fournisseur-oidc.md § 2-6, garde Bearer § 11.2-11.4, routes
// `/instances` et `/hardware` d'api-v1.md § 3-5 et du contrat des mesures § 6, formes de
// openapi-v1.json. Il ne sert qu'aux tests (aucun import hors `_test.go`).
package fakeirundo

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

// Prefix : IRUNDO publié sous un préfixe de chemin (issuer = origine + préfixe).
const Prefix = "/controlhub"

// Forced : réponse imposée à la prochaine requête d'une route de l'API.
type Forced struct {
	Status  int
	Body    string
	Headers map[string]string
	// Sticky : la réponse reste imposée jusqu'à remise à zéro.
	Sticky bool
}

type code struct {
	redirectURI, challenge, nonce, scope string
	used                                 bool
	expires                              time.Time
}

type token struct {
	machine bool
	scope   []string
	exp     time.Time
}

// Server : l'état du faux IRUNDO, modifiable par les tests (sous Mu).
type Server struct {
	Mu  sync.Mutex
	TS  *httptest.Server
	Key *rsa.PrivateKey
	Kid string

	ClientID, ClientSecret string
	RedirectURIs           []string

	// Octroi (B.4) : scopes accordés par famille.
	UserScopes, MachineScopes []string
	// Session IRUNDO ouverte dans le « navigateur ».
	LoggedIn bool
	// LoginOnPrompt : sans prompt et sans session, la page de connexion « réussit » aussitôt.
	LoginOnPrompt bool
	// LoginRequiredAlways : login_required même sans prompt (simule un échec de connexion).
	LoginRequiredAlways bool
	// AccessDenied : l'utilisateur n'est pas dans la Visibilité de la tuile.
	AccessDenied bool
	// UserSub, UserName, UserRoles : identité de l'id_token.
	UserSub, UserName string
	UserRoles         []string
	// IDTokenNonceOverride : nonce faux injecté dans l'id_token (test de refus).
	IDTokenNonceOverride string
	// OmitIss : le retour d'autorisation ne porte pas `iss`.
	OmitIss bool
	// TokenTTL : durée de vie des access tokens émis (900 s par défaut).
	TokenTTL time.Duration
	// IDTokenForge : si non nil, produit l'id_token à partir des claims nominales (tests de refus :
	// aud, exp, autre clé, alg). Appelé sous Mu : ne pas reverrouiller.
	IDTokenForge func(claims map[string]any) string
	// ECKey / PublishEC : une clé EC P-256 publiée dans le JWKS et ES256 annoncé dans la Discovery
	// (un client qui n'épingle pas RS256 accepterait un id_token ES256).
	ECKey     *ecdsa.PrivateKey
	PublishEC bool

	// Données servies.
	Instances     []map[string]any
	Hardware      []map[string]any
	Reduced       bool
	PerimeterGone bool

	Force map[string]*Forced // clé : "instances" | "hardware" | "token"

	// Compteurs.
	Calls          map[string]int // "instances", "hardware", "token:authorization_code", "token:client_credentials", "authorize"
	AuthorizeQuery []url.Values
	TokenForms     []url.Values
	TokenAuth      []string
	APIAuth        []string

	codes  map[string]*code
	tokens map[string]*token
}

// New démarre le faux IRUNDO.
func New() *Server {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	s := &Server{
		Key: key, Kid: "2026-10-01", ECKey: ec,
		ClientID:     "0123456789abcdef0123456789abcdef",
		ClientSecret: strings.Repeat("ab", 32),
		UserSub:      "42", UserName: "Ada Lovelace", UserRoles: []string{"admin"},
		UserScopes:    []string{"irundoo:instances:read", "irundoo:hardware:read"},
		MachineScopes: []string{"irundoo:instances:read", "irundoo:hardware:read"},
		LoggedIn:      true,
		TokenTTL:      900 * time.Second,
		Force:         map[string]*Forced{},
		Calls:         map[string]int{},
		codes:         map[string]*code{},
		tokens:        map[string]*token{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+Prefix+"/.well-known/openid-configuration", s.discovery)
	mux.HandleFunc("GET "+Prefix+"/oidc/jwks", s.jwks)
	mux.HandleFunc("GET "+Prefix+"/oidc/authorize", s.authorize)
	mux.HandleFunc("POST "+Prefix+"/oidc/token", s.token)
	mux.HandleFunc("GET "+Prefix+"/api/v1/extensions/instances", s.api("instances", "irundoo:instances:read"))
	mux.HandleFunc("GET "+Prefix+"/api/v1/extensions/hardware", s.api("hardware", "irundoo:hardware:read"))
	s.TS = httptest.NewServer(mux)
	return s
}

// Close arrête le serveur.
func (s *Server) Close() { s.TS.Close() }

// Issuer : origine + préfixe, sans « / » final.
func (s *Server) Issuer() string { return s.TS.URL + Prefix }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) discovery(w http.ResponseWriter, _ *http.Request) {
	s.Mu.Lock()
	s.Calls["discovery"]++
	algs := []string{"RS256"}
	if s.PublishEC {
		algs = append(algs, "ES256")
	}
	s.Mu.Unlock()
	iss := s.Issuer()
	writeJSON(w, 200, map[string]any{
		"issuer":                                         iss,
		"authorization_endpoint":                         iss + "/oidc/authorize",
		"token_endpoint":                                 iss + "/oidc/token",
		"jwks_uri":                                       iss + "/oidc/jwks",
		"response_types_supported":                       []string{"code"},
		"response_modes_supported":                       []string{"query"},
		"grant_types_supported":                          []string{"authorization_code", "client_credentials"},
		"subject_types_supported":                        []string{"public"},
		"id_token_signing_alg_values_supported":          algs,
		"scopes_supported":                               []string{"openid", "irundoo:perimeter:read", "irundoo:instances:read", "irundoo:objects:read", "irundoo:objects:write", "irundoo:users:read", "irundoo:users:write", "irundoo:hardware:read"},
		"token_endpoint_auth_methods_supported":          []string{"client_secret_basic", "client_secret_post"},
		"code_challenge_methods_supported":               []string{"S256"},
		"claims_supported":                               []string{"iss", "sub", "aud", "exp", "iat", "jti", "nonce", "name", "roles"},
		"authorization_response_iss_parameter_supported": true,
		"prompt_values_supported":                        []string{"none"},
	})
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (s *Server) jwks(w http.ResponseWriter, _ *http.Request) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	pub := s.Key.PublicKey
	keys := []map[string]string{{
		"kty": "RSA", "use": "sig", "alg": "RS256", "kid": s.Kid,
		"n": b64(pub.N.Bytes()), "e": b64(big.NewInt(int64(pub.E)).Bytes()),
	}}
	if s.PublishEC {
		keys = append(keys, map[string]string{"kty": "EC", "use": "sig", "alg": "ES256", "kid": "ec-1", "crv": "P-256",
			"x": b64(s.ECKey.X.FillBytes(make([]byte, 32))), "y": b64(s.ECKey.Y.FillBytes(make([]byte, 32)))})
	}
	writeJSON(w, 200, map[string]any{"keys": keys})
}

// SignWith produit un JWT de type JWT avec l'algorithme et la clé donnés : RS256 (*rsa.PrivateKey),
// ES256 (*ecdsa.PrivateKey), HS256 ([]byte), none (clé ignorée, signature vide).
func SignWith(alg string, key any, kid string, claims map[string]any) string {
	h, _ := json.Marshal(map[string]string{"typ": "JWT", "alg": alg, "kid": kid})
	p, _ := json.Marshal(claims)
	in := b64(h) + "." + b64(p)
	sum := sha256.Sum256([]byte(in))
	switch alg {
	case "RS256":
		sig, err := rsa.SignPKCS1v15(rand.Reader, key.(*rsa.PrivateKey), crypto.SHA256, sum[:])
		if err != nil {
			panic(err)
		}
		return in + "." + b64(sig)
	case "ES256":
		r, ss, err := ecdsa.Sign(rand.Reader, key.(*ecdsa.PrivateKey), sum[:])
		if err != nil {
			panic(err)
		}
		return in + "." + b64(append(r.FillBytes(make([]byte, 32)), ss.FillBytes(make([]byte, 32))...))
	case "HS256":
		m := hmac.New(sha256.New, key.([]byte))
		m.Write([]byte(in))
		return in + "." + b64(m.Sum(nil))
	default:
		return in + "."
	}
}

// Sign produit un JWT RS256.
func (s *Server) Sign(typ string, claims map[string]any) string {
	h, _ := json.Marshal(map[string]string{"typ": typ, "alg": "RS256", "kid": s.Kid})
	p, _ := json.Marshal(claims)
	in := b64(h) + "." + b64(p)
	sum := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.Key, crypto.SHA256, sum[:])
	if err != nil {
		panic(err)
	}
	return in + "." + b64(sig)
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	q := r.URL.Query()
	s.Calls["authorize"]++
	s.AuthorizeQuery = append(s.AuthorizeQuery, q)
	w.Header().Set("X-Frame-Options", "DENY")
	if q.Get("client_id") != s.ClientID {
		http.Error(w, "oidc.client_unknown", 400)
		return
	}
	ru := q.Get("redirect_uri")
	if !slices.Contains(s.RedirectURIs, ru) {
		http.Error(w, "oidc.redirect_uri_mismatch", 400)
		return
	}
	back := func(v url.Values) {
		v.Set("state", q.Get("state"))
		if !s.OmitIss {
			v.Set("iss", s.Issuer())
		}
		http.Redirect(w, r, ru+"?"+v.Encode(), http.StatusFound)
	}
	scopes := strings.Fields(q.Get("scope"))
	switch {
	case q.Get("response_type") != "code":
		back(url.Values{"error": {"unsupported_response_type"}})
		return
	case len(q.Get("code_challenge")) != 43, q.Get("code_challenge_method") != "S256",
		q.Has("max_age"), q.Get("prompt") != "" && q.Get("prompt") != "none":
		back(url.Values{"error": {"invalid_request"}})
		return
	case !slices.Contains(scopes, "openid"):
		back(url.Values{"error": {"invalid_scope"}})
		return
	}
	if s.LoginRequiredAlways {
		back(url.Values{"error": {"login_required"}})
		return
	}
	if !s.LoggedIn {
		if q.Get("prompt") == "none" {
			back(url.Values{"error": {"login_required"}})
			return
		}
		if !s.LoginOnPrompt {
			w.WriteHeader(200)
			_, _ = w.Write([]byte("<html>page de connexion IRUNDO</html>"))
			return
		}
		s.LoggedIn = true
	}
	if s.AccessDenied {
		back(url.Values{"error": {"access_denied"}})
		return
	}
	granted := []string{"openid"}
	for _, sc := range scopes {
		if sc != "openid" && slices.Contains(s.UserScopes, sc) {
			granted = append(granted, sc)
		}
	}
	c := randHex(32)
	s.codes[c] = &code{redirectURI: ru, challenge: q.Get("code_challenge"), nonce: q.Get("nonce"),
		scope: strings.Join(granted, " "), expires: time.Now().Add(60 * time.Second)}
	back(url.Values{"code": {c}})
}

func oauthErr(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": code})
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	if f := s.take("token"); f != nil {
		s.respond(w, f)
		return
	}
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		oauthErr(w, 400, "invalid_request")
		return
	}
	if err := r.ParseForm(); err != nil {
		oauthErr(w, 400, "invalid_request")
		return
	}
	s.TokenForms = append(s.TokenForms, r.PostForm)
	s.TokenAuth = append(s.TokenAuth, r.Header.Get("Authorization"))
	id, secret, ok := r.BasicAuth()
	if ok && (r.PostForm.Has("client_secret") || (r.PostForm.Has("client_id") && r.PostForm.Get("client_id") != id)) {
		oauthErr(w, 400, "invalid_request")
		return
	}
	if !ok || id != s.ClientID || secret != s.ClientSecret {
		w.Header().Set("WWW-Authenticate", `Basic realm="irundoo-oidc"`)
		oauthErr(w, 401, "invalid_client")
		return
	}
	grant := r.PostForm.Get("grant_type")
	s.Calls["token:"+grant]++
	switch grant {
	case "client_credentials":
		req := strings.Split(r.PostForm.Get("scope"), " ")
		for _, sc := range req {
			if sc == "" || sc == "openid" || !slices.Contains(s.MachineScopes, sc) {
				oauthErr(w, 400, "invalid_scope")
				return
			}
		}
		at := s.issue(true, req)
		writeJSON(w, 200, map[string]any{"access_token": at, "token_type": "Bearer",
			"expires_in": int(s.TokenTTL.Seconds()), "scope": strings.Join(req, " ")})
	case "authorization_code":
		c, found := s.codes[r.PostForm.Get("code")]
		if !found || c.used || time.Now().After(c.expires) || c.redirectURI != r.PostForm.Get("redirect_uri") {
			oauthErr(w, 400, "invalid_grant")
			return
		}
		c.used = true
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if b64(sum[:]) != c.challenge {
			oauthErr(w, 400, "invalid_grant")
			return
		}
		scopes := strings.Fields(c.scope)
		at := s.issue(false, scopes)
		nonce := c.nonce
		if s.IDTokenNonceOverride != "" {
			nonce = s.IDTokenNonceOverride
		}
		now := time.Now()
		claims := map[string]any{"iss": s.Issuer(), "sub": s.UserSub, "aud": s.ClientID,
			"exp": now.Add(300 * time.Second).Unix(), "iat": now.Unix(), "jti": randHex(16),
			"nonce": nonce, "name": s.UserName, "roles": s.UserRoles}
		idt := s.Sign("JWT", claims)
		if s.IDTokenForge != nil {
			idt = s.IDTokenForge(claims)
		}
		writeJSON(w, 200, map[string]any{"access_token": at, "token_type": "Bearer",
			"expires_in": int(s.TokenTTL.Seconds()), "id_token": idt, "scope": c.scope})
	default:
		oauthErr(w, 400, "unsupported_grant_type")
	}
}

func (s *Server) issue(machine bool, scopes []string) string {
	now := time.Now()
	sub := s.UserSub
	if machine {
		sub = s.ClientID
	}
	at := s.Sign("at+jwt", map[string]any{"iss": s.Issuer(), "sub": sub, "aud": s.ClientID,
		"client_id": s.ClientID, "exp": now.Add(s.TokenTTL).Unix(), "iat": now.Unix(), "nbf": now.Unix(),
		"jti": randHex(16), "scope": strings.Join(scopes, " "), "irundoo_perimeter": []string{}})
	s.tokens[at] = &token{machine: machine, scope: scopes, exp: now.Add(s.TokenTTL)}
	return at
}

// Revoke rend tous les jetons émis invalides (401 invalid_token à l'appel suivant).
func (s *Server) Revoke() {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	s.tokens = map[string]*token{}
}

func (s *Server) take(route string) *Forced {
	f := s.Force[route]
	if f != nil && !f.Sticky {
		delete(s.Force, route)
	}
	return f
}

func (s *Server) respond(w http.ResponseWriter, f *Forced) {
	for k, v := range f.Headers {
		w.Header().Set(k, v)
	}
	if f.Body != "" {
		w.Header().Set("Content-Type", "application/json")
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(f.Status)
	_, _ = w.Write([]byte(f.Body))
}

func (s *Server) api(route, scope string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.Mu.Lock()
		defer s.Mu.Unlock()
		s.Calls[route]++
		s.APIAuth = append(s.APIAuth, r.Header.Get("Authorization"))
		if f := s.take(route); f != nil {
			s.respond(w, f)
			return
		}
		h := r.Header.Get("Authorization")
		if !strings.HasPrefix(h, "Bearer ") {
			w.Header().Set("WWW-Authenticate", `Bearer realm="irundoo-extensions"`)
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(401)
			return
		}
		t, ok := s.tokens[strings.TrimPrefix(h, "Bearer ")]
		if !ok || time.Now().After(t.exp) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="irundoo-extensions", error="invalid_token"`)
			oauthErr(w, 401, "invalid_token")
			return
		}
		granted := s.UserScopes
		if t.machine {
			granted = s.MachineScopes
		}
		if !slices.Contains(t.scope, scope) || !slices.Contains(granted, scope) {
			writeJSON(w, 403, map[string]string{"error": "insufficient_scope",
				"error_description": "The access token does not carry the required scope.", "scope": scope})
			return
		}
		if s.PerimeterGone || len(s.Instances) == 0 {
			writeJSON(w, 403, map[string]string{"error": "perimeter_empty", "error_description": "The extension's perimeter is empty."})
			return
		}
		inst := strings.ToLower(r.URL.Query().Get("instance"))
		if r.URL.Query().Has("instance") && !slices.ContainsFunc(s.Instances, func(m map[string]any) bool { return m["id"] == inst }) {
			writeJSON(w, 403, map[string]string{"error": "out_of_perimeter", "error_description": "The requested instance is not in the extension's perimeter."})
			return
		}
		w.Header().Set("X-RateLimit-Limit", "300")
		switch route {
		case "instances":
			list := []map[string]any{}
			for _, m := range s.Instances {
				if inst == "" || m["id"] == inst {
					list = append(list, m)
				}
			}
			writeJSON(w, 200, map[string]any{"instances": list, "reduced": s.Reduced})
		case "hardware":
			list := []map[string]any{}
			for _, m := range s.Hardware {
				if inst == "" || m["instance_id"] == inst {
					list = append(list, m)
				}
			}
			writeJSON(w, 200, map[string]any{"hardware": list, "reduced": s.Reduced})
		}
	}
}

// Instance construit un établissement à sept clés (api-v1.md § 4).
func Instance(id, name, uai string, active bool) map[string]any {
	return map[string]any{"id": id, "name": name, "uai": uai, "establishment_name": "Collège " + name,
		"establishment_type": "college", "academic_zone": "Versailles", "active": active}
}

// Measure construit une entrée de /hardware (huit clés, contrat § 6) autour d'une charge.
func Measure(instance, messageID string, received time.Time, payload json.RawMessage) map[string]any {
	return map[string]any{"instance_id": instance, "extension_key": "collectrice-materiel",
		"extension_version": "1.0.0", "message_id": messageID, "kind": "hardware/v1",
		"collected_at": received.Add(-5 * time.Second).UTC().Format("2006-01-02T15:04:05.000000Z"),
		"received_at":  received.UTC().Format("2006-01-02T15:04:05.000000Z"),
		"payload":      payload}
}

// MustJSON : raccourci de test.
func MustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprint(err))
	}
	return b
}

// IssueToken émet un access token avec les scopes accordés à sa famille (raccourci de test).
func (s *Server) IssueToken(machine bool) string {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	scopes := s.UserScopes
	if machine {
		scopes = s.MachineScopes
	}
	return s.issue(machine, slices.Clone(scopes))
}
