// Package oidc est le client OpenID Connect de la centralisatrice auprès d'IRUNDO
// (fournisseur-oidc.md § 2-6, § 4.2 bis ; guide-developpeur.md § 3, § 16) :
//
//   - Discovery obligatoire (aucun chemin /oidc/* codé), issuer comparé à IRUNDOO_ISSUER, mise en
//     cache une heure ; JWKS relu sur `kid` inconnu (KeySet de go-oidc) ;
//   - flot utilisateur `authorization_code` + PKCE S256, client confidentiel en
//     `client_secret_basic` seul, `state` / `nonce` / `code_verifier` neufs par tentative,
//     `iss` de la réponse vérifié (RFC 9207), `id_token` vérifié (RS256 épinglé, iss, aud, exp,
//     nonce, typ JWT), scope accordé comparé au demandé ;
//   - jeton machine `client_credentials`, réutilisé jusqu'à `exp − 30 s`.
//
// L'access token reste opaque : il n'est jamais décodé.
package oidc

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// Scopes d'API demandés, identiques dans les deux familles (manifeste : user_scopes = machine_scopes).
var APIScopes = []string{"irundoo:instances:read", "irundoo:hardware:read"}

// Marge avant l'échéance d'un jeton.
const Marge = 30 * time.Second

// DiscoveryTTL : durée de la mise en cache de la Discovery.
const DiscoveryTTL = time.Hour

// ErrAuthorize : retour d'autorisation portant `error` (fournisseur-oidc.md § 3).
type ErrAuthorize struct{ Code string }

func (e *ErrAuthorize) Error() string { return "autorisation refusée par IRUNDO : " + e.Code }

// ErrScopeNotGranted : le scope accordé ne contient pas tout le demandé (downscoping, § 4.3).
type ErrScopeNotGranted struct{ Missing []string }

func (e *ErrScopeNotGranted) Error() string {
	return "droit non accordé par l'administrateur : " + strings.Join(e.Missing, ", ")
}

// ErrMachineScope : `400 invalid_scope` au grant client_credentials (scopes machine non accordés).
var ErrMachineScope = errors.New("scopes machine non accordés")

// ErrCallback : retour d'autorisation invalide (state, iss, code absent).
var ErrCallback = errors.New("retour d'autorisation invalide")

// Config du client.
type Config struct {
	Issuer, ClientID, ClientSecret string
	// RedirectURL = PUBLIC_URL + "/oidc/callback", exacte.
	RedirectURL string
	HTTPClient  *http.Client
}

// Client OIDC.
type Client struct {
	cfg Config
	Now func() time.Time

	mu        sync.Mutex
	provider  *gooidc.Provider
	fetchedAt time.Time

	machineMu  sync.Mutex
	machineTok string
	machineExp time.Time
}

// New ne contacte pas IRUNDO : la Discovery est lue au premier besoin.
func New(cfg Config) *Client {
	return &Client{cfg: cfg, Now: time.Now}
}

func (c *Client) ctx(ctx context.Context) context.Context {
	return gooidc.ClientContext(ctx, c.cfg.HTTPClient)
}

// discovery : Discovery en cache (1 h) ; go-oidc refuse un `issuer` différent de celui configuré.
func (c *Client) discovery(ctx context.Context) (*gooidc.Provider, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.provider != nil && c.Now().Sub(c.fetchedAt) < DiscoveryTTL {
		return c.provider, nil
	}
	p, err := gooidc.NewProvider(c.ctx(ctx), c.cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("discovery : %w", err)
	}
	c.provider, c.fetchedAt = p, c.Now()
	return p, nil
}

func (c *Client) oauth(p *gooidc.Provider, scopes []string) *oauth2.Config {
	ep := p.Endpoint()
	ep.AuthStyle = oauth2.AuthStyleInHeader // client_secret_basic seul : jamais client_id dans le corps
	return &oauth2.Config{ClientID: c.cfg.ClientID, ClientSecret: c.cfg.ClientSecret, Endpoint: ep,
		RedirectURL: c.cfg.RedirectURL, Scopes: scopes}
}

// UserScopes : scopes demandés au flot utilisateur.
func UserScopes() []string { return append([]string{gooidc.ScopeOpenID}, APIScopes...) }

// Random : 32 octets aléatoires en base64url (43 caractères).
func Random() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// Tentative : les valeurs neuves d'une demande d'autorisation.
type Tentative struct {
	State, Nonce, Verifier string
	PromptNone             bool
}

// NouvelleTentative : state, nonce et code_verifier neufs.
func NouvelleTentative(promptNone bool) Tentative {
	return Tentative{State: Random(), Nonce: Random(), Verifier: oauth2.GenerateVerifier(), PromptNone: promptNone}
}

// AuthURL : l'adresse d'autorisation, lue dans la Discovery.
func (c *Client) AuthURL(ctx context.Context, t Tentative) (string, error) {
	p, err := c.discovery(ctx)
	if err != nil {
		return "", err
	}
	opts := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(t.Verifier), oauth2.SetAuthURLParam("nonce", t.Nonce)}
	if t.PromptNone {
		opts = append(opts, oauth2.SetAuthURLParam("prompt", "none"))
	}
	return c.oauth(p, UserScopes()).AuthCodeURL(t.State, opts...), nil
}

// CheckCallback contrôle le retour sur redirect_uri : `state` égal octet pour octet, `iss` égal à
// l'issuer, puis `error` éventuel. Retourne le code.
func (c *Client) CheckCallback(q url.Values, t Tentative) (string, error) {
	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(t.State)) != 1 || t.State == "" {
		return "", fmt.Errorf("%w : state", ErrCallback)
	}
	if q.Get("iss") != c.cfg.Issuer {
		return "", fmt.Errorf("%w : iss", ErrCallback)
	}
	if e := q.Get("error"); e != "" {
		return "", &ErrAuthorize{Code: e}
	}
	code := q.Get("code")
	if code == "" {
		return "", fmt.Errorf("%w : code absent", ErrCallback)
	}
	return code, nil
}

// UserToken : ce que la session garde.
type UserToken struct {
	AccessToken string
	Expiry      time.Time
	Sub, Name   string
	Roles       []string
	Scope       string
}

// Exchange échange le code (une seule fois : jamais rejoué après un échec) et vérifie l'id_token.
func (c *Client) Exchange(ctx context.Context, code string, t Tentative) (*UserToken, error) {
	p, err := c.discovery(ctx)
	if err != nil {
		return nil, err
	}
	tok, err := c.oauth(p, UserScopes()).Exchange(c.ctx(ctx), code, oauth2.VerifierOption(t.Verifier))
	if err != nil {
		return nil, fmt.Errorf("échange du code : %w", err)
	}
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		return nil, errors.New("réponse du token_endpoint sans id_token")
	}
	if err := checkTyp(raw); err != nil {
		return nil, err
	}
	v := p.Verifier(&gooidc.Config{ClientID: c.cfg.ClientID, SupportedSigningAlgs: []string{gooidc.RS256}, Now: c.Now})
	idt, err := v.Verify(c.ctx(ctx), raw)
	if err != nil {
		return nil, fmt.Errorf("id_token : %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(t.Nonce)) != 1 {
		return nil, errors.New("id_token : nonce différent de celui de la tentative")
	}
	var claims struct {
		Name  string   `json:"name"`
		Roles []string `json:"roles"`
	}
	if err := idt.Claims(&claims); err != nil {
		return nil, fmt.Errorf("id_token : %w", err)
	}
	scope, _ := tok.Extra("scope").(string)
	granted := strings.Fields(scope)
	var missing []string
	for _, s := range APIScopes {
		if !slices.Contains(granted, s) {
			missing = append(missing, s)
		}
	}
	ut := &UserToken{AccessToken: tok.AccessToken, Expiry: tok.Expiry, Sub: idt.Subject, Name: claims.Name, Roles: claims.Roles, Scope: scope}
	if len(missing) > 0 {
		return ut, &ErrScopeNotGranted{Missing: missing}
	}
	return ut, nil
}

// checkTyp : l'id_token porte `typ: JWT` (un access token `at+jwt` n'est pas un id_token).
func checkTyp(raw string) error {
	h, _, ok := strings.Cut(raw, ".")
	if !ok {
		return errors.New("id_token mal formé")
	}
	b, err := base64.RawURLEncoding.DecodeString(h)
	if err != nil {
		return errors.New("id_token mal formé")
	}
	var hdr struct {
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(b, &hdr); err != nil {
		return errors.New("id_token mal formé")
	}
	if hdr.Typ != "" && !strings.EqualFold(hdr.Typ, "JWT") {
		return fmt.Errorf("id_token : typ %q refusé", hdr.Typ)
	}
	return nil
}

// MachineToken : jeton `client_credentials` réutilisé jusqu'à exp − 30 s (fournisseur-oidc.md § 2.2).
// Tout ou rien : `invalid_scope` ⇒ ErrMachineScope.
func (c *Client) MachineToken(ctx context.Context) (string, error) {
	c.machineMu.Lock()
	defer c.machineMu.Unlock()
	if c.machineTok != "" && c.Now().Before(c.machineExp.Add(-Marge)) {
		return c.machineTok, nil
	}
	p, err := c.discovery(ctx)
	if err != nil {
		return "", err
	}
	cc := &clientcredentials.Config{ClientID: c.cfg.ClientID, ClientSecret: c.cfg.ClientSecret,
		TokenURL: p.Endpoint().TokenURL, Scopes: APIScopes, AuthStyle: oauth2.AuthStyleInHeader}
	tok, err := cc.Token(c.ctx(ctx))
	if err != nil {
		var re *oauth2.RetrieveError
		if errors.As(err, &re) && re.ErrorCode == "invalid_scope" {
			return "", ErrMachineScope
		}
		return "", fmt.Errorf("jeton machine : %w", err)
	}
	c.machineTok, c.machineExp = tok.AccessToken, tok.Expiry
	return tok.AccessToken, nil
}

// ForgetMachineToken : après un 401 de l'API, le jeton machine se redemande au passage suivant.
func (c *Client) ForgetMachineToken() {
	c.machineMu.Lock()
	defer c.machineMu.Unlock()
	c.machineTok = ""
}

// TokenErrorStatus : statut HTTP d'une erreur du token_endpoint (0 si inconnu), pour la relève.
func TokenErrorStatus(err error) int {
	var re *oauth2.RetrieveError
	if errors.As(err, &re) && re.Response != nil {
		return re.Response.StatusCode
	}
	if errors.Is(err, ErrMachineScope) {
		return http.StatusBadRequest
	}
	return 0
}
