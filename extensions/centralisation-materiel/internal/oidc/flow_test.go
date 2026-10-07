package oidc

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/henritouchard/irundoo-extensions/extensions/centralisation-materiel/internal/fakeirundo"
)

const redirect = "http://127.0.0.1:8090/oidc/callback"

func setup(t *testing.T) (*fakeirundo.Server, *Client) {
	t.Helper()
	f := fakeirundo.New()
	t.Cleanup(f.Close)
	f.RedirectURIs = []string{redirect}
	hc := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return f, New(Config{Issuer: f.Issuer(), ClientID: f.ClientID, ClientSecret: f.ClientSecret, RedirectURL: redirect, HTTPClient: hc})
}

// navigue suit /oidc/authorize comme un navigateur et rend la query du retour sur redirect_uri.
func navigue(t *testing.T, c *Client, tt Tentative) url.Values {
	t.Helper()
	u, err := c.AuthURL(context.Background(), tt)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.cfg.HTTPClient.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize : %d", resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if !strings.HasPrefix(loc.String(), redirect+"?") {
		t.Fatalf("retour vers %s", loc)
	}
	return loc.Query()
}

func TestAuthURL(t *testing.T) {
	f, c := setup(t)
	a, b := NouvelleTentative(false), NouvelleTentative(true)
	if a.State == b.State || a.Nonce == b.Nonce || a.Verifier == b.Verifier || len(a.Verifier) < 43 {
		t.Fatal("valeurs non neuves")
	}
	navigue(t, c, a)
	navigue(t, c, b)
	f.Mu.Lock()
	defer f.Mu.Unlock()
	q := f.AuthorizeQuery[0]
	want := map[string]string{"response_type": "code", "client_id": f.ClientID, "redirect_uri": redirect,
		"scope": "openid irundoo:instances:read irundoo:hardware:read", "code_challenge_method": "S256",
		"state": a.State, "nonce": a.Nonce}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("%s = %q, attendu %q", k, q.Get(k), v)
		}
	}
	if len(q.Get("code_challenge")) != 43 || q.Has("prompt") || q.Has("max_age") {
		t.Fatalf("challenge/prompt : %v", q)
	}
	if f.AuthorizeQuery[1].Get("prompt") != "none" {
		t.Fatal("prompt=none attendu au renouvellement")
	}
}

func TestFlotNominal(t *testing.T) {
	f, c := setup(t)
	tt := NouvelleTentative(false)
	q := navigue(t, c, tt)
	code, err := c.CheckCallback(q, tt)
	if err != nil {
		t.Fatal(err)
	}
	ut, err := c.Exchange(context.Background(), code, tt)
	if err != nil {
		t.Fatal(err)
	}
	if ut.Sub != "42" || ut.Name != "Ada Lovelace" || !slices.Equal(ut.Roles, []string{"admin"}) || ut.AccessToken == "" ||
		ut.Expiry.Before(time.Now().Add(14*time.Minute)) {
		t.Fatalf("%+v", ut)
	}
	f.Mu.Lock()
	form, auth := f.TokenForms[0], f.TokenAuth[0]
	f.Mu.Unlock()
	if form.Has("client_id") || form.Has("client_secret") {
		t.Fatalf("client_secret_basic seul : %v", form)
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte(f.ClientID+":"+f.ClientSecret))
	if auth != want || form.Get("code_verifier") != tt.Verifier || form.Get("redirect_uri") != redirect || form.Get("grant_type") != "authorization_code" {
		t.Fatalf("échange : %q %v", auth, form)
	}
	// Un code ne se rejoue pas.
	_, err = c.Exchange(context.Background(), code, tt)
	if err == nil || !strings.Contains(err.Error(), "invalid_grant") {
		t.Fatalf("rejeu du code accepté : %v", err)
	}
}

func TestRetourInvalide(t *testing.T) {
	f, c := setup(t)
	tt := NouvelleTentative(false)
	q := navigue(t, c, tt)
	bad := url.Values{}
	for k, v := range q {
		bad[k] = v
	}
	bad.Set("state", tt.State+"x")
	if _, err := c.CheckCallback(bad, tt); !errors.Is(err, ErrCallback) {
		t.Fatal("state différent accepté")
	}
	bad.Set("state", tt.State)
	bad.Set("iss", "https://ailleurs.example.org")
	if _, err := c.CheckCallback(bad, tt); !errors.Is(err, ErrCallback) {
		t.Fatal("iss différent accepté")
	}
	f.Mu.Lock()
	f.OmitIss = true
	f.Mu.Unlock()
	q = navigue(t, c, tt)
	if _, err := c.CheckCallback(q, tt); !errors.Is(err, ErrCallback) {
		t.Fatal("iss absent accepté")
	}
	if _, err := c.CheckCallback(url.Values{"state": {tt.State}, "iss": {f.Issuer()}}, tt); !errors.Is(err, ErrCallback) {
		t.Fatal("code absent accepté")
	}
}

func TestNonceFaux(t *testing.T) {
	f, c := setup(t)
	f.IDTokenNonceOverride = "autre"
	tt := NouvelleTentative(false)
	code, err := c.CheckCallback(navigue(t, c, tt), tt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Exchange(context.Background(), code, tt); err == nil || !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("nonce faux accepté : %v", err)
	}
}

func TestScopeNonAccorde(t *testing.T) {
	f, c := setup(t)
	f.UserScopes = []string{"irundoo:instances:read"}
	tt := NouvelleTentative(false)
	code, _ := c.CheckCallback(navigue(t, c, tt), tt)
	_, err := c.Exchange(context.Background(), code, tt)
	var sng *ErrScopeNotGranted
	if !errors.As(err, &sng) || !slices.Equal(sng.Missing, []string{"irundoo:hardware:read"}) {
		t.Fatalf("downscoping non détecté : %v", err)
	}
}

func TestLoginRequiredEtAccessDenied(t *testing.T) {
	f, c := setup(t)
	f.LoggedIn = false
	tt := NouvelleTentative(true)
	var ea *ErrAuthorize
	if _, err := c.CheckCallback(navigue(t, c, tt), tt); !errors.As(err, &ea) || ea.Code != "login_required" {
		t.Fatalf("%v", err)
	}
	f.Mu.Lock()
	f.LoggedIn, f.AccessDenied = true, true
	f.Mu.Unlock()
	tt = NouvelleTentative(false)
	if _, err := c.CheckCallback(navigue(t, c, tt), tt); !errors.As(err, &ea) || ea.Code != "access_denied" {
		t.Fatalf("%v", err)
	}
}

func TestIssuerDifferent(t *testing.T) {
	f, c := setup(t)
	c.cfg.Issuer = f.Issuer() + "/"
	if _, err := c.AuthURL(context.Background(), NouvelleTentative(false)); err == nil {
		t.Fatal("issuer différent de la Discovery accepté")
	}
}

func TestDiscoveryEnCache(t *testing.T) {
	f, c := setup(t)
	if _, err := c.AuthURL(context.Background(), NouvelleTentative(false)); err != nil {
		t.Fatal(err)
	}
	c.cfg.HTTPClient.CloseIdleConnections()
	f.Close() // IRUNDO injoignable : la Discovery en cache suffit à construire l'adresse
	if _, err := c.AuthURL(context.Background(), NouvelleTentative(false)); err != nil {
		t.Fatal(err)
	}
	c.Now = func() time.Time { return time.Now().Add(DiscoveryTTL + time.Minute) }
	if _, err := c.AuthURL(context.Background(), NouvelleTentative(false)); err == nil {
		t.Fatal("Discovery périmée non relue")
	}
}

func TestTypIDToken(t *testing.T) {
	if err := checkTyp("x"); err == nil {
		t.Fatal()
	}
	if err := checkTyp("!!!.x.y"); err == nil {
		t.Fatal()
	}
	at := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"at+jwt","alg":"RS256"}`))
	if err := checkTyp(at + ".x.y"); err == nil {
		t.Fatal("un access token présenté comme id_token")
	}
	nonJSON := base64.RawURLEncoding.EncodeToString([]byte(`pas du json`))
	if err := checkTyp(nonJSON + ".x.y"); err == nil {
		t.Fatal()
	}
}

func TestJetonMachine(t *testing.T) {
	f, c := setup(t)
	ctx := context.Background()
	t1, err := c.MachineToken(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t2, _ := c.MachineToken(ctx)
	f.Mu.Lock()
	n := f.Calls["token:client_credentials"]
	form, auth := f.TokenForms[0], f.TokenAuth[0]
	f.Mu.Unlock()
	if t1 != t2 || n != 1 {
		t.Fatalf("jeton non réutilisé : %d appels", n)
	}
	if form.Get("scope") != "irundoo:instances:read irundoo:hardware:read" || form.Has("client_id") || !strings.HasPrefix(auth, "Basic ") {
		t.Fatalf("demande : %v %q", form, auth)
	}
	// Proche de l'échéance (marge 30 s) : redemandé.
	c.Now = func() time.Time { return time.Now().Add(900*time.Second - 20*time.Second) }
	t3, _ := c.MachineToken(ctx)
	c.Now = time.Now
	if t3 == t1 {
		t.Fatal("jeton à moins de 30 s de son échéance réutilisé")
	}
	c.ForgetMachineToken()
	if _, err := c.MachineToken(ctx); err != nil {
		t.Fatal(err)
	}
	f.Mu.Lock()
	n = f.Calls["token:client_credentials"]
	f.MachineScopes = []string{"irundoo:instances:read"}
	f.Mu.Unlock()
	if n != 3 {
		t.Fatalf("%d", n)
	}
	c.ForgetMachineToken()
	if _, err := c.MachineToken(ctx); !errors.Is(err, ErrMachineScope) || TokenErrorStatus(err) != 400 {
		t.Fatalf("invalid_scope : %v", err)
	}
	f.Mu.Lock()
	f.ClientSecret = "autre"
	f.Mu.Unlock()
	if _, err := c.MachineToken(ctx); err == nil || TokenErrorStatus(err) != 401 {
		t.Fatalf("invalid_client : %v", err)
	}
}
