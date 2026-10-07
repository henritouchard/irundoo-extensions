package irundoo_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/henritouchard/irundoo-extensions/extensions/centralisation-materiel/internal/fakeirundo"
	"github.com/henritouchard/irundoo-extensions/extensions/centralisation-materiel/internal/irundoo"
)

const (
	idA = "11111111-1111-4111-8111-111111111111"
	idB = "22222222-2222-4222-8222-222222222222"
)

func setup(t *testing.T) (*fakeirundo.Server, *irundoo.Client, string) {
	t.Helper()
	f := fakeirundo.New()
	t.Cleanup(f.Close)
	vm, err := os.ReadFile("../../testdata/hardware/vm.json")
	if err != nil {
		t.Fatal(err)
	}
	f.Instances = []map[string]any{fakeirundo.Instance(idA, "A", "0951234A", true), fakeirundo.Instance(idB, "B", "0951234B", false)}
	f.Hardware = []map[string]any{fakeirundo.Measure(idA, "6f1c2b7e-3a4d-4e5f-8a9b-0c1d2e3f4a5b", time.Now(), vm)}
	c, err := irundoo.New(f.Issuer(), irundoo.NewHTTPClient(), "test")
	if err != nil {
		t.Fatal(err)
	}
	f.Mu.Lock()
	tok := f.Sign("x", nil) // jeton inconnu du serveur : sert aux 401
	f.Mu.Unlock()
	return f, c, tok
}

func machineToken(t *testing.T, f *fakeirundo.Server) string {
	t.Helper()
	return f.IssueToken(true)
}

func TestNominal(t *testing.T) {
	f, c, _ := setup(t)
	tok := machineToken(t, f)
	ins, err := c.Instances(context.Background(), tok)
	if err != nil || len(ins.Instances) != 2 || ins.Instances[1].Active || ins.Reduced {
		t.Fatalf("instances: %+v %v", ins, err)
	}
	hw, err := c.Hardware(context.Background(), tok, "")
	if err != nil || len(hw.Hardware) != 1 {
		t.Fatalf("hardware: %+v %v", hw, err)
	}
	m := hw.Hardware[0]
	if m.InstanceID != idA || m.ExtensionKey != "collectrice-materiel" || m.ReceivedAt.IsZero() || !strings.Contains(string(m.Payload), `"profile"`) {
		t.Fatalf("mesure: %+v", m)
	}
	hw, err = c.Hardware(context.Background(), tok, idB)
	if err != nil || len(hw.Hardware) != 0 {
		t.Fatalf("hardware ?instance=B : %+v %v", hw, err)
	}
	f.Mu.Lock()
	defer f.Mu.Unlock()
	for _, a := range f.APIAuth {
		if a != "Bearer "+tok {
			t.Fatalf("en-tête Authorization inattendu : %q", a)
		}
	}
}

func TestErreursTypees(t *testing.T) {
	f, c, unknown := setup(t)
	tok := machineToken(t, f)
	ctx := context.Background()

	if _, err := c.Instances(ctx, unknown); !errors.Is(err, irundoo.ErrInvalidToken) {
		t.Fatalf("401 invalid_token : %v", err)
	}
	// 401 sans corps (jeton absent côté serveur) : forcé.
	f.Mu.Lock()
	f.Force["hardware"] = &fakeirundo.Forced{Status: 401, Headers: map[string]string{"WWW-Authenticate": `Bearer realm="irundoo-extensions"`}}
	f.Mu.Unlock()
	if _, err := c.Hardware(ctx, tok, ""); !errors.Is(err, irundoo.ErrInvalidToken) {
		t.Fatalf("401 vide : %v", err)
	}
	if _, err := c.Instances(ctx, ""); err == nil {
		t.Fatal("un appel sans jeton doit être refusé avant l'envoi")
	}

	f.Mu.Lock()
	f.MachineScopes = []string{"irundoo:instances:read"}
	f.Mu.Unlock()
	var sc *irundoo.ErrInsufficientScope
	if _, err := c.Hardware(ctx, tok, ""); !errors.As(err, &sc) || sc.Scope != "irundoo:hardware:read" {
		t.Fatalf("403 insufficient_scope : %v", err)
	}
	f.Mu.Lock()
	f.MachineScopes = []string{"irundoo:instances:read", "irundoo:hardware:read"}
	f.Mu.Unlock()

	if _, err := c.Hardware(ctx, tok, "33333333-3333-4333-8333-333333333333"); !errors.Is(err, irundoo.ErrOutOfPerimeter) {
		t.Fatalf("403 out_of_perimeter : %v", err)
	}
	f.Mu.Lock()
	f.PerimeterGone = true
	f.Mu.Unlock()
	if _, err := c.Instances(ctx, tok); !errors.Is(err, irundoo.ErrPerimeterEmpty) {
		t.Fatalf("403 perimeter_empty : %v", err)
	}
	f.Mu.Lock()
	f.PerimeterGone = false
	f.Force["instances"] = &fakeirundo.Forced{Status: 429, Body: `{"error":"rate_limited","error_description":"Too many requests."}`, Headers: map[string]string{"Retry-After": "7"}}
	f.Mu.Unlock()
	var rl *irundoo.ErrRateLimited
	if _, err := c.Instances(ctx, tok); !errors.As(err, &rl) || rl.RetryAfter != 7*time.Second {
		t.Fatalf("429 : %v", err)
	}
	f.Mu.Lock()
	f.Force["instances"] = &fakeirundo.Forced{Status: 503, Body: `{"error":"server_error","error_description":"Token verification is unavailable."}`}
	f.Mu.Unlock()
	if _, err := c.Instances(ctx, tok); !errors.Is(err, irundoo.ErrUnavailable) {
		t.Fatalf("503 : %v", err)
	}
	f.Mu.Lock()
	f.Force["instances"] = &fakeirundo.Forced{Status: 403, Body: `{"error":"nouveau_code","error_description":"x"}`}
	f.Mu.Unlock()
	var ue *irundoo.ErrUnexpected
	if _, err := c.Instances(ctx, tok); !errors.As(err, &ue) || ue.Status != 403 || ue.Code != "nouveau_code" {
		t.Fatalf("code inconnu : %v", err)
	}
	f.Mu.Lock()
	f.Force["instances"] = &fakeirundo.Forced{Status: 200, Body: `{"instances":[`}
	f.Mu.Unlock()
	if _, err := c.Instances(ctx, tok); !errors.As(err, &ue) {
		t.Fatalf("corps illisible : %v", err)
	}
}

func TestLectureBornee(t *testing.T) {
	f, c, _ := setup(t)
	tok := machineToken(t, f)
	f.Mu.Lock()
	f.Force["hardware"] = &fakeirundo.Forced{Status: 200, Body: `{"hardware":[],"reduced":false,"x":"` + strings.Repeat("a", irundoo.MaxBody) + `"}`}
	f.Mu.Unlock()
	var ue *irundoo.ErrUnexpected
	if _, err := c.Hardware(context.Background(), tok, ""); !errors.As(err, &ue) || ue.Code != "corps trop volumineux" {
		t.Fatalf("lecture non bornée : %v", err)
	}
}

func TestDatesTolerantes(t *testing.T) {
	f, c, _ := setup(t)
	tok := machineToken(t, f)
	f.Mu.Lock()
	f.Force["hardware"] = &fakeirundo.Forced{Status: 200, Body: `{"hardware":[{"instance_id":"` + idA + `","extension_key":"k","extension_version":null,"message_id":"m","kind":"hardware/v1","collected_at":"2026-10-07T10:00:00+00:00","received_at":"2026-10-07T10:00:05.123456Z","payload":{}}],"reduced":true}`}
	f.Mu.Unlock()
	hw, err := c.Hardware(context.Background(), tok, "")
	if err != nil || !hw.Reduced || hw.Hardware[0].ExtensionVersion != nil || hw.Hardware[0].CollectedAt.Unix() != time.Date(2026, 10, 7, 10, 0, 0, 0, time.UTC).Unix() {
		t.Fatalf("dates : %+v %v", hw, err)
	}
}

// Une redirection de l'API n'est jamais suivie : le jeton ne part pas vers une autre adresse.
func TestRedirectionNonSuivie(t *testing.T) {
	var recu atomic.Int32
	ailleurs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recu.Add(1)
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"instances":[],"reduced":false}`))
	}))
	defer ailleurs.Close()
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, ailleurs.URL+r.URL.Path, http.StatusFound)
	}))
	defer api.Close()
	c, err := irundoo.New(api.URL, irundoo.NewHTTPClient(), "test")
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Instances(context.Background(), "jeton")
	var ue *irundoo.ErrUnexpected
	if !errors.As(err, &ue) || ue.Status != http.StatusFound {
		t.Fatalf("%v", err)
	}
	if _, err := c.Hardware(context.Background(), "jeton", ""); !errors.As(err, &ue) || ue.Status != http.StatusFound {
		t.Fatalf("%v", err)
	}
	if recu.Load() != 0 {
		t.Fatal("redirection suivie : le jeton est parti ailleurs")
	}
}
