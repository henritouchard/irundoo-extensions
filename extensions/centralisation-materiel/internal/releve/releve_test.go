package releve

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/henritouchard/irundoo-extensions/extensions/centralisation-materiel/internal/fakeirundo"
	"github.com/henritouchard/irundoo-extensions/extensions/centralisation-materiel/internal/irundoo"
	"github.com/henritouchard/irundoo-extensions/extensions/centralisation-materiel/internal/oidc"
	"github.com/henritouchard/irundoo-extensions/extensions/centralisation-materiel/internal/store"
)

const (
	idA = "11111111-1111-4111-8111-111111111111"
	idB = "22222222-2222-4222-8222-222222222222"
)

type env struct {
	f     *fakeirundo.Server
	r     *Runner
	st    *store.Store
	log   *bytes.Buffer
	slept []time.Duration
}

func setup(t *testing.T) *env {
	t.Helper()
	f := fakeirundo.New()
	t.Cleanup(f.Close)
	vm, _ := os.ReadFile("../../testdata/hardware/vm.json")
	f.Instances = []map[string]any{fakeirundo.Instance(idA, "A", "0951234A", true), fakeirundo.Instance(idB, "B", "0951234B", true)}
	f.Hardware = []map[string]any{fakeirundo.Measure(idA, "6f1c2b7e-3a4d-4e5f-8a9b-0c1d2e3f4a5b", time.Now(), vm)}
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	hc := irundoo.NewHTTPClient()
	api, _ := irundoo.New(f.Issuer(), hc, "test")
	oc := oidc.New(oidc.Config{Issuer: f.Issuer(), ClientID: f.ClientID, ClientSecret: f.ClientSecret, RedirectURL: "http://127.0.0.1:8090/oidc/callback", HTTPClient: hc})
	e := &env{f: f, st: st, log: &bytes.Buffer{}}
	e.r = &Runner{Tokens: oc, API: api, Store: st, Log: slog.New(slog.NewJSONHandler(e.log, nil)), Interval: time.Minute,
		StaleAfter: 30 * time.Minute, Retention: 180, Sleep: func(_ context.Context, d time.Duration) { e.slept = append(e.slept, d) }}
	return e
}

func (e *env) calls(k string) int {
	e.f.Mu.Lock()
	defer e.f.Mu.Unlock()
	return e.f.Calls[k]
}

func TestPassageNominalEtRejeu(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	rel := e.r.Pass(ctx)
	if rel.Status != "ok" || rel.Instances != 2 || rel.Inserted != 1 {
		t.Fatalf("%+v", rel)
	}
	// Second passage : même message_id ⇒ aucune ligne nouvelle ; jeton machine réutilisé.
	rel = e.r.Pass(ctx)
	if rel.Status != "ok" || rel.Inserted != 0 {
		t.Fatalf("rejeu inséré : %+v", rel)
	}
	if n, _ := e.st.CountMeasurements(ctx, idA); n != 1 {
		t.Fatal(n)
	}
	if e.calls("token:client_credentials") != 1 || e.calls("instances") != 2 || e.calls("hardware") != 2 {
		t.Fatalf("appels : %v", e.f.Calls)
	}
	// Nouvelle mesure ⇒ une ligne de plus, état calculé et consigné.
	phys, _ := os.ReadFile("../../testdata/hardware/physical.json")
	e.f.Mu.Lock()
	e.f.Hardware = append(e.f.Hardware, fakeirundo.Measure(idB, "0b8e7d6c-5f4a-4b3c-9d2e-1f0a9b8c7d6e", time.Now(), phys))
	e.f.Mu.Unlock()
	if rel = e.r.Pass(ctx); rel.Inserted != 1 {
		t.Fatalf("%+v", rel)
	}
	st, _ := e.st.LastReleves(ctx)
	if st.LastOK == nil || st.LastEchec != nil {
		t.Fatalf("%+v", st)
	}
	if strings.Contains(e.log.String(), "eyJ") || strings.Contains(e.log.String(), e.f.ClientSecret) {
		t.Fatal("jeton ou secret dans le journal")
	}
}

func TestInstanceDisparueGardeSonHistorique(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	e.r.Pass(ctx)
	e.f.Mu.Lock()
	e.f.Instances = e.f.Instances[1:] // A sort du périmètre
	e.f.Hardware = nil
	e.f.Reduced = true
	e.f.Mu.Unlock()
	if rel := e.r.Pass(ctx); rel.Status != "ok" || rel.Instances != 1 {
		t.Fatalf("%+v", rel)
	}
	if n, _ := e.st.CountMeasurements(ctx, idA); n != 1 {
		t.Fatal("l'historique d'une instance sortie du périmètre est conservé (NFR11)")
	}
}

func TestMesureHorsInstancesIgnoree(t *testing.T) {
	e := setup(t)
	e.f.Mu.Lock()
	e.f.Hardware = append(e.f.Hardware, fakeirundo.Measure("33333333-3333-4333-8333-333333333333", "m", time.Now(), []byte(`{}`)))
	e.f.Mu.Unlock()
	if rel := e.r.Pass(context.Background()); rel.Inserted != 1 {
		t.Fatalf("%+v", rel)
	}
}

func TestEchecs(t *testing.T) {
	cas := []struct {
		nom     string
		prepare func(f *fakeirundo.Server)
		http    int
		motif   string
		hw      int // appels /hardware attendus
	}{
		{"scopes machine non accordés", func(f *fakeirundo.Server) { f.MachineScopes = []string{"irundoo:instances:read"} }, 400, "scopes machine non accordés", 0},
		{"429", func(f *fakeirundo.Server) {
			f.Force["instances"] = &fakeirundo.Forced{Status: 429, Body: `{"error":"rate_limited","error_description":"Too many requests."}`, Headers: map[string]string{"Retry-After": "12"}}
		}, 429, "quota", 0},
		{"503", func(f *fakeirundo.Server) {
			f.Force["hardware"] = &fakeirundo.Forced{Status: 503, Body: `{"error":"server_error","error_description":"Token verification is unavailable."}`}
		}, 503, "IRUNDO indisponible", 1},
		{"périmètre vide", func(f *fakeirundo.Server) { f.PerimeterGone = true }, 403, "aucun établissement accordé", 0},
		{"scope retiré", func(f *fakeirundo.Server) {
			f.Force["hardware"] = &fakeirundo.Forced{Status: 403, Body: `{"error":"insufficient_scope","error_description":"x","scope":"irundoo:hardware:read"}`}
		}, 403, "droit machine non accordé : irundoo:hardware:read", 1},
		{"401", func(f *fakeirundo.Server) {
			f.Force["instances"] = &fakeirundo.Forced{Status: 401, Body: `{"error":"invalid_token","error_description":"x"}`}
		}, 401, "redemandé au passage suivant", 0},
		{"500", func(f *fakeirundo.Server) { f.Force["instances"] = &fakeirundo.Forced{Status: 500, Body: `{}`} }, 500, "inattendue 500", 0},
		{"jeton refusé à /oidc/token", func(f *fakeirundo.Server) { f.ClientSecret = "autre" }, 401, "jeton machine", 0},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			e := setup(t)
			e.f.Mu.Lock()
			c.prepare(e.f)
			e.f.Mu.Unlock()
			rel := e.r.Pass(context.Background())
			if rel.Status != "echec" || rel.HTTPStatus != c.http || !strings.Contains(rel.Motif, c.motif) {
				t.Fatalf("%+v", rel)
			}
			if e.calls("hardware") != c.hw || e.calls("instances") > 1 || e.calls("token:client_credentials") > 1 {
				t.Fatalf("pas de rafale : %v", e.f.Calls)
			}
			st, _ := e.st.LastReleves(context.Background())
			if st.LastEchec == nil || st.EchecDepuis == nil {
				t.Fatal("échec non consigné")
			}
			if c.http == 429 && (len(e.slept) != 1 || e.slept[0] != 12*time.Second) {
				t.Fatalf("Retry-After non respecté : %v", e.slept)
			}
		})
	}
}

func TestApres401LeJetonEstRedemande(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	e.r.Pass(ctx)
	e.f.Revoke()
	if rel := e.r.Pass(ctx); rel.HTTPStatus != 401 {
		t.Fatalf("%+v", rel)
	}
	if rel := e.r.Pass(ctx); rel.Status != "ok" {
		t.Fatalf("%+v", rel)
	}
	if n := e.calls("token:client_credentials"); n != 2 {
		t.Fatalf("jetons demandés : %d", n)
	}
}

func TestRunEtArret(t *testing.T) {
	e := setup(t)
	e.r.Interval = 20 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.r.Run(ctx); close(done) }()
	deadline := time.Now().Add(2 * time.Second)
	for e.calls("hardware") < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("arrêt non propre")
	}
	if e.calls("hardware") < 2 {
		t.Fatal("la relève ne tourne pas")
	}
	e.r.Interval = 0
	e.r.Run(context.Background()) // désactivée : rend la main aussitôt
	if !strings.Contains(e.log.String(), "relève désactivée") || !strings.Contains(e.log.String(), "purge locale") {
		t.Fatal(e.log.String())
	}
}
