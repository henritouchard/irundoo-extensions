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
	f   *fakeirundo.Server
	r   *Runner
	st  *store.Store
	log *bytes.Buffer
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
		StaleAfter: 30 * time.Minute, Retention: 180}
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
		{"401 sur jeton neuf : pas de rejeu, arrêt", func(f *fakeirundo.Server) {
			f.Force["instances"] = &fakeirundo.Forced{Status: 401, Body: `{"error":"invalid_token","error_description":"x"}`}
		}, 401, "jeton machine neuf refusé par l'API (401) — relève arrêtée jusqu'au redémarrage", 0},
		{"500", func(f *fakeirundo.Server) { f.Force["instances"] = &fakeirundo.Forced{Status: 500, Body: `{}`} }, 500, "inattendue 500", 0},
		{"invalid_client à /oidc/token : arrêt", func(f *fakeirundo.Server) { f.ClientSecret = "autre" }, 401, "invalid_client", 0},
		{"autre refus du token_endpoint", func(f *fakeirundo.Server) {
			f.Force["token"] = &fakeirundo.Forced{Status: 400, Body: `{"error":"invalid_request","error_description":"x"}`}
		}, 400, "jeton machine refusé : token_endpoint : HTTP 400 (invalid_request)", 0},
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
			if c.http == 429 && !strings.Contains(rel.Motif, "Retry-After (12 s)") {
				t.Fatalf("Retry-After non noté : %+v", rel)
			}
			arret := c.http == 401
			if (e.r.Arret() != "") != arret {
				t.Fatalf("arrêt %q, attendu %v", e.r.Arret(), arret)
			}
		})
	}
}

// § 11.5 : un 401 sur un jeton du cache ⇒ un jeton neuf et un seul rejeu, dans le même passage.
func TestApres401SurJetonDuCacheUnSeulRejeu(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	e.r.Pass(ctx)
	e.f.Revoke()
	if rel := e.r.Pass(ctx); rel.Status != "ok" || rel.Instances != 2 {
		t.Fatalf("%+v", rel)
	}
	if e.calls("token:client_credentials") != 2 || e.calls("instances") != 3 || e.calls("hardware") != 2 {
		t.Fatalf("appels : %v", e.f.Calls)
	}
	st, _ := e.st.LastReleves(ctx)
	if st.LastEchec != nil {
		t.Fatal("le rejeu réussi n'est pas un échec")
	}
}

// Second 401 consécutif (jeton neuf refusé après le rejeu) ⇒ consigné, puis la relève cesse :
// plus aucun appel aux intervalles suivants ; elle reprend au redémarrage du service.
func TestSecond401ArreteLaReleve(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	e.r.Pass(ctx)
	e.f.Mu.Lock()
	e.f.Force["hardware"] = &fakeirundo.Forced{Status: 401, Body: `{"error":"invalid_token","error_description":"x"}`, Sticky: true}
	e.f.Mu.Unlock()
	rel := e.r.Pass(ctx)
	if rel.Status != "echec" || rel.HTTPStatus != 401 || !strings.Contains(rel.Motif, "relève arrêtée jusqu'au redémarrage") {
		t.Fatalf("%+v", rel)
	}
	if e.calls("token:client_credentials") != 2 || e.calls("hardware") != 3 {
		t.Fatalf("appels : %v", e.f.Calls)
	}
	avant := map[string]int{"token:client_credentials": e.calls("token:client_credentials"), "instances": e.calls("instances"), "hardware": e.calls("hardware")}
	for range 3 {
		if rel := e.r.Pass(ctx); rel.Status != StatutArretee {
			t.Fatalf("%+v", rel)
		}
	}
	for k, n := range avant {
		if e.calls(k) != n {
			t.Fatalf("appel %s après l'arrêt : %v", k, e.f.Calls)
		}
	}
	st, _ := e.st.LastReleves(ctx)
	if st.LastEchec == nil || !strings.Contains(st.LastEchec.Motif, "relève arrêtée") {
		t.Fatalf("%+v", st)
	}
	if !strings.Contains(e.log.String(), "relève arrêtée jusqu'au redémarrage du service") {
		t.Fatal(e.log.String())
	}
	// Redémarrage : un Runner neuf repart.
	e.f.Mu.Lock()
	delete(e.f.Force, "hardware")
	e.f.Mu.Unlock()
	r2 := *e.r
	r2.arret = ""
	if rel := r2.Pass(ctx); rel.Status != "ok" {
		t.Fatalf("%+v", rel)
	}
}

// 429 : le passage s'abandonne aussitôt (aucun sommeil), le suivant attend Retry-After.
func Test429PassageSuivantDiffere(t *testing.T) {
	e := setup(t)
	t0 := time.Now()
	e.r.Now = func() time.Time { return t0 }
	e.f.Mu.Lock()
	e.f.Force["instances"] = &fakeirundo.Forced{Status: 429, Body: `{"error":"rate_limited"}`, Headers: map[string]string{"Retry-After": "30"}}
	e.f.Mu.Unlock()
	debut := time.Now()
	if rel := e.r.Pass(context.Background()); rel.HTTPStatus != 429 {
		t.Fatalf("%+v", rel)
	}
	if time.Since(debut) > 5*time.Second {
		t.Fatal("sommeil dans le passage")
	}
	if rel := e.r.Pass(context.Background()); rel.Status != StatutSautee || e.calls("instances") != 1 {
		t.Fatalf("%+v %v", rel, e.f.Calls)
	}
	e.r.Now = func() time.Time { return t0.Add(31 * time.Second) }
	if rel := e.r.Pass(context.Background()); rel.Status != "ok" {
		t.Fatalf("%+v", rel)
	}
}

// SIGTERM pendant un passage : pas d'échec consigné.
func TestArretDuServiceNEstPasUnEchec(t *testing.T) {
	e := setup(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if rel := e.r.Pass(ctx); rel.Status != StatutInterrompue {
		t.Fatalf("%+v", rel)
	}
	st, _ := e.st.LastReleves(context.Background())
	if st.LastEchec != nil || st.LastOK != nil {
		t.Fatalf("passage interrompu consigné : %+v", st)
	}
	if e.r.Arret() != "" {
		t.Fatal("arrêt sur interruption")
	}
}

// Le corps d'une erreur du token_endpoint n'est ni consigné ni journalisé : il pourrait contenir
// n'importe quoi (ici le secret client et un jeton). Pas plus le secret dans le journal de la relève.
func TestAucunSecretDansLeJournalNiLeMotif(t *testing.T) {
	for _, status := range []int{400, 401, 500} {
		e := setup(t)
		e.f.Mu.Lock()
		e.f.Force["token"] = &fakeirundo.Forced{Status: status,
			Body: `{"error":"invalid_request\u0000` + e.f.ClientSecret + `","error_description":"` + e.f.ClientSecret + ` eyJhbGciOi"}`}
		e.f.Mu.Unlock()
		rel := e.r.Pass(context.Background())
		st, _ := e.st.LastReleves(context.Background())
		for _, out := range []string{rel.Motif, st.LastEchec.Motif, e.log.String()} {
			if strings.Contains(out, e.f.ClientSecret[:8]) || strings.Contains(out, "eyJ") || strings.Contains(out, "\x00") {
				t.Fatalf("%d : secret ou corps brut : %s", status, out)
			}
		}
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
