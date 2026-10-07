package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func open(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, dir
}

func TestFichier0600EtMigrationsIdempotentes(t *testing.T) {
	s, dir := open(t)
	ctx := context.Background()
	if err := s.Healthy(ctx); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(dir, FileName))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("permissions %v %v", st.Mode().Perm(), err)
	}
	if err := s.UpsertInstance(ctx, Instance{ID: "a", Name: "A", Active: true}); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	// Ouvrir une seconde fois : les migrations ne se rejouent pas, les données restent.
	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if err := s2.Healthy(ctx); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := s2.r.QueryRow(`SELECT count(*) FROM instances`).Scan(&n); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if st, err := os.Stat(filepath.Join(dir, FileName+suffix)); err == nil && st.Mode().Perm()&0o077 != 0 {
			t.Fatalf("%s lisible par d'autres : %v", suffix, st.Mode().Perm())
		}
	}
}

func TestSchemaPerime(t *testing.T) {
	s, _ := open(t)
	if _, err := s.w.Exec(`PRAGMA user_version = 99`); err != nil {
		t.Fatal(err)
	}
	if err := s.Healthy(context.Background()); err == nil {
		t.Fatal("un schéma qui n'est pas celui attendu doit rendre la santé en échec")
	}
}

func TestInsertUniqueEtHistorique(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	base := time.Date(2026, 10, 7, 10, 0, 0, 0, time.UTC)
	m := func(id string, rec time.Time, boot string) Measure {
		return Measure{InstanceID: "a", ExtensionKey: "collectrice-materiel", MessageID: id, Kind: "hardware/v1",
			CollectedAt: rec, ReceivedAt: rec, Payload: []byte(`{"b": 1, "a": 2}`), Etat: "sain", BootID: boot,
			Signaux: []byte(`[{"niveau":"attention","cle":"fs[/].used_b","message":"volume / plein à 91 %"}]`)}
	}
	_ = s.UpsertInstance(ctx, Instance{ID: "a", Name: "A", Active: true})
	for i, c := range []struct {
		id   string
		boot string
		ok   bool
	}{{"m1", "b1", true}, {"m2", "b1", true}, {"m1", "b1", false}, {"m3", "b2", true}} {
		ok, err := s.Insert(ctx, m(c.id, base.Add(time.Duration(i)*time.Minute), c.boot))
		if err != nil || ok != c.ok {
			t.Fatalf("%s : %v %v", c.id, ok, err)
		}
	}
	n, _ := s.CountMeasurements(ctx, "a")
	if n != 3 {
		t.Fatalf("rejeu inséré : %d", n)
	}
	var payload, lastBoot string
	_ = s.r.QueryRow(`SELECT payload FROM measurements WHERE message_id = 'm1'`).Scan(&payload)
	_ = s.r.QueryRow(`SELECT last_boot_id FROM instances WHERE id = 'a'`).Scan(&lastBoot)
	if payload != `{"b": 1, "a": 2}` || lastBoot != "b2" {
		t.Fatalf("payload non conservé tel que servi (%q) ou boot (%q)", payload, lastBoot)
	}
	h, err := s.History(ctx, "a", base.Add(-time.Hour))
	if err != nil || h.Count != 3 || !h.First.Equal(base) || len(h.BootChanges) != 1 || !h.BootChanges[0].Equal(base.Add(3*time.Minute)) {
		t.Fatalf("historique %+v %v", h, err)
	}
	if len(h.SignauxPasses) != 1 || !h.SignauxPasses[0].Vu.Equal(base.Add(3*time.Minute)) {
		t.Fatalf("signaux passés %+v", h.SignauxPasses)
	}
}

func TestPurge(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 7, 10, 0, 0, 0, time.UTC)
	s.Now = func() time.Time { return now }
	for i, age := range []int{200, 181, 10} {
		rec := now.AddDate(0, 0, -age)
		if _, err := s.Insert(ctx, Measure{InstanceID: "a", ExtensionKey: "k", MessageID: string(rune('a' + i)), Kind: "hardware/v1",
			CollectedAt: rec, ReceivedAt: rec, Payload: []byte(`{}`), Etat: "sain"}); err != nil {
			t.Fatal(err)
		}
		_ = s.RecordReleve(ctx, Releve{StartedAt: rec, FinishedAt: rec, Status: "ok"})
	}
	_ = s.CreateSession(ctx, Session{ID: "vieille", AccessToken: "x", TokenExp: now})
	_ = s.CreateAttempt(ctx, Attempt{ID: "t", State: "s", Nonce: "n", Verifier: "v"})
	s.Now = func() time.Time { return now.Add(13 * time.Hour) }
	n, err := s.Prune(ctx, 180)
	if err != nil || n != 2 {
		t.Fatalf("purge %d %v", n, err)
	}
	c, _ := s.CountMeasurements(ctx, "a")
	var r, se, at int
	_ = s.r.QueryRow(`SELECT count(*) FROM releves`).Scan(&r)
	_ = s.r.QueryRow(`SELECT count(*) FROM sessions`).Scan(&se)
	_ = s.r.QueryRow(`SELECT count(*) FROM attempts`).Scan(&at)
	if c != 1 || r != 1 || se != 0 || at != 0 {
		t.Fatalf("après purge : mesures %d relèves %d sessions %d tentatives %d", c, r, se, at)
	}
}

func TestReleves(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	st, err := s.LastReleves(ctx)
	if err != nil || st.LastOK != nil || st.LastEchec != nil {
		t.Fatal(st, err)
	}
	t0 := time.Date(2026, 10, 7, 10, 0, 0, 0, time.UTC)
	_ = s.RecordReleve(ctx, Releve{StartedAt: t0, FinishedAt: t0, Status: "ok", Instances: 2, Inserted: 1})
	_ = s.RecordReleve(ctx, Releve{StartedAt: t0.Add(time.Minute), FinishedAt: t0.Add(time.Minute), Status: "echec", HTTPStatus: 400, Motif: "scopes machine non accordés"})
	_ = s.RecordReleve(ctx, Releve{StartedAt: t0.Add(2 * time.Minute), FinishedAt: t0.Add(2 * time.Minute), Status: "echec", Motif: "x"})
	st, _ = s.LastReleves(ctx)
	if st.LastOK == nil || st.LastOK.Inserted != 1 || st.LastEchec.Motif != "x" || st.EchecDepuis == nil || !st.EchecDepuis.Equal(t0.Add(time.Minute)) {
		t.Fatalf("%+v", st)
	}
	_ = s.RecordReleve(ctx, Releve{StartedAt: t0.Add(3 * time.Minute), FinishedAt: t0.Add(3 * time.Minute), Status: "ok"})
	st, _ = s.LastReleves(ctx)
	if st.EchecDepuis != nil {
		t.Fatal("un succès clôt la série d'échecs")
	}
}

func TestSessionsEtTentatives(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 7, 10, 0, 0, 0, time.UTC)
	s.Now = func() time.Time { return now }
	se := Session{ID: "sid", Sub: "42", Name: "Ada", Roles: []string{"admin", "technicien"}, AccessToken: "at", TokenExp: now.Add(15 * time.Minute), Scope: "openid x"}
	if err := s.CreateSession(ctx, se); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetSession(ctx, "sid")
	if err != nil || got == nil || got.Name != "Ada" || len(got.Roles) != 2 || !got.TokenExp.Equal(se.TokenExp) {
		t.Fatalf("%+v %v", got, err)
	}
	if got, _ := s.GetSession(ctx, "inconnue"); got != nil {
		t.Fatal("session inconnue")
	}
	_ = s.DeleteSession(ctx, "sid")
	if got, _ := s.GetSession(ctx, "sid"); got != nil {
		t.Fatal("session non effacée")
	}
	_ = s.CreateAttempt(ctx, Attempt{ID: "t1", State: "st", Nonce: "no", Verifier: "ve", PromptNone: true})
	a, err := s.TakeAttempt(ctx, "t1")
	if err != nil || a == nil || !a.PromptNone || a.State != "st" {
		t.Fatalf("%+v %v", a, err)
	}
	if a, _ := s.TakeAttempt(ctx, "t1"); a != nil {
		t.Fatal("tentative à usage unique")
	}
	_ = s.CreateAttempt(ctx, Attempt{ID: "t2", State: "st", Nonce: "no", Verifier: "ve"})
	s.Now = func() time.Time { return now.Add(6 * time.Minute) }
	if a, _ := s.TakeAttempt(ctx, "t2"); a != nil {
		t.Fatal("tentative périmée acceptée")
	}
	_ = s.CreateSession(ctx, Session{ID: "s2", AccessToken: "x", TokenExp: now})
	s.Now = func() time.Time { return now.Add(6*time.Minute + SessionIdle + time.Minute) }
	if got, _ := s.GetSession(ctx, "s2"); got != nil {
		t.Fatal("session inactive acceptée")
	}
}

// Horodatages à largeur fixe : l'ordre lexical est l'ordre chronologique, y compris entre une
// seconde ronde (« …05Z » en RFC3339Nano) et la même seconde plus 100 ms (« …05.1Z »).
func TestTriHorodatagesLargeurFixe(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	t0 := time.Date(2026, 10, 7, 10, 0, 5, 0, time.UTC)
	for i, d := range []time.Duration{100 * time.Millisecond, 0, 2 * time.Second} {
		if _, err := s.Insert(ctx, Measure{InstanceID: "a", ExtensionKey: "k", MessageID: string(rune('a' + i)), Kind: "hardware/v1",
			CollectedAt: t0.Add(d), ReceivedAt: t0.Add(d), Payload: []byte(`{}`), Etat: "sain"}); err != nil {
			t.Fatal(err)
		}
	}
	h, err := s.History(ctx, "a", t0)
	if err != nil || h.Count != 3 || !h.First.Equal(t0) || !h.Last.Equal(t0.Add(2*time.Second)) {
		t.Fatalf("%+v %v", h, err)
	}
	var v string
	_ = s.r.QueryRow(`SELECT received_at FROM measurements WHERE message_id = 'b'`).Scan(&v)
	if v != "2026-10-07T10:00:05.000000000Z" {
		t.Fatal(v)
	}
}

// Migration 0002 : les valeurs écrites par la 0.1.0 (RFC3339Nano, zéros finaux retirés) sont
// réécrites en largeur fixe.
func TestMigrationHorodatages(t *testing.T) {
	s, dir := open(t)
	ctx := context.Background()
	if _, err := s.w.Exec(`PRAGMA user_version = 1`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.w.Exec(`INSERT INTO releves (started_at, finished_at, status, instances_count, measurements_inserted)
		VALUES ('2026-10-07T10:00:05Z', '2026-10-07T10:00:05.1Z', 'ok', 0, 0)`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.w.Exec(`INSERT INTO attempts (id, state, nonce, verifier, prompt_none, relance, created_at)
		VALUES ('x', 's', 'n', 'v', 0, 0, 'illisible')`); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	var a, b, c string
	_ = s2.r.QueryRow(`SELECT started_at, finished_at FROM releves`).Scan(&a, &b)
	_ = s2.r.QueryRow(`SELECT created_at FROM attempts`).Scan(&c)
	if a != "2026-10-07T10:00:05.000000000Z" || b != "2026-10-07T10:00:05.100000000Z" || c != "illisible" {
		t.Fatal(a, b, c)
	}
	if err := s2.Healthy(ctx); err != nil {
		t.Fatal(err)
	}
}

// Les tentatives OIDC (créées sans authentification) sont plafonnées ; les expirées sont purgées
// à l'insertion.
func TestPlafondTentatives(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	t0 := time.Now()
	s.Now = func() time.Time { return t0 }
	tx, _ := s.w.Begin()
	for i := 0; i < DefaultMaxAttempts; i++ {
		if _, err := tx.Exec(`INSERT INTO attempts (id, state, nonce, verifier, prompt_none, relance, created_at) VALUES (?, 's', 'n', 'v', 0, 0, ?)`,
			"t"+strconv.Itoa(i), fmtT(t0)); err != nil {
			t.Fatal(err)
		}
	}
	_ = tx.Commit()
	if err := s.CreateAttempt(ctx, Attempt{ID: "neuve", State: "s"}); !errors.Is(err, ErrTropDeTentatives) {
		t.Fatal(err)
	}
	s.Now = func() time.Time { return t0.Add(AttemptTTL + time.Second) }
	if err := s.CreateAttempt(ctx, Attempt{ID: "neuve", State: "s"}); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = s.r.QueryRow(`SELECT count(*) FROM attempts`).Scan(&n)
	if n != 1 {
		t.Fatal(n)
	}
}

func TestEnregistrerPassage(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	m := Measure{InstanceID: "a", ExtensionKey: "k", MessageID: "m1", Kind: "hardware/v1", CollectedAt: time.Now(), ReceivedAt: time.Now(), Payload: []byte(`{}`), Etat: "sain"}
	m2 := m
	m2.MessageID = "m2"
	n, err := s.EnregistrerPassage(ctx, []Instance{{ID: "a", Name: "A", Active: true}}, []Measure{m, m2, m})
	if err != nil || n != 2 {
		t.Fatal(n, err)
	}
	if n, _ := s.EnregistrerPassage(ctx, nil, []Measure{m, m2}); n != 0 {
		t.Fatal("rejeu inséré", n)
	}
}
