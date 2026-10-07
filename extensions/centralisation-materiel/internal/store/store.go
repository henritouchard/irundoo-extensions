// Package store est le magasin local de la centralisatrice : SQLite pur Go (modernc.org/sqlite,
// binaire statique), fichier 0600, WAL. Il accumule l'historique des mesures relevées sous jeton
// machine, les passages de la relève, les sessions et les tentatives OIDC.
//
// Il n'est jamais la source des lignes affichées : l'écran part de /instances à chaque rendu et ne
// lit ici que l'historique d'un établissement **rendu** (le périmètre est celui du serveur).
package store

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pilote « sqlite », sans cgo
)

// FileName : nom du fichier dans le répertoire d'état.
const FileName = "centralisation-materiel.sqlite"

//go:embed migrations/*.sql
var migrations embed.FS

// Store : deux pools, une connexion d'écriture (SQLite n'a qu'un écrivain), des lectures en WAL.
type Store struct {
	w, r *sql.DB
	path string
	// Now est l'horloge (remplaçable en test).
	Now func() time.Time
}

const ts = time.RFC3339Nano

func fmtT(t time.Time) string { return t.UTC().Format(ts) }

func parseT(s string) time.Time {
	t, _ := time.Parse(ts, s)
	return t
}

// Open crée au besoin le fichier en 0600 avant toute écriture de SQLite, puis applique les migrations.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, FileName)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	_ = f.Close()
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, err
	}
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_txlock=immediate"
	w, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	w.SetMaxOpenConns(1)
	r, err := sql.Open("sqlite", dsn)
	if err != nil {
		_ = w.Close()
		return nil, err
	}
	r.SetMaxOpenConns(4)
	s := &Store{w: w, r: r, path: path, Now: time.Now}
	if err := s.migrate(context.Background()); err != nil {
		_ = s.Close()
		return nil, err
	}
	return s, nil
}

// Close ferme les deux pools.
func (s *Store) Close() error {
	return errors.Join(s.w.Close(), s.r.Close())
}

// Path du fichier SQLite.
func (s *Store) Path() string { return s.path }

func migrationFiles() ([]string, error) {
	names, err := migrations.ReadDir("migrations")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, n := range names {
		out = append(out, n.Name())
	}
	sort.Strings(out)
	return out, nil
}

// Version : nombre de migrations embarquées (le schéma attendu).
func Version() int {
	f, _ := migrationFiles()
	return len(f)
}

func (s *Store) migrate(ctx context.Context) error {
	files, err := migrationFiles()
	if err != nil {
		return err
	}
	var cur int
	if err := s.w.QueryRowContext(ctx, "PRAGMA user_version").Scan(&cur); err != nil {
		return err
	}
	for i := cur; i < len(files); i++ {
		sqlText, err := migrations.ReadFile("migrations/" + files[i])
		if err != nil {
			return err
		}
		tx, err := s.w.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, string(sqlText)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migration %s : %w", files[i], err)
		}
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", i+1)); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// Healthy : le fichier s'ouvre et le schéma est à jour (santé C.5).
func (s *Store) Healthy(ctx context.Context) error {
	var v int
	if err := s.r.QueryRowContext(ctx, "PRAGMA user_version").Scan(&v); err != nil {
		return err
	}
	if v != Version() {
		return fmt.Errorf("schéma %d, attendu %d", v, Version())
	}
	return nil
}

// Instance : copie locale d'un établissement vu par la relève (enrichissement seulement).
type Instance struct {
	ID, Name                                        string
	UAI, EstablishmentName, EstablishmentType, Zone *string
	Active                                          bool
}

// UpsertInstance : nom, UAI, actif, vu à. Une instance disparue du périmètre garde sa ligne (NFR11).
func (s *Store) UpsertInstance(ctx context.Context, in Instance) error {
	now := fmtT(s.Now())
	_, err := s.w.ExecContext(ctx, `INSERT INTO instances (id, name, uai, establishment_name, establishment_type, academic_zone, active, first_seen_at, last_seen_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET name=excluded.name, uai=excluded.uai, establishment_name=excluded.establishment_name,
		establishment_type=excluded.establishment_type, academic_zone=excluded.academic_zone, active=excluded.active, last_seen_at=excluded.last_seen_at`,
		in.ID, in.Name, in.UAI, in.EstablishmentName, in.EstablishmentType, in.Zone, in.Active, now, now)
	return err
}

// Measure : une mesure relevée.
type Measure struct {
	InstanceID, ExtensionKey, MessageID, Kind string
	ExtensionVersion                          *string
	CollectedAt, ReceivedAt                   time.Time
	Payload                                   []byte // octets JSON tels que servis
	Etat                                      string
	Signaux                                   []byte // JSON
	BootID                                    string
}

// Insert : INSERT OR IGNORE sur (instance_id, extension_key, message_id). inserted = false sur un rejeu.
// Un boot_id différent du dernier connu pour l'instance est consigné sur l'instance (last_boot_id) ;
// l'historique le retrouve par la suite des mesures.
func (s *Store) Insert(ctx context.Context, m Measure) (bool, error) {
	var boot any
	if m.BootID != "" {
		boot = m.BootID
	}
	sig := m.Signaux
	if sig == nil {
		sig = []byte("[]")
	}
	res, err := s.w.ExecContext(ctx, `INSERT OR IGNORE INTO measurements
		(instance_id, extension_key, extension_version, message_id, kind, collected_at, received_at, payload, etat, signaux, boot_id, inserted_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		m.InstanceID, m.ExtensionKey, m.ExtensionVersion, m.MessageID, m.Kind, fmtT(m.CollectedAt), fmtT(m.ReceivedAt),
		string(m.Payload), m.Etat, string(sig), boot, fmtT(s.Now()))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil || n == 0 {
		return false, err
	}
	if m.BootID != "" {
		_, err = s.w.ExecContext(ctx, `UPDATE instances SET last_boot_id = ? WHERE id = ?`, m.BootID, m.InstanceID)
	}
	return true, err
}

// History : ce que l'écran affiche d'une instance **rendue** (D.4a : liste, pas de graphique).
type History struct {
	Count       int
	First, Last time.Time
	BootChanges []time.Time // received_at de la première mesure d'un nouveau démarrage
	// SignauxPasses : signaux distincts levés aux mesures conservées (clé ⇒ dernière vue).
	SignauxPasses []PastSignal
}

// PastSignal : un signal levé à une relève précédente.
type PastSignal struct {
	Cle, Niveau, Message string
	Vu                   time.Time
}

// History lit l'historique local d'une instance depuis since.
func (s *Store) History(ctx context.Context, instance string, since time.Time) (*History, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT received_at, COALESCE(boot_id, ''), signaux FROM measurements
		WHERE instance_id = ? AND received_at >= ? ORDER BY received_at, id`, instance, fmtT(since))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	h := &History{}
	prevBoot := ""
	seen := map[string]int{}
	for rows.Next() {
		var rec, boot, sig string
		if err := rows.Scan(&rec, &boot, &sig); err != nil {
			return nil, err
		}
		t := parseT(rec)
		if h.Count == 0 {
			h.First = t
		}
		h.Last = t
		h.Count++
		if boot != "" {
			if prevBoot != "" && boot != prevBoot {
				h.BootChanges = append(h.BootChanges, t)
			}
			prevBoot = boot
		}
		for _, p := range decodeSignaux(sig) {
			if i, ok := seen[p.Cle]; ok {
				h.SignauxPasses[i].Vu = t
				continue
			}
			seen[p.Cle] = len(h.SignauxPasses)
			h.SignauxPasses = append(h.SignauxPasses, PastSignal{Cle: p.Cle, Niveau: p.Niveau, Message: p.Message, Vu: t})
		}
	}
	return h, rows.Err()
}

// CountMeasurements : nombre de mesures conservées pour une instance (recette, tests).
func (s *Store) CountMeasurements(ctx context.Context, instance string) (int, error) {
	var n int
	err := s.r.QueryRowContext(ctx, `SELECT count(*) FROM measurements WHERE instance_id = ?`, instance).Scan(&n)
	return n, err
}

// Releve : un passage de la relève.
type Releve struct {
	ID                    int64
	StartedAt, FinishedAt time.Time
	Status                string // "ok" | "echec"
	HTTPStatus            int
	Motif                 string
	Instances, Inserted   int
}

// RecordReleve consigne un passage.
func (s *Store) RecordReleve(ctx context.Context, r Releve) error {
	var hs, motif any
	if r.HTTPStatus != 0 {
		hs = r.HTTPStatus
	}
	if r.Motif != "" {
		motif = r.Motif
	}
	_, err := s.w.ExecContext(ctx, `INSERT INTO releves (started_at, finished_at, status, http_status, motif, instances_count, measurements_inserted)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, fmtT(r.StartedAt), fmtT(r.FinishedAt), r.Status, hs, motif, r.Instances, r.Inserted)
	return err
}

// ReleveState : ce que le bandeau affiche.
type ReleveState struct {
	LastOK, LastEchec *Releve
	// EchecDepuis : premier échec de la série en cours (si le dernier passage est un échec).
	EchecDepuis *time.Time
}

// LastReleves : dernier succès, dernier échec, et début de la série d'échecs en cours.
func (s *Store) LastReleves(ctx context.Context) (*ReleveState, error) {
	st := &ReleveState{}
	one := func(status string) (*Releve, error) {
		r := &Releve{}
		var start, fin string
		var hs sql.NullInt64
		var motif sql.NullString
		err := s.r.QueryRowContext(ctx, `SELECT id, started_at, finished_at, status, http_status, motif, instances_count, measurements_inserted
			FROM releves WHERE status = ? ORDER BY id DESC LIMIT 1`, status).Scan(&r.ID, &start, &fin, &r.Status, &hs, &motif, &r.Instances, &r.Inserted)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		r.StartedAt, r.FinishedAt, r.HTTPStatus, r.Motif = parseT(start), parseT(fin), int(hs.Int64), motif.String
		return r, nil
	}
	var err error
	if st.LastOK, err = one("ok"); err != nil {
		return nil, err
	}
	if st.LastEchec, err = one("echec"); err != nil {
		return nil, err
	}
	if st.LastEchec != nil && (st.LastOK == nil || st.LastEchec.ID > st.LastOK.ID) {
		var after int64
		if st.LastOK != nil {
			after = st.LastOK.ID
		}
		var start string
		if err := s.r.QueryRowContext(ctx, `SELECT started_at FROM releves WHERE status = 'echec' AND id > ? ORDER BY id LIMIT 1`, after).Scan(&start); err == nil {
			t := parseT(start)
			st.EchecDepuis = &t
		}
	}
	return st, nil
}

// Prune supprime les mesures et les passages plus anciens que days jours, les sessions expirées et
// les tentatives OIDC périmées. Retourne le nombre de mesures supprimées.
func (s *Store) Prune(ctx context.Context, days int) (int64, error) {
	now := s.Now()
	cut := fmtT(now.AddDate(0, 0, -days))
	res, err := s.w.ExecContext(ctx, `DELETE FROM measurements WHERE received_at < ?`, cut)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	_, err1 := s.w.ExecContext(ctx, `DELETE FROM releves WHERE started_at < ?`, cut)
	_, err2 := s.w.ExecContext(ctx, `DELETE FROM sessions WHERE last_seen_at < ?`, fmtT(now.Add(-SessionIdle)))
	_, err3 := s.w.ExecContext(ctx, `DELETE FROM attempts WHERE created_at < ?`, fmtT(now.Add(-AttemptTTL)))
	return n, errors.Join(err1, err2, err3)
}

// SessionIdle : une session inutilisée plus longtemps est supprimée.
const SessionIdle = 12 * time.Hour

// AttemptTTL : durée de vie d'une tentative OIDC.
const AttemptTTL = 5 * time.Minute

// Session : session serveur de l'utilisateur (cookie opaque = ID).
type Session struct {
	ID, Sub, Name string
	Roles         []string
	AccessToken   string
	TokenExp      time.Time
	Scope         string
	CreatedAt     time.Time
}

// CreateSession enregistre une session.
func (s *Store) CreateSession(ctx context.Context, se Session) error {
	now := fmtT(s.Now())
	_, err := s.w.ExecContext(ctx, `INSERT INTO sessions (id, sub, name, roles, access_token, token_exp, scope, created_at, last_seen_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, se.ID, se.Sub, se.Name, strings.Join(se.Roles, "\n"), se.AccessToken, fmtT(se.TokenExp), se.Scope, now, now)
	return err
}

// GetSession : nil si absente ou inactive depuis plus de SessionIdle.
func (s *Store) GetSession(ctx context.Context, id string) (*Session, error) {
	se := &Session{ID: id}
	var roles, exp, created, seen string
	err := s.r.QueryRowContext(ctx, `SELECT sub, name, roles, access_token, token_exp, scope, created_at, last_seen_at FROM sessions WHERE id = ?`, id).
		Scan(&se.Sub, &se.Name, &roles, &se.AccessToken, &exp, &se.Scope, &created, &seen)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if s.Now().Sub(parseT(seen)) > SessionIdle {
		return nil, nil
	}
	if roles != "" {
		se.Roles = strings.Split(roles, "\n")
	}
	se.TokenExp, se.CreatedAt = parseT(exp), parseT(created)
	_, _ = s.w.ExecContext(ctx, `UPDATE sessions SET last_seen_at = ? WHERE id = ?`, fmtT(s.Now()), id)
	return se, nil
}

// DeleteSession efface une session (déconnexion locale).
func (s *Store) DeleteSession(ctx context.Context, id string) error {
	_, err := s.w.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, id)
	return err
}

// Attempt : tentative d'autorisation OIDC en cours.
type Attempt struct {
	ID, State, Nonce, Verifier string
	PromptNone                 bool
	// Relance : cette tentative est déjà la relance d'un échec (une seule relance, jamais de boucle).
	Relance   bool
	CreatedAt time.Time
}

// CreateAttempt enregistre une tentative.
func (s *Store) CreateAttempt(ctx context.Context, a Attempt) error {
	_, err := s.w.ExecContext(ctx, `INSERT INTO attempts (id, state, nonce, verifier, prompt_none, relance, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		a.ID, a.State, a.Nonce, a.Verifier, a.PromptNone, a.Relance, fmtT(s.Now()))
	return err
}

// TakeAttempt lit et supprime une tentative (usage unique) ; nil si absente ou périmée.
func (s *Store) TakeAttempt(ctx context.Context, id string) (*Attempt, error) {
	a := &Attempt{ID: id}
	var created string
	err := s.w.QueryRowContext(ctx, `DELETE FROM attempts WHERE id = ? RETURNING state, nonce, verifier, prompt_none, relance, created_at`, id).
		Scan(&a.State, &a.Nonce, &a.Verifier, &a.PromptNone, &a.Relance, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	a.CreatedAt = parseT(created)
	if s.Now().Sub(a.CreatedAt) > AttemptTTL {
		return nil, nil
	}
	return a, nil
}

type signal struct {
	Niveau  string `json:"niveau"`
	Cle     string `json:"cle"`
	Message string `json:"message"`
}

func decodeSignaux(s string) []signal {
	var out []signal
	_ = json.Unmarshal([]byte(s), &out)
	return out
}
