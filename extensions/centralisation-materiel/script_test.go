package centralisation

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/henritouchard/irundoo-extensions/extensions/centralisation-materiel/internal/etat"
)

const instanceTest = "9d3f5c2a-7e41-4b8a-9c2d-1f0e8a6b4c3d"

func outils(t *testing.T) {
	t.Helper()
	for _, o := range []string{"bash", "jq", "curl"} {
		if _, err := exec.LookPath(o); err != nil {
			t.Skipf("%s absent", o)
		}
	}
}

func depose(t *testing.T, env []string, stdin string, args ...string) (string, string, error) {
	t.Helper()
	cmd := exec.Command("bash", append([]string{"scripts/depose-mesures-test.sh"}, args...)...)
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH"), "INSTANCE=" + instanceTest}, env...)
	cmd.Stdin = strings.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	return out.String(), errb.String(), err
}

func compile(t *testing.T, p string) *jsonschema.Schema {
	t.Helper()
	c := jsonschema.NewCompiler()
	c.UseRegexpEngine(ecmaCompile)
	s, err := c.Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// L'enveloppe produite est valide contre le schéma public du relais, chaque charge contre
// hardware/v1, et l'altération demandée lève l'état attendu côté centralisatrice.
func TestScriptADeBlanc(t *testing.T) {
	outils(t)
	relais := compile(t, "testdata/se5-extension-relay-v1.schema.json")
	charge := compile(t, "testdata/hardware-v1.schema.json")
	cas := []struct {
		args []string
		etat etat.Etat
		cle  string
	}{
		{[]string{"--profile", "vm"}, etat.NonObserve, ""},
		{[]string{"--profile", "physical"}, etat.Sain, ""},
		// Carte Redfish de l'hôte de virtualisation : signaux de l'hôte, pas l'état de l'établissement.
		{[]string{"--profile", "redfish"}, etat.NonObserve, "redfish.power.redundancy"},
		{[]string{"--profile", "physical", "--degrade", "md-degraded"}, etat.Critique, "md[md0].degraded"},
		{[]string{"--profile", "vm", "--degrade", "disk-smart"}, etat.Critique, "disk[vda].smart.passed"},
		{[]string{"--profile", "vm", "--degrade", "psu"}, etat.Critique, "redfish.power.supplies[PS2 Status].health"},
		{[]string{"--profile", "physical", "--degrade", "fs-full"}, etat.Critique, "fs[/].used_b"},
		{[]string{"--profile", "physical", "--degrade", "edac-ue"}, etat.Critique, "mem.edac[mc0].ue"},
		{[]string{"--profile", "redfish", "--degrade", "fs-full", "--degrade", "edac-ue"}, etat.Critique, "mem.edac[mc0].ue"},
		{[]string{"--profile", "vm", "--sources", `{"local":"ok","redfish":"unauthorized"}`}, etat.NonObserve, ""},
		{[]string{"--profile", "vm", "--count", "3"}, etat.NonObserve, ""},
	}
	for _, c := range cas {
		t.Run(strings.Join(c.args, " "), func(t *testing.T) {
			out, errOut, err := depose(t, nil, "", append(c.args, "--dry-run")...)
			if err != nil {
				t.Fatalf("%v %s", err, errOut)
			}
			doc, err := jsonschema.UnmarshalJSON(strings.NewReader(out))
			if err != nil {
				t.Fatal(err)
			}
			if err := relais.Validate(doc); err != nil {
				t.Fatalf("enveloppe invalide : %v", err)
			}
			var env struct {
				InstanceID string `json:"instance_id"`
				Messages   []struct {
					MessageID   string          `json:"message_id"`
					CollectedAt time.Time       `json:"collected_at"`
					Payload     json.RawMessage `json:"payload"`
				} `json:"messages"`
			}
			_ = json.Unmarshal([]byte(out), &env)
			if env.InstanceID != instanceTest || len(env.Messages) == 0 {
				t.Fatal(out)
			}
			ids := map[string]bool{}
			for _, m := range env.Messages {
				ids[m.MessageID] = true
				pd, _ := jsonschema.UnmarshalJSON(bytes.NewReader(m.Payload))
				if err := charge.Validate(pd); err != nil {
					t.Fatalf("charge invalide : %v", err)
				}
			}
			if len(ids) != len(env.Messages) {
				t.Fatal("message_id non neufs")
			}
			last := env.Messages[len(env.Messages)-1]
			r := etat.Compute(time.Now(), &etat.Mesure{ReceivedAt: time.Now(), Payload: last.Payload}, 30*time.Minute)
			if r.Etat != c.etat {
				t.Fatalf("état %s, attendu %s", r.Etat, c.etat)
			}
			if c.cle != "" {
				found := false
				for _, s := range append(r.Signaux, r.SignauxHote...) {
					found = found || s.Cle == c.cle
				}
				if !found {
					t.Fatalf("signal %s absent : %+v", c.cle, r.Signaux)
				}
			}
		})
	}
}

func TestScriptRefus(t *testing.T) {
	outils(t)
	for _, args := range [][]string{
		{"--token", "abc"}, {"--profile", "autre"}, {"--count", "51"}, {"--count", "0"},
		{"--degrade", "autre"}, {"--sources", "pas-du-json"}, {"--message-id", "x"},
		{"--count", "2", "--message-id", "6f1c2b7e-3a4d-4e5f-8a9b-0c1d2e3f4a5b"}, {"--inconnue"},
		{"--extension-key", "Mauvaise Clé"}, {"--extension-key", "-x"}, {"--extension-key", strings.Repeat("a", 65)},
		{"--max-time", "abc"}, {"--max-time", "0"}, {"--connect-timeout", "9999"},
		{"--profile"}, {"--degrade"}, {"--profile", "vm", "--degrade", "psu", "--degrade", "autre"},
	} {
		if _, _, err := depose(t, nil, "", append(args, "--dry-run")...); err == nil {
			t.Errorf("accepté : %v", args)
		}
	}
	// Une option invalide est refusée avant tout envoi, même placée après une option valide.
	if _, errOut, err := depose(t, []string{"IRUNDO_URL=http://127.0.0.1:1"}, "jeton\n", "--degrade", "psu", "--degrade", "autre"); err == nil ||
		!strings.Contains(errOut, "--degrade") || strings.Contains(errOut, "requête") {
		t.Errorf("--degrade invalide : %v %s", err, errOut)
	}
	// Envoi sans IRUNDO_URL, ou sans jeton : refusé.
	if _, _, err := depose(t, nil, ""); err == nil {
		t.Error("IRUNDO_URL absente acceptée")
	}
	if _, _, err := depose(t, []string{"IRUNDO_URL=http://127.0.0.1:1"}, ""); err == nil {
		t.Error("jeton vide accepté")
	}
}

// Contre un faux relais écrit d'après le contrat § 4 : chemin, en-têtes, corps, réponse 202.
func TestScriptEnvoi(t *testing.T) {
	outils(t)
	const token = "jeton-de-handshake-de-test"
	var recu struct {
		path, auth, ctype string
		body              []byte
	}
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		recu.path, recu.auth, recu.ctype = r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("Content-Type")
		recu.body, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		if recu.auth != "Bearer "+token {
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{"data":{"success":false,"message":"Authentification invalide"}}`))
			return
		}
		w.WriteHeader(202)
		_, _ = w.Write([]byte(`{"success":true,"data":{"batch_id":"0e1d2c3b-4a59-4687-9a0b-1c2d3e4f5a6b","accepted":1},"message":"Lot de mesures accepté"}`))
	}))
	defer srv.Close()
	tf := filepath.Join(t.TempDir(), "token")
	_ = os.WriteFile(tf, []byte(token+"\n"), 0o600)

	out, errOut, err := depose(t, []string{"IRUNDO_URL=" + srv.URL + "/controlhub", "TOKEN_FILE=" + tf}, "",
		"--profile", "physical", "--message-id", "6f1c2b7e-3a4d-4e5f-8a9b-0c1d2e3f4a5b")
	if err != nil {
		t.Fatalf("%v %s", err, errOut)
	}
	if !strings.Contains(out, "HTTP 202 batch_id=0e1d2c3b-4a59-4687-9a0b-1c2d3e4f5a6b message_id=6f1c2b7e-3a4d-4e5f-8a9b-0c1d2e3f4a5b") {
		t.Fatal(out)
	}
	if recu.path != "/controlhub/api/sambaedu/extension-relay/"+instanceTest || recu.ctype != "application/json" || !json.Valid(recu.body) {
		t.Fatalf("%+v", recu)
	}
	// Jeton par l'entrée standard.
	if out, _, err := depose(t, []string{"IRUNDO_URL=" + srv.URL}, token+"\n", "--profile", "vm"); err != nil || !strings.Contains(out, "HTTP 202") {
		t.Fatal(out, err)
	}
	// Jeton refusé : statut affiché, code de sortie non nul.
	out, errOut, err = depose(t, []string{"IRUNDO_URL=" + srv.URL}, "faux\n")
	if err == nil || !strings.Contains(out, "HTTP 401") || !strings.Contains(errOut, "Authentification invalide") {
		t.Fatal(out, errOut, err)
	}
	if n != 3 {
		t.Fatal(n)
	}
	// Un jeton portant « " » et « \ » arrive intact (échappé dans la configuration de curl).
	const bizarre = `a"b\c`
	_ = os.WriteFile(tf, []byte(bizarre+"\n"), 0o600)
	_, errOut, err = depose(t, []string{"IRUNDO_URL=" + srv.URL, "TOKEN_FILE=" + tf}, "", "--max-time", "5", "--connect-timeout", "2")
	if err == nil || recu.auth != "Bearer "+bizarre {
		t.Fatalf("%q %v %s", recu.auth, err, errOut)
	}
	if strings.Contains(errOut, "avertissement") {
		t.Fatal("avertissement http sur loopback")
	}
}

// IRUNDO_URL en http:// hors loopback : avertissement (le jeton passerait en clair).
func TestScriptAvertitHTTP(t *testing.T) {
	outils(t)
	tf := filepath.Join(t.TempDir(), "token")
	_ = os.WriteFile(tf, []byte("jeton\n"), 0o600)
	_, errOut, err := depose(t, []string{"IRUNDO_URL=http://irundo.invalid", "TOKEN_FILE=" + tf}, "", "--connect-timeout", "1", "--max-time", "2")
	if err == nil || !strings.Contains(errOut, "avertissement : IRUNDO_URL en http:// hors loopback") {
		t.Fatal(err, errOut)
	}
}
