package centralisation

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dlclark/regexp2"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Les motifs du schéma sont écrits pour ECMA-262 et PCRE (irundoo-extension-manifest-v1.md § 3) et
// emploient une assertion avant `(?=…)` que le moteur RE2 de Go (paquet regexp) ne connaît pas :
// le schéma se compile avec regexp2 en mode ECMAScript (guide-developpeur.md § 18).
type ecmaRegexp regexp2.Regexp

func (re *ecmaRegexp) MatchString(s string) bool {
	ok, err := (*regexp2.Regexp)(re).MatchString(s)
	return err == nil && ok
}

func (re *ecmaRegexp) String() string { return (*regexp2.Regexp)(re).String() }

func ecmaCompile(s string) (jsonschema.Regexp, error) {
	re, err := regexp2.Compile(s, regexp2.ECMAScript)
	if err != nil {
		return nil, err
	}
	return (*ecmaRegexp)(re), nil
}

func schema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	c := jsonschema.NewCompiler()
	c.UseRegexpEngine(ecmaCompile)
	sch, err := c.Compile("testdata/irundoo-extension-manifest-v1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	return sch
}

func lire(t *testing.T, p string) (any, map[string]any) {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return doc, m
}

func TestManifeste(t *testing.T) {
	sch := schema(t)
	doc, m := lire(t, "manifest.json")
	if err := sch.Validate(doc); err != nil {
		t.Fatalf("manifest.json invalide : %v", err)
	}
	wd, _ := os.Getwd()
	if m["id"] != filepath.Base(wd) {
		t.Fatalf("id %v ≠ nom du dossier %s (exigence de scripts/publish.php)", m["id"], filepath.Base(wd))
	}
	entry := m["entry_url"].(string)
	if !strings.HasPrefix(entry, "https://") || !strings.HasSuffix(entry, "/") {
		t.Fatal(entry)
	}
	ru := m["redirect_uris"].([]any)
	if len(ru) != 1 || ru[0] != entry+"oidc/callback" || m["health_url"] != entry+"health" || m["type"] != "app" {
		t.Fatalf("%v %v", ru, m["health_url"])
	}
	for _, k := range []string{"user_scopes", "machine_scopes"} {
		got, _ := json.Marshal(m[k])
		if string(got) != `["irundoo:instances:read","irundoo:hardware:read"]` {
			t.Fatalf("%s = %s", k, got)
		}
	}
	if Version() != m["extension_version"] {
		t.Fatal("version embarquée")
	}
}

func TestManifesteDev(t *testing.T) {
	doc, m := lire(t, "dev/manifest.dev.json")
	if err := schema(t).Validate(doc); err != nil {
		t.Fatalf("dev/manifest.dev.json invalide : %v", err)
	}
	if m["id"] != "centralisation-materiel-dev" || m["redirect_uris"].([]any)[0] != "http://127.0.0.1:8090/oidc/callback" {
		t.Fatal(m)
	}
	// Le manifeste de développement n'est jamais à l'endroit que lit publish.php.
	if _, err := os.Stat("../centralisation-materiel-dev"); err == nil {
		t.Fatal("dossier extensions/centralisation-materiel-dev présent : il serait publié")
	}
}

func TestSchemaRefuseUnManifesteFaux(t *testing.T) {
	sch := schema(t)
	for _, bad := range []string{
		`{"format":"irundoo-extension-manifest","version":1}`,
		strings.Replace(string(ManifestJSON), `"https://centralisation-materiel.example.org/oidc/callback"`, `"http://localhost/oidc/callback"`, 1),
		strings.Replace(string(ManifestJSON), `"irundoo:hardware:read"]`, `"irundoo:inconnu"]`, 1),
	} {
		doc, err := jsonschema.UnmarshalJSON(strings.NewReader(bad))
		if err != nil {
			t.Fatal(err)
		}
		if sch.Validate(doc) == nil {
			t.Fatalf("accepté : %s", bad)
		}
	}
}
