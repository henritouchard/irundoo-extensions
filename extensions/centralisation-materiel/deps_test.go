package centralisation

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Liste blanche des modules (AC3) : les dépendances directes choisies et leurs transitives connues.
// Ajouter un module est une décision de review, pas un effet de bord.
var modulesAdmis = []string{
	// directes
	"github.com/coreos/go-oidc/v3",
	"golang.org/x/oauth2",
	"modernc.org/sqlite",
	"github.com/santhosh-tekuri/jsonschema/v6",
	"github.com/dlclark/regexp2", // tests seulement : moteur ECMAScript pour les motifs du schéma
	"github.com/oapi-codegen/runtime",
	// transitives
	"github.com/go-jose/go-jose/v4",
	"github.com/apapsch/go-jsonmerge/v2",
	"github.com/google/uuid",
	"github.com/dustin/go-humanize",
	"github.com/mattn/go-isatty",
	"github.com/ncruces/go-strftime",
	"github.com/remyoudompheng/bigfft",
	"golang.org/x/sys",
	"golang.org/x/text",
	"golang.org/x/exp",
	"modernc.org/libc",
	"modernc.org/mathutil",
	"modernc.org/memory",
}

// Aucun pilote de base, aucun client d'annuaire, aucune adresse SE5 (AC3).
var interdits = []string{"lib/pq", "jackc/pgx", "go-sql-driver", "go-ldap", "ldap.v3", "mattn/go-sqlite3"}

func TestModulesListeBlanche(t *testing.T) {
	f, err := os.Open("go.mod")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	inReq := false
	n := 0
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(l, "require ("):
			inReq = true
			continue
		case inReq && l == ")":
			inReq = false
			continue
		case strings.HasPrefix(l, "require "):
			l = strings.TrimPrefix(l, "require ")
		case !inReq:
			continue
		}
		fields := strings.Fields(l)
		if len(fields) < 2 {
			continue
		}
		n++
		admis := false
		for _, m := range modulesAdmis {
			if fields[0] == m {
				admis = true
			}
		}
		if !admis {
			t.Errorf("module hors liste blanche : %s", fields[0])
		}
	}
	if n == 0 {
		t.Fatal("aucun require lu dans go.mod")
	}
	sum, _ := os.ReadFile("go.sum")
	for _, x := range interdits {
		if strings.Contains(string(sum), x) {
			t.Errorf("module interdit dans go.sum : %s", x)
		}
	}
}

// Le code ne connaît d'IRUNDO que l'API publique : ni base, ni annuaire, ni API SE5.
func TestAucuneAdresseHorsAPIPublique(t *testing.T) {
	err := filepath.WalkDir(".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		s := string(b)
		for _, x := range []string{"/api/ext/", "/api/sambaedu", "/oidc/authorize", "/oidc/token", "/oidc/jwks", "ldap", "postgres"} {
			if strings.Contains(strings.ToLower(s), x) && !strings.Contains(p, "fakeirundo") {
				t.Errorf("%s cite %q : aucun chemin d'IRUNDO hors Discovery et servers[0], aucun accès SE5 / base / annuaire", p, x)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
