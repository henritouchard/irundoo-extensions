package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func base() map[string]string {
	return map[string]string{"IRUNDOO_ISSUER": "https://irundo.example.org/controlhub", "CLIENT_ID": "0123456789abcdef0123456789abcdef",
		"CLIENT_SECRET": "s3cr3t", "PUBLIC_URL": "https://cm.example.org", "DATA_DIR": "/tmp/x"}
}

func TestDefauts(t *testing.T) {
	c, err := Load(env(base()))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != "127.0.0.1:8090" || c.StaleAfter != 30*time.Minute || c.PollInterval != 5*time.Minute || c.RetentionDays != 180 ||
		c.RedirectURL() != "https://cm.example.org/oidc/callback" || c.InsecureDev || !c.SecureCookies {
		t.Fatalf("%+v", c)
	}
}

func TestSecretFichierPrime(t *testing.T) {
	f := filepath.Join(t.TempDir(), "secret")
	_ = os.WriteFile(f, []byte("du-fichier\n"), 0o644)
	m := base()
	m["CLIENT_SECRET_FILE"] = f
	c, err := Load(env(m))
	if err != nil || c.ClientSecret != "du-fichier" || len(c.Warnings) != 1 {
		t.Fatalf("%+v %v", c, err)
	}
	_ = os.Chmod(f, 0o600)
	if c, _ := Load(env(m)); len(c.Warnings) != 0 {
		t.Fatal(c.Warnings)
	}
	for _, w := range c.Warnings {
		if strings.Contains(w, "du-fichier") {
			t.Fatal("secret dans un avertissement")
		}
	}
}

func TestRefus(t *testing.T) {
	cas := map[string]map[string]string{
		"IRUNDOO_ISSUER":         {"IRUNDOO_ISSUER": ""},
		"IRUNDOO_ISSUER : sans":  {"IRUNDOO_ISSUER": "https://irundo.example.org/"},
		"IRUNDOO_ISSUER : https": {"IRUNDOO_ISSUER": "http://irundo.example.org/controlhub"},
		"CLIENT_ID":              {"CLIENT_ID": ""},
		"CLIENT_SECRET_FILE ou":  {"CLIENT_SECRET": ""},
		"CLIENT_SECRET_FILE :":   {"CLIENT_SECRET_FILE": "/nexiste/pas"},
		"PUBLIC_URL : https":     {"PUBLIC_URL": "http://127.0.0.1:8090"},
		"PUBLIC_URL : préfixe":   {"PUBLIC_URL": "https://cm.example.org/sous"},
		"PUBLIC_URL : URL":       {"PUBLIC_URL": "cm.example.org"},
		"STATE_DIRECTORY ou":     {"DATA_DIR": ""},
		"STALE_AFTER":            {"STALE_AFTER": "trente"},
		"STALE_AFTER : durée p":  {"STALE_AFTER": "0"},
		"POLL_INTERVAL : au":     {"POLL_INTERVAL": "30s"},
		"POLL_INTERVAL : durée":  {"POLL_INTERVAL": "-1m"},
		"HISTORY_RETENTION_DAYS": {"HISTORY_RETENTION_DAYS": "0"},
		"LOG_LEVEL":              {"LOG_LEVEL": "bavard"},
		"DEV_INSECURE_COOKIES":   {"DEV_INSECURE_COOKIES": "peut-être"},
	}
	for want, over := range cas {
		m := base()
		for k, v := range over {
			m[k] = v
		}
		if _, err := Load(env(m)); err == nil || !strings.HasPrefix(err.Error(), want) {
			t.Errorf("%s : %v", want, err)
		} else if strings.Contains(err.Error(), "s3cr3t") {
			t.Error("secret dans le message")
		}
	}
}

func TestDev(t *testing.T) {
	m := base()
	m["PUBLIC_URL"] = "http://127.0.0.1:8090"
	m["IRUNDOO_ISSUER"] = "http://local.irundoo.fr:3000"
	m["DEV_INSECURE_COOKIES"] = "true"
	m["STATE_DIRECTORY"] = "/var/lib/a:/var/lib/b"
	m["POLL_INTERVAL"] = "0"
	m["STALE_AFTER"] = "2m"
	m["LOG_LEVEL"] = "debug"
	m["HISTORY_RETENTION_DAYS"] = "90"
	m["LISTEN"] = "0.0.0.0:9000"
	c, err := Load(env(m))
	if err != nil || c.SecureCookies || c.DataDir != "/var/lib/a" || c.PollInterval != 0 || c.StaleAfter != 2*time.Minute || c.RetentionDays != 90 || c.Listen != "0.0.0.0:9000" {
		t.Fatalf("%+v %v", c, err)
	}
}

// En développement, une PUBLIC_URL https garde ses cookies Secure : le drapeau ne fait qu'autoriser
// le http, il ne retire jamais Secure à une adresse https.
func TestSecureSuitLeSchemaDePublicURL(t *testing.T) {
	m := base()
	m["DEV_INSECURE_COOKIES"] = "true"
	c, err := Load(env(m))
	if err != nil || !c.SecureCookies {
		t.Fatalf("%+v %v", c, err)
	}
}
