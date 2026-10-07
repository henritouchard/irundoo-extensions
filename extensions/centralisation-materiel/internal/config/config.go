// Package config lit la configuration de la centralisatrice, par variables d'environnement seules
// (jamais d'argument : un secret en argv est visible dans `ps`). Un démarrage refusé nomme la
// variable en cause.
package config

import (
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config : la configuration validée.
type Config struct {
	Issuer        string
	ClientID      string
	ClientSecret  string
	PublicURL     string
	Listen        string
	DataDir       string
	StaleAfter    time.Duration
	PollInterval  time.Duration
	RetentionDays int
	LogLevel      slog.Level
	InsecureDev   bool
	// Warnings : avertissements à journaliser (jamais une valeur secrète).
	Warnings []string
}

// RedirectURL : PUBLIC_URL + "/oidc/callback", exacte (jamais déduite d'un en-tête X-Forwarded-*).
func (c Config) RedirectURL() string { return c.PublicURL + "/oidc/callback" }

// Load lit la configuration. getenv : os.Getenv en production.
func Load(getenv func(string) string) (Config, error) {
	c := Config{Listen: "127.0.0.1:8090", StaleAfter: 30 * time.Minute, PollInterval: 5 * time.Minute, RetentionDays: 180, LogLevel: slog.LevelInfo}
	need := func(k string) (string, error) {
		v := strings.TrimSpace(getenv(k))
		if v == "" {
			return "", fmt.Errorf("%s : variable obligatoire absente", k)
		}
		return v, nil
	}
	var err error
	if v := strings.TrimSpace(getenv("DEV_INSECURE_COOKIES")); v != "" {
		if c.InsecureDev, err = strconv.ParseBool(v); err != nil {
			return c, fmt.Errorf("DEV_INSECURE_COOKIES : booléen attendu")
		}
	}
	if c.Issuer, err = need("IRUNDOO_ISSUER"); err != nil {
		return c, err
	}
	if err := absURL("IRUNDOO_ISSUER", c.Issuer, true); err != nil {
		return c, err
	}
	if c.ClientID, err = need("CLIENT_ID"); err != nil {
		return c, err
	}
	if f := strings.TrimSpace(getenv("CLIENT_SECRET_FILE")); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return c, fmt.Errorf("CLIENT_SECRET_FILE : fichier illisible")
		}
		c.ClientSecret = strings.TrimSpace(string(b))
		if st, err := os.Stat(f); err == nil && st.Mode().Perm()&0o077 != 0 {
			c.Warnings = append(c.Warnings, "CLIENT_SECRET_FILE lisible par d'autres que son propriétaire : chmod 600 recommandé")
		}
		if c.ClientSecret == "" {
			return c, fmt.Errorf("CLIENT_SECRET_FILE : fichier vide")
		}
	} else if c.ClientSecret, err = need("CLIENT_SECRET"); err != nil {
		return c, fmt.Errorf("CLIENT_SECRET_FILE ou CLIENT_SECRET : l'un des deux est obligatoire")
	}
	if c.PublicURL, err = need("PUBLIC_URL"); err != nil {
		return c, err
	}
	if err := absURL("PUBLIC_URL", c.PublicURL, false); err != nil {
		return c, err
	}
	if !strings.HasPrefix(c.PublicURL, "https://") && !c.InsecureDev {
		return c, fmt.Errorf("PUBLIC_URL : https:// obligatoire hors développement (DEV_INSECURE_COOKIES=true)")
	}
	if v := strings.TrimSpace(getenv("LISTEN")); v != "" {
		c.Listen = v
	}
	dir := strings.TrimSpace(getenv("STATE_DIRECTORY"))
	if i := strings.IndexByte(dir, ':'); i >= 0 { // systemd peut en donner plusieurs
		dir = dir[:i]
	}
	if dir == "" {
		dir = strings.TrimSpace(getenv("DATA_DIR"))
	}
	if dir == "" {
		return c, fmt.Errorf("STATE_DIRECTORY ou DATA_DIR : l'un des deux est obligatoire")
	}
	c.DataDir = dir
	if c.StaleAfter, err = duree(getenv, "STALE_AFTER", c.StaleAfter); err != nil {
		return c, err
	}
	if c.StaleAfter <= 0 {
		return c, fmt.Errorf("STALE_AFTER : durée positive attendue")
	}
	if c.PollInterval, err = duree(getenv, "POLL_INTERVAL", c.PollInterval); err != nil {
		return c, err
	}
	if c.PollInterval != 0 && c.PollInterval < time.Minute {
		return c, fmt.Errorf("POLL_INTERVAL : au moins 1m (ou 0 pour désactiver la relève)")
	}
	if v := strings.TrimSpace(getenv("HISTORY_RETENTION_DAYS")); v != "" {
		if c.RetentionDays, err = strconv.Atoi(v); err != nil || c.RetentionDays < 1 {
			return c, fmt.Errorf("HISTORY_RETENTION_DAYS : entier ≥ 1 attendu")
		}
	}
	if v := strings.TrimSpace(getenv("LOG_LEVEL")); v != "" {
		if err := c.LogLevel.UnmarshalText([]byte(v)); err != nil {
			return c, fmt.Errorf("LOG_LEVEL : debug, info, warn ou error")
		}
	}
	return c, nil
}

func duree(getenv func(string) string, k string, def time.Duration) (time.Duration, error) {
	v := strings.TrimSpace(getenv(k))
	if v == "" {
		return def, nil
	}
	if v == "0" {
		return 0, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < 0 {
		return 0, fmt.Errorf("%s : durée attendue (ex. 30m, 5m)", k)
	}
	return d, nil
}

// absURL : URL absolue http(s), sans « / » final, sans query ni fragment ; un chemin n'est admis que
// pour l'issuer (préfixe de publication d'IRUNDO). La centralisatrice vit à la racine de son hôte.
func absURL(k, v string, pathOK bool) error {
	u, err := url.Parse(v)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%s : URL absolue http(s) attendue", k)
	}
	if strings.HasSuffix(v, "/") {
		return fmt.Errorf("%s : sans « / » final", k)
	}
	if !pathOK && u.Path != "" {
		return fmt.Errorf("%s : préfixe de chemin non pris en charge en v1 (l'extension vit à la racine de son hôte)", k)
	}
	return nil
}
