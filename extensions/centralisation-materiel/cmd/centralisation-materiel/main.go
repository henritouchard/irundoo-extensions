// Commande centralisation-materiel : l'extension IRUNDO de centralisation de l'état matériel des
// établissements (story EXT-D.4). Configuration par variables d'environnement seules (README).
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	centralisation "github.com/henritouchard/irundoo-extensions/extensions/centralisation-materiel"
	"github.com/henritouchard/irundoo-extensions/extensions/centralisation-materiel/internal/config"
	"github.com/henritouchard/irundoo-extensions/extensions/centralisation-materiel/internal/irundoo"
	"github.com/henritouchard/irundoo-extensions/extensions/centralisation-materiel/internal/oidc"
	"github.com/henritouchard/irundoo-extensions/extensions/centralisation-materiel/internal/releve"
	"github.com/henritouchard/irundoo-extensions/extensions/centralisation-materiel/internal/store"
	"github.com/henritouchard/irundoo-extensions/extensions/centralisation-materiel/internal/web"
)

func main() {
	if len(os.Args) > 1 {
		if os.Args[1] == "--version" || os.Args[1] == "-version" {
			fmt.Println(centralisation.Version())
			return
		}
		fmt.Fprintln(os.Stderr, "usage : centralisation-materiel [--version] — configuration par variables d'environnement (README)")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Getenv, os.Stderr, nil); err != nil {
		fmt.Fprintln(os.Stderr, "centralisation-materiel :", err)
		os.Exit(1)
	}
}

// run démarre le service jusqu'à l'annulation de ctx. ready, si non nil, reçoit l'adresse d'écoute.
func run(ctx context.Context, getenv func(string) string, logOut io.Writer, ready chan<- string) error {
	cfg, err := config.Load(getenv)
	if err != nil {
		return fmt.Errorf("configuration : %w", err)
	}
	log := slog.New(slog.NewJSONHandler(logOut, &slog.HandlerOptions{Level: cfg.LogLevel}))
	for _, w := range cfg.Warnings {
		log.Warn(w)
	}
	version := centralisation.Version()

	st, err := store.Open(cfg.DataDir)
	if err != nil {
		return fmt.Errorf("magasin local (%s) : %w", cfg.DataDir, err)
	}
	defer st.Close()

	hc := irundoo.NewHTTPClient()
	api, err := irundoo.New(cfg.Issuer, hc, version)
	if err != nil {
		return err
	}
	oc := oidc.New(oidc.Config{Issuer: cfg.Issuer, ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret,
		RedirectURL: cfg.RedirectURL(), HTTPClient: hc})

	runner := &releve.Runner{Tokens: oc, API: api, Store: st, Log: log.With("composant", "releve"),
		Interval: cfg.PollInterval, StaleAfter: cfg.StaleAfter, Retention: cfg.RetentionDays}
	srv := &web.Server{OIDC: oc, API: api, Store: st, Log: log.With("composant", "web"), StaleAfter: cfg.StaleAfter,
		RetentionDays: cfg.RetentionDays, SecureCookies: cfg.SecureCookies, PublicURL: cfg.PublicURL, Version: version}

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("LISTEN %s : %w", cfg.Listen, err)
	}
	// WriteTimeout au-delà du délai d'un rendu (web.DelaiRequete : deux appels d'API de 15 s au plus,
	// ou Discovery + jeton + JWKS au retour d'autorisation) : la réponse d'erreur part toujours.
	hs := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: web.DelaiRequete + 5*time.Second, IdleTimeout: 120 * time.Second, ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelWarn)}
	log.Info("démarrage", "version", version, "listen", ln.Addr().String(), "public_url", cfg.PublicURL,
		"issuer", cfg.Issuer, "client_id", cfg.ClientID, "poll_interval", cfg.PollInterval.String(),
		"stale_after", cfg.StaleAfter.String(), "data", st.Path())

	bg, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { runner.Run(bg); close(done) }()
	errc := make(chan error, 1)
	go func() { errc <- hs.Serve(ln) }()
	if ready != nil {
		ready <- ln.Addr().String()
	}
	select {
	case <-ctx.Done():
	case err := <-errc:
		cancel()
		<-done
		return err
	}
	log.Info("arrêt demandé")
	cancel()
	sctx, scancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer scancel()
	err = hs.Shutdown(sctx)
	<-done
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	log.Info("arrêté")
	return err
}
