// Package releve est la relève de fond : sous jeton machine (client_credentials, B.8), toutes les
// POLL_INTERVAL, elle lit /instances puis /hardware et accumule les mesures nouvelles en SQLite
// (seul endroit où l'historique existe : l'API ne sert que la dernière mesure).
//
// Conduite (fournisseur-oidc.md § 11.5) : un passage = un jeton (du cache ou neuf) + deux appels
// d'API. 401 sur un jeton **du cache** ⇒ jeton oublié, un seul nouveau jeton, l'appel rejoué une
// fois (au plus 2 jetons + 3 appels par passage). 401 sur un jeton **neuf**, second 401, ou
// `invalid_client` au token_endpoint ⇒ consigné, puis la relève **cesse** jusqu'au redémarrage du
// service (la configuration ou l'enregistrement est à corriger : redemander à chaque intervalle
// n'y changerait rien). 429 ⇒ passage abandonné aussitôt, le suivant attend Retry-After. 503,
// réseau, 403 ⇒ passage en échec consigné, réessayé à l'intervalle suivant. Un passage interrompu
// par l'arrêt du service (SIGTERM) n'est pas consigné comme un échec. Jamais de rafale.
package releve

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/henritouchard/irundoo-extensions/extensions/centralisation-materiel/internal/etat"
	"github.com/henritouchard/irundoo-extensions/extensions/centralisation-materiel/internal/irundoo"
	"github.com/henritouchard/irundoo-extensions/extensions/centralisation-materiel/internal/oidc"
	"github.com/henritouchard/irundoo-extensions/extensions/centralisation-materiel/internal/store"
)

// Tokener : le jeton machine (oidc.Client). fresh : délivré à l'instant (pas du cache).
type Tokener interface {
	MachineToken(ctx context.Context) (tok string, fresh bool, err error)
	ForgetMachineToken()
}

// API : les deux lectures (irundoo.Client).
type API interface {
	Instances(ctx context.Context, token string) (*irundoo.Instances, error)
	Hardware(ctx context.Context, token, instance string) (*irundoo.Hardware, error)
}

// Runner : la boucle de relève.
type Runner struct {
	Tokens     Tokener
	API        API
	Store      *store.Store
	Log        *slog.Logger
	Interval   time.Duration
	StaleAfter time.Duration
	Retention  int // jours
	Now        func() time.Time

	// arret : motif de l'arrêt de la relève (401 sur jeton neuf, invalid_client) ; vide sinon.
	// Levé au redémarrage du service seulement.
	arret string
	// pasAvant : un 429 a demandé d'attendre jusque-là (Retry-After) ; le passage d'avant est sauté.
	pasAvant time.Time
}

// Statuts d'un passage non consigné (retournés par Pass, jamais écrits en base).
const (
	StatutArretee     = "arretee"     // relève arrêtée (motif dans Arret)
	StatutSautee      = "sautee"      // Retry-After d'un 429 pas encore écoulé
	StatutInterrompue = "interrompue" // arrêt du service pendant le passage
)

// Arret : motif de l'arrêt de la relève, vide si elle tourne.
func (r *Runner) Arret() string { return r.arret }

// Run : purge au démarrage puis une fois par jour ; un passage immédiat puis toutes les Interval.
// Interval == 0 : relève désactivée (écran seul). S'arrête à l'annulation de ctx (SIGTERM).
func (r *Runner) Run(ctx context.Context) {
	r.prune(ctx)
	if r.Interval <= 0 {
		r.Log.Info("relève désactivée (POLL_INTERVAL=0)")
		return
	}
	tick := time.NewTicker(r.Interval)
	defer tick.Stop()
	purge := time.NewTicker(24 * time.Hour)
	defer purge.Stop()
	r.Pass(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			r.Pass(ctx)
		case <-purge.C:
			r.prune(ctx)
		}
	}
}

func (r *Runner) prune(ctx context.Context) {
	n, err := r.Store.Prune(ctx, r.Retention)
	if err != nil {
		r.Log.Error("purge locale en échec", "err", err)
		return
	}
	r.Log.Info("purge locale", "mesures_supprimees", n, "retention_jours", r.Retention)
}

func (r *Runner) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Pass : un passage. Retourne le passage (consigné, sauf statuts StatutArretee, StatutSautee et
// StatutInterrompue).
func (r *Runner) Pass(ctx context.Context) store.Releve {
	if r.arret != "" {
		return store.Releve{Status: StatutArretee, Motif: r.arret}
	}
	if r.now().Before(r.pasAvant) {
		r.Log.Info("relève : passage sauté, Retry-After pas encore écoulé", "jusqu_a", r.pasAvant.UTC().Format(time.RFC3339))
		return store.Releve{Status: StatutSautee}
	}
	rel := store.Releve{StartedAt: r.now(), Status: "ok"}
	r.pass(ctx, &rel)
	rel.FinishedAt = r.now()
	if ctx.Err() != nil && rel.Status != "ok" {
		// Arrêt du service pendant le passage : ce n'est pas un échec de la relève.
		r.Log.Info("relève interrompue par l'arrêt du service")
		rel.Status = StatutInterrompue
		return rel
	}
	if err := r.Store.RecordReleve(context.WithoutCancel(ctx), rel); err != nil {
		r.Log.Error("consignation de la relève en échec", "err", err)
	}
	if rel.Status == "ok" {
		r.Log.Info("relève", "statut", rel.Status, "etablissements", rel.Instances, "mesures_nouvelles", rel.Inserted)
	} else if r.arret != "" {
		r.Log.Error("relève arrêtée jusqu'au redémarrage du service", "http", rel.HTTPStatus, "motif", rel.Motif)
	} else {
		r.Log.Warn("relève", "statut", rel.Status, "http", rel.HTTPStatus, "motif", rel.Motif)
	}
	return rel
}

// arreter consigne l'échec et cesse la relève (§ 11.5 : « consigner l'erreur et cesser »).
func (r *Runner) arreter(rel *store.Releve, status int, motif string) {
	r.Tokens.ForgetMachineToken()
	r.arret = motif + " — relève arrêtée jusqu'au redémarrage du service"
	r.echec(rel, status, r.arret)
}

// jeton : le jeton machine ; ok = false si le passage est déjà consigné en échec.
func (r *Runner) jeton(ctx context.Context, rel *store.Releve) (tok string, fresh, ok bool) {
	tok, fresh, err := r.Tokens.MachineToken(ctx)
	var te *oidc.ErrTokenEndpoint
	switch {
	case err == nil:
		return tok, fresh, true
	case errors.Is(err, oidc.ErrMachineScope):
		r.echec(rel, 400, "scopes machine non accordés")
	case errors.Is(err, oidc.ErrInvalidClient):
		r.arreter(rel, 401, "client refusé par IRUNDO (invalid_client : application révoquée ou secret changé)")
	case errors.As(err, &te):
		r.echec(rel, te.Status, "jeton machine refusé : "+te.Error())
	default:
		r.echec(rel, 0, "jeton machine : "+oidc.Borne(err.Error(), 200))
	}
	return "", false, false
}

func (r *Runner) echec(rel *store.Releve, status int, motif string) {
	rel.Status, rel.HTTPStatus, rel.Motif = "echec", status, motif
}

func (r *Runner) pass(ctx context.Context, rel *store.Releve) {
	tok, fresh, ok := r.jeton(ctx, rel)
	if !ok {
		return
	}
	rejoue := false
	// appel : un 401 sur un jeton du cache ⇒ un jeton neuf et un seul rejeu dans le passage.
	appel := func(f func(token string) error) bool {
		err := f(tok)
		if errors.Is(err, irundoo.ErrInvalidToken) && !fresh && !rejoue {
			rejoue = true
			r.Tokens.ForgetMachineToken()
			if tok, fresh, ok = r.jeton(ctx, rel); !ok {
				return false
			}
			err = f(tok)
		}
		if err != nil {
			r.apiErr(rel, err)
			return false
		}
		return true
	}
	var ins *irundoo.Instances
	if !appel(func(t string) (err error) { ins, err = r.API.Instances(ctx, t); return }) {
		return
	}
	rel.Instances = len(ins.Instances)
	known := map[string]bool{}
	locales := make([]store.Instance, 0, len(ins.Instances))
	for _, in := range ins.Instances {
		known[in.Id] = true
		locales = append(locales, store.Instance{ID: in.Id, Name: in.Name, UAI: in.Uai,
			EstablishmentName: in.EstablishmentName, EstablishmentType: in.EstablishmentType, Zone: in.AcademicZone, Active: in.Active})
	}
	var hw *irundoo.Hardware
	if !appel(func(t string) (err error) { hw, err = r.API.Hardware(ctx, t, ""); return }) {
		return
	}
	now := r.now()
	mesures := make([]store.Measure, 0, len(hw.Hardware))
	for _, m := range hw.Hardware {
		if !known[m.InstanceID] {
			// Ne devrait pas arriver (même jeton, même périmètre) : rien n'est pris hors de /instances.
			continue
		}
		res := etat.Compute(now, &etat.Mesure{CollectedAt: m.CollectedAt, ReceivedAt: m.ReceivedAt, Payload: m.Payload}, r.StaleAfter)
		sig, _ := json.Marshal(res.Signaux)
		if sig == nil || string(sig) == "null" {
			sig = []byte("[]")
		}
		mesures = append(mesures, store.Measure{InstanceID: m.InstanceID, ExtensionKey: m.ExtensionKey,
			ExtensionVersion: m.ExtensionVersion, MessageID: m.MessageID, Kind: m.Kind, CollectedAt: m.CollectedAt,
			ReceivedAt: m.ReceivedAt, Payload: m.Payload, Etat: string(res.Etat), Signaux: sig, BootID: res.BootID})
	}
	n, err := r.Store.EnregistrerPassage(ctx, locales, mesures)
	if err != nil {
		r.echec(rel, 0, "magasin local : "+oidc.Borne(err.Error(), 200))
		return
	}
	rel.Inserted = n
}

func (r *Runner) apiErr(rel *store.Releve, err error) {
	var sc *irundoo.ErrInsufficientScope
	var rl *irundoo.ErrRateLimited
	var ue *irundoo.ErrUnexpected
	switch {
	case errors.Is(err, irundoo.ErrInvalidToken):
		// Jeton neuf refusé, ou second 401 consécutif (§ 11.5).
		r.arreter(rel, 401, "jeton machine neuf refusé par l'API (401)")
	case errors.As(err, &sc):
		r.echec(rel, 403, "droit machine non accordé : "+sc.Scope)
	case errors.Is(err, irundoo.ErrPerimeterEmpty):
		r.echec(rel, 403, "aucun établissement accordé")
	case errors.Is(err, irundoo.ErrOutOfPerimeter):
		r.echec(rel, 403, "établissement hors périmètre")
	case errors.As(err, &rl):
		r.pasAvant = r.now().Add(rl.RetryAfter)
		r.echec(rel, 429, fmt.Sprintf("quota de l'extension atteint : passage abandonné, le suivant attend Retry-After (%d s)", int(rl.RetryAfter.Seconds())))
	case errors.Is(err, irundoo.ErrUnavailable):
		r.echec(rel, 503, "IRUNDO indisponible")
	case errors.As(err, &ue):
		r.echec(rel, ue.Status, ue.Error())
	default:
		r.echec(rel, 0, "IRUNDO injoignable : "+oidc.Borne(err.Error(), 200))
	}
}
