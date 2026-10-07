// Package releve est la relève de fond : sous jeton machine (client_credentials, B.8), toutes les
// POLL_INTERVAL, elle lit /instances puis /hardware et accumule les mesures nouvelles en SQLite
// (seul endroit où l'historique existe : l'API ne sert que la dernière mesure).
//
// Un passage = au plus un jeton + deux appels d'API. Aucun retry dans le passage : 401 ⇒ jeton
// oublié, redemandé au passage suivant ; 429 ⇒ attendre Retry-After puis abandonner ; 503, réseau,
// 403 ⇒ passage en échec consigné. Jamais de rafale.
package releve

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/henritouchard/irundoo-extensions/extensions/centralisation-materiel/internal/etat"
	"github.com/henritouchard/irundoo-extensions/extensions/centralisation-materiel/internal/irundoo"
	"github.com/henritouchard/irundoo-extensions/extensions/centralisation-materiel/internal/oidc"
	"github.com/henritouchard/irundoo-extensions/extensions/centralisation-materiel/internal/store"
)

// Tokener : le jeton machine (oidc.Client).
type Tokener interface {
	MachineToken(ctx context.Context) (string, error)
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
	// Sleep attend d ou l'annulation (remplaçable en test).
	Sleep func(ctx context.Context, d time.Duration)
}

func sleepCtx(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

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

// Pass : un passage. Retourne le passage consigné.
func (r *Runner) Pass(ctx context.Context) store.Releve {
	rel := store.Releve{StartedAt: r.now(), Status: "ok"}
	r.pass(ctx, &rel)
	rel.FinishedAt = r.now()
	if err := r.Store.RecordReleve(context.WithoutCancel(ctx), rel); err != nil {
		r.Log.Error("consignation de la relève en échec", "err", err)
	}
	if rel.Status == "ok" {
		r.Log.Info("relève", "statut", rel.Status, "etablissements", rel.Instances, "mesures_nouvelles", rel.Inserted)
	} else {
		r.Log.Warn("relève", "statut", rel.Status, "http", rel.HTTPStatus, "motif", rel.Motif)
	}
	return rel
}

func (r *Runner) echec(rel *store.Releve, status int, motif string) {
	rel.Status, rel.HTTPStatus, rel.Motif = "echec", status, motif
}

func (r *Runner) pass(ctx context.Context, rel *store.Releve) {
	tok, err := r.Tokens.MachineToken(ctx)
	if err != nil {
		if errors.Is(err, oidc.ErrMachineScope) {
			r.echec(rel, 400, "scopes machine non accordés")
			return
		}
		r.echec(rel, oidc.TokenErrorStatus(err), "jeton machine : "+err.Error())
		return
	}
	ins, err := r.API.Instances(ctx, tok)
	if err != nil {
		r.apiErr(ctx, rel, err)
		return
	}
	rel.Instances = len(ins.Instances)
	known := map[string]bool{}
	for _, in := range ins.Instances {
		known[in.Id] = true
		if err := r.Store.UpsertInstance(ctx, store.Instance{ID: in.Id, Name: in.Name, UAI: in.Uai,
			EstablishmentName: in.EstablishmentName, EstablishmentType: in.EstablishmentType, Zone: in.AcademicZone, Active: in.Active}); err != nil {
			r.echec(rel, 0, "magasin local : "+err.Error())
			return
		}
	}
	hw, err := r.API.Hardware(ctx, tok, "")
	if err != nil {
		r.apiErr(ctx, rel, err)
		return
	}
	now := r.now()
	for _, m := range hw.Hardware {
		if !known[m.InstanceID] {
			// Ne devrait pas arriver (même jeton, même périmètre) : rien n'est pris hors de /instances.
			continue
		}
		res := etat.Compute(now, &etat.Mesure{ReceivedAt: m.ReceivedAt, Payload: m.Payload}, r.StaleAfter)
		sig, _ := json.Marshal(res.Signaux)
		if sig == nil || string(sig) == "null" {
			sig = []byte("[]")
		}
		ok, err := r.Store.Insert(ctx, store.Measure{InstanceID: m.InstanceID, ExtensionKey: m.ExtensionKey,
			ExtensionVersion: m.ExtensionVersion, MessageID: m.MessageID, Kind: m.Kind, CollectedAt: m.CollectedAt,
			ReceivedAt: m.ReceivedAt, Payload: m.Payload, Etat: string(res.Etat), Signaux: sig, BootID: res.BootID})
		if err != nil {
			r.echec(rel, 0, "magasin local : "+err.Error())
			return
		}
		if ok {
			rel.Inserted++
		}
	}
}

func (r *Runner) apiErr(ctx context.Context, rel *store.Releve, err error) {
	var sc *irundoo.ErrInsufficientScope
	var rl *irundoo.ErrRateLimited
	var ue *irundoo.ErrUnexpected
	switch {
	case errors.Is(err, irundoo.ErrInvalidToken):
		r.Tokens.ForgetMachineToken()
		r.echec(rel, 401, "jeton machine refusé : redemandé au passage suivant")
	case errors.As(err, &sc):
		r.echec(rel, 403, "droit machine non accordé : "+sc.Scope)
	case errors.Is(err, irundoo.ErrPerimeterEmpty):
		r.echec(rel, 403, "aucun établissement accordé")
	case errors.Is(err, irundoo.ErrOutOfPerimeter):
		r.echec(rel, 403, "établissement hors périmètre")
	case errors.As(err, &rl):
		sleep := r.Sleep
		if sleep == nil {
			sleep = sleepCtx
		}
		sleep(ctx, rl.RetryAfter)
		r.echec(rel, 429, "quota de l'extension atteint : passage abandonné")
	case errors.Is(err, irundoo.ErrUnavailable):
		r.echec(rel, 503, "IRUNDO indisponible")
	case errors.As(err, &ue):
		r.echec(rel, ue.Status, ue.Error())
	default:
		r.echec(rel, 0, "IRUNDO injoignable : "+err.Error())
	}
}
