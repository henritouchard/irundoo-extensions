// Package etat calcule l'état matériel d'un établissement à partir de sa dernière mesure
// `hardware/v1` (contrat-mesures-materielles-v1.md § 5, § 6 « Lire une mesure » ;
// monitoring-materiel-inventaire.md § 6.3). Fonction pure : aucune E/S, aucune horloge implicite.
//
// La charge est lue en `map[string]any` tolérant : toute clé est optionnelle, une valeur d'un type
// inattendu n'est pas évaluée (comptée dans Ignores), jamais une panique, jamais un « critique » par
// défaut.
package etat

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Etat : constantes de chaîne, libellés français dans le gabarit.
type Etat string

// Les cinq états, exclusifs.
const (
	PasDeNouvelle Etat = "pas-de-nouvelle"
	NonObserve    Etat = "non-observe"
	Attention     Etat = "attention"
	Critique      Etat = "critique"
	Sain          Etat = "sain"
)

// Rang : ordre d'affichage (le plus grave d'abord).
func (e Etat) Rang() int {
	switch e {
	case Critique:
		return 0
	case Attention:
		return 1
	case PasDeNouvelle:
		return 2
	case NonObserve:
		return 3
	default:
		return 4
	}
}

// Niveau d'un signal.
const (
	NiveauCritique  = "critique"
	NiveauAttention = "attention"
)

// Signal : une valeur de la charge hors seuil.
type Signal struct {
	Niveau  string `json:"niveau"`
	Cle     string `json:"cle"`
	Message string `json:"message"`
}

// Mesure : ce dont le calcul a besoin d'une entrée de /hardware.
type Mesure struct {
	ReceivedAt time.Time
	Payload    []byte
}

// Resultat du calcul pour une ligne.
type Resultat struct {
	Etat     Etat
	Motif    string
	Signaux  []Signal
	Ignores  int
	Mentions []string
	Profil   string
	// DemarreLe : received_at − os.uptime_s (origine des compteurs remis à zéro), si connu.
	DemarreLe *time.Time
	BootID    string
}

// Seuils v1 (constantes ; réglables en D.4b).
const (
	SeuilTempDefautC    = 85.0
	SeuilFsAttention    = 0.90
	SeuilFsCritique     = 0.97
	SeuilInodeAttention = 90.0
	SeuilInodeCritique  = 97.0
	SeuilMemDispo       = 0.05
	SeuilUsureNVMe      = 90.0
	SeuilVieRestante    = 10.0
	FenetreSEL          = 7 * 24 * time.Hour
)

// Compute : état d'une ligne. m == nil : aucune entrée /hardware pour l'établissement.
// La fraîcheur se juge sur received_at (horloge d'IRUNDO), jamais collected_at.
func Compute(now time.Time, m *Mesure, staleAfter time.Duration) Resultat {
	if m == nil {
		return Resultat{Etat: PasDeNouvelle, Motif: "aucune mesure reçue"}
	}
	p := map[string]any{}
	r := Resultat{}
	if err := json.Unmarshal(m.Payload, &p); err != nil || p == nil {
		p = map[string]any{}
		r.Ignores++
	}
	sig, ign := Signaux(p, now)
	r.Signaux, r.Ignores = sig, r.Ignores+ign
	r.Profil, _ = str(get(p, "host", "profile"))
	if up, ok := num(get(p, "os", "uptime_s")); ok && up >= 0 {
		t := m.ReceivedAt.Add(-time.Duration(up) * time.Second)
		r.DemarreLe = &t
	}
	r.BootID, _ = str(get(p, "os", "boot_id"))

	if now.Sub(m.ReceivedAt) > staleAfter {
		r.Etat = PasDeNouvelle
		r.Motif = "dernière mesure reçue il y a " + duree(now.Sub(m.ReceivedAt))
		return r
	}
	sources, sourcesOK := p["sources"].(map[string]any)
	if !sourcesOK {
		r.Mentions = append(r.Mentions, "sources non renseignées")
	}
	for _, s := range r.Signaux {
		if s.Niveau == NiveauCritique {
			r.Etat = Critique
			return r
		}
	}
	if len(r.Signaux) > 0 {
		r.Etat = Attention
		return r
	}
	materiel := false
	for _, k := range []string{"redfish", "pve"} {
		if v, _ := str(sources[k]); v == "ok" || v == "partial" {
			materiel = true
		}
	}
	if r.Profil != "physical" && !materiel {
		r.Etat = NonObserve
		r.Motif = "matériel non observé (VM, aucune source matérielle)"
		if r.Profil == "" {
			r.Motif = "matériel non observé (profil inconnu, aucune source matérielle)"
		}
		return r
	}
	r.Etat = Sain
	if r.Profil == "physical" && !materiel && disquesSansSmart(p) {
		r.Mentions = append(r.Mentions, "disques derrière contrôleur : inventaire seulement")
	}
	return r
}

func disquesSansSmart(p map[string]any) bool {
	disks, ok := p["disk"].([]any)
	if !ok || len(disks) == 0 {
		return false
	}
	for _, d := range disks {
		if dm, ok := d.(map[string]any); ok {
			if _, has := dm["smart"]; has {
				return false
			}
		}
	}
	return true
}

// lecteur accumule signaux et valeurs ignorées.
type lecteur struct {
	sig []Signal
	ign int
}

func (l *lecteur) leve(niveau, cle, format string, a ...any) {
	l.sig = append(l.sig, Signal{Niveau: niveau, Cle: cle, Message: fmt.Sprintf(format, a...)})
}

// nombre lit une valeur numérique optionnelle : absente ⇒ (0, false) sans compter ; mauvais type ⇒ compté.
func (l *lecteur) nombre(m map[string]any, k string) (float64, bool) {
	v, has := m[k]
	if !has {
		return 0, false
	}
	f, ok := num(v)
	if !ok {
		l.ign++
	}
	return f, ok
}

func (l *lecteur) booleen(m map[string]any, k string) (bool, bool) {
	v, has := m[k]
	if !has {
		return false, false
	}
	b, ok := v.(bool)
	if !ok {
		l.ign++
	}
	return b, ok
}

func (l *lecteur) chaine(m map[string]any, k string) (string, bool) {
	v, has := m[k]
	if !has {
		return "", false
	}
	s, ok := v.(string)
	if !ok {
		l.ign++
	}
	return s, ok
}

// liste : éléments objets d'une liste optionnelle ; un élément non objet est compté et sauté.
func (l *lecteur) liste(v any) []map[string]any {
	if v == nil {
		return nil
	}
	arr, ok := v.([]any)
	if !ok {
		l.ign++
		return nil
	}
	out := make([]map[string]any, 0, len(arr))
	for _, e := range arr {
		if m, ok := e.(map[string]any); ok {
			out = append(out, m)
		} else {
			l.ign++
		}
	}
	return out
}

func (l *lecteur) objet(v any) map[string]any {
	if v == nil {
		return nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		l.ign++
	}
	return m
}

func nom(m map[string]any, k string, i int) string {
	if s, ok := m[k].(string); ok && s != "" {
		return s
	}
	return fmt.Sprint(i)
}

// Signaux évalue le tableau « Modèle d'état » de la story (seuils v1) sur une charge décodée.
// Retourne les signaux levés et le nombre de valeurs non évaluées (type inattendu).
func Signaux(p map[string]any, now time.Time) ([]Signal, int) {
	l := &lecteur{}

	for i, md := range l.liste(p["md"]) {
		n := nom(md, "name", i)
		if d, ok := l.booleen(md, "degraded"); ok && d {
			l.leve(NiveauCritique, "md["+n+"].degraded", "RAID %s dégradé", n)
		} else if st, ok := l.chaine(md, "array_state"); ok && !slices.Contains([]string{"clean", "active", "active-idle"}, st) {
			l.leve(NiveauCritique, "md["+n+"].array_state", "RAID %s : état %q", n, st)
		}
	}

	for i, d := range l.liste(p["disk"]) {
		n := nom(d, "name", i)
		if io, ok := l.nombre(d, "ioerr"); ok && io > 0 {
			l.leve(NiveauAttention, "disk["+n+"].ioerr", "disque %s : %.0f erreur(s) d'E/S depuis le démarrage", n, io)
		}
		sm := l.objet(d["smart"])
		if sm == nil {
			continue
		}
		if ok, has := l.booleen(sm, "passed"); has && !ok {
			l.leve(NiveauCritique, "disk["+n+"].smart.passed", "disque %s : test SMART échoué", n)
		}
		for _, c := range []struct {
			k, niv, lib string
		}{
			{"uncorrectable", NiveauCritique, "secteurs non corrigibles"},
			{"critical_warning", NiveauCritique, "avertissement critique NVMe"},
			{"reallocated", NiveauAttention, "secteurs réalloués"},
			{"pending", NiveauAttention, "secteurs en attente"},
			{"media_errors", NiveauAttention, "erreurs de support"},
		} {
			if v, ok := l.nombre(sm, c.k); ok && v > 0 {
				l.leve(c.niv, "disk["+n+"].smart."+c.k, "disque %s : %.0f %s", n, v, c.lib)
			}
		}
		if v, ok := l.nombre(sm, "pct_used"); ok && v >= SeuilUsureNVMe {
			l.leve(NiveauAttention, "disk["+n+"].smart.pct_used", "disque %s : usure %.0f %%", n, v)
		}
	}

	rf := l.objet(p["redfish"])
	if rf != nil {
		for i, d := range l.liste(rf["drive"]) {
			n := nom(d, "id", i)
			if fp, ok := l.booleen(d, "failure_predicted"); ok && fp {
				l.leve(NiveauCritique, "redfish.drive["+n+"].failure_predicted", "disque %s : panne prédite", n)
			}
			if h, ok := l.chaine(d, "health"); ok && h != "OK" {
				l.leve(NiveauCritique, "redfish.drive["+n+"].health", "disque %s : santé %s", n, h)
			}
			if v, ok := l.nombre(d, "life_left_pct"); ok && v <= SeuilVieRestante {
				l.leve(NiveauAttention, "redfish.drive["+n+"].life_left_pct", "disque %s : %.0f %% de vie restante", n, v)
			}
		}
		if sys := l.objet(rf["system"]); sys != nil {
			for _, k := range []string{"health", "health_rollup"} {
				switch h, _ := l.chaine(sys, k); h {
				case "Critical":
					l.leve(NiveauCritique, "redfish.system."+k, "serveur : santé %s Critical", k)
				case "Warning":
					l.leve(NiveauAttention, "redfish.system."+k, "serveur : santé %s Warning", k)
				}
			}
		}
		if pw := l.objet(rf["power"]); pw != nil {
			for i, s := range l.liste(pw["supplies"]) {
				n := nom(s, "name", i)
				if h, ok := l.chaine(s, "health"); ok && h != "OK" {
					l.leve(NiveauCritique, "redfish.power.supplies["+n+"].health", "alimentation %s : %s", n, h)
				}
			}
			if r, ok := l.chaine(pw, "redundancy"); ok && (r == "Degraded" || r == "Failed") {
				l.leve(NiveauCritique, "redfish.power.redundancy", "redondance d'alimentation : %s", r)
			}
		}
		if th := l.objet(rf["thermal"]); th != nil {
			for _, k := range []string{"fans", "temperatures"} {
				for i, e := range l.liste(th[k]) {
					n := nom(e, "name", i)
					if h, ok := l.chaine(e, "health"); ok && h != "OK" {
						l.leve(NiveauAttention, "redfish.thermal."+k+"["+n+"].health", "%s : %s", n, h)
					}
				}
			}
		}
		for i, e := range l.liste(rf["sel_tail"]) {
			sev, _ := l.chaine(e, "severity")
			if sev != "Critical" {
				continue
			}
			ts, ok := l.chaine(e, "timestamp")
			if !ok {
				continue
			}
			t, err := time.Parse(time.RFC3339, ts)
			if err != nil {
				l.ign++
				continue
			}
			if now.Sub(t) <= FenetreSEL && !t.After(now.Add(time.Hour)) {
				mid := nom(e, "message_id", i)
				l.leve(NiveauAttention, "redfish.sel_tail["+mid+"]", "journal matériel : événement critique %s le %s", mid, t.UTC().Format("2006-01-02"))
			}
		}
		for i, e := range l.liste(rf["memory"]) {
			n := nom(e, "id", i)
			if h, ok := l.chaine(e, "health"); ok && h != "OK" {
				l.leve(NiveauAttention, "redfish.memory["+n+"].health", "barrette %s : %s", n, h)
			}
		}
	}

	if pve := l.objet(p["pve"]); pve != nil {
		for i, d := range l.liste(pve["disk"]) {
			n := nom(d, "devpath", i)
			if v, ok := l.nombre(d, "wearout_pct"); ok && v <= SeuilVieRestante {
				l.leve(NiveauAttention, "pve.disk["+n+"].wearout_pct", "disque %s (Proxmox) : usure %.0f %%", n, v)
			}
		}
	}

	if mem := l.objet(p["mem"]); mem != nil {
		for i, e := range l.liste(mem["edac"]) {
			n := nom(e, "mc", i)
			if ue, ok := l.nombre(e, "ue"); ok && ue > 0 {
				l.leve(NiveauCritique, "mem.edac["+n+"].ue", "mémoire %s : %.0f erreur(s) non corrigée(s) depuis le démarrage", n, ue)
			} else if ce, ok := l.nombre(e, "ce"); ok && ce > 0 {
				l.leve(NiveauAttention, "mem.edac["+n+"].ce", "mémoire %s : %.0f erreur(s) corrigée(s) depuis le démarrage", n, ce)
			}
		}
		total, okT := l.nombre(mem, "total_b")
		avail, okA := l.nombre(mem, "available_b")
		if okT && okA && total > 0 && avail/total < SeuilMemDispo {
			l.leve(NiveauAttention, "mem.available_b", "mémoire disponible : %.1f %%", 100*avail/total)
		}
		temperatures(l, "mem", mem)
	}
	if cpu := l.objet(p["cpu"]); cpu != nil {
		temperatures(l, "cpu", cpu)
	}

	for i, fs := range l.liste(p["fs"]) {
		n := nom(fs, "mount", i)
		size, okS := l.nombre(fs, "size_b")
		used, okU := l.nombre(fs, "used_b")
		if okS && okU && size > 0 {
			switch r := used / size; {
			case r >= SeuilFsCritique:
				l.leve(NiveauCritique, "fs["+n+"].used_b", "volume %s plein à %.0f %%", n, 100*r)
			case r >= SeuilFsAttention:
				l.leve(NiveauAttention, "fs["+n+"].used_b", "volume %s plein à %.0f %%", n, 100*r)
			}
		}
		if v, ok := l.nombre(fs, "inodes_used_pct"); ok {
			switch {
			case v >= SeuilInodeCritique:
				l.leve(NiveauCritique, "fs["+n+"].inodes_used_pct", "volume %s : %.0f %% des inodes", n, v)
			case v >= SeuilInodeAttention:
				l.leve(NiveauAttention, "fs["+n+"].inodes_used_pct", "volume %s : %.0f %% des inodes", n, v)
			}
		}
	}
	slices.SortStableFunc(l.sig, func(a, b Signal) int {
		return strings.Compare(rangNiveau(a.Niveau), rangNiveau(b.Niveau))
	})
	return l.sig, l.ign
}

func rangNiveau(n string) string {
	if n == NiveauCritique {
		return "0"
	}
	return "1"
}

func temperatures(l *lecteur, famille string, m map[string]any) {
	for i, t := range l.liste(m["temp_c"]) {
		n := nom(t, "sensor", i)
		v, ok := l.nombre(t, "value")
		if !ok {
			continue
		}
		seuil := SeuilTempDefautC
		if c, ok := l.nombre(t, "crit"); ok {
			seuil = c
		}
		if v >= seuil {
			l.leve(NiveauAttention, famille+".temp_c["+n+"]", "température %s : %.0f °C (seuil %.0f °C)", n, v, seuil)
		}
	}
}

func get(p map[string]any, path ...string) any {
	var cur any = p
	for _, k := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[k]
	}
	return cur
}

func num(v any) (float64, bool) {
	f, ok := v.(float64)
	return f, ok
}

func str(v any) (string, bool) {
	s, ok := v.(string)
	return s, ok
}

func duree(d time.Duration) string {
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h", int(d.Hours()))
	default:
		return fmt.Sprintf("%d j", int(d.Hours()/24))
	}
}
