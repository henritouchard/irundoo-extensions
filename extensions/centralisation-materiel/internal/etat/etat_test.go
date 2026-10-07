package etat

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

func exemple(t *testing.T, nom string) map[string]any {
	t.Helper()
	b, err := os.ReadFile("../../testdata/hardware/" + nom + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// modif applique une altération à une copie profonde de la charge.
func modif(t *testing.T, p map[string]any, f func(map[string]any)) []byte {
	t.Helper()
	b, _ := json.Marshal(p)
	var c map[string]any
	_ = json.Unmarshal(b, &c)
	f(c)
	out, _ := json.Marshal(c)
	return out
}

func cles(r Resultat) []string {
	var out []string
	for _, s := range r.Signaux {
		out = append(out, s.Niveau+":"+s.Cle)
	}
	return out
}

func TestCompute(t *testing.T) {
	vm, phys, rf := exemple(t, "vm"), exemple(t, "physical"), exemple(t, "redfish")
	frais := now.Add(-time.Minute)
	cas := []struct {
		nom      string
		payload  []byte
		recu     time.Time
		etat     Etat
		contient []string
		mention  string
	}{
		{"vm.json : VM sans source matérielle", modif(t, vm, func(map[string]any) {}), frais, NonObserve, nil, ""},
		{"physical.json : physique, canal local seul", modif(t, phys, func(map[string]any) {}), frais, Sain, nil, "disques derrière contrôleur : inventaire seulement"},
		{"redfish.json : PSU critique, panne prédite", modif(t, rf, func(map[string]any) {}), frais, Critique,
			[]string{"critique:redfish.power.supplies[PS2 Status].health", "critique:redfish.power.redundancy",
				"critique:redfish.drive[Disk.Bay.3].failure_predicted", "critique:redfish.drive[Disk.Bay.3].health",
				"attention:redfish.system.health_rollup", "attention:redfish.sel_tail[PSU0003]"}, ""},
		{"mesure ancienne", modif(t, phys, func(map[string]any) {}), now.Add(-31 * time.Minute), PasDeNouvelle, nil, ""},
		{"sources absente, VM", modif(t, vm, func(m map[string]any) { delete(m, "sources") }), frais, NonObserve, nil, "sources non renseignées"},
		{"VM avec Redfish ok (carte de l'hôte)", modif(t, vm, func(m map[string]any) { m["sources"].(map[string]any)["redfish"] = "ok" }), frais, Sain, nil, ""},
		{"VM avec Proxmox partial", modif(t, vm, func(m map[string]any) { m["sources"].(map[string]any)["pve"] = "partial" }), frais, Sain, nil, ""},
		{"Redfish unauthorized, VM", modif(t, vm, func(m map[string]any) { m["sources"].(map[string]any)["redfish"] = "unauthorized" }), frais, NonObserve, nil, ""},
		{"md dégradé", modif(t, phys, func(m map[string]any) {
			m["md"] = []any{map[string]any{"name": "md0", "degraded": true, "array_state": "clean"}}
		}), frais, Critique, []string{"critique:md[md0].degraded"}, ""},
		{"md état inconnu", modif(t, phys, func(m map[string]any) {
			m["md"] = []any{map[string]any{"name": "md1", "degraded": false, "array_state": "inactive"}}
		}), frais, Critique, []string{"critique:md[md1].array_state"}, ""},
		{"SMART échoué", modif(t, phys, func(m map[string]any) {
			m["disk"].([]any)[0].(map[string]any)["smart"] = map[string]any{"passed": false}
		}), frais, Critique, []string{"critique:disk[sda].smart.passed"}, ""},
		{"SMART réalloués", modif(t, phys, func(m map[string]any) {
			m["disk"].([]any)[0].(map[string]any)["smart"] = map[string]any{"passed": true, "reallocated": 8.0, "pct_used": 91.0}
		}), frais, Attention, []string{"attention:disk[sda].smart.reallocated", "attention:disk[sda].smart.pct_used"}, ""},
		{"SMART non corrigibles", modif(t, phys, func(m map[string]any) {
			m["disk"].([]any)[0].(map[string]any)["smart"] = map[string]any{"passed": true, "uncorrectable": 1.0}
		}), frais, Critique, []string{"critique:disk[sda].smart.uncorrectable"}, ""},
		{"ioerr depuis le démarrage", modif(t, phys, func(m map[string]any) {
			m["disk"].([]any)[1].(map[string]any)["ioerr"] = 3.0
		}), frais, Attention, []string{"attention:disk[sdb].ioerr"}, ""},
		{"fs à 97 %", modif(t, phys, func(m map[string]any) {
			m["fs"] = []any{map[string]any{"mount": "/", "fstype": "ext4", "size_b": 100.0, "used_b": 97.0, "inodes_used_pct": 1.0}}
		}), frais, Critique, []string{"critique:fs[/].used_b"}, ""},
		{"fs à 92 %, VM", modif(t, vm, func(m map[string]any) {
			m["fs"] = []any{map[string]any{"mount": "/home", "fstype": "xfs", "size_b": 100.0, "used_b": 92.0, "inodes_used_pct": 91.0}}
		}), frais, Attention, []string{"attention:fs[/home].used_b", "attention:fs[/home].inodes_used_pct"}, ""},
		{"EDAC non corrigée", modif(t, phys, func(m map[string]any) {
			m["mem"].(map[string]any)["edac"].([]any)[1].(map[string]any)["ue"] = 1.0
		}), frais, Critique, []string{"critique:mem.edac[mc1].ue"}, ""},
		{"EDAC corrigée", modif(t, phys, func(m map[string]any) {
			m["mem"].(map[string]any)["edac"].([]any)[0].(map[string]any)["ce"] = 12.0
		}), frais, Attention, []string{"attention:mem.edac[mc0].ce"}, ""},
		{"température CPU au seuil crit", modif(t, phys, func(m map[string]any) {
			m["cpu"].(map[string]any)["temp_c"].([]any)[0].(map[string]any)["value"] = 98.0
		}), frais, Attention, []string{"attention:cpu.temp_c[coretemp/Package id 0]"}, ""},
		{"température mémoire sans crit ≥ 85", modif(t, phys, func(m map[string]any) {
			m["mem"].(map[string]any)["temp_c"] = []any{map[string]any{"sensor": "dimm0", "value": 86.0}}
		}), frais, Attention, []string{"attention:mem.temp_c[dimm0]"}, ""},
		{"mémoire disponible < 5 %", modif(t, phys, func(m map[string]any) {
			m["mem"].(map[string]any)["available_b"] = 1.0
		}), frais, Attention, []string{"attention:mem.available_b"}, ""},
		{"Proxmox usure", modif(t, vm, func(m map[string]any) {
			m["sources"].(map[string]any)["pve"] = "ok"
			m["pve"] = map[string]any{"disk": []any{map[string]any{"devpath": "/dev/sda", "wearout_pct": 5.0}}}
		}), frais, Attention, []string{"attention:pve.disk[/dev/sda].wearout_pct"}, ""},
		{"Redfish ventilateur et barrette", modif(t, rf, func(m map[string]any) {
			r := m["redfish"].(map[string]any)
			delete(r, "power")
			delete(r, "sel_tail")
			r["system"].(map[string]any)["health_rollup"] = "OK"
			r["drive"] = []any{}
			r["thermal"].(map[string]any)["fans"].([]any)[0].(map[string]any)["health"] = "Warning"
			r["memory"] = []any{map[string]any{"id": "DIMM.A1", "capacity_mib": 16384.0, "health": "Critical"}}
		}), frais, Attention, []string{"attention:redfish.thermal.fans[Fan1A].health", "attention:redfish.memory[DIMM.A1].health"}, ""},
		{"SEL ancien ignoré", modif(t, rf, func(m map[string]any) {
			r := m["redfish"].(map[string]any)
			r["sel_tail"].([]any)[0].(map[string]any)["timestamp"] = "2026-09-01T10:00:00Z"
			delete(r, "power")
			r["drive"] = []any{}
			r["system"].(map[string]any)["health_rollup"] = "OK"
		}), frais, Sain, nil, ""},
		{"système Critical", modif(t, rf, func(m map[string]any) {
			m["redfish"].(map[string]any)["system"].(map[string]any)["health"] = "Critical"
		}), frais, Critique, []string{"critique:redfish.system.health"}, ""},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			r := Compute(now, &Mesure{ReceivedAt: c.recu, Payload: c.payload}, 30*time.Minute)
			if r.Etat != c.etat {
				t.Fatalf("état %s, attendu %s (signaux %v)", r.Etat, c.etat, cles(r))
			}
			for _, k := range c.contient {
				if !slices.Contains(cles(r), k) {
					t.Errorf("signal %s absent de %v", k, cles(r))
				}
			}
			if c.mention != "" && !slices.Contains(r.Mentions, c.mention) {
				t.Errorf("mention %q absente de %v", c.mention, r.Mentions)
			}
		})
	}
}

func TestPasDeNouvelle(t *testing.T) {
	r := Compute(now, nil, 30*time.Minute)
	if r.Etat != PasDeNouvelle || r.Motif != "aucune mesure reçue" {
		t.Fatalf("%+v", r)
	}
	// La fraîcheur se juge sur received_at seul : une charge saine reçue il y a 3 h reste « pas de nouvelle ».
	p, _ := os.ReadFile("../../testdata/hardware/physical.json")
	r = Compute(now, &Mesure{ReceivedAt: now.Add(-3 * time.Hour), Payload: p}, 30*time.Minute)
	if r.Etat != PasDeNouvelle || !strings.Contains(r.Motif, "3 h") {
		t.Fatalf("%+v", r)
	}
	r = Compute(now, &Mesure{ReceivedAt: now.Add(-50 * 24 * time.Hour), Payload: p}, 30*time.Minute)
	if !strings.Contains(r.Motif, "50 j") {
		t.Fatal(r.Motif)
	}
	r = Compute(now, &Mesure{ReceivedAt: now.Add(-3 * time.Minute), Payload: p}, 2*time.Minute)
	if r.Etat != PasDeNouvelle || !strings.Contains(r.Motif, "3 min") {
		t.Fatalf("%+v", r)
	}
}

func TestTypesInattendus(t *testing.T) {
	p := []byte(`{"host":{"profile":"physical"},"sources":{"local":"ok"},
		"md":"pas une liste","disk":[42,{"name":"sda","ioerr":"trois","smart":{"passed":"non","reallocated":"8"}}],
		"fs":[{"mount":"/","size_b":"100","used_b":99}],"mem":{"edac":[{"mc":"mc0","ue":"1"}],"total_b":0,"available_b":0},
		"cpu":{"temp_c":[{"sensor":"x","value":"99"}]},"redfish":{"drive":{"id":"x"},"power":"non","system":[]}}`)
	r := Compute(now, &Mesure{ReceivedAt: now, Payload: p}, 30*time.Minute)
	if r.Etat != Sain {
		t.Fatalf("une valeur de type inattendu ne lève rien : %s %v", r.Etat, cles(r))
	}
	if r.Ignores < 10 {
		t.Fatalf("valeurs non évaluées comptées : %d", r.Ignores)
	}
	for _, bad := range []string{`[]`, `"x"`, `null`, `{`, ``} {
		r := Compute(now, &Mesure{ReceivedAt: now, Payload: []byte(bad)}, 30*time.Minute)
		if r.Etat != NonObserve {
			t.Fatalf("charge %q : %s", bad, r.Etat)
		}
	}
}

func TestDemarrage(t *testing.T) {
	p, _ := os.ReadFile("../../testdata/hardware/vm.json")
	recu := now.Add(-time.Minute)
	r := Compute(now, &Mesure{ReceivedAt: recu, Payload: p}, 30*time.Minute)
	if r.DemarreLe == nil || !r.DemarreLe.Equal(recu.Add(-1466698*time.Second)) || r.BootID != "3f2a9c1e-5b7d-4e8a-9c0f-1d2e3f4a5b6c" || r.Profil != "vm" {
		t.Fatalf("%+v", r)
	}
}

func TestRang(t *testing.T) {
	ordre := []Etat{Critique, Attention, PasDeNouvelle, NonObserve, Sain}
	for i := 1; i < len(ordre); i++ {
		if ordre[i-1].Rang() >= ordre[i].Rang() {
			t.Fatal(ordre[i])
		}
	}
}
