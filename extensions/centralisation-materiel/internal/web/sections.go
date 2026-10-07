package web

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Ordre et titres des familles de la charge hardware/v1 (contrat D.2 § 5). Une famille inconnue
// (ajout futur) est rendue à la suite, sous sa clé.
var familles = []struct{ cle, titre string }{
	{"sources", "Sources"},
	{"host", "Hôte"},
	{"os", "Système"},
	{"cpu", "Processeur"},
	{"mem", "Mémoire"},
	{"fs", "Systèmes de fichiers"},
	{"disk", "Disques"},
	{"md", "RAID logiciel (md)"},
	{"redfish", "Carte de gestion (Redfish)"},
	{"pve", "Proxmox"},
}

// TitreHote : section Redfish d'un hôte de virtualisation (redfish.scope = hypervisor-host).
const TitreHote = "Matériel de l'hôte de virtualisation (partagé, Redfish) — non attribué à l'établissement"

// sections rend la charge en tableaux, de façon tolérante : objet ⇒ clé / valeur, liste d'objets ⇒
// tableau à colonnes. Aucune valeur n'est interprétée ici (l'état est calculé par internal/etat).
func sections(payload []byte) []Section {
	var p map[string]any
	if err := json.Unmarshal(payload, &p); err != nil || p == nil {
		return nil
	}
	var out []Section
	vu := map[string]bool{}
	for _, f := range familles {
		vu[f.cle] = true
		if v, ok := p[f.cle]; ok {
			titre := f.titre
			if rf, ok := v.(map[string]any); ok && f.cle == "redfish" && rf["scope"] == "hypervisor-host" {
				// La carte est celle de l'hôte Proxmox, partagée : pas le matériel de l'établissement.
				titre = TitreHote
			}
			out = append(out, rendre(titre, v)...)
		}
	}
	var autres []string
	for k := range p {
		if !vu[k] {
			autres = append(autres, k)
		}
	}
	sort.Strings(autres)
	for _, k := range autres {
		out = append(out, rendre(k, p[k])...)
	}
	return out
}

func rendre(titre string, v any) []Section {
	switch t := v.(type) {
	case map[string]any:
		s := Section{Titre: titre, Entetes: []string{"Clé", "Valeur"}}
		var sub []Section
		for _, k := range cles(t) {
			switch c := t[k].(type) {
			case []any:
				sub = append(sub, rendre(titre+" — "+k, c)...)
			case map[string]any:
				if plat(c) {
					s.Lignes = append(s.Lignes, []string{k, valeur(c)})
				} else {
					sub = append(sub, rendre(titre+" — "+k, c)...)
				}
			default:
				s.Lignes = append(s.Lignes, []string{k, valeur(c)})
			}
		}
		if len(s.Lignes) > 0 {
			return append([]Section{s}, sub...)
		}
		return sub
	case []any:
		var objs []map[string]any
		for _, e := range t {
			if m, ok := e.(map[string]any); ok {
				objs = append(objs, m)
			}
		}
		if len(objs) == 0 {
			return []Section{{Titre: titre, Lignes: [][]string{{"(vide)"}}, Entetes: []string{""}}}
		}
		colset := map[string]bool{}
		for _, m := range objs {
			for k := range m {
				colset[k] = true
			}
		}
		cols := cles(colset)
		remplissage := colset["size_b"] && colset["used_b"]
		s := Section{Titre: titre, Entetes: cols}
		if remplissage {
			s.Entetes = append(s.Entetes, "rempli")
		}
		for _, m := range objs {
			var row []string
			for _, c := range cols {
				if x, ok := m[c]; ok {
					row = append(row, valeur(x))
				} else {
					row = append(row, "")
				}
			}
			if remplissage {
				row = append(row, pourcent(m["used_b"], m["size_b"]))
			}
			s.Lignes = append(s.Lignes, row)
		}
		return []Section{s}
	default:
		return []Section{{Titre: titre, Entetes: []string{"Valeur"}, Lignes: [][]string{{valeur(v)}}}}
	}
}

func plat(m map[string]any) bool {
	for _, v := range m {
		switch v.(type) {
		case map[string]any, []any:
			return false
		}
	}
	return true
}

func cles[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func valeur(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case float64:
		if t == float64(int64(t)) {
			return fmt.Sprintf("%d", int64(t))
		}
		return fmt.Sprintf("%g", t)
	case bool:
		if t {
			return "oui"
		}
		return "non"
	case map[string]any:
		var parts []string
		for _, k := range cles(t) {
			parts = append(parts, k+" : "+valeur(t[k]))
		}
		return strings.Join(parts, ", ")
	default:
		b, _ := json.Marshal(t)
		return string(b)
	}
}

func pourcent(used, size any) string {
	u, ok1 := used.(float64)
	s, ok2 := size.(float64)
	if !ok1 || !ok2 || s <= 0 {
		return ""
	}
	return fmt.Sprintf("%.0f", 100*u/s)
}
