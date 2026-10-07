// Package centralisation porte le manifeste IRUNDO de l'extension, embarqué dans le binaire : la
// version servie par /health est celle du manifeste (une seule source pour la version).
package centralisation

import (
	_ "embed"
	"encoding/json"
)

// ManifestJSON : octets de manifest.json.
//
//go:embed manifest.json
var ManifestJSON []byte

// Version : extension_version du manifeste embarqué.
func Version() string {
	var m struct {
		V string `json:"extension_version"`
	}
	if err := json.Unmarshal(ManifestJSON, &m); err != nil || m.V == "" {
		panic("manifest.json embarqué illisible")
	}
	return m.V
}
