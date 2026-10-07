// Package irundoo appelle l'API des extensions d'IRUNDO (`{issuer}/api/v1/extensions`) par le client
// généré depuis openapi-v1.json, et traduit chaque refus en erreur typée (api-v1.md § 5 ;
// fournisseur-oidc.md § 11.3). Il ne connaît d'IRUNDO que cette surface publique.
package irundoo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/henritouchard/irundoo-extensions/extensions/centralisation-materiel/internal/irundoo/irundooapi"
)

// MaxBody borne la lecture d'une réponse (8 Mio).
const MaxBody = 8 << 20

// Erreurs typées, décidées sur `error` du corps (jamais sur le texte).
var (
	// ErrInvalidToken : 401, avec ou sans corps. Conduite : renouveler le jeton une fois.
	ErrInvalidToken = errors.New("irundoo: jeton refusé (401)")
	// ErrPerimeterEmpty : 403 perimeter_empty.
	ErrPerimeterEmpty = errors.New("irundoo: périmètre vide (403 perimeter_empty)")
	// ErrOutOfPerimeter : 403 out_of_perimeter.
	ErrOutOfPerimeter = errors.New("irundoo: établissement hors périmètre (403 out_of_perimeter)")
	// ErrUnavailable : 503 server_error (vérification des jetons indisponible).
	ErrUnavailable = errors.New("irundoo: IRUNDO indisponible (503)")
)

// ErrInsufficientScope : 403 insufficient_scope ; Scope nomme le scope requis par la route.
type ErrInsufficientScope struct{ Scope string }

func (e *ErrInsufficientScope) Error() string {
	return "irundoo: droit non accordé (403 insufficient_scope) : " + e.Scope
}

// ErrRateLimited : 429 ; RetryAfter vient de l'en-tête Retry-After.
type ErrRateLimited struct{ RetryAfter time.Duration }

func (e *ErrRateLimited) Error() string {
	return fmt.Sprintf("irundoo: quota atteint (429), réessayer dans %s", e.RetryAfter)
}

// ErrUnexpected : tout autre statut ou corps illisible (403 d'un code inconnu compris).
type ErrUnexpected struct {
	Status int
	Code   string
}

func (e *ErrUnexpected) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("irundoo: réponse inattendue %d (%s)", e.Status, e.Code)
	}
	return fmt.Sprintf("irundoo: réponse inattendue %d", e.Status)
}

// Instance : un établissement de `/instances` (sept clés, api-v1.md § 4).
type Instance = irundooapi.Instance

// Instances : réponse de `/instances`.
type Instances struct {
	Instances []Instance
	Reduced   bool
}

// Measure : une entrée de `/hardware` (huit clés, contrat D.2 § 6). Payload garde les octets JSON
// tels que servis (le modèle généré le décode en map, ce qui perdrait la forme servie).
type Measure struct {
	InstanceID       string          `json:"instance_id"`
	ExtensionKey     string          `json:"extension_key"`
	ExtensionVersion *string         `json:"extension_version"`
	MessageID        string          `json:"message_id"`
	Kind             string          `json:"kind"`
	CollectedAt      time.Time       `json:"collected_at"`
	ReceivedAt       time.Time       `json:"received_at"`
	Payload          json.RawMessage `json:"payload"`
}

// Hardware : réponse de `/hardware`.
type Hardware struct {
	Hardware []Measure `json:"hardware"`
	Reduced  bool      `json:"reduced"`
}

// Client appelle la surface v1. Base = `{issuer}/api/v1/extensions` (servers[0] de la spécification).
type Client struct {
	api       *irundooapi.Client
	userAgent string
}

// NewHTTPClient : délais imposés (connexion 5 s, total 15 s).
func NewHTTPClient() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DialContext = (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	tr.TLSHandshakeTimeout = 5 * time.Second
	return &http.Client{
		Timeout:   15 * time.Second,
		Transport: tr,
		// Une API qui redirige n'est pas suivie : le jeton ne part jamais vers une autre adresse.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// New : issuer = IRUNDOO_ISSUER (préfixe de chemin compris, sans « / » final).
func New(issuer string, hc *http.Client, version string) (*Client, error) {
	base := strings.TrimRight(issuer, "/") + "/api/v1/extensions/"
	api, err := irundooapi.NewClient(base, irundooapi.WithHTTPClient(hc))
	if err != nil {
		return nil, err
	}
	return &Client{api: api, userAgent: "centralisation-materiel/" + version}, nil
}

func (c *Client) editor(token string) irundooapi.RequestEditorFn {
	return func(_ context.Context, req *http.Request) error {
		if token == "" {
			return errors.New("irundoo: aucun appel sans jeton")
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", c.userAgent)
		return nil
	}
}

// Instances : GET /instances avec le jeton (utilisateur ou machine).
func (c *Client) Instances(ctx context.Context, token string) (*Instances, error) {
	resp, err := c.api.ApiExtensionsV1Instances(ctx, nil, c.editor(token))
	if err != nil {
		return nil, err
	}
	body, err := read(resp)
	if err != nil {
		return nil, err
	}
	var out irundooapi.InstancesResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, &ErrUnexpected{Status: resp.StatusCode, Code: "corps illisible"}
	}
	return &Instances{Instances: out.Instances, Reduced: out.Reduced}, nil
}

// Hardware : GET /hardware avec le jeton (utilisateur ou machine). instance, si non vide, réduit
// la liste (`?instance=`) : l'appelant ne passe qu'un id rendu par /instances au même rendu.
func (c *Client) Hardware(ctx context.Context, token, instance string) (*Hardware, error) {
	var params *irundooapi.ApiExtensionsV1HardwareParams
	if instance != "" {
		params = &irundooapi.ApiExtensionsV1HardwareParams{Instance: &instance}
	}
	resp, err := c.api.ApiExtensionsV1Hardware(ctx, params, c.editor(token))
	if err != nil {
		return nil, err
	}
	body, err := read(resp)
	if err != nil {
		return nil, err
	}
	var out Hardware
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(&out); err != nil {
		return nil, &ErrUnexpected{Status: resp.StatusCode, Code: "corps illisible"}
	}
	if out.Hardware == nil {
		out.Hardware = []Measure{}
	}
	return &out, nil
}

// read lit au plus MaxBody octets et traduit tout statut autre que 200 en erreur typée.
func read(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBody+1))
	if err != nil {
		return nil, err
	}
	if len(body) > MaxBody {
		return nil, &ErrUnexpected{Status: resp.StatusCode, Code: "corps trop volumineux"}
	}
	if resp.StatusCode == http.StatusOK {
		return body, nil
	}
	return nil, decodeError(resp, body)
}

func decodeError(resp *http.Response, body []byte) error {
	var e struct {
		Error string `json:"error"`
		Scope string `json:"scope"`
	}
	_ = json.Unmarshal(body, &e) // le 401 sans jeton a un corps vide (api-v1.md § 5)
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return ErrInvalidToken
	case http.StatusForbidden:
		switch e.Error {
		case "insufficient_scope":
			return &ErrInsufficientScope{Scope: e.Scope}
		case "perimeter_empty":
			return ErrPerimeterEmpty
		case "out_of_perimeter":
			return ErrOutOfPerimeter
		}
	case http.StatusTooManyRequests:
		return &ErrRateLimited{RetryAfter: retryAfter(resp.Header.Get("Retry-After"))}
	case http.StatusServiceUnavailable:
		return ErrUnavailable
	}
	return &ErrUnexpected{Status: resp.StatusCode, Code: e.Error}
}

// retryAfter : secondes (1 à 60 annoncées) ; borné à [1 s, 60 s], 60 s si illisible.
func retryAfter(v string) time.Duration {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n < 1 {
		if err == nil {
			return time.Second
		}
		return 60 * time.Second
	}
	if n > 60 {
		n = 60
	}
	return time.Duration(n) * time.Second
}
