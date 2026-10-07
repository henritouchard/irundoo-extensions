package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/henritouchard/irundoo-extensions/extensions/centralisation-materiel/internal/fakeirundo"
	"github.com/henritouchard/irundoo-extensions/extensions/centralisation-materiel/internal/store"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *syncBuf) Write(p []byte) (int, error) { b.mu.Lock(); defer b.mu.Unlock(); return b.b.Write(p) }
func (b *syncBuf) String() string              { b.mu.Lock(); defer b.mu.Unlock(); return b.b.String() }

func TestRun(t *testing.T) {
	f := fakeirundo.New()
	defer f.Close()
	f.Instances = []map[string]any{fakeirundo.Instance("11111111-1111-4111-8111-111111111111", "A", "0951234A", true)}
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	_ = os.WriteFile(secret, []byte(f.ClientSecret+"\n"), 0o600)
	env := map[string]string{"IRUNDOO_ISSUER": f.Issuer(), "CLIENT_ID": f.ClientID, "CLIENT_SECRET_FILE": secret,
		"PUBLIC_URL": "http://127.0.0.1:8090", "DEV_INSECURE_COOKIES": "true", "DATA_DIR": filepath.Join(dir, "data"),
		"LISTEN": "127.0.0.1:0", "POLL_INTERVAL": "1m", "LOG_LEVEL": "debug"}
	logs := &syncBuf{}
	ready := make(chan string, 1)
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- run(ctx, func(k string) string { return env[k] }, logs, ready) }()
	var addr string
	select {
	case addr = <-ready:
	case err := <-errc:
		t.Fatal(err)
	}
	resp, err := http.Get("http://" + addr + "/health")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || strings.TrimSpace(string(b)) != `{"version":"0.1.0"}` {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	st, err := os.Stat(filepath.Join(dir, "data", store.FileName))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("%v %v", st.Mode(), err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(logs.String(), `"msg":"relève"`) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	out := logs.String()
	for _, want := range []string{`"msg":"démarrage"`, `"msg":"relève"`, `"statut":"ok"`, `"msg":"arrêté"`} {
		if !strings.Contains(out, want) {
			t.Errorf("absent du journal : %s", want)
		}
	}
	if strings.Contains(out, f.ClientSecret) || strings.Contains(out, "eyJ") {
		t.Fatal("secret ou jeton dans le journal")
	}
}

func TestRunConfigurationRefusee(t *testing.T) {
	err := run(context.Background(), func(string) string { return "" }, io.Discard, nil)
	if err == nil || !strings.Contains(err.Error(), "IRUNDOO_ISSUER") {
		t.Fatal(err)
	}
}
