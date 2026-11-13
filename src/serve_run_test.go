package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"io/fs"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/skoszewski/serve-markdown/v3/render"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/cert"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/oidc"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/tokens"
)

// srvBuffer is a buffer written and read by several goroutines.
type srvBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *srvBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *srvBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// srvCaptureStderr makes os.Stderr a pipe until the test ends, and returns the buffer of what was
// written to it.
func srvCaptureStderr(t *testing.T) *srvBuffer {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = w
	b := &srvBuffer{}
	done := make(chan struct{})
	go func() {
		io.Copy(b, r)
		close(done)
	}()
	t.Cleanup(func() {
		os.Stderr = old
		w.Close()
		<-done
		r.Close()
	})
	return b
}

// srvWaitFor waits until the text of b holds each of want, failing the test after five seconds.
func srvWaitFor(t *testing.T, b *srvBuffer, want ...string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		missing := ""
		for _, w := range want {
			if !strings.Contains(b.String(), w) {
				missing = w
				break
			}
		}
		if missing == "" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%q not written; got:\n%s", missing, b.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// srvFreePort returns a TCP port of 127.0.0.1 that was free a moment ago.
func srvFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// srvLogState restores the loggers, the log stream and the settings of serve when the test ends.
func srvLogState(t *testing.T) {
	t.Helper()
	logger, stream, logRequests := slog.Default(), simpleca.LogStream, requestLog
	t.Cleanup(func() {
		slog.SetDefault(logger)
		log.SetOutput(os.Stderr)
		log.SetFlags(log.LstdFlags)
		simpleca.LogStream, requestLog, trustedProxies = stream, logRequests, nil
		downloadsDir, packagesDir = "", ""
	})
}

// srvTLSFiles makes a CA in a new directory and the certificate of localhost it issues, and
// returns the CA directory and the directory of the certificate and its key.
func srvTLSFiles(t *testing.T) (string, string) {
	t.Helper()
	caDir, tlsDir := t.TempDir(), t.TempDir()
	if err := cert.MakeCA(caDir, "TLS CA", 3650, "", "", "ec"); err != nil {
		t.Fatal(err)
	}
	if _, err := cert.MakeCert("localhost", nil, caDir, tlsDir, "server", 30, nil, nil, ""); err != nil {
		t.Fatal(err)
	}
	return caDir, tlsDir
}

func TestResolveTLS(t *testing.T) {
	t.Setenv("SIMPLE_CA_TLS_CERT", "")
	t.Setenv("SIMPLE_CA_TLS_KEY", "")
	if c, k, err := resolveTLS("", ""); c != "" || k != "" || err != nil {
		t.Errorf("no TLS: %q %q %v", c, k, err)
	}
	if c, k, err := resolveTLS("c.pem", "k.pem"); c != "c.pem" || k != "k.pem" || err != nil {
		t.Errorf("options: %q %q %v", c, k, err)
	}
	if _, _, err := resolveTLS("c.pem", ""); err == nil || !strings.Contains(err.Error(), "must be given together") {
		t.Errorf("--tls-cert alone: %v", err)
	}
	t.Setenv("SIMPLE_CA_TLS_CERT", "env-c.pem")
	t.Setenv("SIMPLE_CA_TLS_KEY", "env-k.pem")
	if c, k, err := resolveTLS("", ""); c != "env-c.pem" || k != "env-k.pem" || err != nil {
		t.Errorf("environment: %q %q %v", c, k, err)
	}
	if c, k, err := resolveTLS("c.pem", ""); c != "c.pem" || k != "env-k.pem" || err != nil {
		t.Errorf("--tls-cert and SIMPLE_CA_TLS_KEY: %q %q %v", c, k, err)
	}
}

func TestRunHTTPServerRefusals(t *testing.T) {
	caDir, tlsDir := srvTLSFiles(t)
	certFile, keyFile := filepath.Join(tlsDir, "localhost_cert.pem"), filepath.Join(tlsDir, "localhost_key.pem")
	dir := t.TempDir()
	noBlock := filepath.Join(dir, "none.pem")
	if err := os.WriteFile(noBlock, []byte("not PEM\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	badCert := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(badCert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("x")}), 0o600); err != nil {
		t.Fatal(err)
	}
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	busyPort := busy.Addr().(*net.TCPAddr).Port
	never := func(string) { t.Error("the server listens, want a refusal") }

	for _, c := range []struct {
		name, address string
		port          int
		cert, key     string
		want          string
	}{
		{"empty address", "", 8080, "", "", "--address must not be empty"},
		{"port 0", "127.0.0.1", 0, "", "", "--port must be from 1 to 65535, got 0"},
		{"port 65536", "127.0.0.1", 65536, "", "", "--port must be from 1 to 65535, got 65536"},
		{"port in use", "127.0.0.1", busyPort, "", "", "address already in use"},
		{"missing certificate", "127.0.0.1", srvFreePort(t), filepath.Join(dir, "missing.pem"), keyFile, "missing.pem"},
		{"no CERTIFICATE block", "127.0.0.1", srvFreePort(t), noBlock, keyFile, "no CERTIFICATE PEM block in"},
		{"bad certificate", "127.0.0.1", srvFreePort(t), badCert, keyFile, strconv.Quote(badCert) + ": "},
		{"missing key", "127.0.0.1", srvFreePort(t), certFile, filepath.Join(dir, "missing_key.pem"), "missing_key.pem"},
		{"key of another certificate", "127.0.0.1", srvFreePort(t), certFile, filepath.Join(caDir, "ca_key.pem"),
			"does not match the certificate"},
	} {
		err := runHTTPServer(http.NotFoundHandler(), c.address, c.port, c.cert, c.key, never)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
		// A refused TLS setup leaves its port free.
		if c.cert != "" {
			l, err := net.Listen("tcp", net.JoinHostPort(c.address, strconv.Itoa(c.port)))
			if err != nil {
				t.Errorf("%s: port %d is still bound after the refusal: %v", c.name, c.port, err)
				continue
			}
			l.Close()
		}
	}
}

func TestRunHTTPServer(t *testing.T) {
	srvLogState(t)
	caDir, tlsDir := srvTLSFiles(t)
	var lines srvBuffer
	simpleca.LogStream = func(line string, _ [][2]string, _ slog.Level) error {
		lines.Write([]byte(line))
		return nil
	}
	slog.SetDefault(slog.New(streamHandler{}))
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		io.WriteString(w, "tea")
	})
	pool := x509.NewCertPool()
	caPEM, err := os.ReadFile(filepath.Join(caDir, "ca_cert.pem"))
	if err != nil || !pool.AppendCertsFromPEM(caPEM) {
		t.Fatalf("CA certificate: %v", err)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}

	for _, c := range []struct {
		name, cert, key, scheme string
		log                     bool
	}{
		{"HTTP", "", "", "http", false},
		{"HTTPS with the request log", filepath.Join(tlsDir, "localhost_cert.pem"), filepath.Join(tlsDir, "localhost_key.pem"), "https", true},
	} {
		requestLog = c.log
		origins := make(chan string, 1)
		errs := make(chan error, 1)
		port := srvFreePort(t)
		go func() {
			errs <- runHTTPServer(handler, "localhost", port, c.cert, c.key, func(origin string) { origins <- origin })
		}()
		var origin string
		select {
		case origin = <-origins:
		case err := <-errs:
			t.Fatalf("%s: %v", c.name, err)
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: the server does not listen", c.name)
		}
		if !strings.HasPrefix(origin, c.scheme+"://") {
			t.Errorf("%s: origin %q", c.name, origin)
		}
		url := c.scheme + "://localhost:" + strconv.Itoa(port) + "/x"
		resp, err := client.Get(url)
		if err != nil {
			t.Fatalf("%s: GET %s: %v", c.name, url, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusTeapot || string(body) != "tea" || resp.Header.Get("X-Content-Type-Options") != "nosniff" ||
			resp.Header.Get("X-Frame-Options") != "DENY" || resp.Header.Get("Referrer-Policy") != "same-origin" {
			t.Errorf("%s: %d %q %v, want 418 tea with the security headers", c.name, resp.StatusCode, body, resp.Header)
		}
	}
	got := lines.String()
	if strings.Count(got, "event=http.request") != 1 || !strings.Contains(got, "status=418") || !strings.Contains(got, "path=/x") {
		t.Errorf("request log %q, want the one HTTPS request, with its status", got)
	}
}

// srvMakeCA makes a root CA with the settings config, unless empty, in a new directory, and returns
// the directory.
func srvMakeCA(t *testing.T, config string) string {
	t.Helper()
	dir := t.TempDir()
	if config != "" {
		if err := os.WriteFile(filepath.Join(dir, simpleca.ConfigFile), []byte(config), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := cert.MakeCA(dir, "Serve CA", 3650, "", "", "ec"); err != nil {
		t.Fatal(err)
	}
	return dir
}

// srvServe runs the command line serve of args in a goroutine and waits until it answers at port,
// failing the test with what stderr shows when it stops or does not answer.
func srvServe(t *testing.T, stderr *srvBuffer, port int, args ...string) {
	t.Helper()
	errs := make(chan error, 1)
	go func() {
		errs <- run(append([]string{"serve", "--port", strconv.Itoa(port)}, args...))
	}()
	origin := "http://localhost:" + strconv.Itoa(port)
	deadline := time.Now().Add(10 * time.Second)
	for {
		if resp, err := http.Get(origin + "/"); err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		select {
		case err := <-errs:
			t.Fatalf("serve %q: %v\n%s", args, err, stderr.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("serve %q does not answer at %s:\n%s", args, origin, stderr.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestRunServe(t *testing.T) {
	srvLogState(t)
	for _, name := range []string{"SIMPLE_CA_TLS_CERT", "SIMPLE_CA_TLS_KEY", "SIMPLE_CA_DIR", "SIMPLE_CA_KEY_PASSWORD",
		"SIMPLE_CA_KEY_PASSWORD_FILE"} {
		t.Setenv(name, "")
	}
	caDir := srvMakeCA(t, `{"tokens": {"keep_expired": "1d"}}`)
	if err := cert.MakeCA(caDir, "Servers CA", 0, "servers", "", "ec"); err != nil {
		t.Fatal(err)
	}
	if _, err := tokens.MakeToken(caDir, "old", time.Hour, nil, []string{"server"}, []string{"example.com"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	db, err := tokens.LoadTokens(caDir)
	if err != nil {
		t.Fatal(err)
	}
	db.Tokens["old"].Expires = time.Now().Add(-72 * time.Hour)
	if err := db.Save(caDir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(caDir, "servers", tokens.TokensFile), []byte("not JSON"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, tlsDir := srvTLSFiles(t)
	badTheme := srvMakeCA(t, "")
	if err := os.WriteFile(filepath.Join(badTheme, themeFile), []byte("not JSON"), 0o644); err != nil {
		t.Fatal(err)
	}
	badConfig := srvMakeCA(t, "")
	if err := os.WriteFile(filepath.Join(badConfig, simpleca.ConfigFile), []byte(`{"bogus": 1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	badUsers := srvMakeCA(t, "")
	if err := os.WriteFile(filepath.Join(badUsers, oidc.UsersFile), []byte("not JSON"), 0o644); err != nil {
		t.Fatal(err)
	}
	badKey := srvMakeCA(t, "")
	if err := os.WriteFile(filepath.Join(badKey, "ca_key.pem"),
		pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte("x")}), 0o600); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	savedDocs := docsSite
	docsSite = nil
	t.Cleanup(func() { docsSite = savedDocs })

	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"--bogus"}, ""},
		{[]string{"--tls-cert", "c.pem"}, "must be given together"},
		{[]string{"--docs"}, "--docs needs the browser files"},
		{[]string{"--downloads", file}, "--downloads: " + strconv.Quote(file) + " is not a directory"},
		{[]string{"--packages", filepath.Join(caDir, "missing")}, "--packages: "},
		{[]string{"--ca-dir", t.TempDir()}, ""},
		{[]string{"--ca-dir", badConfig}, "bogus"},
		{[]string{"--ca-dir", badTheme}, themeFile},
		{[]string{"--ca-dir", badKey}, ""},
		{[]string{"--ca-dir", badUsers}, ""},
		{[]string{"--ca-dir", caDir, "--trusted-proxy", "nope", "--tls-cert", filepath.Join(tlsDir, "localhost_cert.pem"),
			"--tls-key", filepath.Join(tlsDir, "localhost_key.pem")}, `--trusted-proxy: "nope" is not an IP address or a prefix`},
		{[]string{"--ca-dir", srvMakeCA(t, `{"tokens": {"keep_expired": "soon"}}`)}, "keep_expired"},
	} {
		err := run(append([]string{"serve", "--port", "0"}, c.args...))
		if err == nil || !strings.Contains(err.Error(), c.want) || strings.Contains(err.Error(), "--port must be") {
			t.Errorf("serve %q: %v, want %q", c.args, err, c.want)
		}
		trustedProxies = nil
	}

	guides, err := fs.Sub(docsPages, "docs")
	if err != nil {
		t.Fatal(err)
	}
	docsSite = render.New(guides, render.Options{Prefix: docsPath, Search: render.IndexSearch{"usage.md"},
		Menu: docsMenu, List: render.DefaultList, Assets: fstest.MapFS{"page.js": {Data: []byte("// page")}}})
	stderr := srvCaptureStderr(t)
	srvServe(t, stderr, srvFreePort(t), "--ca-dir", filepath.Join(caDir, "servers"), "--address", "localhost", "--webui",
		"--request-log", "--trusted-proxy", "10.0.0.0/8", "--downloads", t.TempDir(), "--packages", t.TempDir(), "--docs")
	log.Print("a line of the log package")
	srvWaitFor(t, stderr, "event=serve.start", "request_log=true", "page=index", "page=tokens", "page=certificates",
		"page=audit", "page=docs", "page=downloads", "page=apt", "event=serve.warning", "event=http.request",
		"a line of the log package", "event=token.purge", "count=1", "could not remove the expired tokens")
	if len(trustedProxies) != 1 || trustedProxies[0].String() != "10.0.0.0/8" {
		t.Errorf("trusted proxies %v, want 10.0.0.0/8", trustedProxies)
	}
	if db, err := tokens.LoadTokens(caDir); err != nil || db.Tokens["old"] != nil {
		t.Errorf("tokens after serve started: %v, want the expired token removed", err)
	}

	trustedProxies = nil
	srvServe(t, stderr, srvFreePort(t), "--ca-dir", srvMakeCA(t, ""))
}

func TestStreamHandler(t *testing.T) {
	srvLogState(t)
	type record struct {
		line  string
		pairs [][2]string
		level slog.Level
	}
	var got []record
	simpleca.LogStream = func(line string, pairs [][2]string, level slog.Level) error {
		got = append(got, record{line, pairs, level})
		return nil
	}
	h := streamHandler{}.WithAttrs([]slog.Attr{slog.String("ca", "servers")})
	if g, ok := h.WithGroup("g").(streamHandler); !ok || len(g.attrs) != 1 {
		t.Error("WithGroup returns another handler, want groups unused")
	}
	if !h.Enabled(t.Context(), slog.LevelDebug) {
		t.Error("Enabled for debug, want every level")
	}
	slog.New(h).Warn("serve.warning", "message", "plain")
	if len(got) != 1 || got[0].level != slog.LevelWarn || !strings.Contains(got[0].line, "event=serve.warning") ||
		!strings.Contains(got[0].line, "ca=servers") || !strings.Contains(got[0].line, "message=plain") {
		t.Fatalf("records %+v, want the warning with the attribute of WithAttrs", got)
	}

	slog.SetDefault(slog.New(streamHandler{}))
	if n, err := (logWriter{}).Write([]byte("http: TLS handshake error\n")); n != len("http: TLS handshake error\n") || err != nil {
		t.Errorf("logWriter.Write: %d %v", n, err)
	}
	if len(got) != 2 || !strings.Contains(got[1].line, `message="http: TLS handshake error"`) {
		t.Errorf("records %+v, want the line of the log package as its message", got)
	}

	stderr := srvCaptureStderr(t)
	simpleca.LogStream = nil
	slog.Info("serve.start", "version", "test")
	if err := streamStderr("a line\n", nil, slog.LevelInfo); err != nil {
		t.Errorf("streamStderr: %v", err)
	}
	srvWaitFor(t, stderr, "event=serve.start", "version=test", "a line\n")
}
