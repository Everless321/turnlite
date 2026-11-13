package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/Everless321/turnlite/turnrest"
	"github.com/pion/turn/v4"
)

func TestAllowPeerSSRFVectors(t *testing.T) {
	cases := map[string]bool{
		"8.8.8.8":                    true,
		"1.1.1.1":                    true,
		"2001:4860:4860::8888":       true,
		"10.0.0.1":                   false,
		"172.16.10.25":               false,
		"192.168.1.2":                false,
		"127.0.0.1":                  false,
		"100.100.100.200":            false,
		"100.64.0.1":                 false,
		"169.254.169.254":            false, // cloud metadata IPv4
		"198.18.52.33":               false, // RFC 2544 / Fake-IP
		"0.1.2.3":                    false,
		"224.0.0.1":                  false,
		"::1":                        false,
		"fd00::1":                    false,
		"fe80::1":                    false,
		"::ffff:127.0.0.1":           false, // IPv4-mapped loopback
		"::ffff:169.254.169.254":     false, // IPv4-mapped metadata
		"::ffff:10.0.0.5":            false, // IPv4-mapped private
		"::ffff:100.64.1.2":          false, // IPv4-mapped CGNAT
		"::ffff:8.8.8.8":             true,  // IPv4-mapped public unmaps cleanly
	}
	for ip, want := range cases {
		if got := allowPeer(nil, net.ParseIP(ip), false); got != want {
			t.Errorf("allowPeer(%s, false) = %v, want %v", ip, got, want)
		}
	}

	if !allowPeer(nil, net.ParseIP("192.168.1.2"), true) {
		t.Error("allowPrivate=true should allow RFC1918")
	}
	if allowPeer(nil, net.ParseIP("0.0.0.0"), true) {
		t.Error("allowPrivate=true should still block 0.0.0.0")
	}
}

func TestCertLoaderHotReloadAndResilience(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	writeSelfSignedCert(t, certPath, keyPath, big.NewInt(1))

	loader, err := newCertLoader(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	first, err := loader.get(nil)
	if err != nil || first == nil {
		t.Fatalf("first load: %v", err)
	}

	// Ensure distinct mtime for second cert.
	time.Sleep(20 * time.Millisecond)
	writeSelfSignedCert(t, certPath, keyPath, big.NewInt(2))
	second, err := loader.get(nil)
	if err != nil || second == nil || second == first {
		t.Fatalf("expected hot-reloaded cert pointer change")
	}

	// Corrupt disk cert mid-renewal: loader must continue serving the last valid cert.
	time.Sleep(20 * time.Millisecond)
	if err := os.WriteFile(certPath, []byte("truncated"), 0o600); err != nil {
		t.Fatal(err)
	}
	fallback, err := loader.get(nil)
	if err != nil || fallback != second {
		t.Fatalf("expected fallback to cached valid cert on corrupt read")
	}
}

func TestQuotaConcurrency(t *testing.T) {
	q := newQuota(4)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				if q.allow("u", "", nil) {
					q.add("u", 1)
					q.add("u", -1)
				}
			}
		}()
	}
	wg.Wait()
}

// TestRelayEndToEnd runs the real binary and talks to it with pion's TURN client.
func TestRelayEndToEnd(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "relay")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	const secret = "test-secret-0123456789abcdef"
	secretFile := filepath.Join(dir, "secret")
	if err := os.WriteFile(secretFile, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	port := freePort(t)
	cmd := exec.Command(bin, "-public-ip", "127.0.0.1", "-listen-ip", "127.0.0.1", "-port", strconv.Itoa(port),
		"-tls-port", "0", "-secret-file", secretFile, "-min-port", "50100", "-max-port", "50199", "-realm", "test")
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	time.Sleep(300 * time.Millisecond)
	server := "127.0.0.1:" + strconv.Itoa(port)

	creds, err := turnrest.Mint([]byte(secret), "session-1", time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("stun", func(t *testing.T) {
		c := newClient(t, server, creds.Username, creds.Password)
		if _, err := c.SendBindingRequest(); err != nil {
			t.Fatalf("binding: %v", err)
		}
	})

	t.Run("allocate and permissions", func(t *testing.T) {
		c := newClient(t, server, creds.Username, creds.Password)
		relay, err := c.Allocate()
		if err != nil {
			t.Fatalf("allocate: %v", err)
		}
		defer relay.Close()
		if err := c.CreatePermission(&net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 9}); err != nil {
			t.Errorf("public peer rejected: %v", err)
		}
		for _, ip := range []string{"10.0.0.1", "172.16.10.25", "100.100.100.200", "169.254.169.254", "127.0.0.1"} {
			if err := c.CreatePermission(&net.UDPAddr{IP: net.ParseIP(ip), Port: 9}); err == nil {
				t.Errorf("private peer %s allowed", ip)
			}
		}
	})

	t.Run("bad credential", func(t *testing.T) {
		c := newClient(t, server, creds.Username, "wrong")
		if _, err := c.Allocate(); err == nil {
			t.Fatal("allocate with a wrong password succeeded")
		}
	})

	t.Run("expired credential", func(t *testing.T) {
		exp, _ := turnrest.Mint([]byte(secret), "session-2", time.Now(), -time.Minute)
		c := newClient(t, server, exp.Username, exp.Password)
		if _, err := c.Allocate(); err == nil {
			t.Fatal("allocate with an expired credential succeeded")
		}
	})
}

func newClient(t *testing.T, server, user, pass string) *turn.Client {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c, err := turn.NewClient(&turn.ClientConfig{
		STUNServerAddr: server, TURNServerAddr: server, Conn: conn,
		Username: user, Password: pass, Realm: "test", RTO: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Listen(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(); _ = conn.Close() })
	return c
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func writeSelfSignedCert(t *testing.T, certPath, keyPath string, serial *big.Int) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "turnlite-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	kder, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	_ = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0o600)
}
