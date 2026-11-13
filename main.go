// Command relay (`turnlite`) is an SSRF-hardened, standalone STUN/TURN server
// compatible with WebRTC clients and the TURN REST (static-auth-secret) scheme.
package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Everless321/turnlite/turnrest"
	"github.com/pion/logging"
	"github.com/pion/turn/v4"
)

func main() {
	publicIP := flag.String("public-ip", "", "public IP announced as the relay address (required unless -mint)")
	listenIP := flag.String("listen-ip", "0.0.0.0", "local IP to listen and relay on")
	port := flag.Int("port", 3478, "STUN/TURN port (UDP and TCP)")
	tlsPort := flag.Int("tls-port", 5349, "TURN over TLS port; 0 disables it")
	certFile := flag.String("cert", "", "TLS certificate chain (PEM), cached and hot-reloaded on mtime change")
	keyFile := flag.String("key", "", "TLS private key (PEM)")
	realm := flag.String("realm", "turnlite", "TURN realm")
	secretFile := flag.String("secret-file", "", "file holding the shared TURN REST secret (fallback: TURN_SECRET env)")
	minPort := flag.Int("min-port", 49160, "first relay port")
	maxPort := flag.Int("max-port", 49359, "last relay port")
	userQuota := flag.Int("user-quota", 8, "max concurrent allocations per credential")
	allowPrivate := flag.Bool("allow-private", false, "allow relaying to private/CGNAT/loopback peers (dev only)")
	mintID := flag.String("mint", "", "mint TURN REST credentials JSON for this session/user ID and exit")
	mintTTL := flag.Duration("mint-ttl", 8*time.Hour, "TTL for -mint credentials")
	flag.Parse()

	secret, err := loadSecret(*secretFile)
	if err != nil {
		log.Fatal(err)
	}

	if *mintID != "" {
		if err := runMint([]byte(secret), *mintID, *mintTTL, *realm, *port, *tlsPort); err != nil {
			log.Fatal(err)
		}
		return
	}

	relayIP := net.ParseIP(*publicIP)
	if relayIP == nil {
		log.Fatal("-public-ip is required")
	}
	if err := validatePorts(*port, *tlsPort, *minPort, *maxPort, *userQuota); err != nil {
		log.Fatal(err)
	}

	addr := net.JoinHostPort(*listenIP, strconv.Itoa(*port))
	udp, err := net.ListenPacket("udp4", addr)
	if err != nil {
		log.Fatalf("listen udp: %v", err)
	}
	tcp, err := net.Listen("tcp4", addr)
	if err != nil {
		log.Fatalf("listen tcp: %v", err)
	}

	perm := func(client net.Addr, peer net.IP) bool {
		return allowPeer(client, peer, *allowPrivate)
	}
	gen := func() turn.RelayAddressGenerator {
		return &turn.RelayAddressGeneratorPortRange{
			RelayAddress: relayIP,
			Address:      *listenIP,
			MinPort:      uint16(*minPort),
			MaxPort:      uint16(*maxPort),
		}
	}

	listeners := []turn.ListenerConfig{{Listener: tcp, RelayAddressGenerator: gen(), PermissionHandler: perm}}
	if *tlsPort > 0 {
		if *certFile == "" || *keyFile == "" {
			log.Fatal("-cert and -key are required when -tls-port is set")
		}
		loader, err := newCertLoader(*certFile, *keyFile)
		if err != nil {
			log.Fatalf("load tls cert: %v", err)
		}
		cfg := &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: loader.get,
		}
		tl, err := tls.Listen("tcp4", net.JoinHostPort(*listenIP, strconv.Itoa(*tlsPort)), cfg)
		if err != nil {
			log.Fatalf("listen tls: %v", err)
		}
		listeners = append(listeners, turn.ListenerConfig{Listener: tl, RelayAddressGenerator: gen(), PermissionHandler: perm})
	}

	quota := newQuota(*userQuota)
	logs := logging.NewDefaultLoggerFactory()
	logs.DefaultLogLevel = logging.LogLevelWarn
	server, err := turn.NewServer(turn.ServerConfig{
		Realm: *realm,
		AuthHandler: func(username, authRealm string, _ net.Addr) ([]byte, bool) {
			return turnrest.Verify([]byte(secret), authRealm, username, time.Now())
		},
		QuotaHandler:      quota.allow,
		LoggerFactory:     logs,
		PacketConnConfigs: []turn.PacketConnConfig{{PacketConn: udp, RelayAddressGenerator: gen(), PermissionHandler: perm}},
		ListenerConfigs:   listeners,
		EventHandler: turn.EventHandler{
			OnAllocationCreated: func(src, _ net.Addr, proto, user, _ string, relay net.Addr, _ int) {
				quota.add(user, 1)
				log.Printf("allocation created %s user=%s client=%s relay=%s", proto, user, src, relay)
			},
			OnAllocationDeleted: func(src, _ net.Addr, proto, user, _ string) {
				quota.add(user, -1)
				log.Printf("allocation deleted %s user=%s client=%s", proto, user, src)
			},
			OnAuth: func(src, _ net.Addr, _, user, _, method string, ok bool) {
				if !ok {
					log.Printf("auth rejected %s user=%s client=%s", method, user, src)
				}
			},
		},
	})
	if err != nil {
		log.Fatalf("start: %v", err)
	}
	log.Printf("relay on %s (udp+tcp), tls :%d, relay %s ports %d-%d allow-private=%t",
		addr, *tlsPort, relayIP, *minPort, *maxPort, *allowPrivate)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	_ = server.Close()
}

func loadSecret(secretFile string) (string, error) {
	var raw string
	if secretFile != "" {
		b, err := os.ReadFile(secretFile)
		if err != nil {
			return "", fmt.Errorf("read secret: %w", err)
		}
		raw = string(b)
	} else {
		raw = os.Getenv("TURN_SECRET")
	}
	secret := strings.TrimSpace(raw)
	if len(secret) < 16 {
		return "", fmt.Errorf("-secret-file or TURN_SECRET (>= 16 bytes) is required")
	}
	return secret, nil
}

func runMint(secret []byte, id string, ttl time.Duration, realm string, port, tlsPort int) error {
	creds, err := turnrest.Mint(secret, id, time.Now(), ttl)
	if err != nil {
		return err
	}
	var urls []string
	if realm != "" {
		if port > 0 {
			urls = append(urls, fmt.Sprintf("stun:%s:%d", realm, port))
			urls = append(urls, fmt.Sprintf("turn:%s:%d?transport=udp", realm, port))
			urls = append(urls, fmt.Sprintf("turn:%s:%d?transport=tcp", realm, port))
		}
		if tlsPort > 0 {
			urls = append(urls, fmt.Sprintf("turns:%s:%d?transport=tcp", realm, tlsPort))
		}
	}
	out := struct {
		URLs       []string  `json:"urls,omitempty"`
		Username   string    `json:"username"`
		Credential string    `json:"credential"`
		ExpiresAt  time.Time `json:"expiresAt"`
	}{
		URLs:       urls,
		Username:   creds.Username,
		Credential: creds.Password,
		ExpiresAt:  creds.ExpiresAt,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func validatePorts(port, tlsPort, minPort, maxPort, userQuota int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid -port %d", port)
	}
	if tlsPort < 0 || tlsPort > 65535 {
		return fmt.Errorf("invalid -tls-port %d", tlsPort)
	}
	if minPort < 1 || maxPort > 65535 || minPort > maxPort {
		return fmt.Errorf("invalid relay port range %d-%d", minPort, maxPort)
	}
	if userQuota < 1 {
		return fmt.Errorf("invalid -user-quota %d", userQuota)
	}
	return nil
}

var blockedIPv4Prefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // "this network"
	netip.MustParsePrefix("100.64.0.0/10"),   // CGNAT / Tailscale / cloud metadata overlaps
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1
	netip.MustParsePrefix("198.18.0.0/15"),   // RFC 2544 benchmark / Fake-IP TUN
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3
	netip.MustParsePrefix("255.255.255.255/32"),
}

var blockedIPv6Prefixes = []netip.Prefix{
	netip.MustParsePrefix("100::/64"),      // Discard-Only
	netip.MustParsePrefix("2001:db8::/32"), // Documentation
}

// allowPeer keeps the relay from reaching non-public destinations (SSRF guard):
// unmaps IPv4-mapped IPv6 addresses and blocks loopback, RFC1918/ULA, link-local,
// CGNAT, multicast, unspecified, and test/benchmark prefixes unless allowPrivate is true.
func allowPeer(_ net.Addr, ip net.IP, allowPrivate bool) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	if addr.IsUnspecified() || addr.IsMulticast() {
		return false
	}
	if allowPrivate {
		return true
	}
	if !addr.IsGlobalUnicast() || addr.IsPrivate() {
		return false
	}
	if addr.Is4() {
		for _, p := range blockedIPv4Prefixes {
			if p.Contains(addr) {
				return false
			}
		}
		return true
	}
	for _, p := range blockedIPv6Prefixes {
		if p.Contains(addr) {
			return false
		}
	}
	return true
}

// certLoader caches the active X.509 keypair in memory and reloads only when file mtimes advance.
type certLoader struct {
	certPath string
	keyPath  string

	mu       sync.Mutex
	cert     *tls.Certificate
	certTime time.Time
	keyTime  time.Time
}

func newCertLoader(certPath, keyPath string) (*certLoader, error) {
	l := &certLoader{certPath: certPath, keyPath: keyPath}
	if err := l.reloadIfNeeded(); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *certLoader) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.reloadLocked(); err != nil && l.cert == nil {
		return nil, err
	}
	return l.cert, nil
}

func (l *certLoader) reloadIfNeeded() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.reloadLocked()
}

func (l *certLoader) reloadLocked() error {
	cInfo, err := os.Stat(l.certPath)
	if err != nil {
		return err
	}
	kInfo, err := os.Stat(l.keyPath)
	if err != nil {
		return err
	}
	if l.cert != nil && cInfo.ModTime().Equal(l.certTime) && kInfo.ModTime().Equal(l.keyTime) {
		return nil
	}
	loaded, err := tls.LoadX509KeyPair(l.certPath, l.keyPath)
	if err != nil {
		return err
	}
	l.cert = &loaded
	l.certTime = cInfo.ModTime()
	l.keyTime = kInfo.ModTime()
	return nil
}

type quota struct {
	mu    sync.Mutex
	max   int
	count map[string]int
}

func newQuota(max int) *quota { return &quota{max: max, count: map[string]int{}} }

func (q *quota) allow(user, _ string, _ net.Addr) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.count[user] < q.max
}

func (q *quota) add(user string, d int) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.count[user] += d; q.count[user] <= 0 {
		delete(q.count, user)
	}
}
