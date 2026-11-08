package buddy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/feature/buildfeatures"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/ipn/store"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
)

type NetworkStatus struct {
	Ready    bool     `json:"ready"`
	AuthURL  string   `json:"auth_url"`
	NodeID   string   `json:"node_id"`
	IP       string   `json:"ip"`
	Warnings []string `json:"warnings"`
}
type Network interface {
	Start(string, http.Handler) error
	Login(context.Context) error
	Status(context.Context) (NetworkStatus, error)
	Verify(context.Context, Invitation, bool) (string, error)
	Dial(context.Context, Invitation) (net.Conn, error)
	Close() error
}
type TSNetwork struct {
	controlURL string // Set only by in-package tests; production uses official control.
	mu         sync.Mutex
	server     *tsnet.Server
	local      *local.Client
	http       *http.Server
	dir        string
}

// Upstream's LocalBackend dispatches its built-in PeerAPI before tsnet listeners.
// Fail closed even when a developer builds without the mandatory omission tags.
func validateTSBuild() error {
	if buildfeatures.HasPeerAPIServer || buildfeatures.HasWebClient || buildfeatures.HasSSH || buildfeatures.HasDrive {
		return errors.New("Unsicherer Build: Tailscale PeerAPI, Webclient, SSH und Drive müssen per Build-Tags deaktiviert sein.")
	}
	return nil
}

func NewTSNetwork(dir string) *TSNetwork { return &TSNetwork{dir: dir} }
func tailnetIP(s string) bool {
	a, e := netip.ParseAddr(s)
	return e == nil && netip.MustParsePrefix("100.64.0.0/10").Contains(a)
}

// Exactly one listener is registered. No Loopback, Serve, Funnel, fallback handlers,
// SOCKS or generic HTTP proxy is enabled. tsnet rejects unregistered TCP/UDP ports.
func backupListener(s interface {
	Listen(string, string) (net.Listener, error)
}) (net.Listener, error) {
	return s.Listen("tcp", fmt.Sprintf(":%d", BackupPort))
}
func (n *TSNetwork) Start(name string, h http.Handler) error {
	if e := validateTSBuild(); e != nil {
		return e
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.server != nil {
		return nil
	}
	tsDir := filepath.Join(n.dir, "tailscale")
	if e := os.MkdirAll(tsDir, 0700); e != nil {
		return e
	}
	disk, e := store.New(func(string, ...any) {}, filepath.Join(tsDir, "tailscaled.state"))
	if e != nil {
		return e
	}
	s := &tsnet.Server{Dir: filepath.Join(n.dir, "tailscale"), Hostname: "buddy-" + name, AuthKey: os.Getenv("BUDDY_TS_AUTHKEY"), ControlURL: n.controlURL, RunWebClient: false, Store: noServeStore{disk}, Logf: func(string, ...any) {}, UserLogf: func(string, ...any) {}}
	ln, e := backupListener(s)
	if e != nil {
		s.Close()
		return errors.New("Tailscale konnte nicht gestartet werden.")
	}
	lc, e := s.LocalClient()
	if e != nil {
		ln.Close()
		s.Close()
		return e
	}
	n.server = s
	n.local = lc
	n.http = &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 16384}
	go n.http.Serve(ln)
	return nil
}
func (n *TSNetwork) client() (*tsnet.Server, *local.Client, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.local == nil {
		return nil, nil, errors.New("Tailscale wurde noch nicht eingerichtet.")
	}
	return n.server, n.local, nil
}
func (n *TSNetwork) Login(ctx context.Context) error {
	_, lc, e := n.client()
	if e != nil {
		return e
	}
	st, e := lc.Status(ctx)
	if e != nil {
		return e
	}
	if st.BackendState == "Running" {
		return nil
	}
	return lc.StartLoginInteractive(ctx)
}
func (n *TSNetwork) Status(ctx context.Context) (NetworkStatus, error) {
	_, lc, e := n.client()
	if e != nil {
		return NetworkStatus{}, nil
	}
	s, e := lc.Status(ctx)
	if e != nil {
		return NetworkStatus{}, errors.New("Tailscale-Status ist nicht erreichbar.")
	}
	r := NetworkStatus{Ready: s.BackendState == "Running", AuthURL: s.AuthURL, Warnings: []string{}}
	if s.Self != nil {
		r.NodeID = string(s.Self.ID)
		for _, a := range s.Self.TailscaleIPs {
			if a.Is4() {
				r.IP = a.String()
				break
			}
		}
		if s.Self.Expired {
			r.Ready = false
			r.Warnings = append(r.Warnings, "Tailscale-Geräteschlüssel ist abgelaufen.")
		}
		if s.Self.KeyExpiry != nil && time.Until(*s.Self.KeyExpiry) < 14*24*time.Hour {
			r.Warnings = append(r.Warnings, "Tailscale-Geräteschlüssel läuft in weniger als 14 Tagen ab.")
		}
	}
	r.Ready = r.Ready && r.IP != ""
	return r, nil
}
func pinnedPeer(s *ipnstate.Status, inv Invitation) error {
	if s.BackendState != "Running" {
		return errors.New("Tailscale ist nicht verbunden.")
	}
	for _, p := range s.Peer {
		if string(p.ID) == inv.NodeID {
			for _, a := range p.TailscaleIPs {
				if a.String() == inv.IP && !p.Expired {
					return nil
				}
			}
			return errors.New("Die bestätigte Geräteadresse stimmt nicht überein oder der Schlüssel ist abgelaufen.")
		}
	}
	return errors.New("Die bestätigte Tailscale-Geräteidentität fehlt. Gegenseitige Gerätefreigabe prüfen.")
}
func (n *TSNetwork) pin(ctx context.Context, inv Invitation) error {
	_, lc, e := n.client()
	if e != nil {
		return e
	}
	st, e := lc.Status(ctx)
	if e != nil {
		return errors.New("Geräteidentität konnte nicht geprüft werden.")
	}
	return pinnedPeer(st, inv)
}
func (n *TSNetwork) Dial(ctx context.Context, inv Invitation) (net.Conn, error) {
	s, _, e := n.client()
	if e != nil {
		return nil, e
	}
	if e = n.pin(ctx, inv); e != nil {
		return nil, e
	}
	return s.Dial(ctx, "tcp", net.JoinHostPort(inv.IP, strconv.Itoa(inv.Port)))
}
func authenticatedProbe(ctx context.Context, inv Invitation, dial func(context.Context, Invitation) (net.Conn, error)) error {
	tr := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return dial(ctx, inv) }, DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	r, _ := http.NewRequestWithContext(ctx, http.MethodHead, "http://"+net.JoinHostPort(inv.IP, strconv.Itoa(inv.Port))+"/"+inv.Username+"/config", nil)
	r.SetBasicAuth(inv.Username, inv.Password)
	res, e := c.Do(r)
	if e != nil {
		return errors.New("Freund nicht erreichbar. Gegenseitige Freigabe und Netzwerkregeln prüfen.")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 && res.StatusCode != 404 {
		return errors.New("Backup-Zugang wurde abgelehnt.")
	}
	return nil
}
func (n *TSNetwork) Verify(ctx context.Context, inv Invitation, direct bool) (string, error) {
	// Online is deliberately not consulted. Shared-in peers expose stable ID/IP in
	// the netmap, while Online only reports connectivity to the control plane.
	if e := authenticatedProbe(ctx, inv, n.Dial); e != nil {
		return "unknown", e
	}
	_, lc, e := n.client()
	if e != nil {
		return "unknown", e
	}
	pctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	route := "unknown"
	for range 4 {
		p, e := lc.Ping(pctx, netip.MustParseAddr(inv.IP), tailcfg.PingDisco)
		if e != nil || p.Err != "" {
			break
		}
		if p.Endpoint != "" && p.DERPRegionID == 0 && p.PeerRelay == "" {
			route = "direct"
			break
		}
		route = "relay"
	}
	if direct && route != "direct" {
		return route, errors.New("Keine bestätigte Direktverbindung. Übertragung pausiert.")
	}
	return route, nil
}
func (n *TSNetwork) Close() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.http != nil {
		n.http.Close()
	}
	if n.server != nil {
		return n.server.Close()
	}
	return nil
}

// tsnet currently cannot compile with ts_omit_serve. Block persisted Serve
// configuration before LocalBackend starts instead; no transient forwarding.
// The only LocalAPI client is in-process and the UI exposes no Serve API.
type noServeStore struct{ ipn.StateStore }

func (s noServeStore) ReadState(k ipn.StateKey) ([]byte, error) {
	if strings.HasPrefix(string(k), "_serve/") {
		return nil, ipn.ErrStateNotExist
	}
	return s.StateStore.ReadState(k)
}
func (s noServeStore) WriteState(k ipn.StateKey, b []byte) error {
	if strings.HasPrefix(string(k), "_serve/") {
		var c map[string]any
		if len(b) > 0 && (json.Unmarshal(b, &c) != nil || len(c) > 0) {
			return errors.New("Tailscale Serve ist für BuddyBackup gesperrt.")
		}
		return nil
	}
	return s.StateStore.WriteState(k, b)
}
