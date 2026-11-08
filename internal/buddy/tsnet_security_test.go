//go:build ts_omit_peerapiserver && ts_omit_webclient && ts_omit_ssh && ts_omit_drive

package buddy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"tailscale.com/derp/derpserver"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/net/netns"
	"tailscale.com/net/stun/stuntest"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/key"
)

// Real tsnet nodes, a local fake control server, and local DERP/STUN. No login,
// external tailnet, VM, kernel TUN, or userspace loopback forwarding is involved.
func TestRealTSNetOnlyAcceptsBackupPort(t *testing.T) {
	if e := validateTSBuild(); e != nil {
		t.Fatal(e)
	}
	t.Setenv("BUDDY_TS_AUTHKEY", "test-only-key")
	t.Setenv("TS_LOGS_DIR", t.TempDir())
	netns.SetEnabled(false)
	t.Cleanup(func() { netns.SetEnabled(true) })
	quiet := func(string, ...any) {}
	control := &testcontrol.Server{DERPMap: localDERP(t), RequireAuthKey: "test-only-key", DNSConfig: &tailcfg.DNSConfig{}, Logf: quiet}
	control.HTTPTestServer = httptest.NewUnstartedServer(control)
	control.HTTPTestServer.Start()
	t.Cleanup(control.HTTPTestServer.Close)
	node := NewTSNetwork(t.TempDir())
	// The receive auth callback rejects before host dialing. No Docker DNS or bridge is needed.
	node.zfsEndpoint = func() (string, string, string, error) { return "127.0.0.1:2288", "127.0.0.1:22", "127.0.0.1", nil }
	node.controlURL = control.HTTPTestServer.URL
	if e := node.Start("receiver", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "backup-only") })); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { node.Close() })
	client := &tsnet.Server{Dir: filepath.Join(t.TempDir(), "client"), Hostname: "buddy-client", ControlURL: control.HTTPTestServer.URL, Store: noServeStore{new(mem.Store)}, AuthKey: "test-only-key", Logf: quiet, UserLogf: quiet}
	t.Cleanup(func() { client.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	receiverStatus, e := node.server.Up(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if len(receiverStatus.Self.PeerAPIURL) != 0 {
		t.Fatal("unexpected built-in PeerAPI listener", receiverStatus.Self.PeerAPIURL)
	}
	clientStatus, e := client.Up(ctx)
	if e != nil {
		t.Fatal(e)
	}
	ip := receiverStatus.TailscaleIPs[0].String()
	// An actual host loopback HTTP listener must be unreachable over the tailnet.
	sentinel, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer sentinel.Close()
	sentinelHTTP := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("tailnet reached host loopback")
		w.WriteHeader(500)
	})}
	go sentinelHTTP.Serve(sentinel)
	defer sentinelHTTP.Close()
	tr := &http.Transport{Proxy: nil, DialContext: client.Dial}
	defer tr.CloseIdleConnections()
	httpClient := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	res, e := httpClient.Get(fmt.Sprintf("http://%s:%d/", ip, BackupPort))
	if e != nil {
		t.Fatal(e)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if string(b) != "backup-only" {
		t.Fatal("backup port not reachable")
	}
	peer := Invitation{NodeID: string(clientStatus.Self.ID), IP: clientStatus.TailscaleIPs[0].String()}
	if !node.PeerSource(ctx, peer, net.JoinHostPort(peer.IP, "1234")) {
		t.Fatal("real pinned source rejected")
	}
	wrong := peer
	wrong.NodeID = "different-node"
	if node.PeerSource(ctx, wrong, net.JoinHostPort(peer.IP, "1234")) || node.PeerSource(ctx, peer, "100.100.100.100:1234") {
		t.Fatal("wrong source/node accepted")
	}

	blocked := []int{22, 80, 443, 8080, 2288, 8788, 5252, sentinel.Addr().(*net.TCPAddr).Port}
	for _, port := range blocked {
		t.Run(fmt.Sprint(port), func(t *testing.T) {
			pctx, pc := context.WithTimeout(ctx, time.Second)
			defer pc()
			conn, e := client.Dial(pctx, "tcp", net.JoinHostPort(ip, fmt.Sprint(port)))
			if e == nil {
				conn.Close()
				t.Fatalf("tsnet accepted forbidden port %d", port)
			}
		})
	}
	// Enabling receive registers exactly one additional tailnet listener. The
	// callback rejects every test connection before any host SSH dial occurs.
	if e := node.ConfigureZFS(true, false, func(context.Context, string) bool { return false }, func() *Invitation { return nil }); e != nil {
		t.Fatal(e)
	}
	pctx, pc := context.WithTimeout(ctx, 3*time.Second)
	conn, err := client.Dial(pctx, "tcp", net.JoinHostPort(ip, "8788"))
	pc()
	if err != nil {
		t.Fatal("enabled ZFS port unreachable", err)
	}
	conn.Close()
	for _, port := range []int{22, 2288, 8080, 443} {
		pctx, pc := context.WithTimeout(ctx, time.Second)
		conn, e := client.Dial(pctx, "tcp", net.JoinHostPort(ip, fmt.Sprint(port)))
		pc()
		if e == nil {
			conn.Close()
			t.Fatalf("enabled ZFS leaked port %d", port)
		}
	}
	if e := node.ConfigureZFS(false, false, nil, nil); e != nil {
		t.Fatal(e)
	}
	pctx, pc = context.WithTimeout(ctx, time.Second)
	defer pc()
	if conn, e := client.Dial(pctx, "tcp", net.JoinHostPort(ip, "8788")); e == nil {
		conn.Close()
		t.Fatal("disabled ZFS port remained open")
	}

}

func localDERP(t *testing.T) *tailcfg.DERPMap {
	t.Helper()
	server := derpserver.New(key.NewNode(), func(string, ...any) {})
	web := httptest.NewTLSServer(derpserver.Handler(server))
	stun, stopSTUN := stuntest.Serve(t)
	t.Cleanup(func() { web.CloseClientConnections(); web.Close(); server.Close(); stopSTUN() })
	return &tailcfg.DERPMap{Regions: map[int]*tailcfg.DERPRegion{1: {RegionID: 1, RegionCode: "local", Nodes: []*tailcfg.DERPNode{{Name: "local", RegionID: 1, HostName: "127.0.0.1", IPv4: "127.0.0.1", IPv6: "none", STUNPort: stun.Port, DERPPort: web.Listener.Addr().(*net.TCPAddr).Port, InsecureForTests: true, STUNTestIP: "127.0.0.1"}}}}}
}
