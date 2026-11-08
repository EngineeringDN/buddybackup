//go:build integration

package buddy

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"time"
)

// Only linked into the explicitly tagged integration image. Never use on a real LAN.
type testNetwork struct{ server *http.Server }

func NetworkFromEnvironment(dir string) (Network, error) {
	if os.Getenv("BUDDY_TEST_TRANSPORT") == "1" {
		return &testNetwork{}, nil
	}
	return NewTSNetwork(dir), nil
}
func (n *testNetwork) Start(name string, h http.Handler) error {
	if n.server != nil {
		return nil
	}
	ln, e := backupListener(netListen{})
	if e != nil {
		return e
	}
	n.server = &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go n.server.Serve(ln)
	return nil
}

type netListen struct{}

func (netListen) Listen(network, addr string) (net.Listener, error) { return net.Listen(network, addr) }
func (n *testNetwork) Login(context.Context) error                  { return nil }
func (n *testNetwork) Status(context.Context) (NetworkStatus, error) {
	return NetworkStatus{Ready: n.server != nil, IP: os.Getenv("BUDDY_TEST_IP"), NodeID: os.Getenv("BUDDY_TEST_NODE"), Warnings: []string{"Testtransport ohne Tailscale."}}, nil
}
func (n *testNetwork) Dial(ctx context.Context, i Invitation) (net.Conn, error) {
	if i.NodeID != os.Getenv("BUDDY_TEST_PEER_NODE") || i.IP != os.Getenv("BUDDY_TEST_PEER_IP") || i.Port != BackupPort {
		return nil, errors.New("Test-Geräteidentität stimmt nicht überein.")
	}
	return (&net.Dialer{}).DialContext(ctx, "tcp", os.Getenv("BUDDY_TEST_PEER_HOST")+":8787")
}
func (n *testNetwork) Verify(ctx context.Context, i Invitation, d bool) (string, error) {
	return "direct", authenticatedProbe(ctx, i, n.Dial)
}
func (n *testNetwork) Close() error {
	if n.server != nil {
		return n.server.Close()
	}
	return nil
}
