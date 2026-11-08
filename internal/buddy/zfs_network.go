package buddy

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const ZFSPort = 8788
const ZFSLocalPort = 2288

// Optional interface keeps the restic transport contract unchanged.
type zfsNetwork interface {
	ConfigureZFS(bool, bool, func(context.Context, string) bool, func() *Invitation) error
	ZFSDial(context.Context, Invitation) (net.Conn, error)
	PeerSource(context.Context, Invitation, string) bool
}

type zfsTunnels struct {
	mu        sync.Mutex
	listeners []net.Listener
	conns     map[net.Conn]bool
	closed    bool
}

func (z *zfsTunnels) close() {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.closed = true
	for _, l := range z.listeners {
		l.Close()
	}
	for c := range z.conns {
		c.Close()
	}
}
func (z *zfsTunnels) track(c net.Conn) bool {
	z.mu.Lock()
	defer z.mu.Unlock()
	if z.closed {
		c.Close()
		return false
	}
	z.conns[c] = true
	return true
}
func (z *zfsTunnels) forward(c net.Conn, allowed func(string) bool, dial func(context.Context) (net.Conn, error)) {
	if !z.track(c) {
		return
	}
	defer func() { c.Close(); z.mu.Lock(); delete(z.conns, c); z.mu.Unlock() }()
	if !allowed(c.RemoteAddr().String()) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	dst, e := dial(ctx)
	if e != nil {
		return
	}
	if !z.track(dst) {
		return
	}
	defer func() { dst.Close(); z.mu.Lock(); delete(z.conns, dst); z.mu.Unlock() }()
	done := make(chan struct{})
	go func() {
		io.Copy(dst, c)
		if t, ok := dst.(interface{ CloseWrite() error }); ok {
			t.CloseWrite()
		}
		close(done)
	}()
	io.Copy(c, dst)
	c.Close()
	dst.Close()
	<-done
}
func (z *zfsTunnels) serve(l net.Listener, allowed func(string) bool, dial func(context.Context) (net.Conn, error)) {
	z.listeners = append(z.listeners, l)
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			go z.forward(c, allowed, dial)
		}
	}()
}

// Compose maps host.docker.internal to host-gateway, which Docker points at the host through its
// default bridge. That address differs from this container's own bridge gateway, which is what
// published ports appear to come from, so the SSH target and the allowed client are separate.
func bridgeEndpoint() (bind, target, client string, err error) {
	hosts, e := net.LookupIP("host.docker.internal")
	if e != nil {
		return "", "", "", errors.New("host.docker.internal fehlt; extra_hosts in der App-Konfiguration prüfen.")
	}
	var host net.IP
	for _, ip := range hosts {
		if ip.To4() == nil {
			continue
		}
		if host != nil && !host.Equal(ip) {
			return "", "", "", errors.New("host.docker.internal muss eindeutig auf das NAS zeigen.")
		}
		host = ip
	}
	if host == nil {
		return "", "", "", errors.New("host.docker.internal hat keine IPv4-Adresse.")
	}
	return bridgeEndpointFor(host, "/proc/net/route", net.InterfaceByName)
}

func bridgeEndpointFor(host net.IP, route string, byName func(string) (*net.Interface, error)) (bind, target, client string, err error) {
	if !host.IsPrivate() {
		return "", "", "", errors.New("host.docker.internal muss eine private Adresse sein.")
	}
	f, e := os.Open(route)
	if e != nil {
		return "", "", "", e
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		p := strings.Fields(sc.Text())
		if len(p) < 4 || p[1] != "00000000" {
			continue
		}
		g, e := strconv.ParseUint(p[2], 16, 32)
		if e != nil || g == 0 {
			continue
		}
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, uint32(g))
		gw := net.IP(b)
		iface, e := byName(p[0])
		if e != nil {
			continue
		}
		addrs, e := iface.Addrs()
		if e != nil {
			continue
		}
		for _, a := range addrs {
			ip, n, e := net.ParseCIDR(a.String())
			if e == nil && ip.To4() != nil && n.Contains(gw) && ip.IsPrivate() && gw.IsPrivate() {
				return net.JoinHostPort(ip.String(), "2288"), net.JoinHostPort(host.String(), "22"), gw.String(), nil
			}
		}
	}
	return "", "", "", errors.New("Docker-Bridge nicht erkannt; ZFS-Tunnel bleibt geschlossen.")
}
func (n *TSNetwork) PeerSource(ctx context.Context, inv Invitation, remote string) bool {
	host, _, e := net.SplitHostPort(remote)
	if e != nil || host != inv.IP {
		return false
	}
	return n.pin(ctx, inv) == nil // control-plane pin checks stable node ID AND address
}
func (n *TSNetwork) ZFSDial(ctx context.Context, inv Invitation) (net.Conn, error) {
	if e := n.pin(ctx, inv); e != nil {
		return nil, e
	}
	s, _, e := n.client()
	if e != nil {
		return nil, e
	}
	return s.Dial(ctx, "tcp", net.JoinHostPort(inv.IP, "8788"))
}
func (n *TSNetwork) ConfigureZFS(receive, send bool, auth func(context.Context, string) bool, peer func() *Invitation) error {
	n.zfsMu.Lock()
	defer n.zfsMu.Unlock()
	if n.zfs != nil {
		n.zfs.close()
		n.zfs = nil
	}
	if !receive && !send {
		return nil
	}
	s, _, e := n.client()
	if e != nil {
		return e
	}
	endpoint := n.zfsEndpoint
	if endpoint == nil {
		endpoint = bridgeEndpoint
	}
	bind, target, client, e := endpoint()
	if e != nil {
		return e
	}
	z := &zfsTunnels{conns: map[net.Conn]bool{}}
	if receive {
		l, e := s.Listen("tcp", ":8788")
		if e != nil {
			z.close()
			return e
		}
		z.serve(l, func(remote string) bool {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			return auth(ctx, remote)
		}, fixedSSHDial(target, (&net.Dialer{}).DialContext))
	}
	if send {
		l, e := net.Listen("tcp", bind)
		if e != nil {
			z.close()
			return e
		}
		z.serve(l, func(remote string) bool { ip, _, e := net.SplitHostPort(remote); return e == nil && ip == client }, func(ctx context.Context) (net.Conn, error) {
			p := peer()
			if p == nil {
				return nil, errors.New("Freund fehlt.")
			}
			return n.ZFSDial(ctx, *p)
		})
	}
	n.zfs = z
	return nil
}

// Fixed endpoint closure deliberately ignores all bytes sent by the SSH client.
func fixedSSHDial(gateway string, dial func(context.Context, string, string) (net.Conn, error)) func(context.Context) (net.Conn, error) {
	return func(ctx context.Context) (net.Conn, error) { return dial(ctx, "tcp", gateway) }
}
