package buddy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"golang.org/x/crypto/ssh"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type fakeZFSNetwork struct {
	zfsDial func() (net.Conn, error)
	fakeNetwork
	source        bool
	receive, send bool
	handler       http.Handler
	target        string
}

func (n *fakeZFSNetwork) ConfigureZFS(r, s bool, _ func(context.Context, string) bool, _ func() *Invitation) error {
	n.receive = r
	n.send = s
	return nil
}
func (n *fakeZFSNetwork) PeerSource(_ context.Context, p Invitation, remote string) bool {
	return n.source && remote == net.JoinHostPort(p.IP, "1234")
}
func (n *fakeZFSNetwork) ZFSDial(context.Context, Invitation) (net.Conn, error) {
	if n.zfsDial != nil {
		return n.zfsDial()
	}
	return nil, errors.New("not implemented")
}
func (n *fakeZFSNetwork) Dial(ctx context.Context, p Invitation) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "tcp", n.target)
}
func zfsTestApp(t *testing.T) (*App, *fakeZFSNetwork, ZFSOffer) {
	a := testApp(t, &fakeRunner{})
	n := &fakeZFSNetwork{source: true}
	a.network = n
	p := inv("bob")
	a.store.S.Peer = &p
	a.store.S.Name = "alice"
	a.store.S.ReceiverUser = "buddy-0123456789abcdef"
	a.store.S.ReceiverPassword = strings.Repeat("a", 43)
	priv, pub, e := zfsKey()
	if e != nil {
		t.Fatal(e)
	}
	o := ZFSOffer{ID: randomID(), Name: "bob", Datasets: []string{"tank/photos"}, Hour: 3, RetentionDays: 30, PublicKey: pub, Created: time.Now().UTC()}
	a.store.S.ZFS.PrivateKey = priv
	a.mounts = func() ([]Mount, error) {
		return []Mount{{Path: "/data", Source: "tank/buddy", Root: "/", FS: "zfs"}}, nil
	}
	return a, n, o
}
func zfsAdmin(t *testing.T, a *App) (*http.Cookie, string) {
	c, csrf := auth(t, a)
	a.sessionMu.Lock()
	for _, s := range a.sessions {
		s.Authed = true
	}
	a.sessionMu.Unlock()
	return c, csrf
}
func TestZFSSignallingAuthAndPrefixIsolation(t *testing.T) {
	a, n, o := zfsTestApp(t)
	a.store.S.ZFS.Receive = ZFSReceive{true, 50}
	calls := 0
	h := a.peerHandler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }))
	for _, tc := range []struct {
		name, path, remote, user, password string
		source                             bool
		want                               int
	}{
		{"valid", "/buddy-zfs/v1/offer", "100.64.0.2:1234", a.store.S.ReceiverUser, a.store.S.ReceiverPassword, true, 200},
		{"password", "/buddy-zfs/v1/offer", "100.64.0.2:1234", a.store.S.ReceiverUser, "wrong", true, 401},
		{"source", "/buddy-zfs/v1/offer", "100.64.0.99:1234", a.store.S.ReceiverUser, a.store.S.ReceiverPassword, true, 401},
		{"node", "/buddy-zfs/v1/offer", "100.64.0.2:1234", a.store.S.ReceiverUser, a.store.S.ReceiverPassword, false, 401},
		{"bare-prefix", "/buddy-zfs", "100.64.0.2:1234", a.store.S.ReceiverUser, a.store.S.ReceiverPassword, true, 404},
		{"unknown", "/buddy-zfs/unrecognized", "100.64.0.2:1234", a.store.S.ReceiverUser, a.store.S.ReceiverPassword, true, 404},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n.source = tc.source
			b, _ := json.Marshal(o)
			r := httptest.NewRequest("POST", tc.path, strings.NewReader(string(b)))
			r.RemoteAddr = tc.remote
			r.Header.Set("Content-Type", "application/json")
			r.SetBasicAuth(tc.user, tc.password)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatal(w.Code, w.Body.String())
			}
		})
	}
	if calls != 0 {
		t.Fatal("signalling leaked into rest-server")
	}
	n.source = true
	a.store.S.ZFS.Receive.Enabled = false
	if a.zfsSource(context.Background(), "100.64.0.2:1234", true) {
		t.Fatal("disabled receive admitted peer")
	}
	a.store.S.ZFS.Receive.Enabled = true
	if !a.zfsSource(context.Background(), "100.64.0.2:1234", true) {
		t.Fatal("pinned source rejected")
	}
}
func TestZFSKeyLifecycleAndAdminGate(t *testing.T) {
	a, _, o := zfsTestApp(t)
	a.store.S.ZFS.Outgoing = &o
	if w := request(a, "GET", "zfs/status", "", nil, ""); w.Code != 401 {
		t.Fatal(w.Code)
	}
	c, csrf := zfsAdmin(t, a)
	if w := request(a, "POST", "zfs/confirm", `{}`, c, ""); w.Code != 403 {
		t.Fatal(w.Code)
	}
	body := `{"side":"sender","offer_id":"` + o.ID + `"}`
	if w := request(a, "POST", "zfs/confirm", body, c, csrf); w.Code != 409 || a.store.S.ZFS.PrivateKey == "" {
		t.Fatal("missing marker erased key")
	}
	status := request(a, "GET", "zfs/status", "", c, "").Body.String()
	if strings.Contains(status, "PRIVATE KEY") || strings.Contains(status, "private_key") {
		t.Fatal("key in status")
	}
	os.MkdirAll(filepath.Join(a.store.dir, "buddy-zfs"), 0700)
	if e := atomicJSON(a.zfsFile(o.ID, "sender", "-complete.json"), map[string]string{"id": o.ID}); e != nil {
		t.Fatal(e)
	}
	if w := request(a, "POST", "zfs/confirm", body, c, csrf); w.Code != 409 {
		t.Fatal("confirm without rescue ack", w.Code)
	}
	_, host, _ := zfsKey()
	a.store.S.ZFS.HostKey = host
	a.store.S.ZFS.PeerStatus = ZFSPeerStatus{OfferID: o.ID, Ready: true, Username: "bz" + o.ID[:16], Parent: "tank/buddy-zfs-" + o.ID[:16]}
	exported := request(a, "POST", "zfs/rescue/export", `{}`, c, csrf)
	var export struct {
		Rescue      ZFSRescue `json:"rescue"`
		Fingerprint string    `json:"fingerprint"`
	}
	json.Unmarshal(exported.Body.Bytes(), &export)
	if exported.Code != 200 || export.Rescue.PrivateKey == "" {
		t.Fatal(exported.Code, exported.Body.String())
	}
	ack := `{"fingerprint":"` + export.Fingerprint + `","confirm":"SAVED_OFFLINE"}`
	if w := request(a, "POST", "zfs/rescue/ack", ack, c, csrf); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	for range 2 {
		if w := request(a, "POST", "zfs/confirm", body, c, csrf); w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	if a.store.S.ZFS.PrivateKey != "" || !a.store.S.ZFS.SenderComplete {
		t.Fatal("key not deleted")
	}
	state, e := os.ReadFile(filepath.Join(a.store.dir, "state.json"))
	if e != nil || strings.Contains(string(state), "PRIVATE KEY") {
		t.Fatal("persisted private key after completion", e)
	}
	if _, e := a.zfsCommand("sender"); e == nil {
		t.Fatal("regenerated private key after completion")
	}
}
func TestZFSOfferRetryKeepsKeyAndRejectsChangedSelection(t *testing.T) {
	a, n, _ := zfsTestApp(t)
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			var o ZFSOffer
			json.NewDecoder(r.Body).Decode(&o)
			a.store.mu.Lock()
			a.store.S.ZFS.PeerStatus.OfferID = o.ID
			a.store.mu.Unlock()
		}
		a.store.mu.Lock()
		p := a.store.S.ZFS.PeerStatus
		a.store.mu.Unlock()
		writeJSON(w, 200, p)
	}))
	defer receiver.Close()
	n.target = strings.TrimPrefix(receiver.URL, "http://")
	c, csrf := zfsAdmin(t, a)
	body := `{"datasets":["tank/photos"],"hour":3,"retention_days":30}`
	if w := request(a, "POST", "zfs/offer", body, c, csrf); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	key, id := a.store.S.ZFS.PrivateKey, a.store.S.ZFS.Outgoing.ID
	if w := request(a, "POST", "zfs/offer", body, c, csrf); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if key == "" || key != a.store.S.ZFS.PrivateKey || id != a.store.S.ZFS.Outgoing.ID {
		t.Fatal("retry changed key/identity")
	}
	if w := request(a, "POST", "zfs/offer", strings.ReplaceAll(body, "photos", "other"), c, csrf); w.Code != 409 {
		t.Fatal("selection changed without removal")
	}
}
func TestZFSCommandsHostileNamesAndSyntax(t *testing.T) {
	a, _, o := zfsTestApp(t)
	a.store.S.ZFS.Receive = ZFSReceive{true, 50}
	a.store.S.ZFS.Incoming = &o
	a.store.S.ZFS.Outgoing = &o
	_, hostkey, _ := zfsKey()
	a.store.S.ZFS.HostKey = hostkey
	a.store.S.ZFS.PeerStatus = ZFSPeerStatus{OfferID: o.ID, Ready: true, Parent: "tank/buddy-zfs-test", Username: "bz" + o.ID[:16]}
	// Even bind mount subdirectory names that contain shell operators stay data.
	a.mounts = func() ([]Mount, error) {
		return []Mount{{Path: "/data", Source: "tank/buddy", Root: "/a'$(touch PWNED); b", FS: "zfs"}}, nil
	}
	for _, side := range []string{"sender", "receiver", "remove-sender", "remove-receiver"} {
		cmd, e := a.zfsCommand(side)
		if e != nil {
			t.Fatal(e)
		}
		path := filepath.Join(t.TempDir(), side+".sh")
		os.WriteFile(path, []byte(cmd), 0600)
		if bash, e := exec.LookPath("bash"); e == nil {
			c := exec.Command(bash, "-n", path)
			if b, e := c.CombinedOutput(); e != nil {
				t.Fatal(e, string(b))
			}
		} else {
			t.Fatal("bash required for script validation")
		}
		if check, e := exec.LookPath("shellcheck"); e == nil {
			c := exec.Command(check, "-s", "bash", path)
			if b, e := c.CombinedOutput(); e != nil {
				t.Fatal(e, string(b))
			}
		} else {
			t.Fatal("shellcheck required for generated script validation")
		}
	}
	for _, name := range []string{"tank/a';touch PWNED;#", "tank/$(id)", "tank/a\nb", "tank/../x", "tank//x", "tank/-x", "/tank/x"} {
		o.Datasets = []string{name}
		if e := validateOffer(o); e == nil {
			t.Fatal("hostile dataset accepted", name)
		}
	}
}
func TestZFSSenderRefusesUnencryptedBeforeAnyMutation(t *testing.T) {
	if _, e := exec.LookPath("python3"); e != nil {
		t.Fatal("python3 required for script tests")
	}
	a, _, o := zfsTestApp(t)
	o.Datasets = []string{"tank/encrypted", "tank/plain"}
	a.store.S.ZFS.Outgoing = &o
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	os.Mkdir(bin, 0700)
	// Only read-only get calls are accepted by this executable. Any attempted
	// mutation fails the test. The second source is deliberately unencrypted.
	fake := `#!/bin/sh
if [ "$1" != get ]; then echo MUTATION >&2; exit 90; fi
case "$*" in
 *' encryption tank/plain') echo off ;;
 *' encryption '*) echo aes-256-gcm ;;
 *' type '*) echo filesystem ;;
 *' origin '*) echo - ;;
 *' encryptionroot '*) echo tank ;;
 *' keystatus '*) echo available ;;
 *) exit 91 ;;
esac
`
	os.WriteFile(filepath.Join(bin, "zfs"), []byte(fake), 0700)
	cfg := map[string]any{"side": "sender", "offer": o, "directory": filepath.Join(root, "must-not-exist"), "pool": "tank"}
	code := "import json,base64\nCONFIG=json.loads(" + string(mustJSON(string(mustJSON(cfg)))) + ")\nBODY=base64.b64decode('" + base64.StdEncoding.EncodeToString([]byte(strings.ReplaceAll(zfsHostProgram, "/usr/sbin/zfs", filepath.Join(bin, "zfs")))) + "').decode()\nEXEC_WRAPPER=" + string(mustJSON(zfsExecWrapper)) + "\nexec(EXEC_WRAPPER)\n"
	c := exec.Command("python3", "-")
	c.Stdin = strings.NewReader(code)
	c.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"))
	b, e := c.CombinedOutput()
	if e == nil || !strings.Contains(string(b), "Unverschlüsseltes Dataset abgelehnt") || strings.Contains(string(b), "MUTATION") {
		t.Fatal(e, string(b))
	}
	if _, e := os.Stat(cfg["directory"].(string)); !os.IsNotExist(e) {
		t.Fatal("created state before encryption validation")
	}
}
func TestZFSFixedForwardingAndCancellation(t *testing.T) {
	var calls atomic.Int32
	client, accepted := net.Pipe()
	defer client.Close()
	z := &zfsTunnels{conns: map[net.Conn]bool{}}
	denied := make(chan struct{})
	go func() {
		z.forward(accepted, func(string) bool { return false }, func(context.Context) (net.Conn, error) { calls.Add(1); return nil, errors.New("must not dial") })
		close(denied)
	}()
	<-denied
	if calls.Load() != 0 {
		t.Fatal("denied source forwarded")
	}
	c, s := net.Pipe()
	defer c.Close()
	remote, host := net.Pipe()
	defer host.Close()
	dial := fixedSSHDial("172.19.0.1:22", func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "172.19.0.1:22" {
			t.Error("wrong target", network, address)
		}
		calls.Add(1)
		return remote, nil
	})
	done := make(chan struct{})
	go func() { z.forward(s, func(string) bool { return true }, dial); close(done) }()
	payload := "CONNECT 192.168.1.1:443 HTTP/1.1\r\n\r\n"
	go io.WriteString(c, payload)
	b := make([]byte, len(payload))
	host.SetReadDeadline(time.Now().Add(time.Second))
	if _, e := io.ReadFull(host, b); e != nil || string(b) != payload {
		t.Fatal(e, string(b))
	}
	z.close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("disable did not close active tunnel")
	}
	if calls.Load() != 1 {
		t.Fatal(calls.Load())
	}
}
func TestZFSWarningsIncludeMissingStaleAndUnlocked(t *testing.T) {
	a, _, o := zfsTestApp(t)
	a.store.S.ZFS.Outgoing = &o
	a.store.S.ZFS.PeerStatus = ZFSPeerStatus{OfferID: o.ID, Ready: true, Parent: "tank/recv", Report: ZFSReport{Updated: time.Now(), Datasets: []ZFSDataset{{Name: "tank/recv/d0", Snapshot: "s", SnapshotTime: time.Now().Add(-72 * time.Hour), KeyStatus: "available"}}}}
	w := strings.Join(a.zfsWarnings(a.store.S.ZFS, ZFSPeerStatus{}), " ")
	if !strings.Contains(w, "Sicherheitswarnung") || !strings.Contains(w, "veraltet") {
		t.Fatal(w)
	}
	a.store.S.ZFS.PeerStatus.Report.Datasets = nil
	w = strings.Join(a.zfsWarnings(a.store.S.ZFS, ZFSPeerStatus{}), " ")
	if !strings.Contains(w, "Snapshot fehlt") {
		t.Fatal(w)
	}
}

func TestZFSHostProgram(t *testing.T) {
	c := exec.Command("python3", "-B", "zfs_host_test.py")
	if b, e := c.CombinedOutput(); e != nil {
		t.Fatal(e, string(b))
	} else {
		t.Log(string(b))
	}
}

func TestZFSHostKeyDiscoveryUsesSSHHandshake(t *testing.T) {
	a, n, _ := zfsTestApp(t)
	private, public, e := zfsKey()
	if e != nil {
		t.Fatal(e)
	}
	signer, e := ssh.ParsePrivateKey([]byte(private))
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan struct{})
	n.zfsDial = func() (net.Conn, error) {
		// TCP avoids net.Pipe's simultaneous SSH version-write deadlock.
		ln, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			return nil, e
		}
		go func() {
			defer close(done)
			defer ln.Close()
			conn, e := ln.Accept()
			if e != nil {
				return
			}
			defer conn.Close()
			cfg := &ssh.ServerConfig{NoClientAuth: true}
			cfg.AddHostKey(signer)
			_, _, _, _ = ssh.NewServerConn(conn, cfg)
		}()
		return net.Dial("tcp", ln.Addr().String())
	}
	got, e := a.captureHostKey(context.Background(), *a.store.S.Peer)
	if e != nil || got != public {
		t.Fatal(e, got)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("host key discovery did not abort authentication")
	}
}

func TestZFSRejectsPublicKeyLineAndOptionInjection(t *testing.T) {
	_, _, o := zfsTestApp(t)
	for _, v := range []string{o.PublicKey + "\n", o.PublicKey + "\r", o.PublicKey + " ", " " + o.PublicKey, o.PublicKey + "\ncommand=\"id\" " + o.PublicKey, "restrict " + o.PublicKey} {
		bad := o
		bad.PublicKey = v
		if validateOffer(bad) == nil {
			t.Fatalf("accepted %q", v)
		}
	}
}
func TestZFSResetRequiresMarkerGoneIncludingWrongQuota(t *testing.T) {
	a, _, o := zfsTestApp(t)
	a.store.S.ZFS.Incoming = &o
	a.store.S.ZFS.Receive = ZFSReceive{true, 50}
	c, csrf := zfsAdmin(t, a)
	os.MkdirAll(filepath.Join(a.store.dir, "buddy-zfs"), 0700)
	marker := a.zfsFile(o.ID, "receiver", "-complete.json")
	atomicJSON(marker, map[string]any{"id": o.ID, "quota_gib": 1})
	body := `{"side":"receiver","offer_id":"` + o.ID + `","confirm":"REMOVED_ON_NAS"}`
	if w := request(a, "POST", "zfs/reset", body, c, csrf); w.Code != 409 || a.store.S.ZFS.Incoming == nil {
		t.Fatal("reset bypassed marker", w.Code, w.Body.String())
	}
	os.Remove(marker)
	if w := request(a, "POST", "zfs/reset", body, c, csrf); w.Code != 200 || a.store.S.ZFS.Incoming != nil {
		t.Fatal(w.Code, w.Body.String())
	}
}
func TestZFSRescueImportNoOfferAndRepinPreservesAccount(t *testing.T) {
	sender, _, o := zfsTestApp(t)
	sender.store.S.ZFS.Outgoing = &o
	_, host, _ := zfsKey()
	sender.store.S.ZFS.HostKey = host
	sender.store.S.ZFS.PeerStatus = ZFSPeerStatus{OfferID: o.ID, Ready: true, Username: "bz" + o.ID[:16], Parent: "tank/buddy-zfs-" + o.ID[:16]}
	k, e := sender.zfsRescue()
	if e != nil {
		t.Fatal(e)
	}
	replacement, n, _ := zfsTestApp(t)
	replacement.store.S.Peer = nil
	replacement.store.S.ZFS = ZFSState{}
	c, csrf := zfsAdmin(t, replacement)
	body := string(mustJSON(map[string]any{"rescue": k, "fingerprint": fingerprint(k), "confirm": "IMPORT_ZFS_RESCUE"}))
	if w := request(replacement, "POST", "zfs/rescue/import", body, c, csrf); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if !n.send || n.receive || replacement.store.S.ZFS.Outgoing != nil || replacement.store.S.AllowInit {
		t.Fatal("rescue did not open ONLY outbound tunnel without offer")
	}
	status := request(replacement, "GET", "zfs/status", "", c, "").Body.String()
	if strings.Contains(status, "PRIVATE KEY") || strings.Contains(status, "private_key") {
		t.Fatal("rescue key leaked")
	}
	if w := request(replacement, "POST", "zfs/rescue/import", body, c, csrf); w.Code != 409 {
		t.Fatal("second import accepted", w.Code)
	}
	if w := request(replacement, "POST", "zfs/rescue/close", `{"confirm":"CLOSE_ZFS_RESCUE"}`, c, csrf); w.Code != 200 || n.send || replacement.store.S.ZFS.Rescue != nil {
		t.Fatal("rescue close", w.Code)
	}
	receiver, _, _ := zfsTestApp(t)
	receiver.store.S.ZFS.Incoming = &o
	receiver.store.S.ZFS.Receive = ZFSReceive{true, 50}
	c, csrf = zfsAdmin(t, receiver)
	old := *receiver.store.S.Peer
	fresh := old
	fresh.NodeID = "replacement-node"
	fresh.IP = "100.64.0.99"
	fresh.Username = "buddy-aaaaaaaaaaaaaaaa"
	fresh.Password = strings.Repeat("b", 43)
	repin := map[string]any{"invitation": fresh, "fingerprint": fingerprint(fresh), "previous_node_id": old.NodeID, "confirm": "REPIN_REPLACED_ZFS_PEER"}
	if w := request(receiver, "POST", "zfs/peer/repin", string(mustJSON(repin)), c, csrf); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if receiver.store.S.Peer.NodeID != fresh.NodeID || receiver.store.S.Peer.Username != old.Username || receiver.store.S.ZFS.Incoming.ID != o.ID || !receiver.store.S.ZFS.Receive.Enabled {
		t.Fatal("repin lost existing access/data identity")
	}
	// The full offer API no longer accepts a recursive flag.
	if w := request(receiver, "POST", "zfs/offer", `{"datasets":["tank/a"],"hour":3,"retention_days":30,"recursive":true}`, c, csrf); w.Code != 400 {
		t.Fatal("recursive accepted", w.Code)
	}
}
func TestZFSControlDirectoryNeverInsideBindMount(t *testing.T) {
	a, _, o := zfsTestApp(t)
	a.store.S.ZFS.Incoming = &o
	a.store.S.ZFS.Receive = ZFSReceive{true, 50}
	a.mounts = func() ([]Mount, error) {
		return []Mount{{Path: "/data", Source: "tank/buddy", Root: "/", FS: "zfs"}, {Path: "/sources/pool", Source: "tank", Root: "/", FS: "zfs"}}, nil
	}
	if _, e := a.zfsCommand("receiver"); e == nil {
		t.Fatal("gate exposed by pool bind mount")
	}
}
func TestZFSBridgeRequiresExplicitResolvedHostGateway(t *testing.T) {
	dir := t.TempDir()
	route := filepath.Join(dir, "route")
	os.WriteFile(route, []byte("Iface Destination Gateway Flags\neth0 00000000 010013AC 0003\n"), 0600)
	var calls int
	_, _, _, e := bridgeEndpointFor(net.ParseIP("8.8.8.8"), route, func(string) (*net.Interface, error) { calls++; return nil, errors.New("unexpected") })
	if e == nil || calls != 0 {
		t.Fatal("accepted a public host target", calls, e)
	}
	_, _, _, e = bridgeEndpointFor(net.ParseIP("172.16.0.1"), route, func(string) (*net.Interface, error) { calls++; return nil, errors.New("no matching local interface") })
	if e == nil || calls != 1 {
		t.Fatal("route interface not validated", calls, e)
	}
}

func TestZFSSenderStatusWarningsAndNtfy(t *testing.T) {
	a, n, o := zfsTestApp(t)
	a.store.S.ZFS.Outgoing = &o
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, ZFSPeerStatus{OfferID: o.ID, Ready: true, Parent: "tank/buddy-zfs-" + o.ID[:16], Username: "bz" + o.ID[:16]})
	}))
	defer peer.Close()
	n.target = strings.TrimPrefix(peer.URL, "http://")
	notices := make(chan string, 2)
	notify := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		notices <- string(b)
		w.WriteHeader(200)
	}))
	defer notify.Close()
	a.store.S.Settings.NtfyURL = notify.URL
	now := time.Now().UTC()
	report := ZFSSenderReport{Updated: now, Scheduler: "cron", Datasets: []ZFSSenderDataset{{
		Name: o.Datasets[0], State: "error", LastAttempt: &now, Error: "receive verification failed", SecurityWarning: "hostile token refused",
	}}}
	os.MkdirAll(filepath.Join(a.store.dir, "buddy-zfs"), 0700)
	if err := atomicJSON(a.zfsFile(o.ID, "sender", "-status.json"), report); err != nil {
		t.Fatal(err)
	}
	c, _ := zfsAdmin(t, a)
	response := request(a, "GET", "zfs/status", "", c, "")
	var status struct {
		Sender   ZFSSenderReport `json:"sender_status"`
		Warnings []string        `json:"warnings"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status.Sender.Scheduler != "cron" || len(status.Sender.Datasets) != 1 || status.Sender.Datasets[0].LastSuccess != nil {
		t.Fatal(response.Body.String())
	}
	warnings := strings.Join(status.Warnings, " ")
	if !strings.Contains(warnings, "receive verification failed") || !strings.Contains(warnings, "hostile token refused") {
		t.Fatal(warnings)
	}
	a.zfsTick()
	select {
	case message := <-notices:
		if !strings.Contains(message, "ZFS-Warnung") {
			t.Fatal(message)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("sender failure did not reach ntfy")
	}
}

func TestZFSControlDatasetCannotExposeAnyOtherFolder(t *testing.T) {
	a, _, o := zfsTestApp(t)
	a.store.S.ZFS.Incoming = &o
	a.store.S.ZFS.Receive = ZFSReceive{true, 50}
	a.mounts = func() ([]Mount, error) {
		return []Mount{{Path: "/data", Source: "tank/buddy", Root: "/", FS: "zfs"},
			{Path: "/sources/unrelated", Source: "tank/buddy-zfs-control", Root: "/unrelated", FS: "zfs"}}, nil
	}
	if _, err := a.zfsCommand("receiver"); err == nil {
		t.Fatal("same filesystem exposed by unrelated folder bind")
	}
}

func TestDatasetRootExposureWarningsIncludeFileBackupsAndData(t *testing.T) {
	a, _, _ := zfsTestApp(t)
	a.mounts = func() ([]Mount, error) {
		return []Mount{
			{Path: "/data", FS: "zfs", Source: "tank/shared", Root: "/app"},
			{Path: "/sources/photos", FS: "zfs", Source: "tank/shared", Root: "/photos"},
			{Path: "/sources/safe", FS: "zfs", Source: "tank/safe", Root: "/"},
		}, nil
	}
	c, _ := zfsAdmin(t, a)
	for _, path := range []string{"sources", "status"} {
		w := request(a, "GET", path, "", c, "")
		var result struct {
			Warnings []string `json:"warnings"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		joined := strings.Join(result.Warnings, "\n")
		if !strings.Contains(joined, "/data:") || !strings.Contains(joined, "/sources/photos:") || strings.Contains(joined, "/sources/safe:") || !strings.Contains(joined, "Dateisicherungen") {
			t.Fatal(path, w.Code, joined)
		}
	}
}

func TestZFSPasteReviewHashConfigAndAPITrustWarning(t *testing.T) {
	a, _, o := zfsTestApp(t)
	a.store.S.ZFS.Incoming, a.store.S.ZFS.Outgoing = &o, &o
	a.store.S.ZFS.Receive = ZFSReceive{true, 50}
	_, host, _ := zfsKey()
	a.store.S.ZFS.HostKey = host
	a.store.S.ZFS.PeerStatus = ZFSPeerStatus{Ready: true, OfferID: o.ID, Parent: "other/received", Username: "bz" + o.ID[:16]}
	c, _ := zfsAdmin(t, a)
	w := request(a, "GET", "zfs/commands/receiver", "", c, "")
	var result struct {
		Command string `json:"command"`
		Hash    string `json:"zfs_host_sha256"`
		Warning string `json:"root_trust_warning"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || result.Hash != zfsHostSHA256() || len(result.Hash) != 64 || !strings.Contains(result.Warning, "kompromittierter") {
		t.Fatal(w.Code, w.Body.String())
	}
	for _, side := range []string{"sender", "receiver", "remove-sender", "remove-receiver"} {
		command, err := a.zfsCommand(side)
		if err != nil {
			t.Fatal(err)
		}
		parts := strings.SplitN(command, "<<'BUDDY_ZFS_PY'\n", 2)
		if len(parts) != 2 {
			t.Fatal("missing python heredoc")
		}
		program := strings.SplitN(parts[1], "\nBUDDY_ZFS_PY\n", 2)[0]
		// Compile the full generated Python, including the real execution wrapper,
		// but execute only its review prefix in this disposable test process.
		boundary := "\nEXEC_WRAPPER ="
		if strings.HasPrefix(side, "remove-") {
			boundary = "\nimport subprocess, sys"
		}
		review := strings.SplitN(program, boundary, 2)[0]
		testCode := "import base64\nfrom unittest.mock import patch, mock_open\ncompile(base64.b64decode('" + base64.StdEncoding.EncodeToString([]byte(program)) + "'), '<paste>', 'exec')\nwith patch('builtins.open', mock_open(read_data='RUN\\n')):\n exec(base64.b64decode('" + base64.StdEncoding.EncodeToString([]byte(review)) + "'))\n"
		cmd := exec.Command("python3", "-I", "-")
		cmd.Stdin = strings.NewReader(testCode)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatal(side, err, string(output))
		}
		text := string(output)
		for _, expected := range []string{zfsHostSHA256(), "username", "datasets", "parent", "quota_gib", "offer_key_fingerprint", "SHA256:", "Root-Vertrauensgrenze"} {
			if !strings.Contains(text, expected) {
				t.Fatal(side, "missing review field", expected, text)
			}
		}
		if strings.Contains(text, "PRIVATE KEY") || strings.Contains(text, "private_key") {
			t.Fatal("private key in review")
		}
	}
}

func TestZFSPasteReviewUsesRealTerminalAndCanAbort(t *testing.T) {
	// A real controlling PTY catches nonseekable /dev/tty I/O bugs that mock_open
	// cannot. Only the review is executed; HOST_ACTION is a test sentinel.
	review := "import base64,json\nCONFIG=" + string(mustJSON(map[string]any{"side": "receiver", "pool": "tank", "offer": map[string]any{"id": strings.Repeat("a", 32), "datasets": []string{"tank/a"}, "public_key": "ssh-ed25519 YQ=="}})) + "\nBODY='release-helper'\n" + zfsPasteReview + "\nprint('HOST_ACTION', flush=True)\n"
	harness := `import base64,os,pty,select,signal,sys,time
program = base64.b64decode(sys.argv[1]).decode()
for answer in (b'RUN\n', b'ABORT\n'):
    pid, fd = pty.fork()
    if pid == 0:
        os.execv(sys.executable, [sys.executable, '-I', '-c', program])
    data, answered = b'', False
    deadline = time.monotonic() + 5
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
                raise AssertionError('terminal review hung: ' + repr(data))
            try:
                block = os.read(fd, 65536)
            except OSError:
                break
            if not block:
                break
            data += block
            if b'RUN eingeben:' in data and not answered:
                assert b'ZFS host SHA-256:' in data and b'quota_gib' in data
                assert b'HOST_ACTION' not in data
                os.write(fd, answer)
                answered = True
        _, status = os.waitpid(pid, 0)
        pid = None
        assert answered, data
        if answer == b'RUN\n':
            assert status == 0 and b'HOST_ACTION' in data, data
        else:
            assert status != 0 and b'HOST_ACTION' not in data, data
    finally:
        os.close(fd)
        if pid is not None:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
`
	cmd := exec.Command("python3", "-I", "-c", harness, base64.StdEncoding.EncodeToString([]byte(review)))
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatal(err, string(b))
	}
}
