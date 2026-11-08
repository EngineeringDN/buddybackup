package buddy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"tailscale.com/feature/buildfeatures"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

type fakeNetwork struct {
	handler   http.Handler
	verifyErr error
	dials     int
}

func (f *fakeNetwork) Start(_ string, h http.Handler) error { f.handler = h; return nil }
func (f *fakeNetwork) Login(context.Context) error          { return nil }
func (f *fakeNetwork) Status(context.Context) (NetworkStatus, error) {
	return NetworkStatus{Ready: true, IP: "100.64.0.1", NodeID: "self", Warnings: []string{}}, nil
}
func (f *fakeNetwork) Verify(context.Context, Invitation, bool) (string, error) {
	return "direct", f.verifyErr
}
func (f *fakeNetwork) Dial(context.Context, Invitation) (net.Conn, error) {
	return nil, errors.New("not implemented")
}
func (f *fakeNetwork) Close() error { return nil }

type fakeRunner struct {
	mu    sync.Mutex
	calls [][]string
	fn    func([]string) (RunResult, error)
}

func (f *fakeRunner) Run(_ context.Context, args, env []string, _ func(map[string]any)) (RunResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, append([]string{}, args...))
	if f.fn != nil {
		return f.fn(args)
	}
	return RunResult{}, nil
}
func inv(name string) Invitation {
	return Invitation{1, name, "100.64.0.2", "node-" + name, 8787, "buddy-0123456789abcdef", strings.Repeat("a", 43)}
}
func testStore(t *testing.T) *Store {
	t.Helper()
	s, e := NewStore(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	s.S.Name = "alice"
	t.Cleanup(s.Close)
	return s
}
func testApp(t *testing.T, r Runner) *App {
	t.Helper()
	a, e := New(Options{DataDir: t.TempDir(), Network: &fakeNetwork{}, Runner: r, AllowedHost: "example.com", Mounts: func() ([]Mount, error) { return nil, nil }})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		ctx, c := context.WithTimeout(context.Background(), 3*time.Second)
		defer c()
		if e := a.Close(ctx); e != nil {
			t.Error(e)
		}
	})
	return a
}
func testWorker(t *testing.T, f *fakeRunner) *worker {
	a := testApp(t, f)
	a.store.S.Name = "alice"
	i := inv("bob")
	if e := a.store.pair(i, fingerprint(i), false); e != nil {
		t.Fatal(e)
	}
	return &worker{app: a, cfg: copyState(a.store.S), op: &Operation{Progress: map[string]any{}}}
}
func hasArgs(args []string, values ...string) bool {
	for i := 0; i+len(values) <= len(args); i++ {
		if reflect.DeepEqual(args[i:i+len(values)], values) {
			return true
		}
	}
	return false
}

const snapID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const newSnapID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

// Defect 1: pending at creation, no promotion on exit 3/crash/cancel.
func TestEverySnapshotStartsPending(t *testing.T) {
	for _, code := range []int{0, 3, 1} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			f := &fakeRunner{fn: func(args []string) (RunResult, error) {
				if hasArgs(args, "backup") {
					if !hasArgs(args, "--tag", pendingTag) {
						t.Fatal("snapshot created without pending")
					}
					return RunResult{Output: []byte(`{"message_type":"summary","snapshot_id":"` + snapID + `"}`), Code: code}, nil
				}
				return RunResult{Output: []byte(`{"message_type":"changed","old_snapshot_id":"` + snapID + `","new_snapshot_id":"` + newSnapID + `"}`)}, nil
			}}
			w := testWorker(t, f)
			id, e := w.pendingBackup(context.Background(), []string{"/tmp/probe"}, "buddybackup-selftest")
			if code == 0 {
				if e != nil || id != newSnapID {
					t.Fatalf("%s %v", id, e)
				}
				if len(f.calls) != 2 || !hasArgs(f.calls[1], "--remove", pendingTag, "--add", completeTag) {
					t.Fatal("success not promoted")
				}
			} else {
				if e == nil || len(f.calls) != 1 {
					t.Fatal("failed snapshot promoted")
				}
			}
		})
	}
}
func TestCrashCannotPromoteSnapshot(t *testing.T) {
	f := &fakeRunner{fn: func(a []string) (RunResult, error) {
		if !hasArgs(a, "--tag", pendingTag) {
			t.Fatal("not pending")
		}
		return RunResult{}, errors.New("crash")
	}}
	w := testWorker(t, f)
	if _, e := w.pendingBackup(context.Background(), []string{"/tmp/probe"}); e == nil {
		t.Fatal("expected failure")
	}
	if len(f.calls) != 1 {
		t.Fatal("promoted crashed backup")
	}
}

// Defect 2: exported connection must still be current when acknowledged.
func TestRecoveryAcknowledgementBoundToExportedConnection(t *testing.T) {
	s := testStore(t)
	a, b := inv("bob"), inv("carol")
	if e := s.pair(a, fingerprint(a), false); e != nil {
		t.Fatal(e)
	}
	x, e := s.exportRecovery()
	if e != nil {
		t.Fatal(e)
	}
	if e = s.pair(b, fingerprint(b), true); e != nil {
		t.Fatal(e)
	}
	if e = s.ackRecovery(x.Fingerprint, x.ConnectionFingerprint, "SAVED_OFFLINE"); e == nil || s.S.RecoveryAck {
		t.Fatal("old export acknowledged new connection")
	}
	x, e = s.exportRecovery()
	if e != nil {
		t.Fatal(e)
	}
	if e = s.ackRecovery(x.Fingerprint, x.ConnectionFingerprint, "SAVED_OFFLINE"); e != nil || !s.S.RecoveryAck {
		t.Fatal(e)
	}
	if x.Kit.RepositoryKey == "" {
		t.Fatal("kit misses key")
	}
}
func TestConcurrentExportAndReplaceStayAtomic(t *testing.T) {
	s := testStore(t)
	i := inv("bob")
	_ = s.pair(i, fingerprint(i), false)
	var wg sync.WaitGroup
	for j := 0; j < 15; j++ {
		wg.Add(2)
		go func(j int) {
			defer wg.Done()
			s.mu.Lock()
			defer s.mu.Unlock()
			i := inv(fmt.Sprintf("peer%d", j))
			if e := s.pair(i, fingerprint(i), true); e != nil {
				t.Error(e)
			}
		}(j)
		go func() {
			defer wg.Done()
			s.mu.Lock()
			defer s.mu.Unlock()
			x, e := s.exportRecovery()
			if e != nil {
				t.Error(e)
				return
			}
			if x.ConnectionFingerprint != s.connection() || x.Fingerprint != fingerprint(x.Kit) || x.Kit.Peer != *s.S.Peer {
				t.Error("mixed connection export")
			}
		}()
	}
	wg.Wait()
}

// Defect 3: cancellation must allow restic cleanup; unlock cannot race an op.
func TestRunnerGracefulInterrupt(t *testing.T) {
	root := t.TempDir()
	script := filepath.Join(root, "restic")
	ready := filepath.Join(root, "ready")
	clean := filepath.Join(root, "clean")
	body := "#!/bin/sh\ntrap 'echo clean > \"$CLEAN\"; exit 0' INT\necho ready > \"$READY\"\nwhile :; do sleep 0.02; done\n"
	if e := os.WriteFile(script, []byte(body), 0700); e != nil {
		t.Fatal(e)
	}
	ctx, c := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, e := (ExecRunner{Binary: script, Grace: time.Second}).Run(ctx, nil, []string{"PATH=/usr/bin:/bin", "READY=" + ready, "CLEAN=" + clean}, nil)
		done <- e
	}()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, e := os.Stat(ready); e == nil {
			break
		}
		if time.Now().After(deadline) {
			c()
			t.Fatal("not started")
		}
		time.Sleep(10 * time.Millisecond)
	}
	c()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("cancellation omitted")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown exceeded grace")
	}
	if _, e := os.Stat(clean); e != nil {
		t.Fatal("SIGINT cleanup did not run", e)
	}
}
func TestUnlockRefusesWhileOperationRuns(t *testing.T) {
	a := testApp(t, &fakeRunner{})
	a.store.S.Peer = new(Invitation)
	a.op = &Operation{State: "running"}
	if _, e := a.startOperation(OperationRequest{Kind: "unlock", Confirm: "UNLOCK_STALE_LOCKS"}, false); !errors.Is(e, ErrBusy) {
		t.Fatal("unlock not guarded", e)
	}
	a.op = nil
	if _, e := a.startOperation(OperationRequest{Kind: "unlock"}, false); e == nil {
		t.Fatal("unguarded unlock")
	}
}

// Defect 4: independently callable low-space maintenance, even without last success.
func TestIndependentLowSpaceMaintenance(t *testing.T) {
	f := &fakeRunner{fn: func(a []string) (RunResult, error) {
		if hasArgs(a, "cat", "config") {
			return RunResult{Output: []byte(`{"id":"` + snapID + `"}`)}, nil
		}
		if hasArgs(a, "backup") {
			t.Fatal("maintenance invoked backup")
		}
		return RunResult{}, nil
	}}
	w := testWorker(t, f)
	w.cfg.ActiveSet = "source-set"
	if _, e := w.maintenance(context.Background(), true); e != nil {
		t.Fatal(e)
	}
	pruned := false
	for _, a := range f.calls {
		if hasArgs(a, "prune", "--max-repack-size", "0") {
			pruned = true
		}
		if hasArgs(a, "forget") && !hasArgs(a, "--tag", w.tag()+","+w.setTag()+","+completeTag) && !hasArgs(a, "--tag", w.tag()+","+w.setTag()+","+pendingTag) {
			t.Fatal("retention includes pending or inactive source sets")
		}
	}
	if !pruned {
		t.Fatal("no zero-repack prune")
	}
}

// Defect 5: only confirmed inactive source sets may be removed.
func TestRetiredSourceSetRequiresConfirmation(t *testing.T) {
	f := &fakeRunner{fn: func(a []string) (RunResult, error) {
		if hasArgs(a, "cat", "config") {
			return RunResult{Output: []byte(`{"id":"` + snapID + `"}`)}, nil
		}
		if hasArgs(a, "snapshots") {
			return RunResult{Output: []byte(`[{"id":"` + snapID + `","tags":["buddybackup-source:old","buddybackup:backup"]},{"id":"` + newSnapID + `","tags":["buddybackup-source:current","buddybackup:backup"]}]`)}, nil
		}
		return RunResult{}, nil
	}}
	w := testWorker(t, f)
	w.cfg.BackupID = "backup"
	w.cfg.ActiveSet = "current"
	w.cfg.Sets = []SourceSet{{ID: "old", Retired: true}, {ID: "current"}}
	w.app.store.S.Sets = w.cfg.Sets
	if _, e := w.retire(context.Background(), OperationRequest{SetID: "old"}); e == nil {
		t.Fatal("unconfirmed deletion")
	}
	if _, e := w.retire(context.Background(), OperationRequest{SetID: "current", Confirm: "DELETE_RETIRED_SNAPSHOTS"}); e == nil {
		t.Fatal("deleted active")
	}
	if _, e := w.retire(context.Background(), OperationRequest{SetID: "old", Confirm: "DELETE_RETIRED_SNAPSHOTS"}); e != nil {
		t.Fatal(e)
	}
	if !w.app.store.S.Sets[0].Deleted {
		t.Fatal("not persisted")
	}
	for _, a := range f.calls {
		if hasArgs(a, "forget", newSnapID) {
			t.Fatal("active snapshot deleted")
		}
	}
}

// Defect 6: previous planned slot, not operation completion time.
func TestScheduleNoDriftCoalescesMissedSlots(t *testing.T) {
	start := time.Date(2026, 1, 1, 3, 0, 0, 0, time.UTC)
	for _, test := range []struct{ elapsed, want time.Duration }{{10 * time.Minute, time.Hour}, {time.Hour, time.Hour * 2}, {5*time.Hour + 12*time.Minute, 6 * time.Hour}} {
		got := nextSlot(start, start.Add(test.elapsed), time.Hour)
		if got != start.Add(test.want) {
			t.Fatalf("got %s want %s", got, start.Add(test.want))
		}
	}
}

// Defect 7: Online=false is not a denial, but ID/IP/expired pinning stays strict.
func TestSharedPeerOfflineControlPlaneStillAccepted(t *testing.T) {
	i := inv("bob")
	p := &ipnstate.PeerStatus{ID: tailcfg.StableNodeID(i.NodeID), Online: false, TailscaleIPs: []netip.Addr{netip.MustParseAddr(i.IP)}}
	st := &ipnstate.Status{BackendState: "Running", Peer: map[key.NodePublic]*ipnstate.PeerStatus{{}: p}}
	if e := pinnedPeer(st, i); e != nil {
		t.Fatal(e)
	}
	bad := i
	bad.NodeID = "substitute"
	if pinnedPeer(st, bad) == nil {
		t.Fatal("ID substitution allowed")
	}
	bad = i
	bad.IP = "100.64.0.3"
	if pinnedPeer(st, bad) == nil {
		t.Fatal("IP substitution allowed")
	}
	p.Expired = true
	if pinnedPeer(st, i) == nil {
		t.Fatal("expired peer accepted")
	}
}

type portRecorder struct {
	ports []string
	ln    net.Listener
}

func (p *portRecorder) Listen(network, addr string) (net.Listener, error) {
	p.ports = append(p.ports, network+addr)
	return p.ln, nil
}
func TestTSNetAcceptsBackupPortOnly(t *testing.T) {
	p := &portRecorder{}
	if _, e := backupListener(p); e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(p.ports, []string{"tcp:8787"}) {
		t.Fatal("unexpected tailnet listeners", p.ports)
	}
	source, e := os.ReadFile("network.go")
	if e != nil {
		t.Fatal(e)
	}
	for _, forbidden := range []string{".Loopback(", ".ListenFunnel(", ".ListenService(", ".RegisterFallbackTCPHandler(", ".ListenSSH(", ".ListenPacket("} {
		if strings.Contains(string(source), forbidden) {
			t.Fatal("unsafe tsnet API", forbidden)
		}
	}
	if strings.Count(string(source), "s.Listen(") != 1 {
		t.Fatal("additional raw tailnet listeners")
	}
}
func TestRecoveryNeverInitializesMissingRepository(t *testing.T) {
	f := &fakeRunner{fn: func(a []string) (RunResult, error) {
		if hasArgs(a, "init") {
			t.Fatal("recovery initialized repository")
		}
		return RunResult{Code: 10}, nil
	}}
	w := testWorker(t, f)
	w.cfg.AllowInit = false
	for _, allow := range []bool{true, false} {
		if e := w.ensureRepository(context.Background(), allow); !errors.Is(e, errNoRepository) {
			t.Fatal(e)
		}
	}
	s := testStore(t)
	k := w.app.store.kit()
	if e := s.importRecovery(k, fingerprint(k), "IMPORT_RECOVERY"); e != nil {
		t.Fatal(e)
	}
	if s.S.AllowInit {
		t.Fatal("import enables init")
	}
}
func TestRepositoryIDPinning(t *testing.T) {
	f := &fakeRunner{fn: func(a []string) (RunResult, error) {
		return RunResult{Output: []byte(`{"id":"` + newSnapID + `"}`)}, nil
	}}
	w := testWorker(t, f)
	w.cfg.RepositoryID = snapID
	if w.ensureRepository(context.Background(), true) == nil {
		t.Fatal("replaced repository accepted")
	}
}
func TestInvitationNeverContainsEncryptionKey(t *testing.T) {
	s := testStore(t)
	i := inv("bob")
	_ = s.pair(i, fingerprint(i), false)
	b, _ := json.Marshal(i)
	if strings.Contains(string(b), s.S.Key) || strings.Contains(string(b), "repository_key") {
		t.Fatal("key leaked")
	}
	if fingerprint(i) != "923163c70d7d0a2930e3c1823efc332e2a649e225f068a19ae7cb11852b3abad" {
		t.Fatal("canonical fingerprint differs from Python reference:", fingerprint(i))
	}
}
func TestMountValidationAndEmptySource(t *testing.T) {
	if validSourcePath("/sources/../data") || validSourcePath("/sources/photos/subdir") || validSourcePath("/data") {
		t.Fatal("invalid source accepted")
	}
	root := t.TempDir()
	if nonempty(root) == nil {
		t.Fatal("empty source accepted")
	}
	if e := os.WriteFile(filepath.Join(root, "file"), []byte("x"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := nonempty(root); e != nil {
		t.Fatal(e)
	}
	if e := verifyManifest([]string{"/sources/photos"}, []Mount{{Path: "/sources/photos", Source: "pool/photos", ReadOnly: true}}, nil); e == nil {
		t.Fatal("unmounted source accepted")
	}
}
func TestRestoreNeverOverwritesAndRequiresMount(t *testing.T) {
	root := t.TempDir()
	m := []Mount{{Path: root}}
	p, e := restoreDir(root, "new", m)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = restoreDir(root, "new", m); e == nil {
		t.Fatal("overwrites directory", p)
	}
	for _, folder := range []string{"../outside", "a/b", ".", ""} {
		if _, e := restoreDir(root, folder, m); e == nil {
			t.Fatal("unsafe folder", folder)
		}
	}
	if _, e = restoreDir(root, "other", nil); e == nil {
		t.Fatal("missing mount accepted")
	}
	if e = os.Symlink(root, filepath.Join(root, "link")); e != nil {
		t.Fatal(e)
	}
	if _, e = restoreDir(root, "link", m); e == nil {
		t.Fatal("symlink accepted")
	}
}
func TestPersistentLockAndInterruptedStatus(t *testing.T) {
	dir := t.TempDir()
	s, e := NewStore(dir)
	if e != nil {
		t.Fatal(e)
	}
	s.S.LastResult = "running"
	_ = s.save()
	if _, e := NewStore(dir); !errors.Is(e, ErrBusy) {
		t.Fatal("two apps share state", e)
	}
	s.Close()
	s, e = NewStore(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if s.S.LastResult != "interrupted" {
		t.Fatal("lost interrupted status")
	}
	st, _ := os.Stat(filepath.Join(dir, "state.json"))
	if st.Mode().Perm() != 0600 {
		t.Fatal("state not private")
	}
}
func TestNotificationsFailureAndNoRedirect(t *testing.T) {
	a := testApp(t, &fakeRunner{})
	got := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got <- string(b)
		w.WriteHeader(200)
	}))
	defer srv.Close()
	a.notify(srv.URL, "Backup fehlgeschlagen.")
	if s := <-got; s != "Backup fehlgeschlagen." {
		t.Fatal(s)
	}
	for _, raw := range []string{"file:///etc/passwd", "http://user:pass@localhost/x", "ftp://localhost/x"} {
		if validateNotifyURL(raw) == nil {
			t.Fatal(raw)
		}
	}
}

func request(a *App, method, path, body string, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://example.com/api/v1/"+path, strings.NewReader(body))
	r.RemoteAddr = "192.168.1.10:1234"
	r.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		r.AddCookie(cookie)
	}
	if csrf != "" {
		r.Header.Set("X-CSRF-Token", csrf)
	}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	return w
}
func auth(t *testing.T, a *App) (*http.Cookie, string) {
	t.Helper()
	w := request(a, "GET", "auth", "", nil, "")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var b struct {
		CSRF string `json:"csrf_token"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &b)
	return w.Result().Cookies()[0], b.CSRF
}
func TestAuthenticationCSRFStrictCookieAndRateLimit(t *testing.T) {
	a := testApp(t, &fakeRunner{})
	c, csrf := auth(t, a)
	if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
		t.Fatal("unsafe cookie")
	}
	if w := request(a, "GET", "status", "", nil, ""); w.Code != 401 {
		t.Fatal(w.Code)
	}
	if w := request(a, "POST", "login", `{"password":"bad"}`, c, ""); w.Code != 403 {
		t.Fatal("no csrf accepted", w.Code)
	}
	for j := 0; j < 5; j++ {
		if w := request(a, "POST", "login", `{"password":"bad"}`, c, csrf); w.Code != 401 {
			t.Fatal(w.Code)
		}
	}
	if w := request(a, "POST", "login", `{"password":"bad"}`, c, csrf); w.Code != 429 {
		t.Fatal("no rate limit", w.Code)
	}
	r := httptest.NewRequest("POST", "http://example.com/api/v1/login", strings.NewReader(`{}`))
	r.RemoteAddr = "192.168.1.10:1234"
	r.AddCookie(c)
	r.Header.Set("X-CSRF-Token", csrf)
	r.Header.Set("Origin", "http://evil.com")
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("cross-origin accepted")
	}
}
func TestSessionRotationAndStatusNoSecrets(t *testing.T) {
	a := testApp(t, &fakeRunner{})
	c, csrf := auth(t, a)
	hash, _ := bcrypt.GenerateFromPassword([]byte("correct-password"), bcrypt.MinCost)
	a.store.S.AdminHash = string(hash)
	a.store.S.Name = "alice"
	i := inv("bob")
	_ = a.store.pair(i, fingerprint(i), false)
	w := request(a, "POST", "login", `{"password":"correct-password"}`, c, csrf)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	newCookie := w.Result().Cookies()[0]
	if newCookie.Value == c.Value {
		t.Fatal("session not rotated")
	}
	if w = request(a, "GET", "status", "", c, ""); w.Code != 401 {
		t.Fatal("old session active")
	}
	w = request(a, "GET", "status", "", newCookie, "")
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	for _, secret := range []string{a.store.S.Key, i.Password, string(hash)} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatal("secret in status")
		}
	}
	w = request(a, "POST", "settings", `{"unknown":true}`, newCookie, csrf)
	if w.Code != 400 {
		t.Fatal("unknown field accepted", w.Code)
	}
}
func TestLANAndDNSRebindingGuard(t *testing.T) {
	a := testApp(t, &fakeRunner{})
	for _, test := range []struct{ remote, host string }{{"100.64.0.2:42", "192.168.1.1"}, {"8.8.8.8:42", "192.168.1.1"}, {"192.168.1.2:42", "evil.example"}} {
		r := httptest.NewRequest("GET", "http://"+test.host+"/api/v1/auth", nil)
		r.RemoteAddr = test.remote
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal("exposed UI", test, w.Code)
		}
	}
}

func TestUnsafeTSNetBuildFailsClosed(t *testing.T) {
	unsafe := buildfeatures.HasPeerAPIServer || buildfeatures.HasWebClient || buildfeatures.HasSSH || buildfeatures.HasDrive
	if unsafe && validateTSBuild() == nil {
		t.Fatal("tsnet built-in service ports left enabled")
	}
	if !unsafe && validateTSBuild() != nil {
		t.Fatal("secure tsnet build rejected")
	}
}

type memoryTSStore map[ipn.StateKey][]byte

func (s memoryTSStore) ReadState(k ipn.StateKey) ([]byte, error) {
	if b, ok := s[k]; ok {
		return b, nil
	}
	return nil, ipn.ErrStateNotExist
}
func (s memoryTSStore) WriteState(k ipn.StateKey, b []byte) error { s[k] = b; return nil }
func TestPersistedServeCanNeverForwardToLoopback(t *testing.T) {
	s := noServeStore{memoryTSStore{"_serve/profile": []byte(`{"TCP":{"8080":{"TCPForward":"127.0.0.1:8080"}}}`)}}
	if _, e := s.ReadState("_serve/profile"); !errors.Is(e, ipn.ErrStateNotExist) {
		t.Fatal("loaded unsafe Serve state")
	}
	if e := s.WriteState("_serve/profile", []byte(`{"TCP":{"8080":{}}}`)); e == nil {
		t.Fatal("forwarding config permitted")
	}
	if e := s.WriteState("_serve/profile", []byte(`{}`)); e != nil {
		t.Fatal(e)
	}
}

func TestFailureAndStalenessNotifications(t *testing.T) {
	a := testApp(t, &fakeRunner{fn: func([]string) (RunResult, error) { return RunResult{Code: 1}, nil }})
	got := make(chan string, 3)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got <- string(b)
		w.WriteHeader(200)
	}))
	defer srv.Close()
	i := inv("bob")
	a.store.mu.Lock()
	_ = a.store.pair(i, fingerprint(i), false)
	a.store.S.Settings.NtfyURL = srv.URL
	a.store.S.Settings.Sources = []string{"/sources/photos"}
	a.store.S.RecoveryAck = true
	a.store.S.AcknowledgedAt = time.Now().Add(-72 * time.Hour)
	a.store.mu.Unlock()
	a.scheduleTick(time.Now())
	select {
	case msg := <-got:
		if !strings.Contains(msg, "keine vollständige Sicherung") {
			t.Fatal(msg)
		}
	case <-time.After(time.Second):
		t.Fatal("missing stale alert")
	}
	a.scheduleTick(time.Now())
	select {
	case <-got:
		t.Fatal("duplicate stale alert")
	default:
	}
	if _, e := a.startOperation(OperationRequest{Kind: "check"}, false); e != nil {
		t.Fatal(e)
	}
	select {
	case msg := <-got:
		if !strings.Contains(msg, "fehlgeschlagen") {
			t.Fatal(msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("missing failure alert")
	}
}
func TestRecoveredSnapshotsDiscoverRetiredSourceGroups(t *testing.T) {
	setID := strings.Repeat("c", 24)
	f := &fakeRunner{fn: func([]string) (RunResult, error) {
		return RunResult{Output: []byte(`[{"id":"` + snapID + `","paths":["/sources/old"],"tags":["buddybackup-source:` + setID + `"]}]`)}, nil
	}}
	w := testWorker(t, f)
	if _, e := w.snapshots(context.Background()); e != nil {
		t.Fatal(e)
	}
	if len(w.app.store.S.Sets) != 1 || w.app.store.S.Sets[0].ID != setID || !w.app.store.S.Sets[0].Retired {
		t.Fatal("lost recovered retired group")
	}
}

func TestWeeklyMaintenanceIndependentOfBackupSuccess(t *testing.T) {
	f := &fakeRunner{fn: func(args []string) (RunResult, error) {
		if hasArgs(args, "cat", "config") {
			return RunResult{Output: []byte(`{"id":"` + snapID + `"}`)}, nil
		}
		if hasArgs(args, "backup") {
			t.Error("maintenance depends on backup")
		}
		return RunResult{}, nil
	}}
	a := testApp(t, f)
	i := inv("bob")
	a.store.mu.Lock()
	_ = a.store.pair(i, fingerprint(i), false)
	a.store.S.RecoveryAck = true
	a.store.S.Settings.Sources = []string{"/sources/photos"}
	a.store.S.NextRun = time.Now().Add(time.Hour)
	a.store.S.NextMaintenance = time.Now().Add(-time.Hour)
	a.store.S.LastResult = "error"
	a.store.mu.Unlock()
	a.scheduleTick(time.Now())
	a.store.mu.Lock()
	done := a.done
	a.store.mu.Unlock()
	if done == nil {
		t.Fatal("no maintenance scheduled")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("maintenance did not finish")
	}
	a.store.mu.Lock()
	defer a.store.mu.Unlock()
	if a.op.Kind != "maintenance" || a.op.State != "success" || a.store.S.LastMaintenance.IsZero() {
		t.Fatal(a.op)
	}
}
func TestReceiverEnforcesQuotaAndPrivateRepos(t *testing.T) {
	s := testStore(t)
	s.S.Quota = 4096
	s.S.ReceiverUser = "buddy-0123456789abcdef"
	s.S.ReceiverPassword = secret()
	hash, _ := bcrypt.GenerateFromPassword([]byte(s.S.ReceiverPassword), bcrypt.MinCost)
	s.S.ReceiverHash = string(hash)
	h, e := receiver(s)
	if e != nil {
		t.Fatal(e)
	}
	call := func(method, path, body string, auth bool) int {
		r := httptest.NewRequest(method, "http://receiver"+path, strings.NewReader(body))
		if auth {
			r.SetBasicAuth(s.S.ReceiverUser, s.S.ReceiverPassword)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	root := "/" + s.S.ReceiverUser
	if c := call("GET", root+"/config", "", false); c != 401 {
		t.Fatal("unauthenticated access", c)
	}
	if c := call("GET", "/someone-else/config", "", true); c != 401 {
		t.Fatal("private-repos bypass", c)
	}
	if c := call("POST", root+"/?create=true", "", true); c != 200 {
		t.Fatal("repo create", c)
	}
	data := strings.Repeat("x", 8192)
	sum := sha256.Sum256([]byte(data))
	if c := call("POST", root+"/data/"+hex.EncodeToString(sum[:]), data, true); c != 507 && c != 500 {
		t.Fatal("quota bypass", c)
	}
	var bytes int64
	_ = filepath.WalkDir(filepath.Join(s.dir, "incoming"), func(p string, d os.DirEntry, e error) error {
		if e == nil && d.Type().IsRegular() {
			st, _ := d.Info()
			bytes += st.Size()
		}
		return nil
	})
	if bytes > s.S.Quota {
		t.Fatal("quota exceeded", bytes)
	}
}

func TestRestoreSelectionIsLiteralAndValidated(t *testing.T) {
	args, err := restoreIncludes([]string{"/sources/a/foto[1]*.jpg"})
	if err != nil || len(args) != 2 || args[0] != "--include" || args[1] != `/sources/a/foto\[1]\*.jpg` {
		t.Fatalf("unexpected include args %v err %v", args, err)
	}
	for _, bad := range []string{"relative/path", "/a\nb"} {
		if _, err := restoreIncludes([]string{bad}); err == nil {
			t.Fatalf("expected rejection for %q", bad)
		}
	}
}

func TestFileListIgnoresSnapshotHeaderAndCaps(t *testing.T) {
	out := []byte(`{"struct_type":"snapshot","message_type":"snapshot","id":"x"}
{"struct_type":"node","message_type":"node","path":"/sources/a/b.txt","type":"file","size":7}
`)
	entries, truncated := parseFileList(out)
	if truncated || len(entries) != 1 || entries[0].Path != "/sources/a/b.txt" || entries[0].Size != 7 {
		t.Fatalf("unexpected entries %+v truncated %v", entries, truncated)
	}
}

func TestMountIdentitySurvivesNewDeviceNumbers(t *testing.T) {
	before := []Mount{{Path: "/sources/a/kind", Device: "0:59", Root: "/", FS: "zfs", Source: "tank/a/kind", ReadOnly: true}}
	after := []Mount{{Path: "/sources/a/kind", Device: "0:58", Root: "/", FS: "zfs", Source: "tank/a/kind", ReadOnly: true}}
	if fingerprint(stableMounts(before)) != fingerprint(stableMounts(after)) {
		t.Fatal("a reboot must not invalidate the source manifest")
	}
	after[0].Source = "tank/other"
	if fingerprint(stableMounts(before)) == fingerprint(stableMounts(after)) {
		t.Fatal("a different dataset must invalidate the source manifest")
	}
}
