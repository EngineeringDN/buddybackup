package buddy

import (
	"context"
	"errors"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type Options struct {
	DataDir      string
	RestoreRoot  string
	Network      Network
	Runner       Runner
	Web          fs.FS
	Mounts       func() ([]Mount, error)
	AllowedHost  string
	SecureCookie bool
}
type App struct {
	usage           usageCache
	store           *Store
	network         Network
	runner          Runner
	mounts          func() ([]Mount, error)
	restoreRoot     string
	web             http.Handler
	allowedHost     string
	secureCookie    bool
	op              *Operation
	cancel          context.CancelFunc
	done            chan struct{}
	stopping        bool
	httpWG          sync.WaitGroup
	sessionMu       sync.Mutex
	sessions        map[string]*session
	limits          map[string]attempts
	loginGate       chan struct{}
	notifyClient    *http.Client
	receiver        http.Handler
	schedulerCancel context.CancelFunc
	schedulerDone   chan struct{}
}

func New(o Options) (*App, error) {
	s, e := NewStore(o.DataDir)
	if e != nil {
		return nil, e
	}
	if o.Network == nil {
		o.Network = NewTSNetwork(o.DataDir)
	}
	if o.Runner == nil {
		o.Runner = ExecRunner{Binary: "/usr/bin/restic"}
	}
	if o.Mounts == nil {
		o.Mounts = readMounts
	}
	if o.RestoreRoot == "" {
		o.RestoreRoot = "/restore"
	}
	a := &App{store: s, network: o.Network, runner: o.Runner, mounts: o.Mounts, restoreRoot: o.RestoreRoot, allowedHost: o.AllowedHost, secureCookie: o.SecureCookie, sessions: map[string]*session{}, limits: map[string]attempts{}, loginGate: make(chan struct{}, 2), notifyClient: &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	if o.Web != nil {
		a.web = http.FileServer(http.FS(o.Web))
	} else {
		a.web = http.NotFoundHandler()
	}
	for _, p := range []string{"cache", "incoming"} {
		if e = os.MkdirAll(filepath.Join(o.DataDir, p), 0700); e != nil {
			s.Close()
			return nil, e
		}
	}
	if reset := os.Getenv("BUDDY_RESET_PASSWORD"); reset != "" && s.S.AdminHash != "" {
		hash, e := passwordHash(reset)
		if e != nil {
			s.Close()
			return nil, e
		}
		s.S.AdminHash = hash
		if e = s.save(); e != nil {
			s.Close()
			return nil, e
		}
		log.Print("Passwort wurde zurückgesetzt. BUDDY_RESET_PASSWORD jetzt wieder aus der App-Konfiguration entfernen.")
	}
	if s.S.AdminHash != "" {
		if e = a.startNetwork(); e != nil {
			s.Close()
			return nil, e
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.schedulerCancel = cancel
	a.schedulerDone = make(chan struct{})
	go a.schedule(ctx)
	return a, nil
}
func (a *App) startNetwork() error {
	if a.receiver == nil {
		h, e := receiver(a.store)
		if e != nil {
			return e
		}
		a.receiver = h
	}
	return a.network.Start(a.store.S.Name, a.receiver)
}
func (a *App) Close(ctx context.Context) error {
	a.store.mu.Lock()
	a.stopping = true
	a.schedulerCancel()
	if a.cancel != nil {
		a.cancel()
	}
	done := a.done
	a.store.mu.Unlock()
	if done != nil {
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	select {
	case <-a.schedulerDone:
	case <-ctx.Done():
		return ctx.Err()
	}
	requestsDone := make(chan struct{})
	go func() { a.httpWG.Wait(); close(requestsDone) }()
	select {
	case <-requestsDone:
	case <-ctx.Done():
		return ctx.Err()
	}
	e := a.network.Close()
	a.store.Close()
	return e
}
func (a *App) busy() bool { return a.op != nil && a.op.State == "running" }
func (a *App) startOperation(r OperationRequest, scheduled bool) (*Operation, error) {
	a.store.mu.Lock()
	defer a.store.mu.Unlock()
	if a.stopping || a.busy() {
		return nil, ErrBusy
	}
	switch r.Kind {
	case "backup", "snapshots", "files", "check", "maintenance", "restore", "restore-test", "unlock", "retire":
	default:
		return nil, errors.New("Unbekannte Operation.")
	}
	if a.store.S.Peer == nil {
		return nil, errors.New("Zuerst einen Freund verbinden.")
	}
	if r.Kind == "unlock" && r.Confirm != "UNLOCK_STALE_LOCKS" {
		return nil, errors.New("Entsperren ausdrücklich bestätigen.")
	}
	a.op = &Operation{ID: randomID(), Kind: r.Kind, State: "running", Started: time.Now(), Progress: map[string]any{}}
	ctx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel
	a.done = make(chan struct{})
	op, done := a.op, a.done
	cfg := copyState(a.store.S)
	planned := cfg.NextRun
	a.store.S.LastResult = "running"
	if e := a.store.save(); e != nil {
		cancel()
		a.op = nil
		close(done)
		return nil, e
	}
	go func() {
		w := &worker{app: a, cfg: cfg, op: op}
		result, e := w.execute(ctx, r)
		cancel()
		a.store.mu.Lock()
		op.Finished = time.Now()
		op.Result = result
		op.Error = publicError(e)
		op.State = "success"
		if e != nil {
			op.State = "error"
		}
		a.store.S.LastResult = op.State
		a.store.S.LastError = op.Error
		switch {
		case r.Kind == "backup":
			a.store.S.LastBackupError = op.Error
		case r.Kind == "maintenance" && scheduled && e != nil && a.store.S.LastBackupError == "":
			a.store.S.LastBackupError = op.Error
		}
		if r.Kind == "backup" && e == nil {
			a.store.S.LastSuccess = op.Finished
		}
		if r.Kind == "maintenance" {
			if e == nil {
				a.store.S.LastMaintenance = op.Finished
			}
			a.store.S.NextMaintenance = nextSlot(cfg.NextMaintenance, op.Finished, 7*24*time.Hour)
		}
		if scheduled && r.Kind == "backup" {
			a.store.S.NextRun = nextSlot(planned, op.Finished, time.Duration(cfg.Settings.IntervalHours)*time.Hour)
		}
		if se := a.store.save(); se != nil {
			op.State = "error"
			op.Error = "Status konnte nicht dauerhaft gespeichert werden."
		}
		a.cancel = nil
		close(done)
		a.store.mu.Unlock()
		if e != nil {
			a.notify(cfg.Settings.NtfyURL, "BuddyBackup: Operation fehlgeschlagen. Status in der lokalen Oberfläche prüfen.")
		}
	}()
	clone := *op
	return &clone, nil
}
func (a *App) schedule(ctx context.Context) {
	defer close(a.schedulerDone)
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			a.scheduleTick(now)
		}
	}
}
func (a *App) scheduleTick(now time.Time) {
	a.store.mu.Lock()
	s := copyState(a.store.S)
	ready := !a.stopping && !a.busy() && s.RecoveryAck && len(s.Settings.Sources) > 0
	due := ready && !s.NextRun.IsZero() && !now.Before(s.NextRun)
	maintenanceDue := ready && !s.NextMaintenance.IsZero() && !now.Before(s.NextMaintenance)
	baseline := s.LastSuccess
	if baseline.IsZero() {
		baseline = s.AcknowledgedAt
	}
	stale := ready && !baseline.IsZero() && now.Sub(baseline) > time.Duration(s.Settings.StaleHours)*time.Hour
	notice := stale && s.Settings.NtfyURL != "" && now.Sub(s.LastStaleNotice) > 24*time.Hour
	if notice {
		a.store.S.LastStaleNotice = now
		_ = a.store.save()
	}
	a.store.mu.Unlock()
	if notice {
		a.notify(s.Settings.NtfyURL, "BuddyBackup: Seit längerem keine vollständige Sicherung. Lokalen Status prüfen.")
	}
	if due {
		_, _ = a.startOperation(OperationRequest{Kind: "backup"}, true)
	} else if maintenanceDue {
		_, _ = a.startOperation(OperationRequest{Kind: "maintenance"}, true)
	}
}

func passwordHash(password string) (string, error) {
	if len(password) < 12 || len(password) > 72 {
		return "", errors.New("Passwort: 12 bis 72 Bytes erforderlich.")
	}
	b, e := bcrypt.GenerateFromPassword([]byte(password), 12)
	return string(b), e
}
