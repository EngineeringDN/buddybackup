package buddy

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

const BackupPort = 8787

var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,30}$`)
var idRE = regexp.MustCompile(`^[a-f0-9]{64}$`)
var secretRE = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
var nodeRE = regexp.MustCompile(`^[A-Za-z0-9:_-]{1,128}$`)
var userRE = regexp.MustCompile(`^buddy-[a-f0-9]{16}$`)
var ErrBusy = errors.New("Eine Operation läuft bereits. Bitte später erneut versuchen.")

type Invitation struct {
	Schema   int    `json:"schema"`
	Name     string `json:"name"`
	IP       string `json:"ip"`
	NodeID   string `json:"node_id"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
}
type Settings struct {
	Sources       []string `json:"sources"`
	IntervalHours int      `json:"interval_hours"`
	KeepDaily     int      `json:"keep_daily"`
	KeepWeekly    int      `json:"keep_weekly"`
	KeepMonthly   int      `json:"keep_monthly"`
	DirectOnly    bool     `json:"direct_only"`
	UploadKiB     int      `json:"upload_kib"`
	NtfyURL       string   `json:"ntfy_url"`
	StaleHours    int      `json:"stale_hours"`
}
type SourceSet struct {
	ID      string   `json:"id"`
	Paths   []string `json:"paths"`
	Retired bool     `json:"retired"`
	Deleted bool     `json:"deleted"`
}
type Kit struct {
	Schema        int        `json:"schema"`
	Peer          Invitation `json:"peer"`
	RepositoryKey string     `json:"repository_key"`
	RepositoryID  string     `json:"repository_id"`
	BackupID      string     `json:"backup_id"`
	BackupHost    string     `json:"backup_host"`
}
type Export struct {
	Kit                   Kit    `json:"kit"`
	Fingerprint           string `json:"fingerprint"`
	ConnectionFingerprint string `json:"connection_fingerprint"`
}
type State struct {
	Name              string      `json:"name"`
	AdminHash         string      `json:"admin_hash"`
	Quota             int64       `json:"quota_bytes"`
	ReceiverUser      string      `json:"receiver_user"`
	ReceiverPassword  string      `json:"receiver_password"`
	ReceiverHash      string      `json:"receiver_hash"`
	Peer              *Invitation `json:"peer"`
	Key               string      `json:"repository_key"`
	RepositoryID      string      `json:"repository_id"`
	BackupID          string      `json:"backup_id"`
	BackupHost        string      `json:"backup_host"`
	AllowInit         bool        `json:"allow_init"`
	RecoveryAck       bool        `json:"recovery_acknowledged"`
	ExportFingerprint string      `json:"export_fingerprint"`
	ExportConnection  string      `json:"export_connection"`
	Settings          Settings    `json:"settings"`
	Manifest          []Mount     `json:"manifest"`
	Sets              []SourceSet `json:"source_sets"`
	ActiveSet         string      `json:"active_set"`
	NextMaintenance   time.Time   `json:"next_maintenance"`
	LastMaintenance   time.Time   `json:"last_maintenance"`
	NextRun           time.Time   `json:"next_run"`
	LastSuccess       time.Time   `json:"last_success"`
	LastResult        string      `json:"last_result"`
	LastError         string      `json:"last_error"`
	LastBackupError   string      `json:"last_backup_error"`
	RecoveryOnly      bool        `json:"recovery_only"`
	AcknowledgedAt    time.Time   `json:"acknowledged_at"`
	LastStaleNotice   time.Time   `json:"last_stale_notice"`
}
type Store struct {
	mu   sync.Mutex
	dir  string
	S    State
	lock *os.File
}

func secret() string {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func randomID() string {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b)
}

// Roundtrip through a map ensures lexicographically sorted JSON keys, matching Python canonical().
func fingerprint(v any) string {
	b, _ := json.Marshal(v)
	var m any
	_ = json.Unmarshal(b, &m)
	b, _ = json.Marshal(m)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
func atomicJSON(path string, v any) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".state-")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	if e = os.Rename(f.Name(), path); e != nil {
		return e
	}
	d, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
func NewStore(dir string) (*Store, error) {
	if e := os.MkdirAll(dir, 0700); e != nil {
		return nil, e
	}
	real, e := filepath.EvalSymlinks(dir)
	if e != nil || real != filepath.Clean(dir) {
		return nil, errors.New("Datenpfad darf kein symbolischer Link sein.")
	}
	if e = ownPrivateDir(dir); e != nil {
		return nil, e
	}
	f, e := os.OpenFile(filepath.Join(dir, "app.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return nil, e
	}
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		f.Close()
		return nil, ErrBusy
	}
	st := &Store{dir: dir, lock: f}
	statePath := filepath.Join(dir, "state.json")
	if info, se := os.Lstat(statePath); se == nil && (info.Mode()&os.ModeSymlink != 0 || info.Size() > 8<<20) {
		f.Close()
		return nil, errors.New("Ungültige Zustandsdatei.")
	}
	b, e := os.ReadFile(statePath)
	if e == nil {
		e = json.Unmarshal(b, &st.S)
	} else if os.IsNotExist(e) {
		e = nil
		st.S.Settings = Settings{Sources: []string{}, IntervalHours: 24, KeepDaily: 7, KeepWeekly: 4, KeepMonthly: 12, StaleHours: 48}
	}
	if e != nil {
		f.Close()
		return nil, e
	}
	if st.S.LastResult == "running" {
		st.S.LastResult = "interrupted"
		st.S.LastBackupError = "Der letzte Lauf wurde unterbrochen. Teilweise Versionen bleiben als unvollständig markiert."
		if e = st.save(); e != nil {
			f.Close()
			return nil, e
		}
	}
	return st, nil
}
func (s *Store) Close()      { s.lock.Close() }
func (s *Store) save() error { return atomicJSON(filepath.Join(s.dir, "state.json"), s.S) }
func (s *Store) kit() Kit {
	return Kit{1, *s.S.Peer, s.S.Key, s.S.RepositoryID, s.S.BackupID, s.S.BackupHost}
}
func (s *Store) connection() string {
	if s.S.Peer == nil {
		return ""
	}
	return fingerprint(struct {
		Peer   Invitation `json:"peer"`
		Key    string     `json:"key"`
		Backup string     `json:"backup"`
	}{*s.S.Peer, s.S.Key, s.S.BackupID})
}
func (s *Store) exportRecovery() (Export, error) {
	if s.S.Peer == nil || s.S.Key == "" {
		return Export{}, errors.New("Zuerst einen Freund verbinden.")
	}
	k := s.kit()
	e := Export{k, fingerprint(k), s.connection()}
	s.S.ExportFingerprint = e.Fingerprint
	s.S.ExportConnection = e.ConnectionFingerprint
	return e, s.save()
}
func (s *Store) ackRecovery(fp, conn, confirm string) error {
	if confirm != "SAVED_OFFLINE" || fp == "" || fp != s.S.ExportFingerprint || conn != s.S.ExportConnection || conn != s.connection() {
		return errors.New("Das Notfall-Kit gehört nicht zur aktuellen Verbindung. Neu exportieren.")
	}
	s.S.RecoveryAck = true
	if s.S.NextMaintenance.IsZero() {
		s.S.NextMaintenance = time.Now().Add(7 * 24 * time.Hour)
	}
	s.S.AcknowledgedAt = time.Now()
	if s.S.NextRun.IsZero() {
		s.S.NextRun = time.Now().Add(time.Duration(s.S.Settings.IntervalHours) * time.Hour)
	}
	return s.save()
}
func (s *Store) pair(inv Invitation, fp string, replace bool) error {
	if e := validateInvitation(inv); e != nil {
		return e
	}
	if fingerprint(inv) != fp {
		return errors.New("Der SHA-256-Fingerabdruck stimmt nicht überein.")
	}
	if s.S.Peer != nil {
		if *s.S.Peer == inv {
			return nil
		}
		if !replace {
			return errors.New("Bestehende Verbindung: Ersetzen ausdrücklich bestätigen.")
		}
		if e := atomicJSON(filepath.Join(s.dir, "connection-"+randomID()+".json"), s.kit()); e != nil {
			return e
		}
	}
	s.S.Peer = &inv
	s.S.Key = secret()
	s.S.BackupID = randomID()
	s.S.BackupHost = s.S.Name
	s.S.RepositoryID = ""
	s.S.AllowInit = true
	s.S.RecoveryAck = false
	s.S.ExportFingerprint = ""
	s.S.ExportConnection = ""
	s.S.NextRun = time.Time{}
	s.S.NextMaintenance = time.Time{}
	s.S.LastMaintenance = time.Time{}
	s.S.LastSuccess = time.Time{}
	return s.save()
}
func (s *Store) importRecovery(k Kit, fp, confirm string) error {
	if s.S.Peer != nil {
		return errors.New("Eine Verbindung ist bereits eingerichtet.")
	}
	if k.Schema != 1 || confirm != "IMPORT_RECOVERY" || fingerprint(k) != fp || !secretRE.MatchString(k.RepositoryKey) || !regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(k.BackupID) || !nameRE.MatchString(k.BackupHost) || (k.RepositoryID != "" && !idRE.MatchString(k.RepositoryID)) {
		return errors.New("Ungültiges Notfall-Kit.")
	}
	if e := validateInvitation(k.Peer); e != nil {
		return e
	}
	s.S.Peer = &k.Peer
	s.S.Key = k.RepositoryKey
	s.S.RepositoryID = k.RepositoryID
	s.S.BackupID = k.BackupID
	s.S.BackupHost = k.BackupHost
	s.S.AllowInit = false
	s.S.RecoveryOnly = true
	s.S.RecoveryAck = false
	s.S.ExportFingerprint = ""
	s.S.ExportConnection = ""
	return s.save()
}
func (s *Store) configure(v Settings, mounts []Mount) error {
	if v.IntervalHours < 1 || v.IntervalHours > 168 || v.KeepDaily < 0 || v.KeepWeekly < 0 || v.KeepMonthly < 0 || v.KeepDaily > 3650 || v.KeepWeekly > 3650 || v.KeepMonthly > 3650 || v.KeepDaily+v.KeepWeekly+v.KeepMonthly == 0 || v.UploadKiB < 0 || v.UploadKiB > 10000000 || v.StaleHours < 1 || v.StaleHours > 87600 || len(v.Sources) > 64 {
		return errors.New("Ungültige Sicherungs- oder Aufbewahrungseinstellung.")
	}
	if e := validateNotifyURL(v.NtfyURL); e != nil {
		return e
	}
	sort.Strings(v.Sources)
	for i, p := range v.Sources {
		if !validSourcePath(p) || (i > 0 && p == v.Sources[i-1]) {
			return errors.New("Nur getrennte Mounts unter /sources/<name> sind erlaubt.")
		}
	}
	manifest, e := captureManifest(v.Sources, mounts)
	if e != nil {
		return e
	}
	id := ""
	if len(v.Sources) > 0 {
		id = fingerprint(v.Sources)[:24]
	}
	for i := range s.S.Sets {
		s.S.Sets[i].Retired = s.S.Sets[i].ID != id
	}
	found := false
	for i := range s.S.Sets {
		if s.S.Sets[i].ID == id {
			s.S.Sets[i].Retired = false
			s.S.Sets[i].Deleted = false
			found = true
		}
	}
	if !found && id != "" {
		s.S.Sets = append(s.S.Sets, SourceSet{ID: id, Paths: append([]string{}, v.Sources...)})
	}
	if s.S.Settings.IntervalHours != v.IntervalHours {
		s.S.NextRun = time.Now().Add(time.Duration(v.IntervalHours) * time.Hour)
	}
	if id != s.S.ActiveSet && s.S.ActiveSet != "" {
		// A changed folder selection is not protected until its first backup succeeds.
		s.S.LastSuccess = time.Time{}
	}
	s.S.Settings = v
	s.S.Manifest = manifest
	s.S.ActiveSet = id
	if len(v.Sources) > 0 {
		s.S.RecoveryOnly = false
	}
	return s.save()
}
func nextSlot(previous, now time.Time, interval time.Duration) time.Time {
	if previous.IsZero() {
		return now.Add(interval)
	}
	if previous.After(now) {
		return previous
	}
	return previous.Add((now.Sub(previous)/interval + 1) * interval)
}
func validateInvitation(i Invitation) error {
	if i.Schema != 1 || !nameRE.MatchString(i.Name) || !tailnetIP(i.IP) || !nodeRE.MatchString(i.NodeID) || i.Port != BackupPort || !userRE.MatchString(i.Username) || !secretRE.MatchString(i.Password) {
		return fmt.Errorf("Ungültige Einladung; erforderlich ist Tailscale TCP %d.", BackupPort)
	}
	return nil
}
func safeMessage(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 32 && r != 127 {
			b.WriteRune(r)
		}
	}
	return b.String()
}
