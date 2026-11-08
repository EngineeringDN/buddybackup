package buddy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const pendingTag = "buddybackup-pending"
const completeTag = "buddybackup-complete"

type OperationRequest struct {
	Kind     string   `json:"kind"`
	ReadData bool     `json:"read_data"`
	LowSpace bool     `json:"low_space"`
	Snapshot string   `json:"snapshot"`
	Folder   string   `json:"folder"`
	Paths    []string `json:"paths"`
	Confirm  string   `json:"confirm"`
	SetID    string   `json:"id"`
}
type Operation struct {
	ID       string         `json:"id"`
	Kind     string         `json:"kind"`
	State    string         `json:"state"`
	Started  time.Time      `json:"started"`
	Finished time.Time      `json:"finished"`
	Progress map[string]any `json:"progress"`
	Result   any            `json:"result"`
	Error    string         `json:"error"`
}
type worker struct {
	app              *App
	cfg              State
	repo, user, pass string
	op               *Operation
}

func (w *worker) tag() string    { return "buddybackup:" + w.cfg.BackupID }
func (w *worker) setTag() string { return "buddybackup-source:" + w.cfg.ActiveSet }
func (w *worker) run(ctx context.Context, args ...string) (RunResult, error) {
	if _, e := w.app.network.Verify(ctx, *w.cfg.Peer, w.cfg.Settings.DirectOnly); e != nil {
		return RunResult{}, e
	}
	command := []string{"--retry-lock", "10s"}
	if w.cfg.Settings.UploadKiB > 0 {
		command = append(command, "--limit-upload", strconv.Itoa(w.cfg.Settings.UploadKiB))
	}
	command = append(command, args...)
	env := []string{"PATH=/usr/bin:/bin", "HOME=/tmp", "TMPDIR=/tmp", "TZ=UTC", "RESTIC_REPOSITORY=" + w.repo, "RESTIC_PASSWORD=" + w.cfg.Key, "RESTIC_REST_USERNAME=" + w.user, "RESTIC_REST_PASSWORD=" + w.pass, "RESTIC_CACHE_DIR=" + filepath.Join(w.app.store.dir, "cache"), "RESTIC_PROGRESS_FPS=1"}
	r, e := w.app.runner.Run(ctx, command, env, func(v map[string]any) { w.app.store.mu.Lock(); defer w.app.store.mu.Unlock(); w.op.Progress = v })
	if e != nil {
		return r, e
	}
	return r, nil
}
func (w *worker) rest(ctx context.Context, args ...string) ([]byte, error) {
	r, e := w.run(ctx, args...)
	if e != nil {
		return nil, e
	}
	if r.Code != 0 {
		return nil, fmt.Errorf("restic meldet Exit %d. Verbindung, freien Speicher und Zugriffsrechte prüfen.", r.Code)
	}
	return r.Output, nil
}
func (w *worker) ensureRepository(ctx context.Context, allowCreate bool) error {
	r, e := w.run(ctx, "cat", "config")
	if e != nil {
		return e
	}
	if r.Code == 10 {
		if !allowCreate || !w.cfg.AllowInit || w.cfg.RepositoryID != "" {
			return errNoRepository
		}
		if _, e = w.rest(ctx, "init", "--repository-version", "2"); e != nil {
			return e
		}
		r, e = w.run(ctx, "cat", "config")
		if e != nil {
			return e
		}
	}
	if r.Code != 0 {
		return errors.New("Repository kann nicht gelesen werden. Passwort oder Verbindung prüfen.")
	}
	var c struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(r.Output, &c) != nil || !idRE.MatchString(c.ID) {
		return errors.New("Ungültige Repository-Identität.")
	}
	if w.cfg.RepositoryID != "" && w.cfg.RepositoryID != c.ID {
		return errors.New("Repository wurde ersetzt. Keine Änderungen vorgenommen.")
	}
	w.cfg.RepositoryID = c.ID
	w.cfg.AllowInit = false
	w.app.store.mu.Lock()
	defer w.app.store.mu.Unlock()
	w.app.store.S.RepositoryID = c.ID
	w.app.store.S.AllowInit = false
	return w.app.store.save()
}
func snapshotID(b []byte) (string, error) {
	for _, line := range bytes.Split(b, []byte{'\n'}) {
		var r struct {
			Type string `json:"message_type"`
			ID   string `json:"snapshot_id"`
		}
		if json.Unmarshal(line, &r) == nil && r.Type == "summary" && idRE.MatchString(r.ID) {
			return r.ID, nil
		}
	}
	return "", errors.New("Backup lieferte keine vollständige Snapshot-ID.")
}
func (w *worker) pendingBackup(ctx context.Context, paths []string, extra ...string) (string, error) {
	args := []string{"backup", "--json", "--host", w.cfg.BackupHost, "--tag", w.tag(), "--tag", pendingTag}
	for _, t := range extra {
		args = append(args, "--tag", t)
	}
	args = append(args, "--exclude", ".zfs", "--exclude", ".ix-apps", "--exclude", "buddybackup-control", "--exclude", "buddybackup-incoming", "--")
	args = append(args, paths...)
	r, e := w.run(ctx, args...)
	if e != nil {
		return "", e
	}
	id, se := snapshotID(r.Output)
	if r.Code != 0 {
		return id, fmt.Errorf("Sicherung unvollständig (restic Exit %d). Snapshot bleibt als pending markiert.", r.Code)
	}
	if se != nil {
		return "", se
	}
	// Require all reported errors absent AND final source verification before promotion.
	for _, line := range bytes.Split(r.Output, []byte{'\n'}) {
		var row struct {
			Type string `json:"message_type"`
		}
		if json.Unmarshal(line, &row) == nil && row.Type == "error" {
			return id, errors.New("Sicherung meldet Lesefehler. Snapshot bleibt pending.")
		}
	}
	if len(extra) > 0 && extra[0] == w.setTag() {
		mounts, e := w.app.mounts()
		if e != nil {
			return id, e
		}
		if e = verifyManifest(w.cfg.Settings.Sources, w.cfg.Manifest, mounts); e != nil {
			return id, e
		}
	}
	b, e := w.rest(ctx, "tag", "--json", "--remove", pendingTag, "--add", completeTag, id)
	if e != nil {
		return id, e
	}
	var promoted string
	for _, line := range bytes.Split(b, []byte{'\n'}) {
		var c struct {
			Type string `json:"message_type"`
			Old  string `json:"old_snapshot_id"`
			New  string `json:"new_snapshot_id"`
		}
		if json.Unmarshal(line, &c) == nil && c.Type == "changed" && c.Old == id && idRE.MatchString(c.New) {
			promoted = c.New
		}
	}
	if promoted == "" {
		return id, errors.New("Abschlussmarkierung konnte nicht bestätigt werden.")
	}
	return promoted, nil
}
func (w *worker) backup(ctx context.Context) (any, error) {
	if !w.cfg.RecoveryAck || len(w.cfg.Settings.Sources) == 0 {
		return nil, errors.New("Quellen konfigurieren und extern gesichertes Notfall-Kit bestätigen.")
	}
	m, e := w.app.mounts()
	if e != nil {
		return nil, e
	}
	if e = verifyManifest(w.cfg.Settings.Sources, w.cfg.Manifest, m); e != nil {
		return nil, e
	}
	if e = w.ensureRepository(ctx, true); e != nil {
		return nil, e
	}
	id, e := w.pendingBackup(ctx, w.cfg.Settings.Sources, w.setTag())
	if e != nil {
		return nil, e
	}
	return map[string]any{"snapshot_id": id, "detail": "Sicherung abgeschlossen."}, nil
}

type Snapshot struct {
	ID       string    `json:"id"`
	Time     time.Time `json:"time"`
	Paths    []string  `json:"paths"`
	Tags     []string  `json:"tags"`
	Hostname string    `json:"hostname"`
}

func (w *worker) snapshots(ctx context.Context) ([]Snapshot, error) {
	b, e := w.rest(ctx, "snapshots", "--json", "--tag", w.tag())
	if e != nil {
		return nil, e
	}
	var rows []Snapshot
	if json.Unmarshal(b, &rows) != nil {
		return nil, errors.New("Snapshots konnten nicht gelesen werden.")
	}
	if rows == nil {
		rows = []Snapshot{}
	}
	// Recovery kits intentionally omit local mount paths. Rebuild group metadata
	// from authenticated, decrypted snapshot tags after recovery/import.
	w.app.store.mu.Lock()
	changed := false
	for _, row := range rows {
		for _, tag := range row.Tags {
			if strings.HasPrefix(tag, "buddybackup-source:") {
				id := strings.TrimPrefix(tag, "buddybackup-source:")
				if !regexp.MustCompile(`^[a-f0-9]{24}$`).MatchString(id) {
					continue
				}
				found := false
				for i := range w.app.store.S.Sets {
					if w.app.store.S.Sets[i].ID == id {
						found = true
						if w.app.store.S.Sets[i].Deleted {
							w.app.store.S.Sets[i].Deleted = false
							changed = true
						}
					}
				}
				if !found {
					w.app.store.S.Sets = append(w.app.store.S.Sets, SourceSet{ID: id, Paths: append([]string{}, row.Paths...), Retired: id != w.cfg.ActiveSet})
					changed = true
				}
			}
		}
	}
	var saveErr error
	if changed {
		saveErr = w.app.store.save()
	}
	w.app.store.mu.Unlock()
	return rows, saveErr
}
func hasTag(s Snapshot, t string) bool {
	for _, v := range s.Tags {
		if v == t {
			return true
		}
	}
	return false
}
func (w *worker) maintenance(ctx context.Context, low bool) (any, error) {
	if e := w.ensureRepository(ctx, false); e != nil {
		return nil, e
	}
	// Explicit sets, never all backup tags: inactive sets require confirmed retirement.
	// Group by tags keeps crash/pending snapshots away from complete snapshots.
	if w.cfg.ActiveSet != "" {
		_, e := w.rest(ctx, "forget", "--host", w.cfg.BackupHost, "--tag", w.tag()+","+w.setTag()+","+completeTag, "--group-by", "host,paths,tags", "--keep-daily", strconv.Itoa(w.cfg.Settings.KeepDaily), "--keep-weekly", strconv.Itoa(w.cfg.Settings.KeepWeekly), "--keep-monthly", strconv.Itoa(w.cfg.Settings.KeepMonthly))
		if e != nil {
			return nil, e
		}
	}
	// Pending snapshots are a separate retention group. Keep the newest pending
	// attempt only, so repeated interrupted runs cannot grow indefinitely.
	if w.cfg.ActiveSet != "" {
		if _, e := w.rest(ctx, "forget", "--host", w.cfg.BackupHost, "--tag", w.tag()+","+w.setTag()+","+pendingTag, "--group-by", "host,paths,tags", "--keep-last", "1"); e != nil {
			return nil, e
		}
	}
	repack := "1G"
	if low {
		repack = "0"
	}
	if _, e := w.rest(ctx, "prune", "--max-repack-size", repack); e != nil {
		return nil, e
	}
	if _, e := w.rest(ctx, "check"); e != nil {
		return nil, e
	}
	return map[string]any{"ok": true, "low_space": low}, nil
}
func (w *worker) retire(ctx context.Context, r OperationRequest) (any, error) {
	if r.Confirm != "DELETE_RETIRED_SNAPSHOTS" || r.SetID == w.cfg.ActiveSet {
		return nil, errors.New("Nur inaktive Quellgruppen nach ausdrücklicher Bestätigung löschen.")
	}
	found := false
	for _, s := range w.cfg.Sets {
		if s.ID == r.SetID && s.Retired && !s.Deleted {
			found = true
		}
	}
	if !found {
		return nil, errors.New("Inaktive Quellgruppe nicht gefunden.")
	}
	if e := w.ensureRepository(ctx, false); e != nil {
		return nil, e
	}
	rows, e := w.snapshots(ctx)
	if e != nil {
		return nil, e
	}
	ids := []string{}
	for _, s := range rows {
		if hasTag(s, "buddybackup-source:"+r.SetID) && hasTag(s, w.tag()) && idRE.MatchString(s.ID) {
			ids = append(ids, s.ID)
		}
	}
	for _, id := range ids {
		if _, e = w.rest(ctx, "forget", id); e != nil {
			return nil, e
		}
	}
	w.app.store.mu.Lock()
	defer w.app.store.mu.Unlock()
	for i := range w.app.store.S.Sets {
		if w.app.store.S.Sets[i].ID == r.SetID {
			w.app.store.S.Sets[i].Deleted = true
		}
	}
	return map[string]any{"deleted_snapshots": len(ids)}, w.app.store.save()
}
func (w *worker) restore(ctx context.Context, r OperationRequest) (any, error) {
	if !idRE.MatchString(r.Snapshot) {
		return nil, errors.New("Eine vollständige konkrete Snapshot-ID ist erforderlich.")
	}
	if e := w.ensureRepository(ctx, false); e != nil {
		return nil, e
	}
	rows, e := w.snapshots(ctx)
	if e != nil {
		return nil, e
	}
	found := false
	for _, s := range rows {
		if s.ID == r.Snapshot {
			found = true
		}
	}
	if !found {
		return nil, errors.New("Snapshot gehört nicht zu dieser Sicherung.")
	}
	// Validate the selection first, so a rejected one leaves no destination folder behind.
	includes, e := restoreIncludes(r.Paths)
	if e != nil {
		return nil, e
	}
	m, e := w.app.mounts()
	if e != nil {
		return nil, e
	}
	dest, e := restoreDir(w.app.restoreRoot, r.Folder, m)
	if e != nil {
		return nil, e
	}
	args := append([]string{"restore", r.Snapshot, "--verify", "--overwrite", "never", "--target", dest}, includes...)
	_, e = w.rest(ctx, args...)
	result := map[string]any{"path": dest}
	if mount, ok := exactMount(w.app.restoreRoot, m); ok {
		result["host_path"] = hostPath(mount, filepath.Base(dest))
	}
	return result, e
}

// restoreIncludes turns a file selection into restic --include flags. An empty selection restores everything.
func restoreIncludes(paths []string) ([]string, error) {
	if len(paths) > maxRestorePaths {
		return nil, errors.New("Zu viele einzelne Dateien gewählt. Bitte ganze Ordner auswählen.")
	}
	args := make([]string, 0, len(paths)*2)
	for _, p := range paths {
		if !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "\x00\n\r") {
			return nil, errors.New("Ungültiger Dateipfad in der Auswahl.")
		}
		args = append(args, "--include", escapeResticPattern(p))
	}
	return args, nil
}

// restic treats --include values as glob patterns; a literal selection must not expand.
func escapeResticPattern(p string) string {
	return strings.NewReplacer("\\", "\\\\", "*", "\\*", "?", "\\?", "[", "\\[").Replace(p)
}

const (
	maxRestorePaths = 2000
	maxFileEntries  = 20000
)

type FileEntry struct {
	Path string `json:"path"`
	Type string `json:"type"`
	Size int64  `json:"size"`
}

func (w *worker) files(ctx context.Context, r OperationRequest) (any, error) {
	if e := w.ensureRepository(ctx, false); e != nil {
		return nil, e
	}
	rows, e := w.snapshots(ctx)
	if e != nil {
		return nil, e
	}
	found := false
	for _, s := range rows {
		found = found || s.ID == r.Snapshot
	}
	if !found {
		return nil, errors.New("Snapshot gehört nicht zu dieser Sicherung.")
	}
	out, e := w.rest(ctx, "ls", "--json", r.Snapshot)
	if e != nil {
		if strings.Contains(e.Error(), "API-Limit") {
			return nil, errors.New("Diese Version enthält zu viele Dateien für die Auswahl. Bitte die ganze Version wiederherstellen.")
		}
		return nil, e
	}
	entries, truncated := parseFileList(out)
	return map[string]any{"entries": entries, "truncated": truncated}, nil
}

func parseFileList(out []byte) ([]FileEntry, bool) {
	entries := []FileEntry{}
	for _, line := range bytes.Split(out, []byte("\n")) {
		var node struct {
			StructType string `json:"struct_type"`
			Path       string `json:"path"`
			Type       string `json:"type"`
			Size       int64  `json:"size"`
		}
		if json.Unmarshal(line, &node) != nil || node.StructType != "node" {
			continue
		}
		if len(entries) == maxFileEntries {
			return entries, true
		}
		entries = append(entries, FileEntry{Path: node.Path, Type: node.Type, Size: node.Size})
	}
	return entries, false
}
func (w *worker) restoreTest(ctx context.Context) (any, error) {
	if !w.cfg.RecoveryAck {
		return nil, errors.New("Notfall-Kit zuerst bestätigen.")
	}
	if e := w.ensureRepository(ctx, false); e != nil {
		return nil, e
	}
	temp, e := os.MkdirTemp("/tmp", "buddy-test-")
	if e != nil {
		return nil, e
	}
	defer os.RemoveAll(temp)
	src := filepath.Join(temp, "probe")
	if e = os.Mkdir(src, 0700); e != nil {
		return nil, e
	}
	data := make([]byte, 64<<10)
	if _, e = rand.Read(data); e != nil {
		return nil, e
	}
	if e = os.WriteFile(filepath.Join(src, "buddybackup-test.bin"), data, 0600); e != nil {
		return nil, e
	}
	id, e := w.pendingBackup(ctx, []string{src}, "buddybackup-selftest")
	if e != nil {
		return nil, e
	}
	dst := filepath.Join(temp, "restored")
	if _, e = w.rest(ctx, "restore", id, "--verify", "--target", dst); e != nil {
		return nil, e
	}
	count := 0
	ok := false
	e = filepath.WalkDir(dst, func(p string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.Name() == "buddybackup-test.bin" && !d.IsDir() {
			count++
			b, e := os.ReadFile(p)
			if e != nil {
				return e
			}
			ok = bytes.Equal(b, data)
		}
		return nil
	})
	if e != nil {
		return nil, e
	}
	if count != 1 || !ok {
		return nil, errors.New("Wiederherstellungstest: Inhalt stimmt nicht überein.")
	}
	if _, e = w.rest(ctx, "forget", id); e != nil {
		return nil, e
	}
	return map[string]any{"ok": true, "detail": "64 KiB verschlüsselt gesichert, wiederhergestellt und bytegenau geprüft."}, nil
}
func (w *worker) execute(ctx context.Context, r OperationRequest) (any, error) {
	if w.cfg.Peer == nil {
		return nil, errors.New("Zuerst einen Freund verbinden.")
	}
	repo, user, pass, closeForwarder, e := localForwarder(w.app.network, *w.cfg.Peer)
	if e != nil {
		return nil, e
	}
	defer closeForwarder()
	w.repo, w.user, w.pass = repo, user, pass
	// Periodic checks enforce direct-only on route changes, not only at startup.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	watchDone := make(chan struct{})
	defer close(watchDone)
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-watchDone:
				return
			case <-ctx.Done():
				return
			case <-t.C:
				pctx, pc := context.WithTimeout(ctx, 12*time.Second)
				_, e := w.app.network.Verify(pctx, *w.cfg.Peer, w.cfg.Settings.DirectOnly)
				pc()
				if e != nil {
					cancel()
					return
				}
			}
		}
	}()
	switch r.Kind {
	case "backup":
		return w.backup(ctx)
	case "snapshots":
		if e = w.ensureRepository(ctx, false); e != nil {
			return nil, e
		}
		return w.snapshots(ctx)
	case "check":
		if e = w.ensureRepository(ctx, false); e != nil {
			return nil, e
		}
		args := []string{"check"}
		if r.ReadData {
			args = append(args, "--read-data")
		}
		_, e = w.rest(ctx, args...)
		return map[string]any{"ok": e == nil}, e
	case "maintenance":
		return w.maintenance(ctx, r.LowSpace)
	case "restore":
		return w.restore(ctx, r)
	case "files":
		return w.files(ctx, r)
	case "restore-test":
		return w.restoreTest(ctx)
	case "retire":
		return w.retire(ctx, r)
	case "unlock":
		if r.Confirm != "UNLOCK_STALE_LOCKS" {
			return nil, errors.New("Entsperren ausdrücklich bestätigen.")
		}
		if e = w.ensureRepository(ctx, false); e != nil {
			return nil, e
		}
		_, e = w.rest(ctx, "unlock")
		return map[string]any{"ok": e == nil}, e
	}
	return nil, errors.New("Unbekannte Operation.")
}
func copyState(s State) State {
	b, _ := json.Marshal(s)
	var c State
	_ = json.Unmarshal(b, &c)
	return c
}
func publicError(e error) string {
	if e == nil {
		return ""
	}
	s := safeMessage(e.Error())
	if len(s) > 1500 {
		s = s[:1500]
	}
	return strings.TrimSpace(s)
}
