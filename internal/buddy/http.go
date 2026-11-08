package buddy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": apiError{code, message}})
}
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		fail(w, 400, "invalid_request", "JSON-Anfrage erforderlich.")
		return false
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		fail(w, 400, "invalid_request", "Ungültige JSON-Anfrage oder unbekannte Felder.")
		return false
	}
	if d.Decode(new(any)) != io.EOF {
		fail(w, 400, "invalid_request", "Nur ein JSON-Objekt ist erlaubt.")
		return false
	}
	return true
}
func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.store.mu.Lock()
	if a.stopping {
		a.store.mu.Unlock()
		fail(w, 503, "conflict", "BuddyBackup wird beendet.")
		return
	}
	a.httpWG.Add(1)
	a.store.mu.Unlock()
	defer a.httpWG.Done()

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'")
	if !a.validUIRequest(r) {
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(403)
			_, _ = io.WriteString(w, "Bitte BuddyBackup ueber die IP-Adresse des NAS oeffnen, zum Beispiel http://192.168.1.10:8080\nFuer einen Namen statt der IP in der App-Konfiguration BUDDY_UI_HOST setzen.\n")
			return
		}
		fail(w, 403, "csrf", "Nur der lokale LAN-Zugang ist erlaubt. Bei DNS-Namen BUDDY_UI_HOST konfigurieren.")
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/api/") {
		if r.Method != "GET" && r.Method != "HEAD" {
			fail(w, 405, "invalid_request", "Methode nicht erlaubt.")
			return
		}
		a.web.ServeHTTP(w, r)
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/api/v1/") {
		fail(w, 404, "not_found", "Endpunkt nicht gefunden.")
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/")
	s, id := a.getSession(w, r, path == "auth")
	if r.Method == http.MethodPost {
		if !a.checkOrigin(r) || !csrfOK(s, r) {
			fail(w, 403, "csrf", "Sicherheitsprüfung fehlgeschlagen. Bitte die Seite neu laden.")
			return
		}
	} else if r.Method != http.MethodGet {
		fail(w, 405, "invalid_request", "Methode nicht erlaubt.")
		return
	}
	if r.Method == "GET" && path == "auth" {
		a.store.mu.Lock()
		initialized := a.store.S.AdminHash != ""
		a.store.mu.Unlock()
		writeJSON(w, 200, map[string]any{"initialized": initialized, "csrf_token": s.CSRF, "authenticated": s.Authed})
		return
	}
	if r.Method == "POST" && path == "setup" {
		a.setup(w, r, id)
		return
	}
	if r.Method == "POST" && path == "login" {
		a.login(w, r, id)
		return
	}
	if s == nil || !s.Authed {
		fail(w, 401, "unauthorized", "Bitte anmelden.")
		return
	}
	if r.Method == "POST" && path == "logout" {
		var v struct{}
		if !decode(w, r, &v) {
			return
		}
		a.setAuth(w, r, id, false)
		writeJSON(w, 200, map[string]bool{"ok": true})
		return
	}
	if strings.HasPrefix(path, "zfs/") {
		a.zfsHTTP(w, r, path)
		return
	}
	if r.Method == "GET" {
		switch path {
		case "status":
			a.status(w, r)
			return
		case "sources":
			rows, e := a.mounts()
			if e != nil {
				fail(w, 500, "internal", "Mounts konnten nicht gelesen werden.")
				return
			}
			out := []map[string]any{}
			for _, m := range rows {
				if validSourcePath(m.Path) {
					_, e := captureManifest([]string{m.Path}, rows)
					out = append(out, map[string]any{"path": m.Path, "valid": e == nil, "message": publicError(e)})
				} else if filepath.Dir(m.Path) == "/sources" {
					out = append(out, map[string]any{"path": m.Path, "valid": false, "message": "Name nicht erlaubt, nur Buchstaben, Ziffern und Bindestriche."})
				}
			}
			writeJSON(w, 200, map[string]any{"sources": out, "warnings": datasetRootWarnings(rows)})
			return
		case "operations/current":
			a.store.mu.Lock()
			defer a.store.mu.Unlock()
			writeJSON(w, 200, a.op)
			return
		case "source-sets":
			a.store.mu.Lock()
			defer a.store.mu.Unlock()
			sets := a.store.S.Sets
			if sets == nil {
				sets = []SourceSet{}
			}
			writeJSON(w, 200, map[string]any{"source_sets": sets})
			return
		case "invitation":
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()
			n, e := a.network.Status(ctx)
			if e != nil || !n.Ready {
				fail(w, 409, "conflict", "Zuerst Tailscale verbinden.")
				return
			}
			a.store.mu.Lock()
			defer a.store.mu.Unlock()
			st := a.store.S
			i := Invitation{1, st.Name, n.IP, n.NodeID, BackupPort, st.ReceiverUser, st.ReceiverPassword}
			writeJSON(w, 200, map[string]any{"invitation": i, "fingerprint": fingerprint(i)})
			return
		}
		fail(w, 404, "not_found", "Endpunkt nicht gefunden.")
		return
	}
	switch path {
	case "peer/check":
		var v struct{}
		if !decode(w, r, &v) {
			return
		}
		a.store.mu.Lock()
		peer := a.store.S.Peer
		a.store.mu.Unlock()
		if peer == nil {
			fail(w, 409, "conflict", "Zuerst einen Freund verbinden.")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		route, e := a.network.Verify(ctx, *peer, false)
		writeJSON(w, 200, map[string]any{"reachable": e == nil, "route": route, "message": publicError(e)})
		return
	case "password":
		var v struct {
			Old string `json:"old_password"`
			New string `json:"new_password"`
		}
		if !decode(w, r, &v) {
			return
		}
		if !a.allowLogin(r) {
			fail(w, 429, "rate_limited", "Zu viele Versuche. In 15 Minuten erneut versuchen.")
			return
		}
		a.store.mu.Lock()
		current := a.store.S.AdminHash
		a.store.mu.Unlock()
		if bcrypt.CompareHashAndPassword([]byte(current), []byte(v.Old)) != nil {
			fail(w, 409, "conflict", "Das bisherige Passwort stimmt nicht.")
			return
		}
		hash, e := passwordHash(v.New)
		if e != nil {
			fail(w, 400, "invalid_request", publicError(e))
			return
		}
		a.mutate(w, func() error { a.store.S.AdminHash = hash; return a.store.save() })
		return
	case "quota":
		var v struct {
			Quota int64 `json:"quota_bytes"`
		}
		if !decode(w, r, &v) {
			return
		}
		if v.Quota < 1<<20 || v.Quota > 1<<60 {
			fail(w, 400, "invalid_request", "Speicherlimit ab 1 MiB erforderlich.")
			return
		}
		a.mutate(w, func() error {
			a.store.S.Quota = v.Quota
			if q, ok := a.receiver.(*quotaReceiver); ok {
				if e := q.setQuota(v.Quota); e != nil {
					return e
				}
			}
			return a.store.save()
		})
		return
	case "network/login":
		var v struct{}
		if !decode(w, r, &v) {
			return
		}
		a.store.mu.Lock()
		e := a.startNetwork()
		a.store.mu.Unlock()
		if e == nil {
			ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
			defer cancel()
			e = a.network.Login(ctx)
		}
		respond(w, e)
		return
	case "peer":
		var v struct {
			Invitation  Invitation `json:"invitation"`
			Fingerprint string     `json:"fingerprint"`
			Replace     bool       `json:"replace"`
		}
		if !decode(w, r, &v) {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		n, e := a.network.Status(ctx)
		if e != nil {
			respond(w, e)
			return
		}
		if v.Invitation.NodeID == n.NodeID {
			fail(w, 400, "invalid_request", "Das eigene Gerät ist kein Backupziel.")
			return
		}
		a.mutate(w, func() error { return a.store.pair(v.Invitation, v.Fingerprint, v.Replace) })
		return
	case "settings":
		var v Settings
		if !decode(w, r, &v) {
			return
		}
		mounts, e := a.mounts()
		if e != nil {
			respond(w, e)
			return
		}
		a.mutate(w, func() error { return a.store.configure(v, mounts) })
		return
	case "recovery/export":
		var v struct{}
		if !decode(w, r, &v) {
			return
		}
		a.store.mu.Lock()
		defer a.store.mu.Unlock()
		out, e := a.store.exportRecovery()
		if e != nil {
			respond(w, e)
			return
		}
		w.Header().Set("Content-Disposition", "attachment; filename=buddybackup-notfall-kit.json")
		writeJSON(w, 200, out)
		return
	case "recovery/ack":
		var v struct {
			Fingerprint           string `json:"fingerprint"`
			ConnectionFingerprint string `json:"connection_fingerprint"`
			Confirm               string `json:"confirm"`
		}
		if !decode(w, r, &v) {
			return
		}
		a.mutate(w, func() error { return a.store.ackRecovery(v.Fingerprint, v.ConnectionFingerprint, v.Confirm) })
		return
	case "recovery/import":
		var v struct {
			Kit         Kit    `json:"kit"`
			Fingerprint string `json:"fingerprint"`
			Confirm     string `json:"confirm"`
		}
		if !decode(w, r, &v) {
			return
		}
		a.mutate(w, func() error { return a.store.importRecovery(v.Kit, v.Fingerprint, v.Confirm) })
		return
	case "operations":
		var v OperationRequest
		if !decode(w, r, &v) {
			return
		}
		if v.Kind == "retire" {
			fail(w, 400, "invalid_request", "Quellgruppen über den bestätigten Endpunkt löschen.")
			return
		}
		op, e := a.startOperation(v, false)
		if e != nil {
			respond(w, e)
			return
		}
		writeJSON(w, 202, op)
		return
	case "source-sets/retire":
		var v struct {
			ID      string `json:"id"`
			Confirm string `json:"confirm"`
		}
		if !decode(w, r, &v) {
			return
		}
		op, e := a.startOperation(OperationRequest{Kind: "retire", SetID: v.ID, Confirm: v.Confirm}, false)
		if e != nil {
			respond(w, e)
			return
		}
		writeJSON(w, 202, op)
		return
	case "operations/cancel":
		var v struct{}
		if !decode(w, r, &v) {
			return
		}
		a.store.mu.Lock()
		if a.cancel != nil {
			a.cancel()
		}
		a.store.mu.Unlock()
		writeJSON(w, 200, map[string]bool{"ok": true})
		return
	}
	fail(w, 404, "not_found", "Endpunkt nicht gefunden.")
}
func respond(w http.ResponseWriter, e error) {
	if e == nil {
		writeJSON(w, 200, map[string]bool{"ok": true})
		return
	}
	if errors.Is(e, ErrBusy) {
		fail(w, 409, "conflict", e.Error())
	} else {
		fail(w, 409, "conflict", publicError(e))
	}
}
func (a *App) mutate(w http.ResponseWriter, f func() error) {
	a.store.mu.Lock()
	defer a.store.mu.Unlock()
	if a.busy() || a.stopping {
		respond(w, ErrBusy)
		return
	}
	old := copyState(a.store.S)
	e := f()
	if e != nil {
		a.store.S = old
	}
	respond(w, e)
}
func (a *App) setup(w http.ResponseWriter, r *http.Request, id string) {
	var v struct {
		Name     string `json:"name"`
		Password string `json:"password"`
		Quota    int64  `json:"quota_bytes"`
	}
	if !decode(w, r, &v) {
		return
	}
	if !nameRE.MatchString(v.Name) || v.Quota < 1<<20 || v.Quota > 1<<60 {
		fail(w, 400, "invalid_request", "Gültiger Name und Speicherlimit ab 1 MiB erforderlich.")
		return
	}
	if !a.allowLogin(r) {
		fail(w, 429, "rate_limited", "Zu viele Versuche. In 15 Minuten erneut versuchen.")
		return
	}
	select {
	case a.loginGate <- struct{}{}:
		defer func() { <-a.loginGate }()
	default:
		fail(w, 429, "rate_limited", "Anmeldung ausgelastet.")
		return
	}
	hash, e := passwordHash(v.Password)
	if e != nil {
		fail(w, 400, "invalid_request", publicError(e))
		return
	}
	recvPass := secret()
	recvHash, e := passwordHash(recvPass)
	if e != nil {
		respond(w, e)
		return
	}
	a.store.mu.Lock()
	defer a.store.mu.Unlock()
	if a.store.S.AdminHash != "" {
		fail(w, 409, "conflict", "Bereits eingerichtet. Bitte anmelden.")
		return
	}
	old := copyState(a.store.S)
	a.store.S.Name = v.Name
	a.store.S.AdminHash = hash
	a.store.S.Quota = v.Quota
	a.store.S.ReceiverUser = "buddy-" + randomID()[:16]
	a.store.S.ReceiverPassword = recvPass
	a.store.S.ReceiverHash = recvHash
	if e = a.store.save(); e != nil {
		a.store.S = old
		fail(w, 500, "internal", "Einrichtung konnte nicht gespeichert werden.")
		return
	}
	a.setAuth(w, r, id, true)
	if e = a.startNetwork(); e != nil {
		writeJSON(w, 200, map[string]any{"ok": true, "warning": "Tailscale konnte nicht gestartet werden. Netzwerkanmeldung erneut versuchen."})
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func (a *App) login(w http.ResponseWriter, r *http.Request, id string) {
	var v struct {
		Password string `json:"password"`
	}
	if !decode(w, r, &v) {
		return
	}
	if !a.allowLogin(r) {
		fail(w, 429, "rate_limited", "Zu viele Versuche. In 15 Minuten erneut versuchen.")
		return
	}
	select {
	case a.loginGate <- struct{}{}:
		defer func() { <-a.loginGate }()
	default:
		fail(w, 429, "rate_limited", "Anmeldung ausgelastet.")
		return
	}
	a.store.mu.Lock()
	hash := a.store.S.AdminHash
	a.store.mu.Unlock()
	if hash == "" || bcrypt.CompareHashAndPassword([]byte(hash), []byte(v.Password)) != nil {
		fail(w, 401, "unauthorized", "Anmeldung fehlgeschlagen.")
		return
	}
	a.setAuth(w, r, id, true)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

const snapshotInstructions = "In TrueNAS eine regelmäßige ZFS-Snapshot-Aufgabe für den nach /data gemounteten Datensatz anlegen und Aufbewahrung sowie freien Poolplatz prüfen. BuddyBackup kann ohne TrueNAS-Zugang nicht erkennen, ob diese Aufgabe existiert. Snapshots schützen auch vor Löschungen durch den Freund; sie belegen zusätzlichen Platz außerhalb des rest-server-Limits."

func (a *App) status(w http.ResponseWriter, r *http.Request) {
	a.store.mu.Lock()
	s := copyState(a.store.S)
	var op *Operation
	if a.op != nil {
		b, _ := json.Marshal(a.op)
		op = &Operation{}
		_ = json.Unmarshal(b, op)
	}
	a.store.mu.Unlock()
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	n, e := a.network.Status(ctx)
	warnings := append([]string{}, n.Warnings...)
	if rows, err := a.mounts(); err == nil {
		warnings = append(warnings, datasetRootWarnings(rows)...)
	}
	if e != nil {
		warnings = append(warnings, publicError(e))
	}
	if s.LastBackupError != "" {
		warnings = append(warnings, s.LastBackupError)
	}
	if !n.Ready && s.Peer != nil {
		warnings = append(warnings, "Tailscale ist nicht verbunden. Backups pausieren, bis die Verbindung wieder steht.")
	}
	if len(s.Settings.Sources) > 0 {
		m, e := a.mounts()
		if e == nil {
			e = verifyManifest(s.Settings.Sources, s.Manifest, m)
		}
		if e != nil {
			warnings = append(warnings, publicError(e))
		}
	}
	baseline := s.LastSuccess
	if baseline.IsZero() {
		baseline = s.AcknowledgedAt
	}
	if s.RecoveryAck && !baseline.IsZero() && time.Since(baseline) > time.Duration(s.Settings.StaleHours)*time.Hour {
		warnings = append(warnings, "Seit längerem keine vollständige Sicherung. Letzten Fehler prüfen.")
	}
	wizard := "ready"
	switch {
	case s.AdminHash == "":
		wizard = "setup"
	case !n.Ready && s.Peer == nil:
		wizard = "network"
	case s.Peer == nil:
		wizard = "peer"
	case s.RecoveryOnly:
		wizard = "ready"
	case len(s.Settings.Sources) == 0:
		wizard = "sources"
	case !s.RecoveryAck:
		wizard = "recovery"
	}
	fp := ""
	var peer any
	if s.Peer != nil {
		fp = fingerprint(*s.Peer)
		peer = map[string]string{"name": s.Peer.Name, "ip": s.Peer.IP, "node_id": s.Peer.NodeID}
	}
	used, free, usageErr := a.receiverUsage()
	if usageErr != nil {
		warnings = append(warnings, "Empfangsbelegung konnte nicht bestimmt werden.")
	} else if s.Quota > 0 && used >= s.Quota*85/100 {
		warnings = append(warnings, "Empfangsbereich zu mindestens 85 % belegt. Speicherlimit und freien Poolplatz prüfen.")
	}
	if usageErr == nil && free < 64<<20 {
		warnings = append(warnings, "Auf dem App-Dateisystem ist weniger als 64 MiB frei. Platz für Sperren und Wartung freigeben.")
	}
	a.store.mu.Lock()
	zfs := a.zfsStatusLocked()
	a.store.mu.Unlock()
	warnings = append(warnings, zfs["warnings"].([]string)...)
	settings := s.Settings // Never emit repository encryption key or HTTP credentials here.
	writeJSON(w, 200, map[string]any{"zfs": zfs, "wizard": wizard, "name": s.Name, "network": n, "peer": peer, "peer_fingerprint": fp, "recovery_only": s.RecoveryOnly, "recovery_acknowledged": s.RecoveryAck, "settings": settings, "operation": op, "warnings": warnings, "next_run": s.NextRun, "next_maintenance": s.NextMaintenance, "last_maintenance": s.LastMaintenance, "last_success": s.LastSuccess, "receiver": map[string]any{"quota_bytes": s.Quota, "used_bytes": used, "filesystem_free_bytes": free}, "snapshot_instructions": snapshotInstructions})
}
