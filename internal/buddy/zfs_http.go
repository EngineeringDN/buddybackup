package buddy

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"time"
)

// Called only after the standard UI authentication/CSRF gate.
func (a *App) zfsHTTP(w http.ResponseWriter, r *http.Request, path string) {
	if r.Method == "GET" {
		if path == "zfs/status" {
			a.store.mu.Lock()
			defer a.store.mu.Unlock()
			writeJSON(w, 200, a.zfsStatusLocked())
			return
		}
		if path == "zfs/commands/sender" {
			if e := a.zfsSync(r.Context()); e != nil {
				respond(w, e)
				return
			}
			peer := a.zfsPeer()
			if peer == nil {
				respond(w, errors.New("Freund fehlt."))
				return
			}
			a.store.mu.Lock()
			key := a.store.S.ZFS.HostKey
			a.store.mu.Unlock()
			if key == "" {
				var e error
				key, e = a.captureHostKey(r.Context(), *peer)
				if e != nil {
					respond(w, e)
					return
				}
			}
			a.store.mu.Lock()
			defer a.store.mu.Unlock()
			if a.store.S.Peer == nil || *a.store.S.Peer != *peer {
				respond(w, ErrBusy)
				return
			}
			if a.store.S.ZFS.HostKey != "" && a.store.S.ZFS.HostKey != key {
				respond(w, errors.New("SSH-Hostschlüssel hat sich geändert."))
				return
			}
			a.store.S.ZFS.HostKey = key
			if e := a.store.save(); e != nil {
				respond(w, e)
				return
			}
			a.zfsCommandResponse(w, "sender")
			return
		}
		for _, side := range []string{"receiver", "remove-receiver", "remove-sender"} {
			if path == "zfs/commands/"+side {
				a.store.mu.Lock()
				defer a.store.mu.Unlock()
				a.zfsCommandResponse(w, side)
				return
			}
		}
		fail(w, 404, "not_found", "ZFS-Endpunkt nicht gefunden.")
		return
	}
	if r.Method != "POST" {
		fail(w, 405, "method_not_allowed", "POST erforderlich.")
		return
	}
	switch path {
	case "zfs/rescue/export", "zfs/rescue/ack", "zfs/rescue/import", "zfs/rescue/close", "zfs/peer/repin":
		a.zfsRescueHTTP(w, r, path)
		return
	case "zfs/receive":
		var v ZFSReceive
		if !decode(w, r, &v) {
			return
		}
		if v.Enabled && (v.QuotaGiB < 1 || v.QuotaGiB > 1048576) {
			respond(w, errors.New("ZFS-Speicherlimit: 1 bis 1048576 GiB."))
			return
		}
		a.zfsMutate(w, func() error {
			if v.Enabled && a.store.S.Peer == nil {
				return errors.New("Zuerst einen Freund verbinden.")
			}
			a.store.S.ZFS.Receive = v
			return nil
		})
		return
	case "zfs/offer":
		var v struct {
			Datasets      []string `json:"datasets"`
			Hour          int      `json:"hour"`
			RetentionDays int      `json:"retention_days"`
		}
		if !decode(w, r, &v) {
			return
		}
		a.store.mu.Lock()
		if a.store.S.Peer == nil || a.busy() || a.stopping || a.store.S.ZFS.Rescue != nil {
			a.store.mu.Unlock()
			respond(w, ErrBusy)
			return
		}
		o := ZFSOffer{ID: randomID(), Name: a.store.S.Name, Datasets: v.Datasets, Hour: v.Hour, RetentionDays: v.RetentionDays, Created: time.Now().UTC()}
		previous := copyState(a.store.S)
		old := a.store.S.ZFS.Outgoing
		if old != nil {
			o.ID = old.ID
			o.Created = old.Created
			o.PublicKey = old.PublicKey
		} else {
			priv, pub, e := zfsKey()
			if e != nil {
				a.store.mu.Unlock()
				respond(w, e)
				return
			}
			o.PublicKey = pub
			a.store.S.ZFS.PrivateKey = priv
		}
		if e := validateOffer(o); e != nil {
			if old == nil {
				a.store.S.ZFS.PrivateKey = ""
			}
			a.store.mu.Unlock()
			respond(w, e)
			return
		}
		if old != nil && fingerprint(old) != fingerprint(o) {
			a.store.mu.Unlock()
			respond(w, errors.New("ZFS-Auftrag zuerst entfernen und zurücksetzen."))
			return
		}
		a.store.S.ZFS.Outgoing = &o
		e := a.zfsCommit(previous)
		a.store.mu.Unlock()
		if e != nil {
			respond(w, e)
			return
		}
		var out ZFSPeerStatus
		e = a.zfsRequest(r.Context(), "POST", "offer", o, &out)
		if e == nil {
			e = a.zfsSync(r.Context())
		}
		respond(w, e)
		return
	case "zfs/sync":
		var v struct{}
		if !decode(w, r, &v) {
			return
		}
		respond(w, a.zfsSync(r.Context()))
		return
	case "zfs/confirm", "zfs/reset":
		var v struct {
			Side    string `json:"side"`
			ID      string `json:"offer_id"`
			Confirm string `json:"confirm,omitempty"`
		}
		if !decode(w, r, &v) {
			return
		}
		a.zfsMutate(w, func() error {
			z := &a.store.S.ZFS
			o := z.Outgoing
			if v.Side == "receiver" {
				o = z.Incoming
			} else if v.Side != "sender" {
				return errors.New("Ungültige ZFS-Seite.")
			}
			if o == nil || o.ID != v.ID {
				return errors.New("ZFS-Angebot stimmt nicht überein.")
			}
			if path == "zfs/reset" {
				if _, e := os.Lstat(a.zfsFile(o.ID, v.Side, "-complete.json")); !os.IsNotExist(e) {
					return errors.New("ZFS-Abschlussmarker existiert noch oder ist nicht prüfbar. Zuerst auf dem NAS erfolgreich entfernen.")
				}
				if v.Confirm != "REMOVED_ON_NAS" {
					return errors.New("Entfernung auf dem NAS bestätigen.")
				}
				if v.Side == "receiver" {
					z.Incoming = nil
					z.Receive.Enabled = false
				} else {
					z.Outgoing = nil
					z.PrivateKey = ""
					z.HostKey = ""
					z.PeerStatus = ZFSPeerStatus{}
					z.SenderComplete = false
					z.RescueAck = false
					z.RescueExport = ""
				}

			} else {
				if !a.zfsMarker(o.ID, v.Side) {
					return errors.New("TrueNAS-Abschlussmarker fehlt. Shell-Befehl erfolgreich ausführen.")
				}
				if v.Side == "sender" {
					if !z.SenderComplete {
						k, e := a.zfsRescue()
						if e != nil {
							return e
						}
						if fingerprint(k) != z.RescueExport {
							return errors.New("ZFS-Rettungsdatei ist nicht mehr aktuell; erneut exportieren und bestätigen.")
						}
					}
					if !z.RescueAck {
						return errors.New("ZFS-Rettungsdatei exportieren und Offline-Sicherung bestätigen.")
					}
					z.PrivateKey = ""
					z.SenderComplete = true
				}
			}
			return nil
		})
		return
	}
	fail(w, 404, "not_found", "ZFS-Endpunkt nicht gefunden.")
}
func (a *App) zfsCommandResponse(w http.ResponseWriter, side string) {
	cmd, e := a.zfsCommand(side)
	if e != nil {
		respond(w, e)
		return
	}
	writeJSON(w, 200, map[string]any{"command": cmd, "sensitive": side == "sender", "zfs_host_sha256": zfsHostSHA256(), "root_trust_warning": zfsRootTrustWarning})
}
func (a *App) zfsTick() {
	a.store.mu.Lock()
	active := a.store.S.ZFS.Outgoing != nil
	a.store.mu.Unlock()
	if active {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		_ = a.zfsSync(ctx)
		cancel()
	}
	a.store.mu.Lock()
	status := a.zfsStatusLocked()
	b, _ := json.Marshal(status["warnings"])
	warn := string(b) != "[]"
	z := &a.store.S.ZFS
	notify := warn && time.Since(z.LastNotice) > 24*time.Hour
	url := a.store.S.Settings.NtfyURL
	if notify {
		z.LastNotice = time.Now()
		_ = a.store.save()
	}
	a.store.mu.Unlock()
	if notify {
		a.notify(url, "BuddyBackup: ZFS-Warnung oder Sicherheitswarnung. Lokalen Status prüfen.")
	}
}

// Persist before exposing listeners; restore both state and listeners on failure.
// Caller holds store.mu. An unchanged confirmation never interrupts SSH streams.
func (a *App) zfsCommit(old State) error {
	changed := old.ZFS.Receive.Enabled != a.store.S.ZFS.Receive.Enabled || (old.ZFS.Outgoing == nil && old.ZFS.Rescue == nil) != (a.store.S.ZFS.Outgoing == nil && a.store.S.ZFS.Rescue == nil) || (old.Peer == nil) != (a.store.S.Peer == nil) || (old.Peer != nil && a.store.S.Peer != nil && *old.Peer != *a.store.S.Peer)
	e := a.store.save()
	if e == nil && changed {
		e = a.configureZFS()
	}
	if e != nil {
		a.store.S = old
		_ = a.store.save()
		if changed {
			_ = a.configureZFS()
		}
	}
	return e
}
func (a *App) zfsMutate(w http.ResponseWriter, f func() error) {
	a.store.mu.Lock()
	defer a.store.mu.Unlock()
	if a.busy() || a.stopping {
		respond(w, ErrBusy)
		return
	}
	old := copyState(a.store.S)
	e := f()
	if e == nil {
		e = a.zfsCommit(old)
	} else {
		a.store.S = old
	}
	respond(w, e)
}

func (a *App) zfsRescueHTTP(w http.ResponseWriter, r *http.Request, path string) {
	if r.Method != "POST" {
		fail(w, 405, "method_not_allowed", "POST erforderlich.")
		return
	}
	switch path {
	case "zfs/rescue/export":
		var v struct{}
		if !decode(w, r, &v) {
			return
		}
		a.store.mu.Lock()
		defer a.store.mu.Unlock()
		if a.busy() || a.stopping {
			respond(w, ErrBusy)
			return
		}
		k, e := a.zfsRescue()
		if e != nil {
			respond(w, e)
			return
		}
		old := copyState(a.store.S)
		fp := fingerprint(k)
		a.store.S.ZFS.RescueExport = fp
		// A repeat download returns the same rescue; acknowledgement stays tied to it.
		if old.ZFS.RescueExport != fp {
			a.store.S.ZFS.RescueAck = false
		}
		if e = a.zfsCommit(old); e != nil {
			respond(w, e)
			return
		}
		writeJSON(w, 200, map[string]any{"rescue": k, "fingerprint": fp})
	case "zfs/rescue/ack":
		var v struct {
			Fingerprint string `json:"fingerprint"`
			Confirm     string `json:"confirm"`
		}
		if !decode(w, r, &v) {
			return
		}
		a.zfsMutate(w, func() error {
			k, e := a.zfsRescue()
			if e != nil {
				return e
			}
			if v.Confirm != "SAVED_OFFLINE" || v.Fingerprint != fingerprint(k) || v.Fingerprint != a.store.S.ZFS.RescueExport {
				return errors.New("Genau die exportierte ZFS-Rettungsdatei offline sichern und bestätigen.")
			}
			a.store.S.ZFS.RescueAck = true
			return nil
		})
	case "zfs/rescue/import":
		var v struct {
			Rescue      ZFSRescue `json:"rescue"`
			Fingerprint string    `json:"fingerprint"`
			Confirm     string    `json:"confirm"`
		}
		if !decode(w, r, &v) {
			return
		}
		a.zfsMutate(w, func() error {
			if v.Confirm != "IMPORT_ZFS_RESCUE" || v.Fingerprint != fingerprint(v.Rescue) {
				return errors.New("ZFS-Rettungsdatei und Fingerabdruck bestätigen.")
			}
			if e := validateZFSRescue(v.Rescue); e != nil {
				return e
			}
			z := &a.store.S.ZFS
			if z.Outgoing != nil || z.Incoming != nil || z.Receive.Enabled || z.Rescue != nil {
				return errors.New("ZFS ist bereits konfiguriert.")
			}
			if a.store.S.Peer != nil && *a.store.S.Peer != v.Rescue.Peer {
				return errors.New("Verbundener Freund stimmt nicht mit der Rettungsdatei überein.")
			}
			p := v.Rescue.Peer
			a.store.S.Peer = &p
			z.Rescue = &v.Rescue
			// Restic must never initialize a new repository due to a ZFS-only import.
			a.store.S.AllowInit = false
			a.store.S.RecoveryOnly = true
			return nil
		})
	case "zfs/rescue/close":
		var v struct {
			Confirm string `json:"confirm"`
		}
		if !decode(w, r, &v) {
			return
		}
		a.zfsMutate(w, func() error {
			if v.Confirm != "CLOSE_ZFS_RESCUE" {
				return errors.New("Schließen des Rettungstunnels bestätigen.")
			}
			a.store.S.ZFS.Rescue = nil
			return nil
		})
	case "zfs/peer/repin":
		var v struct {
			Invitation     Invitation `json:"invitation"`
			Fingerprint    string     `json:"fingerprint"`
			PreviousNodeID string     `json:"previous_node_id"`
			Confirm        string     `json:"confirm"`
		}
		if !decode(w, r, &v) {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		status, e := a.network.Status(ctx)
		if e != nil {
			respond(w, e)
			return
		}
		a.zfsMutate(w, func() error {
			old := a.store.S.Peer
			if old == nil || v.PreviousNodeID != old.NodeID || v.Confirm != "REPIN_REPLACED_ZFS_PEER" || fingerprint(v.Invitation) != v.Fingerprint {
				return errors.New("Ersetztes Freundesgerät und beide Fingerabdrücke ausdrücklich bestätigen.")
			}
			if e := validateInvitation(v.Invitation); e != nil {
				return e
			}
			if v.Invitation.NodeID == old.NodeID || v.Invitation.NodeID == status.NodeID || v.Invitation.Name != old.Name {
				return errors.New("Ungültiges Ersatzgerät.")
			}
			if a.store.S.ZFS.Incoming == nil || a.store.S.ZFS.Rescue != nil {
				return errors.New("Neu-Pinnen ist nur für bestehenden ZFS-Empfang erlaubt.")
			}
			// Only control-plane node/address change. Keep HTTP credentials, account,
			// offer, ZFS data and Restic identity. Lost opposite-direction config is separate.
			p := *old
			p.IP = v.Invitation.IP
			p.NodeID = v.Invitation.NodeID
			a.store.S.Peer = &p
			return nil
		})
	}
}
