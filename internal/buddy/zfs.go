package buddy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

type ZFSReceive struct {
	Enabled  bool  `json:"enabled"`
	QuotaGiB int64 `json:"quota_gib"`
}
type ZFSOffer struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Datasets      []string  `json:"datasets"`
	Hour          int       `json:"hour"`
	RetentionDays int       `json:"retention_days"`
	PublicKey     string    `json:"public_key"`
	Created       time.Time `json:"created"`
}
type ZFSDataset struct {
	Name         string    `json:"name"`
	Snapshot     string    `json:"snapshot"`
	SnapshotTime time.Time `json:"snapshot_time"`
	KeyStatus    string    `json:"keystatus"`
	Used         int64     `json:"used_bytes"`
}
type ZFSReport struct {
	Updated  time.Time    `json:"updated"`
	Datasets []ZFSDataset `json:"datasets"`
}
type ZFSPeerStatus struct {
	OfferID  string    `json:"offer_id"`
	Ready    bool      `json:"ready"`
	Username string    `json:"username"`
	Parent   string    `json:"parent"`
	Report   ZFSReport `json:"report"`
}
type ZFSProbe struct {
	Updated time.Time `json:"updated"`
	State   string    `json:"state"`
	Message string    `json:"message"`
}

// Sender reports are produced by the root cron runner, never by the peer.
type ZFSSenderDataset struct {
	Name             string     `json:"name"`
	State            string     `json:"state"`
	LastAttempt      *time.Time `json:"last_attempt"`
	LastSuccess      *time.Time `json:"last_success"`
	LastSentSnapshot string     `json:"last_sent_snapshot"`
	Error            string     `json:"error"`
	SecurityWarning  string     `json:"security_warning"`
	Bytes            *uint64    `json:"bytes"`
}
type ZFSSenderReport struct {
	Updated   time.Time          `json:"updated"`
	Scheduler string             `json:"scheduler"`
	Datasets  []ZFSSenderDataset `json:"datasets"`
}
type ZFSState struct {
	Receive        ZFSReceive    `json:"receive"`
	Incoming       *ZFSOffer     `json:"incoming"`
	Outgoing       *ZFSOffer     `json:"outgoing"`
	PrivateKey     string        `json:"private_key,omitempty"`
	HostKey        string        `json:"host_key,omitempty"`
	PeerStatus     ZFSPeerStatus `json:"peer_status"`
	SenderComplete bool          `json:"sender_complete"`
	LastNotice     time.Time     `json:"last_notice"`
	RescueExport   string        `json:"rescue_export,omitempty"`
	RescueAck      bool          `json:"rescue_acknowledged"`
	Rescue         *ZFSRescue    `json:"rescue,omitempty"`
}

var datasetPartRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)
var offerIDRE = regexp.MustCompile(`^[a-f0-9]{32}$`)

func validDataset(s string) bool {
	if len(s) == 0 || len(s) > 200 {
		return false
	}
	for _, p := range strings.Split(s, "/") {
		if !datasetPartRE.MatchString(p) || p == "." || p == ".." {
			return false
		}
	}
	return true
}
func validateOffer(o ZFSOffer) error {
	if !offerIDRE.MatchString(o.ID) || !nameRE.MatchString(o.Name) || len(o.Datasets) < 1 || len(o.Datasets) > 32 || o.Hour < 0 || o.Hour > 23 || o.RetentionDays < 1 || o.RetentionDays > 3650 || o.Created.IsZero() {
		return errors.New("Ungültiges ZFS-Angebot.")
	}
	for i, d := range o.Datasets {
		if !validDataset(d) {
			return errors.New("Ungültiger ZFS-Datasetname.")
		}
		for j, e := range o.Datasets {
			if i != j && (d == e || strings.HasPrefix(d, e+"/")) {
				return errors.New("ZFS-Datasets dürfen sich nicht überlappen.")
			}
		}
	}
	key, _, _, rest, e := ssh.ParseAuthorizedKey([]byte(o.PublicKey))
	if e != nil || len(rest) > 0 || key.Type() != ssh.KeyAlgoED25519 || strings.ContainsAny(o.PublicKey, "\r\n") || o.PublicKey != strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(key)), "\n") {
		return errors.New("Ungültiger öffentlicher SSH-Schlüssel.")
	}
	return nil
}
func zfsKey() (string, string, error) {
	pub, priv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return "", "", e
	}
	p, e := ssh.MarshalPrivateKey(priv, "")
	if e != nil {
		return "", "", e
	}
	k, e := ssh.NewPublicKey(pub)
	if e != nil {
		return "", "", e
	}
	return string(pem.EncodeToMemory(p)), strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(k)), "\n"), nil
}
func (a *App) zfsPeer() *Invitation {
	a.store.mu.Lock()
	defer a.store.mu.Unlock()
	if a.store.S.Peer == nil {
		return nil
	}
	p := *a.store.S.Peer
	return &p
}
func (a *App) zfsSource(ctx context.Context, remote string, receive bool) bool {
	a.store.mu.Lock()
	enabled := a.store.S.ZFS.Receive.Enabled
	p := a.store.S.Peer
	var peer Invitation
	if p != nil {
		peer = *p
	}
	a.store.mu.Unlock()
	if p == nil || receive && !enabled {
		return false
	}
	n, ok := a.network.(zfsNetwork)
	return ok && n.PeerSource(ctx, peer, remote)
}

// Caller holds the state lock; callbacks are invoked only after listener accept.
func (a *App) configureZFS() error {
	z := a.store.S.ZFS
	n, ok := a.network.(zfsNetwork)
	if !ok {
		if z.Receive.Enabled || z.Outgoing != nil || z.Rescue != nil {
			return errors.New("ZFS-Tunnel wird von diesem Transport nicht unterstützt.")
		}
		return nil
	}
	return n.ConfigureZFS(z.Receive.Enabled, (z.Outgoing != nil || z.Rescue != nil), func(ctx context.Context, r string) bool { return a.zfsSource(ctx, r, true) }, a.zfsPeer)
}
func (a *App) peerHandler(rest http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/buddy-zfs" && !strings.HasPrefix(r.URL.Path, "/buddy-zfs/") {
			rest.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		a.store.mu.Lock()
		user, pass := a.store.S.ReceiverUser, a.store.S.ReceiverPassword
		a.store.mu.Unlock()
		u, p, ok := r.BasicAuth()
		if !ok || user == "" || pass == "" || subtle.ConstantTimeCompare([]byte(u), []byte(user)) != 1 || subtle.ConstantTimeCompare([]byte(p), []byte(pass)) != 1 || !a.zfsSource(r.Context(), r.RemoteAddr, false) {
			fail(w, 401, "unauthorized", "ZFS-Zugang abgelehnt.")
			return
		}
		if r.URL.Path == "/buddy-zfs/v1/offer" && r.Method == "POST" {
			var o ZFSOffer
			if !decode(w, r, &o) {
				return
			}
			if e := validateOffer(o); e != nil {
				respond(w, e)
				return
			}
			a.store.mu.Lock()
			defer a.store.mu.Unlock()
			z := &a.store.S.ZFS
			if !z.Receive.Enabled {
				respond(w, errors.New("ZFS-Empfang ist ausgeschaltet."))
				return
			}
			if z.Incoming != nil && fingerprint(z.Incoming) != fingerprint(o) {
				respond(w, errors.New("Vorhandenes ZFS-Angebot zuerst entfernen."))
				return
			}
			z.Incoming = &o
			if e := a.store.save(); e != nil {
				respond(w, e)
				return
			}
			writeJSON(w, 200, a.zfsLocalPeerStatus())
			return
		}
		if r.URL.Path == "/buddy-zfs/v1/status" && r.Method == "GET" {
			a.store.mu.Lock()
			defer a.store.mu.Unlock()
			writeJSON(w, 200, a.zfsLocalPeerStatus())
			return
		}
		fail(w, 404, "not_found", "ZFS-Endpunkt nicht gefunden.")
	})
}
func (a *App) zfsRequest(ctx context.Context, method, path string, body any, out any) error {
	peer := a.zfsPeer()
	if peer == nil {
		return errors.New("Zuerst einen Freund verbinden.")
	}
	var data io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		data = strings.NewReader(string(b))
	}
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return a.network.Dial(ctx, *peer) }}
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	r, _ := http.NewRequestWithContext(ctx, method, "http://"+net.JoinHostPort(peer.IP, "8787")+"/buddy-zfs/v1/"+path, data)
	r.SetBasicAuth(peer.Username, peer.Password)
	r.Header.Set("Content-Type", "application/json")
	res, e := c.Do(r)
	if e != nil {
		return errors.New("ZFS-Freund nicht erreichbar.")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return errors.New("ZFS-Freund hat die Anfrage abgelehnt.")
	}
	return json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(out)
}
func (a *App) zfsFile(id, side, suffix string) string {
	return filepath.Join(a.store.dir, "buddy-zfs", side+"-"+id+suffix)
}
func readZFSJSON(path string, v any) bool {
	f, e := os.Open(path)
	if e != nil {
		return false
	}
	defer f.Close()
	s, e := f.Stat()
	if e != nil || s.Size() > 1<<20 || !s.Mode().IsRegular() {
		return false
	}
	return json.NewDecoder(io.LimitReader(f, 1<<20)).Decode(v) == nil
}
func (a *App) zfsMarker(id, side string) bool {
	var v struct {
		ID       string `json:"id"`
		QuotaGiB int64  `json:"quota_gib"`
	}
	return readZFSJSON(a.zfsFile(id, side, "-complete.json"), &v) && v.ID == id && (side != "receiver" || v.QuotaGiB == a.store.S.ZFS.Receive.QuotaGiB)
}

func (a *App) zfsLocalPeerStatus() ZFSPeerStatus {
	z := a.store.S.ZFS
	r := ZFSPeerStatus{}
	if z.Incoming == nil {
		return r
	}
	r.OfferID = z.Incoming.ID
	r.Username = "bz" + z.Incoming.ID[:16]
	m, e := a.zfsMount()
	if e == nil {
		r.Parent = strings.Split(m.Source, "/")[0] + "/buddy-zfs-" + z.Incoming.ID[:16]
	}
	r.Ready = z.Receive.Enabled && e == nil && a.zfsMarker(z.Incoming.ID, "receiver")
	readZFSJSON(a.zfsFile(z.Incoming.ID, "receiver", "-status.json"), &r.Report)
	return r
}
func (a *App) zfsMount() (Mount, error) {
	rows, e := a.mounts()
	if e != nil {
		return Mount{}, e
	}
	m, ok := exactMount("/data", rows)
	if !ok || m.FS != "zfs" || !validDataset(m.Source) || m.ReadOnly {
		return Mount{}, errors.New("/data muss ein schreibbarer ZFS-Bind-Mount sein.")
	}
	if !strings.HasPrefix(hostPath(m, ""), "/mnt/") {
		return Mount{}, errors.New("Ungültiger Host-Pfad.")
	}
	return m, nil
}
func (a *App) zfsWarnings(z ZFSState, local ZFSPeerStatus) []string {
	warnings := []string{}
	now := time.Now()
	stale := 48 * time.Hour
	if a.store.S.Settings.StaleHours > 0 {
		stale = time.Duration(a.store.S.Settings.StaleHours) * time.Hour
	}
	for _, report := range []ZFSPeerStatus{local, z.PeerStatus} {
		if report.OfferID == "" {
			continue
		}
		if report.Report.Updated.IsZero() || now.Sub(report.Report.Updated) > 10*time.Minute {
			warnings = append(warnings, "ZFS-Empfangsstatus fehlt oder ist veraltet.")
		}
		for _, d := range report.Report.Datasets {
			if d.KeyStatus != "unavailable" {
				warnings = append(warnings, "Sicherheitswarnung: empfangenes ZFS-Dataset ist nicht gesperrt: "+d.Name)
			}
			if d.SnapshotTime.IsZero() || now.Sub(d.SnapshotTime) > stale {
				warnings = append(warnings, "ZFS-Sicherung ist veraltet: "+d.Name)
			}
		}
	}
	if z.Outgoing != nil {
		if z.PeerStatus.OfferID != z.Outgoing.ID || !z.PeerStatus.Ready {
			warnings = append(warnings, "ZFS-Empfänger ist noch nicht bereit.")
		}
		for i := range z.Outgoing.Datasets {
			target := fmt.Sprintf("%s/d%d", z.PeerStatus.Parent, i)
			found := false
			for _, d := range z.PeerStatus.Report.Datasets {
				if d.Name == target && d.Snapshot != "" {
					found = true
				}
			}
			if !found {
				warnings = append(warnings, "ZFS-Snapshot fehlt: "+z.Outgoing.Datasets[i])
			}
		}
	}
	return warnings
}
func (a *App) zfsStatusLocked() map[string]any {
	z := a.store.S.ZFS
	local := a.zfsLocalPeerStatus()
	var probe, guard ZFSProbe
	var sender ZFSSenderReport
	if z.Outgoing != nil {
		readZFSJSON(a.zfsFile(z.Outgoing.ID, "sender", "-probe.json"), &probe)
		readZFSJSON(a.zfsFile(z.Outgoing.ID, "sender", "-status.json"), &sender)
		readZFSJSON(a.zfsFile(z.Outgoing.ID, "sender", "-guard.json"), &guard)
	}
	warnings := a.zfsWarnings(z, local)
	if a.zfsStartError != "" {
		warnings = append(warnings, "ZFS-Tunnel konnte nicht starten: "+a.zfsStartError)
	}
	for _, d := range sender.Datasets {
		if d.Error != "" {
			warnings = append(warnings, d.Name+": "+d.Error)
		}
		if d.SecurityWarning != "" {
			warnings = append(warnings, d.Name+": "+d.SecurityWarning)
		}
	}
	if z.SenderComplete && (sender.Updated.IsZero() || time.Since(sender.Updated) > 2*time.Hour) {
		warnings = append(warnings, "ZFS-Senderstatus fehlt oder ist veraltet; Root-Cron prüfen.")
	}
	if guard.State == "error" {
		warnings = append(warnings, guard.Message)
	}
	if z.SenderComplete && (probe.Updated.IsZero() || time.Since(probe.Updated) > 40*24*time.Hour || probe.State == "error") {
		warnings = append(warnings, "ZFS-Wiederherstellungsprobe fehlt, ist veraltet oder fehlgeschlagen.")
	}
	return map[string]any{"receive": z.Receive, "incoming": z.Incoming, "outgoing": z.Outgoing, "receiver_ready": local.Ready, "sender_complete": z.SenderComplete, "peer_status": z.PeerStatus, "local_status": local.Report, "probe": probe, "guard": guard, "sender_status": sender, "rescue_acknowledged": z.RescueAck, "rescue_mode": z.Rescue != nil, "warnings": warnings}
}
func (a *App) zfsSync(ctx context.Context) error {
	var p ZFSPeerStatus
	if e := a.zfsRequest(ctx, "GET", "status", nil, &p); e != nil {
		return e
	}
	a.store.mu.Lock()
	defer a.store.mu.Unlock()
	z := &a.store.S.ZFS
	if z.Outgoing == nil || p.OfferID != z.Outgoing.ID {
		return errors.New("ZFS-Angebot beim Freund stimmt nicht überein.")
	}
	if p.Ready && (!validDataset(p.Parent) || !strings.HasSuffix(p.Parent, "/buddy-zfs-"+z.Outgoing.ID[:16]) || p.Username != "bz"+z.Outgoing.ID[:16]) {
		return errors.New("Ungültiger ZFS-Empfangsstatus.")
	}
	z.PeerStatus = p
	return a.store.save()
}
func (a *App) captureHostKey(ctx context.Context, peer Invitation) (string, error) {
	n, ok := a.network.(zfsNetwork)
	if !ok {
		return "", errors.New("ZFS-Tunnel fehlt.")
	}
	c, e := n.ZFSDial(ctx, peer)
	if e != nil {
		return "", e
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	var key string
	cfg := &ssh.ClientConfig{User: "buddy-host-key-probe", HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
		key = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
		return errors.New("host key captured")
	}, Timeout: 10 * time.Second}
	_, _, _, _ = ssh.NewClientConn(c, net.JoinHostPort(peer.IP, "8788"), cfg)
	if key == "" {
		return "", errors.New("SSH-Hostschlüssel konnte nicht gelesen werden.")
	}
	return key, nil
}
func parseHostKey(s string) (ssh.PublicKey, error) {
	k, _, _, rest, e := ssh.ParseAuthorizedKey([]byte(s))
	if e != nil || len(rest) > 0 {
		return nil, errors.New("Ungültiger SSH-Hostschlüssel.")
	}
	return k, nil
}

// Rescue is deliberately independent of an active replication offer. It contains
// SSH transport credentials, never the dataset decryption key.
type ZFSRescue struct {
	Schema     int        `json:"schema"`
	OfferID    string     `json:"offer_id"`
	Peer       Invitation `json:"peer"`
	Datasets   []string   `json:"datasets"`
	Username   string     `json:"username"`
	Parent     string     `json:"parent"`
	HostKey    string     `json:"host_key"`
	PrivateKey string     `json:"private_key"`
}

func validateZFSRescue(k ZFSRescue) error {
	if k.Schema != 1 || !offerIDRE.MatchString(k.OfferID) || k.Username != "bz"+k.OfferID[:16] || !validDataset(k.Parent) || !strings.HasSuffix(k.Parent, "/buddy-zfs-"+k.OfferID[:16]) || len(k.Datasets) < 1 || len(k.Datasets) > 32 {
		return errors.New("Ungültige ZFS-Rettungsdatei.")
	}
	if e := validateInvitation(k.Peer); e != nil {
		return e
	}
	for _, d := range k.Datasets {
		if !validDataset(d) {
			return errors.New("Ungültiger Datasetname.")
		}
	}
	if _, e := parseHostKey(k.HostKey); e != nil || strings.ContainsAny(k.HostKey, "\r\n") {
		return errors.New("Ungültiger SSH-Hostschlüssel.")
	}
	signer, e := ssh.ParsePrivateKey([]byte(k.PrivateKey))
	if e != nil || signer.PublicKey().Type() != ssh.KeyAlgoED25519 {
		return errors.New("Ungültiger SSH-Privatschlüssel.")
	}
	return nil
}
func (a *App) zfsRescue() (ZFSRescue, error) {
	z := a.store.S.ZFS
	if z.Outgoing == nil || a.store.S.Peer == nil || z.SenderComplete || z.PrivateKey == "" || !z.PeerStatus.Ready || z.PeerStatus.OfferID != z.Outgoing.ID {
		return ZFSRescue{}, errors.New("ZFS-Rettungsdatei vor Senderabschluss und nach Empfängereinrichtung sichern.")
	}
	signer, e := ssh.ParsePrivateKey([]byte(z.PrivateKey))
	if e != nil || strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(signer.PublicKey())), "\n") != z.Outgoing.PublicKey {
		return ZFSRescue{}, errors.New("SSH-Schlüsselpaar stimmt nicht überein.")
	}
	k := ZFSRescue{1, z.Outgoing.ID, *a.store.S.Peer, z.Outgoing.Datasets, z.PeerStatus.Username, z.PeerStatus.Parent, z.HostKey, z.PrivateKey}
	return k, validateZFSRescue(k)
}

// A folder bind grants a root container with DAC_READ_SEARCH inode-handle access
// across the source filesystem, including outside the mounted folder (also Restic).
func datasetRootWarnings(rows []Mount) []string {
	warnings := []string{}
	for _, m := range rows {
		if (m.Path == "/data" || validSourcePath(m.Path)) && (m.FS != "zfs" || m.Root != "/") {
			warnings = append(warnings, m.Path+": Kein ZFS-Dataset-Root. Container-Root mit DAC_READ_SEARCH kann auf das gesamte Quell-Dateisystem zugreifen; eigenes Dataset verwenden. Das gilt auch für Dateisicherungen.")
		}
	}
	return warnings
}
