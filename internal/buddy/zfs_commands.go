package buddy

import (
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

//go:embed zfs_host.py
var zfsHostProgram string

// pyBase64 renders a Python literal wrapped at 76 columns. Terminals and zsh choke when one
// 80 KB line is pasted; base64 has no quote characters and b64decode skips the newlines.
func pyBase64(b []byte) string {
	text := base64.StdEncoding.EncodeToString(b)
	var out strings.Builder
	out.WriteString("'''\n")
	for len(text) > 76 {
		out.WriteString(text[:76] + "\n")
		text = text[76:]
	}
	out.WriteString(text + "\n'''")
	return out.String()
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
func (a *App) zfsCommand(side string) (string, error) {
	z := a.store.S.ZFS
	m, e := a.zfsMount()
	if e != nil {
		return "", e
	}
	remove := strings.HasPrefix(side, "remove-")
	side = strings.TrimPrefix(side, "remove-")
	o := z.Outgoing
	if side == "receiver" {
		o = z.Incoming
	}
	if o == nil {
		return "", errors.New("ZFS-Angebot fehlt.")
	}
	if e := validateOffer(*o); e != nil {
		return "", e
	}
	dir := hostPath(m, "buddy-zfs")
	control := filepath.Join("/mnt", strings.Split(m.Source, "/")[0], "buddy-zfs-control")
	// A bind of ANY folder on the control filesystem exposes every inode via handles.
	rows, err := a.mounts()
	if err != nil {
		return "", err
	}
	for _, row := range rows {
		if row.FS != "zfs" {
			continue
		}
		host := filepath.Clean(hostPath(row, ""))
		if row.Source == strings.Split(m.Source, "/")[0]+"/buddy-zfs-control" || control == host || strings.HasPrefix(control, host+"/") || strings.HasPrefix(host, control+"/") {
			return "", errors.New("ZFS-Kontroll-Dataset darf durch keinen Container-Mount erreichbar sein.")
		}
	}
	path := filepath.Join(control, side+"-"+o.ID+".py")
	cfg := map[string]any{"side": side, "offer": o, "directory": dir, "pool": strings.Split(m.Source, "/")[0]}
	binds := []string{}
	for _, row := range rows {
		if row.FS == "zfs" {
			binds = append(binds, row.Source)
		}
	}
	cfg["bind_datasets"] = binds
	if remove {
		cfg["host_key"] = z.HostKey
		cfg["parent"] = z.PeerStatus.Parent
		cfg["username"] = z.PeerStatus.Username
		if side == "receiver" {
			cfg["parent"] = cfg["pool"].(string) + "/buddy-zfs-" + o.ID[:16]
			cfg["username"] = "bz" + o.ID[:16]
		}
		cfg["quota_gib"] = z.Receive.QuotaGiB
		b, _ := json.Marshal(cfg)
		return fmt.Sprintf("sudo bash -s -- \"${BUDDY_ZFS_REMOVE_FLAG:-}\" <<'BUDDY_ZFS_REMOVE'\nset -euo pipefail\numask 077\n/usr/bin/python3 -I - \"$1\" <<'BUDDY_ZFS_PY'\nimport base64, json\nCONFIG = json.loads(base64.b64decode(%s))\nBODY = base64.b64decode(%s).decode()\n%s\nimport subprocess, sys\nsubprocess.run(['/usr/bin/python3', '-I', %s, 'remove', sys.argv[1]], check=True)\nBUDDY_ZFS_PY\nBUDDY_ZFS_REMOVE\n", pyBase64(b), pyBase64([]byte(zfsHostProgram)), zfsPasteReview, string(mustJSON(path))), nil
	}
	if side == "receiver" {
		if !z.Receive.Enabled || z.Receive.QuotaGiB < 1 || z.Receive.QuotaGiB > 1048576 {
			return "", errors.New("Zuerst ZFS-Empfang und Speicherlimit einschalten.")
		}
		cfg["quota_gib"] = z.Receive.QuotaGiB
	} else {
		if z.SenderComplete || z.PrivateKey == "" {
			return "", errors.New("SSH-Schlüssel wurde nach Abschluss gelöscht. Auftrag ist bereits eingerichtet.")
		}
		p := z.PeerStatus
		if !p.Ready || p.OfferID != o.ID || !validDataset(p.Parent) {
			return "", errors.New("ZFS-Empfänger ist noch nicht bereit.")
		}
		if _, e := parseHostKey(z.HostKey); e != nil {
			return "", e
		}
		cfg["parent"] = p.Parent
		cfg["username"] = p.Username
		cfg["host_key"] = z.HostKey
		cfg["private_key"] = z.PrivateKey
	}
	b, _ := json.Marshal(cfg)
	return fmt.Sprintf("sudo bash <<'BUDDY_ZFS_SETUP'\nset -euo pipefail\numask 077\n/usr/bin/python3 -I - <<'BUDDY_ZFS_PY'\nimport base64, json\nCONFIG = json.loads(base64.b64decode(%s))\nBODY = base64.b64decode(%s).decode()\n%s\nEXEC_WRAPPER = %s\nexec(EXEC_WRAPPER)\nBUDDY_ZFS_PY\nBUDDY_ZFS_SETUP\n", pyBase64(b), pyBase64([]byte(zfsHostProgram)), zfsPasteReview, string(mustJSON(zfsExecWrapper))), nil
}

const zfsExecWrapper = `try:
    exec(compile(BODY, '<buddy-zfs>', 'exec'))
except Exception as exc:
    import sys
    print(str(exc) if type(exc).__name__ == 'BuddyError' else 'ZFS-Aktion fehlgeschlagen. TrueNAS-Konfiguration prüfen; Einrichtung kann erneut ausgeführt werden.', file=sys.stderr)
    sys.exit(1)
`

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

func zfsHostSHA256() string { return fmt.Sprintf("%x", sha256.Sum256([]byte(zfsHostProgram))) }

const zfsRootTrustWarning = "Ein kompromittierter App-Container kann den gesamten Root-Paste verändern. Hash unabhängig mit der veröffentlichten Release-Datei vergleichen und Konfiguration prüfen."

// Printed before host imports or any mutation; private key material is never printed.
const zfsPasteReview = `import hashlib
print('ZFS host SHA-256: ' + hashlib.sha256(BODY.encode()).hexdigest(), flush=True)
def key_fingerprint(key):
    return 'SHA256:' + base64.b64encode(hashlib.sha256(base64.b64decode(key.split()[1])).digest()).decode().rstrip('=') if key else None
pool, offer = CONFIG['pool'], CONFIG['offer']
print(json.dumps({'action': 'review', 'side': CONFIG['side'],
    'username': CONFIG.get('username', 'bz' + offer['id'][:16]),
    'datasets': offer['datasets'], 'control_dataset': pool + '/buddy-zfs-control',
    'parent': CONFIG.get('parent', pool + '/buddy-zfs-' + offer['id'][:16]),
    'quota_gib': CONFIG.get('quota_gib'),
    'offer_key_fingerprint': key_fingerprint(offer['public_key']),
    'host_key_fingerprint': key_fingerprint(CONFIG.get('host_key'))}, ensure_ascii=True, indent=2), flush=True)
print('Root-Vertrauensgrenze: Ein kompromittierter Container kann auch diesen Paste und seine Hash-Ausgabe fälschen. Mit unabhängig veröffentlichtem Release vergleichen.', flush=True)
with open('/dev/tty', 'w') as tty:
    tty.write('Hash und Konfiguration unabhängig geprüft? Zum Ausführen RUN eingeben: ')
    tty.flush()
with open('/dev/tty', 'r') as tty:
    # Leftover newlines from the paste itself must not count as the answer.
    answer = tty.readline()
    while answer and not answer.strip():
        answer = tty.readline()
    if answer.strip() != 'RUN':
        raise SystemExit('Abgebrochen.')
`
