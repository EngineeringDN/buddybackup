package buddy

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

type Mount struct {
	Path     string `json:"path"`
	Device   string `json:"device"`
	Root     string `json:"root"`
	FS       string `json:"filesystem"`
	Source   string `json:"source"`
	ReadOnly bool   `json:"read_only"`
}

func unescapeMount(s string) string {
	return regexp.MustCompile(`\\[0-7]{3}`).ReplaceAllStringFunc(s, func(v string) string { n, _ := strconv.ParseUint(v[1:], 8, 8); return string(rune(n)) })
}
func readMounts() ([]Mount, error) {
	f, e := os.Open("/proc/self/mountinfo")
	if e != nil {
		return nil, e
	}
	defer f.Close()
	var rows []Mount
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		p := strings.SplitN(sc.Text(), " - ", 2)
		if len(p) != 2 {
			continue
		}
		a, b := strings.Fields(p[0]), strings.Fields(p[1])
		if len(a) < 6 || len(b) < 2 {
			continue
		}
		rows = append(rows, Mount{unescapeMount(a[4]), a[2], unescapeMount(a[3]), b[0], unescapeMount(b[1]), strings.Contains(","+a[5]+",", ",ro,")})
	}
	return rows, sc.Err()
}
func validSourcePath(p string) bool {
	return filepath.Dir(p) == "/sources" && nameRE.MatchString(filepath.Base(p)) && filepath.Clean(p) == p
}
func exactMount(p string, rows []Mount) (Mount, bool) {
	for _, m := range rows {
		if m.Path == p {
			return m, true
		}
	}
	return Mount{}, false
}
func realDir(p string) error {
	r, e := filepath.EvalSymlinks(p)
	if e != nil || r != p {
		return errors.New("Pfad fehlt oder enthält einen symbolischen Link.")
	}
	st, e := os.Stat(p)
	if e != nil || !st.IsDir() {
		return errors.New("Ordner fehlt.")
	}
	return nil
}
func nonempty(p string) error {
	f, e := os.Open(p)
	if e != nil {
		return e
	}
	defer f.Close()
	for {
		names, e := f.Readdirnames(64)
		for _, name := range names {
			if name != ".zfs" && name != ".ix-apps" && name != "buddybackup-control" && name != "buddybackup-incoming" {
				return nil
			}
		}
		if e != nil {
			return errors.New("Quelle ist leer oder nicht lesbar. Kein Backup erstellt.")
		}
	}
}
func captureManifest(paths []string, rows []Mount) ([]Mount, error) {
	out := []Mount{}
	for _, p := range paths {
		if !validSourcePath(p) {
			return nil, errors.New("Ungültiger Quellpfad.")
		}
		if e := realDir(p); e != nil {
			return nil, e
		}
		m, ok := exactMount(p, rows)
		if !ok || !m.ReadOnly {
			return nil, errors.New("Jede Quelle muss einzeln schreibgeschützt eingehängt sein.")
		}
		if e := nonempty(p); e != nil {
			return nil, e
		}
		out = append(out, m)
		for _, c := range rows {
			if strings.HasPrefix(c.Path, p+"/") && !strings.Contains(c.Path, "/.zfs/") {
				if !c.ReadOnly {
					return nil, errors.New("Unter-Mount ist nicht schreibgeschützt.")
				}
				if e := realDir(c.Path); e != nil {
					return nil, e
				}
				if e := nonempty(c.Path); e != nil {
					return nil, e
				}
				out = append(out, c)
			}
		}
	}
	return out, nil
}
func verifyManifest(paths []string, expected, actual []Mount) error {
	if len(paths) == 0 || len(expected) == 0 {
		return errors.New("Quellen fehlen.")
	}
	now, e := captureManifest(paths, actual)
	if e != nil {
		return e
	}
	if fingerprint(stableMounts(now)) != fingerprint(stableMounts(expected)) {
		return errors.New("Mount-Struktur wurde verändert oder Quelle ist nicht eingehängt. Quellen neu bestätigen.")
	}
	return nil
}

// stableMounts drops the kernel device number: ZFS gets a new anonymous one on every boot.
func stableMounts(rows []Mount) []Mount {
	out := make([]Mount, len(rows))
	for i, m := range rows {
		m.Device = ""
		out[i] = m
	}
	return out
}
func restoreDir(root, folder string, rows []Mount) (string, error) {
	if !nameRE.MatchString(folder) {
		return "", errors.New("Restore-Ordner: nur Buchstaben, Ziffern und Bindestriche.")
	}
	if e := realDir(root); e != nil {
		return "", e
	}
	m, ok := exactMount(root, rows)
	if !ok || m.ReadOnly {
		return "", errors.New("Restore-Pfad muss separat schreibbar eingehängt sein.")
	}
	// Readable by NAS users on purpose: restored data is meant to be picked up, unlike /data.
	if e := adoptDir(root); e != nil {
		return "", e
	}
	p := filepath.Join(root, folder)
	if e := os.Mkdir(p, 0755); e != nil {
		return "", errors.New("Restore-Ziel existiert bereits oder kann nicht erstellt werden.")
	}
	return p, nil
}

// adoptDir takes ownership without touching permissions, so an ACL dataset keeps working as a restore target.
func adoptDir(path string) error {
	st, e := os.Stat(path)
	if e != nil {
		return e
	}
	raw, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("Linux-Dateisystem erforderlich.")
	}
	if int(raw.Uid) != os.Geteuid() {
		if e = os.Chown(path, os.Geteuid(), os.Getegid()); e != nil {
			return errors.New("Restore-Ordner benötigt CHOWN oder passenden Eigentümer.")
		}
	}
	return nil
}

// hostPath maps a path below a bind mount to where it lives on the NAS, using TrueNAS's /mnt layout.
func hostPath(m Mount, sub string) string {
	root := m.Root
	if root == "/" {
		root = ""
	}
	return filepath.Join("/mnt", m.Source, root, sub)
}

// /data and the dedicated /restore root are app-owned output mounts.
// CHOWN/FOWNER let first startup adopt pre-created host directories without
// DAC_OVERRIDE or broad host privileges.
func ownPrivateDir(path string) error {
	st, e := os.Stat(path)
	if e != nil {
		return e
	}
	raw, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("Linux-Dateisystem erforderlich.")
	}
	if int(raw.Uid) != os.Geteuid() {
		if e = os.Chown(path, os.Geteuid(), os.Getegid()); e != nil {
			return errors.New("App-Datenordner benötigt CHOWN oder passenden Eigentümer.")
		}
	}
	if e = os.Chmod(path, 0700); e != nil {
		return errors.New("App-Datenordner benötigt FOWNER oder passende Rechte.")
	}
	return nil
}
