package buddy

import (
	"io/fs"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

type usageCache struct {
	mu   sync.Mutex
	at   time.Time
	used int64
	err  error
}

func (a *App) receiverUsage() (int64, uint64, error) {
	a.usage.mu.Lock()
	defer a.usage.mu.Unlock()
	if time.Since(a.usage.at) > 30*time.Second {
		var total int64
		e := filepath.WalkDir(filepath.Join(a.store.dir, "incoming"), func(path string, d fs.DirEntry, e error) error {
			if e != nil {
				return e
			}
			if d.Type().IsRegular() {
				st, e := d.Info()
				if e != nil {
					return e
				}
				total += st.Size()
			}
			return nil
		})
		a.usage.used = total
		a.usage.err = e
		a.usage.at = time.Now()
	}
	var st syscall.Statfs_t
	e := syscall.Statfs(a.store.dir, &st)
	if a.usage.err != nil {
		return a.usage.used, 0, a.usage.err
	}
	return a.usage.used, st.Bavail * uint64(st.Bsize), e
}
