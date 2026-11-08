package buddy

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	restserver "github.com/restic/rest-server"
)

func receiver(s *Store) (http.Handler, error) {
	path := filepath.Join(s.dir, "incoming")
	if e := os.MkdirAll(path, 0700); e != nil {
		return nil, e
	}
	if e := realDir(path); e != nil {
		return nil, e
	}
	auth := filepath.Join(s.dir, "receiver.htpasswd")
	if !strings.HasPrefix(s.S.ReceiverHash, "$2") {
		return nil, errors.New("Ungültiger bcrypt-Empfängerzugang.")
	}
	if e := os.WriteFile(auth, []byte(s.S.ReceiverUser+":"+s.S.ReceiverHash+"\n"), 0600); e != nil {
		return nil, e
	}
	q := &quotaReceiver{path: path, auth: auth}
	if e := q.setQuota(s.S.Quota); e != nil {
		return nil, e
	}
	return q, nil
}

// quotaReceiver allows changing the storage limit without restarting the tsnet listener.
type quotaReceiver struct {
	path, auth string
	mu         sync.RWMutex
	handler    http.Handler
	upload     sync.Mutex
}

func (q *quotaReceiver) setQuota(limit int64) error {
	h, e := restserver.NewHandler(&restserver.Server{Path: q.path, HtpasswdPath: q.auth, PrivateRepos: true, MaxRepoSize: limit})
	if e != nil {
		return e
	}
	q.mu.Lock()
	q.handler = h
	q.mu.Unlock()
	return nil
}

func (q *quotaReceiver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Serialize uploads: upstream quota's check-then-write is not a reservation.
	if r.Method == http.MethodPost {
		q.upload.Lock()
		defer q.upload.Unlock()
	}
	q.mu.RLock()
	h := q.handler
	q.mu.RUnlock()
	h.ServeHTTP(w, r)
}
