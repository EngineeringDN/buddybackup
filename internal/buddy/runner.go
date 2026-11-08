package buddy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

type RunResult struct {
	Output []byte
	Code   int
}
type Runner interface {
	Run(context.Context, []string, []string, func(map[string]any)) (RunResult, error)
}
type ExecRunner struct {
	Binary string
	Grace  time.Duration
}
type progressWriter struct {
	mu       sync.Mutex
	b        bytes.Buffer
	line     []byte
	over     bool
	progress func(map[string]any)
}

func (w *progressWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.b.Len()+len(p) <= 8<<20 {
		w.b.Write(p)
	} else {
		w.over = true
	}
	for _, b := range p {
		if b == '\n' {
			var row map[string]any
			if json.Unmarshal(w.line, &row) == nil && w.progress != nil {
				allowed := map[string]any{}
				for _, k := range []string{"message_type", "percent_done", "total_files", "files_done", "total_bytes", "bytes_done", "seconds_elapsed", "seconds_remaining", "snapshot_id"} {
					if v, ok := row[k]; ok {
						allowed[k] = v
					}
				}
				w.progress(allowed)
			}
			w.line = w.line[:0]
		} else if len(w.line) < 64<<10 {
			w.line = append(w.line, b)
		}
	}
	return len(p), nil
}
func (r ExecRunner) Run(ctx context.Context, args, env []string, progress func(map[string]any)) (RunResult, error) {
	grace := r.Grace
	if grace == 0 {
		grace = 25 * time.Second
	}
	cmd := exec.CommandContext(ctx, r.Binary, args...)
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		e := cmd.Process.Signal(os.Interrupt)
		if errors.Is(e, os.ErrProcessDone) {
			return nil
		}
		return e
	}
	cmd.WaitDelay = grace
	w := &progressWriter{progress: progress}
	cmd.Stdout = w
	cmd.Stderr = w
	err := cmd.Run()
	res := RunResult{Output: append([]byte{}, w.b.Bytes()...)}
	if cmd.ProcessState != nil {
		res.Code = cmd.ProcessState.ExitCode()
	} else {
		return res, errors.New("restic konnte nicht gestartet werden.")
	}
	if w.over {
		return res, errors.New("restic-Ausgabe überschreitet das sichere API-Limit.")
	}
	if ctx.Err() != nil {
		return res, errors.New("Operation wurde abgebrochen; restic wurde gestoppt.")
	}
	if err != nil && res.Code == 0 {
		return res, err
	}
	return res, nil
}

var _ io.Writer = (*progressWriter)(nil)
