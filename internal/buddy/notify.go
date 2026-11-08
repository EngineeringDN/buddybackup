package buddy

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
)

func validateNotifyURL(raw string) error {
	if raw == "" {
		return nil
	}
	u, e := url.Parse(raw)
	if e != nil || len(raw) > 2048 || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return errors.New("ntfy benötigt eine gültige HTTP(S)-Adresse ohne eingebettete Zugangsdaten.")
	}
	return nil
}
func (a *App) notify(raw, message string) {
	if raw == "" || validateNotifyURL(raw) != nil {
		return
	}
	r, e := http.NewRequest(http.MethodPost, raw, strings.NewReader(message))
	if e != nil {
		return
	}
	r.Header.Set("Content-Type", "text/plain; charset=utf-8")
	r.Header.Set("Title", "BuddyBackup")
	res, e := a.notifyClient.Do(r)
	if e == nil {
		res.Body.Close()
	}
}
