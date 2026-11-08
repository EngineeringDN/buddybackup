package buddy

import (
	"crypto/subtle"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

type session struct {
	CSRF    string
	Authed  bool
	Expires time.Time
}
type attempts struct {
	Count int
	Until time.Time
}

const cookieName = "buddy_session"

func (a *App) getSession(w http.ResponseWriter, r *http.Request, create bool) (*session, string) {
	a.sessionMu.Lock()
	defer a.sessionMu.Unlock()
	now := time.Now()
	for k, s := range a.sessions {
		if now.After(s.Expires) {
			delete(a.sessions, k)
		}
	}
	c, e := r.Cookie(cookieName)
	if e == nil {
		if s, ok := a.sessions[c.Value]; ok {
			return &session{s.CSRF, s.Authed, s.Expires}, c.Value
		}
	}
	if !create {
		return nil, ""
	}
	if len(a.sessions) >= 2048 {
		for k := range a.sessions {
			delete(a.sessions, k)
			break
		}
	}
	id := secret()
	s := &session{CSRF: secret(), Expires: now.Add(12 * time.Hour)}
	a.sessions[id] = s
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: id, Path: "/", HttpOnly: true, Secure: a.secureCookie || r.TLS != nil, SameSite: http.SameSiteStrictMode, MaxAge: 43200})
	return &session{s.CSRF, s.Authed, s.Expires}, id
}
func (a *App) setAuth(w http.ResponseWriter, r *http.Request, id string, authed bool) {
	a.sessionMu.Lock()
	defer a.sessionMu.Unlock()
	old := a.sessions[id]
	if old == nil {
		return
	}
	delete(a.sessions, id)
	id = secret()
	a.sessions[id] = &session{CSRF: old.CSRF, Authed: authed, Expires: time.Now().Add(12 * time.Hour)}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: id, Path: "/", HttpOnly: true, Secure: a.secureCookie || r.TLS != nil, SameSite: http.SameSiteStrictMode, MaxAge: 43200})
}
func (a *App) allowLogin(r *http.Request) bool {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	a.sessionMu.Lock()
	defer a.sessionMu.Unlock()
	now := time.Now()
	for k, v := range a.limits {
		if now.After(v.Until) {
			delete(a.limits, k)
		}
	}
	if len(a.limits) > 1024 {
		return false
	}
	v := a.limits[ip]
	if v.Until.IsZero() {
		v.Until = now.Add(15 * time.Minute)
	}
	v.Count++
	a.limits[ip] = v
	return v.Count <= 5
}
func privateUIAddress(host string) bool {
	a, e := netip.ParseAddr(strings.Trim(host, "[]"))
	if e != nil {
		return false
	}
	a = a.Unmap()
	return a.IsPrivate() || a.IsLoopback()
}
func (a *App) checkOrigin(r *http.Request) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, e := url.Parse(origin)
	scheme := "http"
	if r.TLS != nil || a.secureCookie {
		scheme = "https"
	}
	return e == nil && u.Scheme == scheme && u.Host == r.Host && u.Path == ""
}
func (a *App) validUIRequest(r *http.Request) bool {
	ip, _, e := net.SplitHostPort(r.RemoteAddr)
	if e != nil || !privateUIAddress(ip) {
		return false
	}
	host := r.Host
	if h, _, e := net.SplitHostPort(host); e == nil {
		host = h
	}
	return host == "localhost" || privateUIAddress(host) || (a.allowedHost != "" && strings.EqualFold(host, a.allowedHost))
}
func csrfOK(s *session, r *http.Request) bool {
	return s != nil && subtle.ConstantTimeCompare([]byte(s.CSRF), []byte(r.Header.Get("X-CSRF-Token"))) == 1
}
