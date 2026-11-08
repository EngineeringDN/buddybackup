package buddy

import (
	"context"
	"crypto/subtle"
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

// Not a proxy service: fixed node/IP/port, fixed repository path, no CONNECT,
// no URL chosen by the caller. Exists only for the duration of one operation.
func localForwarder(n Network, inv Invitation) (string, string, string, func(), error) {
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		return "", "", "", nil, e
	}
	user, pass := "local-"+randomID(), secret()
	target, _ := url.Parse("http://" + net.JoinHostPort(inv.IP, "8787"))
	tr := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return n.Dial(ctx, inv) }, MaxIdleConnsPerHost: 8, IdleConnTimeout: 30 * time.Second, ResponseHeaderTimeout: 60 * time.Second}
	proxy := &httputil.ReverseProxy{Rewrite: func(pr *httputil.ProxyRequest) {
		pr.SetURL(target)
		pr.Out.Header.Del("Forwarded")
		pr.Out.Header.Del("X-Forwarded-For")
		pr.Out.Header.Del("X-Forwarded-Host")
		pr.Out.Header.Del("X-Forwarded-Proto")
		pr.Out.SetBasicAuth(inv.Username, inv.Password)
	}, Transport: tr, ErrorHandler: func(w http.ResponseWriter, r *http.Request, e error) {
		http.Error(w, "Backup-Verbindung unterbrochen.", 502)
	}}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || subtle.ConstantTimeCompare([]byte(u), []byte(user)) != 1 || subtle.ConstantTimeCompare([]byte(p), []byte(pass)) != 1 {
			w.WriteHeader(401)
			return
		}
		if r.URL.IsAbs() || r.Method == "CONNECT" || !strings.HasPrefix(r.URL.Path, "/"+inv.Username+"/") || strings.Contains(r.URL.Path, "..") {
			http.Error(w, "Ungültiger Repository-Pfad.", 403)
			return
		}
		switch r.Method {
		case "GET", "HEAD", "POST", "DELETE":
		default:
			w.WriteHeader(405)
			return
		}
		proxy.ServeHTTP(w, r)
	})
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second, MaxHeaderBytes: 16384}
	go srv.Serve(ln)
	close := func() { srv.Close(); tr.CloseIdleConnections() }
	return "rest:http://" + ln.Addr().String() + "/" + inv.Username + "/", user, pass, close, nil
}

var errNoRepository = errors.New("Repository fehlt. Wiederherstellung initialisiert niemals ein neues Repository.")
