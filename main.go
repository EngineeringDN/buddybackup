package main

import (
	"context"
	"embed"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"buddybackup/internal/buddy"
)

//go:embed web
var assets embed.FS

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func main() {
	data := env("BUDDY_DATA_DIR", "/data")
	n, e := buddy.NetworkFromEnvironment(data)
	if e != nil {
		log.Fatal(e)
	}
	web, _ := fs.Sub(assets, "web")
	a, e := buddy.New(buddy.Options{DataDir: data, Network: n, Web: web, AllowedHost: os.Getenv("BUDDY_UI_HOST"), SecureCookie: os.Getenv("BUDDY_COOKIE_SECURE") == "1"})
	if e != nil {
		log.Fatal(e)
	}
	ln, e := net.Listen("tcp", env("BUDDY_LISTEN", "0.0.0.0:8080"))
	if e != nil {
		log.Fatal(e)
	}
	srv := &http.Server{Handler: a, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 16384}
	go func() {
		if e := srv.Serve(ln); e != nil && e != http.ErrServerClosed {
			log.Print("Webserver beendet: ", e)
		}
	}()
	log.Print("BuddyBackup Weboberfläche bereit.")
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	<-sig
	log.Print("BuddyBackup stoppt laufende Operationen …")
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	if e = a.Close(ctx); e != nil {
		log.Print("Stoppen: ", e)
	}
	_ = srv.Shutdown(ctx)
}
