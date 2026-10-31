// Package browserlogin approves a sign-in of the app with a passkey in the user's browser.
//
// A passkey only works on the web UI's own address, so the app cannot ask for one itself. The app opens
// the web UI's approve page with the browser options in the URL fragment, which the browser never sends
// to a server, and listens on 127.0.0.1 for the answer, like `gh auth login` and RFC 8252. The page posts
// the answer only to 127.0.0.1, and the answer is useless without the session token that stays in the app,
// so a link someone else sends cannot steal a sign-in.
package browserlogin

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// Timeout is how long the app waits for the browser.
var Timeout = 5 * time.Minute

// Request is one sign-in to approve.
type Request struct {
	ApproveURL string          // the web UI's passkey-approve.php
	Options    json.RawMessage // from the API, for navigator.credentials.get
	Username   string
}

// Approve opens the approve page (open, or the system browser when open is nil), waits for the browser's
// answer and hands it to finish, which signs in with the API. show gets the address to print in case
// the browser does not open.
func Approve(ctx context.Context, req Request, open func(string) error, show func(string),
	finish func(credential json.RawMessage) error) error {
	u, err := url.Parse(req.ApproveURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return fmt.Errorf("the server gave no usable address for the passkey page (%q)", req.ApproveURL)
	}
	origin := u.Scheme + "://" + u.Host
	stateBytes := make([]byte, 16)
	if _, err := rand.Read(stateBytes); err != nil {
		return err
	}
	state := hex.EncodeToString(stateBytes)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("could not listen for the browser: %w", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	payload, _ := json.Marshal(map[string]any{"o": req.Options, "p": port, "s": state, "u": req.Username})
	page := req.ApproveURL + "#" + base64.RawURLEncoding.EncodeToString(payload)

	type answer struct {
		cred  json.RawMessage
		reply chan error
	}
	answers := make(chan answer)
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// A form post from the approve page carries its origin; anything else is not ours
		if o := r.Header.Get("Origin"); o != "" && o != "null" && o != origin {
			http.Error(w, "wrong origin", http.StatusForbidden)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if subtle.ConstantTimeCompare([]byte(r.PostForm.Get("state")), []byte(state)) != 1 {
			http.Error(w, "this sign-in was not started here", http.StatusForbidden)
			return
		}
		cred := r.PostForm.Get("credential")
		if !json.Valid([]byte(cred)) {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		a := answer{json.RawMessage(cred), make(chan error, 1)}
		select {
		case answers <- a:
		case <-r.Context().Done():
			return
		}
		writePage(w, <-a.reply)
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go srv.Serve(ln) //nolint:errcheck // ends with Shutdown
	defer func() {
		sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		srv.Shutdown(sctx) //nolint:errcheck
	}()

	if open == nil {
		open = OpenBrowser
	}
	show(page)
	_ = open(page) // the address is shown as well, so a browser that does not open is not fatal

	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	select {
	case a := <-answers:
		err := finish(a.cred)
		a.reply <- err
		// let the page get its answer before the server stops
		time.Sleep(200 * time.Millisecond)
		return err
	case <-ctx.Done():
		return errors.New("no answer from the browser in time; sign in again")
	}
}

func writePage(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	msg, color := "Signed in. You can close this tab and return to the app.", "#00e5a0"
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		msg, color = "The sign-in was refused: "+err.Error()+". Start it again in the app.", "#ff4d6d"
	}
	fmt.Fprintf(w, `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Sign-in</title></head>`+
		`<body style="background:#0a0a0f;color:%s;font-family:system-ui,sans-serif;padding:3rem">`+
		`<p>%s</p></body></html>`, color, html.EscapeString(msg))
}

// OpenBrowser opens url in the system browser.
func OpenBrowser(url string) error {
	switch runtime.GOOS {
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		return exec.Command("open", url).Start()
	}
	if strings.HasPrefix(url, "-") {
		return errors.New("bad address")
	}
	return exec.Command("xdg-open", url).Start()
}
