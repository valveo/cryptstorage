package setup

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"cryptclient/apiclient"
	"cryptclient/crypto"
	"cryptclient/e2ee"
	"cryptclient/escrowcheck"
	"cryptclient/sshconn"
	"cryptclient/stickkey"
	"cryptclient/stickserver"
)

// scripted plays the user: answers are taken in order, the recovery code is read from what was shown.
type scripted struct {
	t       *testing.T
	answers []string
	said    []string
	code    string
}

func (u *scripted) Say(f string, a ...any) {
	line := fmt.Sprintf(f, a...)
	u.said = append(u.said, line)
	if t := strings.TrimSpace(line); strings.Count(t, "-") >= 5 && !strings.Contains(t, " ") {
		u.code = t
	}
}
func (u *scripted) next(label string) string {
	if strings.Contains(label, "first group") {
		return strings.SplitN(u.code, "-", 2)[0]
	}
	if len(u.answers) == 0 {
		u.t.Fatalf("the flow asked an unexpected question: %q", label)
	}
	a := u.answers[0]
	u.answers = u.answers[1:]
	return a
}
func (u *scripted) Ask(l string) string       { return u.next(l) }
func (u *scripted) AskSecret(l string) string { return u.next(l) }
func (u *scripted) Confirm(l string) bool     { return u.next(l) == "yes" }
func (u *scripted) all() string               { return strings.Join(u.said, "\n") }

// fakeStick keeps the encrypted key in memory.
type fakeStick struct {
	blob  []byte
	mount string
}

func (s *fakeStick) Present() bool            { return s.blob != nil }
func (s *fakeStick) ReadKey() ([]byte, error) { return s.blob, nil }
func (s *fakeStick) MountPath() string        { return s.mount }
func (s *fakeStick) WriteKey(old, blob []byte) error {
	s.blob = blob
	return nil
}
func (s *fakeStick) Prepare(password string, _ bool) ([]byte, string, error) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(priv)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	enc, err := crypto.EncryptKey(pemBytes, password)
	if err != nil {
		return nil, "", err
	}
	s.blob = enc
	pub, err := publicKey(pemBytes)
	return pemBytes, pub, err
}

func TestRefusesWhenSomethingIsMissing(t *testing.T) {
	u := &scripted{t: t}
	_, err := Run(Env{UI: u, Missing: func() []string { return []string{"gocryptfs"} }})
	if err == nil || !strings.Contains(u.all(), "gocryptfs") {
		t.Fatalf("expected a clear refusal, got %v\n%s", err, u.all())
	}
}

func TestWaitsForTheEmailAndCanBeResumed(t *testing.T) {
	logins := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/login" {
			http.NotFound(w, r)
			return
		}
		logins++
		if logins < 4 {
			w.WriteHeader(403)
			json.NewEncoder(w).Encode(map[string]string{"detail": "Email not verified. Check your inbox."})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"access_token": "a", "refresh_token": "r"})
	}))
	defer srv.Close()
	keys, _ := e2ee.Derive("alice", "correct horse battery")
	api := apiclient.New(srv.URL, "", "")

	u := &scripted{t: t, answers: []string{"yes", "yes", "yes"}}
	if err := waitForVerification(Env{UI: u}, api, "alice", keys); err != nil {
		t.Fatalf("%v\n%s", err, u.all())
	}
	if logins != 4 || !strings.Contains(u.all(), "click the confirmation link") {
		t.Fatalf("logins=%d\n%s", logins, u.all())
	}

	logins = 0
	u = &scripted{t: t, answers: []string{"no"}}
	if err := waitForVerification(Env{UI: u}, api, "alice", keys); !errors.Is(err, ErrAborted) {
		t.Fatalf("saying no should stop cleanly, got %v", err)
	}
}

// An existing account with two-factor authentication: the code is asked once, and the stick is
// registered with the session of that sign-in. The server refuses a code used before, as the real
// one does; asking again for the same code made setup fail on Windows.
func TestExistingAccountAsksTheCodeOnce(t *testing.T) {
	used := map[string]bool{}
	logins, keyAuth := 0, ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/server-info":
			json.NewEncoder(w).Encode(map[string]any{"storage_mode": "e2ee"})
		case "/auth/login":
			var body map[string]string
			json.NewDecoder(r.Body).Decode(&body)
			logins++
			code := body["totp_code"]
			if code == "" {
				w.WriteHeader(401)
				json.NewEncoder(w).Encode(map[string]string{"detail": "TOTP_REQUIRED"})
				return
			}
			if used[code] {
				w.WriteHeader(401)
				json.NewEncoder(w).Encode(map[string]string{"detail": "Invalid verification code."})
				return
			}
			used[code] = true
			json.NewEncoder(w).Encode(map[string]any{"access_token": "session-1", "refresh_token": "r"})
		case "/users/me/ssh-key":
			keyAuth = r.Header.Get("Authorization")
			json.NewEncoder(w).Encode(map[string]any{"pending": true, "effective_at": "2026-11-01T09:00:00"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	u := &scripted{t: t, answers: []string{"alice", "correct horse battery", "123456"}}
	res, err := Run(Env{
		UI:      u,
		Stick:   &fakeStick{mount: t.TempDir()},
		API:     func(string) *apiclient.Client { return apiclient.New(srv.URL, "", "") },
		Missing: func() []string { return nil },
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, u.all())
	}
	if !res.KeyPending || logins != 2 || keyAuth != "Bearer session-1" {
		t.Fatalf("pending=%v logins=%d auth=%q\n%s", res.KeyPending, logins, keyAuth, u.all())
	}
}

func TestRecoveryCodeMustBeTypedBack(t *testing.T) {
	u := &scripted{t: t, answers: []string{"wrong", "also wrong", "wrong", "wrong", "wrong"}}
	u.code = "ABCDEF-GHIJKL-MNOPQR-STUVWX-YZ2345-ABCDEF"
	// the scripted user never types the right group (label check is bypassed by naming it differently)
	u2 := &answersOnly{scripted: u}
	if err := showRecoveryCode(u2, u.code); err == nil {
		t.Fatal("a code that was never confirmed must not pass silently")
	}
	u3 := &answersOnly{scripted: &scripted{t: t, answers: []string{"abcdef"}}}
	if err := showRecoveryCode(u3, "ABCDEF-GHIJKL-MNOPQR-STUVWX-YZ2345-ABCDEF"); err != nil {
		t.Fatalf("lower case should be accepted: %v", err)
	}
}

// answersOnly takes every answer from the list, including the "first group" question.
type answersOnly struct{ *scripted }

func (u *answersOnly) Ask(string) string {
	a := u.answers[0]
	u.answers = u.answers[1:]
	return a
}

// The whole setup against the real server, twice: the second run must find everything in place.
func TestIntegrationFullSetup(t *testing.T) {
	url := os.Getenv("CRYPTSTORAGE_IT_URL")
	if url == "" {
		t.Skip("CRYPTSTORAGE_IT_URL not set")
	}
	user := fmt.Sprintf("su%d%d", os.Getpid(), time.Now().Unix()%100000)
	pw := "correct horse battery staple"
	stick := &fakeStick{mount: t.TempDir()}
	env := func(u UI) Env {
		return Env{
			UI: u, Stick: stick,
			API:      func(string) *apiclient.Client { return apiclient.New(url, "", "") },
			HostKeys: func(m string) *sshconn.HostKeyManager { h := sshconn.NewHostKeyManager(m); h.Load(); return h },
			Trust:    func(string, string) bool { return true },
			Missing:  func() []string { return nil },
		}
	}

	// the last "yes" agrees to the escrow copy (the integration server runs policy "both")
	u := &scripted{t: t, answers: []string{user, pw, "yes", pw, user + "@example.com", "yes"}}
	res, err := Run(env(u))
	if err != nil {
		t.Fatalf("%v\n%s", err, u.all())
	}
	if rec, found, err := escrowcheck.Load(stick.mount); err != nil || !found || !rec.On() {
		t.Fatalf("the accepted escrow setting should be on the stick: %+v %v %v", rec, found, err)
	}
	if !res.NewAccount || !res.NewVolume || res.RecoveryCode == "" || !res.Escrow {
		t.Fatalf("unexpected result %+v\n%s", res, u.all())
	}
	if len(u.answers) != 0 {
		t.Fatalf("unused answers: %v", u.answers)
	}
	// the stick's key is sealed with the server's stick secret: the password alone no longer opens it.
	// Only where the server under test offers stick secrets (scripts/e2ee_integration.sh says so); the
	// Windows run uses the deployed test server, which may run an older API.
	if os.Getenv("CRYPTSTORAGE_IT_STICK_SECRETS") == "" {
		t.Log("not checking the sealed key: CRYPTSTORAGE_IT_STICK_SECRETS not set")
	} else if !stickkey.Sealed(stick.blob) {
		t.Fatalf("the stick's key was not sealed\n%s", u.all())
	} else if _, err := crypto.DecryptKey(stick.blob, pw); !errors.Is(err, crypto.ErrSealed) {
		t.Fatalf("the sealed key opened with the password alone: %v", err)
	}

	// the stick notes its server, with the id where the server has stick secrets
	if rec, err := stickserver.Load(stick.mount); err != nil || rec == nil || rec.URL != url || len(rec.HostKeys) == 0 ||
		(os.Getenv("CRYPTSTORAGE_IT_STICK_SECRETS") != "" && rec.ServerID == "") {
		t.Fatalf("the stick should name its server: %+v %v", rec, err)
	}

	// the second run opens the sealed key after the login
	u = &scripted{t: t, answers: []string{user, pw}}
	res, err = Run(env(u))
	if err != nil {
		t.Fatalf("second run: %v\n%s", err, u.all())
	}
	if res.NewAccount || res.NewVolume || !strings.Contains(u.all(), "already exists") {
		t.Fatalf("second run should change nothing: %+v\n%s", res, u.all())
	}

	// A different password for the same name must not create anything or touch the stick
	u = &scripted{t: t, answers: []string{user, "another long wrong password", "no"}}
	if _, err = Run(env(u)); err == nil {
		t.Fatal("a wrong password must stop the setup")
	}
}

// A stick of another server is never used or sealed by setup unless the user agrees to move it.
func TestStickOfAnotherServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/server-info":
			json.NewEncoder(w).Encode(map[string]any{"storage_mode": "e2ee", "recovery_policy": "user", "server_id": "id-here"})
		case "/auth/login":
			json.NewEncoder(w).Encode(map[string]any{"access_token": "a", "refresh_token": "r"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	env := func(u *scripted, st *fakeStick) Env {
		return Env{UI: u, Stick: st, Missing: func() []string { return nil },
			API: func(string) *apiclient.Client { return apiclient.New(srv.URL, "", "") }}
	}
	newStick := func() *fakeStick {
		st := &fakeStick{mount: t.TempDir(), blob: []byte("the other server's key")}
		if err := stickserver.Save(st.mount, stickserver.Record{URL: "https://other.example/api", ServerID: "id-other"}); err != nil {
			t.Fatal(err)
		}
		return st
	}

	st := newStick()
	u := &scripted{t: t, answers: []string{"alice", "correct horse battery", "no"}}
	if _, err := Run(env(u, st)); err == nil || string(st.blob) != "the other server's key" {
		t.Fatalf("saying no must leave the stick alone: %v\n%s", err, u.all())
	}
	if !strings.Contains(u.all(), "cryptclient server https://other.example/api") {
		t.Fatalf("setup should say how to reach the stick's own server:\n%s", u.all())
	}

	st = newStick()
	u = &scripted{t: t, answers: []string{"alice", "correct horse battery", "yes"}}
	_, _ = Run(env(u, st)) // stops at registering the key: this fake server has no more
	rec, _ := stickserver.Load(st.mount)
	if string(st.blob) == "the other server's key" || rec == nil || rec.ServerID != "id-here" || rec.URL != srv.URL {
		t.Fatalf("after yes the stick is prepared for this server: %+v\n%s", rec, u.all())
	}
}
