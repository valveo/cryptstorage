package apiclient

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func stubAPI(t *testing.T, status int, body string) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return New(srv.URL, "", "")
}

func TestRegisterKeyReportsTheSafetyWait(t *testing.T) {
	c := stubAPI(t, 200, `{"message":"later","pending":true,"change_id":"x","effective_at":"2026-10-26T20:15:00"}`)
	err := c.RegisterKey("ssh-ed25519 AAAA", "key")
	var p *KeyPendingError
	if !errors.As(err, &p) {
		t.Fatalf("want KeyPendingError, got %v", err)
	}
	// said in the computer's own time, not UTC
	local := time.Date(2026, 10, 26, 20, 15, 0, 0, time.UTC).Local().Format("2.1.2006 at 15:04")
	if !strings.Contains(err.Error(), local) {
		t.Fatalf("the message must say when, in local time (%s): %v", local, err)
	}
	text := strings.Join(p.Explain(), "\n")
	for _, want := range []string{"✓ The new stick is registered", local, "cancel", "cryptclient connect"} {
		if !strings.Contains(text, want) {
			t.Errorf("the explanation lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "went wrong") || strings.Contains(text, "again") {
		t.Errorf("the wait is a normal step, not a failure to repeat:\n%s", text)
	}
	if err := stubAPI(t, 200, `{"message":"SSH public key added."}`).RegisterKey("k", "key"); err != nil {
		t.Fatalf("an immediate key is not an error: %v", err)
	}
}

func TestMissingSecondFactorSetupIsExplained(t *testing.T) {
	_, err := stubAPI(t, 403, `{"detail":"SECOND_FACTOR_SETUP_REQUIRED"}`).E2EEStorage()
	if !errors.Is(err, ErrSecondFactorSetup) {
		t.Fatalf("want ErrSecondFactorSetup, got %v", err)
	}
}

func TestRecoveryAndPasswordChangeAskForTheCode(t *testing.T) {
	c := stubAPI(t, 401, `{"detail":"TOTP_REQUIRED"}`)
	if err := c.RecoverE2EE("u", "p", "k", ""); !errors.Is(err, ErrTOTPRequired) {
		t.Fatalf("recover: %v", err)
	}
	if err := c.ChangeLoginKey("a", "b", ""); !errors.Is(err, ErrTOTPRequired) {
		t.Fatalf("change: %v", err)
	}
}

func TestSyncLockConflictAndRefresh(t *testing.T) {
	expired := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/auth/refresh":
			expired = false
			w.Write([]byte(`{"access_token":"new","refresh_token":"r2"}`))
		case expired:
			w.WriteHeader(401)
			w.Write([]byte(`{"detail":"Invalid or expired token."}`))
		case r.Method == "POST" && r.Header.Get("Authorization") == "Bearer new":
			w.WriteHeader(409)
			w.Write([]byte(`{"detail":"SYNC_LOCKED","holder_name":"desktop","expires_in":42}`))
		case r.Method == "DELETE" && r.URL.Query().Get("holder") == "me-0123456789abcdef":
			w.Write([]byte(`{"message":"Released."}`))
		default:
			w.WriteHeader(400)
		}
	}))
	defer srv.Close()
	c := New(srv.URL, "old", "")
	c.RefreshToken = "r1"
	_, err := c.AcquireSyncLock("me-0123456789abcdef", "laptop")
	var locked *SyncLockedError
	if !errors.As(err, &locked) || locked.HolderName != "desktop" || locked.ExpiresIn != 42*time.Second {
		t.Fatalf("got %v", err)
	}
	if c.Token != "new" {
		t.Fatal("the expired token was not renewed")
	}
	if err := c.ReleaseSyncLock("me-0123456789abcdef"); err != nil {
		t.Fatal(err)
	}
}
