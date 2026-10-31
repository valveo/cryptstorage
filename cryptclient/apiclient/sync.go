package apiclient

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"
)

// SyncLockedError means another device is synchronising the volume right now.
type SyncLockedError struct {
	HolderName string
	ExpiresIn  time.Duration
}

func (e *SyncLockedError) Error() string {
	who := e.HolderName
	if who == "" {
		who = "another device"
	}
	return fmt.Sprintf("%s is synchronising (lock lasts %s more unless renewed)", who, e.ExpiresIn)
}

// AcquireSyncLock takes or renews the sync lock of the personal volume for this installation
// (holder) and returns how long it lasts. Held elsewhere: *SyncLockedError.
func (c *Client) AcquireSyncLock(holder, holderName string) (time.Duration, error) {
	var resp struct {
		TTLSeconds int `json:"ttl_seconds"`
	}
	body := map[string]string{"holder": holder, "holder_name": holderName}
	err := retryOnce(func() error {
		return c.withRefresh(func() error { return c.post("/storage/sync-lock", body, &resp) })
	})
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.Status == 409 {
		var locked struct {
			HolderName string `json:"holder_name"`
			ExpiresIn  int    `json:"expires_in"`
		}
		_ = json.Unmarshal(apiErr.Body, &locked)
		return 0, &SyncLockedError{HolderName: locked.HolderName, ExpiresIn: time.Duration(locked.ExpiresIn) * time.Second}
	}
	if err != nil {
		return 0, err
	}
	return time.Duration(resp.TTLSeconds) * time.Second, nil
}

// ReleaseSyncLock gives the lock back if this installation holds it.
func (c *Client) ReleaseSyncLock(holder string) error {
	return retryOnce(func() error {
		return c.withRefresh(func() error {
			return c.do("DELETE", "/storage/sync-lock?holder="+url.QueryEscape(holder), nil, nil)
		})
	})
}

// retryOnce repeats a lock call once when the request never got an answer. The server closes an
// idle connection after a few seconds, and a POST sent on it just as it closes fails with EOF; Go
// does not resend a POST by itself. Both lock calls are safe to repeat for the same holder.
func retryOnce(call func() error) error {
	err := call()
	var apiErr *APIError
	if err == nil || errors.As(err, &apiErr) || errors.Is(err, ErrSecondFactorSetup) {
		return err
	}
	time.Sleep(200 * time.Millisecond)
	return call()
}
