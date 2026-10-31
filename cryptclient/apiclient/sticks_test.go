package apiclient

import (
	"errors"
	"testing"
)

func TestStickErrors(t *testing.T) {
	for _, c := range []struct {
		status int
		detail string
		want   error
	}{
		{404, "STICK_REVOKED", ErrStickRevoked},
		{403, "STICK_LOCKED", ErrStickLocked},
		{503, "off", ErrNoStickSecrets},
		{404, "Not Found", ErrNoStickSecrets},
	} {
		if got := stickErr(&APIError{Status: c.status, Detail: c.detail}); !errors.Is(got, c.want) {
			t.Errorf("%d %s: %v", c.status, c.detail, got)
		}
	}
	other := &APIError{Status: 403, Detail: "WEB_SESSION_REFUSED"}
	if got := stickErr(other); got != error(other) {
		t.Errorf("other errors pass through: %v", got)
	}
}
