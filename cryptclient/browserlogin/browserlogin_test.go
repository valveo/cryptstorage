package browserlogin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// browser plays the approve page: it reads the fragment and posts to the app's listener.
type browser struct {
	t       *testing.T
	origin  string
	payload struct {
		O json.RawMessage `json:"o"`
		P int             `json:"p"`
		S string          `json:"s"`
		U string          `json:"u"`
	}
}

func (b *browser) open(page string) error {
	frag := page[strings.Index(page, "#")+1:]
	raw, err := base64.RawURLEncoding.DecodeString(frag)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, &b.payload)
}

func (b *browser) post(state, origin string) (int, string) {
	form := url.Values{"state": {state}, "credential": {`{"id":"abc"}`}}
	req, _ := http.NewRequest("POST", "http://127.0.0.1:"+strconv.Itoa(b.payload.P)+"/callback", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		b.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func TestApprove(t *testing.T) {
	b := &browser{t: t}
	opened := make(chan struct{})
	got := make(chan error, 1)
	var cred json.RawMessage
	go func() {
		got <- Approve(context.Background(),
			Request{ApproveURL: "https://files.example.eu/passkey-approve.php", Options: json.RawMessage(`{"challenge":"x"}`), Username: "alice"},
			func(page string) error {
				if !strings.HasPrefix(page, "https://files.example.eu/passkey-approve.php#") {
					t.Errorf("page %s", page)
				}
				err := b.open(page)
				close(opened)
				return err
			},
			func(string) {},
			func(c json.RawMessage) error { cred = c; return nil })
	}()
	<-opened
	if b.payload.U != "alice" || string(b.payload.O) != `{"challenge":"x"}` || len(b.payload.S) != 32 {
		t.Fatalf("payload %+v", b.payload)
	}
	if code, _ := b.post(strings.Repeat("0", 32), ""); code != http.StatusForbidden {
		t.Fatalf("wrong state: %d", code)
	}
	if code, _ := b.post(b.payload.S, "https://evil.example"); code != http.StatusForbidden {
		t.Fatalf("wrong origin: %d", code)
	}
	if code, body := b.post(b.payload.S, "https://files.example.eu"); code != http.StatusOK || !strings.Contains(body, "Signed in") {
		t.Fatalf("right answer: %d %s", code, body)
	}
	if err := <-got; err != nil || string(cred) != `{"id":"abc"}` {
		t.Fatalf("Approve: %v, cred %s", err, cred)
	}
}

func TestRefusesAPageThatIsNoWebAddress(t *testing.T) {
	err := Approve(context.Background(), Request{ApproveURL: "file:///etc/passwd"}, func(string) error { return nil },
		func(string) {}, func(json.RawMessage) error { return nil })
	if err == nil {
		t.Fatal("accepted a file: address")
	}
}
