package apiclient

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client talks to the CryptStorage API server.
type Client struct {
	BaseURL      string
	Token        string
	RefreshToken string
	http         *http.Client
}

// LoginResponse from POST /auth/login
type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// RefreshResponse from POST /auth/refresh
type RefreshResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// New creates an API client with optional certificate pinning.
//
// certPins is a list of pins separated by commas (see pin.go): "sha256/<base64>" public
// key pins and/or 64-hex-character leaf certificate fingerprints. Pass an empty string
// to skip pinning (not recommended for production). The pins are checked in addition to
// normal certificate verification. An unparsable value makes every connection fail:
// a mistyped pin must never silently turn pinning off.
//
// To get the pin of your server's key:
//
//	openssl s_client -connect your-server.example.com:443 </dev/null 2>/dev/null \
//	  | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der \
//	  | openssl dgst -sha256 -binary | openssl enc -base64
//
// and prefix the result with "sha256/" (or run `cryptclient init-usb`, which stores it).
func New(baseURL, token string, certPins string) *Client {
	return newWithTLS(baseURL, token, certPins, &tls.Config{MinVersion: tls.VersionTLS12})
}

// newWithTLS lets tests supply their own root CAs.
func newWithTLS(baseURL, token, certPins string, tlsConfig *tls.Config) *Client {
	return &Client{
		BaseURL: baseURL,
		Token:   token,
		http:    buildHTTPClient(certPins, tlsConfig),
	}
}

// buildHTTPClient returns an http.Client with optional certificate pinning.
func buildHTTPClient(certPins string, tlsConfig *tls.Config) *http.Client {
	if strings.TrimSpace(certPins) != "" {
		pins, err := parsePins(certPins)
		tlsConfig.VerifyConnection = func(cs tls.ConnectionState) error {
			if err != nil {
				return fmt.Errorf("invalid CRYPTSTORAGE_CERT_PIN: %w", err)
			}
			return verifyPins(cs, pins)
		}
	}

	transport := &http.Transport{
		TLSClientConfig:     tlsConfig,
		DisableKeepAlives:   false,
		MaxIdleConnsPerHost: 4,
	}

	return &http.Client{
		// Mounting (key derivation + starting the user container) can take a minute;
		// 20 s made the client give up while the server was still working.
		Timeout:   90 * time.Second,
		Transport: transport,
	}
}

// GetPinnedFingerprint connects to the server, retrieves its TLS certificate
// and returns the pin of its public key ("sha256/..."). Used during init-usb to store
// the pin. (The name is historical: it used to return a leaf certificate fingerprint.)
func GetPinnedFingerprint(serverURL string) (string, error) {
	// Connect without pinning to retrieve the cert
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			// VerifyConnection not set – we just want the cert
		},
	}
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}

	resp, err := client.Get(serverURL + "/health")
	if err != nil {
		// Even a connection error may give us the cert via TLS
		return "", fmt.Errorf("could not connect to %s: %w", serverURL, err)
	}
	defer resp.Body.Close()

	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		return "", fmt.Errorf("no TLS certificate received from server")
	}

	return SPKIPin(resp.TLS.PeerCertificates[0]), nil
}

// --- API calls ---

// Login authenticates and returns a full LoginResponse.
// ErrTOTPRequired means the password was right but the account has two-factor
// authentication on: call Login again with the code.
var ErrTOTPRequired = errors.New("two-factor code required")

func totpErr(err error) error {
	if err != nil && strings.HasSuffix(err.Error(), "API error: TOTP_REQUIRED") {
		return ErrTOTPRequired
	}
	return err
}

// ErrSecondFactorSetup means the server requires two-factor authentication and this account
// has not set it up yet: everything but the setup is refused until it has.
var ErrSecondFactorSetup = errors.New("this server requires two-factor authentication. Sign in on the " +
	"web page, turn it on under \"Two-factor authentication\", then run this again")

func (c *Client) Login(username, password, totpCode string) (*LoginResponse, error) {
	var resp LoginResponse
	body := map[string]string{
		"username": username,
		"password": password,
	}
	if totpCode != "" {
		body["totp_code"] = totpCode
	}
	if err := c.post("/auth/login", body, &resp); err != nil {
		return nil, totpErr(err)
	}
	c.Token = resp.AccessToken
	c.RefreshToken = resp.RefreshToken
	return &resp, nil
}

// Refresh uses the stored refresh token to get a new access token.
func (c *Client) Refresh() error {
	if c.RefreshToken == "" {
		return fmt.Errorf("no refresh token stored")
	}
	var resp RefreshResponse
	if err := c.post("/auth/refresh", map[string]string{
		"refresh_token": c.RefreshToken,
	}, &resp); err != nil {
		return err
	}
	c.Token = resp.AccessToken
	c.RefreshToken = resp.RefreshToken
	return nil
}

// --- HTTP helpers ---

// APIError is a refusal from the API: its status code and the detail it gave, if any.
type APIError struct {
	Status int
	Detail string
	Body   []byte
}

func (e *APIError) Error() string {
	if e.Detail != "" {
		return "API error: " + e.Detail
	}
	return fmt.Sprintf("API error %d: %s", e.Status, string(e.Body))
}

// withRefresh runs call, and once more after renewing the access token if the token had expired.
// For calls made long after the login, such as the sync lock renewed through a whole session.
func (c *Client) withRefresh(call func() error) error {
	err := call()
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.Status == 401 && c.RefreshToken != "" {
		if rerr := c.Refresh(); rerr != nil {
			return fmt.Errorf("%w (renewing the session failed: %v)", err, rerr)
		}
		return call()
	}
	return err
}

func (c *Client) get(path string, out interface{}) error {
	return c.do("GET", path, nil, out)
}

func (c *Client) post(path string, body, out interface{}) error {
	return c.do("POST", path, body, out)
}

func (c *Client) put(path string, body, out interface{}) error {
	return c.do("PUT", path, body, out)
}

func (c *Client) do(method, path string, body, out interface{}) error {
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		bodyReader = bytes.NewReader(b)
	}

	req, err := http.NewRequest(method, c.BaseURL+path, bodyReader)
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		// Provide a clear error message for pinning failures
		if strings.Contains(err.Error(), "fingerprint mismatch") ||
			strings.Contains(err.Error(), "man-in-the-middle") {
			return fmt.Errorf("⚠️  SECURITY WARNING: %w", err)
		}
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		var errResp map[string]interface{}
		if json.Unmarshal(raw, &errResp) == nil {
			if detail, ok := errResp["detail"].(string); ok {
				if detail == "SECOND_FACTOR_SETUP_REQUIRED" {
					return ErrSecondFactorSetup
				}
				return &APIError{Status: resp.StatusCode, Detail: detail, Body: raw}
			}
		}
		return &APIError{Status: resp.StatusCode, Body: raw}
	}

	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}
