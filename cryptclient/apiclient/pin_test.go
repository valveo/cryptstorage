package apiclient

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type testCert struct {
	cert *x509.Certificate
	der  []byte
	key  *ecdsa.PrivateKey
}

func (c testCert) tlsCert(chain ...[]byte) tls.Certificate {
	der := append([][]byte{c.der}, chain...)
	return tls.Certificate{Certificate: der, PrivateKey: c.key}
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// makeCert creates a certificate for 127.0.0.1 with the given key, signed by parent
// (self-signed when parent is nil).
func makeCert(t *testing.T, key *ecdsa.PrivateKey, serial int64, isCA bool, parent *testCert) testCert {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: "pin test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	signer, signerCert := key, tmpl
	if parent != nil {
		signer, signerCert = parent.key, parent.cert
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testCert{cert: cert, der: der, key: key}
}

// serve starts an HTTPS server presenting tlsCert; the client trusts the given roots.
func serve(t *testing.T, tlsCert tls.Certificate) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{tlsCert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func get(t *testing.T, srvURL, pins string, roots ...*x509.Certificate) error {
	t.Helper()
	pool := x509.NewCertPool()
	for _, r := range roots {
		pool.AddCert(r)
	}
	c := newWithTLS(srvURL, "", pins, &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool})
	resp, err := c.http.Get(srvURL + "/health")
	if err == nil {
		resp.Body.Close()
	}
	return err
}

func TestSPKIPinAcceptsMatchingKeyAndRejectsOthers(t *testing.T) {
	c := makeCert(t, newKey(t), 1, true, nil)
	srv := serve(t, c.tlsCert())

	if err := get(t, srv.URL, SPKIPin(c.cert), c.cert); err != nil {
		t.Fatalf("matching pin rejected: %v", err)
	}
	other := makeCert(t, newKey(t), 2, true, nil)
	err := get(t, srv.URL, SPKIPin(other.cert), c.cert)
	if err == nil || !strings.Contains(err.Error(), "does not match any pin") {
		t.Fatalf("wrong pin accepted or wrong error: %v", err)
	}
	if !strings.Contains(err.Error(), SPKIPin(c.cert)) {
		t.Fatalf("error should show the server's pin so it can be compared: %v", err)
	}
}

func TestBackupPinIsEnough(t *testing.T) {
	c := makeCert(t, newKey(t), 1, true, nil)
	srv := serve(t, c.tlsCert())
	backup := SPKIPin(makeCert(t, newKey(t), 2, true, nil).cert)

	for _, spec := range []string{backup + "," + SPKIPin(c.cert), backup + " " + SPKIPin(c.cert), SPKIPin(c.cert) + "," + backup} {
		if err := get(t, srv.URL, spec, c.cert); err != nil {
			t.Fatalf("pins %q rejected: %v", spec, err)
		}
	}
}

// The reason for SPKI pins: a renewed certificate with the same key has a new leaf
// fingerprint but the same public key pin.
func TestRenewedCertificateWithSameKeyKeepsWorking(t *testing.T) {
	key := newKey(t)
	first := makeCert(t, key, 1, true, nil)
	renewed := makeCert(t, key, 2, true, nil)
	srv := serve(t, renewed.tlsCert())

	if err := get(t, srv.URL, SPKIPin(first.cert), renewed.cert); err != nil {
		t.Fatalf("SPKI pin broke across a same-key renewal: %v", err)
	}
	sum := sha256.Sum256(first.cert.Raw)
	err := get(t, srv.URL, hex.EncodeToString(sum[:]), renewed.cert)
	if err == nil {
		t.Fatal("legacy leaf fingerprint of the old certificate must not match the renewed one")
	}
}

func TestLegacyLeafFingerprintStillWorks(t *testing.T) {
	c := makeCert(t, newKey(t), 1, true, nil)
	srv := serve(t, c.tlsCert())
	sum := sha256.Sum256(c.cert.Raw)
	fp := hex.EncodeToString(sum[:])

	if err := get(t, srv.URL, fp, c.cert); err != nil {
		t.Fatalf("legacy pin rejected: %v", err)
	}
	colons := strings.ToUpper(strings.Join(splitEvery(fp, 2), ":"))
	if err := get(t, srv.URL, colons, c.cert); err != nil {
		t.Fatalf("legacy pin with colons rejected: %v", err)
	}
	if err := get(t, srv.URL, strings.Repeat("0", 64), c.cert); err == nil {
		t.Fatal("wrong legacy pin accepted")
	}
}

func splitEvery(s string, n int) []string {
	var out []string
	for i := 0; i < len(s); i += n {
		out = append(out, s[i:i+n])
	}
	return out
}

// Pinning an intermediate CA works as a backup pin: after a full key rotation the
// new leaf still chains to the same CA.
func TestPinOfIssuingCAMatchesAnyLeafItSigned(t *testing.T) {
	ca := makeCert(t, newKey(t), 10, true, nil)
	leaf1 := makeCert(t, newKey(t), 11, false, &ca)
	leaf2 := makeCert(t, newKey(t), 12, false, &ca)
	caPin := SPKIPin(ca.cert)

	for _, leaf := range []testCert{leaf1, leaf2} {
		srv := serve(t, leaf.tlsCert(ca.der))
		if err := get(t, srv.URL, caPin, ca.cert); err != nil {
			t.Fatalf("CA pin rejected a leaf it signed: %v", err)
		}
	}

	rogueCA := makeCert(t, newKey(t), 20, true, nil)
	rogueLeaf := makeCert(t, newKey(t), 21, false, &rogueCA)
	srv := serve(t, rogueLeaf.tlsCert(rogueCA.der))
	if err := get(t, srv.URL, caPin, rogueCA.cert); err == nil {
		t.Fatal("a leaf from a different CA matched the CA pin")
	}
}

// Pins are in addition to normal verification, never a replacement.
func TestPinDoesNotBypassCertificateVerification(t *testing.T) {
	c := makeCert(t, newKey(t), 1, true, nil)
	srv := serve(t, c.tlsCert())
	if err := get(t, srv.URL, SPKIPin(c.cert) /* no trusted roots */); err == nil {
		t.Fatal("untrusted certificate accepted just because its pin matched")
	}
}

func TestInvalidPinConfigurationFailsClosed(t *testing.T) {
	c := makeCert(t, newKey(t), 1, true, nil)
	srv := serve(t, c.tlsCert())
	for _, spec := range []string{"sha256/not-base64!", "sha256/AAAA", "zzzz", "abcd"} {
		err := get(t, srv.URL, spec, c.cert)
		if err == nil || !strings.Contains(err.Error(), "invalid CRYPTSTORAGE_CERT_PIN") {
			t.Fatalf("pin %q: expected a configuration error, got %v", spec, err)
		}
	}
}

func TestNoPinMeansOnlyNormalVerification(t *testing.T) {
	c := makeCert(t, newKey(t), 1, true, nil)
	srv := serve(t, c.tlsCert())
	if err := get(t, srv.URL, "", c.cert); err != nil {
		t.Fatalf("unpinned connection to a trusted server failed: %v", err)
	}
}
