package sshconn

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func testKeyPEM(t *testing.T) ([]byte, ssh.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "test")
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(block), sshPub
}

func TestAgentServesTheKeyAndSigns(t *testing.T) {
	pemBytes, pub := testKeyPEM(t)
	a, err := StartAgent(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	conn, err := net.Dial("unix", a.Socket())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := agent.NewClient(conn)

	keys, err := client.List()
	if err != nil || len(keys) != 1 {
		t.Fatalf("agent should hold exactly one key, got %v (%v)", keys, err)
	}
	if string(keys[0].Blob) != string(pub.Marshal()) {
		t.Fatal("agent holds a different key than the one it was given")
	}

	data := []byte("challenge")
	sig, err := client.Sign(pub, data)
	if err != nil {
		t.Fatalf("agent cannot sign: %v", err)
	}
	if err := pub.Verify(data, sig); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}
}

// The signing works end to end with the Go SSH client, the same way ssh would use it.
func TestAgentAuthenticatesAnSSHHandshake(t *testing.T) {
	pemBytes, pub := testKeyPEM(t)
	a, _ := StartAgent(pemBytes)
	defer a.Close()

	hostPub, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, _ := ssh.NewSignerFromKey(hostPriv)
	hostKey, _ := ssh.NewPublicKey(hostPub)

	serverCfg := &ssh.ServerConfig{PublicKeyCallback: func(c ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		if string(k.Marshal()) == string(pub.Marshal()) {
			return nil, nil
		}
		return nil, os.ErrPermission
	}}
	serverCfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		if sc, chans, reqs, err := ssh.NewServerConn(c, serverCfg); err == nil {
			go ssh.DiscardRequests(reqs)
			go func() {
				for range chans {
				}
			}()
			_ = sc
		}
	}()

	sock, err := net.Dial("unix", a.Socket())
	if err != nil {
		t.Fatal(err)
	}
	defer sock.Close()
	cfg := &ssh.ClientConfig{
		User:            "alice",
		Auth:            []ssh.AuthMethod{ssh.PublicKeysCallback(agent.NewClient(sock).Signers)},
		HostKeyCallback: ssh.FixedHostKey(hostKey),
	}
	client, err := ssh.Dial("tcp", ln.Addr().String(), cfg)
	if err != nil {
		t.Fatalf("handshake using the agent failed: %v", err)
	}
	client.Close()
}

func TestAgentSocketIsPrivateAndCleanedUp(t *testing.T) {
	pemBytes, _ := testKeyPEM(t)
	a, err := StartAgent(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(a.Socket())
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Windows has no Unix permission bits (access is governed by ACLs and the
	// per-user temp directory), so the mode check only makes sense elsewhere.
	if runtime.GOOS != "windows" {
		if info.Mode().Perm() != 0o700 {
			t.Fatalf("agent directory must be 0700, got %v", info.Mode().Perm())
		}
		sockInfo, err := os.Stat(a.Socket())
		if err != nil || sockInfo.Mode().Perm()&0o077 != 0 {
			t.Fatalf("agent socket must not be accessible to others: %v (%v)", sockInfo.Mode().Perm(), err)
		}
	}

	a.Close()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("agent directory still exists after Close")
	}
	if _, err := net.Dial("unix", a.Socket()); err == nil {
		t.Fatal("agent still reachable after Close")
	}
}

func TestAgentRejectsGarbage(t *testing.T) {
	if _, err := StartAgent([]byte("not a key")); err == nil {
		t.Fatal("garbage accepted as a private key")
	}
}

func TestSessionCloseIsIdempotentAndNilSafe(t *testing.T) {
	pemBytes, _ := testKeyPEM(t)
	a, _ := StartAgent(pemBytes)
	f, _ := os.CreateTemp("", "kh")
	f.Close()
	s := &Session{agent: a, knownHosts: f.Name()}
	s.Close()
	s.Close()
	if _, err := os.Stat(f.Name()); !os.IsNotExist(err) {
		t.Fatal("known_hosts file not removed")
	}
	var nilSession *Session
	nilSession.Close()
}

func TestSSHFSArguments(t *testing.T) {
	a := strings.Join(sshfsArgs("u@h:/data", "/mnt/x", "2201", "/tmp/a/agent.sock", "", "/tmp/kh", true), " ")
	for _, want := range []string{"-p 2201", "IdentityAgent=/tmp/a/agent.sock", "UserKnownHostsFile=/tmp/kh",
		"StrictHostKeyChecking=yes", "PasswordAuthentication=no", "reconnect"} {
		if !strings.Contains(a, want) {
			t.Fatalf("missing %q in %s", want, a)
		}
	}
	if strings.Contains(a, "IdentityFile") {
		t.Fatal("agent mode must not reference a key file")
	}
	if runtime.GOOS == "linux" && !strings.Contains(a, "dir_cache=no") {
		t.Fatalf("the directory cache must be off: %s", a)
	}
	w := strings.Join(sshfsArgs("u@h:/data", "/mnt/x", "2201", "", "/tmp/key", "/tmp/kh", false), " ")
	if !strings.Contains(w, "IdentityFile=/tmp/key") || strings.Contains(w, "IdentityAgent") || strings.Contains(w, "reconnect") {
		t.Fatalf("unexpected windows-style arguments: %s", w)
	}
}
