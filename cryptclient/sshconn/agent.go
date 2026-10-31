package sshconn

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Agent is a minimal in-process ssh-agent holding the user's private key.
//
// sshfs reconnects on its own after a network drop, and every reconnect needs to
// authenticate again. A key file deleted right after sshfs started (what Mount used to
// do) makes reconnecting impossible, and keeping it on disk for the whole session would
// leave the decrypted key there. The agent keeps the key in this process's memory only:
// it is served on a Unix socket inside a private (0700) directory, readable by this
// user alone, and disappears when the client exits.
type Agent struct {
	dir      string
	sockPath string
	ln       net.Listener
	wg       sync.WaitGroup
}

// StartAgent loads a PEM/OpenSSH private key into a new agent and starts serving it.
func StartAgent(pemBytes []byte) (*Agent, error) {
	key, err := ssh.ParseRawPrivateKey(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}
	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: key, Comment: "cryptclient"}); err != nil {
		return nil, fmt.Errorf("adding key to agent: %w", err)
	}

	dir, err := os.MkdirTemp("", "cryptagent-")
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	sock := filepath.Join(dir, "agent.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		os.RemoveAll(dir)
		return nil, fmt.Errorf("listening on agent socket: %w", err)
	}
	// Belt and braces: the directory already keeps others out
	os.Chmod(sock, 0o600)

	a := &Agent{dir: dir, sockPath: sock, ln: ln}
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			a.wg.Add(1)
			go func() {
				defer a.wg.Done()
				defer conn.Close()
				agent.ServeAgent(keyring, conn)
			}()
		}
	}()
	return a, nil
}

// Socket is the path ssh should use as IdentityAgent.
func (a *Agent) Socket() string { return a.sockPath }

// Close stops the agent, removes the socket and drops the key.
func (a *Agent) Close() {
	a.ln.Close()
	os.RemoveAll(a.dir)
}
