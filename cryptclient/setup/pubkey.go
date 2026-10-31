package setup

import (
	"strings"

	"golang.org/x/crypto/ssh"
)

func publicKey(pem []byte) (string, error) {
	signer, err := ssh.ParsePrivateKey(pem)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))), nil
}
