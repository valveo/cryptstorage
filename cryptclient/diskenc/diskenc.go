// Package diskenc tells whether the disk that holds a folder is encrypted (BitLocker, LUKS, FileVault).
//
// CryptStorage does not encrypt the synchronised folder itself: the server only ever holds ciphertext, and the
// device protects what is stored on it (docs/design-features.md section 5). The client checks the disk so
// users do not read "encrypted storage" as "my laptop is protected". The check is best effort and
// needs no administrator rights; when it cannot tell, it says so instead of guessing.
package diskenc

import (
	"os"
	"path/filepath"
)

// State is the result of a check.
type State int

const (
	Unknown      State = iota // could not tell, for example on a network or FUSE file system
	Encrypted                 // the folder's disk is encrypted
	NotEncrypted              // no disk encryption found under the folder
)

func (s State) String() string {
	switch s {
	case Encrypted:
		return "encrypted"
	case NotEncrypted:
		return "not encrypted"
	}
	return "unknown"
}

// Result is a State with a short reason the user can read, such as "LUKS (dm-crypt)" or "BitLocker off".
type Result struct {
	State  State
	Detail string
}

// Check looks at the disk that holds dir. dir need not exist yet; its nearest existing parent is used.
func Check(dir string) Result {
	p, err := existingParent(dir)
	if err != nil {
		return Result{Unknown, err.Error()}
	}
	return check(p)
}

func existingParent(dir string) (string, error) {
	p, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	for {
		if r, err := filepath.EvalSymlinks(p); err == nil {
			return r, nil
		}
		parent := filepath.Dir(p)
		if parent == p {
			return "", os.ErrNotExist
		}
		p = parent
	}
}

// Warning is the text to show when the disk is not encrypted, or "" when there is nothing to warn about.
func Warning(dir string, r Result) string {
	if r.State != NotEncrypted {
		return ""
	}
	return "Your synchronised folder " + dir + " is on a disk without encryption (" + r.Detail + "). " +
		"CryptStorage keeps your files encrypted on the server, but the copies in this folder are readable " +
		"by anyone who gets this computer or its disk. Turn on " + Advice() + "."
}
