package syncer

import (
	"bufio"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// A file in the storage that cannot be decrypted (damaged on the server's disk, or changed by the server)
// gives a read error. rclone then stops the whole run and wants a full comparison. The client
// names the file, leaves it out of syncing from then on and carries on with the rest. The local copy is
// kept. The file comes back by itself when it can be read again (for example restored from the server's
// backup) or is gone from the storage; with ReplaceUnreadable the client deletes the damaged copy so that
// the local one is uploaded in its place.

// unreadableFile lists the left-out files (relative paths with "/", one per line) in the work folder.
const unreadableFile = "unreadable.txt"

// rclone logs a failed read as
//
//	ERROR : docs/a.txt: Failed to copy: read /mnt/volume/docs/a.txt: input/output error
//	ERROR : docs/a.txt: Failed to calculate src hash: hash: failed to read: read /mnt/volume/docs/a.txt: ...
var readErrorRe = regexp.MustCompile(`ERROR : (.+?): Failed to [^:]+:.*?\bread (.+?): `)

// unreadable returns the files in rclone's output that could not be read from the storage (remote).
// Failed reads of local files are not the storage's fault and are left to rclone.
func unreadable(output, remote string) []string {
	seen := map[string]bool{}
	var names []string
	slash := func(p string) string { return strings.ReplaceAll(p, `\`, "/") }
	prefix := strings.TrimSuffix(slash(remote), "/") + "/"
	for _, line := range strings.Split(output, "\n") {
		m := readErrorRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		name, path := m[1], slash(m[2])
		// Windows paths are not case sensitive
		if len(path) < len(prefix) || !strings.EqualFold(path[:len(prefix)], prefix) || path[len(prefix):] != name {
			continue
		}
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	return names
}

func (s *Syncer) unreadablePath() string { return filepath.Join(s.cfg.WorkDir, unreadableFile) }

// loadUnreadable reads the left-out files.
func (s *Syncer) loadUnreadable() []string {
	f, err := os.Open(s.unreadablePath())
	if err != nil {
		return nil
	}
	defer f.Close()
	var names []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if n := strings.TrimSpace(sc.Text()); n != "" {
			names = append(names, n)
		}
	}
	return names
}

func (s *Syncer) saveUnreadable(names []string) error {
	if len(names) == 0 {
		err := os.Remove(s.unreadablePath())
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	sort.Strings(names)
	return os.WriteFile(s.unreadablePath(), []byte(strings.Join(names, "\n")+"\n"), 0o600)
}

// excludeRule is an rclone filter rule that matches exactly this file: glob characters are escaped.
func excludeRule(name string) string {
	var b strings.Builder
	b.WriteString("/")
	for _, r := range name {
		if strings.ContainsRune(`\*?[]{}`, r) {
			b.WriteRune('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// writeExcludes writes the rclone exclude file for the left-out files and returns its path, or "" when
// there are none.
func (s *Syncer) writeExcludes(names []string) (string, error) {
	if len(names) == 0 {
		return "", nil
	}
	var b strings.Builder
	for _, n := range names {
		b.WriteString(excludeRule(n) + "\n")
	}
	p := filepath.Join(s.cfg.WorkDir, "unreadable.filter")
	return p, os.WriteFile(p, []byte(b.String()), 0o600)
}

// readable reports whether the file can be read in full, and whether it still exists.
func readable(path string) (ok, exists bool) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, false
	}
	if err != nil {
		return false, true
	}
	defer f.Close()
	_, err = io.Copy(io.Discard, f)
	return err == nil, true
}

// checkUnreadable looks at the left-out files again before a run and returns the ones still left out.
// A file that reads again, or is gone from the storage, is synchronised again (two different versions
// then become conflict copies, nothing is lost). With ReplaceUnreadable the damaged copy is deleted from
// the storage when there is a local one, which is then uploaded.
func (s *Syncer) checkUnreadable() ([]string, error) {
	names := s.loadUnreadable()
	var still []string
	for _, n := range names {
		remote := filepath.Join(s.cfg.Remote, filepath.FromSlash(n))
		ok, exists := readable(remote)
		switch {
		case ok:
			s.warn("%s can be read in your storage again and is synchronised again.", n)
			continue
		case !exists:
			s.warn("The damaged %s is gone from your storage; your local copy is uploaded.", n)
			continue
		case s.cfg.ReplaceUnreadable:
			if _, err := os.Stat(filepath.Join(s.cfg.Local, filepath.FromSlash(n))); err == nil {
				if err := os.Remove(remote); err != nil {
					s.warn("Could not delete the damaged %s from your storage: %v", n, err)
				} else {
					s.warn("Deleted the damaged %s from your storage; your local copy is uploaded in its place.", n)
					continue
				}
			}
		}
		still = append(still, n)
	}
	if len(still) != len(names) {
		if err := s.saveUnreadable(still); err != nil {
			return names, err
		}
	}
	return still, nil
}

// addUnreadable adds newly found files to the left-out list and tells the user about each one.
func (s *Syncer) addUnreadable(found []string) error {
	names := s.loadUnreadable()
	have := map[string]bool{}
	for _, n := range names {
		have[n] = true
	}
	for _, n := range found {
		if have[n] {
			continue
		}
		names = append(names, n)
		s.warn("%s in your storage cannot be read: the server's copy is damaged or was changed. Your local "+
			"copy (if any) is kept and the file is left out of syncing until the server's copy can be read "+
			"again. To replace it with your local copy, connect once with `cryptclient connect --sync "+
			"--replace-unreadable`.", n)
	}
	return s.saveUnreadable(names)
}
