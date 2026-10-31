// Package syncer keeps a local folder synchronised with the unlocked volume using rclone bisync
// (docs/design-features.md section 5.1).
//
// Each run takes the volume's sync lock on the server first: rclone's own lock only covers one
// computer, and two computers syncing at the same moment lose files without a conflict copy. The
// lock is renewed while rclone runs; if it cannot be renewed, rclone is stopped.
//
// Local files that a run deletes or overwrites because of the storage go to a trash folder first (// trash.go). A file in the storage that cannot be read is left out instead of stopping everything (// unreadable.go).
package syncer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"cryptclient/apiclient"
	"cryptclient/nowindow"
)

// Locker is the server's sync lock (apiclient.Client).
type Locker interface {
	AcquireSyncLock(holder, holderName string) (time.Duration, error)
	ReleaseSyncLock(holder string) error
}

// Runner runs rclone with the given arguments and returns its combined output.
type Runner func(ctx context.Context, args []string) ([]byte, error)

// Config describes one synchronised folder.
type Config struct {
	Rclone          string        // path of the rclone program
	Local           string        // the user's local folder
	Remote          string        // the unlocked volume (plaintext mount point)
	WorkDir         string        // rclone's state for this pair (listings), kept between runs
	Holder          string        // id of this installation, for the server lock
	HolderName      string        // shown to another device that has to wait
	Interval        time.Duration // time between runs in Loop
	AllowMassDelete bool          // pass --force once: the user confirmed deleting more than half the files
	// ReplaceUnreadable deletes a storage file that cannot be read when there is a local copy, so the
	// local one is uploaded in its place (the user asked for it)
	ReplaceUnreadable bool
	Log               func(format string, args ...any)
	// Warn gets what the user should see even when the log is not shown (the tray); Log when nil
	Warn func(string)
}

type Syncer struct {
	cfg  Config
	lock Locker
	run  Runner
}

// New returns a Syncer that runs the real rclone.
func New(cfg Config, lock Locker) *Syncer {
	if runtime.GOOS == "windows" && len(cfg.Remote) == 2 && cfg.Remote[1] == ':' {
		cfg.Remote += `\` // "S:" alone would mean the current directory on drive S
	}
	s := &Syncer{cfg: cfg, lock: lock}
	s.run = func(ctx context.Context, args []string) ([]byte, error) {
		return nowindow.CommandContext(ctx, cfg.Rclone, args...).CombinedOutput()
	}
	return s
}

func (s *Syncer) log(format string, args ...any) {
	if s.cfg.Log != nil {
		s.cfg.Log(format, args...)
	}
}

func (s *Syncer) warn(format string, args ...any) {
	if s.cfg.Warn != nil {
		s.cfg.Warn(fmt.Sprintf(format, args...))
		return
	}
	s.log(format, args...)
}

// ErrLocalNotEmpty means the first sync would merge an existing local folder into the volume.
var ErrLocalNotEmpty = errors.New("the local folder is not empty; the first synchronisation needs an empty or new folder")

// ErrTooManyDeletes means more than half of the files were deleted on one side. rclone stops rather
// than spread what may be an accident; the user confirms with AllowMassDelete.
var ErrTooManyDeletes = errors.New("more than half of the files were deleted on one side, so nothing was synchronised (a safety stop)")

// ErrNeedsResync means rclone lost track of the folder pair and refuses to continue on its own.
var ErrNeedsResync = errors.New("synchronisation stopped: rclone needs a full comparison (resync) to continue safely")

// FirstRun reports whether this pair has never been synchronised (no listings kept yet).
func (s *Syncer) FirstRun() bool {
	m, _ := filepath.Glob(filepath.Join(s.cfg.WorkDir, "*.path1.lst"))
	return len(m) == 0 && !s.lostListings()
}

// lostListings reports whether rclone set its listings aside after a failed run (as .lst-err, keeping
// .lst-old): the pair was synchronised before, but rclone will only go on after a full comparison.
func (s *Syncer) lostListings() bool {
	cur, _ := filepath.Glob(filepath.Join(s.cfg.WorkDir, "*.path1.lst"))
	old, _ := filepath.Glob(filepath.Join(s.cfg.WorkDir, "*.path1.lst-*"))
	return len(cur) == 0 && len(old) > 0
}

// run describes one rclone bisync run.
type run struct {
	resync     bool
	resyncMode string // with resync: which side wins where both have the file ("" = rclone's default, path1)
	trash      string // --backup-dir1
	excludes   string // --exclude-from, the unreadable files
}

// args builds the bisync command line. The options are the ones the spike showed to be needed:
// --modify-window because SSHFS reports whole seconds, --slow-hash-sync-only so checksums are read
// only for files about to be copied, not for every file on every run.
func (s *Syncer) args(r run) []string {
	a := []string{"bisync", s.cfg.Local, s.cfg.Remote,
		"--workdir", s.cfg.WorkDir,
		"--create-empty-src-dirs",
		"--compare", "size,modtime,checksum", "--slow-hash-sync-only",
		"--modify-window", "1s",
		"--resilient", "--recover", "--max-lock", "2m",
		"--conflict-resolve", "none", "--conflict-loser", "num",
		// The canary proves the recovery code opens the volume; it must never be deleted from here
		"--exclude", "/.secdisk-canary",
		"--exclude", "/" + TrashName + "/**",
		"--log-level", "NOTICE", "--color", "NEVER",
	}
	if r.trash != "" {
		a = append(a, "--backup-dir1", r.trash)
	}
	if r.excludes != "" {
		a = append(a, "--exclude-from", r.excludes)
	}
	if r.resync {
		a = append(a, "--resync")
		if r.resyncMode != "" {
			a = append(a, "--resync-mode", r.resyncMode)
		}
	}
	if s.cfg.AllowMassDelete {
		a = append(a, "--force")
	}
	return a
}

// Once runs one synchronisation under the server lock. It waits while another device holds the lock.
func (s *Syncer) Once(ctx context.Context) error {
	resync := s.FirstRun()
	if resync {
		if err := os.MkdirAll(s.cfg.Local, 0o700); err != nil {
			return err
		}
		if entries, err := os.ReadDir(s.cfg.Local); err != nil {
			return err
		} else if len(entries) > 0 {
			return ErrLocalNotEmpty
		}
	}
	if err := os.MkdirAll(s.cfg.WorkDir, 0o700); err != nil {
		return err
	}
	ttl, err := s.acquire(ctx)
	if err != nil {
		return err
	}
	defer func() {
		if err := s.lock.ReleaseSyncLock(s.cfg.Holder); err != nil {
			s.log("Could not release the sync lock (it lapses by itself): %v", err)
		}
	}()
	if err := s.ensureMarker(); err != nil {
		return err
	}
	s.clearStaleLocks()
	s.cleanTrash(time.Now())
	left, err := s.checkUnreadable()
	if err != nil {
		return err
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	lost := make(chan error, 1)
	go s.renew(runCtx, ttl, cancel, lost)

	r := run{resync: resync, trash: s.newTrashRun()}
	defer s.reportTrash(r.trash) // after both runs below, and after files are put back
	if s.lostListings() {
		// An earlier run stopped half way (the client was ended, or the run failed): compare in full,
		// as below, instead of asking the user to start the folder again
		s.log("The last synchronisation did not finish; comparing the folder with your storage in full.")
		r.resync, r.resyncMode = true, "newer"
	}
	if r.excludes, err = s.writeExcludes(left); err != nil {
		return err
	}
	err = s.bisync(runCtx, ctx, lost, r)
	var unread *unreadableError
	switch {
	case errors.As(err, &unread):
		// Files in the storage could not be read: leave them out from now on
		if err := s.addUnreadable(unread.names); err != nil {
			return err
		}
		s.restoreFromTrash(r.trash, unread.names)
	case errors.Is(err, ErrNeedsResync) && !r.resync:
	default:
		return err
	}
	// rclone stopped and set its listings aside. Compare both sides in full: the newer version wins where
	// they differ, a local file replaced that way goes to the trash, and files deleted since the last run
	// may come back. Nothing is lost.
	r = run{resync: true, resyncMode: "newer", trash: r.trash}
	if r.excludes, err = s.writeExcludes(s.loadUnreadable()); err != nil {
		return err
	}
	s.log("Comparing the folder with your storage in full, without the files that cannot be read.")
	if err := s.bisync(runCtx, ctx, lost, r); err != nil {
		if errors.As(err, &unread) {
			s.addUnreadable(unread.names)
			return fmt.Errorf("%w\n%s", ErrNeedsResync, unread.output)
		}
		return err
	}
	return nil
}

// unreadableError is a run that rclone stopped because files in the storage could not be read.
type unreadableError struct {
	names  []string
	output string
}

func (e *unreadableError) Error() string {
	return "files in the storage cannot be read: " + strings.Join(e.names, ", ")
}

// bisync runs rclone once and turns its result into the errors above.
func (s *Syncer) bisync(runCtx, ctx context.Context, lost <-chan error, r run) error {
	out, err := s.run(runCtx, s.args(r))
	select {
	case lerr := <-lost:
		return fmt.Errorf("the sync lock was lost, synchronisation stopped: %w", lerr)
	default:
	}
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		text := string(out)
		if strings.Contains(text, "too many deletes") {
			return ErrTooManyDeletes
		}
		if strings.Contains(text, "Must run --resync") {
			if names := unreadable(text, s.cfg.Remote); len(names) > 0 {
				return &unreadableError{names: names, output: tail(text, 10)}
			}
			return fmt.Errorf("%w\n%s", ErrNeedsResync, tail(text, 10))
		}
		return fmt.Errorf("rclone: %v\n%s", err, tail(text, 10))
	}
	if bytes.Contains(out, []byte("changed in both paths")) {
		s.log("Some files were changed on two devices; both versions were kept (names ending in .conflict1, .conflict2).")
	}
	return nil
}

// MarkerName is a small file kept in the volume's root and synchronised like any other. rclone
// refuses to sync against an empty listing (a safety check against a vanished folder), so a new,
// empty volume would never get past its first run without it.
//
// The .secdisk- names here and in trash.go are from the product's earlier name and stay: volumes and
// folders already synchronised have them.
const MarkerName = ".secdisk-sync"

func (s *Syncer) ensureMarker() error {
	p := filepath.Join(s.cfg.Remote, MarkerName)
	if _, err := os.Stat(p); err == nil {
		return nil
	}
	text := "This file keeps the synchronised folder working. Deleting it does no harm; it comes back.\n"
	return os.WriteFile(p, []byte(text), 0o600)
}

// acquire takes the lock, waiting while another device holds it.
func (s *Syncer) acquire(ctx context.Context) (time.Duration, error) {
	told := false
	for {
		ttl, err := s.lock.AcquireSyncLock(s.cfg.Holder, s.cfg.HolderName)
		if err == nil {
			return ttl, nil
		}
		var locked *apiclient.SyncLockedError
		if !errors.As(err, &locked) {
			return 0, fmt.Errorf("could not take the sync lock: %w", err)
		}
		if !told {
			s.log("Waiting: %v", locked)
			told = true
		}
		wait := locked.ExpiresIn
		if wait <= 0 || wait > 5*time.Second {
			wait = 5 * time.Second
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(wait):
		}
	}
}

// renew keeps the lock while rclone runs. A failed renewal stops the run (cancel), because another
// device may take a lapsed lock.
func (s *Syncer) renew(ctx context.Context, ttl time.Duration, cancel func(), lost chan<- error) {
	every := ttl / 3
	if every <= 0 {
		every = 30 * time.Second
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := s.lock.AcquireSyncLock(s.cfg.Holder, s.cfg.HolderName); err != nil {
				lost <- err
				cancel()
				return
			}
		}
	}
}

// Loop runs Once now and then every Interval until ctx ends. Errors are logged; a refusal that needs
// the user (ErrLocalNotEmpty, ErrNeedsResync, ErrTooManyDeletes) ends the loop and is returned.
func (s *Syncer) Loop(ctx context.Context) error {
	for {
		err := s.Once(ctx)
		switch {
		case ctx.Err() != nil:
			return nil
		case errors.Is(err, ErrLocalNotEmpty), errors.Is(err, ErrNeedsResync), errors.Is(err, ErrTooManyDeletes):
			return err
		case err != nil:
			s.log("Synchronisation failed, trying again in %s: %v", s.cfg.Interval, err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(s.cfg.Interval):
		}
	}
}

func tail(text string, lines int) string {
	parts := strings.Split(strings.TrimRight(text, "\n"), "\n")
	if len(parts) > lines {
		parts = parts[len(parts)-lines:]
	}
	return strings.Join(parts, "\n")
}
