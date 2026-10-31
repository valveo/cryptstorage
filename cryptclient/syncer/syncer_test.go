package syncer

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"cryptclient/apiclient"
	"cryptclient/deps"
)

// fakeLock is a server lock shared by several syncers, like the API's.
type fakeLock struct {
	mu       sync.Mutex
	holder   string
	until    time.Time
	ttl      time.Duration
	acquired []string
	released []string
	failNext error
}

func (l *fakeLock) AcquireSyncLock(holder, name string) (time.Duration, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.failNext != nil {
		err := l.failNext
		l.failNext = nil
		return 0, err
	}
	if l.holder != "" && l.holder != holder && time.Now().Before(l.until) {
		return 0, &apiclient.SyncLockedError{HolderName: l.holder, ExpiresIn: time.Until(l.until)}
	}
	l.holder, l.until = holder, time.Now().Add(l.ttl)
	l.acquired = append(l.acquired, holder)
	return l.ttl, nil
}

func (l *fakeLock) ReleaseSyncLock(holder string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.holder == holder {
		l.holder = ""
	}
	l.released = append(l.released, holder)
	return nil
}

func testSyncer(t *testing.T, lock Locker, run Runner) *Syncer {
	dir := t.TempDir()
	s := New(Config{
		Local: filepath.Join(dir, "local"), Remote: filepath.Join(dir, "remote"), WorkDir: filepath.Join(dir, "work"),
		Holder: "holder-0123456789abcdef", HolderName: "test", Interval: 10 * time.Millisecond,
	}, lock)
	s.run = run
	os.MkdirAll(s.cfg.Remote, 0o700)
	return s
}

func TestFirstRunResyncsIntoAnEmptyFolder(t *testing.T) {
	var got []string
	s := testSyncer(t, &fakeLock{ttl: time.Minute}, func(ctx context.Context, args []string) ([]byte, error) {
		got = args
		return nil, nil
	})
	if err := s.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(got, " "), "--resync") {
		t.Fatalf("first run must resync: %v", got)
	}
	// Later runs do not, once rclone has kept its listings
	os.WriteFile(filepath.Join(s.cfg.WorkDir, "x.path1.lst"), nil, 0o600)
	s.Once(context.Background())
	if strings.Contains(strings.Join(got, " "), "--resync") {
		t.Fatalf("second run must not resync: %v", got)
	}
}

func TestFirstRunRefusesANonEmptyFolder(t *testing.T) {
	ran := false
	s := testSyncer(t, &fakeLock{ttl: time.Minute}, func(ctx context.Context, args []string) ([]byte, error) {
		ran = true
		return nil, nil
	})
	os.MkdirAll(s.cfg.Local, 0o700)
	os.WriteFile(filepath.Join(s.cfg.Local, "old.txt"), []byte("x"), 0o600)
	if err := s.Once(context.Background()); !errors.Is(err, ErrLocalNotEmpty) {
		t.Fatalf("got %v", err)
	}
	if ran {
		t.Fatal("rclone must not run")
	}
}

func TestLockIsReleasedAfterSuccessAndFailure(t *testing.T) {
	lock := &fakeLock{ttl: time.Minute}
	fail := errors.New("exit status 1")
	s := testSyncer(t, lock, func(ctx context.Context, args []string) ([]byte, error) { return []byte("boom"), fail })
	if err := s.Once(context.Background()); err == nil {
		t.Fatal("expected the rclone failure")
	}
	if len(lock.released) != 1 || lock.holder != "" {
		t.Fatalf("lock not released: %+v", lock)
	}
}

func TestWaitsForAnotherDevice(t *testing.T) {
	lock := &fakeLock{ttl: time.Minute, holder: "other-device-0123456789", until: time.Now().Add(300 * time.Millisecond)}
	start := time.Now()
	s := testSyncer(t, lock, func(ctx context.Context, args []string) ([]byte, error) { return nil, nil })
	if err := s.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) < 250*time.Millisecond {
		t.Fatal("did not wait for the other device's lock")
	}
}

func TestWaitingEndsWithTheContext(t *testing.T) {
	lock := &fakeLock{ttl: time.Minute, holder: "other-device-0123456789", until: time.Now().Add(time.Hour)}
	s := testSyncer(t, lock, func(ctx context.Context, args []string) ([]byte, error) { return nil, nil })
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := s.Once(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
}

func TestLostLockStopsRclone(t *testing.T) {
	lock := &fakeLock{ttl: 90 * time.Millisecond}
	s := testSyncer(t, lock, func(ctx context.Context, args []string) ([]byte, error) {
		lock.mu.Lock()
		lock.failNext = errors.New("server unreachable") // the first renewal fails
		lock.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(5 * time.Second):
			return nil, nil
		}
	})
	err := s.Once(context.Background())
	if err == nil || !strings.Contains(err.Error(), "lock was lost") {
		t.Fatalf("got %v", err)
	}
}

func TestTooManyDeletesStopsTheLoop(t *testing.T) {
	var got []string
	s := testSyncer(t, &fakeLock{ttl: time.Minute}, func(ctx context.Context, args []string) ([]byte, error) {
		got = args
		return []byte("ERROR : Safety abort: too many deletes (>50%, 2 of 3)"), errors.New("exit status 1")
	})
	os.MkdirAll(s.cfg.WorkDir, 0o700)
	os.WriteFile(filepath.Join(s.cfg.WorkDir, "x.path1.lst"), nil, 0o600)
	if err := s.Loop(context.Background()); !errors.Is(err, ErrTooManyDeletes) {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(strings.Join(got, " "), "--force") {
		t.Fatal("--force only when the user confirmed")
	}
	s.cfg.AllowMassDelete = true
	s.Once(context.Background())
	if !strings.Contains(strings.Join(got, " "), "--force") {
		t.Fatal("confirmed mass delete must pass --force")
	}
}

func TestNeedsResyncIsReported(t *testing.T) {
	s := testSyncer(t, &fakeLock{ttl: time.Minute}, func(ctx context.Context, args []string) ([]byte, error) {
		return []byte("ERROR : Bisync aborted. Must run --resync to recover."), errors.New("exit status 7")
	})
	os.MkdirAll(s.cfg.WorkDir, 0o700)
	os.WriteFile(filepath.Join(s.cfg.WorkDir, "x.path1.lst"), nil, 0o600)
	if err := s.Loop(context.Background()); !errors.Is(err, ErrNeedsResync) {
		t.Fatalf("got %v", err)
	}
}

// With the real rclone (skipped if none is installed): two devices, one volume, both syncing at once.
func TestTwoDevicesWithRealRclone(t *testing.T) {
	rclone := os.Getenv("CRYPTCLIENT_TEST_RCLONE")
	if rclone == "" {
		var err error
		if rclone, err = deps.RclonePath(); err != nil {
			t.Skip("no rclone new enough for bisync installed")
		}
	}
	dir := t.TempDir()
	remote := filepath.Join(dir, "volume")
	os.MkdirAll(remote, 0o700)
	lock := &fakeLock{ttl: time.Minute}
	dev := func(name string) *Syncer {
		return New(Config{Rclone: rclone, Local: filepath.Join(dir, name), Remote: remote,
			WorkDir: filepath.Join(dir, name+"-work"), Holder: name + "-0123456789abcdef", HolderName: name,
			Interval: time.Second}, lock)
	}
	a, b := dev("a"), dev("b")
	ctx := context.Background()
	for _, s := range []*Syncer{a, b} {
		if err := s.Once(ctx); err != nil {
			t.Fatal(err)
		}
	}
	// Enough other files that removing the conflict copies below stays under rclone's 50 % delete stop
	for i := 0; i < 10; i++ {
		os.WriteFile(filepath.Join(dir, "a", fmt.Sprintf("keep%d.txt", i)), []byte("x"), 0o600)
	}
	a.Once(ctx)
	b.Once(ctx)
	for i := 0; i < 3; i++ {
		os.WriteFile(filepath.Join(dir, "a", "same.txt"), []byte("from a, longer text"), 0o600)
		os.WriteFile(filepath.Join(dir, "b", "same.txt"), []byte("from b"), 0o600)
		var wg sync.WaitGroup
		for _, s := range []*Syncer{a, b} {
			wg.Add(1)
			go func(s *Syncer) {
				defer wg.Done()
				if err := s.Once(ctx); err != nil {
					t.Error(err)
				}
			}(s)
		}
		wg.Wait()
		a.Once(ctx)
		b.Once(ctx)
		a.Once(ctx)
		for _, d := range []string{"a", "b"} {
			names, _ := filepath.Glob(filepath.Join(dir, d, "same.txt*"))
			var both []string
			for _, n := range names {
				c, _ := os.ReadFile(n)
				both = append(both, string(c))
			}
			j := strings.Join(both, "|")
			if !strings.Contains(j, "from a") || !strings.Contains(j, "from b") {
				t.Fatalf("round %d, device %s lost a version: %v", i, d, both)
			}
		}
		for _, d := range []string{"a", "b"} {
			names, _ := filepath.Glob(filepath.Join(dir, d, "same.txt*"))
			for _, n := range names {
				os.Remove(n)
			}
		}
		a.Once(ctx)
		b.Once(ctx)
	}
}

// rclone's own lines for a file that the storage cannot decrypt (gocryptfs answers EIO), and one for a
// local file that cannot be read, which is not the storage's fault.
const eioOutput = `2026/10/29 10:41:05 ERROR : flipped.txt: Failed to calculate src hash: hash: failed to read: read /mnt/vol/flipped.txt: input/output error
2026/10/29 10:41:05 ERROR : docs/a [1].txt: Failed to copy: read /mnt/vol/docs/a [1].txt: input/output error
2026/10/29 10:41:05 ERROR : flipped.txt: Failed to copy: read /mnt/vol/flipped.txt: input/output error
2026/10/29 10:41:05 ERROR : mine.txt: Failed to copy: read /home/u/secdisk/mine.txt: permission denied
2026/10/29 10:41:05 ERROR : Bisync critical error: read /mnt/vol/flipped.txt: input/output error
2026/10/29 10:41:05 ERROR : Bisync aborted. Must run --resync to recover.`

func TestUnreadableNamesTheStorageFiles(t *testing.T) {
	got := unreadable(eioOutput, "/mnt/vol/")
	want := []string{"flipped.txt", "docs/a [1].txt"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got %q, want %q", got, want)
	}
	win := `ERROR : x.txt: Failed to copy: read S:\x.txt: The request could not be performed because of an I/O device error.`
	if got := unreadable(win, `s:\`); len(got) != 1 || got[0] != "x.txt" {
		t.Fatalf("Windows path: got %q", got)
	}
	if got := excludeRule("docs/a [1]*.txt"); got != `/docs/a \[1\]\*.txt` {
		t.Fatalf("rule %s", got)
	}
}

func hasArgs(args []string, want ...string) bool {
	return strings.Contains(" "+strings.Join(args, " ")+" ", " "+strings.Join(want, " ")+" ")
}

// A file that cannot be read: named, left out, and the rest is compared in full straight away.
func TestUnreadableFileIsLeftOut(t *testing.T) {
	var calls [][]string
	var s *Syncer
	s = testSyncer(t, &fakeLock{ttl: time.Minute}, func(ctx context.Context, args []string) ([]byte, error) {
		calls = append(calls, args)
		if len(calls) == 1 {
			return []byte(strings.ReplaceAll(eioOutput, "/mnt/vol", s.cfg.Remote)), errors.New("exit status 7")
		}
		return nil, nil
	})
	var warned []string
	s.cfg.Warn = func(m string) { warned = append(warned, m) }
	os.MkdirAll(s.cfg.WorkDir, 0o700)
	os.WriteFile(filepath.Join(s.cfg.WorkDir, "x.path1.lst"), nil, 0o600)
	// still unreadable at the next run: a directory cannot be read as a file
	os.MkdirAll(filepath.Join(s.cfg.Remote, "flipped.txt"), 0o700)
	if err := s.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || !hasArgs(calls[1], "--resync", "--resync-mode", "newer") || hasArgs(calls[0], "--resync") {
		t.Fatalf("calls: %q", calls)
	}
	if !hasArgs(calls[1], "--exclude-from", filepath.Join(s.cfg.WorkDir, "unreadable.filter")) {
		t.Fatalf("the full comparison must leave the files out: %q", calls[1])
	}
	rules, _ := os.ReadFile(filepath.Join(s.cfg.WorkDir, "unreadable.filter"))
	if string(rules) != "/docs/a \\[1\\].txt\n/flipped.txt\n" {
		t.Fatalf("rules %q", rules)
	}
	if len(warned) != 2 || !strings.Contains(warned[0], "flipped.txt") || !strings.Contains(warned[0], "--replace-unreadable") {
		t.Fatalf("warned %q", warned)
	}

	// Next run: docs/a [1].txt is gone from the storage and comes back into syncing; flipped.txt stays out
	warned = nil
	if err := s.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	last := calls[len(calls)-1]
	if hasArgs(last, "--resync") || !hasArgs(last, "--exclude-from") {
		t.Fatalf("a normal run that still leaves flipped.txt out: %q", last)
	}
	if left := s.loadUnreadable(); len(left) != 1 || left[0] != "flipped.txt" {
		t.Fatalf("left out: %q", left)
	}
	if len(warned) != 1 || !strings.Contains(warned[0], "docs/a [1].txt") {
		t.Fatalf("warned %q", warned)
	}

	// The user asks to replace it with the local copy: the damaged one is deleted from the storage
	os.MkdirAll(s.cfg.Local, 0o700)
	os.WriteFile(filepath.Join(s.cfg.Local, "flipped.txt"), []byte("mine"), 0o600)
	s.cfg.ReplaceUnreadable = true
	if err := s.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(s.cfg.Remote, "flipped.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the damaged copy is still there: %v", err)
	}
	if hasArgs(calls[len(calls)-1], "--exclude-from") || len(s.loadUnreadable()) != 0 {
		t.Fatal("nothing should be left out any more")
	}
}

// rclone set its listings aside after a failed or interrupted run: a full comparison, not a refusal.
func TestLostListingsAreRecovered(t *testing.T) {
	var got []string
	s := testSyncer(t, &fakeLock{ttl: time.Minute}, func(ctx context.Context, args []string) ([]byte, error) {
		got = args
		return nil, nil
	})
	os.MkdirAll(s.cfg.WorkDir, 0o700)
	os.WriteFile(filepath.Join(s.cfg.WorkDir, "x.path1.lst-err"), nil, 0o600)
	os.MkdirAll(s.cfg.Local, 0o700)
	os.WriteFile(filepath.Join(s.cfg.Local, "old.txt"), []byte("x"), 0o600)
	if s.FirstRun() {
		t.Fatal("not a first run")
	}
	if err := s.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !hasArgs(got, "--resync", "--resync-mode", "newer") {
		t.Fatalf("args %q", got)
	}
}

func TestTrash(t *testing.T) {
	var got []string
	s := testSyncer(t, &fakeLock{ttl: time.Minute}, func(ctx context.Context, args []string) ([]byte, error) {
		got = args
		return nil, nil
	})
	s.Once(context.Background())
	i := 0
	for i < len(got) && got[i] != "--backup-dir1" {
		i++
	}
	if i+1 >= len(got) || filepath.Dir(got[i+1]) != filepath.Join(s.cfg.Local, TrashName) {
		t.Fatalf("no trash for the local side: %q", got)
	}
	if !hasArgs(got, "--exclude", "/"+TrashName+"/**") {
		t.Fatalf("the trash must not be synchronised: %q", got)
	}
	now := time.Now()
	old := filepath.Join(s.trashRoot(), now.Add(-TrashKeep-time.Hour).Format(trashStamp))
	recent := filepath.Join(s.trashRoot(), now.Add(-time.Hour).Format(trashStamp))
	for _, d := range []string{old, recent} {
		os.MkdirAll(d, 0o700)
		os.WriteFile(filepath.Join(d, "f.txt"), []byte("x"), 0o600)
	}
	s.cleanTrash(now)
	if _, err := os.Stat(old); err == nil {
		t.Fatal("old trash kept")
	}
	if _, err := os.Stat(recent); err != nil {
		t.Fatal("recent trash removed")
	}
	os.RemoveAll(recent)
	s.cleanTrash(now)
	if _, err := os.Stat(s.trashRoot()); err == nil {
		t.Fatal("an empty trash folder is left behind")
	}
}

// With the real rclone: a file deleted and one replaced in the storage reach the local folder, and the
// local versions end up in the trash.
func TestTrashWithRealRclone(t *testing.T) {
	rclone := os.Getenv("CRYPTCLIENT_TEST_RCLONE")
	if rclone == "" {
		var err error
		if rclone, err = deps.RclonePath(); err != nil {
			t.Skip("no rclone new enough for bisync installed")
		}
	}
	dir := t.TempDir()
	remote := filepath.Join(dir, "volume")
	os.MkdirAll(remote, 0o700)
	var warned []string
	s := New(Config{Rclone: rclone, Local: filepath.Join(dir, "local"), Remote: remote,
		WorkDir: filepath.Join(dir, "work"), Holder: "a-0123456789abcdef", HolderName: "a", Interval: time.Second,
		Warn: func(m string) { warned = append(warned, m) }}, &fakeLock{ttl: time.Minute})
	ctx := context.Background()
	for i := 0; i < 6; i++ {
		os.WriteFile(filepath.Join(remote, fmt.Sprintf("keep%d.txt", i)), []byte("x"), 0o600)
	}
	os.WriteFile(filepath.Join(remote, "gone.txt"), []byte("deleted on the server"), 0o600)
	os.WriteFile(filepath.Join(remote, "old.txt"), []byte("version 2"), 0o600)
	if err := s.Once(ctx); err != nil {
		t.Fatal(err)
	}
	os.Remove(filepath.Join(remote, "gone.txt"))
	os.WriteFile(filepath.Join(remote, "old.txt"), []byte("version 1"), 0o600)
	future := time.Now().Add(5 * time.Second)
	os.Chtimes(filepath.Join(remote, "old.txt"), future, future)
	if err := s.Once(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "local", "gone.txt")); err == nil {
		t.Fatal("the deletion did not reach the local folder")
	}
	runs, _ := filepath.Glob(filepath.Join(dir, "local", TrashName, "*"))
	if len(runs) != 1 {
		t.Fatalf("trash runs: %v", runs)
	}
	for name, want := range map[string]string{"gone.txt": "deleted on the server", "old.txt": "version 2"} {
		if b, _ := os.ReadFile(filepath.Join(runs[0], name)); string(b) != want {
			t.Errorf("trash %s: %q", name, b)
		}
	}
	if len(warned) != 1 || !strings.Contains(warned[0], "2 local file(s)") {
		t.Fatalf("warned %q", warned)
	}
	if _, err := os.Stat(filepath.Join(remote, TrashName)); err == nil {
		t.Fatal("the trash reached the storage")
	}
	// The next run leaves the trash alone
	if err := s.Once(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(runs[0], "old.txt")); err != nil {
		t.Fatal(err)
	}
}
