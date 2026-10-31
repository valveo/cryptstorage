package main

// The synchronised folder (docs/design-features.md section 5.1): while connected, a local folder is
// kept in step with the volume by rclone bisync, under the server's sync lock. Turned on with
// `connect --sync` or CRYPTCLIENT_SYNC_DIR; removing the stick stops syncing and leaves the folder.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"cryptclient/apiclient"
	"cryptclient/appdir"
	"cryptclient/deps"
	"cryptclient/diskenc"
	"cryptclient/syncer"
)

// syncDir returns the folder to synchronise, or "" when syncing is off.
func syncDir() string {
	if d := os.Getenv("CRYPTCLIENT_SYNC_DIR"); d != "" {
		return d
	}
	if hasArg("--sync") {
		home, _ := os.UserHomeDir()
		// a folder an older version synchronised keeps its name: it may be open or linked to
		if old := filepath.Join(home, appdir.Legacy); isSyncFolder(old) {
			return old
		}
		return filepath.Join(home, "CryptStorage")
	}
	return ""
}

// isSyncFolder tells whether dir is a folder the client has synchronised: the marker file from the
// volume is in it.
func isSyncFolder(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, syncer.MarkerName))
	return err == nil
}

// hasArg looks at the arguments after the command. CryptStorage.exe runs the tray with no command at all,
// so there may be none.
func hasArg(flag string) bool {
	if len(os.Args) < 3 {
		return false
	}
	for _, a := range os.Args[2:] {
		if a == flag {
			return true
		}
	}
	return false
}

func syncInterval() time.Duration {
	if s, err := strconv.Atoi(os.Getenv("CRYPTCLIENT_SYNC_INTERVAL")); err == nil && s >= 10 {
		return time.Duration(s) * time.Second
	}
	return time.Minute
}

func configDir() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return appdir.In(dir), nil
}

// syncHolder is this installation's id for the server lock, created on first use.
func syncHolder() (string, error) {
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	f := filepath.Join(dir, "sync-id")
	if b, err := os.ReadFile(f); err == nil && len(strings.TrimSpace(string(b))) >= 16 {
		return strings.TrimSpace(string(b)), nil
	}
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	id := hex.EncodeToString(buf)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return id, os.WriteFile(f, []byte(id+"\n"), 0o600)
}

// findRclone returns rclone, offering to fetch the pinned version when there is none.
func findRclone(a asker) (string, error) {
	p, err := deps.RclonePath()
	if !errors.Is(err, deps.ErrNoRclone) {
		return p, err
	}
	if !a.Confirm("The synchronised folder needs rclone " + deps.RcloneVersion +
		" (about 25 MB, from its official release, checked against a fixed checksum). Download it now?") {
		return "", err
	}
	return deps.InstallRclone(say)
}

type syncSession struct {
	cancel context.CancelFunc
	done   sync.WaitGroup
}

// stop ends syncing and waits until rclone has stopped, so the volume can be unmounted.
func (s *syncSession) stop() {
	if s == nil {
		return
	}
	s.cancel()
	s.done.Wait()
}

// maybeStartSync starts the synchronised folder for the open volume if syncing is turned on.
func maybeStartSync(a asker, report func(string)) {
	dir := syncDir()
	if dir == "" || openVolume == nil {
		return
	}
	sess, err := startSync(a, openVolume.api, openVolume.username, openVolume.plain, dir, report)
	if err != nil {
		report("Syncing is off: " + err.Error())
		return
	}
	openVolume.sync = sess
	report(fmt.Sprintf("Syncing %s with your storage every %s.", dir, syncInterval()))
	if w := diskenc.Warning(dir, diskenc.Check(dir)); w != "" {
		report("Warning: " + w)
	}
}

// startSync begins synchronising dir with the unlocked volume. report gets the messages the user
// should see; the session ends with stop (disconnect does this).
func startSync(a asker, api *apiclient.Client, username, plain, dir string, report func(string)) (*syncSession, error) {
	rclone, err := findRclone(a)
	if err != nil {
		return nil, err
	}
	holder, err := syncHolder()
	if err != nil {
		return nil, err
	}
	cfgDir, err := configDir()
	if err != nil {
		return nil, err
	}
	host, _ := os.Hostname()
	s := syncer.New(syncer.Config{
		Rclone: rclone, Local: dir, Remote: plain,
		WorkDir: filepath.Join(cfgDir, "bisync", username),
		Holder:  holder, HolderName: host, Interval: syncInterval(),
		AllowMassDelete:   hasArg("--allow-mass-delete"),
		ReplaceUnreadable: hasArg("--replace-unreadable"),
		Log: func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, "%s sync: %s\n", time.Now().Format("15:04:05"), fmt.Sprintf(format, args...))
		},
		Warn: report,
	}, api)
	ctx, cancel := context.WithCancel(context.Background())
	sess := &syncSession{cancel: cancel}
	sess.done.Add(1)
	go func() {
		defer sess.done.Done()
		switch err := s.Loop(ctx); {
		case errors.Is(err, syncer.ErrLocalNotEmpty):
			report(fmt.Sprintf("Syncing is off: %s is not empty. The first synchronisation needs an empty "+
				"or new folder, so nothing in it is overwritten. Choose another folder (CRYPTCLIENT_SYNC_DIR) "+
				"or move its files into the storage first.", dir))
		case errors.Is(err, syncer.ErrNeedsResync):
			report("Syncing stopped: rclone could not compare " + dir + " with your storage, not even in full. " +
				"Your files are kept. Connect again to retry; if it stops again, rename the folder (keep it until " +
				"you have checked the storage) and connect again, so it is filled anew.")
		case errors.Is(err, syncer.ErrTooManyDeletes):
			report("Syncing stopped: " + err.Error() + ". If you meant to delete those files, connect once " +
				"with `cryptclient connect --sync --allow-mass-delete`.")
		case err != nil:
			report("Syncing stopped: " + err.Error())
		}
	}()
	return sess, nil
}
