package syncer

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestClearStaleLocks(t *testing.T) {
	dir := t.TempDir()
	// a process that has ended: its lock is stale
	cmd := exec.Command("go", "version")
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "exit")
	}
	if err := cmd.Run(); err != nil {
		t.Skip("cannot start a helper process:", err)
	}
	dead := filepath.Join(dir, "a..b.lck")
	os.WriteFile(dead, []byte(fmt.Sprintf(`{"Session":"a..b","PID":"%d"}`, cmd.Process.Pid)), 0o600)
	// a running process (the parent of this test): its lock stays
	alive := filepath.Join(dir, "c..d.lck")
	os.WriteFile(alive, []byte(fmt.Sprintf(`{"PID":"%d"}`, os.Getppid())), 0o600)
	// unreadable: left to rclone's own expiry
	odd := filepath.Join(dir, "e..f.lck")
	os.WriteFile(odd, []byte("not json"), 0o600)

	removed := clearStaleLocks(dir)
	if len(removed) != 1 || removed[0] != dead {
		t.Fatalf("removed %v, want only %s", removed, dead)
	}
	for _, f := range []string{alive, odd} {
		if _, err := os.Stat(f); err != nil {
			t.Errorf("%s was removed", f)
		}
	}
}
