package syncer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
)

// clearStaleLocks removes rclone's own lock files in the work folder when the rclone that wrote them is
// gone. Stopping the client (Ctrl+C, removing the stick) ends rclone in the middle of a run, which
// leaves its lock behind, and the next run would refuse to start until the lock expires (--max-lock).
// A lock whose process still runs, or that cannot be read, is left alone.
func clearStaleLocks(workDir string) []string {
	files, _ := filepath.Glob(filepath.Join(workDir, "*.lck"))
	var removed []string
	for _, f := range files {
		pid, ok := lockPID(f)
		if !ok || processAlive(pid) {
			continue
		}
		if os.Remove(f) == nil {
			removed = append(removed, f)
		}
	}
	return removed
}

// lockPID reads the process id from a bisync lock file: JSON with "PID" (rclone writes it as a string).
func lockPID(path string) (int, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	var data struct {
		PID json.RawMessage
	}
	if json.Unmarshal(b, &data) != nil || len(data.PID) == 0 {
		return 0, false
	}
	var s string
	if json.Unmarshal(data.PID, &s) != nil {
		s = string(data.PID)
	}
	pid, err := strconv.Atoi(s)
	if err != nil || pid <= 0 || pid == os.Getpid() {
		return 0, false
	}
	return pid, true
}

func (s *Syncer) clearStaleLocks() {
	for _, f := range clearStaleLocks(s.cfg.WorkDir) {
		s.log("Removed the lock of an interrupted synchronisation (%s).", filepath.Base(f))
	}
}
