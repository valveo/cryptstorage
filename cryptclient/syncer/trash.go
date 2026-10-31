package syncer

import (
	"os"
	"path/filepath"
	"time"
)

// The synchronised folder copies what happens on the server, deletions and older versions put back
// included: it is a mirror, not a backup. So that a change made on the server never destroys a
// local file outright, rclone moves every local file it is about to delete or overwrite because of the
// other side into the trash folder, one sub-folder per run. The trash is inside the local folder (the
// same disk, so moving is a rename, and the user finds it) and never synchronised.

// TrashName is the trash folder inside the local folder.
const TrashName = ".secdisk-trash"

// TrashKeep is how long files stay in the trash.
const TrashKeep = 30 * 24 * time.Hour

const trashStamp = "2006-01-02_150405"

func (s *Syncer) trashRoot() string { return filepath.Join(s.cfg.Local, TrashName) }

// newTrashRun names the trash sub-folder for one run. rclone creates it only when it moves something.
func (s *Syncer) newTrashRun() string {
	return filepath.Join(s.trashRoot(), time.Now().Format(trashStamp))
}

// countFiles counts the files under dir (0 when it does not exist).
func countFiles(dir string) int {
	n := 0
	filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			n++
		}
		return nil
	})
	return n
}

// reportTrash tells the user what a run moved to the trash.
func (s *Syncer) reportTrash(run string) {
	if n := countFiles(run); n > 0 {
		s.warn("%d local file(s) were deleted or replaced because of changes in your storage. The previous "+
			"versions are kept for %d days in %s.", n, int(TrashKeep/(24*time.Hour)), run)
	}
}

// cleanTrash removes the trash sub-folders older than TrashKeep, and the trash itself when it is empty.
func (s *Syncer) cleanTrash(now time.Time) {
	root := s.trashRoot()
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	left := len(entries)
	for _, e := range entries {
		t, err := time.ParseInLocation(trashStamp, e.Name(), time.Local)
		if err != nil || !e.IsDir() || now.Sub(t) < TrashKeep {
			continue
		}
		if err := os.RemoveAll(filepath.Join(root, e.Name())); err != nil {
			s.log("Could not empty the old trash folder %s: %v", e.Name(), err)
			continue
		}
		left--
	}
	if left == 0 {
		os.Remove(root)
	}
}

// restoreFromTrash puts local files back that rclone moved to the trash run before it failed to copy the
// storage's version over them (it moves the old file first). Used for files that cannot be read.
func (s *Syncer) restoreFromTrash(run string, names []string) {
	for _, n := range names {
		local := filepath.Join(s.cfg.Local, filepath.FromSlash(n))
		saved := filepath.Join(run, filepath.FromSlash(n))
		if _, err := os.Stat(local); err == nil {
			continue
		}
		if _, err := os.Stat(saved); err != nil {
			continue
		}
		if err := os.Rename(saved, local); err != nil {
			s.warn("Your local copy of %s is in %s; it could not be put back: %v", n, run, err)
		}
	}
}
