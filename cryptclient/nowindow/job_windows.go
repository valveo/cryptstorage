package nowindow

import (
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The helpers that hold a connection open (sshfs, cppcryptfs) are put in a job object that ends them
// when this program ends, however it ends. Without it a client that was killed (by antivirus, Task
// Manager, a crash) left cppcryptfs running with a mount whose server side was gone.
var (
	jobOnce sync.Once
	job     windows.Handle
)

func theJob() windows.Handle {
	jobOnce.Do(func() {
		h, err := windows.CreateJobObject(nil, nil)
		if err != nil {
			return
		}
		info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
		info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
		if _, err := windows.SetInformationJobObject(h, windows.JobObjectExtendedLimitInformation,
			uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
			windows.CloseHandle(h) //nolint
			return
		}
		job = h // kept open for the life of the process; Windows closes it at exit
	})
	return job
}

// EndWithMe makes the process with this pid end when this program ends. Best effort: on failure the
// process just lives on as before.
func EndWithMe(pid int) {
	j := theJob()
	if j == 0 {
		return
	}
	p, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return
	}
	defer windows.CloseHandle(p) //nolint

	windows.AssignProcessToJobObject(j, p) //nolint
}
