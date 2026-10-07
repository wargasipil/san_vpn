package devtunnel

import (
	"os/exec"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// One job object for the life of the process, set to kill its members when
// its last handle closes -- which happens when we exit, however we exit. A
// relay killed from Task Manager would otherwise leave `devtunnel host`
// serving a tunnel whose relay is gone.
var (
	jobOnce sync.Once
	job     windows.Handle
)

func prepare(*exec.Cmd) {}

func bindToParent(cmd *exec.Cmd) {
	jobOnce.Do(func() {
		h, err := windows.CreateJobObject(nil, nil)
		if err != nil {
			return
		}
		info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
			BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
				LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
			},
		}
		if _, err := windows.SetInformationJobObject(h, windows.JobObjectExtendedLimitInformation,
			uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
			_ = windows.CloseHandle(h)
			return
		}
		job = h
	})
	if job == 0 || cmd.Process == nil {
		return
	}
	p, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	if err != nil {
		return
	}
	_ = windows.AssignProcessToJobObject(job, p)
	_ = windows.CloseHandle(p)
}
