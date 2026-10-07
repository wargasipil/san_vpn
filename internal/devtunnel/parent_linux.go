package devtunnel

import (
	"os/exec"
	"syscall"
)

// prepare asks the kernel to stop `devtunnel host` if we die, however we die,
// so a killed relay does not leave its tunnel served by nobody.
func prepare(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
}

func bindToParent(*exec.Cmd) {}
