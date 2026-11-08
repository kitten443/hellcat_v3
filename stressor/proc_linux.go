//go:build linux

package stressor

import (
	"os/exec"
	"syscall"
)

// setProcAttrs makes the kernel terminate Xray if hellcat dies unexpectedly,
// so a crashed run cannot leave orphaned proxy processes behind.
func setProcAttrs(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Pdeathsig: syscall.SIGKILL,
	}
}
