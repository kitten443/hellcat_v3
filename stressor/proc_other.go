//go:build !linux

package stressor

import "os/exec"

func setProcAttrs(cmd *exec.Cmd) {}
