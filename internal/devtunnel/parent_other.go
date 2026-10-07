//go:build !linux && !windows

package devtunnel

import "os/exec"

func prepare(*exec.Cmd)      {}
func bindToParent(*exec.Cmd) {}
