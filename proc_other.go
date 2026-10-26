//go:build !windows

package main

import "os/exec"

func prepareBackgroundCmd(cmd *exec.Cmd) {}
