package main

import (
	"context"
	"os"
	"os/exec"
	"runtime"
)

func disabledGitHooksPath() string {
	if runtime.GOOS == "windows" {
		return "NUL"
	}
	return "/dev/null"
}

func gitHelperArgs(args ...string) []string {
	out := make([]string, 0, len(args)+4)
	out = append(out, "-c", "core.hooksPath="+disabledGitHooksPath())
	out = append(out, "-c", "core.fsmonitor=false")
	out = append(out, args...)
	return out
}

func newGitHelperCommand(ctx context.Context, dir string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "git", gitHelperArgs(args...)...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_OPTIONAL_LOCKS=0")
	return cmd
}
