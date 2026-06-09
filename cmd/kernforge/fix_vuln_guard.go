package main

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync/atomic"
)

// FixVulnGuard is a non-bypassable safety guard scoped to the /fix-vulnerabilities
// command. While active it hard-denies any git command that changes repository
// state (reset, clean, checkout, etc.) and restricts file writes to dependency
// manifests/lockfiles only. These checks run at unconditional chokepoints
// (RunShellTool.Execute, EnsureGitWithContext, CheckEditBoundary) that execute
// BEFORE the permission layer, so they hold even when the autonomous goal loop
// sets ModeBypass via withAutonomousGoalPermissions.
//
// Active is read/written atomically because the same *FixVulnGuard pointer is
// shared by the Workspace copies handed to every tool in buildRegistry.
type FixVulnGuard struct {
	active int32
}

// SetActive toggles the guard. It is safe to call from the command handler while
// tool goroutines read the flag.
func (g *FixVulnGuard) SetActive(on bool) {
	if g == nil {
		return
	}
	if on {
		atomic.StoreInt32(&g.active, 1)
	} else {
		atomic.StoreInt32(&g.active, 0)
	}
}

// Active reports whether the guard is currently enforcing.
func (g *FixVulnGuard) Active() bool {
	if g == nil {
		return false
	}
	return atomic.LoadInt32(&g.active) == 1
}

// fixVulnManifestBasenames are exact-match dependency manifests/lockfiles the
// guard permits writes to while active.
var fixVulnManifestBasenames = map[string]bool{
	"package.json":        true,
	"package-lock.json":   true,
	"npm-shrinkwrap.json": true,
	"pnpm-lock.yaml":      true,
	"yarn.lock":           true,
	"go.mod":              true,
	"go.sum":              true,
	"pom.xml":             true,
	"build.gradle":        true,
	"build.gradle.kts":    true,
	"gradle.lockfile":     true,
	"packages.lock.json":  true,
	"paket.dependencies":  true,
	"paket.lock":          true,
}

// fixVulnManifestExtensions are file extensions the guard permits writes to while
// active (e.g. *.csproj for .NET dependency references).
var fixVulnManifestExtensions = map[string]bool{
	".csproj": true,
	".vbproj": true,
	".fsproj": true,
}

// isFixVulnManifestPath reports whether path is an allowed dependency manifest.
func isFixVulnManifestPath(path string) bool {
	base := strings.ToLower(filepath.Base(strings.TrimSpace(path)))
	if base == "" {
		return false
	}
	if fixVulnManifestBasenames[base] {
		return true
	}
	if fixVulnManifestExtensions[strings.ToLower(filepath.Ext(base))] {
		return true
	}
	return false
}

// guardShellCommand denies any state-changing git command while the guard is
// active. Read-only git (status/diff/log/...) and all non-git commands pass.
// Reuses shellCommandMutatesGitState so the classification matches the rest of
// the tool surface.
func (w Workspace) guardShellCommand(command string) error {
	if !w.FixVulnGuard.Active() {
		return nil
	}
	if shellCommandMutatesGitState(command) {
		return fmt.Errorf("git state changes are blocked during /fix-vulnerabilities (attempted: %q); this command only edits dependency manifests and never touches git", strings.TrimSpace(command))
	}
	return nil
}

// guardGitAction denies any git mutation issued through the dedicated git_* tools
// (git_add / git_commit / git_push) while the guard is active.
func (w Workspace) guardGitAction(detail string) error {
	if !w.FixVulnGuard.Active() {
		return nil
	}
	return fmt.Errorf("git is blocked during /fix-vulnerabilities (attempted: git %s); this command never touches git", strings.TrimSpace(detail))
}

// guardWritePath denies writes to anything other than a dependency manifest while
// the guard is active. This protects application source from being edited.
func (w Workspace) guardWritePath(path string) error {
	if !w.FixVulnGuard.Active() {
		return nil
	}
	if isFixVulnManifestPath(path) {
		return nil
	}
	return fmt.Errorf("writes are restricted to dependency manifests during /fix-vulnerabilities (attempted: %q); edit only package.json/go.mod/lockfiles and never application source", strings.TrimSpace(path))
}
