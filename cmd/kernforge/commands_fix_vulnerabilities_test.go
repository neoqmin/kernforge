package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestParseFixVulnerabilitiesArgsDefaults(t *testing.T) {
	opts, err := parseFixVulnerabilitiesArgs("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.Severity != "HIGH" {
		t.Fatalf("default severity = %q, want HIGH", opts.Severity)
	}
	if opts.Max != 0 {
		t.Fatalf("default max = %d, want 0", opts.Max)
	}
	if opts.MaxIterations != -1 {
		t.Fatalf("default max-iterations = %d, want -1 (caller decides)", opts.MaxIterations)
	}
	if opts.DryRun || opts.NoTest || opts.ProjectName != "" {
		t.Fatalf("unexpected non-default fields: %+v", opts)
	}
}

func TestParseFixVulnerabilitiesArgsAllFlags(t *testing.T) {
	opts, err := parseFixVulnerabilitiesArgs(`"my project" --severity=critical --max=5 --dry-run --no-test --max-iterations=3`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.ProjectName != "my project" {
		t.Fatalf("project name = %q, want %q", opts.ProjectName, "my project")
	}
	if opts.Severity != "CRITICAL" {
		t.Fatalf("severity = %q, want CRITICAL (uppercased)", opts.Severity)
	}
	if opts.Max != 5 {
		t.Fatalf("max = %d, want 5", opts.Max)
	}
	if !opts.DryRun || !opts.NoTest {
		t.Fatalf("dry-run/no-test not set: %+v", opts)
	}
	if opts.MaxIterations != 3 {
		t.Fatalf("max-iterations = %d, want 3", opts.MaxIterations)
	}
}

func TestParseFixVulnerabilitiesArgsErrors(t *testing.T) {
	cases := []string{
		"--severity=bogus",
		"--max=-1",
		"--max=abc",
		"--unknown",
		"projA projB", // two positional args
	}
	for _, in := range cases {
		if _, err := parseFixVulnerabilitiesArgs(in); err == nil {
			t.Fatalf("parseFixVulnerabilitiesArgs(%q): expected error, got nil", in)
		}
	}
}

func TestBuildFixVulnerabilitiesObjectiveIncludesLoadBearingTokens(t *testing.T) {
	opts, err := parseFixVulnerabilitiesArgs("pgTelemetry/dashboard --severity=HIGH")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got := buildFixVulnerabilitiesObjective(opts, "pgTelemetry/dashboard")
	mustContain := []string{
		"mcp__dependency-track__dtrack_get_findings",
		"mcp__dependency-track__dtrack_get_component_remediation",
		"mcp__dependency-track__dtrack_submit_project",
		"apply_edit_proposal",
		"one finding per change",
		"roll back this single change",
		"package.json",
		"go.mod",
		"severity >= HIGH",
		"re-submit",
		// the non-bypassable hard rule against git must be stated in the objective too
		"NEVER run any git command that changes state",
		"NEVER edit application source files",
	}
	for _, token := range mustContain {
		if !strings.Contains(got, token) {
			t.Fatalf("objective missing %q\n---\n%s", token, got)
		}
	}
}

func TestBuildFixVulnerabilitiesObjectiveDryRunOmitsApply(t *testing.T) {
	opts, err := parseFixVulnerabilitiesArgs("proj --dry-run")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got := buildFixVulnerabilitiesObjective(opts, "proj")
	if !strings.Contains(got, "Do NOT call apply_edit_proposal") {
		t.Fatalf("dry-run objective must explicitly forbid apply_edit_proposal\n---\n%s", got)
	}
	if strings.Contains(got, "Step 3 - Re-scan") {
		t.Fatalf("dry-run objective must not include the apply/re-scan steps\n---\n%s", got)
	}
	if !strings.Contains(got, "dry run") {
		t.Fatalf("dry-run objective should announce dry run\n---\n%s", got)
	}
}

func TestFixVulnerabilitiesAdvisorDefaultOn(t *testing.T) {
	opts, err := parseFixVulnerabilitiesArgs("proj")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !opts.Advise {
		t.Fatalf("advisor should default to on")
	}
	got := buildFixVulnerabilitiesObjective(opts, "proj")
	if !strings.Contains(got, "Step 1.5 - Advisory") {
		t.Fatalf("default objective should include the advisory step\n---\n%s", got)
	}
	if !strings.Contains(got, "before editing anything") {
		t.Fatalf("advisory step should require reporting before editing\n---\n%s", got)
	}
}

func TestFixVulnerabilitiesNoAdviseOmitsAdvisory(t *testing.T) {
	opts, err := parseFixVulnerabilitiesArgs("proj --no-advise")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if opts.Advise {
		t.Fatalf("--no-advise should disable the advisor")
	}
	got := buildFixVulnerabilitiesObjective(opts, "proj")
	if strings.Contains(got, "Step 1.5 - Advisory") {
		t.Fatalf("--no-advise objective must omit the advisory step\n---\n%s", got)
	}
	// Apply steps remain.
	if !strings.Contains(got, "apply_edit_proposal") {
		t.Fatalf("--no-advise objective should still apply fixes\n---\n%s", got)
	}
}

func TestResolveDtrackProjectNameFallsBackToWorkspaceBase(t *testing.T) {
	rt := &runtimeState{workspace: Workspace{Root: filepath.Join("C:", "src", "pgTelemetry-dashboard")}}
	if got := rt.resolveDtrackProjectName(""); got != "pgTelemetry-dashboard" {
		t.Fatalf("fallback project name = %q, want pgTelemetry-dashboard", got)
	}
	if got := rt.resolveDtrackProjectName("explicit"); got != "explicit" {
		t.Fatalf("explicit project name = %q, want explicit", got)
	}
}

func TestIsFixVulnManifestPath(t *testing.T) {
	allow := []string{"package.json", "path/to/go.mod", "go.sum", "App.csproj", "pnpm-lock.yaml", "yarn.lock", "pom.xml"}
	deny := []string{"main.go", "src/app.ts", "README.md", "internal/server.cs", "index.js"}
	for _, p := range allow {
		if !isFixVulnManifestPath(p) {
			t.Fatalf("isFixVulnManifestPath(%q) = false, want true", p)
		}
	}
	for _, p := range deny {
		if isFixVulnManifestPath(p) {
			t.Fatalf("isFixVulnManifestPath(%q) = true, want false", p)
		}
	}
}

// TestFixVulnGuardBlocksGitUnderModeBypass is the highest-priority safety test:
// even when the workspace permission manager is in ModeBypass (as the autonomous
// goal loop sets it), the guard must hard-deny destructive git and source writes.
func TestFixVulnGuardBlocksGitUnderModeBypass(t *testing.T) {
	root := t.TempDir()
	guard := &FixVulnGuard{}
	ws := Workspace{
		Root:         root,
		BaseRoot:     root,
		Perms:        NewPermissionManager(ModeBypass, nil),
		FixVulnGuard: guard,
	}

	// Inactive guard: nothing is blocked by the guard layer.
	if err := ws.guardShellCommand("git reset --hard"); err != nil {
		t.Fatalf("inactive guard should not block: %v", err)
	}

	guard.SetActive(true)

	deniedGit := []string{
		"git reset --hard",
		"git clean -fdx",
		"git checkout -- .",
		"git restore .",
		"git push --force origin main",
		"npm install && git reset --hard HEAD~1",
	}
	for _, cmd := range deniedGit {
		if err := ws.guardShellCommand(cmd); err == nil {
			t.Fatalf("guardShellCommand(%q) = nil under ModeBypass, want deny", cmd)
		}
	}

	allowedShell := []string{
		"git status",
		"git diff",
		"git log --oneline",
		"npm install",
		"go mod tidy",
		"go test ./...",
	}
	for _, cmd := range allowedShell {
		if err := ws.guardShellCommand(cmd); err != nil {
			t.Fatalf("guardShellCommand(%q) = %v under ModeBypass, want allow", cmd, err)
		}
	}

	// Dedicated git_* tools funnel through EnsureGitWithContext -> guardGitAction.
	if err := ws.guardGitAction("stage changes with git_add"); err == nil {
		t.Fatalf("guardGitAction should deny while active under ModeBypass")
	}

	// Write scope: manifests allowed, source denied — via the unconditional CheckEditBoundary chokepoint.
	if err := ws.CheckEditBoundary(filepath.Join(root, "package.json")); err != nil {
		t.Fatalf("CheckEditBoundary(package.json) = %v, want allow", err)
	}
	if err := ws.CheckEditBoundary(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("CheckEditBoundary(go.mod) = %v, want allow", err)
	}
	if err := ws.CheckEditBoundary(filepath.Join(root, "main.go")); err == nil {
		t.Fatalf("CheckEditBoundary(main.go) = nil under ModeBypass, want deny")
	}
	if err := ws.CheckEditBoundary(filepath.Join(root, "src", "app.ts")); err == nil {
		t.Fatalf("CheckEditBoundary(src/app.ts) = nil under ModeBypass, want deny")
	}

	// Deactivation restores normal behavior (no guard denial).
	guard.SetActive(false)
	if err := ws.guardShellCommand("git reset --hard"); err != nil {
		t.Fatalf("after deactivation guard should not block: %v", err)
	}
}
