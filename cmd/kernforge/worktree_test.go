package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestWorkspaceResolveAllowsActiveRootOutsideBaseRoot(t *testing.T) {
	baseRoot := t.TempDir()
	activeRoot := t.TempDir()
	target := filepath.Join(activeRoot, "main.go")
	if err := os.WriteFile(target, []byte("package main\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	ws := Workspace{
		BaseRoot: baseRoot,
		Root:     activeRoot,
	}

	resolved, err := ws.Resolve("main.go")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !strings.EqualFold(filepath.Clean(resolved), filepath.Clean(target)) {
		t.Fatalf("expected %s, got %s", target, resolved)
	}
}

func TestRuntimeEditRoutingIgnoresAmbientFocusWithoutConcreteLease(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "main.go")
	if err := os.WriteFile(target, []byte("package main\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	session := NewSession(root, "scripted", "model", "", "default")
	session.TaskState = &TaskState{ExecutorFocusNode: "plan-02"}
	session.TaskGraph = &TaskGraph{
		Nodes: []TaskNode{
			{
				ID:    "plan-02",
				Title: "Review focused code",
			},
		},
	}
	rt := &runtimeState{
		session:   session,
		workspace: Workspace{BaseRoot: root, Root: root},
	}

	route, err := rt.resolveEditTarget(EditRoutingRequest{Path: "main.go"})
	if err != nil {
		t.Fatalf("resolveEditTarget: %v", err)
	}
	if route.OwnerNodeID != "" || route.Specialist != "" {
		t.Fatalf("ambient focus without concrete lease must not route edit ownership, got %#v", route)
	}
	if !strings.EqualFold(filepath.Clean(route.AbsolutePath), filepath.Clean(target)) {
		t.Fatalf("expected active workspace target %s, got %s", target, route.AbsolutePath)
	}
}

func TestRuntimeShellRoutingIgnoresAmbientFocusWithoutConcreteLease(t *testing.T) {
	root := t.TempDir()
	session := NewSession(root, "scripted", "model", "", "default")
	session.TaskState = &TaskState{ExecutorFocusNode: "plan-02"}
	session.TaskGraph = &TaskGraph{
		Nodes: []TaskNode{
			{
				ID:    "plan-02",
				Title: "Review focused code",
			},
		},
	}
	rt := &runtimeState{
		session:   session,
		workspace: Workspace{BaseRoot: root, Root: root},
	}

	route, err := rt.resolveShellRoot("")
	if err != nil {
		t.Fatalf("resolveShellRoot: %v", err)
	}
	if route.OwnerNodeID != "" || route.Specialist != "" {
		t.Fatalf("ambient focus without concrete lease must not route shell ownership, got %#v", route)
	}
	if !strings.EqualFold(filepath.Clean(route.Root), filepath.Clean(root)) {
		t.Fatalf("expected active workspace root %s, got %s", root, route.Root)
	}
}

func TestRuntimeEditRoutingIgnoresUnknownExplicitOwnerNodeID(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "main.go")
	if err := os.WriteFile(target, []byte("package main\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	session := NewSession(root, "scripted", "model", "", "default")
	session.TaskGraph = &TaskGraph{
		Nodes: []TaskNode{
			{
				ID:    "plan-02",
				Title: "Review focused code",
			},
		},
	}
	rt := &runtimeState{
		session:   session,
		workspace: Workspace{BaseRoot: root, Root: root},
	}

	route, err := rt.resolveEditTarget(EditRoutingRequest{
		Path:        "main.go",
		OwnerNodeID: "RF-001/RF-002 narrow hunk",
	})
	if err != nil {
		t.Fatalf("resolveEditTarget: %v", err)
	}
	if route.OwnerNodeID != "" || route.Specialist != "" {
		t.Fatalf("unknown explicit owner_node_id must not route edit ownership, got %#v", route)
	}
	if !strings.EqualFold(filepath.Clean(route.AbsolutePath), filepath.Clean(target)) {
		t.Fatalf("expected active workspace target %s, got %s", target, route.AbsolutePath)
	}
}

func TestSessionOwnerNodeHasConcreteEditRoutingAcceptsEditPathHint(t *testing.T) {
	root := t.TempDir()
	session := NewSession(root, "scripted", "model", "", "default")
	session.TaskGraph = &TaskGraph{
		Nodes: []TaskNode{
			{
				ID:    "plan-02",
				Title: "Fix src/main.go",
				Kind:  "edit",
			},
		},
	}

	if !sessionOwnerNodeHasConcreteEditRouting(session, "plan-02") {
		t.Fatalf("expected edit node with a concrete path hint to be routable")
	}
}

func TestWorktreeManagerCreateAndRemove(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not available")
	}

	repoRoot := t.TempDir()
	ctx := context.Background()

	if _, err := runGitCommand(ctx, repoRoot, "init"); err != nil {
		t.Fatalf("git init: %v", err)
	}
	if _, err := runGitCommand(ctx, repoRoot, "config", "user.email", "kernforge-test@example.com"); err != nil {
		t.Fatalf("git config user.email: %v", err)
	}
	if _, err := runGitCommand(ctx, repoRoot, "config", "user.name", "Kernforge Test"); err != nil {
		t.Fatalf("git config user.name: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repoRoot, "README.md"), []byte("# test\n"), 0o644); err != nil {
		t.Fatalf("WriteFile README: %v", err)
	}
	if _, err := runGitCommand(ctx, repoRoot, "add", "README.md"); err != nil {
		t.Fatalf("git add: %v", err)
	}
	if _, err := runGitCommand(ctx, repoRoot, "commit", "-m", "init"); err != nil {
		t.Fatalf("git commit: %v", err)
	}

	cfg := DefaultConfig(repoRoot)
	cfg.WorktreeIsolation.RootDir = filepath.Join(t.TempDir(), "managed")
	manager := newWorktreeManager(cfg)

	worktree, err := manager.Create(ctx, repoRoot, "Driver Fix")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !worktree.Managed || !worktree.Active {
		t.Fatalf("expected managed active worktree, got %#v", worktree)
	}
	if !strings.HasPrefix(worktree.Branch, "kernforge/driver-fix-") {
		t.Fatalf("unexpected branch name: %s", worktree.Branch)
	}
	if _, err := os.Stat(filepath.Join(worktree.Root, "README.md")); err != nil {
		t.Fatalf("expected worktree checkout to contain tracked files: %v", err)
	}

	if err := manager.Remove(ctx, repoRoot, worktree); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := os.Stat(worktree.Root); !os.IsNotExist(err) {
		t.Fatalf("expected worktree root to be removed, got err=%v", err)
	}
}

func TestWorktreeListCommandShowsSessionSpecialistAndGitEntries(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not available")
	}

	repoRoot := initTestGitRepo(t)
	session := NewSession(repoRoot, "provider", "model", "", "default")
	session.Worktree = &SessionWorktree{
		ID:      "session-worktree",
		Root:    filepath.Join(repoRoot, "..", "session-worktree"),
		Branch:  "kernforge/session-worktree",
		Managed: true,
		Active:  true,
	}
	session.SpecialistWorktrees = []SpecialistWorktree{{
		Specialist:     "driver-build-fixer",
		Root:           filepath.Join(repoRoot, "..", "driver-worktree"),
		Branch:         "kernforge/driver-worktree",
		OwnershipPaths: []string{"drivers/**"},
		NodeIDs:        []string{"plan-01"},
		Managed:        true,
		AutoCreated:    true,
	}}
	var output strings.Builder
	rt := &runtimeState{
		writer:  &output,
		ui:      NewUI(),
		session: session,
		workspace: Workspace{
			BaseRoot: repoRoot,
			Root:     repoRoot,
		},
	}

	if err := rt.handleWorktreeCommand("list"); err != nil {
		t.Fatalf("handleWorktreeCommand list: %v", err)
	}
	text := output.String()
	for _, want := range []string{"Worktrees", "Session Worktree", "Specialist Worktrees", "driver-build-fixer", "Git Worktree List", "branch=main"} {
		if !strings.Contains(text, want) {
			t.Fatalf("expected worktree list output to contain %q, got %q", want, text)
		}
	}
}

func TestWorktreeEnterReattachesRecordedInactiveWorktree(t *testing.T) {
	repoRoot := t.TempDir()
	worktreeRoot := t.TempDir()
	session := NewSession(repoRoot, "provider", "model", "", "default")
	session.Worktree = &SessionWorktree{
		ID:      "session-worktree",
		Root:    worktreeRoot,
		Branch:  "kernforge/session-worktree",
		Managed: true,
		Active:  false,
	}
	store := NewSessionStore(filepath.Join(repoRoot, "sessions"))
	var output strings.Builder
	rt := &runtimeState{
		writer:  &output,
		ui:      NewUI(),
		session: session,
		store:   store,
		workspace: Workspace{
			BaseRoot: repoRoot,
			Root:     repoRoot,
		},
	}

	if err := rt.handleWorktreeCommand("enter"); err != nil {
		t.Fatalf("handleWorktreeCommand enter: %v", err)
	}
	if !session.Worktree.Active || !strings.EqualFold(session.WorkingDir, worktreeRoot) {
		t.Fatalf("expected session to enter recorded worktree, got working_dir=%q worktree=%#v", session.WorkingDir, session.Worktree)
	}
	if !strings.Contains(output.String(), "Entered isolated worktree") {
		t.Fatalf("expected enter output, got %q", output.String())
	}
}

func TestWorktreeAttachExistingWorktree(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not available")
	}

	repoRoot := initTestGitRepo(t)
	attachedRoot := filepath.Join(t.TempDir(), "attached")
	if _, err := runGitCommand(context.Background(), repoRoot, "worktree", "add", "-b", "kernforge/attached", attachedRoot); err != nil {
		t.Fatalf("git worktree add: %v", err)
	}
	t.Cleanup(func() {
		_, _ = runGitCommand(context.Background(), repoRoot, "worktree", "remove", attachedRoot)
	})
	session := NewSession(repoRoot, "provider", "model", "", "default")
	store := NewSessionStore(filepath.Join(repoRoot, "sessions"))
	var output strings.Builder
	rt := &runtimeState{
		writer:  &output,
		ui:      NewUI(),
		session: session,
		store:   store,
		workspace: Workspace{
			BaseRoot: repoRoot,
			Root:     repoRoot,
		},
	}

	if err := rt.handleWorktreeCommand("attach " + strconv.Quote(attachedRoot)); err != nil {
		t.Fatalf("handleWorktreeCommand attach: %v", err)
	}
	if session.Worktree == nil || !session.Worktree.Active || session.Worktree.Managed {
		t.Fatalf("expected unmanaged active attached worktree, got %#v", session.Worktree)
	}
	if !strings.EqualFold(session.WorkingDir, filepath.Clean(attachedRoot)) {
		t.Fatalf("expected working dir to attached root, got %q", session.WorkingDir)
	}
	if session.Worktree.Branch != "kernforge/attached" {
		t.Fatalf("expected detected branch, got %q", session.Worktree.Branch)
	}
	if !strings.Contains(output.String(), "Attached existing worktree") {
		t.Fatalf("expected attach output, got %q", output.String())
	}
}

func TestResolveEditTargetRoutesOwnedEditsIntoSpecialistWorktree(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not available")
	}

	repoRoot := t.TempDir()
	ctx := context.Background()

	if _, err := runGitCommand(ctx, repoRoot, "init"); err != nil {
		t.Fatalf("git init: %v", err)
	}
	if _, err := runGitCommand(ctx, repoRoot, "config", "user.email", "kernforge-test@example.com"); err != nil {
		t.Fatalf("git config user.email: %v", err)
	}
	if _, err := runGitCommand(ctx, repoRoot, "config", "user.name", "Kernforge Test"); err != nil {
		t.Fatalf("git config user.name: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repoRoot, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatalf("WriteFile main.go: %v", err)
	}
	if _, err := runGitCommand(ctx, repoRoot, "add", "main.go"); err != nil {
		t.Fatalf("git add: %v", err)
	}
	if _, err := runGitCommand(ctx, repoRoot, "commit", "-m", "init"); err != nil {
		t.Fatalf("git commit: %v", err)
	}

	cfg := DefaultConfig(repoRoot)
	cfg.WorktreeIsolation.Enabled = boolPtr(true)
	cfg.WorktreeIsolation.RootDir = filepath.Join(t.TempDir(), "managed")
	sess := NewSession(repoRoot, "openai", "gpt-5.4", "", "default")
	sess.TaskGraph = &TaskGraph{
		Nodes: []TaskNode{
			{
				ID:          "plan-01",
				Title:       "Implement specialist ownership routing",
				Kind:        "edit",
				Status:      "ready",
				LastUpdated: time.Now(),
			},
		},
		LastUpdated: time.Now(),
	}

	rt := &runtimeState{
		cfg:     cfg,
		session: sess,
		workspace: Workspace{
			BaseRoot: repoRoot,
			Root:     repoRoot,
		},
	}
	rt.syncWorkspaceFromSession()

	route, err := rt.resolveEditTarget(EditRoutingRequest{
		Path:        "main.go",
		OwnerNodeID: "plan-01",
		ForLookup:   true,
	})
	if err != nil {
		t.Fatalf("resolveEditTarget: %v", err)
	}
	if route.Specialist != "implementation-owner" {
		t.Fatalf("expected implementation-owner route, got %#v", route)
	}
	if strings.TrimSpace(route.WorktreeRoot) == "" {
		t.Fatalf("expected a specialist worktree root, got %#v", route)
	}
	if sameFilePath(route.WorktreeRoot, repoRoot) {
		t.Fatalf("expected owned edits to use a dedicated worktree root")
	}
	if _, err := os.Stat(route.AbsolutePath); err != nil {
		t.Fatalf("expected routed file to exist inside specialist worktree: %v", err)
	}
	absoluteRoute, err := rt.resolveEditTarget(EditRoutingRequest{
		Path:        filepath.Join(repoRoot, "main.go"),
		OwnerNodeID: "plan-01",
		ForLookup:   true,
	})
	if err != nil {
		t.Fatalf("absolute lookup should route through specialist worktree without ownership mismatch: %v", err)
	}
	expectedWorktreePath := filepath.Join(route.WorktreeRoot, "main.go")
	if !sameFilePath(absoluteRoute.AbsolutePath, expectedWorktreePath) {
		t.Fatalf("expected absolute lookup to map to specialist worktree path %q, got %#v", expectedWorktreePath, absoluteRoute)
	}
	absoluteEditRoute, err := rt.resolveEditTarget(EditRoutingRequest{
		Path:        filepath.Join(repoRoot, "main.go"),
		OwnerNodeID: "plan-01",
		ForLookup:   false,
	})
	if err != nil {
		t.Fatalf("absolute edit should route through specialist worktree without ownership mismatch: %v", err)
	}
	if !sameFilePath(absoluteEditRoute.AbsolutePath, expectedWorktreePath) {
		t.Fatalf("expected absolute edit to map to specialist worktree path %q, got %#v", expectedWorktreePath, absoluteEditRoute)
	}
	if len(rt.session.SpecialistWorktrees) != 1 {
		t.Fatalf("expected one specialist worktree lease, got %#v", rt.session.SpecialistWorktrees)
	}
	node, ok := rt.session.TaskGraph.Node("plan-01")
	if !ok {
		t.Fatalf("expected task node to remain available")
	}
	if !strings.EqualFold(node.EditableSpecialist, "implementation-owner") {
		t.Fatalf("expected editable specialist metadata to be recorded, got %#v", node)
	}
	if !strings.EqualFold(node.EditableWorktreeRoot, route.WorktreeRoot) {
		t.Fatalf("expected node worktree root to match routed root, got %#v", node)
	}

	manager := newWorktreeManager(cfg)
	t.Cleanup(func() {
		_ = manager.Remove(context.Background(), repoRoot, SessionWorktree{
			Root:    route.WorktreeRoot,
			Branch:  rt.session.SpecialistWorktrees[0].Branch,
			Managed: true,
		})
	})
}

func TestResolveEditTargetRejectsPathOutsideSpecialistOwnership(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not available")
	}

	repoRoot := t.TempDir()
	ctx := context.Background()

	if _, err := runGitCommand(ctx, repoRoot, "init"); err != nil {
		t.Fatalf("git init: %v", err)
	}
	if _, err := runGitCommand(ctx, repoRoot, "config", "user.email", "kernforge-test@example.com"); err != nil {
		t.Fatalf("git config user.email: %v", err)
	}
	if _, err := runGitCommand(ctx, repoRoot, "config", "user.name", "Kernforge Test"); err != nil {
		t.Fatalf("git config user.name: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(repoRoot, "telemetry"), 0o755); err != nil {
		t.Fatalf("MkdirAll telemetry: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repoRoot, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatalf("WriteFile main.go: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repoRoot, "telemetry", "provider.man"), []byte("<manifest/>\n"), 0o644); err != nil {
		t.Fatalf("WriteFile provider.man: %v", err)
	}
	if _, err := runGitCommand(ctx, repoRoot, "add", "main.go", "telemetry/provider.man"); err != nil {
		t.Fatalf("git add: %v", err)
	}
	if _, err := runGitCommand(ctx, repoRoot, "commit", "-m", "init"); err != nil {
		t.Fatalf("git commit: %v", err)
	}

	cfg := DefaultConfig(repoRoot)
	cfg.WorktreeIsolation.Enabled = boolPtr(true)
	cfg.WorktreeIsolation.RootDir = filepath.Join(t.TempDir(), "managed")
	sess := NewSession(repoRoot, "openai", "gpt-5.4", "", "default")
	sess.TaskGraph = &TaskGraph{
		Nodes: []TaskNode{
			{
				ID:                     "plan-01",
				Title:                  "Update telemetry assets",
				Kind:                   "edit",
				Status:                 "ready",
				EditableSpecialist:     "telemetry-analyst",
				EditableOwnershipPaths: []string{"telemetry/**", "*.man"},
				LastUpdated:            time.Now(),
			},
		},
		LastUpdated: time.Now(),
	}

	rt := &runtimeState{
		cfg:     cfg,
		session: sess,
		workspace: Workspace{
			BaseRoot: repoRoot,
			Root:     repoRoot,
		},
	}
	rt.syncWorkspaceFromSession()

	manager := newWorktreeManager(cfg)
	t.Cleanup(func() {
		for _, lease := range rt.session.SpecialistWorktrees {
			_ = manager.Remove(context.Background(), repoRoot, SessionWorktree{
				Root:    lease.Root,
				Branch:  lease.Branch,
				Managed: true,
			})
		}
	})

	lookupRoute, err := rt.resolveEditTarget(EditRoutingRequest{
		Path:        "main.go",
		OwnerNodeID: "plan-01",
		ForLookup:   true,
	})
	if err != nil {
		t.Fatalf("read-only lookup should not be constrained by editable ownership: %v", err)
	}
	if !sameFilePath(lookupRoute.AbsolutePath, filepath.Join(repoRoot, "main.go")) {
		t.Fatalf("expected lookup to resolve in the main workspace, got %#v", lookupRoute)
	}

	_, err = rt.resolveEditTarget(EditRoutingRequest{
		Path:        "main.go",
		OwnerNodeID: "plan-01",
		ForLookup:   false,
	})
	if err == nil {
		t.Fatalf("expected editable ownership rejection")
	}
	if !errors.Is(err, ErrEditTargetMismatch) {
		t.Fatalf("expected ErrEditTargetMismatch, got %v", err)
	}
	if !strings.Contains(err.Error(), "editable ownership") {
		t.Fatalf("expected editable ownership guidance, got %v", err)
	}
}
