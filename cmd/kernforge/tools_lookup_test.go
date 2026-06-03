package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func TestWorkspaceResolveForLookupFallsBackToBaseRoot(t *testing.T) {
	base := t.TempDir()
	current := filepath.Join(base, "nested")
	if err := os.MkdirAll(current, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	target := filepath.Join(base, "root_only.txt")
	if err := os.WriteFile(target, []byte("hello"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	ws := Workspace{
		BaseRoot: base,
		Root:     current,
	}

	resolved, err := ws.ResolveForLookup("root_only.txt")
	if err != nil {
		t.Fatalf("ResolveForLookup: %v", err)
	}
	if resolved != target {
		t.Fatalf("expected fallback path %q, got %q", target, resolved)
	}
}

func TestWorkspaceResolveForLookupRejectsSymlinkOutsideRoot(t *testing.T) {
	root := t.TempDir()
	external := filepath.Join(t.TempDir(), "external.txt")
	if err := os.WriteFile(external, []byte("secret"), 0o644); err != nil {
		t.Fatalf("WriteFile external: %v", err)
	}
	link := filepath.Join(root, "link.txt")
	if err := os.Symlink(external, link); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}

	ws := Workspace{
		BaseRoot: root,
		Root:     root,
	}

	_, err := ws.ResolveForLookup("link.txt")
	if err == nil {
		t.Fatalf("expected symlink lookup outside root to be rejected")
	}
	if !strings.Contains(err.Error(), "resolves outside the active workspace root") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReadFileRejectsSymlinkOutsideWorkspace(t *testing.T) {
	root := t.TempDir()
	external := filepath.Join(t.TempDir(), "external.txt")
	if err := os.WriteFile(external, []byte("secret"), 0o644); err != nil {
		t.Fatalf("WriteFile external: %v", err)
	}
	link := filepath.Join(root, "link.txt")
	if err := os.Symlink(external, link); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}

	tool := NewReadFileTool(Workspace{
		BaseRoot: root,
		Root:     root,
	})
	_, err := tool.Execute(context.Background(), map[string]any{
		"path": "link.txt",
	})
	if err == nil {
		t.Fatalf("expected read_file through outside symlink to be rejected")
	}
	if !strings.Contains(err.Error(), "resolves outside the active workspace root") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLookupToolsRecoverFromOwnerEditMismatch(t *testing.T) {
	assertLookupToolsRecoverFromOwnerEditMismatch(t, true)
}

func TestLookupToolsRecoverFromRawOwnerEditMismatch(t *testing.T) {
	assertLookupToolsRecoverFromOwnerEditMismatch(t, false)
}

func TestLookupToolsRecoverFromOwnerEditMismatchWithAbsoluteWorkspacePath(t *testing.T) {
	for _, wrapSentinel := range []bool{true, false} {
		wrapSentinel := wrapSentinel
		t.Run(fmt.Sprintf("wrapSentinel=%v", wrapSentinel), func(t *testing.T) {
			root := t.TempDir()
			sourceDir := filepath.Join(root, "SampleGame", "SampleGame")
			if err := os.MkdirAll(sourceDir, 0o755); err != nil {
				t.Fatalf("MkdirAll sourceDir: %v", err)
			}
			sourceFile := filepath.Join(sourceDir, "RuntimeManager.cpp")
			if err := os.WriteFile(sourceFile, []byte("int runtime_manager_marker = 1;\n"), 0o644); err != nil {
				t.Fatalf("WriteFile sourceFile: %v", err)
			}

			ws := Workspace{
				BaseRoot: root,
				Root:     root,
			}
			ws.ResolveEditTarget = func(req EditRoutingRequest) (EditRoutingResult, error) {
				req = req.normalized()
				if req.lookupIntent() && strings.TrimSpace(req.OwnerNodeID) != "" {
					if !wrapSentinel {
						return EditRoutingResult{}, fmt.Errorf("edit target mismatch: path %s is outside editable ownership for specialist driver-build-fixer", req.Path)
					}
					return EditRoutingResult{}, fmt.Errorf("%w: path %s is outside editable ownership for specialist driver-build-fixer", ErrEditTargetMismatch, req.Path)
				}
				return ws.resolveEditFallback(req)
			}

			readTool := NewReadFileTool(ws)
			readResult, err := readTool.ExecuteDetailed(context.Background(), map[string]any{
				"path":          sourceFile,
				"owner_node_id": "plan-01",
			})
			if err != nil {
				t.Fatalf("read_file should fall back for absolute workspace path after owner mismatch: %v", err)
			}
			if !strings.Contains(readResult.DisplayText, "runtime_manager_marker") {
				t.Fatalf("expected read_file to return absolute workspace file content, got %q", readResult.DisplayText)
			}

			listTool := NewListFilesTool(ws)
			listResult, err := listTool.ExecuteDetailed(context.Background(), map[string]any{
				"path":          sourceDir,
				"owner_node_id": "plan-01",
			})
			if err != nil {
				t.Fatalf("list_files should fall back for absolute workspace path after owner mismatch: %v", err)
			}
			if !strings.Contains(listResult.DisplayText, "RuntimeManager.cpp") {
				t.Fatalf("expected list_files to include absolute workspace file, got %q", listResult.DisplayText)
			}

			grepTool := NewGrepTool(ws)
			grepResult, err := grepTool.ExecuteDetailed(context.Background(), map[string]any{
				"pattern":       "runtime_manager_marker",
				"path":          sourceDir,
				"owner_node_id": "plan-01",
			})
			if err != nil {
				t.Fatalf("grep should fall back for absolute workspace path after owner mismatch: %v", err)
			}
			if !strings.Contains(grepResult.DisplayText, "RuntimeManager.cpp") {
				t.Fatalf("expected grep to find absolute workspace file content, got %q", grepResult.DisplayText)
			}
		})
	}
}

func TestLookupToolsRecoverWhenOwnedWorktreeRouteIsMissing(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "src"), 0o755); err != nil {
		t.Fatalf("MkdirAll src: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "src", "main.go"), []byte("package main\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatalf("WriteFile main.go: %v", err)
	}
	worktreeRoot := filepath.Join(t.TempDir(), "specialist")
	if err := os.MkdirAll(worktreeRoot, 0o755); err != nil {
		t.Fatalf("MkdirAll specialist worktree: %v", err)
	}

	ws := Workspace{
		BaseRoot: root,
		Root:     root,
	}
	ws.ResolveEditTarget = func(req EditRoutingRequest) (EditRoutingResult, error) {
		req = req.normalized()
		if req.lookupIntent() && strings.TrimSpace(req.OwnerNodeID) != "" {
			abs, err := ws.resolveAgainstRoot(worktreeRoot, req.Path)
			if err != nil {
				return EditRoutingResult{}, err
			}
			return EditRoutingResult{
				AbsolutePath: abs,
				DisplayRoot:  worktreeRoot,
				OwnerNodeID:  req.OwnerNodeID,
				Specialist:   "driver-build-fixer",
				WorktreeRoot: worktreeRoot,
			}, nil
		}
		return ws.resolveEditFallback(req)
	}

	readTool := NewReadFileTool(ws)
	readResult, err := readTool.ExecuteDetailed(context.Background(), map[string]any{
		"path":          "src/main.go",
		"owner_node_id": "plan-01",
	})
	if err != nil {
		t.Fatalf("read_file should fall back when owned worktree route is missing: %v", err)
	}
	if !strings.Contains(readResult.DisplayText, "package main") {
		t.Fatalf("expected read_file to return base workspace content, got %q", readResult.DisplayText)
	}

	listTool := NewListFilesTool(ws)
	listResult, err := listTool.ExecuteDetailed(context.Background(), map[string]any{
		"path":          "src",
		"owner_node_id": "plan-01",
	})
	if err != nil {
		t.Fatalf("list_files should fall back when owned worktree route is missing: %v", err)
	}
	if !strings.Contains(listResult.DisplayText, "src/main.go") {
		t.Fatalf("expected list_files to include base workspace file, got %q", listResult.DisplayText)
	}

	grepTool := NewGrepTool(ws)
	grepResult, err := grepTool.ExecuteDetailed(context.Background(), map[string]any{
		"pattern":       "package main",
		"path":          "src",
		"owner_node_id": "plan-01",
	})
	if err != nil {
		t.Fatalf("grep should fall back when owned worktree route is missing: %v", err)
	}
	if !strings.Contains(grepResult.DisplayText, "src/main.go") {
		t.Fatalf("expected grep to find base workspace content, got %q", grepResult.DisplayText)
	}
}

func TestLookupToolsRecoverWhenOwnedLookupReturnsMissingPath(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{name: "sentinel", err: os.ErrNotExist},
		{name: "windows-text", err: fmt.Errorf("The system cannot find the path specified")},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			sourceDir := filepath.Join(root, "src")
			if err := os.MkdirAll(sourceDir, 0o755); err != nil {
				t.Fatalf("MkdirAll sourceDir: %v", err)
			}
			sourceFile := filepath.Join(sourceDir, "main.go")
			if err := os.WriteFile(sourceFile, []byte("package main\nfunc main() {}\n"), 0o644); err != nil {
				t.Fatalf("WriteFile sourceFile: %v", err)
			}

			ws := Workspace{
				BaseRoot: root,
				Root:     root,
			}
			ws.ResolveEditTarget = func(req EditRoutingRequest) (EditRoutingResult, error) {
				req = req.normalized()
				if req.lookupIntent() && strings.TrimSpace(req.OwnerNodeID) != "" {
					return EditRoutingResult{}, tc.err
				}
				return ws.resolveEditFallback(req)
			}

			readTool := NewReadFileTool(ws)
			readResult, err := readTool.ExecuteDetailed(context.Background(), map[string]any{
				"path":          "src/main.go",
				"owner_node_id": "plan-01",
			})
			if err != nil {
				t.Fatalf("read_file should fall back after owned lookup missing path: %v", err)
			}
			if !strings.Contains(readResult.DisplayText, "package main") {
				t.Fatalf("expected read_file to return main workspace file, got %q", readResult.DisplayText)
			}

			listTool := NewListFilesTool(ws)
			listResult, err := listTool.ExecuteDetailed(context.Background(), map[string]any{
				"path":          "src/main.go",
				"owner_node_id": "plan-01",
			})
			if err != nil {
				t.Fatalf("list_files should fall back after owned lookup missing path: %v", err)
			}
			if toolMetaString(listResult.Meta, "path_type") != "file" {
				t.Fatalf("expected list_files fallback to return file metadata, got %#v", listResult.Meta)
			}

			grepTool := NewGrepTool(ws)
			grepResult, err := grepTool.ExecuteDetailed(context.Background(), map[string]any{
				"pattern":       "package main",
				"path":          "src",
				"owner_node_id": "plan-01",
			})
			if err != nil {
				t.Fatalf("grep should fall back after owned lookup missing path: %v", err)
			}
			if !strings.Contains(grepResult.DisplayText, "src/main.go") {
				t.Fatalf("expected grep to find main workspace file, got %q", grepResult.DisplayText)
			}
		})
	}
}

func TestLookupToolsRecoverAcrossWorkspaceRootsAfterOwnerMismatch(t *testing.T) {
	root := t.TempDir()
	current := filepath.Join(root, ".kernforge", "worktrees", "driver-build-fixer")
	if err := os.MkdirAll(current, 0o755); err != nil {
		t.Fatalf("MkdirAll current: %v", err)
	}
	sourceDir := filepath.Join(root, "SampleGame")
	if err := os.MkdirAll(sourceDir, 0o755); err != nil {
		t.Fatalf("MkdirAll sourceDir: %v", err)
	}
	sourceFile := filepath.Join(sourceDir, "BugReport.md")
	if err := os.WriteFile(sourceFile, []byte("# SampleGame bug report\nBUG-001\n"), 0o644); err != nil {
		t.Fatalf("WriteFile sourceFile: %v", err)
	}

	ws := Workspace{
		BaseRoot: root,
		Root:     current,
	}
	ws.ResolveEditTarget = func(req EditRoutingRequest) (EditRoutingResult, error) {
		req = req.normalized()
		if req.lookupIntent() && strings.TrimSpace(req.OwnerNodeID) != "" {
			return EditRoutingResult{}, fmt.Errorf("%w: path %s is outside editable ownership for specialist driver-build-fixer", ErrEditTargetMismatch, req.Path)
		}
		if req.lookupIntent() {
			return EditRoutingResult{}, fmt.Errorf("path is outside the active workspace root: %s", req.Path)
		}
		return ws.resolveEditFallback(req)
	}

	readTool := NewReadFileTool(ws)
	readResult, err := readTool.ExecuteDetailed(context.Background(), map[string]any{
		"path":          "SampleGame/BugReport.md",
		"owner_node_id": "plan-01",
	})
	if err != nil {
		t.Fatalf("read_file should fall back across workspace roots after owner mismatch: %v", err)
	}
	if !strings.Contains(readResult.DisplayText, "BUG-001") {
		t.Fatalf("expected read_file to return base workspace content, got %q", readResult.DisplayText)
	}

	listTool := NewListFilesTool(ws)
	listResult, err := listTool.ExecuteDetailed(context.Background(), map[string]any{
		"path":          "SampleGame",
		"owner_node_id": "plan-01",
	})
	if err != nil {
		t.Fatalf("list_files should fall back across workspace roots after owner mismatch: %v", err)
	}
	if !strings.Contains(listResult.DisplayText, "BugReport.md") {
		t.Fatalf("expected list_files to include base workspace file, got %q", listResult.DisplayText)
	}

	grepTool := NewGrepTool(ws)
	grepResult, err := grepTool.ExecuteDetailed(context.Background(), map[string]any{
		"pattern":       "BUG-001",
		"path":          "SampleGame",
		"owner_node_id": "plan-01",
	})
	if err != nil {
		t.Fatalf("grep should fall back across workspace roots after owner mismatch: %v", err)
	}
	if !strings.Contains(grepResult.DisplayText, "BugReport.md") {
		t.Fatalf("expected grep to find base workspace content, got %q", grepResult.DisplayText)
	}
}

func TestReadOnlyLookupToolDefinitionsDoNotAdvertiseOwnerNodeID(t *testing.T) {
	for _, def := range []ToolDefinition{
		NewListFilesTool(Workspace{}).Definition(),
		NewReadFileTool(Workspace{}).Definition(),
		NewGrepTool(Workspace{}).Definition(),
	} {
		properties, _ := def.InputSchema["properties"].(map[string]any)
		if _, ok := properties["owner_node_id"]; ok {
			t.Fatalf("%s should not advertise owner_node_id for read-only lookup", def.Name)
		}
	}
}

func TestResolveLookupPathFallsBackAcrossWorkspaceRootsWithoutOwner(t *testing.T) {
	root := t.TempDir()
	active := filepath.Join(root, ".kernforge", "worktrees", "driver-build-fixer")
	if err := os.MkdirAll(active, 0o755); err != nil {
		t.Fatalf("MkdirAll active: %v", err)
	}
	sourceDir := filepath.Join(root, "SampleGame")
	if err := os.MkdirAll(sourceDir, 0o755); err != nil {
		t.Fatalf("MkdirAll sourceDir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "BugReport.md"), []byte("# SampleGame bug report\n"), 0o644); err != nil {
		t.Fatalf("WriteFile BugReport: %v", err)
	}

	ws := Workspace{
		BaseRoot: root,
		Root:     active,
	}
	ws.ResolveEditTarget = func(req EditRoutingRequest) (EditRoutingResult, error) {
		req = req.normalized()
		if req.lookupIntent() {
			return EditRoutingResult{}, fmt.Errorf("path is outside the active workspace root: %s", req.Path)
		}
		return ws.resolveEditFallback(req)
	}

	route, err := ws.ResolveLookupPath("SampleGame/BugReport.md", "")
	if err != nil {
		t.Fatalf("lookup should fall back to base workspace without owner_node_id: %v", err)
	}
	if !sameFilePath(route.AbsolutePath, filepath.Join(root, "SampleGame", "BugReport.md")) {
		t.Fatalf("expected base workspace file, got %#v", route)
	}
	if !sameFilePath(route.DisplayRoot, root) {
		t.Fatalf("expected base workspace display root, got %#v", route)
	}
}

func assertLookupToolsRecoverFromOwnerEditMismatch(t *testing.T, wrapSentinel bool) {
	t.Helper()

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	ws := Workspace{
		BaseRoot: root,
		Root:     root,
	}
	ws.ResolveEditTarget = func(req EditRoutingRequest) (EditRoutingResult, error) {
		req = req.normalized()
		if req.lookupIntent() && strings.TrimSpace(req.OwnerNodeID) != "" {
			if !wrapSentinel {
				return EditRoutingResult{}, fmt.Errorf("edit target mismatch: path %s is outside editable ownership for specialist driver-build-fixer", req.Path)
			}
			return EditRoutingResult{}, fmt.Errorf("%w: path %s is outside editable ownership for specialist driver-build-fixer", ErrEditTargetMismatch, req.Path)
		}
		return ws.resolveEditFallback(req)
	}

	readTool := NewReadFileTool(ws)
	readResult, err := readTool.ExecuteDetailed(context.Background(), map[string]any{
		"path":          "main.go",
		"owner_node_id": "plan-01",
	})
	if err != nil {
		t.Fatalf("read_file should fall back to normal lookup after owner mismatch: %v", err)
	}
	if !strings.Contains(readResult.DisplayText, "package main") {
		t.Fatalf("expected read_file to return base workspace content, got %q", readResult.DisplayText)
	}

	listTool := NewListFilesTool(ws)
	listResult, err := listTool.ExecuteDetailed(context.Background(), map[string]any{
		"path":          ".",
		"owner_node_id": "plan-01",
	})
	if err != nil {
		t.Fatalf("list_files should fall back to normal lookup after owner mismatch: %v", err)
	}
	if !strings.Contains(listResult.DisplayText, "main.go") {
		t.Fatalf("expected list_files to include base workspace files, got %q", listResult.DisplayText)
	}

	grepTool := NewGrepTool(ws)
	grepResult, err := grepTool.ExecuteDetailed(context.Background(), map[string]any{
		"pattern":       "package main",
		"path":          ".",
		"owner_node_id": "plan-01",
	})
	if err != nil {
		t.Fatalf("grep should fall back to normal lookup after owner mismatch: %v", err)
	}
	if !strings.Contains(grepResult.DisplayText, "main.go") {
		t.Fatalf("expected grep to find base workspace content, got %q", grepResult.DisplayText)
	}
}

func TestWorkspaceResolveForLookupAcceptsWindowsSlashAbsolutePath(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("slash-rooted lookup aliases are Windows-specific")
	}

	base := t.TempDir()
	target := filepath.Join(base, "guide.md")
	if err := os.WriteFile(target, []byte("hello"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	ws := Workspace{
		BaseRoot: base,
		Root:     base,
	}

	volume := filepath.VolumeName(base)
	if volume == "" {
		t.Fatalf("expected volume for %q", base)
	}
	slashPath := strings.TrimPrefix(filepath.ToSlash(target), filepath.ToSlash(volume))
	resolved, err := ws.ResolveForLookup(slashPath)
	if err != nil {
		t.Fatalf("ResolveForLookup: %v", err)
	}
	if resolved != target {
		t.Fatalf("expected slash-rooted alias %q to resolve to %q, got %q", slashPath, target, resolved)
	}
}

func TestReadFileToolAcceptsWindowsSlashAbsolutePath(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("slash-rooted lookup aliases are Windows-specific")
	}

	base := t.TempDir()
	target := filepath.Join(base, "guide.md")
	if err := os.WriteFile(target, []byte("hello\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	volume := filepath.VolumeName(base)
	if volume == "" {
		t.Fatalf("expected volume for %q", base)
	}
	slashPath := strings.TrimPrefix(filepath.ToSlash(target), filepath.ToSlash(volume))
	tool := NewReadFileTool(Workspace{
		BaseRoot: base,
		Root:     base,
	})

	out, err := tool.Execute(context.Background(), map[string]any{"path": slashPath})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(out, "hello") {
		t.Fatalf("expected slash-rooted read_file lookup to return content, got %q", out)
	}
}

func TestReadFileToolPrefersCurrentDirectoryBeforeBaseRoot(t *testing.T) {
	base := t.TempDir()
	current := filepath.Join(base, "nested")
	if err := os.MkdirAll(current, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(base, "shared.txt"), []byte("base\n"), 0o644); err != nil {
		t.Fatalf("WriteFile base: %v", err)
	}
	if err := os.WriteFile(filepath.Join(current, "shared.txt"), []byte("current\n"), 0o644); err != nil {
		t.Fatalf("WriteFile current: %v", err)
	}

	tool := NewReadFileTool(Workspace{
		BaseRoot: base,
		Root:     current,
	})

	out, err := tool.Execute(context.Background(), map[string]any{"path": "shared.txt"})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(out, "current") {
		t.Fatalf("expected current directory file contents, got %q", out)
	}
	if strings.Contains(out, "base") {
		t.Fatalf("expected current directory file to win over base root, got %q", out)
	}
}

func TestReadFileToolReturnsCachedRangeHintForUnchangedFile(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "cached.txt")
	if err := os.WriteFile(target, []byte("alpha\nbeta\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	tool := NewReadFileTool(Workspace{
		BaseRoot: base,
		Root:     base,
	})

	first, err := tool.Execute(context.Background(), map[string]any{
		"path":       "cached.txt",
		"start_line": 1,
		"end_line":   1,
	})
	if err != nil {
		t.Fatalf("first Execute: %v", err)
	}
	if strings.Contains(first, "NOTE: returning cached content") {
		t.Fatalf("did not expect cache hint on first read, got %q", first)
	}

	second, err := tool.Execute(context.Background(), map[string]any{
		"path":       "cached.txt",
		"start_line": 1,
		"end_line":   1,
	})
	if err != nil {
		t.Fatalf("second Execute: %v", err)
	}
	if !strings.Contains(second, "NOTE: returning cached content for an unchanged read_file range.") {
		t.Fatalf("expected cache hint on repeated identical read, got %q", second)
	}
	if !strings.Contains(second, "   1 | alpha") {
		t.Fatalf("expected cached line content, got %q", second)
	}
}

func TestReadFileToolReturnsOutOfRangeDiagnosticWithoutError(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "short.txt")
	if err := os.WriteFile(target, []byte("alpha\nbeta\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	tool := NewReadFileTool(Workspace{
		BaseRoot: base,
		Root:     base,
	})

	result, err := tool.ExecuteDetailed(context.Background(), map[string]any{
		"path":       "short.txt",
		"start_line": 10,
		"end_line":   20,
	})
	if err != nil {
		t.Fatalf("expected out-of-range read to return diagnostic without error: %v", err)
	}
	if !strings.Contains(result.DisplayText, "read_file range is outside file") ||
		!strings.Contains(result.DisplayText, "File line count: 2") {
		t.Fatalf("expected range diagnostic with file line count, got %q", result.DisplayText)
	}
	if got := toolMetaString(result.Meta, "error_kind"); got != "range_out_of_bounds" {
		t.Fatalf("expected range_out_of_bounds metadata, got %#v", result.Meta)
	}
	if got := intValue(result.Meta, "file_line_count", 0); got != 2 {
		t.Fatalf("expected file_line_count=2 metadata, got %#v", result.Meta)
	}
}

func TestReadFileToolReturnsInvalidRangeDiagnosticWithoutError(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "sample.txt")
	if err := os.WriteFile(target, []byte("alpha\nbeta\ngamma\ndelta\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	tool := NewReadFileTool(Workspace{
		BaseRoot: base,
		Root:     base,
	})

	result, err := tool.ExecuteDetailed(context.Background(), map[string]any{
		"path":       "sample.txt",
		"start_line": 4,
		"end_line":   2,
	})
	if err != nil {
		t.Fatalf("expected invalid range to return diagnostic without error: %v", err)
	}
	if !strings.Contains(result.DisplayText, "read_file received an invalid line range") ||
		!strings.Contains(result.DisplayText, "File line count: 4") {
		t.Fatalf("expected invalid range diagnostic with file line count, got %q", result.DisplayText)
	}
	if got := toolMetaString(result.Meta, "error_kind"); got != "invalid_line_range" {
		t.Fatalf("expected invalid_line_range metadata, got %#v", result.Meta)
	}
	if got := intValue(result.Meta, "file_line_count", 0); got != 4 {
		t.Fatalf("expected file_line_count=4 metadata, got %#v", result.Meta)
	}
}

func TestReadFileToolInvalidatesCacheAfterFileChange(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "cached.txt")
	if err := os.WriteFile(target, []byte("alpha\nbeta\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	tool := NewReadFileTool(Workspace{
		BaseRoot: base,
		Root:     base,
	})

	if _, err := tool.Execute(context.Background(), map[string]any{
		"path":       "cached.txt",
		"start_line": 1,
		"end_line":   1,
	}); err != nil {
		t.Fatalf("first Execute: %v", err)
	}

	if err := os.WriteFile(target, []byte("updated\nbeta\n"), 0o644); err != nil {
		t.Fatalf("WriteFile update: %v", err)
	}

	out, err := tool.Execute(context.Background(), map[string]any{
		"path":       "cached.txt",
		"start_line": 1,
		"end_line":   1,
	})
	if err != nil {
		t.Fatalf("second Execute: %v", err)
	}
	if strings.Contains(out, "NOTE: returning cached content") {
		t.Fatalf("did not expect stale cache hint after file change, got %q", out)
	}
	if !strings.Contains(out, "   1 | updated") {
		t.Fatalf("expected fresh file contents after cache invalidation, got %q", out)
	}
}

func TestReadFileToolReturnsCoveredSubrangeFromCachedRange(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "cached.txt")
	if err := os.WriteFile(target, []byte("alpha\nbeta\ngamma\ndelta\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	tool := NewReadFileTool(Workspace{
		BaseRoot: base,
		Root:     base,
	})

	if _, err := tool.Execute(context.Background(), map[string]any{
		"path":       "cached.txt",
		"start_line": 1,
		"end_line":   4,
	}); err != nil {
		t.Fatalf("seed Execute: %v", err)
	}

	out, err := tool.Execute(context.Background(), map[string]any{
		"path":       "cached.txt",
		"start_line": 2,
		"end_line":   3,
	})
	if err != nil {
		t.Fatalf("subset Execute: %v", err)
	}
	if !strings.Contains(out, "NOTE: returning content from a cached overlapping read_file range.") {
		t.Fatalf("expected overlapping cache hint, got %q", out)
	}
	if !strings.Contains(out, "   2 | beta") || !strings.Contains(out, "   3 | gamma") {
		t.Fatalf("expected covered subrange content, got %q", out)
	}
	if strings.Contains(out, "   1 | alpha") || strings.Contains(out, "   4 | delta") {
		t.Fatalf("expected only requested subrange lines, got %q", out)
	}
}

func TestReadFileToolReturnsPartialOverlapPlusFreshTail(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "cached.txt")
	if err := os.WriteFile(target, []byte("alpha\nbeta\ngamma\ndelta\nepsilon\nzeta\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	tool := NewReadFileTool(Workspace{
		BaseRoot: base,
		Root:     base,
	})

	if _, err := tool.Execute(context.Background(), map[string]any{
		"path":       "cached.txt",
		"start_line": 2,
		"end_line":   4,
	}); err != nil {
		t.Fatalf("seed Execute: %v", err)
	}

	out, err := tool.Execute(context.Background(), map[string]any{
		"path":       "cached.txt",
		"start_line": 3,
		"end_line":   6,
	})
	if err != nil {
		t.Fatalf("partial overlap Execute: %v", err)
	}
	if !strings.Contains(out, "NOTE: returning content assembled from a cached partial overlap plus newly read lines.") {
		t.Fatalf("expected partial overlap hint, got %q", out)
	}
	if !strings.Contains(out, "   3 | gamma") || !strings.Contains(out, "   4 | delta") {
		t.Fatalf("expected cached overlap lines, got %q", out)
	}
	if !strings.Contains(out, "   5 | epsilon") || !strings.Contains(out, "   6 | zeta") {
		t.Fatalf("expected freshly read tail lines, got %q", out)
	}
	if strings.Contains(out, "   2 | beta") {
		t.Fatalf("did not expect extra pre-overlap line, got %q", out)
	}
}

func TestGrepToolAnnotatesMatchesInsideCachedReadSpan(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "sample.cpp")
	if err := os.WriteFile(target, []byte("alpha\nbeta target\ngamma\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	hints := &ToolHints{}
	ws := Workspace{
		BaseRoot:  base,
		Root:      base,
		ToolHints: hints,
	}
	readTool := NewReadFileTool(ws)
	grepTool := NewGrepTool(ws)

	if _, err := readTool.Execute(context.Background(), map[string]any{
		"path":       "sample.cpp",
		"start_line": 2,
		"end_line":   2,
	}); err != nil {
		t.Fatalf("read Execute: %v", err)
	}

	out, err := grepTool.Execute(context.Background(), map[string]any{
		"pattern": "target",
		"path":    ".",
	})
	if err != nil {
		t.Fatalf("grep Execute: %v", err)
	}
	if !strings.Contains(out, "[cached-nearby:inside]") {
		t.Fatalf("expected cached-nearby inside hint, got %q", out)
	}
}

func TestGrepToolAnnotatesMatchesNearCachedReadSpan(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "sample.cpp")
	if err := os.WriteFile(target, []byte("one\ntwo\nthree\nfour\nfive target\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	hints := &ToolHints{}
	ws := Workspace{
		BaseRoot:  base,
		Root:      base,
		ToolHints: hints,
	}
	readTool := NewReadFileTool(ws)
	grepTool := NewGrepTool(ws)

	if _, err := readTool.Execute(context.Background(), map[string]any{
		"path":       "sample.cpp",
		"start_line": 2,
		"end_line":   3,
	}); err != nil {
		t.Fatalf("read Execute: %v", err)
	}

	out, err := grepTool.Execute(context.Background(), map[string]any{
		"pattern": "target",
		"path":    ".",
	})
	if err != nil {
		t.Fatalf("grep Execute: %v", err)
	}
	if !strings.Contains(out, "[cached-nearby:2]") {
		t.Fatalf("expected cached-nearby distance hint, got %q", out)
	}
}

func TestGrepToolSkipsStaleCachedReadHintsAfterFileChange(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "sample.cpp")
	if err := os.WriteFile(target, []byte("alpha\nbeta target\ngamma\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	hints := &ToolHints{}
	ws := Workspace{
		BaseRoot:  base,
		Root:      base,
		ToolHints: hints,
	}
	readTool := NewReadFileTool(ws)
	grepTool := NewGrepTool(ws)

	if _, err := readTool.Execute(context.Background(), map[string]any{
		"path":       "sample.cpp",
		"start_line": 2,
		"end_line":   2,
	}); err != nil {
		t.Fatalf("read Execute: %v", err)
	}
	if err := os.WriteFile(target, []byte("alpha\nbeta target updated\ngamma\n"), 0o644); err != nil {
		t.Fatalf("WriteFile update: %v", err)
	}

	out, err := grepTool.Execute(context.Background(), map[string]any{
		"pattern": "target",
		"path":    ".",
	})
	if err != nil {
		t.Fatalf("grep Execute: %v", err)
	}
	if strings.Contains(out, "[cached-nearby:") {
		t.Fatalf("did not expect stale cached-nearby hint, got %q", out)
	}
}

func TestGrepToolUsesRipgrepBackendFormattingAndMetadata(t *testing.T) {
	root := t.TempDir()
	first := filepath.Join(root, "main.go")
	second := filepath.Join(root, "src", "driver.go")
	if err := os.MkdirAll(filepath.Dir(second), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(first, []byte("alpha needle\n"), 0o644); err != nil {
		t.Fatalf("WriteFile first: %v", err)
	}
	if err := os.WriteFile(second, []byte("beta needle\n"), 0o644); err != nil {
		t.Fatalf("WriteFile second: %v", err)
	}

	tool := NewGrepTool(Workspace{
		BaseRoot: root,
		Root:     root,
	})
	called := false
	tool.ripgrepSearch = func(ctx context.Context, request grepSearchRequest) (grepSearchResult, error) {
		called = true
		if request.Root != root {
			t.Fatalf("expected resolved root %q, got %q", root, request.Root)
		}
		if request.Pattern != "needle" || request.PatternForMeta != "needle" {
			t.Fatalf("unexpected pattern request: %#v", request)
		}
		return grepSearchResult{
			Matches: []grepSearchMatch{
				{Path: first, LineNo: 1, Line: "alpha needle\n"},
				{Path: second, LineNo: 1, Line: "beta needle\n"},
			},
		}, nil
	}

	result, err := tool.ExecuteDetailed(context.Background(), map[string]any{
		"pattern":     "needle",
		"path":        ".",
		"max_results": 10,
	})
	if err != nil {
		t.Fatalf("ExecuteDetailed: %v", err)
	}
	if !called {
		t.Fatalf("expected ripgrep backend to be called")
	}
	if !strings.Contains(result.DisplayText, "main.go:1: alpha needle") ||
		!strings.Contains(result.DisplayText, "src/driver.go:1: beta needle") {
		t.Fatalf("unexpected ripgrep formatted output: %q", result.DisplayText)
	}
	if toolMetaInt(result.Meta, "match_count") != 2 {
		t.Fatalf("expected match_count=2, got %#v", result.Meta)
	}
	if toolMetaInt(result.Meta, "file_count") != 2 {
		t.Fatalf("expected file_count=2, got %#v", result.Meta)
	}
	if toolMetaBool(result.Meta, "truncated") {
		t.Fatalf("did not expect truncation, got %#v", result.Meta)
	}
	paths := toolMetaStringSlice(result.Meta, "matched_paths")
	if len(paths) != 2 || paths[0] != "main.go" || paths[1] != "src/driver.go" {
		t.Fatalf("unexpected matched_paths: %#v", result.Meta)
	}
}

func TestGrepToolRipgrepBackendTruncationMetadata(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "main.go")
	if err := os.WriteFile(target, []byte("needle\nneedle\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	tool := NewGrepTool(Workspace{
		BaseRoot: root,
		Root:     root,
	})
	tool.ripgrepSearch = func(ctx context.Context, request grepSearchRequest) (grepSearchResult, error) {
		if request.MaxResults != 1 {
			t.Fatalf("expected max_results=1, got %d", request.MaxResults)
		}
		return grepSearchResult{
			Matches: []grepSearchMatch{
				{Path: target, LineNo: 1, Line: "needle\n"},
			},
			Truncated: true,
		}, nil
	}

	result, err := tool.ExecuteDetailed(context.Background(), map[string]any{
		"pattern":     "needle",
		"max_results": 1,
	})
	if err != nil {
		t.Fatalf("ExecuteDetailed: %v", err)
	}
	if !toolMetaBool(result.Meta, "truncated") {
		t.Fatalf("expected truncated=true, got %#v", result.Meta)
	}
	if toolMetaInt(result.Meta, "match_count") != 1 {
		t.Fatalf("expected one visible match, got %#v", result.Meta)
	}
}

func TestGrepToolFallsBackWhenRipgrepUnavailable(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("needle\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	tool := NewGrepTool(Workspace{
		BaseRoot: root,
		Root:     root,
	})
	tool.ripgrepSearch = func(ctx context.Context, request grepSearchRequest) (grepSearchResult, error) {
		return grepSearchResult{}, errRipgrepUnavailable
	}

	result, err := tool.ExecuteDetailed(context.Background(), map[string]any{
		"pattern": "needle",
	})
	if err != nil {
		t.Fatalf("ExecuteDetailed: %v", err)
	}
	if !strings.Contains(result.DisplayText, "main.go:1: needle") {
		t.Fatalf("expected Go fallback grep output, got %q", result.DisplayText)
	}
}

func TestGrepToolFallsBackWhenRipgrepJSONIsUnparseable(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("needle\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	tool := NewGrepTool(Workspace{
		BaseRoot: root,
		Root:     root,
	})
	tool.ripgrepSearch = func(ctx context.Context, request grepSearchRequest) (grepSearchResult, error) {
		return grepSearchResult{}, errRipgrepUnparseableJSON
	}

	result, err := tool.ExecuteDetailed(context.Background(), map[string]any{
		"pattern": "needle",
	})
	if err != nil {
		t.Fatalf("ExecuteDetailed: %v", err)
	}
	if !strings.Contains(result.DisplayText, "main.go:1: needle") {
		t.Fatalf("expected fallback after unparseable rg json, got %q", result.DisplayText)
	}
}

func TestGrepToolSkipsBinaryFilesWithFallback(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "text.txt"), []byte("needle\n"), 0o644); err != nil {
		t.Fatalf("WriteFile text: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "binary.bin"), []byte{'n', 'e', 'e', 'd', 'l', 'e', 0, '\n'}, 0o644); err != nil {
		t.Fatalf("WriteFile binary: %v", err)
	}

	tool := NewGrepTool(Workspace{
		BaseRoot: root,
		Root:     root,
	})
	tool.ripgrepSearch = func(ctx context.Context, request grepSearchRequest) (grepSearchResult, error) {
		return grepSearchResult{}, errRipgrepUnavailable
	}

	result, err := tool.ExecuteDetailed(context.Background(), map[string]any{
		"pattern": "needle",
	})
	if err != nil {
		t.Fatalf("ExecuteDetailed: %v", err)
	}
	if !strings.Contains(result.DisplayText, "text.txt:1: needle") {
		t.Fatalf("expected text match, got %q", result.DisplayText)
	}
	if strings.Contains(result.DisplayText, "binary.bin") {
		t.Fatalf("did not expect binary file match, got %q", result.DisplayText)
	}
}

func TestGrepToolFallsBackWhenRipgrepRejectsGoCompatibleRegex(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("needle\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	tool := NewGrepTool(Workspace{
		BaseRoot: root,
		Root:     root,
	})
	tool.ripgrepSearch = func(ctx context.Context, request grepSearchRequest) (grepSearchResult, error) {
		return grepSearchResult{}, fmt.Errorf("%w: regex parse error", errRipgrepInvalidPattern)
	}

	result, err := tool.ExecuteDetailed(context.Background(), map[string]any{
		"pattern": `\Qneedle\E`,
	})
	if err != nil {
		t.Fatalf("ExecuteDetailed should fall back to Go grep: %v", err)
	}
	if !strings.Contains(result.DisplayText, "main.go:1: needle") {
		t.Fatalf("expected Go fallback match for rg-rejected pattern, got %q", result.DisplayText)
	}
}

func TestGrepToolGlobFilteringCompatibility(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("needle\n"), 0o644); err != nil {
		t.Fatalf("WriteFile main: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "notes.txt"), []byte("needle\n"), 0o644); err != nil {
		t.Fatalf("WriteFile notes: %v", err)
	}

	tool := NewGrepTool(Workspace{
		BaseRoot: root,
		Root:     root,
	})
	tool.ripgrepSearch = func(ctx context.Context, request grepSearchRequest) (grepSearchResult, error) {
		return grepSearchResult{}, errRipgrepUnsupportedInput
	}

	result, err := tool.ExecuteDetailed(context.Background(), map[string]any{
		"pattern": "needle",
		"glob":    "*.go",
	})
	if err != nil {
		t.Fatalf("ExecuteDetailed: %v", err)
	}
	if !strings.Contains(result.DisplayText, "main.go:1: needle") {
		t.Fatalf("expected go file match, got %q", result.DisplayText)
	}
	if strings.Contains(result.DisplayText, "notes.txt") {
		t.Fatalf("did not expect txt file match, got %q", result.DisplayText)
	}
}

func TestGrepToolDoesNotExposeRawRipgrepArgs(t *testing.T) {
	def := NewGrepTool(Workspace{}).Definition()
	properties, ok := def.InputSchema["properties"].(map[string]any)
	if !ok {
		t.Fatalf("expected object properties, got %#v", def.InputSchema)
	}
	for _, key := range []string{"args", "rg_args", "ripgrep_args", "pre", "search_zip", "follow"} {
		if _, exists := properties[key]; exists {
			t.Fatalf("grep schema exposed raw ripgrep option %q", key)
		}
	}

	args, err := buildRipgrepArgs(grepSearchRequest{
		Root:       ".",
		Pattern:    "--pre",
		MaxResults: 10,
	})
	if err != nil {
		t.Fatalf("buildRipgrepArgs: %v", err)
	}
	separator := slices.Index(args, "--")
	if separator < 0 {
		t.Fatalf("expected -- separator in rg args: %#v", args)
	}
	for _, arg := range args[:separator] {
		if arg == "--pre" || arg == "--hostname-bin" || arg == "--search-zip" || arg == "--follow" {
			t.Fatalf("dangerous ripgrep option appeared before separator: %#v", args)
		}
	}
	if separator+1 >= len(args) || args[separator+1] != "--pre" {
		t.Fatalf("expected pattern to be passed after --, got %#v", args)
	}
}

func TestBuildRipgrepArgsFallsBackForGoOnlyGlobSemantics(t *testing.T) {
	for _, glob := range []string{`src/*.go`, `!*.go`, `{main,driver}.go`} {
		_, err := buildRipgrepArgs(grepSearchRequest{
			Root:       ".",
			Pattern:    "needle",
			Glob:       glob,
			MaxResults: 10,
		})
		if !errors.Is(err, errRipgrepUnsupportedInput) {
			t.Fatalf("glob %q should use Go fallback, got %v", glob, err)
		}
	}
}

func TestRipgrepPATHFallbackAllowedOnlyForDevVersion(t *testing.T) {
	oldVersion := appVersion
	oldCommit := appCommit
	oldBuildTime := appBuildTime
	defer func() {
		appVersion = oldVersion
		appCommit = oldCommit
		appBuildTime = oldBuildTime
	}()

	appVersion = "dev"
	appCommit = ""
	appBuildTime = ""
	if !ripgrepPATHFallbackAllowed() {
		t.Fatalf("expected dev build to allow PATH ripgrep fallback")
	}

	appVersion = "1.2.3.4"
	appCommit = ""
	appBuildTime = ""
	if ripgrepPATHFallbackAllowed() {
		t.Fatalf("expected versioned build to require a ripgrep sidecar or Go fallback")
	}
}

func TestParseRipgrepJSONMatch(t *testing.T) {
	raw := `{"type":"match","data":{"path":{"text":"src/main.go"},"lines":{"text":"needle here\n"},"line_number":12}}`
	match, ok, err := parseRipgrepJSONMatch([]byte(raw))
	if err != nil {
		t.Fatalf("parseRipgrepJSONMatch: %v", err)
	}
	if !ok {
		t.Fatalf("expected match event")
	}
	if filepath.ToSlash(match.Path) != "src/main.go" || match.LineNo != 12 || match.Line != "needle here\n" {
		t.Fatalf("unexpected parsed match: %+v", match)
	}

	raw = `{"type":"match","data":{"path":{"text":"bin/blob"},"lines":{"bytes":"AAAA"},"line_number":1}}`
	if _, ok, err := parseRipgrepJSONMatch([]byte(raw)); err != nil || ok {
		t.Fatalf("expected binary/bytes match to be ignored, ok=%v err=%v", ok, err)
	}
}

func TestToolRegistrySharesReadHintsBetweenReadFileAndGrep(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "sample.cpp")
	if err := os.WriteFile(target, []byte("alpha\nbeta target\ngamma\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	ws := Workspace{
		BaseRoot: base,
		Root:     base,
	}
	registry := NewToolRegistry(NewReadFileTool(ws), NewGrepTool(ws))

	if _, err := registry.Execute(context.Background(), "read_file", `{"path":"sample.cpp","start_line":2,"end_line":2}`); err != nil {
		t.Fatalf("read_file Execute: %v", err)
	}
	out, err := registry.Execute(context.Background(), "grep", `{"pattern":"target","path":"."}`)
	if err != nil {
		t.Fatalf("grep Execute: %v", err)
	}
	if !strings.Contains(out, "[cached-nearby:inside]") {
		t.Fatalf("expected registry-shared cached hint, got %q", out)
	}
}

func TestGrepToolNormalizesRelativeRipgrepPathsForReadHints(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "sample.cpp")
	if err := os.WriteFile(target, []byte("alpha\nbeta target\ngamma\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	ws := Workspace{
		BaseRoot: base,
		Root:     base,
	}
	readTool := NewReadFileTool(ws)
	grepTool := NewGrepTool(ws)
	grepTool.ripgrepSearch = func(ctx context.Context, request grepSearchRequest) (grepSearchResult, error) {
		return grepSearchResult{
			Matches: []grepSearchMatch{
				{Path: "sample.cpp", LineNo: 2, Line: "beta target"},
			},
		}, nil
	}
	registry := NewToolRegistry(readTool, grepTool)

	if _, err := registry.Execute(context.Background(), "read_file", `{"path":"sample.cpp","start_line":2,"end_line":2}`); err != nil {
		t.Fatalf("read_file Execute: %v", err)
	}
	out, err := registry.Execute(context.Background(), "grep", `{"pattern":"target","path":"."}`)
	if err != nil {
		t.Fatalf("grep Execute: %v", err)
	}
	if !strings.Contains(out, "sample.cpp:2: beta target [cached-nearby:inside]") {
		t.Fatalf("expected relative rg path to preserve cached hint, got %q", out)
	}
}

func TestGrepToolNormalizesRelativeRipgrepPathsForFileRoot(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "sample.cpp")
	if err := os.WriteFile(target, []byte("alpha\nbeta target\ngamma\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	ws := Workspace{
		BaseRoot: base,
		Root:     base,
	}
	readTool := NewReadFileTool(ws)
	grepTool := NewGrepTool(ws)
	grepTool.ripgrepSearch = func(ctx context.Context, request grepSearchRequest) (grepSearchResult, error) {
		return grepSearchResult{
			Matches: []grepSearchMatch{
				{Path: "sample.cpp", LineNo: 2, Line: "beta target"},
			},
		}, nil
	}
	registry := NewToolRegistry(readTool, grepTool)

	if _, err := registry.Execute(context.Background(), "read_file", `{"path":"sample.cpp","start_line":2,"end_line":2}`); err != nil {
		t.Fatalf("read_file Execute: %v", err)
	}
	out, err := registry.Execute(context.Background(), "grep", `{"pattern":"target","path":"sample.cpp"}`)
	if err != nil {
		t.Fatalf("grep Execute: %v", err)
	}
	if !strings.Contains(out, "sample.cpp:2: beta target [cached-nearby:inside]") {
		t.Fatalf("expected file-root relative rg path to preserve cached hint, got %q", out)
	}
}

func TestReadToolsUseWorkspaceConfiguredHintAndCacheLimits(t *testing.T) {
	base := t.TempDir()
	readTool := NewReadFileTool(Workspace{
		BaseRoot:         base,
		Root:             base,
		ReadHintSpans:    5,
		ReadCacheEntries: 3,
	})
	grepTool := NewGrepTool(Workspace{
		BaseRoot:      base,
		Root:          base,
		ReadHintSpans: 5,
	})
	_ = NewToolRegistry(readTool, grepTool)

	if readTool.maxCache != 3 {
		t.Fatalf("expected read cache size 3, got %d", readTool.maxCache)
	}
	if readTool.ws.ToolHints == nil {
		t.Fatalf("expected shared tool hints to be initialized")
	}
	if readTool.ws.ToolHints.maxReadSpans != 5 {
		t.Fatalf("expected shared read hint limit 5, got %d", readTool.ws.ToolHints.maxReadSpans)
	}
}

func TestListFilesToolFallsBackToBaseRootWhenRelativePathMissingInCurrentDirectory(t *testing.T) {
	base := t.TempDir()
	current := filepath.Join(base, "nested")
	targetDir := filepath.Join(base, "docs")
	if err := os.MkdirAll(current, 0o755); err != nil {
		t.Fatalf("MkdirAll current: %v", err)
	}
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		t.Fatalf("MkdirAll target: %v", err)
	}
	if err := os.WriteFile(filepath.Join(targetDir, "guide.md"), []byte("content"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	tool := NewListFilesTool(Workspace{
		BaseRoot: base,
		Root:     current,
	})

	out, err := tool.Execute(context.Background(), map[string]any{"path": "docs"})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(out, "../docs/guide.md") {
		t.Fatalf("expected fallback listing to include root-level file, got %q", out)
	}
}

func TestListFilesToolReturnsFilePathWhenTargetIsFile(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "SampleGame.cpp")
	if err := os.WriteFile(target, []byte("int main() { return 0; }\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	tool := NewListFilesTool(Workspace{
		BaseRoot: root,
		Root:     root,
	})
	result, err := tool.ExecuteDetailed(context.Background(), map[string]any{
		"path": "SampleGame.cpp",
	})
	if err != nil {
		t.Fatalf("ExecuteDetailed: %v", err)
	}
	if strings.TrimSpace(result.DisplayText) != "SampleGame.cpp" {
		t.Fatalf("expected single file listing, got %q", result.DisplayText)
	}
	if toolMetaString(result.Meta, "path_type") != "file" {
		t.Fatalf("expected path_type=file metadata, got %#v", result.Meta)
	}
	if toolMetaInt(result.Meta, "entry_count") != 1 {
		t.Fatalf("expected entry_count=1, got %#v", result.Meta)
	}
}

func TestListFilesToolMissingPathReportsCandidates(t *testing.T) {
	root := t.TempDir()
	sourceDir := filepath.Join(root, "SampleGame", "SampleGame")
	if err := os.MkdirAll(sourceDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "SampleGame.cpp"), []byte("int main() {}\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	tool := NewListFilesTool(Workspace{
		BaseRoot: root,
		Root:     root,
	})
	result, err := tool.ExecuteDetailed(context.Background(), map[string]any{
		"path": "SampleGame.cpp",
	})
	if err == nil {
		t.Fatalf("expected missing path error")
	}
	if !strings.Contains(result.DisplayText, "list_files target does not exist: SampleGame.cpp") {
		t.Fatalf("expected missing path diagnostic, got %q", result.DisplayText)
	}
	if !strings.Contains(result.DisplayText, "SampleGame/SampleGame/SampleGame.cpp") {
		t.Fatalf("expected same-basename candidate, got %q", result.DisplayText)
	}
	if toolMetaString(result.Meta, "path_type") != "missing" {
		t.Fatalf("expected path_type=missing metadata, got %#v", result.Meta)
	}
	if toolMetaString(result.Meta, "error_kind") != "missing_path" {
		t.Fatalf("expected missing_path error_kind, got %#v", result.Meta)
	}
	candidates := toolMetaStringSlice(result.Meta, "candidate_paths")
	if len(candidates) != 1 || candidates[0] != "SampleGame/SampleGame/SampleGame.cpp" {
		t.Fatalf("expected candidate_paths metadata, got %#v", result.Meta)
	}
}

func TestListFilesToolReportsTruncationAndClampsInvalidMaxEntries(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"a.txt", "b.txt", "c.txt"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(name), 0o644); err != nil {
			t.Fatalf("WriteFile %s: %v", name, err)
		}
	}

	tool := NewListFilesTool(Workspace{
		BaseRoot: root,
		Root:     root,
	})
	result, err := tool.ExecuteDetailed(context.Background(), map[string]any{
		"max_entries": 2,
	})
	if err != nil {
		t.Fatalf("ExecuteDetailed truncated: %v", err)
	}
	if !strings.Contains(result.DisplayText, "... (truncated at 2 entries") {
		t.Fatalf("expected visible truncation hint, got %q", result.DisplayText)
	}
	if toolMetaBool(result.Meta, "truncated") != true {
		t.Fatalf("expected truncated=true metadata, got %#v", result.Meta)
	}
	if toolMetaInt(result.Meta, "entry_count") != 2 {
		t.Fatalf("expected entry_count=2 metadata, got %#v", result.Meta)
	}

	result, err = tool.ExecuteDetailed(context.Background(), map[string]any{
		"max_entries": 0,
	})
	if err != nil {
		t.Fatalf("ExecuteDetailed clamped: %v", err)
	}
	if strings.Contains(result.DisplayText, "truncated at 0") {
		t.Fatalf("max_entries=0 should be clamped instead of producing a zero-entry truncation, got %q", result.DisplayText)
	}
	if toolMetaInt(result.Meta, "max_entries") != 200 {
		t.Fatalf("expected max_entries to be clamped to default, got %#v", result.Meta)
	}
	if toolMetaBool(result.Meta, "truncated") {
		t.Fatalf("did not expect clamped default listing to truncate, got %#v", result.Meta)
	}
}

func TestGrepToolMissingPathReportsCandidates(t *testing.T) {
	root := t.TempDir()
	reportDir := filepath.Join(root, "SampleGame")
	if err := os.MkdirAll(reportDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(reportDir, "BugReport.md"), []byte("BUG-001\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	tool := NewGrepTool(Workspace{
		BaseRoot: root,
		Root:     root,
	})
	result, err := tool.ExecuteDetailed(context.Background(), map[string]any{
		"path":    "BugReport.md",
		"pattern": "BUG-",
	})
	if err == nil {
		t.Fatalf("expected missing path error")
	}
	if !strings.Contains(result.DisplayText, "grep target does not exist: BugReport.md") {
		t.Fatalf("expected missing path diagnostic, got %q", result.DisplayText)
	}
	if !strings.Contains(result.DisplayText, "SampleGame/BugReport.md") {
		t.Fatalf("expected same-basename candidate, got %q", result.DisplayText)
	}
	candidates := toolMetaStringSlice(result.Meta, "candidate_paths")
	if len(candidates) != 1 || candidates[0] != "SampleGame/BugReport.md" {
		t.Fatalf("expected candidate_paths metadata, got %#v", result.Meta)
	}
	if toolMetaString(result.Meta, "error_kind") != "missing_path" {
		t.Fatalf("expected missing_path error_kind, got %#v", result.Meta)
	}
}

func TestGrepToolReportsInvalidPatternAndClampsMaxResults(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("needle\nneedle\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	tool := NewGrepTool(Workspace{
		BaseRoot: root,
		Root:     root,
	})
	result, err := tool.ExecuteDetailed(context.Background(), map[string]any{
		"pattern":     "[",
		"max_results": 0,
	})
	if err == nil {
		t.Fatalf("expected invalid pattern error")
	}
	if !strings.Contains(result.DisplayText, "grep received an invalid regular expression") {
		t.Fatalf("expected invalid pattern diagnostic, got %q", result.DisplayText)
	}
	if toolMetaString(result.Meta, "error_kind") != "invalid_pattern" {
		t.Fatalf("expected invalid_pattern error_kind, got %#v", result.Meta)
	}
	if toolMetaInt(result.Meta, "max_results") != 100 {
		t.Fatalf("expected max_results to be clamped to default, got %#v", result.Meta)
	}

	result, err = tool.ExecuteDetailed(context.Background(), map[string]any{
		"pattern":     "needle",
		"max_results": 0,
	})
	if err != nil {
		t.Fatalf("ExecuteDetailed clamped grep: %v", err)
	}
	if toolMetaInt(result.Meta, "max_results") != 100 {
		t.Fatalf("expected max_results to remain clamped to default, got %#v", result.Meta)
	}
	if toolMetaInt(result.Meta, "match_count") != 2 {
		t.Fatalf("expected both matches after clamp, got %#v", result.Meta)
	}
}

func TestWriteFileToolUpdatesFallbackTargetInsteadOfCreatingSiblingFile(t *testing.T) {
	base := t.TempDir()
	current := filepath.Join(base, "nested")
	if err := os.MkdirAll(current, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	target := filepath.Join(base, "config.txt")
	if err := os.WriteFile(target, []byte("old"), 0o644); err != nil {
		t.Fatalf("WriteFile target: %v", err)
	}

	tool := NewWriteFileTool(Workspace{
		BaseRoot: base,
		Root:     current,
	})

	if _, err := tool.Execute(context.Background(), map[string]any{
		"path":    "config.txt",
		"content": "new",
	}); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("ReadFile target: %v", err)
	}
	if string(data) != "new" {
		t.Fatalf("expected fallback target update, got %q", string(data))
	}
	if _, err := os.Stat(filepath.Join(current, "config.txt")); !os.IsNotExist(err) {
		t.Fatalf("did not expect a new file in the current directory, err=%v", err)
	}
}

func TestWriteFileToolCreatesNewFileInCurrentDirectoryWhenNoFallbackExists(t *testing.T) {
	base := t.TempDir()
	current := filepath.Join(base, "nested")
	if err := os.MkdirAll(current, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	tool := NewWriteFileTool(Workspace{
		BaseRoot: base,
		Root:     current,
	})

	if _, err := tool.Execute(context.Background(), map[string]any{
		"path":    "new.txt",
		"content": "hello",
	}); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(current, "new.txt"))
	if err != nil {
		t.Fatalf("ReadFile current: %v", err)
	}
	if string(data) != "hello" {
		t.Fatalf("expected current-directory create, got %q", string(data))
	}
}

func TestReplaceInFileToolUpdatesFallbackTarget(t *testing.T) {
	base := t.TempDir()
	current := filepath.Join(base, "nested")
	if err := os.MkdirAll(current, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	target := filepath.Join(base, "sample.txt")
	if err := os.WriteFile(target, []byte("alpha beta"), 0o644); err != nil {
		t.Fatalf("WriteFile target: %v", err)
	}

	tool := NewReplaceInFileTool(Workspace{
		BaseRoot: base,
		Root:     current,
	})

	if _, err := tool.Execute(context.Background(), map[string]any{
		"path":    "sample.txt",
		"search":  "beta",
		"replace": "gamma",
	}); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("ReadFile target: %v", err)
	}
	if string(data) != "alpha gamma" {
		t.Fatalf("expected fallback replace target update, got %q", string(data))
	}
}
