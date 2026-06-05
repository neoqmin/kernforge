package main

import (
	"path/filepath"
	"sort"
	"strings"
)

func filterPatchScopeChangedPaths(paths []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, path := range paths {
		normalized := normalizePatchScopePath(path)
		if normalized == "" || pathLooksGeneratedRuntimeOrBuildArtifact(normalized) || seen[normalized] {
			continue
		}
		seen[normalized] = true
		out = append(out, normalized)
	}
	sort.Strings(out)
	return out
}

func normalizePatchScopePath(path string) string {
	path = strings.TrimSpace(filepath.ToSlash(path))
	if path == "" {
		return ""
	}
	path = strings.TrimPrefix(path, "./")
	return path
}

func pathLooksGeneratedRuntimeOrBuildArtifact(path string) bool {
	path = normalizePatchScopePath(path)
	if path == "" {
		return true
	}
	lower := strings.ToLower(path)
	segments := strings.Split(lower, "/")
	for _, segment := range segments {
		if segment == "" {
			continue
		}
		switch segment {
		case ".git", ".kernforge", ".claude", ".vs", ".vscode", ".idea",
			"debug", "release", "x64", "x86", "win32", "arm64",
			"bin", "obj", "build", "out", "dist", "target",
			"node_modules", "__pycache__", ".pytest_cache", ".mypy_cache":
			return true
		}
		if strings.HasSuffix(segment, ".tlog") || strings.HasSuffix(segment, ".dir") {
			return true
		}
	}
	base := filepath.Base(lower)
	if strings.EqualFold(base, ".ds_store") || strings.EqualFold(base, "thumbs.db") {
		return true
	}
	switch filepath.Ext(lower) {
	case ".log", ".tlog", ".tmp", ".temp", ".cache",
		".pdb", ".obj", ".o", ".ilk", ".idb", ".pch", ".ipch",
		".bin", ".exe", ".dll", ".sys", ".lib", ".exp", ".cat", ".cer",
		".zip", ".7z", ".rar", ".tar", ".gz",
		".class", ".jar", ".pyc":
		return true
	default:
		return false
	}
}
