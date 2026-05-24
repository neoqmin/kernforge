package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	defaultAgentsMDFilename = "AGENTS.md"
	localAgentsMDFilename   = "AGENTS.override.md"
	agentsMDMaxBytes        = 32 * 1024
)

func (a *Agent) projectAgentsMDPromptSection() string {
	if a == nil || a.Session == nil {
		return ""
	}
	cwd := strings.TrimSpace(a.Session.WorkingDir)
	if cwd == "" {
		cwd = strings.TrimSpace(workspaceEffectiveActiveRoot(a.Workspace, a.Session))
	}
	if cwd == "" {
		return ""
	}
	root := strings.TrimSpace(workspaceEffectiveBaseRoot(a.Workspace, a.Session))
	if root == "" {
		root = strings.TrimSpace(workspaceEffectiveActiveRoot(a.Workspace, a.Session))
	}
	if root == "" {
		root = cwd
	}
	contents := loadProjectAgentsMD(root, cwd, agentsMDMaxBytes)
	if strings.TrimSpace(contents) == "" {
		return ""
	}
	return fmt.Sprintf("# AGENTS.md instructions for %s\n\n<INSTRUCTIONS>\n%s\n</INSTRUCTIONS>", cwd, strings.TrimSpace(contents))
}

func loadProjectAgentsMD(root string, cwd string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	searchDirs := agentsMDSearchDirs(root, cwd)
	if len(searchDirs) == 0 {
		return ""
	}
	remaining := maxBytes
	parts := make([]string, 0, len(searchDirs))
	for _, dir := range searchDirs {
		if remaining <= 0 {
			break
		}
		path := firstAgentsMDPath(dir)
		if path == "" {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if len(data) > remaining {
			data = data[:remaining]
		}
		text := strings.TrimSpace(strings.ToValidUTF8(string(data), "\uFFFD"))
		if text == "" {
			continue
		}
		parts = append(parts, text)
		remaining -= len(data)
	}
	return strings.Join(parts, "\n\n")
}

func agentsMDSearchDirs(root string, cwd string) []string {
	cwd = cleanAbsPath(cwd)
	root = cleanAbsPath(root)
	if cwd == "" {
		return nil
	}
	if root == "" {
		return []string{cwd}
	}
	if !pathContains(root, cwd) {
		return []string{cwd}
	}
	var reversed []string
	cursor := cwd
	for {
		reversed = append(reversed, cursor)
		if samePath(cursor, root) {
			break
		}
		parent := filepath.Dir(cursor)
		if parent == cursor {
			break
		}
		cursor = parent
	}
	dirs := make([]string, 0, len(reversed))
	for i := len(reversed) - 1; i >= 0; i-- {
		dirs = append(dirs, reversed[i])
	}
	return dirs
}

func firstAgentsMDPath(dir string) string {
	for _, name := range []string{localAgentsMDFilename, defaultAgentsMDFilename} {
		path := filepath.Join(dir, name)
		info, err := os.Stat(path)
		if err != nil || info == nil || info.IsDir() {
			continue
		}
		return path
	}
	return ""
}

func cleanAbsPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	return filepath.Clean(path)
}

func pathContains(root string, child string) bool {
	root = cleanAbsPath(root)
	child = cleanAbsPath(child)
	if root == "" || child == "" {
		return false
	}
	if samePath(root, child) {
		return true
	}
	rel, err := filepath.Rel(root, child)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || filepath.IsAbs(rel) {
		return false
	}
	return true
}
