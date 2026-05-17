package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type workspaceFileSignature struct {
	Size                 int64
	ModTime              int64
	Mode                 os.FileMode
	ContentSHA           string
	LinkTarget           string
	LinkTargetStatus     string
	LinkTargetSize       int64
	LinkTargetModTime    int64
	LinkTargetMode       os.FileMode
	LinkTargetContentSHA string
}

func snapshotWorkspaceFiles(root string) (map[string]workspaceFileSignature, error) {
	snapshot := map[string]workspaceFileSignature{}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if resolvedRoot, err := filepath.EvalSymlinks(rootAbs); err == nil {
		rootAbs = resolvedRoot
	}
	walkRoot := rootAbs
	err = filepath.WalkDir(walkRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, infoErr := os.Lstat(path)
		if infoErr != nil {
			return infoErr
		}
		rel := "."
		if path != walkRoot {
			computed, relErr := filepath.Rel(walkRoot, path)
			if relErr != nil {
				return relErr
			}
			rel = filepath.Clean(computed)
		}
		signature, sigErr := workspaceFileSignatureForPath(rootAbs, path, info)
		if sigErr != nil {
			return sigErr
		}
		snapshot[rel] = signature
		if d.IsDir() {
			return nil
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return snapshot, nil
}

func workspaceFileSignatureForPath(rootAbs string, path string, info fs.FileInfo) (workspaceFileSignature, error) {
	signature := workspaceFileSignature{
		Size:    info.Size(),
		ModTime: info.ModTime().UnixNano(),
		Mode:    info.Mode(),
	}
	if info.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(path)
		if err != nil {
			return workspaceFileSignature{}, err
		}
		signature.LinkTarget = target
		targetInfo, err := os.Stat(path)
		if err != nil {
			signature.LinkTargetStatus = workspaceFileSignatureErrorStatus(err)
			return signature, nil
		}
		resolvedTarget, err := filepath.EvalSymlinks(path)
		if err != nil {
			signature.LinkTargetStatus = workspaceFileSignatureErrorStatus(err)
			return signature, nil
		}
		resolvedTargetAbs, err := filepath.Abs(resolvedTarget)
		if err != nil {
			return workspaceFileSignature{}, err
		}
		if !pathWithinRoot(rootAbs, resolvedTargetAbs) {
			signature.LinkTargetStatus = "outside_root"
			return signature, nil
		}
		signature.LinkTargetStatus = "ok"
		signature.LinkTargetSize = targetInfo.Size()
		signature.LinkTargetModTime = targetInfo.ModTime().UnixNano()
		signature.LinkTargetMode = targetInfo.Mode()
		if targetInfo.Mode().IsRegular() {
			contentSHA, err := hashRegularFile(path)
			if err != nil {
				return workspaceFileSignature{}, err
			}
			signature.LinkTargetContentSHA = contentSHA
		}
		return signature, nil
	}
	if info.Mode().IsRegular() {
		contentSHA, err := hashRegularFile(path)
		if err != nil {
			return workspaceFileSignature{}, err
		}
		signature.ContentSHA = contentSHA
	}
	return signature, nil
}

func workspaceFileSignatureErrorStatus(err error) string {
	switch {
	case err == nil:
		return "ok"
	case os.IsNotExist(err):
		return "not_exist"
	case os.IsPermission(err):
		return "permission"
	default:
		return "error"
	}
}

func hashRegularFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func normalizeAllowedWriteScopes(root string, allowed []string) []string {
	scopes := make([]string, 0, len(allowed))
	for _, raw := range allowed {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		abs := trimmed
		if !filepath.IsAbs(abs) {
			abs = filepath.Join(root, trimmed)
		}
		rel, err := filepath.Rel(root, abs)
		if err != nil {
			continue
		}
		rel = filepath.Clean(rel)
		if !workspaceRelativePathStaysWithinRoot(rel) {
			continue
		}
		if rel == "." {
			scopes = append(scopes, rel)
			continue
		}
		scopes = append(scopes, rel)
	}
	return normalizeTaskStateList(scopes, 32)
}

func workspaceRelativePathStaysWithinRoot(rel string) bool {
	clean := filepath.Clean(strings.TrimSpace(rel))
	if clean == "" || filepath.IsAbs(clean) {
		return false
	}
	if clean == "." {
		return true
	}
	if clean == ".." {
		return false
	}
	return !strings.HasPrefix(clean, ".."+string(filepath.Separator))
}

func pathMatchesAnyAllowedScope(relPath string, allowed []string) bool {
	cleanRel := filepath.Clean(relPath)
	for _, scope := range allowed {
		cleanScope := filepath.Clean(scope)
		if cleanScope == "." {
			return true
		}
		if workspaceScopePathEqual(cleanRel, cleanScope) {
			return true
		}
		prefix := cleanScope + string(filepath.Separator)
		if workspaceScopePathHasPrefix(cleanRel, prefix) {
			return true
		}
	}
	return false
}

func changedWorkspaceSignaturePaths(before map[string]workspaceFileSignature, current map[string]workspaceFileSignature) []string {
	if len(before) == 0 && len(current) == 0 {
		return nil
	}
	seen := map[string]bool{}
	for path := range before {
		seen[filepath.Clean(path)] = true
	}
	for path := range current {
		seen[filepath.Clean(path)] = true
	}
	changed := make([]string, 0)
	for path := range seen {
		left, leftOK := before[path]
		right, rightOK := current[path]
		if leftOK && rightOK && left == right {
			continue
		}
		changed = append(changed, filepath.ToSlash(path))
	}
	return normalizeWorkspaceSignaturePathList(changed)
}

func verificationWorkspaceSourceOrConfigChanges(paths []string) []string {
	var out []string
	for _, path := range normalizeWorkspaceSignaturePathList(paths) {
		if verificationWorkspaceChangeIsSourceOrConfig(path) {
			out = append(out, path)
		}
	}
	return normalizeWorkspaceSignaturePathList(out)
}

func verificationWorkspaceChangeIsSourceOrConfig(path string) bool {
	clean := strings.ToLower(filepath.ToSlash(filepath.Clean(strings.TrimSpace(path))))
	if clean == "" || clean == "." {
		return false
	}
	if verificationWorkspacePathIsBuildArtifact(clean) {
		return false
	}
	base := filepath.Base(clean)
	switch base {
	case "go.mod", "go.sum", "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
		"cargo.toml", "cargo.lock", "cmakelists.txt", "makefile", "dockerfile":
		return true
	}
	switch filepath.Ext(clean) {
	case ".go", ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".inl",
		".rs", ".py", ".js", ".jsx", ".ts", ".tsx", ".cs", ".java", ".kt", ".swift",
		".m", ".mm", ".sh", ".ps1", ".bat", ".cmd", ".sql",
		".json", ".yaml", ".yml", ".toml", ".xml", ".props", ".targets", ".sln", ".vcxproj", ".vcproj",
		".cmake", ".gradle", ".md":
		return true
	}
	return false
}

func verificationWorkspacePathIsBuildArtifact(path string) bool {
	parts := strings.Split(strings.ToLower(filepath.ToSlash(path)), "/")
	for _, part := range parts {
		switch part {
		case "bin", "obj", "build", "dist", "out", "target", ".gradle", ".pytest_cache", ".mypy_cache",
			"__pycache__", "node_modules", ".next", ".nuxt", ".turbo", ".cache":
			return true
		}
		if strings.HasSuffix(part, ".tlog") {
			return true
		}
	}
	switch filepath.Ext(path) {
	case ".obj", ".o", ".pch", ".pdb", ".ilk", ".idb", ".ipdb", ".iobj", ".lastbuildstate",
		".log", ".tmp", ".cache", ".dll", ".exe", ".lib", ".exp", ".so", ".dylib", ".class":
		return true
	}
	return false
}

func workspaceSnapshotExternalSymlinkPaths(snapshot map[string]workspaceFileSignature) []string {
	paths := make([]string, 0)
	for path, signature := range snapshot {
		if signature.LinkTargetStatus == "outside_root" {
			paths = append(paths, filepath.ToSlash(filepath.Clean(path)))
		}
	}
	return normalizeWorkspaceSignaturePathList(paths)
}

func normalizeWorkspaceSignaturePathList(paths []string) []string {
	if len(paths) == 0 {
		return nil
	}
	seen := map[string]bool{}
	normalized := make([]string, 0, len(paths))
	for _, path := range paths {
		trimmed := strings.TrimSpace(path)
		if trimmed == "" {
			continue
		}
		clean := filepath.ToSlash(filepath.Clean(trimmed))
		if clean == "" || seen[clean] {
			continue
		}
		seen[clean] = true
		normalized = append(normalized, clean)
	}
	sort.Strings(normalized)
	return normalized
}

func workspaceScopePathEqual(left string, right string) bool {
	if workspacePathsAreCaseInsensitiveByDefault() {
		return strings.EqualFold(left, right)
	}
	return left == right
}

func workspaceScopePathHasPrefix(path string, prefix string) bool {
	cleanPath := filepath.Clean(path)
	cleanScope := filepath.Clean(strings.TrimSuffix(prefix, string(filepath.Separator)))
	if workspacePathsAreCaseInsensitiveByDefault() {
		cleanPath = strings.ToLower(cleanPath)
		cleanScope = strings.ToLower(cleanScope)
	}
	rel, err := filepath.Rel(cleanScope, cleanPath)
	if err != nil {
		return false
	}
	if rel == "." || rel == ".." || filepath.IsAbs(rel) {
		return false
	}
	return !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func shellJobNow() time.Time {
	return time.Now()
}
