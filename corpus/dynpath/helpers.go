package dynpath

import "path/filepath"

// cleanPath 包装 filepath.Clean，作为 path_clean 净化的项目内入口。
func cleanPath(p string) string {
	return filepath.Clean(p)
}
