package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// CachedFinding 与 Finding 结构对齐，用于缓存序列化
type CachedFinding struct {
	RuleID string `json:"rule_id"`
	File   string `json:"file"`
	Line   int    `json:"line"`
	FuncID string `json:"func_id"`
	Origin string `json:"origin"`
}

// Cache 增量分析缓存。
//   - 包级源码指纹：判断哪些包发生变化
//   - 每包 finding：未变包直接复用，无需重新分析
//   - 调用依赖（calleePkg -> callerPkgs）：计算受影响包闭包
type Cache struct {
	dir       string
	root      string
	Packages  map[string]PkgFingerprint  `json:"packages"`
	Findings  map[string][]CachedFinding `json:"findings"`   // 包目录(相对) -> findings
	CallEdges map[string]map[string]bool `json:"call_edges"` // calleePkg -> callerPkgs
	UpdatedAt time.Time                  `json:"updated_at"`
}

type PkgFingerprint struct {
	Files map[string]string `json:"files"`
	Hash  string            `json:"hash"`
}

func NewCache(dir string) *Cache {
	c := &Cache{
		dir:       dir,
		Packages:  map[string]PkgFingerprint{},
		Findings:  map[string][]CachedFinding{},
		CallEdges: map[string]map[string]bool{},
	}
	if data, err := os.ReadFile(filepath.Join(dir, "cache.json")); err == nil {
		_ = json.Unmarshal(data, c)
		if c.Packages == nil {
			c.Packages = map[string]PkgFingerprint{}
		}
		if c.Findings == nil {
			c.Findings = map[string][]CachedFinding{}
		}
		if c.CallEdges == nil {
			c.CallEdges = map[string]map[string]bool{}
		}
	}
	return c
}

func (c *Cache) fingerprintDir(root, dir string) (PkgFingerprint, error) {
	fp := PkgFingerprint{Files: map[string]string{}}
	h := sha256.New()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fp, err
	}
	var names []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".go") && !strings.HasSuffix(e.Name(), "_test.go") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, n := range names {
		full := filepath.Join(dir, n)
		data, err := os.ReadFile(full)
		if err != nil {
			return fp, err
		}
		sum := sha256.Sum256(data)
		rel, _ := filepath.Rel(root, full)
		rel = filepath.ToSlash(rel)
		fp.Files[rel] = hex.EncodeToString(sum[:])
		h.Write(sum[:])
		h.Write([]byte(n))
	}
	fp.Hash = hex.EncodeToString(h.Sum(nil))
	return fp, nil
}

// ChangedPackages 返回相对缓存发生变化的包目录（相对 root 的正斜杠路径）。
func (c *Cache) ChangedPackages(root string) ([]string, error) {
	c.root = root
	var changed []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return err
		}
		base := d.Name()
		if base == "vendor" || strings.HasPrefix(base, ".") {
			return filepath.SkipDir
		}
		hasGo := false
		if es, e := os.ReadDir(path); e == nil {
			for _, en := range es {
				if strings.HasSuffix(en.Name(), ".go") && !strings.HasSuffix(en.Name(), "_test.go") {
					hasGo = true
					break
				}
			}
		}
		if !hasGo {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		fp, err := c.fingerprintDir(root, path)
		if err != nil {
			return err
		}
		old, ok := c.Packages[rel]
		if !ok || old.Hash != fp.Hash {
			changed = append(changed, rel)
		}
		return nil
	})
	return changed, err
}

// AffectedClosure 由变化包出发，沿调用依赖求反向闭包（被调变化 -> 所有调用方受影响）。
func (c *Cache) AffectedClosure(changed []string) map[string]bool {
	affected := map[string]bool{}
	queue := append([]string{}, changed...)
	for len(queue) > 0 {
		pkg := queue[0]
		queue = queue[1:]
		if affected[pkg] {
			continue
		}
		affected[pkg] = true
		for caller := range c.CallEdges[pkg] {
			if !affected[caller] {
				queue = append(queue, caller)
			}
		}
	}
	return affected
}

// CachedFindings 取出不在 affected 集合中的包的缓存 findings。
func (c *Cache) CachedFindings(affected map[string]bool) []CachedFinding {
	var out []CachedFinding
	pkgs := make([]string, 0, len(c.Findings))
	for p := range c.Findings {
		pkgs = append(pkgs, p)
	}
	sort.Strings(pkgs)
	for _, p := range pkgs {
		if affected[p] {
			continue
		}
		out = append(out, c.Findings[p]...)
	}
	return out
}

// SaveFull 全量分析后持久化指纹、每包 finding 与调用依赖。
func (c *Cache) SaveFull(root string, pkgs []*PackageFile, findings []*Finding, edges map[string]map[string]bool) error {
	c.root = root
	c.Findings = map[string][]CachedFinding{}
	c.Packages = map[string]PkgFingerprint{}
	c.CallEdges = map[string]map[string]bool{}

	// 包目录 -> 相对路径
	pkgRel := map[*PackageFile]string{}
	for _, p := range pkgs {
		rel, _ := filepath.Rel(root, p.Dir)
		rel = filepath.ToSlash(rel)
		pkgRel[p] = rel
		fp, err := c.fingerprintDir(root, p.Dir)
		if err == nil {
			c.Packages[rel] = fp
		}
	}
	// findings 按文件归属到包
	filePkg := map[string]string{}
	for p, rel := range pkgRel {
		for _, f := range p.Files {
			fn := filepath.ToSlash(p.FileSet.Position(f.Package).Filename)
			filePkg[fn] = rel
			if r2, e := filepath.Rel(root, fn); e == nil {
				filePkg[filepath.ToSlash(r2)] = rel
			}
		}
	}
	for _, f := range findings {
		rel := filePkg[f.File]
		if rel == "" {
			// 兜底：按文件路径前缀匹配
			for pr, r := range pkgRel {
				_ = pr
				if strings.HasPrefix(filepath.ToSlash(f.File), r+"/") {
					rel = r
					break
				}
			}
		}
		c.Findings[rel] = append(c.Findings[rel], CachedFinding{
			RuleID: f.RuleID, File: filepath.ToSlash(f.File), Line: f.Line,
			FuncID: f.FuncID, Origin: f.Origin,
		})
	}
	// 函数级调用边归并为包级
	for callee, callers := range edges {
		calleePkg := pkgOfFuncID(callee)
		if c.CallEdges[calleePkg] == nil {
			c.CallEdges[calleePkg] = map[string]bool{}
		}
		for caller := range callers {
			c.CallEdges[calleePkg][pkgOfFuncID(caller)] = true
		}
	}
	c.UpdatedAt = time.Now()
	return c.write()
}

func pkgOfFuncID(id string) string {
	// funcID 形如 importPath.Func 或 importPath.Type.Method
	if dot := strings.Index(id, "."); dot > 0 {
		return id[:dot]
	}
	return id
}

func (c *Cache) write() error {
	if err := os.MkdirAll(c.dir, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(c.dir, "cache.json"), data, 0o644)
}

// ready 缓存是否包含可用的全量快照。
func (c *Cache) ready() bool {
	return len(c.Packages) > 0 && len(c.CallEdges) > 0
}

// allFindings 回放缓存中的全部 findings（无变化增量场景）。
func (c *Cache) allFindings() []*Finding {
	var out []*Finding
	pkgs := make([]string, 0, len(c.Findings))
	for p := range c.Findings {
		pkgs = append(pkgs, p)
	}
	sort.Strings(pkgs)
	for _, p := range pkgs {
		for _, cf := range c.Findings[p] {
			out = append(out, &Finding{
				RuleID: cf.RuleID, File: cf.File, Line: cf.Line,
				FuncID: cf.FuncID, Origin: cf.Origin,
			})
		}
	}
	return out
}

// mergeFull 增量后：仅覆盖受影响包的指纹与 findings，调用边增量并入，未变包保留。
func (c *Cache) mergeFull(root string, subPkgs []*PackageFile, fresh []*Finding, edges map[string]map[string]bool) error {
	affected := map[string]bool{}
	for _, p := range subPkgs {
		rel, _ := filepath.Rel(root, p.Dir)
		rel = filepath.ToSlash(rel)
		affected[rel] = true
		fp, err := c.fingerprintDir(root, p.Dir)
		if err == nil {
			c.Packages[rel] = fp
		}
	}
	// 清掉受影响包的旧 findings 后写入新结果
	for rel := range affected {
		delete(c.Findings, rel)
	}
	for _, f := range fresh {
		rel := c.filePkg(root, f.File, affected)
		c.Findings[rel] = append(c.Findings[rel], CachedFinding{
			RuleID: f.RuleID, File: filepath.ToSlash(f.File), Line: f.Line,
			FuncID: f.FuncID, Origin: f.Origin,
		})
	}
	// 调用边增量并入
	for callee, callers := range edges {
		calleePkg := pkgOfFuncID(callee)
		if c.CallEdges[calleePkg] == nil {
			c.CallEdges[calleePkg] = map[string]bool{}
		}
		for caller := range callers {
			c.CallEdges[calleePkg][pkgOfFuncID(caller)] = true
		}
	}
	c.UpdatedAt = time.Now()
	return c.write()
}

func (c *Cache) filePkg(root, file string, affected map[string]bool) string {
	abs := file
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(root, file)
	}
	rel, err := filepath.Rel(root, abs)
	if err != nil {
		return ""
	}
	rel = filepath.ToSlash(rel)
	dir := rel
	if i := strings.LastIndex(rel, "/"); i >= 0 {
		dir = rel[:i]
	}
	return dir
}
