package main

import (
	"go/token"
	"sort"
	"strings"
)

// ---------- 污点事实 ----------

type Token struct {
	Root string // S:<srcID>:<file:line> 或 G:<globalName> 或 P:<funcID>:<index>
	Tags []string
}

type Finding struct {
	RuleID string
	File   string
	Line   int
	FuncID string
	Origin string
	Trace  []string
}

type pendingEffect struct {
	ParamIndex int // 生效的形参位；-1 表示全局根
	GlobalName string
	SinkRuleID string
	Tags       []string
	Trace      []string
	InnerPos   Pos // 被调函数内部 sink 的位置（仅调试）
}

type Engine struct {
	prog      *Program
	rules     *Rules
	match     *Matcher
	state     map[string][]Token // 对象 -> 污点事实（并集）
	dirty     map[string]bool
	queue     []string
	round     int
	maxRnd    int
	finds     map[string]*Finding
	findLoc   map[string]bool // （文件|行|规则）位置级去重
	execCount int             // 函数执行总次数（性能诊断）
	seenEff   map[string]bool
	// 函数摘要（执行过程中累积）
	effects            map[string][]pendingEffect
	edges              map[string]map[string]bool // callee -> callers
	configH            map[string]bool            // 对象是否为“配置查询结果句柄”
	typeLabel          map[string]string          // 对象的类型标签（启发式）
	rowHandle          map[string]bool            // Rows 风格句柄
	handleAlias        map[string]string          // 调用位置 key -> 句柄 key
	globalReaders      map[string]map[string]bool // 全局对象 -> 读取过它的函数 ID
	reflectName        map[string]string          // 对象 -> reflect.MethodByName 捕获的方法名
	pendingReflectName string                     // 最近一次 MethodByName 的方法名，待绑定到赋值目标
	fieldType          map[string]string          // 对象.字段 -> 字段类型短名（结构体字面量登记）

	// 一次性索引（构建于 NewEngine，避免热点路径线性遍历全程序）
	idxPkgFuncs   map[string][]string // 包路径 -> 函数 ID
	idxNameFuncs  map[string][]string // 非方法函数短名 -> ID
	idxNameMethod map[string][]string // 方法短名 -> ID
	idxPkgSet     map[string]bool     // 项目包路径集合
	idxIfaceName  map[string]bool     // 接口类型短名集合（跨包）
}

func NewEngine(p *Program, r *Rules) *Engine {
	maxRnd := 8
	if v, ok := r.Config["max_worklist_rounds"]; ok {
		if f, ok := v.(float64); ok {
			maxRnd = int(f)
		}
	}
	eng := &Engine{
		prog:          p,
		rules:         r,
		match:         NewMatcher(r, p),
		state:         map[string][]Token{},
		dirty:         map[string]bool{},
		finds:         map[string]*Finding{},
		findLoc:       map[string]bool{},
		seenEff:       map[string]bool{},
		effects:       map[string][]pendingEffect{},
		edges:         map[string]map[string]bool{},
		configH:       map[string]bool{},
		typeLabel:     map[string]string{},
		rowHandle:     map[string]bool{},
		handleAlias:   map[string]string{},
		globalReaders: map[string]map[string]bool{},
		reflectName:   map[string]string{},
		fieldType:     map[string]string{},
		maxRnd:        maxRnd,
		idxPkgFuncs:   map[string][]string{},
		idxNameFuncs:  map[string][]string{},
		idxNameMethod: map[string][]string{},
		idxPkgSet:     map[string]bool{},
		idxIfaceName:  map[string]bool{},
	}
	eng.buildIndex()
	return eng
}

// buildIndex 一次性构建全程序查找索引，把热点路径的 O(n) 线性扫描降为 O(1)/O(k)。
func (e *Engine) buildIndex() {
	for id, fn := range e.prog.Funcs {
		e.idxPkgFuncs[fn.PkgPath] = append(e.idxPkgFuncs[fn.PkgPath], id)
		e.idxPkgSet[fn.PkgPath] = true
		if fn.IsMethod {
			e.idxNameMethod[fn.Short] = append(e.idxNameMethod[fn.Short], id)
		} else {
			e.idxNameFuncs[fn.Short] = append(e.idxNameFuncs[fn.Short], id)
		}
	}
	for key, iface := range e.prog.Interfaces {
		_ = iface
		if dot := strings.LastIndex(key, "."); dot >= 0 {
			e.idxIfaceName[key[dot+1:]] = true
		}
	}
}

// Run 全程序 worklist 求精：函数只在获得新污点事实时重新入队，直到不动点或达轮次上限。
func (e *Engine) Run() []*Finding {
	// 初始：所有函数入队一次
	for _, id := range e.prog.Order {
		e.enqueue(id)
	}
	totalRounds := 0
	maxTotal := e.maxRnd * len(e.prog.Order) // 单函数最多重算 maxRnd 次
	if maxTotal < len(e.prog.Order) {
		maxTotal = len(e.prog.Order)
	}
	head := 0
	for len(e.queue) > head && totalRounds < maxTotal {
		id := e.queue[head]
		head++
		// 周期性回收队列前半段，避免无限增长（替代 O(n) 的切片重切）
		if head > 256 && head*2 > len(e.queue) {
			e.queue = append([]string(nil), e.queue[head:]...)
			head = 0
		}
		e.dirty[id] = false
		fn := e.prog.Funcs[id]
		if fn == nil {
			continue
		}
		totalRounds++
		e.execFunc(fn)
	}
	var out []*Finding
	for _, f := range e.finds {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		return out[i].Line < out[j].Line
	})
	return out
}

func (e *Engine) enqueue(id string) {
	if !e.dirty[id] {
		e.dirty[id] = true
		e.queue = append(e.queue, id)
	}
}

func isCompoundAssign(tok token.Token) bool {
	switch tok {
	case token.ADD_ASSIGN, token.SUB_ASSIGN, token.MUL_ASSIGN, token.QUO_ASSIGN,
		token.REM_ASSIGN, token.AND_ASSIGN, token.OR_ASSIGN, token.XOR_ASSIGN,
		token.SHL_ASSIGN, token.SHR_ASSIGN, token.AND_NOT_ASSIGN:
		return true
	}
	return false
}

// Edges 返回 callee -> callers 的函数级调用依赖（供增量缓存归并为包级边）。
func (e *Engine) Edges() map[string]map[string]bool {
	return e.edges
}

// ---------- 对象与事实 ----------

func (e *Engine) isGlobal(name string) bool {
	_, ok := e.prog.Globals[name]
	return ok
}

// lookupGlobal 把短名/全限定名解析为登记的全局对象全限定名。
func (e *Engine) lookupGlobal(pkgPath, name string) (string, bool) {
	if e.isGlobal(name) {
		return name, true
	}
	// 同包短名：pkgPath.name
	full := pkgPath + "." + name
	if e.isGlobal(full) {
		return full, true
	}
	// 字段/下标路径的根
	if idx := strings.Index(name, "."); idx > 0 {
		root := name[:idx]
		if e.isGlobal(root) {
			return root, true
		}
		fullRoot := pkgPath + "." + root
		if e.isGlobal(fullRoot) {
			return fullRoot, true
		}
	}
	return "", false
}

func (e *Engine) addTaint(obj string, tks []Token) {
	if obj == "" || obj == "_" || len(tks) == 0 {
		return
	}
	// 全局对象：token 根规范为 G:<全限定名>，保证跨函数全局效果身份一致
	if e.isGlobal(obj) {
		norm := make([]Token, 0, len(tks))
		for _, t := range tks {
			root := t.Root
			if !strings.HasPrefix(root, "G:") {
				root = "G:" + obj
			}
			norm = append(norm, Token{Root: root, Tags: t.Tags})
		}
		tks = norm
	}
	cur := e.state[obj]
	merged := mergeTokens(cur, tks)
	if len(merged) != len(cur) {
		e.state[obj] = merged
		// 反向通知：若变化的是某函数的形参/结果对象，重新入队它的所有调用方，
		// 保证被调函数返回值/效果的延迟更新能回流到调用点（worklist 达到不动点）。
		if fid, ok := e.funcOfObject(obj); ok {
			for caller := range e.edges[fid] {
				e.enqueue(caller)
			}
		}
		// 全局对象变化：重新入队读取过该全局的函数
		if e.isGlobal(obj) {
			for fid := range e.globalReaders[obj] {
				e.enqueue(fid)
			}
		}
	}
}

// funcOfObject 从对象名 fn.ID#name 反解所属函数 ID。
func (e *Engine) funcOfObject(obj string) (string, bool) {
	idx := strings.Index(obj, "#")
	if idx <= 0 {
		return "", false
	}
	fid := obj[:idx]
	if _, ok := e.prog.Funcs[fid]; ok {
		return fid, true
	}
	return "", false
}

// condGuard 识别条件中的净化守卫 sanitizer(obj)（含 ! 取反、== 比较等常见形态），
// 返回被守卫对象与净化标签 id；不是守卫则返回空。
func (e *Engine) condGuard(fn *FuncIR, fr *frame, cond *ExprIR) (string, string) {
	if cond == nil {
		return "", ""
	}
	// 剥去取反/括号
	inner := cond
	if inner.Kind == EUnary && (inner.Name == "!" || inner.Name == "==" || inner.Name == "!=") && len(inner.Kids) == 1 {
		inner = inner.Kids[0]
	}
	if inner.Kind == EParen && len(inner.Kids) == 1 {
		inner = inner.Kids[0]
	}
	if inner.Kind != ECall {
		return "", ""
	}
	c := inner.Call
	rp, rl := e.recvInfo(fn, fr, c)
	if sm := e.match.MatchSanitizer(c, rp, rl); sm != nil && len(c.Args) > 0 {
		if obj := e.exprObject(fr, c.Args[0]); obj != "" {
			return obj, sm.Rule.ID
		}
	}
	return "", ""
}

func (e *Engine) getTaint(obj string) []Token {
	return e.state[obj]
}

func mergeTokens(a, b []Token) []Token {
	seen := map[string]bool{}
	var out []Token
	for _, t := range append(append([]Token{}, a...), b...) {
		key := t.Root + "|" + strings.Join(t.Tags, ",")
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, t)
	}
	return out
}

func tagUnion(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range append(append([]string{}, a...), b...) {
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out
}

func hasTagFor(tks []Token, sinkID string, rules *Rules) bool {
	for _, t := range tks {
		for _, tag := range t.Tags {
			for _, s := range rules.Sanitizers {
				if s.ID != tag {
					continue
				}
				if len(s.Only) == 0 || containsStr(s.Only, sinkID) {
					return true
				}
			}
		}
	}
	return false
}

// ---------- 函数执行（上下文不敏感，参数取并集） ----------

type frame struct {
	fn     *FuncIR
	locals map[string]string // 短名 -> 全局限定对象（本地对象带函数前缀）
}

func (e *Engine) execFunc(fn *FuncIR) {
	e.execCount++
	fr := &frame{fn: fn, locals: map[string]string{}}
	// 参数对象
	for i, p := range fn.Params {
		obj := fn.ID + "#" + p
		fr.locals[p] = obj
		_ = i
	}
	for _, r := range fn.Results {
		fr.locals[r] = fn.ID + "#" + r
	}
	e.execStmts(fn, fr, fn.Body)
}

func (e *Engine) resolve(fr *frame, name string) string {
	// 全局优先：短名或全限定名命中已登记全局变量
	if gname, ok := e.lookupGlobal(fr.fn.PkgPath, name); ok {
		return gname
	}
	if obj, ok := fr.locals[name]; ok {
		return obj
	}
	// 字段/下标路径：按点分段解析根
	if idx := strings.Index(name, "."); idx > 0 {
		root := name[:idx]
		if base, ok := fr.locals[root]; ok {
			return base + name[idx:]
		}
		if gname, ok := e.lookupGlobal(fr.fn.PkgPath, root); ok {
			return gname + name[idx:]
		}
	}
	if strings.Contains(name, "[*]") {
		root := strings.Split(name, "[*]")[0]
		if base, ok := fr.locals[root]; ok {
			return base + strings.TrimPrefix(name, root)
		}
	}
	// 未知名字：当作本函数局部新对象
	obj := fr.fn.ID + "#" + name
	fr.locals[name] = obj
	return obj
}

func (e *Engine) execStmts(fn *FuncIR, fr *frame, stmts []IRStmt) {
	for _, st := range stmts {
		e.execStmt(fn, fr, st)
	}
}

func (e *Engine) execStmt(fn *FuncIR, fr *frame, st IRStmt) {
	switch st.Op {
	case OpDeclAssign:
		for _, l := range st.LHS {
			fr.locals[l] = fn.ID + "#" + l
		}
	case OpAssign:
		e.execAssign(fn, fr, st)
	case OpExpr:
		for _, x := range st.RHS {
			e.eval(fn, fr, x)
		}
	case OpReturn:
		// 命名返回值对象在进入时已建；匿名返回值把表达式写到 r0..
		if fn.AnonResult {
			for i, x := range st.Ret {
				if i < len(fn.Results) {
					tks := e.eval(fn, fr, x)
					e.addTaint(fn.ID+"#"+fn.Results[i], tks)
				}
			}
		} else {
			// 命名返回：表达式可能是裸 return，也可能带值
			for i, x := range st.Ret {
				if i < len(fn.Results) {
					tks := e.eval(fn, fr, x)
					e.addTaint(fn.ID+"#"+fn.Results[i], tks)
				}
			}
		}
	case OpIf:
		if st.Cond != nil {
			e.eval(fn, fr, st.Cond)
			// 条件守卫：if sanitizer(obj) { ...obj... } —— 在 then 分支给守卫对象的所有 token 打净化标签
			guardObj, guardTag := e.condGuard(fn, fr, st.Cond)
			if guardObj != "" {
				if cur := e.getTaint(guardObj); len(cur) > 0 {
					tagged := make([]Token, 0, len(cur))
					for _, t := range cur {
						tagged = append(tagged, Token{Root: t.Root, Tags: tagUnion(t.Tags, []string{guardTag})})
					}
					// 直接覆盖该对象，确保每个 token（含未带标签的旧 token）都被净化
					e.state[guardObj] = tagged
				}
			}
		}
		// 两支都执行（合并），近似所有路径
		e.execStmts(fn, fr, st.Then)
		e.execStmts(fn, fr, st.Else)
	case OpFor:
		// 两轮迭代近似循环体（首轮建立事实，二轮闭合回边）
		e.execStmts(fn, fr, st.Body)
		e.execStmts(fn, fr, st.Body)
	case OpRange:
		tks := e.eval(fn, fr, st.Range)
		// 容器的元素对象（slice[*] / map[*]）污点并入循环值，
		// 覆盖 append 累积、Scan 写入元素等场景。
		if elemObj := e.exprObject(fr, st.Range); elemObj != "" {
			tks = mergeTokens(tks, e.getTaint(elemObj+"[*]"))
			tks = mergeTokens(tks, e.getTaint(elemObj))
		}
		if st.Key != "" {
			fr.locals[st.Key] = fn.ID + "#" + st.Key
			e.addTaint(fn.ID+"#"+st.Key, tks)
		}
		if st.Val != "" {
			fr.locals[st.Val] = fn.ID + "#" + st.Val
			e.addTaint(fn.ID+"#"+st.Val, tks)
		}
		e.execStmts(fn, fr, st.Body)
	case OpBlock:
		e.execStmts(fn, fr, st.Body)
	case OpSend:
		if len(st.RHS) > 0 {
			tks := e.eval(fn, fr, st.RHS[0])
			if len(st.LHS) > 0 {
				obj := e.resolve(fr, st.LHS[0])
				e.addTaint(obj, tks)
			}
		}
	case OpIncDec:
		// 数值自增不传播字符串污点，忽略
	}
}

func (e *Engine) execAssign(fn *FuncIR, fr *frame, st IRStmt) {
	// 多返回值：单个 call RHS
	if len(st.RHS) == 1 && st.RHS[0].Kind == ECall && len(st.LHS) > 1 {
		call := st.RHS[0].Call
		tksList := e.evalMulti(fn, fr, st.RHS[0], len(st.LHS))
		var handleKey string
		if call != nil {
			handleKey = e.handleAlias[call.Pos.File+":"+itoa(call.Pos.Line)]
		}
		for i, lhs := range st.LHS {
			obj := e.resolve(fr, lhs)
			if i < len(tksList) {
				e.addTaint(obj, tksList[i])
			}
			// 第 0 个返回值（rows/row 句柄）继承配置句柄标记
			if i == 0 && handleKey != "" && e.configH[handleKey] {
				e.configH[obj] = true
			}
		}
		return
	}
	for i, lhs := range st.LHS {
		obj := e.resolve(fr, lhs)
		if i < len(st.RHS) {
			tks := e.eval(fn, fr, st.RHS[i])
			// 复合赋值（+= 等）保留原对象污点
			if isCompoundAssign(st.Tag) {
				tks = mergeTokens(tks, e.getTaint(obj))
			}
			e.addTaint(obj, tks)
			// 结构体字面量赋值：登记字段类型，供后续 holder.R.Render 推断接口接收者
			if st.RHS[i].Kind == EComp && st.RHS[i].FieldTypes != nil {
				for fname, ftype := range st.RHS[i].FieldTypes {
					e.fieldType[obj+"."+fname] = ftype
				}
			}
			// MethodByName 结果赋值给变量：把反射方法名绑定到该变量，供后续 .Call 取回
			if e.pendingReflectName != "" {
				e.reflectName[obj] = e.pendingReflectName
				e.pendingReflectName = ""
			}
			// 数据库配置句柄别名：rows := db.Query(...) 后 rows.Scan 能命中配置标记
			if st.RHS[i].Kind == ECall && st.RHS[i].Call != nil {
				if hk, ok := e.handleAlias[st.RHS[i].Call.Pos.File+":"+itoa(st.RHS[i].Call.Pos.Line)]; ok {
					if e.configH[hk] {
						e.configH[obj] = true
					}
				}
			}
			if strings.Contains(lhs, ".") || strings.Contains(lhs, "[*]") {
				// 字段/元素写入：根对象也并上污点（字段敏感 + 根保守）
				rootName := strings.FieldsFunc(lhs, func(r rune) bool { return r == '.' || r == '[' })[0]
				if root, ok := fr.locals[rootName]; ok && root != obj {
					e.addTaint(root, tks)
				}
			}
		}
	}
}
