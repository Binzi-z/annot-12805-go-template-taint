package main

import (
	"strings"
)

// eval 求一个 IR 表达式的污点事实
func (e *Engine) eval(fn *FuncIR, fr *frame, x *ExprIR) []Token {
	if x == nil {
		return nil
	}
	switch x.Kind {
	case EIdent:
		obj := e.resolve(fr, x.Name)
		tks := e.getTaint(obj)
		// 全局对象：登记读取方，并把 token 根改写为 G:<全限定名>
		if e.isGlobal(obj) {
			if e.globalReaders[obj] == nil {
				e.globalReaders[obj] = map[string]bool{}
			}
			e.globalReaders[obj][fn.ID] = true
			out := make([]Token, 0, len(tks))
			for _, t := range tks {
				root := t.Root
				if !strings.HasPrefix(root, "G:") {
					root = "G:" + obj
				}
				out = append(out, Token{Root: root, Tags: t.Tags})
			}
			return out
		}
		return tks
	case EConst, EBad:
		return nil
	case EParen:
		return e.eval(fn, fr, x.Kids[0])
	case EUnary:
		return e.eval(fn, fr, x.Kids[0])
	case EBinary:
		left := e.eval(fn, fr, x.Kids[0])
		right := e.eval(fn, fr, x.Kids[1])
		if x.Name == "&&" || x.Name == "||" {
			return nil // 布尔运算不传播字符串污点
		}
		return mergeTokens(left, right)
	case EComp:
		var all []Token
		for _, k := range x.Kids {
			all = mergeTokens(all, e.eval(fn, fr, k))
		}
		return all
	case EIndex:
		container := e.eval(fn, fr, x.Kids[0])
		key := e.eval(fn, fr, x.Kids[1])
		return mergeTokens(container, key)
	case ESelect:
		// 字段：优先取字段敏感对象；为空时回退到根对象（Decode(&payload) 染根、读取 payload.Tpl）
		if len(x.Kids) == 1 {
			base := x.Kids[0]
			if base.Kind == EIdent {
				fieldObj := e.resolve(fr, base.Name+"."+x.Name)
				if tks := e.getTaint(fieldObj); len(tks) > 0 {
					return tks
				}
				return e.eval(fn, fr, base)
			}
			return e.eval(fn, fr, base)
		}
		return nil
	case ETypeAssert:
		if len(x.Kids) > 0 {
			return e.eval(fn, fr, x.Kids[0])
		}
		return nil
	case EFuncLit:
		return nil
	case ECall:
		return e.evalCall(fn, fr, x)
	}
	return nil
}

func (e *Engine) evalMulti(fn *FuncIR, fr *frame, x *ExprIR, n int) [][]Token {
	if x.Kind != ECall || x.Call == nil {
		out := make([][]Token, n)
		out[0] = e.eval(fn, fr, x)
		return out
	}
	// 先执行完整调用语义（源标记 / 净化打标 / sink 检查 / 效果实例化），
	// 保证多返回值赋值（rows, err := ...）不会绕过汇聚点检测。
	callRet := e.evalCall(fn, fr, x)
	callees := e.resolveCallees(fn, fr, x)
	res := make([][]Token, n)
	if len(callees) == 0 {
		// 外部/未知函数：第 0 位承接调用返回的污点
		res[0] = mergeTokens(res[0], callRet)
		return res
	}
	for _, cid := range callees {
		cf := e.prog.Funcs[cid]
		if cf == nil {
			res[0] = mergeTokens(res[0], callRet)
			continue
		}
		// 源/净化在调用点直接产生的 token（callRet）并入第 0 返回位，
		// 否则配置访问器这类“项目内函数即污点源”的返回值会被空的被调 result 覆盖。
		res[0] = mergeTokens(res[0], callRet)
		for i := 0; i < n && i < len(cf.Results); i++ {
			res[i] = mergeTokens(res[i], e.getTaint(cf.ID+"#"+cf.Results[i]))
		}
	}
	return res
}

func (e *Engine) argTaint(fn *FuncIR, fr *frame, c *CallInfo) []Token {
	var all []Token
	for _, a := range c.Args {
		all = mergeTokens(all, e.eval(fn, fr, a))
	}
	if c.Recv != nil {
		all = mergeTokens(all, e.eval(fn, fr, c.Recv))
	}
	return all
}

func (e *Engine) evalCall(fn *FuncIR, fr *frame, x *ExprIR) []Token {
	c := x.Call
	if c == nil {
		return nil
	}
	// 接收者位置可能是嵌套调用（exec.Command(...).Output()），先求值以触发内层 sink/源
	if c.Recv != nil && c.Recv.Kind == ECall {
		e.eval(fn, fr, c.Recv)
	}
	recvPkg, recvLabel := e.recvInfo(fn, fr, c)

	// 1) 净化函数：返回值打净化标签
	if sm := e.match.MatchSanitizer(c, recvPkg, recvLabel); sm != nil {
		tks := e.argTaint(fn, fr, c)
		out := make([]Token, 0, len(tks))
		for _, t := range tks {
			out = append(out, Token{Root: t.Root, Tags: tagUnion(t.Tags, []string{sm.Rule.ID})})
		}
		return out
	}

	// 2) 源
	// 数据库句柄建模：Query/QueryRow 的查询串静态命中配置表 -> 结果句柄打配置标记
	if hk := e.markQueryHandle(c); hk != "" {
		e.handleAlias[c.Pos.File+":"+itoa(c.Pos.Line)] = hk
	}
	if sm := e.match.MatchSource(c, recvPkg, recvLabel, e.isConfigRows(fn, fr, c)); sm != nil {
		tks := []Token{{Root: "S:" + sm.Rule.ID + ":" + c.Pos.File + ":" + itoa(c.Pos.Line), Tags: nil}}
		// Decode/Scan 类：同时把污点写到目标参数
		targets := sm.Rule.TaintArgs
		// 配置查询类 Scan（requiresConfigQuery）未显式声明参数位时，所有参数（Scan 目标）都染污
		if len(targets) == 0 && sm.Rule.RequiresConfigQuery {
			targets = allArgIndexes(c)
		}
		for _, ai := range targets {
			if ai < len(c.Args) {
				if obj := e.exprObject(fr, c.Args[ai]); obj != "" {
					e.addTaint(obj, tks)
				}
			}
		}
		return tks
	}

	// 3) 汇聚点：检查参数污点
	if km := e.match.MatchSink(c, recvPkg, recvLabel); km != nil {
		e.checkSink(fn, fr, c, km.Rule)
	}

	// 4) 传播子 / 一般调用
	if pm := e.match.MatchPropagator(c); pm != nil {
		return e.applyPropagator(fn, fr, c, pm.Rule)
	}

	// 5) 已知本地函数：实参染形参、效果实例化、返回值回传
	callees := e.resolveCallees(fn, fr, x)
	if len(callees) > 0 {
		var ret []Token
		for _, cid := range callees {
			e.registerEdge(cid, fn.ID)
			cf := e.prog.Funcs[cid]
			if cf == nil {
				continue
			}
			// 实参污点 -> 被调函数形参对象（上下文不敏感：按位取并集）
			changed := false
			for i, pname := range cf.Params {
				if i >= len(c.Args) {
					break
				}
				argTks := e.eval(fn, fr, c.Args[i])
				if len(argTks) == 0 {
					continue
				}
				pobj := cf.ID + "#" + pname
				before := len(e.getTaint(pobj))
				e.addTaint(pobj, argTks)
				if len(e.getTaint(pobj)) > before {
					changed = true
				}
			}
			// 接收者方法：接收者实参也传给第 0 形参（方法形参表首位是 recv）
			if changed {
				if e.dirty[cid] {
					// 已在 worklist 队列：交给统一调度，避免嵌套重复重算
					e.enqueue(cid)
				} else {
					// 未排队：同步执行一次以闭合短调用链（接口/包装），随后仍会按需重新入队
					e.enqueue(cid)
					e.dirty[cid] = true
					e.execFunc(cf)
				}
			}
			e.instantiateEffects(fn, fr, c, cid)
			if len(cf.Results) > 0 {
				ret = mergeTokens(ret, e.getTaint(cf.ID+"#"+cf.Results[0]))
			}
		}
		// 被调结果稍后才更新时，依赖 callerEdges 在其变化后把当前函数重新入队（见 addTaint 反向通知）
		return ret
	}

	// 6) 未知外部函数：默认不染污（fail-closed，控制误报）
	return nil
}

// checkSink 参数命中汇聚点，按净化标签过滤后报告
func (e *Engine) checkSink(fn *FuncIR, fr *frame, c *CallInfo, sr *SinkRule) {
	argIdx := sr.Args
	if len(argIdx) == 0 {
		argIdx = allArgIndexes(c)
	}
	for _, ai := range argIdx {
		if ai >= len(c.Args) {
			continue
		}
		tks := e.eval(fn, fr, c.Args[ai])
		if len(tks) == 0 {
			continue
		}
		var live []Token
		for _, t := range tks {
			if !tagCovers(t.Tags, sr, e.rules) {
				live = append(live, t)
			}
		}
		if len(live) == 0 {
			continue
		}
		// 若实参表达式解析到本函数形参对象，把 token 根改写为形参根 P:fnID:idx，
		// 使 recordEffect 登记形参位效果（报告延迟到调用点），而非在 sink 包装函数定义处上报。
		// 具体源身份与净化标签在调用点用实参重新求值恢复。
		if pobj := e.exprObject(fr, c.Args[ai]); pobj != "" {
			if pi, ok := e.paramIndexOf(fn, pobj); ok {
				rewritten := make([]Token, 0, len(live))
				for _, t := range live {
					rewritten = append(rewritten, Token{Root: "P:" + fn.ID + ":" + itoa(pi), Tags: t.Tags})
				}
				live = rewritten
			}
		}
		// 登记“形参/全局/具体源到达 sink”的效果。
		// 报告统一延迟到调用点实例化阶段，保证行号落在触发 sink 的调用处，
		// 且跨多层包装（Handle -> forward -> runCmd）能逐层冒泡。
		e.recordEffect(fn, c, sr, live)
	}
}

func tagCovers(tags []string, sr *SinkRule, rules *Rules) bool {
	for _, accept := range sr.Accept {
		for _, tag := range tags {
			if tag != accept {
				continue
			}
			for _, s := range rules.Sanitizers {
				if s.ID == tag && (len(s.Only) == 0 || containsStr(s.Only, sr.ID)) {
					return true
				}
			}
		}
	}
	return false
}

func (e *Engine) recordEffect(fn *FuncIR, c *CallInfo, sr *SinkRule, tks []Token) {
	for _, t := range tks {
		eff := pendingEffect{SinkRuleID: sr.ID, Tags: append([]string{}, t.Tags...), InnerPos: c.Pos, Trace: []string{fn.ID}}
		// 形参身份优先判断：即使形参携带的 token 根是具体源(S:)，也要登记形参位效果，
		// 这样报告位置才能落到调用点，而不是 sink 包装函数的定义处。
		if pi, ok := e.paramIndexOf(fn, t.Root); ok {
			eff.ParamIndex = pi
			eff.GlobalName = ""
		} else if strings.HasPrefix(t.Root, "G:") {
			eff.ParamIndex = -1
			eff.GlobalName = strings.TrimPrefix(t.Root, "G:")
		} else if strings.HasPrefix(t.Root, "S:") {
			// 源在当前函数（不经形参）直达 sink：直接在 sink 调用点报告
			if !tagCovers(t.Tags, sr, e.rules) {
				e.report(c.Pos, sr.ID, fn.ID, t)
			}
			continue
		} else {
			continue
		}
		// 效果只按（函数、形参位/全局、sink）去重；
		// 净化标签在调用点对“实参的具体 token”判定，不固化在效果里。
		key := fn.ID + "|" + itoa(eff.ParamIndex) + "|" + eff.GlobalName + "|" + sr.ID
		if e.seenEff[key] {
			continue
		}
		e.seenEff[key] = true
		e.effects[fn.ID] = append(e.effects[fn.ID], eff)
		// 新效果（含全局效果）登记后，反向入队所有调用方，使其在调用点实例化该效果。
		for caller := range e.edges[fn.ID] {
			e.enqueue(caller)
		}
	}
}

// paramIndexOf 判断污点根是否为该函数的形参（对象名 fn.ID#p 或形参根 P:fnID:idx），返回形参位。
func (e *Engine) paramIndexOf(fn *FuncIR, root string) (int, bool) {
	if strings.HasPrefix(root, "P:") {
		rest := strings.TrimPrefix(root, "P:")
		parts := strings.SplitN(rest, ":", 2)
		if len(parts) == 2 && parts[0] == fn.ID {
			return atoiSafe(parts[1]), true
		}
		return 0, false
	}
	for i, p := range fn.Params {
		if root == fn.ID+"#"+p {
			return i, true
		}
	}
	return 0, false
}

// instantiateEffects 在调用点把被调函数的形参/全局效果落地为报告与传播
func (e *Engine) instantiateEffects(fn *FuncIR, fr *frame, c *CallInfo, calleeID string) {
	cf := e.prog.Funcs[calleeID]
	if cf == nil {
		return
	}
	for _, eff := range e.effects[calleeID] {
		var concrete []Token
		switch {
		case eff.ParamIndex >= 0 && eff.ParamIndex < len(c.Args):
			// 形参效果：用调用点实参的具体污点实例化（源身份与净化标签随实参保留）
			concrete = e.eval(fn, fr, c.Args[eff.ParamIndex])
		case eff.ParamIndex == -1 && eff.GlobalName != "":
			// 全局效果
			concrete = e.getTaint(eff.GlobalName)
		}
		if len(concrete) == 0 {
			continue
		}
		// 净化标签直接取实参 token 自身（被调侧若有额外净化，其 Tags 也并入）
		merged := make([]Token, 0, len(concrete))
		for _, t := range concrete {
			merged = append(merged, Token{Root: t.Root, Tags: tagUnion(t.Tags, eff.Tags)})
		}
		sr := e.sinkByID(eff.SinkRuleID)
		if sr == nil {
			continue
		}
		// 若承载该效果的实参表达式本身解析到当前函数形参，则效果继续向上冒泡，
		// 不能因为形参携带的 token 根是具体源(S:)就在当前调用点提前报告。
		var argParamIdx int
		argIsParam := false
		if eff.ParamIndex >= 0 && eff.ParamIndex < len(c.Args) {
			if pobj := e.exprObject(fr, c.Args[eff.ParamIndex]); pobj != "" {
				if pi, ok := e.paramIndexOf(fn, pobj); ok {
					argParamIdx, argIsParam = pi, true
				}
			}
		}
		for _, t := range merged {
			if tagCovers(t.Tags, sr, e.rules) {
				continue
			}
			if argIsParam {
				// 污点仍是当前函数的形参：效果继续向上一层冒泡
				bubble := pendingEffect{ParamIndex: argParamIdx, SinkRuleID: sr.ID, Tags: append([]string{}, t.Tags...), InnerPos: c.Pos}
				key := fn.ID + "|" + itoa(argParamIdx) + "||" + sr.ID
				if !e.seenEff[key] {
					e.seenEff[key] = true
					e.effects[fn.ID] = append(e.effects[fn.ID], bubble)
					e.enqueue(fn.ID)
				}
				continue
			}
			if strings.HasPrefix(t.Root, "S:") || strings.HasPrefix(t.Root, "G:") {
				e.report(c.Pos, sr.ID, fn.ID, t)
			} else if pi, ok := e.paramIndexOf(fn, t.Root); ok {
				// 形参根（P: 前缀）继续冒泡
				bubble := pendingEffect{ParamIndex: pi, SinkRuleID: sr.ID, Tags: append([]string{}, t.Tags...), InnerPos: c.Pos}
				key := fn.ID + "|" + itoa(pi) + "||" + sr.ID
				if !e.seenEff[key] {
					e.seenEff[key] = true
					e.effects[fn.ID] = append(e.effects[fn.ID], bubble)
					e.enqueue(fn.ID)
				}
			}
		}
	}
}

func (e *Engine) sinkByID(id string) *SinkRule {
	for i := range e.rules.Sinks {
		if e.rules.Sinks[i].ID == id {
			return &e.rules.Sinks[i]
		}
	}
	return nil
}

func (e *Engine) report(pos Pos, ruleID, funcID string, t Token) {
	// 先按（文件、行、规则）做位置级去重：同一汇聚点只保留一条，避免不同污点源产生海量重复
	locKey := pos.File + "|" + itoa(pos.Line) + "|" + ruleID
	if e.findLoc[locKey] {
		return
	}
	e.findLoc[locKey] = true
	origin := t.Root
	if parts := strings.SplitN(t.Root, ":", 3); len(parts) >= 2 {
		origin = parts[1]
	}
	e.finds[locKey] = &Finding{
		RuleID: ruleID,
		File:   pos.File,
		Line:   pos.Line,
		FuncID: funcID,
		Origin: origin,
		Trace:  []string{t.Root},
	}
}

// ---------- 传播子 ----------

func (e *Engine) applyPropagator(fn *FuncIR, fr *frame, c *CallInfo, pr *PropagatorRule) []Token {
	switch pr.Mode {
	case "recv_write":
		// Builder.WriteString(s)：污点写到接收者对象，无返回
		if c.Recv != nil {
			if obj := e.exprObject(fr, c.Recv); obj != "" {
				e.addTaint(obj, e.argTaint(fn, fr, c))
			}
		}
		return nil
	case "recv_read":
		// Builder.String()：从接收者读污点
		if c.Recv != nil {
			return e.eval(fn, fr, c.Recv)
		}
		return nil
	case "reflect_call":
		// v.Call(args)：参数污点透出；接收者方法对象的污点也透出
		out := e.argTaint(fn, fr, c)
		if c.Recv != nil {
			out = mergeTokens(out, e.eval(fn, fr, c.Recv))
		}
		// 反射动态调用：保守地把参数效果作用到所有同名方法（规则开关）
		if on, _ := e.rules.Config["reflect_dynamic_overapprox"].(bool); on {
			e.reflectDispatch(fn, fr, c)
		}
		return out
	case "reflect_method":
		// rv.MethodByName("Render")：返回值携带方法名，绑定到赋值目标对象（m），
		// 同时记录到接收者链，供后续 m.Call 取回。
		if c.ReflectMethod != "" {
			if c.Recv != nil {
				if obj := e.exprObject(fr, c.Recv); obj != "" {
					e.reflectName[obj] = c.ReflectMethod
				}
			}
			e.pendingReflectName = c.ReflectMethod
		}
		if c.Recv != nil {
			return e.eval(fn, fr, c.Recv)
		}
		return nil
	case "slice_append":
		// append(slice, elems...)：返回值同时携带原切片与所有新增元素的污点，
		// 并把元素污点写到切片的 [*] 对象，供后续 range 取值继承。
		out := e.argTaint(fn, fr, c)
		if len(c.Args) > 0 {
			if base := e.exprObject(fr, c.Args[0]); base != "" {
				elemTks := mergeTokens(e.getTaint(base+"[*]"), out)
				e.addTaint(base+"[*]", elemTks)
			}
		}
		return out
	default:
		return e.argTaint(fn, fr, c)
	}
}

// reflectMethodFromChain 从链式调用表达式中递归提取 MethodByName 的静态方法名。
func (e *Engine) reflectMethodFromChain(x *ExprIR) string {
	if x == nil {
		return ""
	}
	if x.Kind == ECall {
		if x.Call.ReflectMethod != "" {
			return x.Call.ReflectMethod
		}
		if x.Call.Recv != nil {
			if s := e.reflectMethodFromChain(x.Call.Recv); s != "" {
				return s
			}
		}
	}
	for _, k := range x.Kids {
		if s := e.reflectMethodFromChain(k); s != "" {
			return s
		}
	}
	return ""
}

func (e *Engine) reflectDispatch(fn *FuncIR, fr *frame, c *CallInfo) {
	tks := e.argTaint(fn, fr, c)
	if len(tks) == 0 {
		return
	}
	name := c.ReflectMethod
	if name == "" && c.Recv != nil {
		// m.Call(...)：从接收者变量取回 MethodByName 绑定的方法名
		if obj := e.exprObject(fr, c.Recv); obj != "" {
			name = e.reflectName[obj]
		}
		// 链式 rv.MethodByName("Render").Call(...)：从接收者调用表达式递归找方法名
		if name == "" {
			name = e.reflectMethodFromChain(c.Recv)
		}
	}
	if name == "" {
		// 退化：用类型标签
		name = c.TypeLabel
	}
	if name == "" {
		return
	}
	// 反射动态调用：把参数污点送入所有已加载包中的同名方法（跨包保守分发）
	for _, id := range e.idxNameMethod[name] {
		cf := e.prog.Funcs[id]
		e.registerEdge(id, fn.ID)
		if len(cf.Params) > 0 {
			// 方法形参首位可能是接收者，污点送到最后一个形参（与 Call 实参对齐）
			pi := len(cf.Params) - 1
			pobj := cf.ID + "#" + cf.Params[pi]
			before := len(e.getTaint(pobj))
			e.addTaint(pobj, tks)
			if len(e.getTaint(pobj)) > before {
				e.enqueue(id)
				e.execFunc(cf)
			}
			// 把目标方法内部的 sink 效果在反射 Call 调用点实例化，
			// 使报告落在 m.Call(...) 行而非方法定义处。
			e.instantiateReflectEffect(fn, fr, c, cf, pi)
		}
	}
}

// instantiateReflectEffect 反射调用点实例化目标方法的形参效果。
func (e *Engine) instantiateReflectEffect(fn *FuncIR, fr *frame, c *CallInfo, cf *FuncIR, paramIdx int) {
	for _, eff := range e.effects[cf.ID] {
		if eff.ParamIndex != paramIdx {
			continue
		}
		// 反射 Call 的实参污点作为具体实例
		concrete := e.argTaint(fn, fr, c)
		if len(concrete) == 0 {
			continue
		}
		sr := e.sinkByID(eff.SinkRuleID)
		if sr == nil {
			continue
		}
		for _, t := range concrete {
			merged := Token{Root: t.Root, Tags: tagUnion(t.Tags, eff.Tags)}
			if tagCovers(merged.Tags, sr, e.rules) {
				continue
			}
			if strings.HasPrefix(merged.Root, "S:") || strings.HasPrefix(merged.Root, "G:") {
				e.report(c.Pos, sr.ID, fn.ID, merged)
			}
		}
	}
}

// ---------- 被调函数解析（含接口与反射、跨包） ----------

func (e *Engine) resolveCallees(fn *FuncIR, fr *frame, x *ExprIR) []string {
	c := x.Call
	if c == nil {
		return nil
	}
	name := c.BareName
	// 匿名函数
	if strings.HasPrefix(name, "anon@") {
		if _, ok := e.prog.Funcs[name]; ok {
			return []string{name}
		}
		return nil
	}
	var out []string
	add := func(id string) {
		if _, ok := e.prog.Funcs[id]; ok && !containsStr(out, id) {
			out = append(out, id)
		}
	}

	// 包限定调用：区分“项目内包”（已加载）与“外部/标准库”
	if c.PkgPath != "" {
		if e.isProjectPkg(c.PkgPath) {
			// 项目内跨包函数：<importPath>.<Func>
			add(c.PkgPath + "." + name)
			return out
		}
		return nil // 标准库/三方库：交由规则（源/sink/净化/传播）处理
	}

	// 同包函数
	add(fn.PkgPath + "." + name)

	// 方法：按接收者类型标签找 pkg.Type.Method
	if c.IsMethod && c.Recv != nil {
		label := e.exprTypeLabel(fn, fr, c.Recv)
		if label != "" {
			add(fn.PkgPath + "." + label + "." + name)
			// 接口分发：label 是接口名（可能定义在别的包）-> 所有同名方法（含跨包实现）
			if e.isInterfaceAnyPkg(label, name) {
				for _, id := range e.idxNameMethod[name] {
					add(id)
				}
			}
		} else {
			// 无类型信息：所有包同名方法保守全分发
			for _, id := range e.idxNameMethod[name] {
				add(id)
			}
		}
	}
	// 兜底：名字在任意已加载包中作为非方法函数存在（跨包裸名）
	if len(out) == 0 {
		for _, id := range e.idxNameFuncs[name] {
			add(id)
		}
	}
	return out
}

// isProjectPkg 判断 import 路径是否属于本次加载的项目包（O(1) 索引查询）。
func (e *Engine) isProjectPkg(importPath string) bool {
	return e.idxPkgSet[importPath]
}

// isInterfaceAnyPkg 在接口名索引中查找名为 typeName 且含 method 的接口。
func (e *Engine) isInterfaceAnyPkg(typeName, method string) bool {
	if !e.idxIfaceName[typeName] {
		return false
	}
	for key, iface := range e.prog.Interfaces {
		if strings.HasSuffix(key, "."+typeName) && iface.Methods[method] {
			return true
		}
	}
	return false
}

func (e *Engine) registerEdge(callee, caller string) {
	if e.edges[callee] == nil {
		e.edges[callee] = map[string]bool{}
	}
	e.edges[callee][caller] = true
}

// ---------- 接收者信息与数据库配置建模 ----------

func (e *Engine) recvInfo(fn *FuncIR, fr *frame, c *CallInfo) (pkgPath, label string) {
	// 包限定调用：PkgPath 已在编译期确定
	if c.PkgPath != "" {
		return c.PkgPath, ""
	}
	if c.Recv == nil {
		return "", ""
	}
	// 接收者根部若是包别名（如 json.NewDecoder），归入包路径
	if id, ok := c.Recv.rawIdent(); ok {
		if pkg, ok2 := e.pkgImportPath(fn, id); ok2 {
			return pkg, ""
		}
		return "", id
	}
	label = e.exprTypeLabel(fn, fr, c.Recv)
	return "", label
}

func (e *Engine) pkgImportPath(fn *FuncIR, alias string) (string, bool) {
	if fn.Imports != nil {
		if pkg, ok := fn.Imports[alias]; ok {
			return pkg, true
		}
	}
	return "", false
}

func (e *Engine) exprTypeLabel(fn *FuncIR, fr *frame, x *ExprIR) string {
	switch x.Kind {
	case EIdent:
		// 形参有声明类型（接口/结构体）时优先用类型名
		if tn, ok := fn.ParamTypes[x.Name]; ok {
			return tn
		}
		obj := e.resolve(fr, x.Name)
		if l, ok := e.typeLabel[obj]; ok {
			return l
		}
		// 启发式：变量名首字母大写形态（如 tpl、tmpl）不做推断；类型名风格直接用
		return x.Name
	case ESelect:
		// 结构体字段：查字段类型映射（来自 CompositeLit 的字段类型登记）
		if len(x.Kids) == 1 && x.Kids[0].Kind == EIdent {
			base := e.resolve(fr, x.Kids[0].Name)
			if l, ok := e.fieldType[base+"."+x.Name]; ok {
				return l
			}
		}
		if len(x.Kids) > 0 {
			return e.exprTypeLabel(fn, fr, x.Kids[0])
		}
	case ECall:
		// 构造函数 NewX() -> 类型 X
		n := x.Call.BareName
		n = strings.TrimPrefix(n, "New")
		if n != x.Call.BareName {
			return n
		}
		if x.Call.TypeLabel != "" {
			return x.Call.TypeLabel
		}
	case EParen:
		return e.exprTypeLabel(fn, fr, x.Kids[0])
	}
	return ""
}

// isConfigRows 判断 Scan 的接收者是否来自“配置表查询”。
// 建模要点：DB 句柄本身永不染污；仅当 Query/QueryRow 的查询串静态命中配置表清单时，
// 产生的 Rows 句柄才被打上配置标记，Scan 目标才成为污点源。动态 SQL 默认不染污。
func (e *Engine) isConfigRows(fn *FuncIR, fr *frame, c *CallInfo) bool {
	if c.Recv == nil {
		return false
	}
	obj := e.exprObject(fr, c.Recv)
	return e.configH[obj]
}

func (e *Engine) markConfigHandle(c *CallInfo, obj string, queryIsConfig bool) {
	if queryIsConfig {
		e.configH[obj] = true
	}
}

func (e *Engine) exprObject(fr *frame, x *ExprIR) string {
	switch x.Kind {
	case EIdent:
		return e.resolve(fr, x.Name)
	case EParen:
		return e.exprObject(fr, x.Kids[0])
	case EUnary:
		// 取址 &body / 解引用 *p：落到内部对象
		if len(x.Kids) == 1 {
			return e.exprObject(fr, x.Kids[0])
		}
	case ESelect:
		if len(x.Kids) == 1 && x.Kids[0].Kind == EIdent {
			return e.resolve(fr, x.Kids[0].Name+"."+x.Name)
		}
	case EIndex:
		if len(x.Kids) > 0 {
			return e.exprObject(fr, x.Kids[0]) + "[*]"
		}
	}
	return ""
}

func allArgIndexes(c *CallInfo) []int {
	out := make([]int, len(c.Args))
	for i := range c.Args {
		out[i] = i
	}
	return out
}

func atoiSafe(s string) int {
	n := 0
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return -1
		}
		n = n*10 + int(ch-'0')
	}
	return n
}
