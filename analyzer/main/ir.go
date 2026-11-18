package main

import (
	"go/ast"
	"go/token"
	"path/filepath"
	"strings"
)

// ---------- 位置 ----------

type Pos struct {
	File string
	Line int
	Col  int
}

func (p Pos) Valid() bool { return p.File != "" && p.Line > 0 }

func posOf(fset *token.FileSet, n ast.Node) Pos {
	p := fset.Position(n.Pos())
	return Pos{File: filepath.ToSlash(p.Filename), Line: p.Line, Col: p.Column}
}

// ---------- IR 表达式 ----------

type EKind int

const (
	EBad EKind = iota
	EIdent
	EConst
	EParen
	EUnary
	EBinary
	EComp
	EIndex
	ESelect
	ECall
	EFuncLit
	ETypeAssert
)

type ExprIR struct {
	Kind EKind
	// 通用字段
	Name       string            // EIdent 名 / ESelect 字段名 / EUnary,EBinary 操作符
	Kids       []*ExprIR         // 操作数（EBinary 2 个；EUnary 1 个；EIndex 0=容器 1=键；ESelect 0=接收者；EComp 元素；EParen 0=内部）
	ConstVal   string            // EConst 字面量文本
	Call       *CallInfo         // ECall 专用
	FuncLit    *FuncIR           // EFuncLit
	FieldTypes map[string]string // EComp：结构体字段名 -> 类型短名（语法层从声明提取）
}

// CallInfo 一次函数/方法调用的归一化描述（语法层，不做类型检查）
type CallInfo struct {
	Pos           Pos
	RawText       string   // 调用表达式源码片段（调试用）
	Chain         []string // 方法链，如 r.URL.Query().Get -> ["URL","Query","Get"]
	PkgPath       string   // 限定调用的 import 路径，如 text/template
	BareName      string   // 裸函数名（同包或已绑定方法名），如 runCmd / Parse（在无法确定包时也用它）
	IsMethod      bool     // X 是标识符/选择器/调用时认为是方法调用
	IsBuiltin     bool     // append/copy/len 等
	Args          []*ExprIR
	Recv          *ExprIR // 方法接收者表达式
	TypeLabel     string  // 接收者类型名（启发式推断）
	ReflectMethod string  // reflect.MethodByName 的字符串实参（反射调用目标方法名）
}

// ---------- IR 语句 ----------

type Op int

const (
	OpAssign     Op = iota // 普通赋值（含 :=、=、var 带初值）
	OpDeclAssign           // 无初值声明（默认空对象，不染污）
	OpExpr                 // 表达式语句（含 sink 调用）
	OpReturn
	OpIf
	OpFor
	OpRange
	OpBlock
	OpSend // ch <- x
	OpIncDec
)

type IRStmt struct {
	Op    Op
	Pos   Pos
	LHS   []string // 赋值目标对象名（局部短名，引擎解析）
	RHS   []*ExprIR
	Ret   []*ExprIR
	Cond  *ExprIR
	Then  []IRStmt
	Else  []IRStmt
	Body  []IRStmt
	Range *ExprIR     // range 的容器
	Key   string      // range key 局部名
	Val   string      // range val 局部名
	Tag   token.Token // IncDec / 赋值操作符
}

// ---------- 函数 IR ----------

type FuncIR struct {
	ID         string // 全限定名 包路径.FuncName
	Short      string
	PkgPath    string
	Pos        Pos
	RecvName   string // 接收者参数名（无则空）
	RecvType   string // 接收者类型短名
	Params     []string
	ParamTypes map[string]string // 形参名 -> 类型短名（接口/结构体），语法层启发式
	Results    []string          // 命名返回值短名（匿名返回值合成 r0,r1...）
	AnonResult bool
	Body       []IRStmt
	Locals     map[string]bool
	IsMethod   bool
	Fset       *token.FileSet
	Imports    map[string]string // 该文件的 import 别名 -> 路径
}

// ---------- 接口/类型登记 ----------

type InterfaceInfo struct {
	PkgPath string
	Name    string
	Methods map[string]bool
}

// Program 整个分析目标的 IR 程序
type Program struct {
	Funcs      map[string]*FuncIR
	Order      []string // 首次发现顺序
	Globals    map[string]bool
	Interfaces map[string]*InterfaceInfo // key: pkgPath.Name
	Structs    map[string][]string       // key: pkgPath.Name -> 字段名
	FsetByFile map[string]*token.FileSet
	Root       string
}

func NewProgram(root string) *Program {
	return &Program{
		Funcs:      map[string]*FuncIR{},
		Globals:    map[string]bool{},
		Interfaces: map[string]*InterfaceInfo{},
		Structs:    map[string][]string{},
		FsetByFile: map[string]*token.FileSet{},
		Root:       root,
	}
}

// ---------- AST -> IR 编译器 ----------

type compiler struct {
	prog     *Program
	pkg      *PackageFile
	fset     *token.FileSet
	fileName string
	imports  map[string]string // alias -> importPath
}

func BuildProgram(pkgs []*PackageFile, root string) *Program {
	prog := NewProgram(root)
	for _, pkg := range pkgs {
		c := &compiler{prog: prog, pkg: pkg, fset: pkg.FileSet}
		// 先登记类型（接口、结构体）
		for _, f := range pkg.Files {
			c.fileName = filepath.Base(fsetFile(c.fset, f))
			c.imports = parseImports(f)
			c.collectTypes(f)
		}
		// 再编译函数与全局变量
		for _, f := range pkg.Files {
			c.fileName = filepath.Base(fsetFile(c.fset, f))
			c.imports = parseImports(f)
			c.collectGlobals(f)
			c.compileFile(f)
		}
	}
	return prog
}

func fsetFile(fset *token.FileSet, f *ast.File) string {
	return fset.Position(f.Package).Filename
}

func (c *compiler) collectTypes(f *ast.File) {
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.TYPE {
			continue
		}
		for _, spec := range gd.Specs {
			ts, ok := spec.(*ast.TypeSpec)
			if !ok {
				continue
			}
			key := c.pkg.ImportPath + "." + ts.Name.Name
			switch t := ts.Type.(type) {
			case *ast.InterfaceType:
				info := &InterfaceInfo{PkgPath: c.pkg.ImportPath, Name: ts.Name.Name, Methods: map[string]bool{}}
				if t.Methods != nil {
					for _, m := range t.Methods.List {
						if len(m.Names) > 0 {
							info.Methods[m.Names[0].Name] = true
						}
					}
				}
				c.prog.Interfaces[key] = info
			case *ast.StructType:
				var fields []string
				if t.Fields != nil {
					for _, fd := range t.Fields.List {
						for _, n := range fd.Names {
							fields = append(fields, n.Name)
						}
					}
				}
				c.prog.Structs[key] = fields
			}
		}
	}
}

func (c *compiler) collectGlobals(f *ast.File) {
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.VAR && gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, n := range vs.Names {
				c.prog.Globals[c.pkg.ImportPath+"."+n.Name] = true
			}
		}
	}
}

func (c *compiler) compileFile(f *ast.File) {
	c.prog.FsetByFile[c.fileName] = c.fset
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		c.compileFunc(fn)
	}
}

func (c *compiler) funcID(fn *ast.FuncDecl) (id, recvType, recvName string, isMethod bool) {
	name := fn.Name.Name
	if fn.Recv != nil && len(fn.Recv.List) > 0 {
		isMethod = true
		ft := fn.Recv.List[0]
		recvType = typeShortName(ft.Type)
		if len(ft.Names) > 0 {
			recvName = ft.Names[0].Name
		}
		id = c.pkg.ImportPath + "." + recvType + "." + name
	} else {
		id = c.pkg.ImportPath + "." + name
	}
	return
}

func typeShortName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.StarExpr:
		return typeShortName(t.X)
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		return t.Sel.Name
	case *ast.IndexExpr:
		return typeShortName(t.X)
	case *ast.IndexListExpr:
		return typeShortName(t.X)
	}
	return ""
}

func (c *compiler) compileFunc(fn *ast.FuncDecl) {
	id, recvType, recvName, isMethod := c.funcID(fn)
	ir := &FuncIR{
		ID:         id,
		Short:      fn.Name.Name,
		PkgPath:    c.pkg.ImportPath,
		Pos:        posOf(c.fset, fn),
		RecvName:   recvName,
		RecvType:   recvType,
		IsMethod:   isMethod,
		Locals:     map[string]bool{},
		ParamTypes: map[string]string{},
		Fset:       c.fset,
	}
	if isMethod && recvName != "" {
		ir.Params = append(ir.Params, recvName)
		ir.Locals[recvName] = true
		if recvType != "" {
			ir.ParamTypes[recvName] = recvType
		}
	}
	if fn.Type.Params != nil {
		for _, fld := range fn.Type.Params.List {
			tn := typeShortName(fld.Type)
			if len(fld.Names) == 0 {
				ir.Params = append(ir.Params, "_p"+itoa(len(ir.Params)))
			} else {
				for _, n := range fld.Names {
					ir.Params = append(ir.Params, n.Name)
					ir.Locals[n.Name] = true
					if tn != "" {
						ir.ParamTypes[n.Name] = tn
					}
				}
			}
		}
	}
	namedResults := false
	if fn.Type.Results != nil {
		for i, fld := range fn.Type.Results.List {
			if len(fld.Names) == 0 {
				ir.Results = append(ir.Results, "r"+itoa(i))
			} else {
				namedResults = true
				for _, n := range fld.Names {
					ir.Results = append(ir.Results, n.Name)
					ir.Locals[n.Name] = true
				}
			}
		}
	}
	ir.AnonResult = !namedResults
	if fn.Body != nil {
		ir.Body = c.compileBlock(fn.Body.List)
	}
	ir.Imports = c.imports
	c.prog.Funcs[id] = ir
	c.prog.Order = append(c.prog.Order, id)
}

func (c *compiler) compileBlock(list []ast.Stmt) []IRStmt {
	var out []IRStmt
	for _, s := range list {
		out = append(out, c.compileStmt(s)...)
	}
	return out
}

func (c *compiler) compileStmt(s ast.Stmt) []IRStmt {
	switch t := s.(type) {
	case *ast.AssignStmt:
		var rhs []*ExprIR
		for _, e := range t.Rhs {
			rhs = append(rhs, c.compileExpr(e))
		}
		// x, y := f() 多返回值：RHS 只有一个 call，引擎按结果位展开
		var lhs []string
		for _, e := range t.Lhs {
			lhs = append(lhs, c.assignTarget(e))
		}
		return []IRStmt{{Op: OpAssign, Pos: posOf(c.fset, t), LHS: lhs, RHS: rhs, Tag: t.Tok}}
	case *ast.DeclStmt:
		gd, ok := t.Decl.(*ast.GenDecl)
		if !ok {
			return nil
		}
		var out []IRStmt
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, n := range vs.Names {
				name := n.Name
				if i < len(vs.Values) {
					out = append(out, IRStmt{Op: OpAssign, Pos: posOf(c.fset, t), LHS: []string{name}, RHS: []*ExprIR{c.compileExpr(vs.Values[i])}})
				} else {
					out = append(out, IRStmt{Op: OpDeclAssign, Pos: posOf(c.fset, t), LHS: []string{name}})
				}
			}
		}
		return out
	case *ast.ExprStmt:
		return []IRStmt{{Op: OpExpr, Pos: posOf(c.fset, t), RHS: []*ExprIR{c.compileExpr(t.X)}}}
	case *ast.ReturnStmt:
		var rs []*ExprIR
		for _, e := range t.Results {
			rs = append(rs, c.compileExpr(e))
		}
		return []IRStmt{{Op: OpReturn, Pos: posOf(c.fset, t), Ret: rs}}
	case *ast.IfStmt:
		st := IRStmt{Op: OpIf, Pos: posOf(c.fset, t), Cond: c.compileExpr(t.Cond)}
		if t.Init != nil {
			st.Then = append(st.Then, c.compileStmt(t.Init)...)
		}
		st.Then = append(st.Then, c.compileBlock(t.Body.List)...)
		if t.Else != nil {
			st.Else = c.compileStmt(t.Else)
		}
		return []IRStmt{st}
	case *ast.ForStmt:
		var pre []IRStmt
		if t.Init != nil {
			pre = c.compileStmt(t.Init)
		}
		st := IRStmt{Op: OpFor, Pos: posOf(c.fset, t)}
		if t.Cond != nil {
			st.Cond = c.compileExpr(t.Cond)
		}
		st.Body = c.compileBlock(t.Body.List)
		if t.Post != nil {
			st.Body = append(st.Body, c.compileStmt(t.Post)...)
		}
		return append(pre, st)
	case *ast.RangeStmt:
		st := IRStmt{Op: OpRange, Pos: posOf(c.fset, t), Range: c.compileExpr(t.X)}
		if t.Key != nil {
			st.Key = c.assignTarget(t.Key)
		}
		if t.Value != nil {
			st.Val = c.assignTarget(t.Value)
		}
		st.Body = c.compileBlock(t.Body.List)
		return []IRStmt{st}
	case *ast.BlockStmt:
		return []IRStmt{{Op: OpBlock, Pos: posOf(c.fset, t), Body: c.compileBlock(t.List)}}
	case *ast.SendStmt:
		return []IRStmt{{Op: OpSend, Pos: posOf(c.fset, t), LHS: []string{c.assignTarget(t.Chan)}, RHS: []*ExprIR{c.compileExpr(t.Value)}}}
	case *ast.IncDecStmt:
		return []IRStmt{{Op: OpIncDec, Pos: posOf(c.fset, t), LHS: []string{c.assignTarget(t.X)}, Tag: t.Tok}}
	case *ast.SwitchStmt, *ast.TypeSwitchStmt:
		return c.compileSwitch(s)
	case *ast.GoStmt:
		g, _ := s.(*ast.GoStmt)
		return []IRStmt{{Op: OpExpr, Pos: posOf(c.fset, t), RHS: []*ExprIR{c.compileExpr(g.Call)}}}
	case *ast.DeferStmt:
		d, _ := s.(*ast.DeferStmt)
		return []IRStmt{{Op: OpExpr, Pos: posOf(c.fset, t), RHS: []*ExprIR{c.compileExpr(d.Call)}}}
	case *ast.LabeledStmt:
		return c.compileStmt(t.Stmt)
	case *ast.BranchStmt, *ast.EmptyStmt:
		return nil
	case *ast.SelectStmt:
		var out []IRStmt
		for _, cc := range t.Body.List {
			clause, ok := cc.(*ast.CommClause)
			if !ok {
				continue
			}
			if clause.Comm != nil {
				out = append(out, c.compileStmt(clause.Comm)...)
			}
			out = append(out, c.compileBlock(clause.Body)...)
		}
		return out
	}
	return nil
}

func (c *compiler) compileSwitch(s ast.Stmt) []IRStmt {
	var out []IRStmt
	switch t := s.(type) {
	case *ast.SwitchStmt:
		if t.Init != nil {
			out = append(out, c.compileStmt(t.Init)...)
		}
		for _, cc := range t.Body.List {
			clause, ok := cc.(*ast.CaseClause)
			if !ok {
				continue
			}
			out = append(out, IRStmt{Op: OpIf, Pos: posOf(c.fset, clause), Then: c.compileBlock(clause.Body)})
		}
	case *ast.TypeSwitchStmt:
		if t.Init != nil {
			out = append(out, c.compileStmt(t.Init)...)
		}
		for _, cc := range t.Body.List {
			clause, ok := cc.(*ast.CaseClause)
			if !ok {
				continue
			}
			out = append(out, IRStmt{Op: OpIf, Pos: posOf(c.fset, clause), Then: c.compileBlock(clause.Body)})
		}
	}
	return out
}

func (c *compiler) assignTarget(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		return c.assignTarget(t.X) + "." + t.Sel.Name
	case *ast.IndexExpr:
		return c.assignTarget(t.X) + "[*]"
	case *ast.StarExpr:
		return c.assignTarget(t.X)
	}
	return "_"
}

func (c *compiler) compileExpr(e ast.Expr) *ExprIR {
	switch t := e.(type) {
	case nil:
		return &ExprIR{Kind: EBad}
	case *ast.Ident:
		return &ExprIR{Kind: EIdent, Name: t.Name}
	case *ast.BasicLit:
		return &ExprIR{Kind: EConst, ConstVal: t.Value}
	case *ast.ParenExpr:
		return &ExprIR{Kind: EParen, Kids: []*ExprIR{c.compileExpr(t.X)}}
	case *ast.UnaryExpr:
		return &ExprIR{Kind: EUnary, Name: t.Op.String(), Kids: []*ExprIR{c.compileExpr(t.X)}}
	case *ast.BinaryExpr:
		return &ExprIR{Kind: EBinary, Name: t.Op.String(), Kids: []*ExprIR{c.compileExpr(t.X), c.compileExpr(t.Y)}}
	case *ast.CompositeLit:
		x := &ExprIR{Kind: EComp, Name: typeShortName(t.Type), FieldTypes: map[string]string{}}
		// 提取匿名字段结构体的字段类型（struct{ R TplRenderer }{...}）
		if st, ok := t.Type.(*ast.StructType); ok && st.Fields != nil {
			for _, fd := range st.Fields.List {
				tn := typeShortName(fd.Type)
				for _, n := range fd.Names {
					x.FieldTypes[n.Name] = tn
				}
			}
		}
		for _, el := range t.Elts {
			if kv, ok := el.(*ast.KeyValueExpr); ok {
				x.Kids = append(x.Kids, &ExprIR{Kind: EIndex, Kids: []*ExprIR{c.compileExpr(kv.Key), c.compileExpr(kv.Value)}})
				// 具名字段初始化：登记字段值的类型（若值是选择器，取其类型短名）
				if id, ok := kv.Key.(*ast.Ident); ok {
					if sel, ok2 := kv.Value.(*ast.SelectorExpr); ok2 {
						x.FieldTypes[id.Name] = sel.Sel.Name
					}
				}
			} else {
				x.Kids = append(x.Kids, c.compileExpr(el))
			}
		}
		return x
	case *ast.IndexExpr:
		return &ExprIR{Kind: EIndex, Kids: []*ExprIR{c.compileExpr(t.X), c.compileExpr(t.Index)}}
	case *ast.SelectorExpr:
		return &ExprIR{Kind: ESelect, Name: t.Sel.Name, Kids: []*ExprIR{c.compileExpr(t.X)}}
	case *ast.CallExpr:
		return c.compileCall(t)
	case *ast.FuncLit:
		fn := c.compileAnonFunc(t)
		return &ExprIR{Kind: EFuncLit, FuncLit: fn}
	case *ast.TypeAssertExpr:
		return &ExprIR{Kind: ETypeAssert, Name: typeShortName(t.Type), Kids: []*ExprIR{c.compileExpr(t.X)}}
	case *ast.StarExpr:
		return c.compileExpr(t.X)
	case *ast.KeyValueExpr:
		return &ExprIR{Kind: EIndex, Kids: []*ExprIR{c.compileExpr(t.Key), c.compileExpr(t.Value)}}
	case *ast.SliceExpr:
		return c.compileExpr(t.X)
	case *ast.Ellipsis:
		return c.compileExpr(t.Elt)
	}
	return &ExprIR{Kind: EBad}
}

func (c *compiler) compileAnonFunc(fl *ast.FuncLit) *FuncIR {
	id := "anon@" + posOf(c.fset, fl).File + ":" + itoa(posOf(c.fset, fl).Line)
	ir := &FuncIR{ID: id, PkgPath: c.pkg.ImportPath, Pos: posOf(c.fset, fl), Locals: map[string]bool{}, Fset: c.fset}
	if fl.Type.Params != nil {
		for _, fld := range fl.Type.Params.List {
			if len(fld.Names) == 0 {
				ir.Params = append(ir.Params, "_p"+itoa(len(ir.Params)))
			} else {
				for _, n := range fld.Names {
					ir.Params = append(ir.Params, n.Name)
					ir.Locals[n.Name] = true
				}
			}
		}
	}
	if fl.Type.Results != nil {
		for i, fld := range fl.Type.Results.List {
			if len(fld.Names) == 0 {
				ir.Results = append(ir.Results, "r"+itoa(i))
			} else {
				for _, n := range fld.Names {
					ir.Results = append(ir.Results, n.Name)
					ir.Locals[n.Name] = true
				}
			}
		}
	}
	ir.AnonResult = true
	ir.Body = c.compileBlock(fl.Body.List)
	ir.Imports = c.imports
	c.prog.Funcs[id] = ir
	c.prog.Order = append(c.prog.Order, id)
	return ir
}

func (c *compiler) compileCall(ce *ast.CallExpr) *ExprIR {
	info := &CallInfo{Pos: posOf(c.fset, ce)}
	for _, a := range ce.Args {
		info.Args = append(info.Args, c.compileExpr(a))
	}
	switch fun := ce.Fun.(type) {
	case *ast.Ident:
		info.BareName = fun.Name
		info.IsBuiltin = builtinNames[fun.Name]
	case *ast.SelectorExpr:
		info.IsMethod = true
		info.Recv = c.compileExpr(fun.X)
		info.BareName = fun.Sel.Name
		// 包限定调用？
		if id, ok := fun.X.(*ast.Ident); ok {
			if pkg, ok2 := c.imports[id.Name]; ok2 {
				info.PkgPath = pkg
				info.IsMethod = false
			} else {
				info.TypeLabel = id.Name
			}
		} else if pkg, ok := c.pkgSelector(fun.X); ok {
			// 嵌套 selector 根部是包别名，如 exec.Command 经由辅助函数包装的形态
			info.PkgPath = pkg
			info.IsMethod = false
		} else {
			// 记录方法链：a.b.c().d -> 收集 Ident/Selector 链
			info.Chain = c.collectChain(fun)
			if len(info.Chain) > 0 {
				info.BareName = info.Chain[len(info.Chain)-1]
			}
			info.TypeLabel = c.inferRecvType(fun.X)
		}
	case *ast.CallExpr:
		// 链式调用 x.y().z()
		inner := c.compileCall(fun)
		if inner.Call != nil {
			info.Chain = append(inner.Call.Chain, c.terminalName(ce.Fun))
			if len(info.Chain) == 0 {
				info.Chain = []string{c.terminalName(ce.Fun)}
			}
			info.IsMethod = true
			info.BareName = info.Chain[len(info.Chain)-1]
			info.Recv = inner
			// 链首若是包限定（如 json.NewDecoder(...).Decode），继承包路径
			if inner.Call.PkgPath != "" {
				info.PkgPath = inner.Call.PkgPath
			}
			// 反射：继承内层 MethodByName 捕获的方法名
			info.ReflectMethod = inner.Call.ReflectMethod
		}
	case *ast.IndexExpr:
		// 泛型实例化 f[T]()
		if id, ok := fun.X.(*ast.Ident); ok {
			info.BareName = id.Name
		}
	case *ast.FuncLit:
		info.BareName = c.compileAnonFunc(fun).ID
	}
	if info.BareName == "" {
		info.BareName = c.terminalName(ce.Fun)
	}
	// 反射：捕获 MethodByName("X") 的静态方法名，供后续 .Call 反射分发使用
	if info.BareName == "MethodByName" && len(info.Args) > 0 {
		if s := c.constString(info.Args[0]); s != "" {
			info.ReflectMethod = s
		}
	}
	return &ExprIR{Kind: ECall, Call: info, Kids: info.Args}
}

// constString 提取字符串字面量常量
func (c *compiler) constString(x *ExprIR) string {
	if x != nil && x.Kind == EConst {
		return strings.Trim(x.ConstVal, `"`)
	}
	return ""
}

func (c *compiler) terminalName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.SelectorExpr:
		return t.Sel.Name
	case *ast.Ident:
		return t.Name
	case *ast.CallExpr:
		return c.terminalName(t.Fun)
	}
	return ""
}

func (c *compiler) collectChain(sel *ast.SelectorExpr) []string {
	var chain []string
	var walk func(e ast.Expr)
	walk = func(e ast.Expr) {
		switch t := e.(type) {
		case *ast.SelectorExpr:
			walk(t.X)
			chain = append(chain, t.Sel.Name)
		case *ast.CallExpr:
			walk(t.Fun)
		case *ast.Ident:
			chain = append(chain, t.Name)
		}
	}
	walk(sel)
	return chain
}

func (c *compiler) inferRecvType(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		return t.Sel.Name
	case *ast.CallExpr:
		return c.inferRecvType(t.Fun)
	}
	return ""
}

// pkgSelector 若表达式根部是已导入的包别名，返回其 import 路径
func (c *compiler) pkgSelector(e ast.Expr) (string, bool) {
	switch t := e.(type) {
	case *ast.Ident:
		pkg, ok := c.imports[t.Name]
		return pkg, ok
	case *ast.SelectorExpr:
		return c.pkgSelector(t.X)
	case *ast.CallExpr:
		return c.pkgSelector(t.Fun)
	case *ast.ParenExpr:
		return c.pkgSelector(t.X)
	}
	return "", false
}

var builtinNames = map[string]bool{
	"append": true, "copy": true, "len": true, "cap": true, "new": true,
	"make": true, "delete": true, "panic": true, "recover": true, "print": true, "println": true,
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b [20]byte
	n := len(b)
	for i > 0 {
		n--
		b[n] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		n--
		b[n] = '-'
	}
	return string(b[n:])
}

func uncapitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToLower(s[:1]) + s[1:]
}
