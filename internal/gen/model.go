package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// side says whether a type is sent (request params) or read (answers).
type side int

const (
	answer side = iota
	request
)

// cat is the category of a Go type, which decides pointers and helpers.
type cat int

const (
	catAny cat = iota
	catString
	catInt
	catFloat
	catBool
	catSlice
	catMap
	catStruct
	catImage
	catFile
)

func (c cat) scalar() bool { return c == catString || c == catInt || c == catFloat || c == catBool }

// defKind is what a generated type is.
type defKind int

const (
	defStruct defKind = iota
	defAlias
	defOpen
)

type typeDef struct {
	Name   string
	Doc    string
	Kind   defKind
	Alias  string // the target of an alias
	Side   side
	Answer bool // an operation returns it: it carries LastResponse
	Fields []*fieldDef
}

type fieldDef struct {
	Name     string // Go name
	Wire     string // the exact JSON name
	Type     string // Go type expression
	Cat      cat
	Doc      string
	Required bool
	List     *imageList // request lists of images whose entries are objects
}

// imageList is an x-verisec-image-list: which keys of an entry the SDK fills in.
type imageList struct {
	ImageKey, IndexKey, IDKey, ItemLabel string
}

type operation struct {
	ID          string
	Resource    []string // operationId segments before the method
	Method      string   // Go method name
	HTTP        string   // GET, POST
	Path        string
	Summary     string
	Description string
	Price       string // credits, as the spec writes it
	Envelope    string // "data" (KYC) or "object" (Financial)
	Tier        string
	Params      string   // the params type; "" when the method takes path arguments only
	Body        string   // "json", "multipart", "query" or "" (path only)
	PathParams  []string // in order
	Answer      string   // the answer type
	Source      bool     // sends X-VeriSec-Source: sdk
	Tag         string
}

// service is one resource of the client: Client.Face, Client.Phone.Otp.
type service struct {
	Segs     []string
	Field    string // the field on its parent
	Type     string // FaceService, PhoneOtpService
	Tag      string
	Children []*service
	Ops      []*operation
}

// skipped are component schemas the core covers by hand: the error body is
// read into *verisec.APIError.
var skipped = map[string]string{
	"ErrorResponse": "the error body, read into *APIError",
	"ApiError":      "the error object, read into *APIError",
}

type generator struct {
	spec     *Object
	schemas  *Object
	defs     map[string]*typeDef
	order    []string
	sides    map[string]side
	open     map[string]bool // answer types of major operations
	ops      []*operation
	services []*service
	usedBy   map[string]string
	paramsOf map[string]*operation
	err      error
}

func newGenerator(spec *Object) *generator {
	return &generator{
		spec:     spec,
		schemas:  spec.Obj("components").Obj("schemas"),
		defs:     map[string]*typeDef{},
		sides:    map[string]side{},
		open:     map[string]bool{},
		usedBy:   map[string]string{},
		paramsOf: map[string]*operation{},
	}
}

func (g *generator) fail(format string, args ...any) {
	if g.err == nil {
		g.err = fmt.Errorf(format, args...)
	}
}

// resolve follows $refs inside the spec.
func (g *generator) resolve(o *Object) *Object {
	for depth := 0; o != nil && o.Str("$ref") != ""; depth++ {
		ref := o.Str("$ref")
		if !strings.HasPrefix(ref, "#/") || depth > 32 {
			g.fail("unsupported $ref %s", ref)
			return nil
		}
		var cur any = g.spec
		for _, part := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
			obj, _ := cur.(*Object)
			cur = obj.Get(part)
		}
		next, _ := cur.(*Object)
		if next == nil {
			g.fail("unresolved $ref %s", ref)
		}
		o = next
	}
	return o
}

func (g *generator) build() error {
	if g.schemas == nil {
		return fmt.Errorf("the spec has no components.schemas")
	}
	g.collectOperations()
	if g.err != nil {
		return g.err
	}
	g.markRequestSchemas()
	for _, name := range g.schemas.Keys {
		if _, skip := skipped[name]; skip {
			continue
		}
		s := g.schemas.Obj(name)
		sd := g.sides[name]
		switch {
		case g.open[name]:
			g.add(&typeDef{Name: name, Doc: g.schemaDoc(name, s), Kind: defOpen, Side: answer})
		case isStruct(s):
			g.buildStruct(name, s, sd, g.schemaDoc(name, s))
		default:
			target, _, _ := g.typeOf(s, name, "", sd)
			g.add(&typeDef{Name: name, Doc: g.schemaDoc(name, s) + enumDoc(s, sd), Kind: defAlias, Alias: target, Side: sd})
		}
	}
	g.buildQueryParams()
	for _, o := range g.ops {
		if d := g.defs[o.Answer]; d != nil {
			d.Answer = true
		}
	}
	g.checkOperations()
	g.buildServices()
	return g.err
}

func (g *generator) add(def *typeDef) {
	if g.defs[def.Name] != nil {
		g.fail("the type name %s is used twice", def.Name)
		return
	}
	g.defs[def.Name] = def
	g.order = append(g.order, def.Name)
}

func isStruct(s *Object) bool {
	props := s.Obj("properties")
	return props != nil && len(props.Keys) > 0
}

// types lists a schema's JSON types without "null", and whether null is allowed.
func types(s *Object) ([]string, bool) {
	var all []string
	switch t := s.Get("type").(type) {
	case string:
		all = append(all, t)
	case []any:
		for _, v := range t {
			if str, ok := v.(string); ok {
				all = append(all, str)
			}
		}
	}
	var out []string
	nullable := false
	for _, t := range all {
		if t == "null" {
			nullable = true
		} else {
			out = append(out, t)
		}
	}
	return out, nullable
}

/* ----------------------------------------------------------------- docs -- */

// sentence turns a description into a doc sentence about name: "The answer of
// X." becomes "FaceVerify is the answer of X.".
func sentence(name, desc string) string {
	desc = strings.TrimSpace(desc)
	for _, lead := range []string{"The ", "A ", "An ", "One ", "Where ", "Why ", "Who ", "What ", "Which "} {
		if strings.HasPrefix(desc, lead) {
			return name + " is " + lowerFirst(desc)
		}
	}
	return name + ": " + desc
}

func (g *generator) schemaDoc(name string, s *Object) string {
	if d := strings.TrimSpace(s.Str("description")); d != "" {
		doc := sentence(name, d)
		if g.open[name] {
			doc += "\n\nIt is an open result, the engine's full answer: read it with Get, Raw or Decode (see OpenResult)."
		}
		return doc
	}
	if o := g.paramsOf[name]; o != nil {
		return fmt.Sprintf("%s is the request of %s: %s %s.", name, o.Summary, o.HTTP, o.Path)
	}
	for _, o := range g.ops {
		if o.Envelope == "data" && o.Answer+"Response" == name {
			return fmt.Sprintf("%s is the envelope of every %s answer. The client returns its Data (a %s) and puts the rest in LastResponse.", name, o.Summary, o.Answer)
		}
		if o.Answer == name {
			return fmt.Sprintf("%s is the answer of %s.", name, o.Summary)
		}
	}
	if where := g.usedBy[name]; where != "" {
		return fmt.Sprintf("%s is used in %s.", name, where)
	}
	return name + " is an object of the VeriSec API."
}

// enumDoc lists the values of an enum (with their descriptions), and on the
// request side the default.
func enumDoc(s *Object, sd side) string {
	var parts []string
	if values := s.Arr("enum"); len(values) > 0 {
		descs := s.Arr("x-enum-descriptions")
		var items []string
		for i, v := range values {
			item := literal(v)
			if i < len(descs) {
				if d, ok := descs[i].(string); ok && d != "" {
					item += " (" + d + ")"
				}
			}
			items = append(items, item)
		}
		parts = append(parts, "One of "+list(items)+".")
	}
	if sd == request && s.Has("default") {
		if d := literal(s.Get("default")); len(d) <= 80 {
			parts = append(parts, "Default "+d+".")
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return "\n\n" + strings.Join(parts, " ")
}

// literal writes a spec value as JSON.
func literal(v any) string {
	data, err := json.Marshal(plain(v))
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(data)
}

func list(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	case 2:
		return items[0] + " or " + items[1]
	}
	return strings.Join(items[:len(items)-1], ", ") + " or " + items[len(items)-1]
}

/* ---------------------------------------------------------------- types -- */

// typeOf returns the Go type of schema s, found at property prop of the type
// owner, and whether the spec allows null there. It builds the named types of
// inline objects on the way.
func (g *generator) typeOf(s *Object, owner, prop string, sd side) (string, cat, bool) {
	if s == nil {
		return "any", catAny, false
	}
	if ref := s.Str("$ref"); ref != "" {
		name := refName(ref)
		target := g.schemas.Obj(name)
		if target == nil || !strings.HasPrefix(ref, "#/components/schemas/") {
			g.fail("%s.%s: unknown $ref %s", owner, prop, ref)
			return "any", catAny, false
		}
		if _, skip := skipped[name]; skip {
			return "any", catAny, false
		}
		if _, seen := g.usedBy[name]; !seen && prop != "" {
			g.usedBy[name] = owner + "." + fieldName(prop)
		}
		if g.open[name] || isStruct(target) {
			return name, catStruct, false
		}
		_, c, nullable := g.typeOf(target, name, "", sd)
		return name, c, nullable
	}
	if s.Bool("x-verisec-image") && sd == request {
		return "Image", catImage, false
	}
	for _, key := range []string{"oneOf", "anyOf"} {
		variants := s.Arr(key)
		if variants == nil {
			continue
		}
		var kept []*Object
		nullable := false
		for _, v := range variants {
			o, _ := v.(*Object)
			if o != nil && o.Str("type") == "null" {
				nullable = true
				continue
			}
			kept = append(kept, o)
		}
		if len(kept) == 1 {
			t, c, n := g.typeOf(kept[0], owner, prop, sd)
			return t, c, n || nullable
		}
		return "any", catAny, nullable
	}
	if parts := s.Arr("allOf"); parts != nil {
		if len(parts) == 1 {
			o, _ := parts[0].(*Object)
			return g.typeOf(o, owner, prop, sd)
		}
		g.fail("%s.%s: allOf with several parts is not supported", owner, prop)
		return "any", catAny, false
	}

	ts, nullable := types(s)
	if len(ts) == 0 {
		switch {
		case isStruct(s):
			ts = []string{"object"}
		case s.Has("enum"):
			ts = valueTypes(s.Arr("enum"))
		case s.Has("const"):
			ts = valueTypes([]any{s.Get("const")})
		}
	}
	if len(ts) != 1 {
		return "any", catAny, nullable
	}
	switch ts[0] {
	case "string":
		if s.Str("format") == "binary" && sd == request {
			return "*File", catFile, false
		}
		return "string", catString, nullable
	case "integer":
		return "int64", catInt, nullable
	case "number":
		return "float64", catFloat, nullable
	case "boolean":
		return "bool", catBool, nullable
	case "array":
		elem, _, _ := g.typeOf(s.Obj("items"), owner, singular(prop), sd)
		return "[]" + elem, catSlice, nullable
	case "object":
		if isStruct(s) {
			name := owner + pascal(prop)
			g.buildStruct(name, s, sd, g.inlineDoc(name, owner, prop, s))
			return name, catStruct, nullable
		}
		if extra, ok := s.Get("additionalProperties").(*Object); ok {
			value, _, _ := g.typeOf(extra, owner, prop, sd)
			return "map[string]" + value, catMap, nullable
		}
		return "map[string]any", catMap, nullable
	}
	return "any", catAny, nullable
}

// resolveShallow follows a $ref, if there is one.
func (g *generator) resolveShallow(o *Object) *Object {
	if o == nil || o.Str("$ref") == "" {
		return o
	}
	return g.resolve(o)
}

// valueTypes is the JSON type all values share: one entry, or none when they differ.
func valueTypes(values []any) []string {
	kinds := map[string]bool{}
	for _, v := range values {
		switch x := v.(type) {
		case string:
			kinds["string"] = true
		case bool:
			kinds["boolean"] = true
		case json.Number:
			if _, err := x.Int64(); err == nil && !strings.ContainsAny(x.String(), ".eE") {
				kinds["integer"] = true
			} else {
				kinds["number"] = true
			}
		case nil:
		default:
			kinds["mixed"] = true
		}
	}
	if kinds["integer"] && kinds["number"] {
		delete(kinds, "integer")
	}
	if len(kinds) != 1 {
		return nil
	}
	for k := range kinds {
		if k == "mixed" {
			return nil
		}
		return []string{k}
	}
	return nil
}

func (g *generator) inlineDoc(name, owner, prop string, s *Object) string {
	if d := strings.TrimSpace(s.Str("description")); d != "" {
		return sentence(name, d)
	}
	return fmt.Sprintf("%s is the %s member of %s.", name, prop, owner)
}

// reserved are the field names a generated answer type keeps for itself.
var reserved = []string{"Extra", "LastResponse", "OpenResult"}

func (g *generator) buildStruct(name string, s *Object, sd side, doc string) {
	if g.schemas.Has(name) && g.schemas.Obj(name) != s {
		g.fail("the inline object %s has the name of a schema", name)
		return
	}
	def := &typeDef{Name: name, Doc: doc, Kind: defStruct, Side: sd}
	g.add(def)

	required := map[string]bool{}
	for _, r := range s.Arr("required") {
		if str, ok := r.(string); ok {
			required[str] = true
		}
	}
	taken := map[string]bool{}
	if sd == answer {
		for _, r := range reserved {
			taken[r] = true
		}
	}
	props := s.Obj("properties")
	for _, key := range props.Keys {
		ps, _ := props.Get(key).(*Object)
		typ, c, nullable := g.typeOf(ps, name, key, sd)
		req := required[key]
		switch sd {
		case request:
			if (c.scalar() && !req) || c == catStruct {
				typ = "*" + typ
			}
		case answer:
			if c == catStruct && nullable {
				typ = "*" + typ
			}
		}
		res := g.resolveShallow(ps)
		desc := strings.TrimSpace(ps.Str("description"))
		if desc == "" && res != nil {
			desc = strings.TrimSpace(res.Str("description"))
		}
		if ps.Str("$ref") == "" {
			desc += enumDoc(ps, sd)
		}
		if sd == request && req {
			desc = strings.TrimSpace(desc + " Required.")
		}
		f := &fieldDef{Name: uniqueName(fieldName(key), taken), Wire: key, Type: typ, Cat: c, Doc: strings.TrimSpace(desc), Required: req}
		if l := ps.Obj("x-verisec-image-list"); l != nil && sd == request && l.Str("imageKey") != "" {
			f.List = &imageList{ImageKey: l.Str("imageKey"), IndexKey: l.Str("indexKey"), IDKey: l.Str("idKey"), ItemLabel: l.Str("itemLabel")}
			if f.List.ItemLabel == "" {
				f.List.ItemLabel = "item"
			}
		}
		def.Fields = append(def.Fields, f)
	}
}

// buildQueryParams writes the params types of the GET operations with query
// parameters (BankLookupParams): every field optional unless required.
func (g *generator) buildQueryParams() {
	for _, o := range g.ops {
		if o.Body != "query" {
			continue
		}
		if g.schemas.Has(o.Params) {
			g.fail("%s: the params type %s is also a schema", o.ID, o.Params)
			continue
		}
		def := &typeDef{Name: o.Params, Doc: fmt.Sprintf("%s are the query parameters of %s: %s %s.", o.Params, o.Summary, o.HTTP, o.Path), Kind: defStruct, Side: request}
		g.add(def)
		taken := map[string]bool{}
		for _, prm := range g.parameters(o, "query") {
			name := prm.Str("name")
			schema := prm.Obj("schema")
			typ, c, _ := g.typeOf(schema, o.Params, name, request)
			req := prm.Bool("required")
			if c.scalar() && !req {
				typ = "*" + typ
			}
			desc := strings.TrimSpace(prm.Str("description")) + enumDoc(schema, request)
			if req {
				desc += " Required."
			}
			def.Fields = append(def.Fields, &fieldDef{Name: uniqueName(fieldName(name), taken), Wire: name, Type: typ, Cat: c, Doc: strings.TrimSpace(desc), Required: req})
		}
	}
}

/* ----------------------------------------------------------- operations -- */

// parameters returns an operation's parameters of one kind, resolved.
func (g *generator) parameters(o *operation, in string) []*Object {
	item := g.spec.Obj("paths").Obj(o.Path)
	op := item.Obj(strings.ToLower(o.HTTP))
	var out []*Object
	for _, raw := range append(append([]any{}, item.Arr("parameters")...), op.Arr("parameters")...) {
		prm := g.resolve(raw.(*Object))
		if prm != nil && prm.Str("in") == in {
			out = append(out, prm)
		}
	}
	return out
}

func (g *generator) collectOperations() {
	paths := g.spec.Obj("paths")
	if paths == nil {
		g.fail("the spec has no paths")
		return
	}
	for _, p := range paths.Keys {
		item := paths.Obj(p)
		for _, method := range []string{"get", "put", "post", "delete", "patch"} {
			op := item.Obj(method)
			if op == nil {
				continue
			}
			id := op.Str("operationId")
			if id == "" {
				g.fail("%s %s has no operationId", strings.ToUpper(method), p)
				continue
			}
			segs := strings.Split(id, ".")
			o := &operation{
				ID:          id,
				Resource:    segs[:len(segs)-1],
				Method:      pascal(segs[len(segs)-1]),
				HTTP:        strings.ToUpper(method),
				Path:        p,
				Summary:     strings.TrimSpace(op.Str("summary")),
				Description: strings.TrimSpace(op.Str("description")),
				Envelope:    op.Str("x-verisec-envelope"),
				Tier:        op.Str("x-verisec-tier"),
				Params:      op.Str("x-params-type"),
			}
			if len(o.Resource) == 0 {
				g.fail("%s: an operationId needs a resource and a method (resource.method)", id)
				continue
			}
			if o.Envelope == "" {
				o.Envelope = "object"
			}
			if price, ok := op.Get("x-price").(json.Number); ok {
				o.Price = price.String()
			}
			if tags := op.Arr("tags"); len(tags) > 0 {
				o.Tag, _ = tags[0].(string)
			}
			g.ops = append(g.ops, o)

			for _, prm := range g.parameters(o, "path") {
				o.PathParams = append(o.PathParams, prm.Str("name"))
			}
			for _, prm := range g.parameters(o, "header") {
				if strings.EqualFold(prm.Str("name"), "X-VeriSec-Source") {
					o.Source = true
				}
			}
			content := op.Obj("requestBody").Obj("content")
			switch {
			case content.Has("application/json"):
				o.Body = "json"
				o.Params = g.bodyType(o, content.Obj("application/json"))
			case content.Has("multipart/form-data"):
				o.Body = "multipart"
				o.Params = g.bodyType(o, content.Obj("multipart/form-data"))
			case content != nil:
				g.fail("%s: unsupported request content %v", id, content.Keys)
			case len(g.parameters(o, "query")) > 0:
				o.Body = "query"
				if o.Params == "" {
					o.Params = pascal(strings.Join(segs, "_")) + "Params"
				}
			default:
				o.Params = "" // path parameters only: they are the method's arguments
			}
			if o.Params != "" {
				g.paramsOf[o.Params] = o
			}
			o.Answer = g.answerType(o, op)
			if o.Tier == "major" && o.Answer != "" {
				g.open[o.Answer] = true
			}
		}
	}
}

func (g *generator) bodyType(o *operation, media *Object) string {
	ref := media.Obj("schema").Str("$ref")
	if ref == "" {
		g.fail("%s: the request body is not a $ref to a component schema", o.ID)
		return ""
	}
	name := refName(ref)
	if o.Params != "" && o.Params != name {
		g.fail("%s: x-params-type %s differs from the body schema %s", o.ID, o.Params, name)
	}
	return name
}

// answerType is the type the method returns: the envelope's data for KYC
// operations, the answer object for Financial ones.
func (g *generator) answerType(o *operation, op *Object) string {
	res := g.resolve(op.Obj("responses").Obj("200"))
	if res == nil {
		for _, status := range op.Obj("responses").Keys {
			if strings.HasPrefix(status, "2") {
				res = g.resolve(op.Obj("responses").Obj(status))
				break
			}
		}
	}
	schema := res.Obj("content").Obj("application/json").Obj("schema")
	ref := schema.Str("$ref")
	if ref == "" {
		g.fail("%s: the success answer is not a $ref to a component schema", o.ID)
		return ""
	}
	if o.Envelope != "data" {
		return refName(ref)
	}
	data := g.resolve(schema).Obj("properties").Obj("data")
	if data == nil || data.Str("$ref") == "" {
		g.fail("%s: the envelope %s has no data $ref", o.ID, refName(ref))
		return ""
	}
	return refName(data.Str("$ref"))
}

// markRequestSchemas finds every schema a request body reaches.
func (g *generator) markRequestSchemas() {
	var visit func(s *Object)
	visit = func(s *Object) {
		if s == nil {
			return
		}
		if ref := s.Str("$ref"); ref != "" {
			name := refName(ref)
			if g.sides[name] == request {
				return
			}
			g.sides[name] = request
			visit(g.schemas.Obj(name))
			return
		}
		for _, key := range []string{"oneOf", "anyOf", "allOf"} {
			for _, v := range s.Arr(key) {
				o, _ := v.(*Object)
				visit(o)
			}
		}
		if p := s.Obj("properties"); p != nil {
			for _, key := range p.Keys {
				visit(p.Obj(key))
			}
		}
		visit(s.Obj("items"))
		visit(s.Obj("additionalProperties"))
	}
	for _, o := range g.ops {
		if o.Body == "json" || o.Body == "multipart" {
			visit(&Object{Keys: []string{"$ref"}, Map: map[string]any{"$ref": "#/components/schemas/" + o.Params}})
		}
	}
	// a schema read in an answer as well as sent would need two shapes
	for _, o := range g.ops {
		if g.sides[o.Answer] == request {
			g.fail("%s: the answer type %s is also part of a request", o.ID, o.Answer)
		}
	}
}

func (g *generator) checkOperations() {
	seen := map[string]string{}
	for _, o := range g.ops {
		key := pascalPath(o)
		if other := seen[key]; other != "" {
			g.fail("%s and %s map to the same method %s", other, o.ID, key)
		}
		seen[key] = o.ID
		if o.Params != "" && g.defs[o.Params] == nil {
			g.fail("%s: no type %s", o.ID, o.Params)
		}
		if g.defs[o.Answer] == nil {
			g.fail("%s: no answer type %s", o.ID, o.Answer)
		}
		if o.Body == "multipart" {
			hasFile := false
			for _, f := range g.defs[o.Params].Fields {
				hasFile = hasFile || f.Cat == catFile
			}
			if !hasFile {
				g.fail("%s: the upload %s has no file field", o.ID, o.Params)
			}
		}
	}
}

// pascalPath is the Go spelling of an operation: Phone.Otp.Send.
func pascalPath(o *operation) string {
	var parts []string
	for _, s := range o.Resource {
		parts = append(parts, pascal(s))
	}
	return strings.Join(append(parts, o.Method), ".")
}

func (g *generator) buildServices() {
	index := map[string]*service{}
	for _, o := range g.ops {
		var parent *service
		for i := range o.Resource {
			key := strings.Join(o.Resource[:i+1], ".")
			s := index[key]
			if s == nil {
				var typ strings.Builder
				for _, seg := range o.Resource[:i+1] {
					typ.WriteString(pascal(seg))
				}
				s = &service{Segs: o.Resource[:i+1], Field: pascal(o.Resource[i]), Type: typ.String() + "Service", Tag: o.Tag}
				index[key] = s
				if parent == nil {
					g.services = append(g.services, s)
				} else {
					parent.Children = append(parent.Children, s)
				}
			}
			parent = s
		}
		parent.Ops = append(parent.Ops, o)
	}
	// a resource name that is also a method of its parent would clash
	var check func(s *service)
	check = func(s *service) {
		names := map[string]bool{}
		for _, o := range s.Ops {
			names[o.Method] = true
		}
		for _, c := range s.Children {
			if names[c.Field] {
				g.fail("%s has both a method and a resource named %s", s.Type, c.Field)
			}
			check(c)
		}
	}
	for _, s := range g.services {
		check(s)
	}
	types := map[string]bool{}
	var collect func(s *service)
	collect = func(s *service) {
		if types[s.Type] || g.defs[s.Type] != nil {
			g.fail("the service type %s is used twice", s.Type)
		}
		types[s.Type] = true
		for _, c := range s.Children {
			collect(c)
		}
	}
	for _, s := range g.services {
		collect(s)
	}
}

// sortedOps returns the operations by operationId.
func (g *generator) sortedOps() []*operation {
	out := append([]*operation(nil), g.ops...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
