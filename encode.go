package verisec

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/textproto"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
)

var (
	pkgPath       = reflect.TypeOf(Client{}).PkgPath()
	marshalerType = reflect.TypeOf((*json.Marshaler)(nil)).Elem()
	imageType     = reflect.TypeOf((*Image)(nil)).Elem()
	fileType      = reflect.TypeOf((*File)(nil))
)

/* ---------------------------------------------------------- struct info -- */

// structField is one exported field of a generated struct, with its wire name.
type structField struct {
	index     int
	wire      string
	omitEmpty bool
	list      *listTag
}

// listTag is the `verisec:"list,…"` tag of an image list: the entry keys the client fills in when they are
// left out, and the label of the ids it makes.
type listTag struct {
	index, id, label string
}

type structInfo struct {
	fields []structField
	byWire map[string]int // wire name -> position in fields
}

var structInfos sync.Map // reflect.Type -> *structInfo

func structInfoOf(t reflect.Type) *structInfo {
	if v, ok := structInfos.Load(t); ok {
		return v.(*structInfo)
	}
	info := &structInfo{byWire: map[string]int{}}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() || f.Anonymous {
			continue
		}
		tag := f.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name, opts, _ := strings.Cut(tag, ",")
		if name == "" {
			name = f.Name
		}
		sf := structField{index: i, wire: name, omitEmpty: strings.Contains(","+opts+",", ",omitempty,")}
		if v, ok := strings.CutPrefix(f.Tag.Get("verisec"), "list"); ok {
			sf.list = &listTag{label: "item"}
			for _, kv := range strings.Split(strings.TrimPrefix(v, ","), ",") {
				key, value, _ := strings.Cut(kv, "=")
				switch key {
				case "index":
					sf.list.index = value
				case "id":
					sf.list.id = value
				case "label":
					sf.list.label = value
				}
			}
		}
		info.byWire[name] = len(info.fields)
		info.fields = append(info.fields, sf)
	}
	structInfos.Store(t, info)
	return info
}

// ownStruct reports whether t is a request struct of this package, encoded field by field (answer types and
// anything with its own MarshalJSON go through encoding/json).
func ownStruct(t reflect.Type) bool {
	return t.Kind() == reflect.Struct && t.PkgPath() == pkgPath && !t.Implements(marshalerType) && !reflect.PointerTo(t).Implements(marshalerType)
}

// empty is encoding/json's omitempty test, except that a non-nil empty slice or map is a value: nil means "not
// sent", []T{} sends [].
func empty(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Slice, reflect.Map:
		return v.IsNil()
	case reflect.Array, reflect.String:
		return v.Len() == 0
	case reflect.Bool:
		return !v.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return v.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return v.Float() == 0
	}
	return false
}

// deref follows pointers and interfaces; it returns an invalid Value at a nil.
func deref(v reflect.Value) reflect.Value {
	for v.IsValid() && (v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface) {
		if v.IsNil() {
			return reflect.Value{}
		}
		v = v.Elem()
	}
	return v
}

/* ------------------------------------------------------------ JSON body -- */

// encodeBody writes a params struct as the JSON body of a KYC call: every field under the exact name the spec
// spells (the json tag), empty optional fields left out, each Image as plain base64, and in an image list the
// entries' index and id filled in where left out. A nil params is {}. The params are only read, never changed.
func encodeBody(params any, extra []extraField) ([]byte, error) {
	e := &bodyEncoder{}
	v := deref(reflect.ValueOf(params))
	switch {
	case !v.IsValid():
		e.buf.WriteByte('{')
		if err := e.extras(extra, 0); err != nil {
			return nil, err
		}
		e.buf.WriteByte('}')
	case ownStruct(v.Type()):
		if err := e.object(v, "", nil, extra); err != nil {
			return nil, err
		}
	default:
		if len(extra) > 0 {
			return nil, fmt.Errorf("verisec: WithExtraField needs a params struct, not %s", v.Type())
		}
		if err := e.value(v, ""); err != nil {
			return nil, err
		}
	}
	return e.buf.Bytes(), nil
}

type bodyEncoder struct {
	buf bytes.Buffer
}

// listEntry is what an image-list entry gets filled in: its position and the label of its id.
type listEntry struct {
	position int
	tag      *listTag
}

func join(path, name string) string {
	if path == "" {
		return name
	}
	return path + "." + name
}

func (e *bodyEncoder) key(n *int, name string) {
	if *n > 0 {
		e.buf.WriteByte(',')
	}
	*n++
	e.writeString(name)
	e.buf.WriteByte(':')
}

func (e *bodyEncoder) object(v reflect.Value, path string, entry *listEntry, extra []extraField) error {
	info := structInfoOf(v.Type())
	replaced := map[string]bool{}
	for _, x := range extra {
		replaced[x.name] = true
	}
	e.buf.WriteByte('{')
	n := 0
	wroteIndex, wroteID := false, false
	for _, f := range info.fields {
		if replaced[f.wire] {
			continue
		}
		fv := v.Field(f.index)
		if entry != nil && f.wire == entry.tag.index && entry.tag.index != "" {
			wroteIndex = true
			if empty(fv) && fv.Kind() == reflect.Pointer {
				e.key(&n, f.wire)
				e.buf.WriteString(strconv.Itoa(entry.position))
				continue
			}
		}
		if entry != nil && f.wire == entry.tag.id && entry.tag.id != "" {
			wroteID = true
			if s := deref(fv); !s.IsValid() || (s.Kind() == reflect.String && s.Len() == 0) {
				e.key(&n, f.wire)
				e.writeString(entry.tag.label + "-" + strconv.Itoa(entry.position+1))
				continue
			}
		}
		if f.omitEmpty && empty(fv) {
			continue
		}
		e.key(&n, f.wire)
		var err error
		if f.list != nil {
			err = e.list(fv, join(path, f.wire), f.list)
		} else {
			err = e.value(fv, join(path, f.wire))
		}
		if err != nil {
			return err
		}
	}
	if entry != nil && entry.tag.index != "" && !wroteIndex {
		e.key(&n, entry.tag.index)
		e.buf.WriteString(strconv.Itoa(entry.position))
	}
	if entry != nil && entry.tag.id != "" && !wroteID {
		e.key(&n, entry.tag.id)
		e.writeString(entry.tag.label + "-" + strconv.Itoa(entry.position+1))
	}
	if err := e.extras(extra, n); err != nil {
		return err
	}
	e.buf.WriteByte('}')
	return nil
}

func (e *bodyEncoder) extras(extra []extraField, n int) error {
	for _, x := range extra {
		e.key(&n, x.name)
		if err := e.value(reflect.ValueOf(x.value), x.name); err != nil {
			return err
		}
	}
	return nil
}

// list writes an image list: entries that are structs get their index and id filled in where left out.
func (e *bodyEncoder) list(v reflect.Value, path string, tag *listTag) error {
	if v.Kind() != reflect.Slice && v.Kind() != reflect.Array {
		return e.value(v, path)
	}
	if v.Kind() == reflect.Slice && v.IsNil() {
		e.buf.WriteString("null")
		return nil
	}
	e.buf.WriteByte('[')
	for i := 0; i < v.Len(); i++ {
		if i > 0 {
			e.buf.WriteByte(',')
		}
		at := fmt.Sprintf("%s[%d]", path, i)
		ev := v.Index(i)
		if ev.Kind() == reflect.Interface && !ev.IsNil() && ev.Type() != imageType {
			ev = ev.Elem()
		}
		if s := deref(ev); s.IsValid() && ownStruct(s.Type()) && ev.Type() != imageType {
			if err := e.object(s, at, &listEntry{position: i, tag: tag}, nil); err != nil {
				return err
			}
			continue
		}
		if err := e.value(ev, at); err != nil {
			return err
		}
	}
	e.buf.WriteByte(']')
	return nil
}

func (e *bodyEncoder) value(v reflect.Value, path string) error {
	if !v.IsValid() {
		e.buf.WriteString("null")
		return nil
	}
	switch v.Kind() {
	case reflect.Interface:
		if v.IsNil() {
			e.buf.WriteString("null")
			return nil
		}
		if img, ok := v.Interface().(Image); ok {
			return e.image(img, path)
		}
		return e.marshal(v.Interface())
	case reflect.Pointer:
		if v.IsNil() {
			e.buf.WriteString("null")
			return nil
		}
		if img, ok := v.Interface().(Image); ok {
			return e.image(img, path)
		}
		if v.Type() == fileType {
			return fmt.Errorf("verisec: %s: a *verisec.File is an upload; KYC images are verisec.Image values", path)
		}
		return e.value(v.Elem(), path)
	case reflect.Struct:
		if ownStruct(v.Type()) {
			return e.object(v, path, nil, nil)
		}
		return e.marshal(v.Interface())
	case reflect.Slice:
		if v.IsNil() {
			e.buf.WriteString("null")
			return nil
		}
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return e.marshal(v.Interface())
		}
		fallthrough
	case reflect.Array:
		e.buf.WriteByte('[')
		for i := 0; i < v.Len(); i++ {
			if i > 0 {
				e.buf.WriteByte(',')
			}
			if err := e.value(v.Index(i), fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
		e.buf.WriteByte(']')
		return nil
	case reflect.Map:
		if v.IsNil() {
			e.buf.WriteString("null")
			return nil
		}
		if v.Type().Key().Kind() != reflect.String {
			return e.marshal(v.Interface())
		}
		keys := make([]string, 0, v.Len())
		for _, k := range v.MapKeys() {
			keys = append(keys, k.String())
		}
		sort.Strings(keys)
		e.buf.WriteByte('{')
		n := 0
		for _, k := range keys {
			e.key(&n, k)
			if err := e.value(v.MapIndex(reflect.ValueOf(k).Convert(v.Type().Key())), join(path, k)); err != nil {
				return err
			}
		}
		e.buf.WriteByte('}')
		return nil
	}
	return e.marshal(v.Interface())
}

func (e *bodyEncoder) image(img Image, path string) error {
	s, err := imageBase64(img, path)
	if err != nil {
		return err
	}
	e.buf.WriteByte('"')
	e.buf.WriteString(s) // base64 needs no escaping
	e.buf.WriteByte('"')
	return nil
}

func (e *bodyEncoder) marshal(x any) error {
	data, err := marshalJSON(x)
	if err != nil {
		return fmt.Errorf("verisec: could not encode the request body: %w", err)
	}
	e.buf.Write(data)
	return nil
}

func (e *bodyEncoder) writeString(s string) {
	data, _ := marshalJSON(s)
	e.buf.Write(data)
}

// marshalJSON is json.Marshal without escaping <, > and &.
func marshalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

/* --------------------------------------------------------------- query -- */

// encodeQuery writes a params struct as a query string ("?name=…&country=…"), in field order. Nil fields are
// left out; a slice repeats its key.
func encodeQuery(params any, extra []extraField) (string, error) {
	var parts []string
	v := deref(reflect.ValueOf(params))
	if v.IsValid() {
		if v.Kind() != reflect.Struct {
			return "", fmt.Errorf("verisec: query parameters must be a params struct, not %s", v.Type())
		}
		info := structInfoOf(v.Type())
		for _, f := range info.fields {
			fv := v.Field(f.index)
			if f.omitEmpty && empty(fv) {
				continue
			}
			if err := addQuery(&parts, f.wire, fv); err != nil {
				return "", err
			}
		}
	}
	for _, x := range extra {
		if err := addQuery(&parts, x.name, reflect.ValueOf(x.value)); err != nil {
			return "", err
		}
	}
	if len(parts) == 0 {
		return "", nil
	}
	return "?" + strings.Join(parts, "&"), nil
}

func addQuery(parts *[]string, name string, v reflect.Value) error {
	v = deref(v)
	if !v.IsValid() {
		return nil
	}
	if v.Kind() == reflect.Slice || v.Kind() == reflect.Array {
		for i := 0; i < v.Len(); i++ {
			if err := addQuery(parts, name, v.Index(i)); err != nil {
				return err
			}
		}
		return nil
	}
	s, ok := formatScalar(v)
	if !ok {
		data, err := marshalJSON(v.Interface())
		if err != nil {
			return fmt.Errorf("verisec: the query parameter %s: %w", name, err)
		}
		s = string(data)
	}
	*parts = append(*parts, url.QueryEscape(name)+"="+url.QueryEscape(s))
	return nil
}

// formatScalar spells a string, number or boolean the way a query string or a form field carries it.
func formatScalar(v reflect.Value) (string, bool) {
	switch v.Kind() {
	case reflect.String:
		return v.String(), true
	case reflect.Bool:
		return strconv.FormatBool(v.Bool()), true
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return strconv.FormatInt(v.Int(), 10), true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return strconv.FormatUint(v.Uint(), 10), true
	case reflect.Float32, reflect.Float64:
		return strconv.FormatFloat(v.Float(), 'f', -1, 64), true
	}
	return "", false
}

/* ----------------------------------------------------------- multipart -- */

var quoteEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`)

// encodeMultipart writes an upload's params struct as multipart/form-data: each *File field as a file part
// (the image first), then the other fields that are set as text parts.
func encodeMultipart(params any, extra []extraField) ([]byte, string, error) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	v := deref(reflect.ValueOf(params))
	if v.IsValid() {
		if v.Kind() != reflect.Struct {
			return nil, "", fmt.Errorf("verisec: an upload's params must be a params struct, not %s", v.Type())
		}
		info := structInfoOf(v.Type())
		for _, f := range info.fields {
			if fv := v.Field(f.index); fv.Type() == fileType && !fv.IsNil() {
				if err := writeFilePart(w, f.wire, fv.Interface().(*File)); err != nil {
					return nil, "", err
				}
			}
		}
		for _, f := range info.fields {
			fv := v.Field(f.index)
			if fv.Type() == fileType || (f.omitEmpty && empty(fv)) {
				continue
			}
			if err := writeTextPart(w, f.wire, fv); err != nil {
				return nil, "", err
			}
		}
	}
	for _, x := range extra {
		if file, ok := x.value.(*File); ok && file != nil {
			if err := writeFilePart(w, x.name, file); err != nil {
				return nil, "", err
			}
			continue
		}
		if err := writeTextPart(w, x.name, reflect.ValueOf(x.value)); err != nil {
			return nil, "", err
		}
	}
	if err := w.Close(); err != nil {
		return nil, "", err
	}
	return buf.Bytes(), w.FormDataContentType(), nil
}

func writeFilePart(w *multipart.Writer, name string, file *File) error {
	data, err := file.content()
	if err != nil {
		return fmt.Errorf("verisec: %s: %w", name, err)
	}
	contentType := file.ContentType
	if contentType == "" {
		contentType = sniffContentType(data)
	}
	header := make(textproto.MIMEHeader)
	header.Set("Content-Disposition", fmt.Sprintf(`form-data; name="%s"; filename="%s"`, quoteEscaper.Replace(name), quoteEscaper.Replace(file.name())))
	header.Set("Content-Type", contentType)
	part, err := w.CreatePart(header)
	if err != nil {
		return err
	}
	_, err = part.Write(data)
	return err
}

func writeTextPart(w *multipart.Writer, name string, v reflect.Value) error {
	v = deref(v)
	if !v.IsValid() {
		return nil
	}
	s, ok := formatScalar(v)
	if !ok {
		data, err := marshalJSON(v.Interface())
		if err != nil {
			return fmt.Errorf("verisec: the form field %s: %w", name, err)
		}
		s = string(data)
	}
	return w.WriteField(name, s)
}
