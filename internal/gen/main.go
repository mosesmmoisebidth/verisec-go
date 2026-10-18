// Command gen writes types.go and resources.go from the VeriSec OpenAPI spec:
// one Go type per component schema (plus the inline objects and the query
// parameters of the GET operations), the Client with one service per
// resource, and one method per operation. Run it from the module root after
// the spec changes:
//
//	go run ./internal/gen
//	go generate ./...
//
// Flags: -spec (default ../spec/openapi.json, the JSON twin of openapi.yaml)
// and -out (default ".").
//
// Naming follows SDK-API.md. Type names are the schema names; an inline object
// is <Parent><Property> and a list item uses the singular property name
// (FaceMatchParamsImage). Resources and methods are the dotted operationId in
// PascalCase (phone.otp.send is Client.Phone.Otp.Send). Field names are Go
// names with initialisms in capitals (LivenessTransactionID, UserIP), tagged
// with the exact wire name.
//
// In request types an optional scalar is a pointer (verisec.String, Int,
// Float, Bool), a nested object is a pointer, an image is a verisec.Image and
// an upload a *verisec.File. Answer types use plain values (a pointer only
// where the spec allows null), keep the members they do not know in Extra,
// and carry LastResponse. The answers of x-verisec-tier: major operations are
// open results (an embedded OpenResult).
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"go/format"
	"os"
	"path/filepath"
)

func main() {
	specPath := flag.String("spec", filepath.Join("..", "spec", "openapi.json"), "the OpenAPI spec (JSON)")
	outDir := flag.String("out", ".", "the directory that gets types.go and resources.go")
	flag.Parse()

	files, summary, err := generate(*specPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(1)
	}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(*outDir, f.Name), f.Source, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "gen:", err)
			os.Exit(1)
		}
	}
	fmt.Println("gen:", summary)
}

// file is one generated source file.
type file struct {
	Name   string
	Source []byte
}

// generate reads the spec and returns the formatted files.
func generate(specPath string) ([]file, string, error) {
	raw, err := os.ReadFile(specPath)
	if err != nil {
		return nil, "", err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	root, err := decodeOrdered(dec)
	if err != nil {
		return nil, "", fmt.Errorf("reading %s: %w", specPath, err)
	}
	spec, ok := root.(*Object)
	if !ok {
		return nil, "", fmt.Errorf("%s is not a JSON object", specPath)
	}

	g := newGenerator(spec)
	if err := g.build(); err != nil {
		return nil, "", err
	}
	var files []file
	for _, f := range []file{{"types.go", g.types()}, {"resources.go", g.resources()}} {
		src, err := format.Source(f.Source)
		if err != nil {
			return nil, "", fmt.Errorf("formatting %s: %w\n%s", f.Name, err, numbered(f.Source))
		}
		files = append(files, file{f.Name, src})
	}
	summary := fmt.Sprintf("%d schemas, %d types, %d resources, %d operations", len(g.schemas.Keys), len(g.order), len(g.services), len(g.ops))
	return files, summary, nil
}

// numbered prints source with line numbers, to find a formatting error.
func numbered(src []byte) string {
	var b bytes.Buffer
	for i, line := range bytes.Split(src, []byte("\n")) {
		fmt.Fprintf(&b, "%5d  %s\n", i+1, line)
	}
	return b.String()
}

/* ------------------------------------------------------------ ordered JSON -- */

// Object is a JSON object that remembers the order of its keys, so the output
// follows the spec's order.
type Object struct {
	Keys []string
	Map  map[string]any
}

// Get returns the member key, or nil.
func (o *Object) Get(key string) any {
	if o == nil {
		return nil
	}
	return o.Map[key]
}

// Has reports whether the member key is present.
func (o *Object) Has(key string) bool {
	if o == nil {
		return false
	}
	_, ok := o.Map[key]
	return ok
}

// Obj returns the member key when it is an object.
func (o *Object) Obj(key string) *Object {
	v, _ := o.Get(key).(*Object)
	return v
}

// Str returns the member key when it is a string.
func (o *Object) Str(key string) string {
	v, _ := o.Get(key).(string)
	return v
}

// Arr returns the member key when it is an array.
func (o *Object) Arr(key string) []any {
	v, _ := o.Get(key).([]any)
	return v
}

// Bool returns the member key when it is a boolean.
func (o *Object) Bool(key string) bool {
	v, _ := o.Get(key).(bool)
	return v
}

func decodeOrdered(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return tok, nil
	}
	switch delim {
	case '{':
		o := &Object{Map: map[string]any{}}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return nil, err
			}
			key, _ := kt.(string)
			v, err := decodeOrdered(dec)
			if err != nil {
				return nil, err
			}
			if _, dup := o.Map[key]; !dup {
				o.Keys = append(o.Keys, key)
			}
			o.Map[key] = v
		}
		_, err := dec.Token()
		return o, err
	case '[':
		arr := []any{}
		for dec.More() {
			v, err := decodeOrdered(dec)
			if err != nil {
				return nil, err
			}
			arr = append(arr, v)
		}
		_, err := dec.Token()
		return arr, err
	}
	return nil, fmt.Errorf("unexpected %v", delim)
}

// plain turns an ordered value back into plain Go values (for json.Marshal).
func plain(v any) any {
	switch x := v.(type) {
	case *Object:
		m := make(map[string]any, len(x.Keys))
		for _, k := range x.Keys {
			m[k] = plain(x.Map[k])
		}
		return m
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = plain(e)
		}
		return out
	}
	return v
}
