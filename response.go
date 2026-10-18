package verisec

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
)

// OpenResult is the result of a major API (x-verisec-tier: major in the spec: Face Match, Document Read,
// Sanctions Screening, …). Those engines return more than a fixed type could list, so their result is the
// engine's full answer as an open JSON object. Every such answer type embeds an OpenResult:
//
//	match, err := client.Face.Match(ctx, params)
//	results, _ := match.Get("results").([]any)
//
//	var mine struct {
//		Results []struct{ Similarity float64 `json:"similarity"` } `json:"results"`
//	}
//	err = match.Decode(&mine)
type OpenResult struct {
	// Raw is the answer as decoded JSON: objects are map[string]any, arrays []any, numbers float64.
	Raw map[string]any

	raw []byte // the bytes as received, for Decode
}

// Get returns the top-level member key, or nil.
func (r OpenResult) Get(key string) any { return r.Raw[key] }

// Decode fills v (a pointer to a struct or map of your own) from the result, as json.Unmarshal would.
func (r OpenResult) Decode(v any) error {
	data := r.raw
	if data == nil {
		var err error
		if data, err = json.Marshal(r.Raw); err != nil {
			return err
		}
	}
	return json.Unmarshal(data, v)
}

// UnmarshalJSON keeps the object in Raw.
func (r *OpenResult) UnmarshalJSON(data []byte) error {
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	r.Raw, r.raw = m, append([]byte(nil), data...)
	if m == nil {
		r.raw = nil
	}
	return nil
}

// MarshalJSON writes Raw.
func (r OpenResult) MarshalJSON() ([]byte, error) {
	if r.Raw == nil {
		return []byte("null"), nil
	}
	return marshalJSON(r.Raw)
}

// decodeObject reads a JSON object into dst (a pointer to an answer struct's plain twin, without methods):
// each member with a field is decoded into it; the members without one, and those whose JSON type is not the
// one the spec gives, go to *extra with their values, so a change in the API never fails a call that was
// charged.
func decodeObject(data []byte, dst any, extra *map[string]any) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &members); err != nil {
		return err
	}
	v := reflect.ValueOf(dst).Elem()
	info := structInfoOf(v.Type())
	for key, raw := range members {
		if i, ok := info.byWire[key]; ok {
			fv := v.Field(info.fields[i].index)
			err := json.Unmarshal(raw, fv.Addr().Interface())
			if err == nil {
				continue
			}
			var typeErr *json.UnmarshalTypeError
			if !errors.As(err, &typeErr) {
				return err
			}
			fv.Set(reflect.Zero(fv.Type()))
		}
		var value any
		if err := json.Unmarshal(raw, &value); err != nil {
			return err
		}
		if *extra == nil {
			*extra = make(map[string]any)
		}
		(*extra)[key] = value
	}
	return nil
}

// encodeObject writes v (an answer struct's plain twin) in field order, then the members of extra it does not
// already hold, in key order. Empty fields are left out, nested objects included, so an answer re-encodes
// without members the API did not send (a zero number or false reads the same as one left out).
func encodeObject(v any, extra map[string]any) ([]byte, error) {
	rv := reflect.ValueOf(v)
	info := structInfoOf(rv.Type())
	var b bytes.Buffer
	b.WriteByte('{')
	present := map[string]bool{}
	write := func(key string, value any) error {
		data, err := marshalJSON(value)
		if err != nil {
			return fmt.Errorf("the member %s: %w", key, err)
		}
		if len(present) > 0 {
			b.WriteByte(',')
		}
		present[key] = true
		k, _ := marshalJSON(key)
		b.Write(k)
		b.WriteByte(':')
		b.Write(data)
		return nil
	}
	for _, f := range info.fields {
		fv := rv.Field(f.index)
		if f.omitEmpty && (empty(fv) || (fv.Kind() == reflect.Struct && fv.IsZero())) {
			continue
		}
		if err := write(f.wire, fv.Interface()); err != nil {
			return nil, err
		}
	}
	keys := make([]string, 0, len(extra))
	for key := range extra {
		if !present[key] {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		if err := write(key, extra[key]); err != nil {
			return nil, err
		}
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}
