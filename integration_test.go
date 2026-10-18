package verisec_test

// Every operation through the SDK against the shared test server (../test-server), which checks each request
// the way the real API does: the key, every field against its designed schema (no unknown fields), images that
// are real base64 JPEG/PNG, uploaded files. Plus injected failures, keys, live OAuth and a server-signed webhook.
// TestMain starts the server on its own port and stops it at the end; go test -short skips these tests.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mosesmmoisebidth/verisec-go"
)

// testServerPort is the Go suite's own port for the shared test server.
const testServerPort = "4022"

var serverURL string

func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Short() {
		os.Exit(m.Run())
	}
	stop, err := startTestServer()
	if err != nil {
		fmt.Fprintln(os.Stderr, "verisec tests: the test server did not start:", err)
		os.Exit(1)
	}
	serverURL = "http://127.0.0.1:" + testServerPort
	code := m.Run()
	stop()
	os.Exit(code)
}

// startTestServer runs node ../test-server/server.mjs --port 4022, with a preload that ends the server when the
// test binary ends, and waits until it listens.
func startTestServer() (stop func(), err error) {
	watchdog, err := filepath.Abs(filepath.Join("testdata", "exit-with-parent.cjs"))
	if err != nil {
		return nil, err
	}
	cmd := exec.Command("node", "--require", watchdog, filepath.Join("..", "test-server", "server.mjs"), "--port", testServerPort)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out := &readyWriter{ready: make(chan struct{})}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("node: %w", err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	stop = func() {
		stdin.Close() // the preload exits node when its stdin closes
		select {
		case <-exited:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-exited
		}
	}
	select {
	case <-out.ready:
		return stop, nil
	case err := <-exited:
		return nil, fmt.Errorf("it exited (%v):\n%s", err, out)
	case <-time.After(20 * time.Second):
		stop()
		return nil, fmt.Errorf("it did not listen within 20 s:\n%s", out)
	}
}

// readyWriter collects the server's output and signals once it says it listens.
type readyWriter struct {
	mu    sync.Mutex
	buf   bytes.Buffer
	ready chan struct{}
	once  sync.Once
}

func (w *readyWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf.Write(p)
	if strings.Contains(w.buf.String(), "VeriSec test server on http://127.0.0.1:"+testServerPort) {
		w.once.Do(func() { close(w.ready) })
	}
	return len(p), nil
}

func (w *readyWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

/* ---------------------------------------------------------------- helpers -- */

const png64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="

var pngBytes, _ = base64.StdEncoding.DecodeString(png64)

func needServer(t *testing.T) {
	t.Helper()
	if serverURL == "" {
		t.Skip("needs the test server (run without -short)")
	}
}

// control calls a /__test endpoint: POST with a body, GET without one.
func control(t *testing.T, path string, body any) map[string]any {
	t.Helper()
	var res *http.Response
	var err error
	if body == nil {
		res, err = http.Get(serverURL + "/__test/" + path)
	} else {
		data, _ := json.Marshal(body)
		res, err = http.Post(serverURL+"/__test/"+path, "application/json", bytes.NewReader(data))
	}
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func reset(t *testing.T) { t.Helper(); control(t, "reset", map[string]any{}) }

// logged is what the server received since the last reset.
func logged(t *testing.T) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, r := range control(t, "requests", nil)["requests"].([]any) {
		out = append(out, r.(map[string]any))
	}
	return out
}

func newClient(t *testing.T, key string, opts ...verisec.ClientOption) *verisec.Client {
	t.Helper()
	c, err := verisec.New(key, append([]verisec.ClientOption{verisec.WithBaseURL(serverURL)}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

type spec struct {
	Paths      map[string]map[string]map[string]any `json:"paths"`
	Components struct {
		Schemas map[string]map[string]any `json:"schemas"`
	} `json:"components"`
}

func loadSpec(t *testing.T) *spec {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "spec", "openapi.json"))
	if err != nil {
		t.Fatal(err)
	}
	s := new(spec)
	if err := json.Unmarshal(data, s); err != nil {
		t.Fatal(err)
	}
	return s
}

// dig walks a decoded JSON value by keys.
func dig(v any, keys ...string) any {
	for _, k := range keys {
		m, _ := v.(map[string]any)
		v = m[k]
	}
	return v
}

// methodOf finds the client method for a Go path such as "Phone.Otp.Send".
func methodOf(t *testing.T, c *verisec.Client, goPath string) reflect.Value {
	t.Helper()
	v := reflect.ValueOf(c)
	parts := strings.Split(goPath, ".")
	for _, field := range parts[:len(parts)-1] {
		v = v.Elem().FieldByName(field)
		if !v.IsValid() {
			t.Fatalf("no resource for %s", goPath)
		}
	}
	m := v.MethodByName(parts[len(parts)-1])
	if !m.IsValid() {
		t.Fatalf("no method %s", goPath)
	}
	return m
}

var (
	imageType = reflect.TypeOf((*verisec.Image)(nil)).Elem()
	fileType  = reflect.TypeOf((*verisec.File)(nil))
)

// developerInput fills params from a request example the way a developer would: images as file paths and
// bytes in turn, image lists as entries holding only their image (the SDK fills the index and ids in).
type developerInput struct {
	t       *testing.T
	pngPath string
	n       int
}

func (d *developerInput) image() verisec.Image {
	d.n++
	if d.n%2 == 1 {
		return verisec.ImageFromPath(d.pngPath)
	}
	return verisec.ImageFromBytes(pngBytes)
}

func (d *developerInput) file() *verisec.File {
	d.n++
	if d.n%2 == 1 {
		return verisec.FileFromPath(d.pngPath)
	}
	return verisec.FileFromBytes(pngBytes, "photo-bytes.png")
}

// wireFields maps a struct's json names to its fields.
func wireFields(t reflect.Type) map[string]reflect.StructField {
	out := map[string]reflect.StructField{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name != "" && name != "-" {
			out[name] = f
		}
	}
	return out
}

func (d *developerInput) fill(sv reflect.Value, example map[string]any) {
	d.t.Helper()
	fields := wireFields(sv.Type())
	for _, key := range sortedKeys(example) {
		value := example[key]
		f, ok := fields[key]
		if !ok {
			d.t.Fatalf("%s has no field for %q", sv.Type(), key)
		}
		fv := sv.FieldByIndex(f.Index)
		switch {
		case fv.Type() == imageType:
			fv.Set(reflect.ValueOf(d.image()))
		case fv.Type() == fileType:
			fv.Set(reflect.ValueOf(d.file()))
		case fv.Kind() == reflect.Slice && fv.Type().Elem() == imageType:
			list := reflect.MakeSlice(fv.Type(), 0, 0)
			for range value.([]any) {
				list = reflect.Append(list, reflect.ValueOf(d.image()))
			}
			fv.Set(list)
		case fv.Kind() == reflect.Slice && strings.HasPrefix(f.Tag.Get("verisec"), "list"):
			// an image list: each entry gets its image, the SDK fills in the index and the id
			filled := map[string]bool{}
			for _, kv := range strings.Split(f.Tag.Get("verisec"), ",")[1:] {
				k, v, _ := strings.Cut(kv, "=")
				if k == "index" || k == "id" {
					filled[v] = true
				}
			}
			list := reflect.MakeSlice(fv.Type(), 0, 0)
			for _, raw := range value.([]any) {
				entry := reflect.New(fv.Type().Elem()).Elem()
				rest := map[string]any{}
				for k, v := range raw.(map[string]any) {
					if !filled[k] {
						rest[k] = v
					}
				}
				d.fill(entry, rest)
				list = reflect.Append(list, entry)
			}
			fv.Set(list)
		case fv.Kind() == reflect.Pointer && fv.Type().Elem().Kind() == reflect.Struct:
			p := reflect.New(fv.Type().Elem())
			d.fill(p.Elem(), value.(map[string]any))
			fv.Set(p)
		default:
			data, _ := json.Marshal(value)
			if err := json.Unmarshal(data, fv.Addr().Interface()); err != nil {
				d.t.Fatalf("%s.%s: %v", sv.Type(), f.Name, err)
			}
		}
	}
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// normalize drops the members a typed Go value cannot tell from left out (null, false, 0, "", empty objects
// and lists), recursively, so a re-encoded result compares with the spec example.
func normalize(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, e := range x {
			if n := normalize(e); !blank(n) {
				out[k] = n
			}
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = normalize(e)
		}
		return out
	}
	return v
}

func blank(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case bool:
		return !x
	case float64:
		return x == 0
	case string:
		return x == ""
	case map[string]any:
		return len(x) == 0
	case []any:
		return len(x) == 0
	}
	return false
}

// extraMembers lists, at any depth of a typed result, the members kept in Extra; mistyped are those whose name
// is a field (their JSON type is not the spec's).
func extraMembers(v reflect.Value, at string, kept, mistyped *[]string) {
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			extraMembers(v.Elem(), at, kept, mistyped)
		}
	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			extraMembers(v.Index(i), fmt.Sprintf("%s[%d]", at, i), kept, mistyped)
		}
	case reflect.Struct:
		if v.Type().PkgPath() != reflect.TypeOf(verisec.Client{}).PkgPath() {
			return
		}
		fields := wireFields(v.Type())
		for name, f := range fields {
			extraMembers(v.FieldByIndex(f.Index), at+"."+name, kept, mistyped)
		}
		if extra := v.FieldByName("Extra"); extra.IsValid() && extra.Kind() == reflect.Map {
			for _, k := range extra.MapKeys() {
				*kept = append(*kept, at+"."+k.String())
				if _, isField := fields[k.String()]; isField {
					*mistyped = append(*mistyped, at+"."+k.String())
				}
			}
		}
	}
}

/* --------------------------------------------------------- every operation -- */

func TestEveryOperation(t *testing.T) {
	needServer(t)
	s := loadSpec(t)
	pngPath := filepath.Join(t.TempDir(), "photo.png")
	if err := os.WriteFile(pngPath, pngBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	type op struct {
		id, method, path string
		def              map[string]any
	}
	var ops []op
	for path, item := range s.Paths {
		for method, def := range item {
			ops = append(ops, op{def["operationId"].(string), strings.ToUpper(method), path, def})
		}
	}
	sort.Slice(ops, func(i, j int) bool { return ops[i].id < ops[j].id })
	if len(ops) != 69 || len(verisec.Operations) != len(ops) {
		t.Fatalf("%d operations in the spec, %d methods", len(ops), len(verisec.Operations))
	}

	var allExtra []string
	for _, o := range ops {
		t.Run(o.id, func(t *testing.T) {
			reset(t)
			c := newClient(t, "sk_test_go_sdk")
			goPath, ok := verisec.Operations[o.id]
			if !ok {
				t.Fatalf("no method for %s", o.id)
			}
			method := methodOf(t, c, goPath)
			in := &developerInput{t: t, pngPath: pngPath}
			args := []reflect.Value{reflect.ValueOf(context.Background())}

			jsonBody, _ := dig(o.def, "requestBody", "content", "application/json").(map[string]any)
			form, _ := dig(o.def, "requestBody", "content", "multipart/form-data").(map[string]any)
			params, _ := o.def["parameters"].([]any)
			wantPath := o.path
			wantQuery := map[string]any{}
			switch {
			case jsonBody != nil || form != nil:
				body := jsonBody
				if body == nil {
					body = form
				}
				p := reflect.New(method.Type().In(1).Elem())
				in.fill(p.Elem(), body["example"].(map[string]any))
				args = append(args, p)
			default:
				var query []map[string]any
				for _, raw := range params {
					prm := raw.(map[string]any)
					switch prm["in"] {
					case "path":
						value := prm["example"].(string)
						args = append(args, reflect.ValueOf(value))
						wantPath = strings.Replace(wantPath, "{"+prm["name"].(string)+"}", value, 1)
					case "query":
						query = append(query, prm)
					}
				}
				if len(query) > 0 {
					example := map[string]any{}
					for _, prm := range query {
						if v, ok := prm["example"]; ok {
							example[prm["name"].(string)] = v
							wantQuery[prm["name"].(string)] = v
						}
					}
					p := reflect.New(method.Type().In(1).Elem())
					in.fill(p.Elem(), example)
					args = append(args, p)
				}
			}

			outs := method.Call(args)
			if err, _ := outs[1].Interface().(error); err != nil {
				t.Fatalf("%s: %v", goPath, err)
			}
			result := outs[0]

			// the answer: the envelope's data for KYC, the object for Financial, equal to the spec example
			example := dig(o.def, "responses", "200", "content", "application/json", "example")
			want := example
			if o.def["x-verisec-envelope"] == "data" {
				want = dig(example, "data")
			}
			info := result.Elem().FieldByName("LastResponse").Interface().(*verisec.ResponseInfo)
			if info == nil || info.Status != 200 || info.Header.Get("Content-Type") == "" {
				t.Fatalf("response info %+v", info)
			}
			if o.def["x-verisec-envelope"] == "data" && !strings.HasPrefix(info.RequestID, "req_") {
				t.Errorf("request id %q", info.RequestID)
			}
			if open := result.Elem().FieldByName("OpenResult"); open.IsValid() {
				if raw := open.FieldByName("Raw").Interface(); !reflect.DeepEqual(raw, want) {
					t.Errorf("open result differs from the spec example:\n got %v\nwant %v", raw, want)
				}
			} else {
				gotJSON, err := json.Marshal(result.Interface())
				if err != nil {
					t.Fatal(err)
				}
				var got any
				json.Unmarshal(gotJSON, &got)
				if !reflect.DeepEqual(normalize(got), normalize(want)) {
					t.Errorf("result differs from the spec example:\n got %s\nwant %s", mustJSON(normalize(got)), mustJSON(normalize(want)))
				}
				// and exactly what decoding the example directly gives, zero values included
				wantJSON, _ := json.Marshal(want)
				direct := reflect.New(result.Type().Elem())
				if err := json.Unmarshal(wantJSON, direct.Interface()); err != nil {
					t.Fatal(err)
				}
				gotValue := reflect.New(result.Type().Elem()).Elem()
				gotValue.Set(result.Elem())
				gotValue.FieldByName("LastResponse").Set(reflect.Zero(gotValue.FieldByName("LastResponse").Type()))
				if !reflect.DeepEqual(gotValue.Interface(), direct.Elem().Interface()) {
					t.Errorf("the result is not the example decoded:\n got %+v\nwant %+v", gotValue.Interface(), direct.Elem().Interface())
				}
				var kept, mistyped []string
				extraMembers(result, o.id, &kept, &mistyped)
				if len(mistyped) > 0 {
					t.Errorf("example members whose JSON type is not the spec's: %v", mistyped)
				}
				allExtra = append(allExtra, kept...)
			}

			// what the server received
			sent := logged(t)
			if len(sent) != 1 {
				t.Fatalf("%d requests logged", len(sent))
			}
			r := sent[0]
			if r["method"] != o.method || r["path"] != wantPath || !reflect.DeepEqual(r["query"], wantQuery) {
				t.Errorf("sent %v %v %v", r["method"], r["path"], r["query"])
			}
			headers := r["headers"].(map[string]any)
			if !strings.HasPrefix(headers["authorization"].(string), "Bearer sk_test_go") || headers["user-agent"] != "verisec-go/1.0.0" || headers["accept"] != "application/json" {
				t.Errorf("headers %v", headers)
			}
			if headers["idempotency-key"] != nil || headers["verisec-version"] != nil {
				t.Errorf("an old header was sent: %v", headers)
			}
			switch {
			case jsonBody != nil:
				// the images went as the example's base64, the index and ids as the example has them
				if !reflect.DeepEqual(r["body"], jsonBody["example"]) {
					t.Errorf("body sent\n %s\nwant\n %s", mustJSON(r["body"]), mustJSON(jsonBody["example"]))
				}
			case form != nil:
				if headers["x-verisec-source"] != "sdk" {
					t.Errorf("X-VeriSec-Source %v", headers["x-verisec-source"])
				}
				upload := r["upload"].(map[string]any)
				fields := map[string]any{}
				for k, v := range form["example"].(map[string]any) {
					if k != "image" {
						fields[k] = v
					}
				}
				if !reflect.DeepEqual(upload["fields"], fields) || dig(upload, "image", "bytes") != float64(len(pngBytes)) || dig(upload, "image", "type") != "image/png" {
					t.Errorf("upload %v", upload)
				}
			}
		})
	}
	sort.Strings(allExtra)
	t.Logf("example members without a field (kept in Extra): %v", allExtra)
}

func mustJSON(v any) string {
	data, _ := json.MarshalIndent(v, "", "  ")
	return string(data)
}

/* --------------------------------------------------------------- failures -- */

var mrz = &verisec.MrzParseParams{Lines: []string{"P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<", "L898902C36UTO7408122F1204159ZE184226B<<<<<10"}}

func TestTwoInjected503sAreRetried(t *testing.T) {
	needServer(t)
	reset(t)
	control(t, "fail", map[string]any{"path": "/v1/mrz/parse", "count": 2, "status": 503})
	r, err := newClient(t, "sk_test_go_sdk").Mrz.Parse(context.Background(), mrz)
	if err != nil || r.Format == "" {
		t.Fatalf("got %+v, %v", r, err)
	}
	if n := len(logged(t)); n != 3 {
		t.Errorf("%d requests logged, want 3", n)
	}
}

func TestA429WithRetryAfterIsRetried(t *testing.T) {
	needServer(t)
	reset(t)
	control(t, "fail", map[string]any{"path": "/v2/cards/check", "count": 1, "status": 429, "retry_after": 0})
	r, err := newClient(t, "sk_test_go_sdk").Cards.Check(context.Background(), &verisec.CardCheckParams{Number: "4242 4242 4242 4242"})
	if err != nil || r.Object != "card_check" {
		t.Fatalf("got %+v, %v", r, err)
	}
	if n := len(logged(t)); n != 2 {
		t.Errorf("%d requests logged, want 2", n)
	}
}

func TestAConnectionResetAfterTheRequestIsNotSentAgain(t *testing.T) {
	needServer(t)
	reset(t)
	control(t, "fail", map[string]any{"path": "/v1/face/detect", "count": 1, "mode": "reset"})
	c := newClient(t, "sk_test_go_sdk", verisec.WithMaxRetries(3))
	_, err := c.Face.Detect(context.Background(), &verisec.FaceDetectParams{Image: verisec.ImageFromBytes(pngBytes)})
	var e *verisec.ConnectionError
	if !errors.As(err, &e) || e.Timeout {
		t.Fatalf("got %v", err)
	}
	if n := len(logged(t)); n != 1 {
		t.Errorf("%d requests logged, want 1", n)
	}

	// a GET on a reused connection too
	reset(t)
	if _, err := c.Bin.Lookup(context.Background(), "424242"); err != nil {
		t.Fatal(err)
	}
	control(t, "fail", map[string]any{"path": "/v2/bin/424242", "count": 1, "mode": "reset"})
	if _, err := c.Bin.Lookup(context.Background(), "424242"); !errors.As(err, &e) {
		t.Fatalf("got %v", err)
	}
	if n := len(logged(t)); n != 2 {
		t.Errorf("%d requests logged, want 2", n)
	}
}

func TestATimeoutIsNotSentAgain(t *testing.T) {
	needServer(t)
	reset(t)
	control(t, "fail", map[string]any{"path": "/v1/face/detect", "count": 1, "mode": "hang"})
	c := newClient(t, "sk_test_go_sdk", verisec.WithMaxRetries(3))
	_, err := c.Face.Detect(context.Background(), &verisec.FaceDetectParams{Image: verisec.ImageFromBytes(pngBytes)}, verisec.WithRequestTimeout(500*time.Millisecond))
	var e *verisec.ConnectionError
	if !errors.As(err, &e) || !e.Timeout || !strings.Contains(err.Error(), "may still have run") {
		t.Fatalf("got %v", err)
	}
	if n := len(logged(t)); n != 1 {
		t.Errorf("%d requests logged, want 1", n)
	}
}

func TestKeysWithoutCreditsRevokedOrForbidden(t *testing.T) {
	needServer(t)
	reset(t)
	ctx := context.Background()
	var e *verisec.APIError
	_, err := newClient(t, "sk_test_nocredits").Bin.Lookup(ctx, "424242")
	if !verisec.IsInsufficientCredits(err) || !errors.As(err, &e) || e.Code != "insufficient_credits" || !strings.HasPrefix(e.RequestID, "req_") {
		t.Errorf("no credits: %v", err)
	}
	_, err = newClient(t, "sk_test_revoked").Bin.Lookup(ctx, "424242")
	if !verisec.IsAuthentication(err) || !errors.As(err, &e) || e.Code != "key_revoked" {
		t.Errorf("revoked: %v", err)
	}
	_, err = newClient(t, "sk_test_forbidden").Mrz.Parse(ctx, mrz)
	if !verisec.IsPermission(err) {
		t.Errorf("forbidden: %v", err)
	}
	_, err = newClient(t, "not_a_key").Mrz.Parse(ctx, mrz)
	if !verisec.IsAuthentication(err) || !errors.As(err, &e) || e.Code != "invalid_key" {
		t.Errorf("not a key: %v", err)
	}
	if n := len(logged(t)); n != 4 {
		t.Errorf("%d requests logged: refused calls were sent again", n)
	}
}

func TestAFieldTheAPIDoesNotHaveIsRefusedWithItsName(t *testing.T) {
	needServer(t)
	reset(t)
	_, err := newClient(t, "sk_test_go_sdk").Mrz.Parse(context.Background(), mrz, verisec.WithExtraField("extra", true))
	var e *verisec.APIError
	if !verisec.IsInvalidRequest(err) || !errors.As(err, &e) || e.Status != 400 || e.Code != "parameter_unknown" || e.Param != "extra" {
		t.Fatalf("got %v", err)
	}
	// and a field the API does have, sent through the same option, is accepted
	if _, err := newClient(t, "sk_test_go_sdk").Face.Detect(context.Background(), &verisec.FaceDetectParams{Image: verisec.ImageFromBytes(pngBytes)}, verisec.WithExtraField("tag", "via-option")); err != nil {
		t.Fatal(err)
	}
	if body := logged(t)[1]["body"].(map[string]any); body["tag"] != "via-option" {
		t.Errorf("body %v", body)
	}
}

func TestAMissingRequiredFieldIsReportedByTheAPI(t *testing.T) {
	needServer(t)
	reset(t)
	_, err := newClient(t, "sk_test_go_sdk").Face.Verify(context.Background(), &verisec.FaceVerifyParams{Image1: verisec.ImageFromBytes(pngBytes)})
	var e *verisec.APIError
	if !errors.As(err, &e) || e.Code != "parameter_missing" || e.Param != "image2" {
		t.Fatalf("got %v", err)
	}
}

/* -------------------------------------------------------------- live keys -- */

func TestALiveKeyWorksThroughOneTokenExchange(t *testing.T) {
	needServer(t)
	control(t, "reset", map[string]any{"token_ttl": 61}) // kept for 1 s: renewed a minute before it expires
	defer control(t, "reset", map[string]any{"token_ttl": 3600})
	c := newClient(t, "ak_live_go", verisec.WithClientCredentials("cli_go", "cs_go"))
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		r, err := c.Bin.Lookup(ctx, "424242")
		if err != nil || r.Network != "Visa" {
			t.Fatalf("call %d: %+v, %v", i, r, err)
		}
	}
	sent := logged(t)
	exchanges := 0
	for _, r := range sent {
		if r["path"] == "/v2/oauth/token" {
			exchanges++
			if dig(r, "body", "grant_type") != "client_credentials" || dig(r, "body", "api_key") != "ak_live_go" || dig(r, "body", "client_id") != "cli_go" || dig(r, "headers", "authorization") != nil {
				t.Errorf("token request %v", r)
			}
		}
	}
	if exchanges != 1 || len(sent) != 3 {
		t.Errorf("%d exchanges in %d requests, want 1 in 3", exchanges, len(sent))
	}
	if auth := dig(sent[len(sent)-1], "headers", "authorization").(string); !strings.HasPrefix(auth, "Bearer at_live_") {
		t.Errorf("bearer %q", auth)
	}

	// once the token is within a minute of expiring, a new one
	time.Sleep(1100 * time.Millisecond)
	if _, err := c.Bin.Lookup(ctx, "424242"); err != nil {
		t.Fatal(err)
	}
	if n := countPath(logged(t), "/v2/oauth/token"); n != 2 {
		t.Errorf("%d exchanges after the token expired, want 2", n)
	}

	// a token the server no longer knows: a 401, one new exchange, the call sent again
	control(t, "reset", map[string]any{"token_ttl": 3600})
	c = newClient(t, "ak_live_go", verisec.WithClientCredentials("cli_go", "cs_go"))
	if _, err := c.Bin.Lookup(ctx, "424242"); err != nil {
		t.Fatal(err)
	}
	reset(t) // forgets every token
	if _, err := c.Bin.Lookup(ctx, "424242"); err != nil {
		t.Fatalf("after the server forgot the token: %v", err)
	}
	if sent := logged(t); len(sent) != 3 || countPath(sent, "/v2/oauth/token") != 1 {
		t.Errorf("after a 401: %d requests, %d exchanges", len(sent), countPath(sent, "/v2/oauth/token"))
	}
}

func countPath(sent []map[string]any, path string) int {
	n := 0
	for _, r := range sent {
		if r["path"] == path {
			n++
		}
	}
	return n
}

func TestAWrongClientSecretIsAnAuthenticationError(t *testing.T) {
	needServer(t)
	reset(t)
	c := newClient(t, "ak_live_go", verisec.WithClientCredentials("cli_go", "cs_wrong"))
	_, err := c.Bin.Lookup(context.Background(), "424242")
	var e *verisec.APIError
	if !verisec.IsAuthentication(err) || !errors.As(err, &e) || e.Code != "invalid_client" {
		t.Fatalf("got %v", err)
	}
	if sent := logged(t); len(sent) != 1 || sent[0]["path"] != "/v2/oauth/token" {
		t.Errorf("sent %v", sent)
	}
}

/* --------------------------------------------------------------- webhooks -- */

func TestADeliverySignedByTheServerVerifies(t *testing.T) {
	needServer(t)
	d := control(t, "webhook", map[string]any{})
	headers := http.Header{}
	for k, v := range d["headers"].(map[string]any) {
		headers[k] = []string{v.(string)} // as the server names them: lower case
	}
	body := []byte(d["body"].(string))
	secret := d["secret"].(string)
	event, err := verisec.ConstructEvent(body, headers, secret)
	if err != nil {
		t.Fatal(err)
	}
	if event.Type != "verification.completed" || event.Environment != "test" || event.Data["decision"] != "approved" {
		t.Errorf("event %+v", event)
	}
	if err := verisec.VerifySignature(append(body, ' '), headers, secret); err == nil {
		t.Error("a changed body verified")
	}

	secret = "whsec_" + base64.StdEncoding.EncodeToString([]byte("a secret of the go suite"))
	d = control(t, "webhook", map[string]any{"secret": secret, "event": map[string]any{"type": "credits.low", "timestamp": "2026-10-17T12:00:00Z", "environment": "live", "data": map[string]any{"balance": 4.5}}})
	headers = http.Header{}
	for k, v := range d["headers"].(map[string]any) {
		headers.Set(k, v.(string))
	}
	event, err = verisec.ConstructEvent([]byte(d["body"].(string)), headers, secret)
	if err != nil || event.Type != "credits.low" || event.Data["balance"] != 4.5 {
		t.Errorf("custom event %+v, %v", event, err)
	}
}
