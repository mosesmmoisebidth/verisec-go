package verisec

// Core behaviour against local stub servers: headers, answers, errors, the retry rules that keep a charged call
// from running twice, OAuth, images, uploads and webhooks. No network, no shared test server.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const png64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="

var pngBytes, _ = base64.StdEncoding.DecodeString(png64)

// writePNG puts the test image in a temporary file.
func writePNG(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, pngBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

/* ----------------------------------------------------------- stub server -- */

// received is one request a stub got.
type received struct {
	Method string
	URL    string // path and query, as sent
	Header http.Header
	Body   []byte
}

// reply is what a stub answers; drop closes the connection without an answer, hang never answers.
type reply struct {
	status int
	body   any // a string is sent as it is
	header map[string]string
	drop   bool
	hang   bool
}

type stub struct {
	srv  *httptest.Server
	mu   sync.Mutex
	reqs []received
	done chan struct{}
}

// newStub starts a stub API: handle answers request number n (from 0).
func newStub(t *testing.T, handle func(r received, n int) reply) *stub {
	t.Helper()
	s := &stub{done: make(chan struct{})}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		rec := received{Method: r.Method, URL: r.URL.RequestURI(), Header: r.Header.Clone(), Body: body}
		s.mu.Lock()
		n := len(s.reqs)
		s.reqs = append(s.reqs, rec)
		s.mu.Unlock()
		out := handle(rec, n)
		switch {
		case out.drop:
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				conn.Close()
			}
			return
		case out.hang:
			select {
			case <-s.done:
			case <-r.Context().Done():
			}
			return
		}
		for k, v := range out.header {
			w.Header().Set(k, v)
		}
		if w.Header().Get("Content-Type") == "" {
			w.Header().Set("Content-Type", "application/json")
		}
		status := out.status
		if status == 0 {
			status = 200
		}
		w.WriteHeader(status)
		switch b := out.body.(type) {
		case nil:
		case string:
			io.WriteString(w, b)
		default:
			json.NewEncoder(w).Encode(b)
		}
	}))
	t.Cleanup(func() {
		close(s.done)
		s.srv.Close()
	})
	return s
}

func (s *stub) requests() []received {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]received(nil), s.reqs...)
}

// waits records the delays the retries asked for, without waiting.
type waits struct {
	mu sync.Mutex
	d  []time.Duration
}

func (w *waits) all() []time.Duration {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]time.Duration(nil), w.d...)
}

func instant(c *Client) *waits {
	w := &waits{}
	c.t.sleep = func(ctx context.Context, d time.Duration) error {
		w.mu.Lock()
		w.d = append(w.d, d)
		w.mu.Unlock()
		return ctx.Err()
	}
	return w
}

// client returns a test-key client of the stub whose retries do not wait.
func (s *stub) client(t *testing.T, opts ...ClientOption) (*Client, *waits) {
	t.Helper()
	c, err := New("sk_test_core", append([]ClientOption{WithBaseURL(s.srv.URL)}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return c, instant(c)
}

func kyc(data any, extra map[string]any) map[string]any {
	out := map[string]any{"ok": true, "request_id": "req_abc", "latency_ms": 12, "data": data, "warnings": []string{}, "error": nil}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

func errBody(code, message, param string) map[string]any {
	e := map[string]any{"code": code, "message": message}
	if param != "" {
		e["param"] = param
	}
	return map[string]any{"ok": false, "request_id": "req_err", "error": e, "warnings": []string{}, "data": nil}
}

func decode(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("not JSON: %v: %s", err, data)
	}
	return out
}

var mrzLines = &MrzParseParams{Lines: []string{"P<UTO", "L898902C3"}}

/* --------------------------------------------------------------- requests -- */

func TestSendsTheKeyUserAgentAndTheBodyExactlyAsGiven(t *testing.T) {
	s := newStub(t, func(received, int) reply { return reply{body: kyc(map[string]any{"x": 1}, nil)} })
	c, _ := s.client(t)
	if _, err := c.Mrz.Parse(context.Background(), mrzLines); err != nil {
		t.Fatal(err)
	}
	r := s.requests()[0]
	for key, want := range map[string]string{
		"Authorization": "Bearer sk_test_core",
		"User-Agent":    "verisec-go/1.0.0",
		"Accept":        "application/json",
		"Content-Type":  "application/json",
	} {
		if got := r.Header.Get(key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	for _, key := range []string{"Idempotency-Key", "Verisec-Version", "X-Verisec-Source"} {
		if v := r.Header.Get(key); v != "" {
			t.Errorf("sent %s: %q", key, v)
		}
	}
	if r.Method != "POST" || r.URL != "/v1/mrz/parse" {
		t.Errorf("sent %s %s", r.Method, r.URL)
	}
	if string(r.Body) != `{"lines":["P<UTO","L898902C3"]}` {
		t.Errorf("body %s", r.Body)
	}
}

func TestNilParamsSendAnEmptyObject(t *testing.T) {
	s := newStub(t, func(received, int) reply { return reply{body: kyc(map[string]any{}, nil)} })
	c, _ := s.client(t)
	if _, err := c.Contact.Dossier(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if body := string(s.requests()[0].Body); body != "{}" {
		t.Errorf("body %s", body)
	}
}

func TestEmptySlicesAreSentNilOnesAreNot(t *testing.T) {
	s := newStub(t, func(received, int) reply { return reply{body: kyc(map[string]any{}, nil)} })
	c, _ := s.client(t)
	ctx := context.Background()
	if _, err := c.Screening.Crypto(ctx, &ScreeningCryptoParams{Addresses: []string{}}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Contact.Dossier(ctx, &ContactDossierParams{Email: String(""), Include: nil}); err != nil {
		t.Fatal(err)
	}
	reqs := s.requests()
	if got := string(reqs[0].Body); got != `{"addresses":[]}` {
		t.Errorf("empty slice: %s", got)
	}
	if got := string(reqs[1].Body); got != `{"email":""}` {
		t.Errorf("nil slice and empty string pointer: %s", got)
	}
}

func TestNewNeedsAnAPIKeyAndReadsTheEnvironment(t *testing.T) {
	t.Setenv("VERISEC_API_KEY", "")
	t.Setenv("VERISEC_BASE_URL", "")
	if _, err := New(""); !errors.Is(err, ErrNoAPIKey) {
		t.Fatalf("no key: %v", err)
	}
	if _, err := New("sk_test_x", WithBaseURL("not a url")); err == nil {
		t.Fatal("a relative base URL was accepted")
	}

	s := newStub(t, func(received, int) reply { return reply{body: map[string]any{"object": "card_fingerprint"}} })
	t.Setenv("VERISEC_API_KEY", "sk_test_from_env")
	t.Setenv("VERISEC_BASE_URL", s.srv.URL+"/")
	c, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	if c.t.baseURL != s.srv.URL || c.t.timeout != 300*time.Second || c.t.maxRetries != 2 {
		t.Errorf("defaults: %s %s %d", c.t.baseURL, c.t.timeout, c.t.maxRetries)
	}
	if _, err := c.Cards.Fingerprint(context.Background(), &CardFingerprintParams{Number: "4242424242424242"}); err != nil {
		t.Fatal(err)
	}
	if got := s.requests()[0].Header.Get("Authorization"); got != "Bearer sk_test_from_env" {
		t.Errorf("Authorization %q", got)
	}

	t.Setenv("VERISEC_BASE_URL", "")
	c, _ = New("sk_test_x")
	if c.t.baseURL != DefaultBaseURL || DefaultBaseURL != "https://verisec.mmose.me" {
		t.Errorf("base URL %s", c.t.baseURL)
	}
}

func TestLiveKeysNeedClientCredentials(t *testing.T) {
	t.Setenv("VERISEC_CLIENT_ID", "")
	t.Setenv("VERISEC_CLIENT_SECRET", "")
	if _, err := New("ak_live_x", WithBaseURL("http://127.0.0.1:1")); !errors.Is(err, ErrNoClientCredentials) {
		t.Fatalf("got %v", err)
	}
	if _, err := New("ak_live_x", WithClientCredentials("cli_1", "")); !errors.Is(err, ErrNoClientCredentials) {
		t.Fatalf("without a secret: %v", err)
	}
	t.Setenv("VERISEC_CLIENT_ID", "cli_env")
	t.Setenv("VERISEC_CLIENT_SECRET", "cs_env")
	if _, err := New("ak_live_x"); err != nil {
		t.Fatalf("credentials from the environment: %v", err)
	}
}

/* ---------------------------------------------------------------- answers -- */

func TestKYCAnswersReturnTheDataWithResponseInfo(t *testing.T) {
	s := newStub(t, func(received, int) reply {
		return reply{body: kyc(map[string]any{"match": true, "similarity": 0.98, "brand_new": "kept"}, map[string]any{"warnings": []any{"low light", map[string]any{"code": "w2"}}}), header: map[string]string{"X-Request-Id": "req_header"}}
	})
	c, _ := s.client(t)
	path := writePNG(t, "face.png")
	r, err := c.Face.Verify(context.Background(), &FaceVerifyParams{Image1: ImageFromPath(path), Image2: ImageFromBytes(pngBytes)})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Match || r.Similarity != 0.98 || r.Extra["brand_new"] != "kept" {
		t.Errorf("result %+v", r)
	}
	info := r.LastResponse
	if info == nil || info.Status != 200 || info.RequestID != "req_abc" || info.LatencyMs != 12 || info.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("response info %+v", info)
	}
	if !reflect.DeepEqual(info.Warnings, []string{"low light", `{"code":"w2"}`}) {
		t.Errorf("warnings %q", info.Warnings)
	}
	body := decode(t, s.requests()[0].Body)
	if body["image1"] != png64 || body["image2"] != png64 || len(body) != 2 {
		t.Errorf("images sent as %v", body)
	}
}

func TestFinancialAnswersAreTheObjectAsItIs(t *testing.T) {
	s := newStub(t, func(received, int) reply {
		return reply{body: map[string]any{"object": "card_check", "luhn_valid": true, "first6": "424242"}, header: map[string]string{"X-Request-Id": "req_fin"}}
	})
	c, _ := s.client(t)
	r, err := c.Cards.Check(context.Background(), &CardCheckParams{Number: "4242 4242 4242 4242"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Object != "card_check" || !r.LuhnValid || r.First6 != "424242" {
		t.Errorf("result %+v", r)
	}
	if r.LastResponse.RequestID != "req_fin" || r.LastResponse.Status != 200 || len(r.LastResponse.Warnings) != 0 {
		t.Errorf("response info %+v", r.LastResponse)
	}
	got, _ := json.Marshal(r)
	if string(got) != `{"object":"card_check","first6":"424242","luhn_valid":true}` {
		t.Errorf("re-encoded as %s", got)
	}
}

func TestOpenResultsKeepTheWholeAnswer(t *testing.T) {
	data := map[string]any{"results": []any{map[string]any{"similarity": 0.99, "first": 3.0}}, "code": 0.0, "new_member": map[string]any{"a": "b"}}
	s := newStub(t, func(received, int) reply { return reply{body: kyc(data, nil)} })
	c, _ := s.client(t)
	r, err := c.Face.Match(context.Background(), &FaceMatchParams{Images: []FaceMatchParamsImage{{Data: ImageFromBytes(pngBytes)}, {Data: ImageFromBytes(pngBytes)}}})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r.Raw, data) || r.Get("code") != 0.0 || r.LastResponse.RequestID != "req_abc" {
		t.Errorf("open result %v %+v", r.Raw, r.LastResponse)
	}
	var mine struct {
		Results []struct {
			Similarity float64 `json:"similarity"`
		} `json:"results"`
	}
	if err := r.Decode(&mine); err != nil || len(mine.Results) != 1 || mine.Results[0].Similarity != 0.99 {
		t.Errorf("Decode: %v %+v", err, mine)
	}
	again, _ := json.Marshal(r)
	var back map[string]any
	json.Unmarshal(again, &back)
	if !reflect.DeepEqual(back, data) {
		t.Errorf("re-encoded as %s", again)
	}
}

func TestAnswersKeepUnknownAndMistypedMembersInExtra(t *testing.T) {
	var v FaceVerify
	err := json.Unmarshal([]byte(`{"match":true,"similarity":"high","compared":[{"image":"a","roi":[1,2],"zoom":2}],"metadata":{"serverTime":"t","ctx":{"userIp":"203.0.113.7","asn":7}},"later":[1]}`), &v)
	if err != nil {
		t.Fatal(err)
	}
	if !v.Match || v.Similarity != 0 || v.Extra["similarity"] != "high" || !reflect.DeepEqual(v.Extra["later"], []any{1.0}) {
		t.Errorf("top level %+v", v)
	}
	if len(v.Compared) != 1 || v.Compared[0].Extra["zoom"] != 2.0 || v.Metadata.Ctx.UserIP != "203.0.113.7" || v.Metadata.Ctx.Extra["asn"] != 7.0 {
		t.Errorf("nested %+v", v)
	}
	out, _ := json.Marshal(v)
	var back map[string]any
	json.Unmarshal(out, &back)
	if back["similarity"] != "high" || back["match"] != true || back["later"] == nil || back["compared"].([]any)[0].(map[string]any)["zoom"] != 2.0 {
		t.Errorf("re-encoded as %s", out)
	}
}

/* ----------------------------------------------------------------- errors -- */

func TestEveryErrorStatusMapsToItsFamily(t *testing.T) {
	type check func(error) bool
	all := map[string]check{
		"invalid": IsInvalidRequest, "auth": IsAuthentication, "credits": IsInsufficientCredits,
		"permission": IsPermission, "notfound": IsNotFound, "ratelimit": IsRateLimited, "server": IsServerError,
	}
	cases := []struct {
		status    int
		body      any
		family    string
		code      string
		param     string
		message   string
		requestID string
	}{
		{400, errBody("invalid_input", "image1 is required.", "image1"), "invalid", "invalid_input", "image1", "image1 is required.", "req_err"},
		{401, errBody("missing_key", "Send your API key.", ""), "auth", "missing_key", "", "Send your API key.", "req_err"},
		{402, errBody("insufficient_credits", "Not enough credits.", ""), "credits", "insufficient_credits", "", "Not enough credits.", "req_err"},
		{403, errBody("forbidden", "Not allowed.", ""), "permission", "forbidden", "", "Not allowed.", "req_err"},
		{404, map[string]any{"error_msg": "404 Route Not Found"}, "notfound", "", "", "404 Route Not Found", "req_hdr"},
		{413, map[string]any{"error": map[string]any{"code": "image_too_large", "message": "Too large."}}, "invalid", "image_too_large", "", "Too large.", "req_hdr"},
		{415, errBody("unsupported_image", "Not an image.", "image"), "invalid", "unsupported_image", "image", "Not an image.", "req_err"},
		{422, map[string]any{"detail": []any{map[string]any{"loc": []any{"body", "doc_hint", "type"}, "msg": "field required"}}}, "invalid", "invalid_input", "doc_hint.type", "field required", "req_hdr"},
		{422, map[string]any{"detail": "Bad lines."}, "invalid", "invalid_input", "", "Bad lines.", "req_hdr"},
		{429, errBody("rate_limited", "Slow down.", ""), "ratelimit", "rate_limited", "", "Slow down.", "req_err"},
		{500, "upstream exploded", "server", "", "", "upstream exploded", "req_hdr"},
		{502, errBody("engine_error", "The check could not run.", ""), "server", "engine_error", "", "The check could not run.", "req_err"},
		{503, nil, "server", "", "", "VeriSec API request failed with status 503", "req_hdr"},
		{409, map[string]any{"error": "conflict", "code": "busy"}, "invalid", "busy", "", "conflict", "req_hdr"},
	}
	for _, tc := range cases {
		s := newStub(t, func(received, int) reply {
			return reply{status: tc.status, body: tc.body, header: map[string]string{"X-Request-Id": "req_hdr"}}
		})
		c, _ := s.client(t, WithMaxRetries(0))
		_, err := c.Mrz.Parse(context.Background(), mrzLines)
		var e *APIError
		if !errors.As(err, &e) {
			t.Fatalf("%d: %v is not an *APIError", tc.status, err)
		}
		if e.Status != tc.status || e.Code != tc.code || e.Param != tc.param || e.Message != tc.message || e.RequestID != tc.requestID {
			t.Errorf("%d: got status %d code %q param %q message %q request %q", tc.status, e.Status, e.Code, e.Param, e.Message, e.RequestID)
		}
		for name, is := range all {
			if is(err) != (name == tc.family) {
				t.Errorf("%d: Is %s = %v", tc.status, name, is(err))
			}
		}
		if !strings.Contains(err.Error(), tc.message) {
			t.Errorf("%d: Error() = %q", tc.status, err.Error())
		}
	}
	if IsInsufficientCredits(nil) || IsServerError(errors.New("x")) {
		t.Error("a non-API error matched a family")
	}
}

func TestA2xxWithOKFalseIsAnError(t *testing.T) {
	s := newStub(t, func(received, int) reply {
		return reply{body: map[string]any{"ok": false, "request_id": "req_nf", "error": map[string]any{"code": "no_face", "message": "No face found."}, "data": nil}}
	})
	c, _ := s.client(t)
	r, err := c.Face.Detect(context.Background(), &FaceDetectParams{Image: ImageFromBytes(pngBytes)})
	var e *APIError
	if r != nil || !errors.As(err, &e) || e.Code != "no_face" || e.Status != 200 || e.RequestID != "req_nf" {
		t.Fatalf("got %v, %v", r, err)
	}
	if len(s.requests()) != 1 {
		t.Errorf("%d requests", len(s.requests()))
	}
}

func TestRateLimitErrorHasRetryAfter(t *testing.T) {
	s := newStub(t, func(received, int) reply {
		return reply{status: 429, body: errBody("rate_limited", "Slow down.", ""), header: map[string]string{"Retry-After": "7"}}
	})
	c, _ := s.client(t, WithMaxRetries(0))
	_, err := c.Mrz.Parse(context.Background(), mrzLines)
	var e *APIError
	if !IsRateLimited(err) || !errors.As(err, &e) || e.RetryAfter != 7*time.Second {
		t.Fatalf("got %v", err)
	}
	if d, ok := parseRetryAfter("Wed, 21 Oct 2015 07:28:10 GMT", time.Date(2015, 10, 21, 7, 28, 0, 0, time.UTC)); !ok || d != 10*time.Second {
		t.Errorf("an HTTP date: %v %v", d, ok)
	}
	if d := retryDelay(0, "600"); d != time.Minute {
		t.Errorf("Retry-After is capped at a minute: %v", d)
	}
}

/* ---------------------------------------------------------------- retries -- */

func Test429IsRetriedAfterRetryAfter(t *testing.T) {
	s := newStub(t, func(_ received, n int) reply {
		if n == 0 {
			return reply{status: 429, body: errBody("rate_limited", "Slow down.", ""), header: map[string]string{"Retry-After": "2"}}
		}
		return reply{body: kyc(map[string]any{"valid": true}, nil)}
	})
	c, waited := s.client(t)
	r, err := c.Mrz.Parse(context.Background(), mrzLines)
	if err != nil || !r.Valid {
		t.Fatalf("got %v, %v", r, err)
	}
	if n := len(s.requests()); n != 2 {
		t.Errorf("%d requests", n)
	}
	if got := waited.all(); !reflect.DeepEqual(got, []time.Duration{2 * time.Second}) {
		t.Errorf("waited %v", got)
	}
	if !bytes.Equal(s.requests()[0].Body, s.requests()[1].Body) {
		t.Error("the retry sent another body")
	}
}

func Test5xxIsRetriedUpToTheLimit(t *testing.T) {
	s := newStub(t, func(received, int) reply { return reply{status: 503, body: errBody("unavailable", "Try later.", "")} })
	c, waited := s.client(t)
	_, err := c.Mrz.Parse(context.Background(), mrzLines)
	if !IsServerError(err) {
		t.Fatalf("got %v", err)
	}
	if n := len(s.requests()); n != 3 {
		t.Errorf("%d requests with the default 2 retries", n)
	}
	got := waited.all() // 0.5 s then 1 s, each ±25%
	if len(got) != 2 || got[0] < 375*time.Millisecond || got[0] > 625*time.Millisecond || got[1] < 750*time.Millisecond || got[1] > 1250*time.Millisecond {
		t.Errorf("backoff %v", got)
	}

	c, _ = s.client(t, WithMaxRetries(4))
	c.Mrz.Parse(context.Background(), mrzLines)
	if n := len(s.requests()); n != 3+5 {
		t.Errorf("WithMaxRetries(4): %d requests in all", n)
	}
	c.Mrz.Parse(context.Background(), mrzLines, WithRequestMaxRetries(0))
	if n := len(s.requests()); n != 3+5+1 {
		t.Errorf("WithRequestMaxRetries(0): %d requests in all", n)
	}
}

func TestBackoffGrowsAndCaps(t *testing.T) {
	for attempt, want := range []float64{0.5, 1, 2, 4, 8, 8} {
		d := retryDelay(attempt, "")
		lo, hi := time.Duration(want*0.75*float64(time.Second)), time.Duration(want*1.25*float64(time.Second))
		if d < lo || d > hi {
			t.Errorf("attempt %d: %v not in [%v, %v]", attempt, d, lo, hi)
		}
	}
}

func Test4xxIsNeverRetried(t *testing.T) {
	for _, status := range []int{400, 401, 402, 403, 404, 409, 413, 422} {
		s := newStub(t, func(received, int) reply { return reply{status: status, body: errBody("x", "No.", "")} })
		c, _ := s.client(t)
		c.Mrz.Parse(context.Background(), mrzLines)
		if n := len(s.requests()); n != 1 {
			t.Errorf("%d: %d requests", status, n)
		}
	}
}

func TestAConnectionThatNeverOpenedIsRetried(t *testing.T) {
	s := newStub(t, func(received, int) reply { return reply{} })
	base := s.srv.URL
	s.srv.Close() // nothing listens there any more
	c, err := New("sk_test_core", WithBaseURL(base))
	if err != nil {
		t.Fatal(err)
	}
	waited := instant(c)
	_, err = c.Mrz.Parse(context.Background(), mrzLines)
	var e *ConnectionError
	if !errors.As(err, &e) || e.Timeout || !strings.Contains(e.Message, "Nothing was sent") {
		t.Fatalf("got %v", err)
	}
	if got := waited.all(); len(got) != 2 {
		t.Errorf("waited %v: want 2 retries", got)
	}
}

func TestAConnectionDroppedAfterSendingIsNotRetried(t *testing.T) {
	s := newStub(t, func(received, int) reply { return reply{drop: true} })
	c, waited := s.client(t, WithMaxRetries(3))
	_, err := c.Face.Detect(context.Background(), &FaceDetectParams{Image: ImageFromBytes(pngBytes)})
	var e *ConnectionError
	if !errors.As(err, &e) || e.Timeout || !strings.Contains(e.Message, "may still have run") {
		t.Fatalf("got %v", err)
	}
	if n := len(s.requests()); n != 1 {
		t.Errorf("%d requests: the call was sent again", n)
	}
	if len(waited.all()) != 0 {
		t.Error("waited for a retry")
	}
}

func TestAGETDroppedOnAReusedConnectionIsNotSentAgain(t *testing.T) {
	// net/http itself re-sends a replayable GET when a kept-alive connection drops after the request went out;
	// the client marks every request as not replayable, because every call is charged.
	s := newStub(t, func(_ received, n int) reply {
		if n == 0 {
			return reply{body: map[string]any{"bin": "424242"}}
		}
		return reply{drop: true}
	})
	c, _ := s.client(t, WithMaxRetries(3))
	ctx := context.Background()
	if _, err := c.Bin.Lookup(ctx, "424242"); err != nil {
		t.Fatal(err)
	}
	_, err := c.Bin.Lookup(ctx, "424242")
	var e *ConnectionError
	if !errors.As(err, &e) || e.Timeout {
		t.Fatalf("got %v", err)
	}
	if n := len(s.requests()); n != 2 {
		t.Errorf("%d requests: the dropped GET was sent again", n)
	}
	r := s.requests()[0]
	if len(r.Body) != 0 || r.Header.Get("Content-Length") != "" || r.Header.Get("Transfer-Encoding") != "" || r.Header.Get("Content-Type") != "" {
		t.Errorf("a GET carried a body: %q %v", r.Body, r.Header)
	}
}

func TestATimeoutIsNotRetried(t *testing.T) {
	s := newStub(t, func(received, int) reply { return reply{hang: true} })
	c, waited := s.client(t, WithTimeout(200*time.Millisecond), WithMaxRetries(3))
	start := time.Now()
	_, err := c.Face.Detect(context.Background(), &FaceDetectParams{Image: ImageFromBytes(pngBytes)})
	var e *ConnectionError
	if !errors.As(err, &e) || !e.Timeout || !strings.Contains(e.Message, "may still have run") {
		t.Fatalf("got %v", err)
	}
	if n := len(s.requests()); n != 1 || len(waited.all()) != 0 {
		t.Errorf("%d requests, waits %v: the call was sent again", n, waited.all())
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("took %v", d)
	}

	// a per-request timeout overrides the client's
	c, _ = s.client(t)
	_, err = c.Face.Detect(context.Background(), &FaceDetectParams{Image: ImageFromBytes(pngBytes)}, WithRequestTimeout(100*time.Millisecond))
	if !errors.As(err, &e) || !e.Timeout {
		t.Fatalf("per-request timeout: %v", err)
	}
}

func TestTheCallersContextEndsTheCall(t *testing.T) {
	s := newStub(t, func(received, int) reply { return reply{status: 503} })
	c, err := New("sk_test_core", WithBaseURL(s.srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Mrz.Parse(ctx, mrzLines); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := c.Mrz.Parse(ctx, mrzLines); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a deadline during the backoff: %v", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("took %v", d)
	}
}

/* ------------------------------------------------------------------ OAuth -- */

func TestLiveKeysAreExchangedOnceCachedAndRefreshedOnceOn401(t *testing.T) {
	var issued atomic.Int32
	s := newStub(t, func(r received, _ int) reply {
		if r.URL == "/v2/oauth/token" {
			time.Sleep(50 * time.Millisecond) // let the concurrent calls pile up on one exchange
			n := issued.Add(1)
			return reply{body: map[string]any{"access_token": "at_live_" + string(rune('0'+n)), "token_type": "Bearer", "expires_in": 3600, "scope": "api"}}
		}
		auth := r.Header.Get("Authorization")
		if strings.Contains(string(r.Body), "expire") && auth == "Bearer at_live_1" {
			return reply{status: 401, body: errBody("token_expired", "Expired.", "")}
		}
		if strings.Contains(string(r.Body), "always") {
			return reply{status: 401, body: errBody("invalid_token", "No.", "")}
		}
		return reply{body: kyc(map[string]any{"format": auth}, nil)}
	})
	c, err := New("ak_live_abc", WithClientCredentials("cli_1", "cs_1"), WithBaseURL(s.srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	var wg sync.WaitGroup
	results := make([]string, 8)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r, err := c.Mrz.Parse(ctx, mrzLines)
			if err != nil {
				t.Error(err)
				return
			}
			results[i] = r.Format
		}(i)
	}
	wg.Wait()
	for _, got := range results {
		if got != "Bearer at_live_1" {
			t.Errorf("a call used %q", got)
		}
	}
	if n := issued.Load(); n != 1 {
		t.Fatalf("%d exchanges for concurrent calls, want 1", n)
	}
	var tokenCall received
	for _, r := range s.requests() {
		if r.URL == "/v2/oauth/token" {
			tokenCall = r
		}
	}
	if string(tokenCall.Body) != `{"grant_type":"client_credentials","api_key":"ak_live_abc","client_id":"cli_1","client_secret":"cs_1"}` {
		t.Errorf("token request body %s", tokenCall.Body)
	}
	if tokenCall.Method != "POST" || tokenCall.Header.Get("Authorization") != "" || tokenCall.Header.Get("Content-Type") != "application/json" {
		t.Errorf("token request %s %v", tokenCall.Method, tokenCall.Header)
	}

	// a 401 on a token fetches a new one once and sends the call again
	r, err := c.Mrz.Parse(ctx, &MrzParseParams{Lines: []string{"expire"}})
	if err != nil || r.Format != "Bearer at_live_2" || issued.Load() != 2 {
		t.Fatalf("after a 401: %v, %v, %d exchanges", r, err, issued.Load())
	}
	// ... but only once
	before := len(s.requests())
	_, err = c.Mrz.Parse(ctx, &MrzParseParams{Lines: []string{"always"}})
	if !IsAuthentication(err) || len(s.requests())-before != 3 || issued.Load() != 3 {
		t.Errorf("a token refused twice: %v, %d requests, %d exchanges", err, len(s.requests())-before, issued.Load())
	}
}

func TestATokenIsRenewedAMinuteBeforeItExpires(t *testing.T) {
	var issued atomic.Int32
	s := newStub(t, func(r received, _ int) reply {
		if r.URL == "/v2/oauth/token" {
			issued.Add(1)
			return reply{body: map[string]any{"access_token": "at_live_x", "token_type": "Bearer", "expires_in": 120}}
		}
		return reply{body: map[string]any{"bin": "424242"}}
	})
	c, _ := New("ak_live_abc", WithClientCredentials("cli_1", "cs_1"), WithBaseURL(s.srv.URL))
	creds := c.t.creds.(*clientCredentials)
	now := time.Now()
	creds.now = func() time.Time { return now }
	ctx := context.Background()
	c.Bin.Lookup(ctx, "424242")
	now = now.Add(59 * time.Second)
	c.Bin.Lookup(ctx, "424242")
	if issued.Load() != 1 {
		t.Fatalf("%d exchanges within the token's life", issued.Load())
	}
	now = now.Add(2 * time.Second) // 61 s: within a minute of expiring
	c.Bin.Lookup(ctx, "424242")
	if issued.Load() != 2 {
		t.Errorf("%d exchanges after the renewal point", issued.Load())
	}
}

func TestATestKeyIsNotRefreshedOn401(t *testing.T) {
	s := newStub(t, func(received, int) reply { return reply{status: 401, body: errBody("key_revoked", "Revoked.", "")} })
	c, _ := s.client(t)
	if _, err := c.Mrz.Parse(context.Background(), mrzLines); !IsAuthentication(err) || len(s.requests()) != 1 {
		t.Fatalf("got %v after %d requests", err, len(s.requests()))
	}
}

func TestAFailedExchangeFailsTheCall(t *testing.T) {
	s := newStub(t, func(r received, _ int) reply {
		return reply{status: 401, body: errBody("invalid_client", "The client id or secret is not valid for this key.", "")}
	})
	c, _ := New("ak_live_abc", WithClientCredentials("cli_1", "cs_wrong"), WithBaseURL(s.srv.URL))
	_, err := c.Bin.Lookup(context.Background(), "424242")
	var e *APIError
	if !IsAuthentication(err) || !errors.As(err, &e) || e.Code != "invalid_client" || len(s.requests()) != 1 {
		t.Fatalf("got %v after %d requests", err, len(s.requests()))
	}
}

/* ----------------------------------------------------------------- images -- */

func TestImagesBecomePlainBase64(t *testing.T) {
	path := writePNG(t, "face.png")
	cases := map[string]Image{
		"path":           ImageFromPath(path),
		"bytes":          ImageFromBytes(pngBytes),
		"reader":         ImageFromReader(bytes.NewReader(pngBytes)),
		"data URI":       ImageFromBase64("data:image/png;base64," + png64),
		"base64":         ImageFromBase64(png64),
		"wrapped base64": ImageFromBase64(" " + png64[:40] + "\n" + png64[40:] + "\n"),
	}
	for name, img := range cases {
		got, err := imageBase64(img, "image")
		if err != nil || got != png64 {
			t.Errorf("%s: %q, %v", name, got, err)
		}
	}
	// a reader is read once and kept
	img := ImageFromReader(bytes.NewReader(pngBytes))
	first, _ := imageBase64(img, "image")
	second, err := imageBase64(img, "image")
	if first != png64 || second != png64 || err != nil {
		t.Errorf("a reader used twice: %v", err)
	}
}

func TestAnImageThatCannotBeReadNamesTheField(t *testing.T) {
	s := newStub(t, func(received, int) reply { return reply{body: kyc(map[string]any{}, nil)} })
	c, _ := s.client(t)
	ctx := context.Background()
	cases := []struct {
		params any
		field  string
	}{
		{&FaceVerifyParams{Image1: ImageFromBytes(pngBytes), Image2: ImageFromPath("no-such-file.jpg")}, "image2"},
		{&FaceVerifyParams{Image1: ImageFromBase64("not base64!"), Image2: ImageFromBytes(pngBytes)}, "image1"},
		{&FaceVerifyParams{Image1: ImageFromBase64("data:image/png,%89PNG"), Image2: ImageFromBytes(pngBytes)}, "image1"},
		{&FaceVerifyParams{Image1: ImageFromBytes(nil), Image2: ImageFromBytes(pngBytes)}, "image1"},
		{&FaceMatchParams{Images: []FaceMatchParamsImage{{Data: ImageFromBytes(pngBytes)}, {Data: ImageFromPath("missing.png")}}}, "images[1].data"},
		{&PhotoBestFrameParams{Frames: []Image{ImageFromBytes(pngBytes), ImageFromBase64("@@@@")}}, "frames[1]"},
	}
	for _, tc := range cases {
		var err error
		switch p := tc.params.(type) {
		case *FaceVerifyParams:
			_, err = c.Face.Verify(ctx, p)
		case *FaceMatchParams:
			_, err = c.Face.Match(ctx, p)
		case *PhotoBestFrameParams:
			_, err = c.Photo.BestFrame(ctx, p)
		}
		if err == nil || !strings.HasPrefix(err.Error(), "verisec: "+tc.field+": ") {
			t.Errorf("%s: got %v", tc.field, err)
		}
	}
	_, err := c.Face.Verify(ctx, &FaceVerifyParams{Image1: ImageFromPath("no-such-file.jpg"), Image2: ImageFromBytes(pngBytes)})
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the file error is not wrapped: %v", err)
	}
	if n := len(s.requests()); n != 0 {
		t.Errorf("%d requests went out with an unreadable image", n)
	}
}

func TestImageListsGetTheirIndexAndIDsFilledIn(t *testing.T) {
	path := writePNG(t, "face.png")
	body, err := encodeBody(&FaceMatchParams{
		Images: []FaceMatchParamsImage{{Data: ImageFromPath(path)}, {Data: ImageFromBytes(pngBytes), Type: Int(1)}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != `{"images":[{"data":"`+png64+`","index":0},{"data":"`+png64+`","index":1,"type":1}]}` {
		t.Errorf("face match body %s", body)
	}

	body, err = encodeBody(&FaceSearchParams{
		Probe:   ImageFromBytes(pngBytes),
		Gallery: []FaceSearchParamsGallery{{Image: ImageFromBytes(pngBytes)}, {Image: ImageFromBytes(pngBytes), ID: String("mine")}, {Image: ImageFromBytes(pngBytes), ID: String("")}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var search struct {
		Gallery []map[string]any `json:"gallery"`
	}
	json.Unmarshal(body, &search)
	var ids []any
	for _, g := range search.Gallery {
		ids = append(ids, g["id"])
		if g["image"] != png64 || len(g) != 2 {
			t.Errorf("entry %v", g)
		}
	}
	if !reflect.DeepEqual(ids, []any{"face-1", "mine", "face-3"}) {
		t.Errorf("ids %v", ids)
	}

	// an index you give is kept; a list without entries is a list of images
	body, _ = encodeBody(&FaceMatchParams{Images: []FaceMatchParamsImage{{Data: ImageFromBytes(pngBytes), Index: Int(5)}}}, nil)
	if !strings.Contains(string(body), `"index":5`) {
		t.Errorf("explicit index: %s", body)
	}
	body, _ = encodeBody(&PhotoBestFrameParams{Frames: []Image{ImageFromBytes(pngBytes), ImageFromPath(path)}}, nil)
	if string(body) != `{"frames":["`+png64+`","`+png64+`"]}` {
		t.Errorf("frames %s", body)
	}
	body, _ = encodeBody(&FaceWatchlistParams{Probe: ImageFromBytes(pngBytes), List: []FaceWatchlistParamsList{{Image: ImageFromBytes(pngBytes), Label: String("VIP")}}}, nil)
	if !strings.Contains(string(body), `"list":[{"image":"`+png64+`","id":"face-1","label":"VIP"}]`) {
		t.Errorf("watchlist %s", body)
	}
}

func TestTheCallersParamsAreNeverChanged(t *testing.T) {
	path := writePNG(t, "face.png")
	gallery := []FaceSearchParamsGallery{{Image: ImageFromPath(path)}, {Image: ImageFromBytes(pngBytes), ID: String("")}}
	params := &FaceSearchParams{Probe: ImageFromPath(path), Gallery: gallery, Threshold: Float(0.8)}
	before := *params
	beforeGallery := append([]FaceSearchParamsGallery(nil), gallery...)
	if _, err := encodeBody(params, nil); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*params, before) || !reflect.DeepEqual(gallery, beforeGallery) || gallery[0].ID != nil || *gallery[1].ID != "" {
		t.Errorf("params changed: %+v", params)
	}
}

func TestImagesInAnyFieldsAndExtraFields(t *testing.T) {
	s := newStub(t, func(received, int) reply { return reply{body: kyc(map[string]any{}, nil)} })
	c, _ := s.client(t)
	_, err := c.Mrz.Parse(context.Background(), mrzLines, WithExtraField("strict", true), WithExtraField("lines", []string{"X"}), WithExtraField("photo", ImageFromBytes(pngBytes)))
	if err != nil {
		t.Fatal(err)
	}
	if got := string(s.requests()[0].Body); got != `{"strict":true,"lines":["X"],"photo":"`+png64+`"}` {
		t.Errorf("body %s", got)
	}
	data, err := json.Marshal(map[string]any{"img": ImageFromBytes(pngBytes)})
	if err != nil || string(data) != `{"img":"`+png64+`"}` {
		t.Errorf("an Image marshals as base64: %s %v", data, err)
	}
}

/* ---------------------------------------------------------------- uploads -- */

func TestUploadsGoAsMultipartWithTheSourceHeader(t *testing.T) {
	path := writePNG(t, "face.png")
	cases := []struct {
		file     *File
		filename string
	}{
		{FileFromPath(path), "face.png"},
		{FileFromBytes(pngBytes, "cheque.png"), "cheque.png"},
		{FileFromReader(bytes.NewReader(pngBytes), "scan.png"), "scan.png"},
		{FileFromBytes(pngBytes, ""), "image"},
	}
	for _, tc := range cases {
		s := newStub(t, func(received, int) reply { return reply{body: map[string]any{"object": "micr_line"}} })
		c, _ := s.client(t)
		r, err := c.Cheques.MicrLine(context.Background(), &ChequeMicrLineParams{Image: tc.file, Format: String("e13b")})
		if err != nil || r.Object != "micr_line" {
			t.Fatalf("%s: %v, %v", tc.filename, r, err)
		}
		req := s.requests()[0]
		if req.Header.Get("X-VeriSec-Source") != "sdk" || req.URL != "/v2/cheques/micr-line" {
			t.Errorf("%s: %s %v", tc.filename, req.URL, req.Header)
		}
		mediaType, mp, err := mime.ParseMediaType(req.Header.Get("Content-Type"))
		if err != nil || mediaType != "multipart/form-data" {
			t.Fatalf("content type %q", req.Header.Get("Content-Type"))
		}
		form, err := multipart.NewReader(bytes.NewReader(req.Body), mp["boundary"]).ReadForm(1 << 20)
		if err != nil {
			t.Fatal(err)
		}
		files := form.File["image"]
		if len(files) != 1 || files[0].Filename != tc.filename || files[0].Header.Get("Content-Type") != "image/png" {
			t.Fatalf("%s: image part %+v", tc.filename, files)
		}
		f, _ := files[0].Open()
		got, _ := io.ReadAll(f)
		f.Close()
		if !bytes.Equal(got, pngBytes) {
			t.Errorf("%s: the image bytes changed", tc.filename)
		}
		if !reflect.DeepEqual(form.Value, map[string][]string{"format": {"e13b"}}) {
			t.Errorf("%s: fields %v", tc.filename, form.Value)
		}
	}

	s := newStub(t, func(received, int) reply { return reply{body: map[string]any{"object": "cheque_amount"}} })
	c, _ := s.client(t)
	if _, err := c.Cheques.Amount(context.Background(), &ChequeAmountParams{Image: FileFromPath("missing.jpg")}); err == nil || !strings.HasPrefix(err.Error(), "verisec: image: ") {
		t.Errorf("a missing upload: %v", err)
	}
	if len(s.requests()) != 0 {
		t.Error("a request went out without its file")
	}
}

/* -------------------------------------------------------------------- GET -- */

func TestGETPathAndQuery(t *testing.T) {
	s := newStub(t, func(received, int) reply { return reply{body: map[string]any{"object": "bank_lookup"}} })
	c, _ := s.client(t)
	ctx := context.Background()
	if _, err := c.Bin.Lookup(ctx, "424242"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Banks.Lookup(ctx, &BankLookupParams{Name: String("Harbor Point"), Country: String("US")}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Bin.Lookup(ctx, "42/42"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Banks.Lookup(ctx, nil, WithExtraField("bic", "HPBKUS33")); err != nil {
		t.Fatal(err)
	}
	reqs := s.requests()
	want := []string{"/v2/bin/424242", "/v2/banks?name=Harbor+Point&country=US", "/v2/bin/42%2F42", "/v2/banks?bic=HPBKUS33"}
	for i, r := range reqs {
		if r.Method != "GET" || r.URL != want[i] {
			t.Errorf("request %d: %s %s, want GET %s", i, r.Method, r.URL, want[i])
		}
	}
	if _, err := c.Bin.Lookup(ctx, ""); err == nil || len(s.requests()) != 4 {
		t.Errorf("an empty path parameter: %v", err)
	}
}

/* ------------------------------------------------------------- operations -- */

func TestEveryOperationHasAMethod(t *testing.T) {
	c, _ := New("sk_test_x")
	if len(operations) != 69 {
		t.Errorf("%d operations, want 69", len(operations))
	}
	for id, goPath := range operations {
		v := reflect.ValueOf(c)
		parts := strings.Split(goPath, ".")
		for _, field := range parts[:len(parts)-1] {
			v = v.Elem().FieldByName(field)
			if !v.IsValid() || v.IsNil() {
				t.Fatalf("%s: no resource %s", id, goPath)
			}
		}
		if !v.MethodByName(parts[len(parts)-1]).IsValid() {
			t.Errorf("%s: no method %s", id, goPath)
		}
	}
	if operations["phone.otp.send"] != "Phone.Otp.Send" || operations["cheques.micrLine"] != "Cheques.MicrLine" || operations["bin.lookup"] != "Bin.Lookup" {
		t.Errorf("names: %v", operations)
	}
}

/* --------------------------------------------------------------- webhooks -- */

func TestWebhooks(t *testing.T) {
	secret := "whsec_" + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 24)))
	payload := []byte(`{"type":"verification.completed","timestamp":"2026-10-17T10:00:00Z","environment":"test","data":{"decision":"approved"}}`)
	headers := GenerateTestHeaders(payload, secret)

	event, err := ConstructEvent(payload, headers, secret)
	if err != nil || event.Type != "verification.completed" || event.Environment != "test" || event.Data["decision"] != "approved" || event.Timestamp == "" {
		t.Fatalf("valid: %+v, %v", event, err)
	}
	if err := VerifySignature(payload, headers, secret); err != nil {
		t.Errorf("valid: %v", err)
	}

	var sigErr *SignatureVerificationError
	other := "whsec_" + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("b", 24)))
	if err := VerifySignature(payload, headers, other); !errors.As(err, &sigErr) {
		t.Errorf("wrong secret: %v", err)
	}
	if err := VerifySignature(bytes.Replace(payload, []byte("approved"), []byte("declined"), 1), headers, secret); !errors.As(err, &sigErr) {
		t.Errorf("tampered body: %v", err)
	}
	old := GenerateTestHeaders(payload, secret, time.Now().Add(-time.Hour))
	if _, err := ConstructEvent(payload, old, secret); !errors.As(err, &sigErr) || !strings.Contains(err.Error(), "tolerance") {
		t.Errorf("stale timestamp: %v", err)
	}
	if err := VerifySignature(payload, old, secret, 2*time.Hour); err != nil {
		t.Errorf("a wider tolerance: %v", err)
	}
	if err := VerifySignature(payload, old, secret, 0); err != nil {
		t.Errorf("tolerance 0 skips the time check: %v", err)
	}
	if err := VerifySignature(payload, http.Header{}, secret); !errors.As(err, &sigErr) || !strings.Contains(err.Error(), "missing webhook-id") {
		t.Errorf("missing headers: %v", err)
	}
	bad := headers.Clone()
	bad.Set("webhook-timestamp", "yesterday")
	if err := VerifySignature(payload, bad, secret); !errors.As(err, &sigErr) {
		t.Errorf("malformed timestamp: %v", err)
	}
	if err := VerifySignature(payload, headers, "whsec_***"); !errors.As(err, &sigErr) {
		t.Errorf("a secret that is not base64: %v", err)
	}

	// a rotating secret: several signatures, any match passes
	rotated := headers.Clone()
	rotated.Set("webhook-signature", "v1,"+strings.Repeat("A", 44)+" v2,xyz "+headers.Get("webhook-signature"))
	if err := VerifySignature(payload, rotated, secret); err != nil {
		t.Errorf("several signatures: %v", err)
	}
	// svix-* names, and a map built by hand with lower-case keys
	svix := http.Header{"svix-id": {headers.Get("webhook-id")}, "svix-timestamp": {headers.Get("webhook-timestamp")}, "svix-signature": {headers.Get("webhook-signature")}}
	if err := VerifySignature(payload, svix, secret); err != nil {
		t.Errorf("svix names: %v", err)
	}
	lower := http.Header{"webhook-id": {headers.Get("webhook-id")}, "webhook-timestamp": {headers.Get("webhook-timestamp")}, "webhook-signature": {headers.Get("webhook-signature")}}
	if err := VerifySignature(payload, lower, secret); err != nil {
		t.Errorf("lower-case keys: %v", err)
	}
	if _, err := ConstructEvent([]byte("not json"), GenerateTestHeaders([]byte("not json"), secret), secret); err == nil || errors.As(err, &sigErr) {
		t.Errorf("a body that is not an event: %v", err)
	}
}

func TestRequestOptionHeaders(t *testing.T) {
	s := newStub(t, func(received, int) reply { return reply{body: map[string]any{"object": "cheque_bank"}} })
	c, _ := s.client(t)
	_, err := c.Cheques.Bank(context.Background(), &ChequeBankParams{Image: FileFromBytes(pngBytes, "c.png")},
		WithHeader("X-Trace", "abc"), WithHeader("User-Agent", "my-app/2"), WithHeader("Authorization", "Bearer stolen"), WithHeader("X-VeriSec-Source", "api"))
	if err != nil {
		t.Fatal(err)
	}
	h := s.requests()[0].Header
	if h.Get("X-Trace") != "abc" || h.Get("User-Agent") != "my-app/2" || h.Get("Authorization") != "Bearer sk_test_core" || h.Get("X-VeriSec-Source") != "api" {
		t.Errorf("headers %v", h)
	}
}
