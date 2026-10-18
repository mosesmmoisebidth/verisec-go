package verisec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const userAgent = "verisec-go/" + Version

// A RequestOption changes one call. Pass request options after a method's other arguments:
//
//	client.Cheques.Read(ctx, params, verisec.WithRequestTimeout(5*time.Minute))
type RequestOption func(*requestConfig)

type requestConfig struct {
	timeout    time.Duration
	maxRetries int
	header     http.Header
	extra      []extraField
}

// extraField is a parameter the params type has no field for (WithExtraField).
type extraField struct {
	name  string
	value any
}

// WithRequestTimeout sets how long each attempt of this call may take, overriding the client's WithTimeout.
func WithRequestTimeout(d time.Duration) RequestOption {
	return func(c *requestConfig) { c.timeout = max(d, 0) }
}

// WithRequestMaxRetries sets how many times this call may be sent again, overriding the client's
// WithMaxRetries. 0 turns retries off.
func WithRequestMaxRetries(n int) RequestOption {
	return func(c *requestConfig) { c.maxRetries = max(n, 0) }
}

// WithHeader adds a header to this call. It can replace Accept, User-Agent and X-VeriSec-Source, but not
// Authorization or Content-Type.
func WithHeader(key, value string) RequestOption {
	return func(c *requestConfig) {
		if c.header == nil {
			c.header = make(http.Header)
		}
		c.header.Set(key, value)
	}
}

// WithExtraField sends a parameter the params type has no field for, such as one the API added after this
// version of the library: a member of the JSON body (sent as given; it replaces a field of the same name), a
// form field of an upload, or a query parameter of a GET.
func WithExtraField(name string, value any) RequestOption {
	return func(c *requestConfig) { c.extra = append(c.extra, extraField{name: name, value: value}) }
}

// ResponseInfo is where an answer came from. Every result has it in its LastResponse field.
type ResponseInfo struct {
	// Status is the HTTP status code.
	Status int
	// Header holds the response headers.
	Header http.Header
	// RequestID identifies the call. Quote it when you contact support.
	RequestID string
	// Warnings are notes about a KYC result that are not errors.
	Warnings []string
	// LatencyMs is how long a KYC check took on the server, in milliseconds (0 when the answer does not say).
	LatencyMs float64
}

// responseHolder is a result that keeps its ResponseInfo (every generated answer type).
type responseHolder interface {
	setLastResponse(*ResponseInfo)
}

// envelope says how to read a successful answer.
type envelope int

const (
	// envelopeObject: the answer is the result (Financial operations).
	envelopeObject envelope = iota
	// envelopeData: the result is in {ok, request_id, latency_ms, data, warnings, error} (KYC operations).
	envelopeData
)

// call describes one API request.
type call struct {
	method string
	path   string
	// body is a params struct sent as JSON; form a params struct sent as multipart/form-data; query a params
	// struct sent as the query string.
	body  any
	form  any
	query any
	// source sends X-VeriSec-Source: sdk, which files a Financial upload under "SDK" in the console.
	source   bool
	envelope envelope
	// anonymous calls carry no bearer token (the token exchange itself).
	anonymous bool
	// noRetries turns retries off for this call whatever the options say.
	noRetries bool
}

// transport sends API requests: authentication, headers, retries, answers and errors.
type transport struct {
	baseURL    string
	timeout    time.Duration
	maxRetries int
	http       *http.Client
	creds      credentials
	// sleep waits between attempts; tests replace it.
	sleep func(context.Context, time.Duration) error
}

// doCall sends a call and decodes its answer into a new T.
func doCall[T any](ctx context.Context, t *transport, c *call, opts []RequestOption) (*T, error) {
	out := new(T)
	if err := t.do(ctx, c, out, opts); err != nil {
		return nil, err
	}
	return out, nil
}

// do sends a call and decodes a successful answer into out.
//
// Calls are charged only when they succeed, so do sends a call again (up to the retry limit) only when nothing
// can have been charged: a 429, a 5xx, or a connection that never opened. A timeout while waiting for the
// answer, or a connection that drops after the request went out, comes back as a *ConnectionError and is not
// sent again, because the check may have run on the server.
func (t *transport) do(ctx context.Context, c *call, out any, opts []RequestOption) error {
	if ctx == nil {
		ctx = context.Background()
	}
	rc := requestConfig{timeout: t.timeout, maxRetries: t.maxRetries}
	for _, opt := range opts {
		if opt != nil {
			opt(&rc)
		}
	}
	if c.noRetries {
		rc.maxRetries = 0
	}

	// Encode once: every attempt sends the same bytes.
	var (
		body        []byte
		contentType string
		query       string
		err         error
	)
	switch {
	case c.form != nil:
		body, contentType, err = encodeMultipart(c.form, rc.extra)
	case c.method == http.MethodGet:
		query, err = encodeQuery(c.query, rc.extra)
	default:
		body, err = encodeBody(c.body, rc.extra)
		contentType = "application/json"
	}
	if err != nil {
		return err
	}
	target := t.baseURL + c.path + query

	refreshed := false
	for attempt := 0; ; attempt++ {
		header := make(http.Header)
		header.Set("Accept", "application/json")
		header.Set("User-Agent", userAgent)
		if c.source {
			header.Set("X-VeriSec-Source", "sdk")
		}
		for key, values := range rc.header {
			header[key] = append([]string(nil), values...)
		}
		token := ""
		if !c.anonymous {
			if token, err = t.creds.token(ctx); err != nil {
				return err
			}
			header.Set("Authorization", "Bearer "+token)
		}
		if contentType != "" {
			header.Set("Content-Type", contentType)
		}

		res, data, err := t.send(ctx, c.method, target, body, header, rc.timeout)
		if err != nil {
			var connErr *ConnectionError
			if errors.As(err, &connErr) && connErr.neverSent && attempt < rc.maxRetries {
				if err := t.sleep(ctx, retryDelay(attempt, "")); err != nil {
					return err
				}
				continue
			}
			return err
		}

		info := responseInfo(res, data)
		if res.StatusCode >= 200 && res.StatusCode < 300 {
			return readAnswer(c, res, data, info, out)
		}
		if res.StatusCode == http.StatusUnauthorized && !c.anonymous && !refreshed && t.creds.invalidate(token) {
			refreshed = true
			attempt-- // a fresh token is not a retry
			continue
		}
		if retryableStatus(res.StatusCode) && attempt < rc.maxRetries {
			if err := t.sleep(ctx, retryDelay(attempt, res.Header.Get("Retry-After"))); err != nil {
				return err
			}
			continue
		}
		return newAPIError(res.StatusCode, res.Header, data)
	}
}

// readAnswer decodes a 2xx answer: the KYC envelope's data (an ok: false there is an error), or the Financial
// object as it is.
func readAnswer(c *call, res *http.Response, data []byte, info *ResponseInfo, out any) error {
	payload := data
	if c.envelope == envelopeData {
		var env struct {
			OK   *bool           `json:"ok"`
			Data json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(data, &env); err != nil {
			return fmt.Errorf("verisec: the answer to %s %s is not the JSON envelope: %w", c.method, c.path, err)
		}
		if env.OK != nil && !*env.OK {
			return newAPIError(res.StatusCode, res.Header, data)
		}
		payload = env.Data
	}
	if trimmed := bytes.TrimSpace(payload); out != nil && len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("null")) {
		if err := json.Unmarshal(trimmed, out); err != nil {
			return fmt.Errorf("verisec: could not read the answer to %s %s: %w", c.method, c.path, err)
		}
	}
	if h, ok := out.(responseHolder); ok {
		h.setLastResponse(info)
	}
	return nil
}

// responseInfo reads the request id, warnings and latency the answer carries.
func responseInfo(res *http.Response, data []byte) *ResponseInfo {
	info := &ResponseInfo{Status: res.StatusCode, Header: res.Header, Warnings: []string{}}
	var meta struct {
		RequestID any `json:"request_id"`
		Warnings  any `json:"warnings"`
		LatencyMs any `json:"latency_ms"`
	}
	if json.Unmarshal(data, &meta) == nil {
		if id, ok := meta.RequestID.(string); ok {
			info.RequestID = id
		}
		if list, ok := meta.Warnings.([]any); ok {
			for _, w := range list {
				if s, ok := w.(string); ok {
					info.Warnings = append(info.Warnings, s)
				} else if b, err := json.Marshal(w); err == nil {
					info.Warnings = append(info.Warnings, string(b))
				}
			}
		}
		if ms, ok := meta.LatencyMs.(float64); ok {
			info.LatencyMs = ms
		}
	}
	if info.RequestID == "" {
		info.RequestID = res.Header.Get("X-Request-Id")
	}
	return info
}

// emptyBody is the body of a request without one. Unlike http.NoBody it makes net/http treat the request as
// not replayable: the standard transport otherwise sends a GET again by itself when a reused connection drops
// after the request went out, and every call here is charged. (A GET whose body reads empty is still sent
// without a body.)
type emptyBody struct{}

func (emptyBody) Read([]byte) (int, error) { return 0, io.EOF }
func (emptyBody) Close() error             { return nil }

// send makes one attempt and reads the whole answer. Network failures come back as *ConnectionError; when
// the caller's context ends, its error comes back as it is.
func (t *transport) send(ctx context.Context, method, target string, body []byte, header http.Header, timeout time.Duration) (*http.Response, []byte, error) {
	actx, cancel := ctx, context.CancelFunc(func() {})
	if timeout > 0 {
		actx, cancel = context.WithTimeout(ctx, timeout)
	}
	defer cancel()

	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(actx, method, target, reader)
	if err != nil {
		return nil, nil, fmt.Errorf("verisec: %w", err)
	}
	if body == nil {
		req.Body, req.GetBody, req.ContentLength = emptyBody{}, nil, 0
	}
	req.Header = header

	res, err := t.http.Do(req)
	if err != nil {
		return nil, nil, t.connectionError(ctx, actx, err, timeout)
	}
	defer res.Body.Close()
	data, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, nil, t.connectionError(ctx, actx, err, timeout)
	}
	return res, data, nil
}

// connectionError says what happened to an attempt that got no answer, and whether it can have reached the
// server.
func (t *transport) connectionError(ctx, actx context.Context, err error, timeout time.Duration) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	cause := err
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		cause = urlErr.Err
	}
	if neverSent(cause) {
		return &ConnectionError{
			Message:   fmt.Sprintf("could not connect to %s: %v. Nothing was sent, so nothing was charged", t.baseURL, cause),
			Err:       err,
			neverSent: true,
		}
	}
	var netErr net.Error
	if errors.Is(actx.Err(), context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
		after := ""
		if timeout > 0 {
			after = " within " + timeout.String()
		}
		return &ConnectionError{
			Timeout: true,
			Message: fmt.Sprintf("no answer from %s%s. The call may still have run (and been charged) on the server, so it was not sent again", t.baseURL, after),
			Err:     err,
		}
	}
	return &ConnectionError{
		Message: fmt.Sprintf("the connection to %s failed after the request was sent: %v. The call may still have run (and been charged) on the server, so it was not sent again", t.baseURL, cause),
		Err:     err,
	}
}

// neverSent reports whether err happened before the request could reach the server: the connection was
// refused, the name did not resolve, the host or network was unreachable, or connecting timed out. Those are
// the only network failures worth another try.
func neverSent(err error) bool {
	for e := err; e != nil; e = errors.Unwrap(e) {
		if op, ok := e.(*net.OpError); ok && op.Op == "dial" {
			return true
		}
		if _, ok := e.(*net.DNSError); ok {
			return true
		}
	}
	return false
}

// retryableStatus reports whether an error status is worth another try. Calls are charged only when they
// succeed, so a 429 (refused before running) or a 5xx (the check did not complete) costs nothing.
func retryableStatus(status int) bool {
	return status == http.StatusTooManyRequests || status >= 500
}

// retryDelay is how long to wait before attempt number attempt+2: what the Retry-After header says (capped at a
// minute), or min(0.5 * 2^attempt, 8) seconds with ±25% jitter.
func retryDelay(attempt int, retryAfter string) time.Duration {
	if d, ok := parseRetryAfter(retryAfter, time.Now()); ok {
		return min(d, time.Minute)
	}
	base := math.Min(0.5*math.Pow(2, float64(attempt)), 8)
	return time.Duration(base * (0.75 + mrand.Float64()*0.5) * float64(time.Second))
}

// parseRetryAfter reads a Retry-After value: seconds, or an HTTP date.
func parseRetryAfter(value string, now time.Time) (time.Duration, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	if seconds, err := strconv.ParseFloat(value, 64); err == nil {
		if seconds < 0 || math.IsNaN(seconds) || math.IsInf(seconds, 0) {
			return 0, false
		}
		return time.Duration(math.Min(seconds, 1e6) * float64(time.Second)), true
	}
	if at, err := http.ParseTime(value); err == nil {
		return max(at.Sub(now), 0), true
	}
	return 0, false
}

// sleepContext waits for d, or until ctx ends.
func sleepContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// buildPath fills the {name} placeholders of a path template, in order, with escaped values. An empty value is
// refused, so a missing argument never turns into another endpoint.
func buildPath(template string, values ...string) (string, error) {
	var b strings.Builder
	rest := template
	for _, value := range values {
		open, end := strings.IndexByte(rest, '{'), strings.IndexByte(rest, '}')
		if open < 0 || end < open {
			return "", fmt.Errorf("verisec: the path %s has fewer parameters than given", template)
		}
		if value == "" {
			return "", fmt.Errorf("verisec: %s must not be empty", rest[open+1:end])
		}
		b.WriteString(rest[:open])
		b.WriteString(url.PathEscape(value))
		rest = rest[end+1:]
	}
	if strings.ContainsRune(rest, '{') {
		return "", fmt.Errorf("verisec: the path %s has more parameters than given", template)
	}
	b.WriteString(rest)
	return b.String(), nil
}
