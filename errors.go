package verisec

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// APIError is an error answer from the VeriSec API: a 4xx or 5xx status, or a KYC answer with ok: false.
// Match it with errors.As, or test its family with IsInvalidRequest, IsAuthentication, IsInsufficientCredits,
// IsPermission, IsNotFound, IsRateLimited and IsServerError:
//
//	result, err := client.Face.Verify(ctx, params)
//	var apiErr *verisec.APIError
//	switch {
//	case verisec.IsInsufficientCredits(err):
//		// top up credits in the console; nothing was charged
//	case errors.As(err, &apiErr):
//		log.Println(apiErr.Status, apiErr.Code, apiErr.Param, apiErr.RequestID)
//	}
//
// The client sends 429 and 5xx answers again before an APIError reaches you; nothing was charged for either.
type APIError struct {
	// Status is the HTTP status code.
	Status int
	// Code is the machine-readable reason, such as "invalid_input", "parameter_unknown", "missing_key" or
	// "insufficient_credits". Empty when the answer has none.
	Code string
	// Message says what went wrong, for developers.
	Message string
	// Param is the request field the error is about, in the API's spelling, when there is one.
	Param string
	// RequestID identifies the call. Quote it when you contact support.
	RequestID string
	// RetryAfter is how long the API asked you to wait (the Retry-After header), mostly on a 429. Zero when it
	// did not say.
	RetryAfter time.Duration
	// Header holds the response headers.
	Header http.Header
}

// Error describes the failure with its status, code, param and request id.
func (e *APIError) Error() string {
	var b strings.Builder
	b.WriteString("verisec: ")
	b.WriteString(e.Message)
	b.WriteString(" (status ")
	b.WriteString(strconv.Itoa(e.Status))
	if e.Code != "" {
		b.WriteString(", code ")
		b.WriteString(e.Code)
	}
	if e.Param != "" {
		b.WriteString(", param ")
		b.WriteString(e.Param)
	}
	if e.RequestID != "" {
		b.WriteString(", request ")
		b.WriteString(e.RequestID)
	}
	b.WriteString(")")
	return b.String()
}

// newAPIError reads an error answer: the API's {error: {code, message, param}}, a validation {detail}, the
// gateway's {error_msg}, or plain text.
func newAPIError(status int, header http.Header, body []byte) *APIError {
	e := &APIError{Status: status, Header: header}
	readErrorBody(e, body)
	if e.Message == "" {
		e.Message = fmt.Sprintf("VeriSec API request failed with status %d", status)
	}
	if e.RequestID == "" {
		e.RequestID = header.Get("X-Request-Id")
	}
	if d, ok := parseRetryAfter(header.Get("Retry-After"), time.Now()); ok {
		e.RetryAfter = d
	}
	return e
}

func readErrorBody(e *APIError, body []byte) {
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		text := strings.TrimSpace(string(body))
		if len(text) > 500 {
			text = text[:500]
			for !utf8.ValidString(text) {
				text = text[:len(text)-1]
			}
		}
		e.Message = text
		return
	}
	if id, ok := doc["request_id"].(string); ok {
		e.RequestID = id
	}
	switch errValue := doc["error"].(type) {
	case map[string]any:
		e.Code, _ = errValue["code"].(string)
		e.Message, _ = errValue["message"].(string)
		e.Param, _ = errValue["param"].(string)
		return
	case string:
		e.Code, _ = doc["code"].(string)
		e.Message = errValue
		return
	}
	switch detail := doc["detail"].(type) {
	case string:
		e.Code, e.Message = "invalid_input", detail
		return
	case []any:
		if len(detail) > 0 {
			e.Code, e.Message = "invalid_input", "The request is not valid."
			if first, ok := detail[0].(map[string]any); ok {
				if msg, ok := first["msg"].(string); ok {
					e.Message = msg
				}
				if loc, ok := first["loc"].([]any); ok {
					var parts []string
					for _, p := range loc {
						if s := fmt.Sprint(p); s != "body" {
							parts = append(parts, s)
						}
					}
					e.Param = strings.Join(parts, ".")
				}
			}
			return
		}
	}
	if msg, ok := doc["error_msg"].(string); ok {
		e.Message = msg
	}
}

// apiError finds the *APIError in err's chain.
func apiError(err error) *APIError {
	var e *APIError
	if errors.As(err, &e) {
		return e
	}
	return nil
}

// IsInvalidRequest reports whether err is an API error about the request itself: a field missing or not
// valid, a file too large or not an image (400, 413, 415, 422 and the other 4xx below).
func IsInvalidRequest(err error) bool {
	e := apiError(err)
	if e == nil {
		return false
	}
	switch e.Status {
	case http.StatusUnauthorized, http.StatusPaymentRequired, http.StatusForbidden, http.StatusNotFound, http.StatusTooManyRequests:
		return false
	}
	return e.Status < 500
}

// IsAuthentication reports whether err is a 401: no API key, or a key (or live token) that is not valid,
// expired or revoked, or a wrong client id or secret.
func IsAuthentication(err error) bool {
	e := apiError(err)
	return e != nil && e.Status == http.StatusUnauthorized
}

// IsInsufficientCredits reports whether err is a 402: not enough credits for the call, or the key reached its
// spend cap. Nothing was charged.
func IsInsufficientCredits(err error) bool {
	e := apiError(err)
	return e != nil && e.Status == http.StatusPaymentRequired
}

// IsPermission reports whether err is a 403: the key may not call this API (permission, environment or IP
// allow-list).
func IsPermission(err error) bool {
	e := apiError(err)
	return e != nil && e.Status == http.StatusForbidden
}

// IsNotFound reports whether err is a 404.
func IsNotFound(err error) bool {
	e := apiError(err)
	return e != nil && e.Status == http.StatusNotFound
}

// IsRateLimited reports whether err is a 429 that was still refused after the retries: wait RetryAfter.
// Nothing was charged.
func IsRateLimited(err error) bool {
	e := apiError(err)
	return e != nil && e.Status == http.StatusTooManyRequests
}

// IsServerError reports whether err is a 5xx that persisted through the retries: the check could not run.
// Nothing was charged; it is safe to try again later.
func IsServerError(err error) bool { e := apiError(err); return e != nil && e.Status >= 500 }

// ConnectionError means a call got no answer: the network failed, the connection dropped, or an attempt timed
// out (then Timeout is true). Match it with errors.As.
//
// A connection that never opened is sent again first, up to the retry limit, and then reported as a
// ConnectionError: nothing was sent, so nothing was charged. A timeout, or a connection that dropped after the
// request went out, is never sent again: the check may still have run, and been charged, on the server. The
// message says which happened.
//
// When the context you passed ends, calls return the context's error instead.
type ConnectionError struct {
	// Timeout reports whether an attempt ran out of time waiting for the answer (WithTimeout,
	// WithRequestTimeout).
	Timeout bool
	// Message says what happened.
	Message string
	// Err is the underlying network error.
	Err error

	// neverSent: the request cannot have reached the server, so another try is safe.
	neverSent bool
}

// Error returns the message.
func (e *ConnectionError) Error() string { return "verisec: " + e.Message }

// Unwrap returns the underlying network error.
func (e *ConnectionError) Unwrap() error { return e.Err }

// SignatureVerificationError means a webhook delivery did not verify: a header is missing or malformed, no
// signature matches the payload and the secret, or the timestamp is outside the tolerance.
type SignatureVerificationError struct {
	// Message says which check failed.
	Message string
}

// Error returns the message.
func (e *SignatureVerificationError) Error() string { return "verisec: " + e.Message }
