package verisec

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// DefaultWebhookTolerance is how far a delivery's timestamp may be from now before it is rejected as a possible
// replay.
const DefaultWebhookTolerance = 300 * time.Second

// WebhookEvent is the body of a webhook delivery.
type WebhookEvent struct {
	// Type is what happened, such as "verification.completed", "verification.declined", "aml.hit" or
	// "credits.low".
	Type string `json:"type"`
	// Timestamp is when it happened (ISO 8601).
	Timestamp string `json:"timestamp"`
	// Environment is "test" or "live".
	Environment string `json:"environment"`
	// Data holds the event's details, as decoded JSON.
	Data map[string]any `json:"data"`
}

// VerifySignature checks a webhook delivery against the raw request body and your endpoint's signing secret
// (whsec_…, shown once when you create the endpoint). Deliveries are signed as Standard Webhooks: the headers
// webhook-id, webhook-timestamp and webhook-signature, the signature being "v1,<base64 HMAC-SHA256 of
// id.timestamp.body>" (several, space-separated, while a secret rotates; any match passes). The svix-id,
// svix-timestamp and svix-signature names work too, and header names are matched in any case.
//
// It returns a *SignatureVerificationError when a header is missing, no signature matches, or the timestamp
// is more than the tolerance from now: five minutes, or the tolerance you pass (zero or less skips the time
// check). Pass the body exactly as it arrived, before any JSON parsing.
func VerifySignature(payload []byte, headers http.Header, secret string, tolerance ...time.Duration) error {
	limit := DefaultWebhookTolerance
	if len(tolerance) > 0 {
		limit = tolerance[0]
	}
	return verifySignatureAt(payload, headers, secret, limit, time.Now())
}

// ConstructEvent verifies a delivery with VerifySignature, then parses its body:
//
//	func handle(w http.ResponseWriter, r *http.Request) {
//		payload, _ := io.ReadAll(r.Body)
//		event, err := verisec.ConstructEvent(payload, r.Header, os.Getenv("VERISEC_WEBHOOK_SECRET"))
//		if err != nil {
//			http.Error(w, "bad signature", http.StatusBadRequest)
//			return
//		}
//		if event.Type == "verification.completed" { /* event.Data */ }
//	}
func ConstructEvent(payload []byte, headers http.Header, secret string, tolerance ...time.Duration) (*WebhookEvent, error) {
	if err := VerifySignature(payload, headers, secret, tolerance...); err != nil {
		return nil, err
	}
	event := new(WebhookEvent)
	if err := json.Unmarshal(payload, event); err != nil {
		return nil, fmt.Errorf("verisec: the webhook body is not an event: %w", err)
	}
	return event, nil
}

// GenerateTestHeaders signs payload with secret the way VeriSec signs deliveries, for testing your webhook
// handler: webhook-id (random), webhook-timestamp (now, or the time you pass) and webhook-signature.
func GenerateTestHeaders(payload []byte, secret string, timestamp ...time.Time) http.Header {
	at := time.Now()
	if len(timestamp) > 0 {
		at = timestamp[0]
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		panic("verisec: crypto/rand failed: " + err.Error())
	}
	msgID := "msg_" + hex.EncodeToString(id[:])
	ts := strconv.FormatInt(at.Unix(), 10)
	key, err := webhookKey(secret)
	if err != nil {
		key = []byte(secret)
	}
	h := make(http.Header)
	h.Set("webhook-id", msgID)
	h.Set("webhook-timestamp", ts)
	h.Set("webhook-signature", "v1,"+base64.StdEncoding.EncodeToString(sign(key, msgID, ts, payload)))
	return h
}

// webhookKey is the HMAC key of a secret: the base64 part after whsec_.
func webhookKey(secret string) ([]byte, error) {
	encoded := strings.TrimPrefix(strings.TrimSpace(secret), "whsec_")
	if key, err := base64.StdEncoding.DecodeString(encoded); err == nil && len(key) > 0 {
		return key, nil
	}
	if key, err := base64.RawStdEncoding.DecodeString(encoded); err == nil && len(key) > 0 {
		return key, nil
	}
	return nil, &SignatureVerificationError{Message: "the signing secret is not a whsec_ secret (base64 after whsec_)"}
}

func sign(key []byte, id, timestamp string, payload []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(id))
	mac.Write([]byte("."))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(payload)
	return mac.Sum(nil)
}

// header finds a header in any case, also in a map built by hand with lower-case keys.
func header(h http.Header, names ...string) string {
	for _, name := range names {
		if v := h.Get(name); v != "" {
			return v
		}
		for key, values := range h {
			if strings.EqualFold(key, name) && len(values) > 0 && values[0] != "" {
				return values[0]
			}
		}
	}
	return ""
}

func verifySignatureAt(payload []byte, headers http.Header, secret string, tolerance time.Duration, now time.Time) error {
	id := header(headers, "webhook-id", "svix-id")
	timestamp := header(headers, "webhook-timestamp", "svix-timestamp")
	signatures := header(headers, "webhook-signature", "svix-signature")
	if id == "" || timestamp == "" || signatures == "" {
		return &SignatureVerificationError{Message: "missing webhook-id, webhook-timestamp or webhook-signature header"}
	}
	seconds, err := strconv.ParseInt(strings.TrimSpace(timestamp), 10, 64)
	if err != nil {
		return &SignatureVerificationError{Message: "malformed webhook-timestamp header: expected unix seconds"}
	}
	if tolerance > 0 {
		age := now.Sub(time.Unix(seconds, 0))
		if age > tolerance || age < -tolerance {
			return &SignatureVerificationError{Message: fmt.Sprintf("the timestamp is outside the %s tolerance", tolerance)}
		}
	}
	key, err := webhookKey(secret)
	if err != nil {
		return err
	}
	expected := sign(key, id, timestamp, payload)
	matched := false
	for _, part := range strings.Fields(signatures) {
		version, value, ok := strings.Cut(part, ",")
		if !ok || version != "v1" {
			continue
		}
		given, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			continue
		}
		if hmac.Equal(given, expected) {
			matched = true
		}
	}
	if !matched {
		return &SignatureVerificationError{Message: "no signature matches the payload: check the signing secret and that the body is unmodified"}
	}
	return nil
}
