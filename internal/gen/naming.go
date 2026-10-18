package main

import (
	"strconv"
	"strings"
	"unicode"
)

// initialisms are written in capitals in field names, as Go spells them
// (RequestID, UserIP, FlagURL). Type, resource and method names keep plain
// PascalCase so they read the same in every SDK (MrzParse, Client.Bin).
var initialisms = map[string]string{
	"id": "ID", "ids": "IDs", "url": "URL", "urls": "URLs", "uri": "URI", "api": "API", "http": "HTTP",
	"https": "HTTPS", "json": "JSON", "xml": "XML", "html": "HTML", "ip": "IP", "ips": "IPs", "uuid": "UUID",
	"dns": "DNS", "tls": "TLS", "ttl": "TTL", "utc": "UTC", "ok": "OK", "asn": "ASN", "isp": "ISP", "vpn": "VPN",
	"mrz": "MRZ", "nfc": "NFC", "rfid": "RFID", "ocr": "OCR", "pdf": "PDF", "kyc": "KYC", "aml": "AML", "pep": "PEP",
	"otp": "OTP", "sms": "SMS", "qr": "QR", "iso": "ISO", "bin": "BIN", "iin": "IIN", "bic": "BIC", "iban": "IBAN",
	"micr": "MICR", "mcc": "MCC", "mnc": "MNC", "cldr": "CLDR", "usd": "USD", "roi": "ROI",
}

// words splits snake_case, kebab-case, spaced words and camelCase into words:
// "livenessTransactionId" -> liveness Transaction Id, "MRZType" -> MRZ Type.
func words(s string) []string {
	var out []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			out = append(out, string(cur))
			cur = nil
		}
	}
	runes := []rune(s)
	for i, r := range runes {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			flush()
			continue
		}
		if i > 0 && unicode.IsUpper(r) {
			prev := runes[i-1]
			nextLower := i+1 < len(runes) && unicode.IsLower(runes[i+1])
			if unicode.IsLower(prev) || unicode.IsDigit(prev) || (unicode.IsUpper(prev) && nextLower) {
				flush()
			}
		}
		cur = append(cur, r)
	}
	flush()
	return out
}

func upperFirst(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	r[0] = unicode.ToUpper(r[0])
	return string(r)
}

func lowerFirst(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	r[0] = unicode.ToLower(r[0])
	return string(r)
}

// pascal is plain PascalCase, for type names built from property names
// (doc_hint -> DocHint) and for resources and methods (micrLine -> MicrLine).
func pascal(s string) string {
	var b strings.Builder
	for _, w := range words(s) {
		b.WriteString(upperFirst(w))
	}
	return b.String()
}

// fieldName is a Go field name: PascalCase with initialisms in capitals.
func fieldName(s string) string {
	var b strings.Builder
	for _, w := range words(s) {
		if up, ok := initialisms[strings.ToLower(w)]; ok {
			b.WriteString(up)
		} else {
			b.WriteString(upperFirst(w))
		}
	}
	name := b.String()
	if name == "" || !unicode.IsLetter([]rune(name)[0]) {
		name = "X" + name
	}
	return name
}

// uniqueName returns name, or name2, name3, … when it is taken.
func uniqueName(name string, taken map[string]bool) string {
	out := name
	for n := 2; taken[out]; n++ {
		out = name + strconv.Itoa(n)
	}
	taken[out] = true
	return out
}

// singular turns a plural property name into the name of one item, for the
// type of a list's entries (images -> Image, matches -> Match).
func singular(s string) string {
	lower := strings.ToLower(s)
	switch {
	case strings.HasSuffix(lower, "ies") && len(s) > 3:
		return s[:len(s)-3] + "y"
	case strings.HasSuffix(lower, "sses"), strings.HasSuffix(lower, "xes"), strings.HasSuffix(lower, "zes"),
		strings.HasSuffix(lower, "ches"), strings.HasSuffix(lower, "shes"), strings.HasSuffix(lower, "uses"):
		return s[:len(s)-2]
	case strings.HasSuffix(lower, "ss"), strings.HasSuffix(lower, "us"), strings.HasSuffix(lower, "is"):
		return s
	case strings.HasSuffix(lower, "s") && len(s) > 1:
		return s[:len(s)-1]
	}
	return s
}

// refName is the last segment of a $ref.
func refName(ref string) string { return ref[strings.LastIndex(ref, "/")+1:] }

// paramName spells a path parameter as a Go argument (gallery_id -> galleryID).
func paramName(s string) string {
	ws := words(s)
	if len(ws) == 0 {
		return "value"
	}
	name := strings.ToLower(ws[0])
	for _, w := range ws[1:] {
		if up, ok := initialisms[strings.ToLower(w)]; ok {
			name += up
		} else {
			name += upperFirst(w)
		}
	}
	switch name {
	case "ctx", "opts", "params", "path", "err", "s", "break", "case", "chan", "const", "continue", "default",
		"defer", "else", "fallthrough", "for", "func", "go", "goto", "if", "import", "interface", "map", "package",
		"range", "return", "select", "struct", "switch", "type", "var":
		name += "Value"
	}
	return name
}
