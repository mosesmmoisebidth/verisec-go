package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The checked-in types.go and resources.go are what the generator makes from the spec today.
func TestGeneratedFilesAreUpToDate(t *testing.T) {
	files, summary, err := generate(filepath.Join("..", "..", "..", "spec", "openapi.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(summary, "69 operations") {
		t.Errorf("summary %q", summary)
	}
	for _, f := range files {
		have, err := os.ReadFile(filepath.Join("..", "..", f.Name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(bytes.ReplaceAll(have, []byte("\r\n"), []byte("\n")), f.Source) {
			t.Errorf("%s is out of date: run go run ./internal/gen from the module root", f.Name)
		}
	}
}

func TestNames(t *testing.T) {
	for in, want := range map[string]string{
		"livenessTransactionId": "LivenessTransactionID", "image_front": "ImageFront", "userIp": "UserIP",
		"request_id": "RequestID", "Date of Birth": "DateOfBirth", "MRZ Type": "MRZType", "flag_url": "FlagURL",
		"first6": "First6", "country_code3": "CountryCode3", "checksum_ok": "ChecksumOK", "id_numbers": "IDNumbers",
		"detectAll": "DetectAll", "ErrorCode": "ErrorCode", "3d": "X3d",
	} {
		if got := fieldName(in); got != want {
			t.Errorf("fieldName(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{"micrLine": "MicrLine", "otp": "Otp", "bin": "Bin", "doc_hint": "DocHint", "verifyLive": "VerifyLive"} {
		if got := pascal(in); got != want {
			t.Errorf("pascal(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{
		"images": "image", "matches": "match", "boxes": "box", "categories": "category", "addresses": "address",
		"statuses": "status", "gallery": "gallery", "compared": "compared", "status": "status", "analysis": "analysis",
		"faces": "face", "profiles": "profile",
	} {
		if got := singular(in); got != want {
			t.Errorf("singular(%q) = %q, want %q", in, got, want)
		}
	}
	taken := map[string]bool{}
	if a, b := uniqueName("Code", taken), uniqueName("Code", taken); a != "Code" || b != "Code2" {
		t.Errorf("uniqueName: %s %s", a, b)
	}
	if paramName("digits") != "digits" || paramName("gallery_id") != "galleryID" || paramName("type") != "typeValue" {
		t.Error("paramName")
	}
}
