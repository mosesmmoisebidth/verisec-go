package verisec

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

// Image is an image for a KYC API, sent as plain base64 inside the JSON body. Make one with ImageFromPath,
// ImageFromBytes, ImageFromReader or ImageFromBase64:
//
//	client.Face.Verify(ctx, &verisec.FaceVerifyParams{
//		Image1: verisec.ImageFromPath("selfie.jpg"),
//		Image2: verisec.ImageFromBytes(idPhoto),
//	})
//
// A nil Image is not sent. The APIs read JPEG and PNG. An image that cannot be read (a missing file, a string
// that is not base64) fails the call before anything is sent, with an error naming the field.
type Image interface {
	// base64 returns the image as plain base64.
	base64() (string, error)
}

// ImageFromPath reads the image from a file when the call is made.
func ImageFromPath(path string) Image { return &pathImage{path: path} }

// ImageFromBytes sends the image bytes you already have.
func ImageFromBytes(data []byte) Image { return &bytesImage{data: data} }

// ImageFromReader sends what r holds. It is read to the end on first use and kept, so retries and later calls
// with the same Image send the same bytes.
func ImageFromReader(r io.Reader) Image { return &readerImage{r: r} }

// ImageFromBase64 sends an image you already have as base64, plain or as a data: URI
// ("data:image/jpeg;base64,…"). The data: prefix and any whitespace are removed.
func ImageFromBase64(s string) Image { return &base64Image{s: s} }

type pathImage struct{ path string }

func (i *pathImage) base64() (string, error) {
	data, err := os.ReadFile(i.path)
	if err != nil {
		return "", fmt.Errorf("reading the image: %w", err)
	}
	if len(data) == 0 {
		return "", fmt.Errorf("the image file %s is empty", i.path)
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

func (i *pathImage) MarshalJSON() ([]byte, error) { return marshalImage(i) }

type bytesImage struct{ data []byte }

func (i *bytesImage) base64() (string, error) {
	if len(i.data) == 0 {
		return "", errors.New("the image has no bytes")
	}
	return base64.StdEncoding.EncodeToString(i.data), nil
}

func (i *bytesImage) MarshalJSON() ([]byte, error) { return marshalImage(i) }

type readerImage struct {
	r    io.Reader
	once sync.Once
	b64  string
	err  error
}

func (i *readerImage) base64() (string, error) {
	i.once.Do(func() {
		if i.r == nil {
			i.err = errors.New("the image reader is nil")
			return
		}
		data, err := io.ReadAll(i.r)
		switch {
		case err != nil:
			i.err = fmt.Errorf("reading the image: %w", err)
		case len(data) == 0:
			i.err = errors.New("the image reader is empty")
		default:
			i.b64 = base64.StdEncoding.EncodeToString(data)
		}
	})
	return i.b64, i.err
}

func (i *readerImage) MarshalJSON() ([]byte, error) { return marshalImage(i) }

type base64Image struct{ s string }

func (i *base64Image) base64() (string, error) {
	s := strings.TrimSpace(i.s)
	if strings.HasPrefix(strings.ToLower(s), "data:") {
		comma := strings.IndexByte(s, ',')
		if comma < 0 || !strings.HasSuffix(strings.ToLower(s[:comma]), ";base64") {
			return "", errors.New("not a base64 data: URI (data:<type>;base64,<data>)")
		}
		s = s[comma+1:]
	}
	s = strings.Join(strings.Fields(s), "")
	if !isBase64(s) {
		return "", errors.New("not valid base64 (standard alphabet, padded)")
	}
	return s, nil
}

func (i *base64Image) MarshalJSON() ([]byte, error) { return marshalImage(i) }

// isBase64 checks the standard, padded alphabet without decoding.
func isBase64(s string) bool {
	if s == "" || len(s)%4 != 0 {
		return false
	}
	pad := len(s) - len(strings.TrimRight(s, "="))
	if pad > 2 {
		return false
	}
	for _, c := range s[:len(s)-pad] {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '+', c == '/':
		default:
			return false
		}
	}
	return true
}

// marshalImage writes an image as a JSON string of base64, for an Image placed in an any-typed field or a
// params struct you marshal yourself.
func marshalImage(i Image) ([]byte, error) {
	s, err := i.base64()
	if err != nil {
		return nil, err
	}
	return json.Marshal(s)
}

// imageBase64 resolves an image for the request field at path, naming the field when it fails.
func imageBase64(i Image, path string) (string, error) {
	s, err := i.base64()
	if err != nil {
		return "", fmt.Errorf("verisec: %s: %w", path, err)
	}
	return s, nil
}
