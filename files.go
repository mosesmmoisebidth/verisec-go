package verisec

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// File is an image for the Financial reads (cheques and cards), uploaded as multipart/form-data in the part
// named image, exactly as given (never resized or re-encoded). Create one with FileFromPath, FileFromBytes or
// FileFromReader:
//
//	cheque, err := client.Cheques.Read(ctx, &verisec.ChequeReadParams{
//		Image: verisec.FileFromPath("cheque.jpg"),
//	})
//
// The reads take JPG, PNG and BMP, up to 10 MB.
type File struct {
	// Filename is sent with the image. FileFromPath uses the path's base name; an empty name is sent as "image".
	Filename string
	// ContentType is the image's media type. When empty, it is read from the first bytes: JPEG, PNG, BMP or
	// WebP, else application/octet-stream.
	ContentType string

	path   string
	reader io.Reader

	mu     sync.Mutex
	data   []byte
	loaded bool
}

// FileFromPath uploads the file at path. The file is read when the call is made; an error reading it is
// returned by the call, before anything is sent.
func FileFromPath(path string) *File {
	return &File{Filename: filepath.Base(path), path: path}
}

// FileFromBytes uploads data under the given file name.
func FileFromBytes(data []byte, filename string) *File {
	return &File{Filename: filename, data: data, loaded: true}
}

// FileFromReader uploads what r holds, under the given file name. The reader is read to the end on first use
// and kept, so retries and later calls with the same File send the same bytes.
func FileFromReader(r io.Reader, filename string) *File {
	return &File{Filename: filename, reader: r}
}

// content returns the file's bytes.
func (f *File) content() ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case f.loaded:
		return f.data, nil
	case f.reader != nil:
		data, err := io.ReadAll(f.reader)
		if err != nil {
			return nil, fmt.Errorf("reading the file: %w", err)
		}
		f.data, f.loaded, f.reader = data, true, nil
		return data, nil
	case f.path != "":
		data, err := os.ReadFile(f.path)
		if err != nil {
			return nil, fmt.Errorf("reading the file: %w", err)
		}
		return data, nil
	}
	return nil, errors.New("empty File: create one with FileFromPath, FileFromBytes or FileFromReader")
}

func (f *File) name() string {
	if f.Filename == "" {
		return "image"
	}
	return f.Filename
}

// sniffContentType guesses an image's media type from its signature.
func sniffContentType(b []byte) string {
	switch {
	case bytes.HasPrefix(b, []byte{0xff, 0xd8}):
		return "image/jpeg"
	case bytes.HasPrefix(b, []byte{0x89, 'P', 'N', 'G'}):
		return "image/png"
	case bytes.HasPrefix(b, []byte("BM")):
		return "image/bmp"
	case bytes.HasPrefix(b, []byte("RIFF")):
		return "image/webp"
	}
	return "application/octet-stream"
}
