package codechallenge

import (
	"bytes"
	"encoding/base64"
	"image/color"

	"github.com/dchest/captcha"
)

// The prototype draws the image with github.com/dchest/captcha: digits only, and a style OCR
// tools may already know. SPEC.md section 4.4 has the plan for our own renderer if it fails
// the OCR test. Audio has its own mixer (audio.go).

// renderImageDataURI draws code as a PNG and returns it as a data: URI, so the challenge
// page needs no second request for the image.
func renderImageDataURI(id, code string, width, height int) (string, error) {
	img := captcha.NewImage(id, digitValues(code), width, height)
	// dchest leaves the background transparent, which is unreadable on a dark page
	img.Palette[0] = color.White
	var buf bytes.Buffer
	if _, err := img.WriteTo(&buf); err != nil {
		return "", err
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

// digitValues turns "4821" into {4, 8, 2, 1}, the form dchest/captcha takes.
func digitValues(code string) []byte {
	d := make([]byte, len(code))
	for i := range len(code) {
		d[i] = code[i] - '0'
	}
	return d
}
