package codechallenge

import (
	"crypto/hmac"
	"crypto/sha256"
	"embed"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"strings"
)

// The spoken digits are the recordings from github.com/dchest/captcha (MIT, see
// sounds/LICENSE-dchest-captcha): 8 kHz, 8-bit mono WAV, one file per digit and language.
// dchest's own mixer buries them under about five reversed digits at once, at nearly the
// level of the code, which people can't follow either. This mixer keeps the speech clear:
// speech-to-text solves audio captchas whatever the noise, so noise mostly hurts the people
// who need audio, and its job here is only to keep the file from being a plain lookup.

//go:embed sounds/*/*.wav sounds/beep.wav
var soundFiles embed.FS

const audioSampleRate = 8000

// audio mix, as fractions of full scale; the digits are normalised to digitPeak
const (
	digitPeak      = 0.8
	noiseLevel     = 0.02 // white noise under everything
	babbleLevel    = 0.12 // reversed digits in the background, at most one at a time
	babblePerSec   = 1.5  // how often a background digit starts
	minDigitGap    = 0.6  // seconds between digits
	maxDigitGap    = 1.0  // seconds between digits
	repeatGap      = 1.5  // seconds between the two readings of the code
	minDigitSpeed  = 0.95 // playback speed of each digit
	maxDigitSpeed  = 1.05 // playback speed of each digit
	leadInSeconds  = 0.4  // silence after the opening beep
	tailSeconds    = 0.5  // after the last digit
	beepLevel      = 0.35 // the opening beep
	audioLanguages = "en ru ja zh pt"
)

// digitSounds maps a language to its ten digit recordings as samples in [-1, 1].
var digitSounds, beepSound = mustLoadSounds()

func mustLoadSounds() (map[string][10][]float64, []float64) {
	sounds := map[string][10][]float64{}
	for _, lang := range strings.Fields(audioLanguages) {
		var digits [10][]float64
		for d := range 10 {
			s, err := loadWAV(fmt.Sprintf("sounds/%s/%d.wav", lang, d))
			if err != nil {
				panic(err)
			}
			digits[d] = normalise(s, digitPeak)
		}
		sounds[lang] = digits
	}
	beep, err := loadWAV("sounds/beep.wav")
	if err != nil {
		panic(err)
	}
	return sounds, normalise(beep, beepLevel)
}

// loadWAV reads an 8 kHz 8-bit mono PCM WAV file as samples in [-1, 1].
func loadWAV(name string) ([]float64, error) {
	b, err := soundFiles.ReadFile(name)
	if err != nil {
		return nil, err
	}
	if len(b) < 12 || string(b[:4]) != "RIFF" || string(b[8:12]) != "WAVE" {
		return nil, fmt.Errorf("%s: not a WAV file", name)
	}
	for p := 12; p+8 <= len(b); {
		id, size := string(b[p:p+4]), int(binary.LittleEndian.Uint32(b[p+4:p+8]))
		p += 8
		if p+size > len(b) {
			size = len(b) - p
		}
		if id == "fmt " {
			if size < 16 || binary.LittleEndian.Uint16(b[p+2:]) != 1 ||
				binary.LittleEndian.Uint32(b[p+4:]) != audioSampleRate || binary.LittleEndian.Uint16(b[p+14:]) != 8 {
				return nil, fmt.Errorf("%s: want 8 kHz 8-bit mono", name)
			}
		}
		if id == "data" {
			s := make([]float64, size)
			for i, v := range b[p : p+size] {
				s[i] = (float64(v) - 128) / 128
			}
			return s, nil
		}
		p += size + size%2
	}
	return nil, errors.New(name + ": no data chunk")
}

// normalise scales s so its peak is peak.
func normalise(s []float64, peak float64) []float64 {
	m := 0.0
	for _, v := range s {
		m = max(m, math.Abs(v))
	}
	out := make([]float64, len(s))
	if m == 0 {
		return out
	}
	for i, v := range s {
		out[i] = v * peak / m
	}
	return out
}

// renderAudio speaks code twice as a 16-bit WAV file in lang ("en", "ru", "ja", "zh", "pt";
// a region such as "pt-BR" is ignored, anything else falls back to English). The output is
// the same for the same seed, so replaying a challenge does not let a client average the
// noise away.
func renderAudio(seed [32]byte, code, lang string) ([]byte, error) {
	lang, _, _ = strings.Cut(strings.ToLower(lang), "-")
	digits, ok := digitSounds[lang]
	if !ok {
		digits = digitSounds["en"]
	}
	rng := rand.New(rand.NewChaCha8(seed))
	between := func(lo, hi float64) float64 { return lo + rng.Float64()*(hi-lo) }
	seconds := func(s float64) int { return int(s * audioSampleRate) }

	// lay out the speech: beep, the code, a pause, the code again
	var speech []float64
	speech = append(speech, beepSound...)
	speech = append(speech, make([]float64, seconds(leadInSeconds))...)
	for reading := range 2 {
		if reading > 0 {
			speech = append(speech, make([]float64, seconds(repeatGap))...)
		}
		for i := range len(code) {
			d := code[i] - '0'
			if d > 9 {
				return nil, fmt.Errorf("codechallenge: audio for non-digit %q", code[i])
			}
			if i > 0 {
				speech = append(speech, make([]float64, seconds(between(minDigitGap, maxDigitGap)))...)
			}
			speech = append(speech, resample(digits[d], between(minDigitSpeed, maxDigitSpeed))...)
		}
	}
	speech = append(speech, make([]float64, seconds(tailSeconds))...)

	// background: quiet white noise and now and then a reversed digit, never overlapping
	mix := speech
	for i := range mix {
		mix[i] += (rng.Float64()*2 - 1) * noiseLevel
	}
	for pos := seconds(between(0, 1/babblePerSec)); pos < len(mix); {
		b := reversed(digits[rng.IntN(10)])
		for i, v := range b {
			if pos+i < len(mix) {
				mix[pos+i] += v / digitPeak * babbleLevel
			}
		}
		pos += len(b) + seconds(between(0.5, 1.5)/babblePerSec)
	}
	return encodeWAV16(mix), nil
}

// audioSeed derives the mixer's seed from the challenge id, under a key the client lacks.
func (k keys) audioSeed(id string) [32]byte {
	h := hmac.New(sha256.New, k.audio)
	h.Write([]byte("seed\x00" + id))
	var seed [32]byte
	copy(seed[:], h.Sum(nil))
	return seed
}

// resample plays s at speed (above 1 is faster and higher), with linear interpolation.
func resample(s []float64, speed float64) []float64 {
	n := int(float64(len(s)) / speed)
	out := make([]float64, n)
	for i := range out {
		x := float64(i) * speed
		j := int(x)
		if j+1 >= len(s) {
			out[i] = s[len(s)-1]
			continue
		}
		f := x - float64(j)
		out[i] = s[j]*(1-f) + s[j+1]*f
	}
	return out
}

func reversed(s []float64) []float64 {
	out := make([]float64, len(s))
	for i, v := range s {
		out[len(s)-1-i] = v
	}
	return out
}

// encodeWAV16 writes samples in [-1, 1] as an 8 kHz 16-bit mono PCM WAV file, clipping
// anything outside.
func encodeWAV16(s []float64) []byte {
	dataLen := uint32(2 * len(s))
	b := make([]byte, 0, 44+dataLen)
	b = append(b, "RIFF"...)
	b = binary.LittleEndian.AppendUint32(b, 36+dataLen)
	b = append(b, "WAVEfmt "...)
	b = binary.LittleEndian.AppendUint32(b, 16)                // fmt chunk size
	b = binary.LittleEndian.AppendUint16(b, 1)                 // PCM
	b = binary.LittleEndian.AppendUint16(b, 1)                 // mono
	b = binary.LittleEndian.AppendUint32(b, audioSampleRate)   // sample rate
	b = binary.LittleEndian.AppendUint32(b, audioSampleRate*2) // byte rate
	b = binary.LittleEndian.AppendUint16(b, 2)                 // block align
	b = binary.LittleEndian.AppendUint16(b, 16)                // bits per sample
	b = append(b, "data"...)
	b = binary.LittleEndian.AppendUint32(b, dataLen)
	for _, v := range s {
		b = binary.LittleEndian.AppendUint16(b, uint16(int16(math.Round(max(-1, min(1, v))*math.MaxInt16))))
	}
	return b
}
