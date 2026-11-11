package codechallenge

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

// audioToken is what the audio URL carries, encrypted: the client must not read the code
// from it, and the audio endpoint needs no state to render it.
type audioToken struct {
	Code    string `json:"c"`
	ID      string `json:"i"`
	Binding string `json:"b"`
	Exp     int64  `json:"e"` // unix seconds, the challenge's expiry
}

// additional data for AES-GCM, so a sealed token is only ever accepted as an audio token
var audioAAD = []byte("eqchallenge/audio/v1")

// sealAudio returns base64url(nonce || AES-GCM(token)).
func (k keys) sealAudio(t audioToken) (string, error) {
	plain, err := json.Marshal(t)
	if err != nil {
		return "", err
	}
	aead, err := newGCM(k.audio)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plain)+aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(aead.Seal(nonce, nonce, plain, audioAAD)), nil
}

func (k keys) openAudio(token string) (audioToken, error) {
	var t audioToken
	sealed, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return t, err
	}
	aead, err := newGCM(k.audio)
	if err != nil {
		return t, err
	}
	if len(sealed) < aead.NonceSize() {
		return t, errors.New("codechallenge: short audio token")
	}
	plain, err := aead.Open(nil, sealed[:aead.NonceSize()], sealed[aead.NonceSize():], audioAAD)
	if err != nil {
		return t, err
	}
	err = json.Unmarshal(plain, &t)
	return t, err
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// passClaims are the signed contents of a pass token.
type passClaims struct {
	Binding string `json:"b"`
	Kind    string `json:"k"` // "code"; leaves room for other interactive challenges
	ID      string `json:"i"` // the solved challenge
	Exp     int64  `json:"e"` // unix seconds
}

// signPass returns base64url(claims JSON) + "." + base64url(HMAC). Only cookie-safe
// characters, so it survives as a cookie value without escaping.
func (k keys) signPass(c passClaims) (string, error) {
	body, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(body)
	return encoded + "." + base64.RawURLEncoding.EncodeToString(k.passMAC(encoded)), nil
}

func (k keys) openPass(pass string) (passClaims, bool) {
	var c passClaims
	encoded, sig, ok := strings.Cut(pass, ".")
	if !ok {
		return c, false
	}
	mac, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || !hmac.Equal(mac, k.passMAC(encoded)) {
		return c, false
	}
	body, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || json.Unmarshal(body, &c) != nil {
		return c, false
	}
	return c, true
}

func (k keys) passMAC(encoded string) []byte {
	h := hmac.New(sha256.New, k.pass)
	h.Write([]byte(encoded))
	return h.Sum(nil)
}
