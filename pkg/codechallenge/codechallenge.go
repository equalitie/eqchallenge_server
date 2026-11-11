// Package codechallenge mints and verifies ALTCHA code challenges: a proof of work followed by
// "enter the code from the image" (with audio), as served by ALTCHA Sentinel to the altcha
// widget. It has no HTTP and no global state, so banjax can link it in and every edge mints
// and verifies challenges on its own.
//
// It is stateless apart from the Store: the code's hash is in the signed challenge data, the
// audio URL carries the code encrypted, and a solved challenge yields a signed pass token.
package codechallenge

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/url"
	"strconv"
	"strings"
	"time"

	altcha "github.com/altcha-org/altcha-lib-go/v2"
)

// same proof of work as banjax (internal/altcha_challenge.go)
const powAlgorithm = "PBKDF2/SHA-256"

// keys in the signed challenge data. binding and issued_at mean the same as in banjax.
const (
	dataBinding  = "binding"
	dataIssuedAt = "issued_at"
	dataID       = "eqc_id"
	dataCodeHash = "eqc_code_hash"
)

// Config holds the settings of an Issuer. Zero fields take the defaults below.
type Config struct {
	// Secret signs and encrypts everything. With banjax's HmacSecret the proof of work is
	// signed exactly like banjax's own ALTCHA challenges. Required.
	Secret string
	// CodeLength is the number of digits in the code (default 6).
	CodeLength int
	// TTL is how long a challenge can be solved (default 3 minutes).
	TTL time.Duration
	// PassTTL is how long a pass token is valid (default 1 hour).
	PassTTL time.Duration
	// MaxAttempts is the number of codes accepted per challenge (default 3). The stock widget
	// sends one; this limits clients that post to the verify URL directly.
	MaxAttempts int
	// PoWMaxNumber is the proof of work difficulty (default 1000). Keep it low: a wrong code
	// makes the widget start over with a new challenge, so every typo costs a proof of work.
	PoWMaxNumber int64
	// PoWCost is the PBKDF2 iteration count (default 5000, as in banjax).
	PoWCost int
	// ImageWidth and ImageHeight size the code image (default 240×80).
	ImageWidth, ImageHeight int
	// AudioURL is where the widget fetches the spoken code; the token is added as ?t=.
	// Empty means no audio button.
	AudioURL string
}

const (
	defaultCodeLength   = 6
	defaultTTL          = 3 * time.Minute
	defaultPassTTL      = time.Hour
	defaultMaxAttempts  = 3
	defaultPoWMaxNumber = 1000
	defaultPoWCost      = 5000
	defaultImageWidth   = 240
	defaultImageHeight  = 80
)

// Issuer mints and verifies code challenges. It is safe for concurrent use if its Store is.
type Issuer struct {
	cfg   Config
	keys  keys
	store Store
}

// New returns an Issuer for cfg, keeping attempts and used challenges in store.
func New(cfg Config, store Store) (*Issuer, error) {
	if cfg.Secret == "" {
		return nil, errors.New("codechallenge: empty secret")
	}
	if store == nil {
		return nil, errors.New("codechallenge: nil store")
	}
	if cfg.CodeLength <= 0 {
		cfg.CodeLength = defaultCodeLength
	}
	if cfg.TTL <= 0 {
		cfg.TTL = defaultTTL
	}
	if cfg.PassTTL <= 0 {
		cfg.PassTTL = defaultPassTTL
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = defaultMaxAttempts
	}
	if cfg.PoWMaxNumber <= 0 {
		cfg.PoWMaxNumber = defaultPoWMaxNumber
	}
	if cfg.PoWCost <= 0 {
		cfg.PoWCost = defaultPoWCost
	}
	if cfg.ImageWidth <= 0 {
		cfg.ImageWidth = defaultImageWidth
	}
	if cfg.ImageHeight <= 0 {
		cfg.ImageHeight = defaultImageHeight
	}
	return &Issuer{cfg: cfg, keys: deriveKeys(cfg.Secret), store: store}, nil
}

// CodeChallenge is the widget's codeChallenge field.
type CodeChallenge struct {
	Image  string `json:"image"`           // data: URI of the PNG
	Audio  string `json:"audio,omitempty"` // URL of the spoken code
	Length int    `json:"length"`
}

// Challenge is the JSON the widget gets: an ALTCHA v2 challenge plus codeChallenge.
type Challenge struct {
	Parameters    altcha.ChallengeParameters `json:"parameters"`
	Signature     string                     `json:"signature"`
	CodeChallenge CodeChallenge              `json:"codeChallenge"`
}

// ID identifies the challenge in logs and in Result.ID, so what is recorded when it is
// issued can be joined with how it ended.
func (c Challenge) ID() string {
	id, _ := c.Parameters.Data[dataID].(string)
	return id
}

// Mint creates a challenge bound to binding (the client IP, or whatever the caller binds
// passes to). The code itself is only in the image, the audio token and, hashed, the data.
func (is *Issuer) Mint(binding string) (Challenge, error) {
	code, err := randomDigits(is.cfg.CodeLength)
	if err != nil {
		return Challenge{}, err
	}
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return Challenge{}, err
	}
	id := base64.RawURLEncoding.EncodeToString(idBytes)
	// the counter must be unpredictable, or a client could skip straight to it
	n, err := rand.Int(rand.Reader, big.NewInt(is.cfg.PoWMaxNumber+1))
	if err != nil {
		return Challenge{}, err
	}
	counter := int(n.Int64())
	now := time.Now()
	expiresAt := now.Add(is.cfg.TTL)
	powChallenge, err := altcha.CreateChallenge(altcha.CreateChallengeOptions{
		Algorithm:              powAlgorithm,
		DeriveKey:              altcha.DeriveKeyPBKDF2(),
		Cost:                   is.cfg.PoWCost,
		Counter:                &counter,
		HMACSignatureSecret:    is.keys.powSignature,
		HMACKeySignatureSecret: is.keys.powKeySignature,
		// ExpiresAt MUST be set: VerifySolution only enforces expiry when present
		ExpiresAt: &expiresAt,
		Data: map[string]interface{}{
			dataBinding:  binding,
			dataIssuedAt: strconv.FormatInt(now.UnixMilli(), 10),
			dataID:       id,
			dataCodeHash: is.keys.codeHash(id, code),
		},
	})
	if err != nil {
		return Challenge{}, err
	}
	image, err := renderImageDataURI(id, code, is.cfg.ImageWidth, is.cfg.ImageHeight)
	if err != nil {
		return Challenge{}, err
	}
	cc := CodeChallenge{Image: image, Length: len(code)}
	if is.cfg.AudioURL != "" {
		token, err := is.keys.sealAudio(audioToken{Code: code, ID: id, Binding: binding, Exp: expiresAt.Unix()})
		if err != nil {
			return Challenge{}, err
		}
		cc.Audio = is.cfg.AudioURL + "?t=" + url.QueryEscape(token)
	}
	return Challenge{
		Parameters:    powChallenge.Parameters,
		Signature:     powChallenge.Signature,
		CodeChallenge: cc,
	}, nil
}

// Reason says why Verify refused a code.
type Reason string

const (
	ReasonInvalid         Reason = "invalid"           // bad payload, signature, solution or binding
	ReasonExpired         Reason = "expired"           // the challenge is past its TTL
	ReasonWrongCode       Reason = "wrong_code"        // the code does not match
	ReasonTooManyAttempts Reason = "too_many_attempts" // MaxAttempts codes already tried
	ReasonUsed            Reason = "used"              // the challenge already gave a pass
)

// Result is the outcome of Verify. Verified results carry the pass token, which the widget
// takes as its payload; the caller sends it back as the widget's verify response.
type Result struct {
	Verified bool
	Reason   Reason // set when not verified
	Pass     string // set when verified
	ID       string // the challenge's ID, once its signature checked out
}

// Verify checks the widget's PoW payload and the typed code for a client with binding. An
// error means the request was malformed, not that the client failed; callers that count
// failures (banjax's TooManyFailedChallenges) count every unverified result and every error.
func (is *Issuer) Verify(payloadB64, code, binding string) (Result, error) {
	payload, err := decodePayload(payloadB64)
	if err != nil {
		return Result{Reason: ReasonInvalid}, err
	}
	// every challenge carries a key signature, so this is the HMAC fast path. DeriveKey is
	// nil on purpose, as in banjax: a payload without one fails instead of costing a KDF run.
	res, err := altcha.VerifySolution(altcha.VerifySolutionOptions{
		Challenge:              payload.Challenge,
		Solution:               payload.Solution,
		HMACSignatureSecret:    is.keys.powSignature,
		HMACKeySignatureSecret: is.keys.powKeySignature,
	})
	if err != nil {
		return Result{Reason: ReasonInvalid}, err
	}
	if res.Expired {
		return Result{Reason: ReasonExpired}, nil
	}
	if !res.Verified {
		return Result{Reason: ReasonInvalid}, nil
	}
	data := payload.Challenge.Parameters.Data
	boundTo, _ := data[dataBinding].(string)
	id, _ := data[dataID].(string)
	codeHash, _ := data[dataCodeHash].(string)
	// a plain banjax ALTCHA challenge has no code; it must not count as solved
	if boundTo != binding || id == "" || codeHash == "" {
		return Result{Reason: ReasonInvalid, ID: id}, nil
	}
	until := time.Unix(payload.Challenge.Parameters.ExpiresAt, 0)
	if is.store.CountAttempt(id, until) > is.cfg.MaxAttempts {
		return Result{Reason: ReasonTooManyAttempts, ID: id}, nil
	}
	if !hmac.Equal([]byte(is.keys.codeHash(id, normaliseCode(code))), []byte(codeHash)) {
		return Result{Reason: ReasonWrongCode, ID: id}, nil
	}
	if !is.store.MarkUsed(id, until) {
		return Result{Reason: ReasonUsed, ID: id}, nil
	}
	pass, err := is.keys.signPass(passClaims{
		Binding: binding,
		Kind:    "code",
		ID:      id,
		Exp:     time.Now().Add(is.cfg.PassTTL).Unix(),
	})
	if err != nil {
		return Result{}, err
	}
	return Result{Verified: true, Pass: pass, ID: id}, nil
}

// VerifyPass reports whether pass is a valid, unexpired pass token for binding.
func (is *Issuer) VerifyPass(pass, binding string) bool {
	claims, ok := is.keys.openPass(pass)
	return ok && claims.Kind == "code" && claims.Binding == binding && time.Now().Unix() < claims.Exp
}

// Audio returns the spoken code (WAV) for an audio token from Mint, if it is valid, unexpired
// and bound to binding. lang is the widget's language parameter; unknown languages fall back
// to English.
func (is *Issuer) Audio(token, lang, binding string) ([]byte, error) {
	t, err := is.keys.openAudio(token)
	if err != nil {
		return nil, err
	}
	if t.Binding != binding || time.Now().Unix() >= t.Exp {
		return nil, errors.New("codechallenge: audio token expired or not for this client")
	}
	return renderAudio(is.keys.audioSeed(t.ID), t.Code, lang)
}

// decodePayload reads the widget's v2 payload: base64(JSON{challenge, solution}).
func decodePayload(payloadB64 string) (altcha.Payload, error) {
	var payload altcha.Payload
	decoded, err := base64.StdEncoding.DecodeString(payloadB64)
	if err != nil {
		return payload, err
	}
	err = json.Unmarshal(decoded, &payload)
	return payload, err
}

// normaliseCode drops what people type around a code: spaces and dashes.
func normaliseCode(code string) string {
	return strings.Map(func(r rune) rune {
		if r == ' ' || r == '-' || r == '\t' {
			return -1
		}
		return r
	}, code)
}

// randomDigits returns n uniformly random decimal digits as a string.
func randomDigits(n int) (string, error) {
	var b strings.Builder
	for range n {
		d, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", err
		}
		b.WriteByte(byte('0' + d.Int64()))
	}
	return b.String(), nil
}

// keys are the per-purpose secrets derived from Config.Secret.
type keys struct {
	powSignature    string // ALTCHA challenge signature, = Secret like banjax
	powKeySignature string // ALTCHA key signature, = Secret+"/altcha-key" like banjax
	code            []byte
	audio           []byte // AES-256
	pass            []byte
}

func deriveKeys(secret string) keys {
	derive := func(label string) []byte {
		h := hmac.New(sha256.New, []byte(secret))
		h.Write([]byte("eqchallenge/" + label))
		return h.Sum(nil)
	}
	return keys{
		powSignature:    secret,
		powKeySignature: secret + "/altcha-key",
		code:            derive("code"),
		audio:           derive("audio"),
		pass:            derive("pass"),
	}
}

// codeHash binds the code to one challenge id, so equal codes in different challenges hash
// differently and a known code-hash pair says nothing about another challenge.
func (k keys) codeHash(id, code string) string {
	h := hmac.New(sha256.New, k.code)
	h.Write([]byte(id))
	h.Write([]byte{0})
	h.Write([]byte(code))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
