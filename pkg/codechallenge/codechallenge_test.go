package codechallenge

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	altcha "github.com/altcha-org/altcha-lib-go/v2"
)

const (
	testSecret  = "test-secret-not-for-production"
	testBinding = "192.0.2.10"
)

// newTestIssuer returns an Issuer with a proof of work cheap enough for tests.
func newTestIssuer(t *testing.T) *Issuer {
	t.Helper()
	is, err := New(Config{
		Secret:       testSecret,
		PoWMaxNumber: 5,
		PoWCost:      10,
		AudioURL:     "/eqc/audio",
	}, NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	return is
}

// solve does what the widget does: solve the proof of work and encode the v2 payload.
func solve(t *testing.T, c Challenge) string {
	t.Helper()
	sol, err := altcha.SolveChallenge(altcha.SolveChallengeOptions{
		Challenge: altcha.Challenge{Parameters: c.Parameters, Signature: c.Signature},
		DeriveKey: altcha.DeriveKeyPBKDF2(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return encodePayload(t, altcha.Payload{
		Challenge: altcha.Challenge{Parameters: c.Parameters, Signature: c.Signature},
		Solution:  *sol,
	})
}

func encodePayload(t *testing.T, p altcha.Payload) string {
	t.Helper()
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// audioTokenOf returns the token in the challenge's audio URL.
func audioTokenOf(t *testing.T, c Challenge) string {
	t.Helper()
	u, err := url.Parse(c.CodeChallenge.Audio)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get("t")
}

// codeOf reads the code back from the audio token, which only the Issuer can decrypt.
func codeOf(t *testing.T, is *Issuer, c Challenge) string {
	t.Helper()
	tok, err := is.keys.openAudio(audioTokenOf(t, c))
	if err != nil {
		t.Fatal(err)
	}
	return tok.Code
}

func mint(t *testing.T, is *Issuer) Challenge {
	t.Helper()
	c, err := is.Mint(testBinding)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func wrongCode(code string) string {
	if code[0] == '9' {
		return "0" + code[1:]
	}
	return string(code[0]+1) + code[1:]
}

func assertReason(t *testing.T, res Result, want Reason) {
	t.Helper()
	if res.Verified || res.Reason != want {
		t.Fatalf("got verified=%v reason=%q, want reason %q", res.Verified, res.Reason, want)
	}
}

func TestVerifyGivesPass(t *testing.T) {
	is := newTestIssuer(t)
	c := mint(t, is)
	res, err := is.Verify(solve(t, c), codeOf(t, is, c), testBinding)
	if err != nil || !res.Verified || res.Pass == "" {
		t.Fatalf("got %+v, %v", res, err)
	}
	if res.ID == "" || res.ID != c.ID() {
		t.Fatalf("result ID %q, challenge ID %q", res.ID, c.ID())
	}
	if !is.VerifyPass(res.Pass, testBinding) {
		t.Fatal("pass rejected for its own binding")
	}
	if is.VerifyPass(res.Pass, "198.51.100.7") {
		t.Fatal("pass accepted for another binding")
	}
}

func TestChallengeJSON(t *testing.T) {
	is := newTestIssuer(t)
	c := mint(t, is)
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var widget struct {
		Parameters    map[string]any `json:"parameters"`
		Signature     string         `json:"signature"`
		CodeChallenge map[string]any `json:"codeChallenge"`
	}
	if err := json.Unmarshal(b, &widget); err != nil {
		t.Fatal(err)
	}
	if widget.Signature == "" || widget.Parameters["keySignature"] == nil || widget.Parameters["expiresAt"] == nil {
		t.Fatalf("not a signed v2 challenge with expiry: %s", b)
	}
	if widget.CodeChallenge["length"] != float64(defaultCodeLength) {
		t.Fatalf("codeChallenge.length = %v", widget.CodeChallenge["length"])
	}
	// the code must not leak into what the client sees, except in the image
	code := codeOf(t, is, c)
	withoutImage := strings.Replace(string(b), c.CodeChallenge.Image, "", 1)
	if strings.Contains(withoutImage, code) {
		t.Fatalf("code %s appears in the challenge JSON", code)
	}
}

func TestImage(t *testing.T) {
	is := newTestIssuer(t)
	img := mint(t, is).CodeChallenge.Image
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(img, "data:image/png;base64,"))
	if err != nil || !bytes.HasPrefix(raw, []byte("\x89PNG")) {
		t.Fatalf("not a PNG data URI: %.40s, %v", img, err)
	}
	if len(img) > 15_000 {
		t.Fatalf("image data URI is %d bytes, target is under 15 KB", len(img))
	}
}

func TestWrongCodeThenRight(t *testing.T) {
	is := newTestIssuer(t)
	c := mint(t, is)
	payload, code := solve(t, c), codeOf(t, is, c)
	res, err := is.Verify(payload, wrongCode(code), testBinding)
	if err != nil {
		t.Fatal(err)
	}
	assertReason(t, res, ReasonWrongCode)
	if res, _ := is.Verify(payload, code, testBinding); !res.Verified {
		t.Fatalf("right code after one wrong one: %+v", res)
	}
}

func TestCodeIsNormalised(t *testing.T) {
	is := newTestIssuer(t)
	c := mint(t, is)
	code := codeOf(t, is, c)
	typed := " " + code[:3] + " - " + code[3:] + "\t"
	if res, _ := is.Verify(solve(t, c), typed, testBinding); !res.Verified {
		t.Fatalf("%q not accepted for %q: %+v", typed, code, res)
	}
}

func TestTooManyAttempts(t *testing.T) {
	is := newTestIssuer(t)
	c := mint(t, is)
	payload, code := solve(t, c), codeOf(t, is, c)
	for range defaultMaxAttempts {
		res, _ := is.Verify(payload, wrongCode(code), testBinding)
		assertReason(t, res, ReasonWrongCode)
	}
	res, _ := is.Verify(payload, code, testBinding)
	assertReason(t, res, ReasonTooManyAttempts)
}

func TestReplay(t *testing.T) {
	is := newTestIssuer(t)
	c := mint(t, is)
	payload, code := solve(t, c), codeOf(t, is, c)
	if res, _ := is.Verify(payload, code, testBinding); !res.Verified {
		t.Fatalf("first verify: %+v", res)
	}
	res, _ := is.Verify(payload, code, testBinding)
	assertReason(t, res, ReasonUsed)
}

func TestWrongBinding(t *testing.T) {
	is := newTestIssuer(t)
	c := mint(t, is)
	res, _ := is.Verify(solve(t, c), codeOf(t, is, c), "198.51.100.7")
	assertReason(t, res, ReasonInvalid)
}

func TestExpired(t *testing.T) {
	is := newTestIssuer(t)
	is.cfg.TTL = -time.Minute
	c := mint(t, is)
	res, _ := is.Verify(solve(t, c), codeOf(t, is, c), testBinding)
	assertReason(t, res, ReasonExpired)
}

func TestTamperedData(t *testing.T) {
	is := newTestIssuer(t)
	c := mint(t, is)
	code := codeOf(t, is, c)
	sol, err := altcha.SolveChallenge(altcha.SolveChallengeOptions{
		Challenge: altcha.Challenge{Parameters: c.Parameters, Signature: c.Signature},
		DeriveKey: altcha.DeriveKeyPBKDF2(),
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(p *altcha.ChallengeParameters){
		// a client that picks its own code and hash
		"code hash": func(p *altcha.ChallengeParameters) {
			p.Data[dataCodeHash] = is.keys.codeHash(p.Data[dataID].(string), "000000")
		},
		"binding": func(p *altcha.ChallengeParameters) { p.Data[dataBinding] = "198.51.100.7" },
		"expiry":  func(p *altcha.ChallengeParameters) { p.ExpiresAt += 3600 },
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			params := c.Parameters
			params.Data = map[string]interface{}{}
			for k, v := range c.Parameters.Data {
				params.Data[k] = v
			}
			tamper(&params)
			// round-trip through JSON as the widget does, so the edited data is what is signed
			payload := encodePayload(t, altcha.Payload{
				Challenge: altcha.Challenge{Parameters: params, Signature: c.Signature},
				Solution:  *sol,
			})
			res, _ := is.Verify(payload, code, testBinding)
			if name == "code hash" {
				res2, _ := is.Verify(payload, "000000", testBinding)
				assertReason(t, res2, ReasonInvalid)
			}
			assertReason(t, res, ReasonInvalid)
		})
	}
}

// A plain ALTCHA proof of work signed with the same secret (banjax's own challenge) has no
// code, so it must not pass as a solved code challenge.
func TestPlainPoWIsNotACodeChallenge(t *testing.T) {
	is := newTestIssuer(t)
	counter := 1
	expiresAt := time.Now().Add(time.Minute)
	plain, err := altcha.CreateChallenge(altcha.CreateChallengeOptions{
		Algorithm:              powAlgorithm,
		DeriveKey:              altcha.DeriveKeyPBKDF2(),
		Cost:                   10,
		Counter:                &counter,
		HMACSignatureSecret:    testSecret,
		HMACKeySignatureSecret: testSecret + "/altcha-key",
		ExpiresAt:              &expiresAt,
		Data:                   map[string]interface{}{dataBinding: testBinding},
	})
	if err != nil {
		t.Fatal(err)
	}
	payload := solve(t, Challenge{Parameters: plain.Parameters, Signature: plain.Signature})
	res, _ := is.Verify(payload, "123456", testBinding)
	assertReason(t, res, ReasonInvalid)
}

func TestMalformedPayload(t *testing.T) {
	is := newTestIssuer(t)
	for _, payload := range []string{"", "not base64!", base64.StdEncoding.EncodeToString([]byte("{"))} {
		res, err := is.Verify(payload, "123456", testBinding)
		if err == nil || res.Verified {
			t.Fatalf("payload %q: got %+v, %v", payload, res, err)
		}
	}
}

func TestOtherSecret(t *testing.T) {
	is := newTestIssuer(t)
	other, err := New(Config{Secret: "another-secret", PoWMaxNumber: 5, PoWCost: 10}, NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	c := mint(t, is)
	res, _ := other.Verify(solve(t, c), codeOf(t, is, c), testBinding)
	assertReason(t, res, ReasonInvalid)
}

func TestAudio(t *testing.T) {
	is := newTestIssuer(t)
	c := mint(t, is)
	token := audioTokenOf(t, c)
	for _, lang := range []string{"en", "ru", "pt-BR", "xx", ""} {
		wav, err := is.Audio(token, lang, testBinding)
		if err != nil || !bytes.HasPrefix(wav, []byte("RIFF")) {
			t.Fatalf("lang %q: not a WAV: %v", lang, err)
		}
	}
	if _, err := is.Audio(token, "en", "198.51.100.7"); err == nil {
		t.Fatal("audio served to another binding")
	}
	tampered := []byte(token)
	tampered[len(tampered)/2] ^= 1
	if _, err := is.Audio(string(tampered), "en", testBinding); err == nil {
		t.Fatal("tampered audio token accepted")
	}
}

func TestNoAudioURL(t *testing.T) {
	is, err := New(Config{Secret: testSecret, PoWMaxNumber: 5, PoWCost: 10}, NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	if a := mint(t, is).CodeChallenge.Audio; a != "" {
		t.Fatalf("audio URL %q without Config.AudioURL", a)
	}
}

func TestPassTampered(t *testing.T) {
	is := newTestIssuer(t)
	c := mint(t, is)
	res, _ := is.Verify(solve(t, c), codeOf(t, is, c), testBinding)
	body, sig, _ := strings.Cut(res.Pass, ".")
	forged, _ := is.keys.signPass(passClaims{Binding: "198.51.100.7", Kind: "code", Exp: time.Now().Add(time.Hour).Unix()})
	forgedBody, _, _ := strings.Cut(forged, ".")
	for _, pass := range []string{"", "x", body, body + ".", forgedBody + "." + sig, res.Pass + "x"} {
		if is.VerifyPass(pass, testBinding) || is.VerifyPass(pass, "198.51.100.7") {
			t.Fatalf("pass %q accepted", pass)
		}
	}
	expired, _ := is.keys.signPass(passClaims{Binding: testBinding, Kind: "code", Exp: time.Now().Add(-time.Second).Unix()})
	if is.VerifyPass(expired, testBinding) {
		t.Fatal("expired pass accepted")
	}
}

func TestNewValidates(t *testing.T) {
	if _, err := New(Config{}, NewMemoryStore()); err == nil {
		t.Fatal("empty secret accepted")
	}
	if _, err := New(Config{Secret: testSecret}, nil); err == nil {
		t.Fatal("nil store accepted")
	}
}

func TestAudioMix(t *testing.T) {
	k := deriveKeys(testSecret)
	seed := k.audioSeed("challenge-1")
	a, err := renderAudio(seed, "123456", "ru")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := renderAudio(seed, "123456", "ru")
	if !bytes.Equal(a, b) {
		t.Fatal("same seed, different audio: replays would let a client average the noise")
	}
	c, _ := renderAudio(k.audioSeed("challenge-2"), "123456", "ru")
	if bytes.Equal(a, c) {
		t.Fatal("different challenges, same audio")
	}
	if string(a[:4]) != "RIFF" || string(a[8:16]) != "WAVEfmt " || string(a[36:40]) != "data" {
		t.Fatal("bad WAV header")
	}
	// two readings of six digits with pauses: long enough to follow, short enough to bear
	if secs := float64(len(a)-44) / 2 / audioSampleRate; secs < 8 || secs > 25 {
		t.Fatalf("audio is %.1f s", secs)
	}
	if _, err := renderAudio(seed, "12a456", "en"); err == nil {
		t.Fatal("non-digit code rendered")
	}
}
