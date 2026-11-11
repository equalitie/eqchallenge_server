package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	altcha "github.com/altcha-org/altcha-lib-go/v2"

	"github.com/equalitie/eqchallenge_server/pkg/codechallenge"
)

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	issuer, err := codechallenge.New(codechallenge.Config{
		Secret:       "test-secret-not-for-production",
		PoWMaxNumber: 5,
		PoWCost:      10,
		AudioURL:     "/eqc/audio",
	}, codechallenge.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(newMux(issuer))
	t.Cleanup(srv.Close)
	return srv
}

func get(t *testing.T, url string) (*http.Response, []byte) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, body
}

func TestProtectedShowsChallenge(t *testing.T) {
	srv := newTestServer(t)
	resp, body := get(t, srv.URL+"/protected")
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status %d", resp.StatusCode)
	}
	for _, want := range []string{`challenge="/eqc/challenge"`, "verifyUrl", "/eqc/verify", "customElements.define"} {
		if !bytes.Contains(body, []byte(want)) {
			t.Fatalf("challenge page lacks %q", want)
		}
	}
}

// TestWidgetFlow does what the widget does: fetch, solve, post a code. The code is only in
// the image, so this checks the wrong-code path; pkg/codechallenge tests the right one.
func TestWidgetFlow(t *testing.T) {
	srv := newTestServer(t)
	resp, body := get(t, srv.URL+"/eqc/challenge")
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "/json") {
		t.Fatalf("challenge content type %q: the widget needs JSON", ct)
	}
	var c codechallenge.Challenge
	if err := json.Unmarshal(body, &c); err != nil {
		t.Fatal(err)
	}
	if c.CodeChallenge.Image == "" || c.CodeChallenge.Audio == "" {
		t.Fatalf("no codeChallenge: %s", body)
	}

	audio, wav := get(t, srv.URL+c.CodeChallenge.Audio+"&language=ru")
	if audio.StatusCode != http.StatusOK || !bytes.HasPrefix(wav, []byte("RIFF")) {
		t.Fatalf("audio: status %d", audio.StatusCode)
	}

	ac := altcha.Challenge{Parameters: c.Parameters, Signature: c.Signature}
	sol, err := altcha.SolveChallenge(altcha.SolveChallengeOptions{Challenge: ac, DeriveKey: altcha.DeriveKeyPBKDF2()})
	if err != nil {
		t.Fatal(err)
	}
	p, _ := json.Marshal(altcha.Payload{Challenge: ac, Solution: *sol})
	req, _ := json.Marshal(map[string]string{"code": "abcdef", "payload": base64.StdEncoding.EncodeToString(p)})
	vresp, err := http.Post(srv.URL+"/eqc/verify", "application/json", bytes.NewReader(req))
	if err != nil {
		t.Fatal(err)
	}
	defer vresp.Body.Close()
	var v struct {
		Verified bool   `json:"verified"`
		Reason   string `json:"reason"`
	}
	if err := json.NewDecoder(vresp.Body).Decode(&v); err != nil {
		t.Fatal(err)
	}
	if v.Verified || v.Reason != reasonText[codechallenge.ReasonWrongCode] || len(vresp.Cookies()) != 0 {
		t.Fatalf("wrong code: got %+v, cookies %v", v, vresp.Cookies())
	}
}

func TestVerifyBadRequest(t *testing.T) {
	srv := newTestServer(t)
	for _, body := range []string{"", "{", `{"code":"1","payload":"x"}`} {
		resp, err := http.Post(srv.URL+"/eqc/verify", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("body %q: status %d", body, resp.StatusCode)
		}
	}
}

func TestForgedPassCookie(t *testing.T) {
	srv := newTestServer(t)
	req, _ := http.NewRequest("GET", srv.URL+"/protected", nil)
	req.AddCookie(&http.Cookie{Name: passCookie, Value: "eyJiIjoiMTI3LjAuMC4xIn0.AAAA"})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("forged pass: status %d", resp.StatusCode)
	}
}

func TestWidgetLanguage(t *testing.T) {
	cases := []struct{ query, accept, want string }{
		{"", "ru-RU,ru;q=0.9,en;q=0.8", "ru-RU"},
		{"", "fa;q=0.9", "fa"},
		{"", "", ""},
		{"lang=pt", "ru", "pt"},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/protected?"+c.query, nil)
		r.Header.Set("Accept-Language", c.accept)
		if got := widgetLanguage(r); got != c.want {
			t.Errorf("?%s, Accept-Language %q: got %q, want %q", c.query, c.accept, got, c.want)
		}
	}
}
