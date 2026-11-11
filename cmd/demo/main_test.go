package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	altcha "github.com/altcha-org/altcha-lib-go/v2"

	"github.com/equalitie/eqchallenge_server/pkg/codechallenge"
)

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	return newRecordingServer(t, nil)
}

func newRecordingServer(t *testing.T, rec *recorder) *httptest.Server {
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
	srv := httptest.NewServer(newMux(issuer, rec))
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
	for _, want := range []string{`challenge="/eqc/challenge"`, `auto="off"`, "verifyFunction", "/eqc/verify", "customElements.define"} {
		if !bytes.Contains(body, []byte(want)) {
			t.Fatalf("challenge page lacks %q", want)
		}
	}
}

const testHIS = `{"his":{"focus":[[0,0,4,0]],"maxTouchPoints":0,"pointer":[[10,10,900],[40,22,950],[90,30,1010],[120,31,1100]],"scroll":[],"time":1762800000000,"touch":[]}}`

func postJSON(t *testing.T, url, body string) (*http.Response, []byte) {
	t.Helper()
	resp, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

// fetchChallenge does what the widget does: GET the challenge URL, get asked for the HIS,
// post it, take the challenge.
func fetchChallenge(t *testing.T, srv *httptest.Server) codechallenge.Challenge {
	t.Helper()
	resp, body := get(t, srv.URL+"/eqc/challenge")
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "/json") {
		t.Fatalf("challenge content type %q: the widget needs JSON", ct)
	}
	var ask struct {
		HIS struct {
			URL string `json:"url"`
		} `json:"his"`
	}
	if err := json.Unmarshal(body, &ask); err != nil || ask.HIS.URL == "" {
		t.Fatalf("no HIS request: %s", body)
	}
	resp, body = postJSON(t, srv.URL+ask.HIS.URL, testHIS)
	if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Header.Get("Content-Type"), "/json") {
		t.Fatalf("HIS: status %d", resp.StatusCode)
	}
	var c codechallenge.Challenge
	if err := json.Unmarshal(body, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestBadHIS(t *testing.T) {
	srv := newTestServer(t)
	for _, body := range []string{"", "{}", `{"his":{"pointer":"x"}}`} {
		if resp, _ := postJSON(t, srv.URL+"/eqc/his", body); resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("HIS %q: status %d", body, resp.StatusCode)
		}
	}
}

// TestWidgetFlow does what the widget does: fetch, solve, post a code. The code is only in
// the image, so this checks the wrong-code path; pkg/codechallenge tests the right one.
func TestWidgetFlow(t *testing.T) {
	srv := newTestServer(t)
	c := fetchChallenge(t, srv)
	if c.CodeChallenge.Image == "" || c.CodeChallenge.Audio == "" {
		t.Fatalf("no codeChallenge: %+v", c.CodeChallenge)
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

func TestRecording(t *testing.T) {
	path := t.TempDir() + "/features.jsonl"
	rec, err := openRecorder(path, "test", false)
	if err != nil {
		t.Fatal(err)
	}
	srv := newRecordingServer(t, rec)
	c := fetchChallenge(t, srv)
	ac := altcha.Challenge{Parameters: c.Parameters, Signature: c.Signature}
	sol, err := altcha.SolveChallenge(altcha.SolveChallengeOptions{Challenge: ac, DeriveKey: altcha.DeriveKeyPBKDF2()})
	if err != nil {
		t.Fatal(err)
	}
	p, _ := json.Marshal(altcha.Payload{Challenge: ac, Solution: *sol})
	req, _ := json.Marshal(map[string]any{
		"code":     "000000x",
		"payload":  base64.StdEncoding.EncodeToString(p),
		"behavior": map[string]any{"shown_ms": 4100, "keys": 6, "key_gaps_ms": []int{200, 180, 260, 150, 210}},
	})
	postJSON(t, srv.URL+"/eqc/verify", string(req))

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 2 {
		t.Fatalf("want an issued and a verify line, got:\n%s", raw)
	}
	var issued, verify map[string]any
	json.Unmarshal([]byte(lines[0]), &issued)
	json.Unmarshal([]byte(lines[1]), &verify)
	if issued["event"] != "issued" || verify["event"] != "verify" || issued["id"] != c.ID() || verify["id"] != c.ID() {
		t.Fatalf("lines not joined by challenge id:\n%s", raw)
	}
	if issued["label"] != "test" || issued["his"].(map[string]any)["pointer_n"] != float64(4) || issued["his_raw"] != nil {
		t.Fatalf("issued line: %s", lines[0])
	}
	if verify["result"] != "wrong_code" || verify["code_step"].(map[string]any)["keys"] != float64(6) {
		t.Fatalf("verify line: %s", lines[1])
	}
	for _, private := range []string{"127.0.0.1", "Go-http-client", "000000"} {
		if strings.Contains(string(raw), private) {
			t.Fatalf("recorded %q:\n%s", private, raw)
		}
	}
}
