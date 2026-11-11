// Command demo wires pkg/codechallenge to HTTP so the whole flow can be shown and bot-tested
// without banjax. It is a prototype test bed, not a production component: in production
// banjax links the package in and serves these routes itself.
//
//	GET  /               home page
//	GET  /protected      200 with a valid pass cookie, otherwise the challenge page
//	GET  /reset          drops the pass cookie
//	GET  /eqc/challenge  proof of work + codeChallenge, for the widget
//	GET  /eqc/audio?t=   the spoken code
//	POST /eqc/verify     checks the code, sets the pass cookie
//
// Config from env: EQC_SECRET (random per start if unset), EQC_LISTEN (default :8080),
// EQC_CODE_LENGTH, EQC_TTL_SECONDS, EQC_PASS_TTL_SECONDS, EQC_POW_MAX_NUMBER.
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/equalitie/eqchallenge_server/pkg/codechallenge"
	"github.com/equalitie/eqchallenge_server/web"
)

const passCookie = "eqc_pass"

func main() {
	secret := os.Getenv("EQC_SECRET")
	if secret == "" {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			log.Fatal(err)
		}
		secret = base64.RawURLEncoding.EncodeToString(b)
		log.Print("EQC_SECRET unset: using a random secret, passes end with this process")
	}
	cfg := codechallenge.Config{
		Secret:       secret,
		CodeLength:   envInt("EQC_CODE_LENGTH"),
		TTL:          time.Duration(envInt("EQC_TTL_SECONDS")) * time.Second,
		PassTTL:      time.Duration(envInt("EQC_PASS_TTL_SECONDS")) * time.Second,
		PoWMaxNumber: int64(envInt("EQC_POW_MAX_NUMBER")),
		AudioURL:     "/eqc/audio",
	}
	issuer, err := codechallenge.New(cfg, codechallenge.NewMemoryStore())
	if err != nil {
		log.Fatal(err)
	}
	addr := os.Getenv("EQC_LISTEN")
	if addr == "" {
		addr = ":8080"
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           newMux(issuer),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("listening on %s", addr)
	log.Fatal(srv.ListenAndServe())
}

// envInt reads a positive int from env; unset or invalid means 0, the package default.
func envInt(name string) int {
	v := os.Getenv(name)
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		log.Fatalf("%s: want a non-negative integer, got %q", name, v)
	}
	return n
}

func newMux(issuer *codechallenge.Issuer) *http.ServeMux {
	mux := http.NewServeMux()
	hasPass := func(r *http.Request) bool {
		c, err := r.Cookie(passCookie)
		return err == nil && issuer.VerifyPass(c.Value, clientBinding(r))
	}

	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		render(w, http.StatusOK, "index.html", map[string]any{"HasPass": hasPass(r)})
	})

	mux.HandleFunc("GET /protected", func(w http.ResponseWriter, r *http.Request) {
		if hasPass(r) {
			render(w, http.StatusOK, "granted.html", nil)
			return
		}
		widgetConfig, _ := json.Marshal(map[string]any{
			"verifyUrl":  "/eqc/verify",
			"language":   widgetLanguage(r),
			"hideFooter": true,
			"hideLogo":   true,
		})
		// 429 like banjax's challenge pages
		render(w, http.StatusTooManyRequests, "challenge.html", map[string]any{
			"Widget":       web.Widget,
			"WidgetConfig": string(widgetConfig),
		})
	})

	mux.HandleFunc("GET /reset", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: passCookie, Value: "", Path: "/", MaxAge: -1})
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})

	mux.HandleFunc("GET /eqc/challenge", func(w http.ResponseWriter, r *http.Request) {
		c, err := issuer.Mint(clientBinding(r))
		if err != nil {
			log.Printf("mint: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "cannot create a challenge"})
			return
		}
		writeJSON(w, http.StatusOK, c)
	})

	mux.HandleFunc("GET /eqc/audio", func(w http.ResponseWriter, r *http.Request) {
		wav, err := issuer.Audio(r.URL.Query().Get("t"), r.URL.Query().Get("language"), clientBinding(r))
		if err != nil {
			http.Error(w, "audio expired, load a new challenge", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "audio/wav")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(wav)
	})

	mux.HandleFunc("POST /eqc/verify", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Code    string `json:"code"`
			Payload string `json:"payload"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
			return
		}
		res, err := issuer.Verify(req.Payload, req.Code, clientBinding(r))
		if err != nil {
			log.Printf("verify: malformed request: %v", err)
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
			return
		}
		if !res.Verified {
			log.Printf("verify: %s", res.Reason)
			writeJSON(w, http.StatusOK, map[string]any{"verified": false, "reason": reasonText[res.Reason]})
			return
		}
		log.Print("verify: passed")
		http.SetCookie(w, &http.Cookie{
			Name:     passCookie,
			Value:    res.Pass,
			Path:     "/",
			HttpOnly: true,
			Secure:   r.TLS != nil,
			SameSite: http.SameSiteLaxMode,
		})
		writeJSON(w, http.StatusOK, map[string]any{"verified": true, "payload": res.Pass})
	})
	return mux
}

// reasonText is what the widget shows; it says what to do next.
var reasonText = map[codechallenge.Reason]string{
	codechallenge.ReasonWrongCode:       "Wrong code. Try again with a new image.",
	codechallenge.ReasonExpired:         "The image expired. Try again with a new one.",
	codechallenge.ReasonTooManyAttempts: "Too many attempts. Try again with a new image.",
	codechallenge.ReasonUsed:            "This image was already used. Try again with a new one.",
	codechallenge.ReasonInvalid:         "Verification failed. Reload the page.",
}

// widgetLanguage is the widget's UI language, which the widget also asks the audio in: ?lang=
// if given, otherwise the visitor's first Accept-Language. The widget falls back to English
// for languages it has no strings for, and the audio for languages it has no voice for.
// Without it the widget would take <html lang>, the language of the page text.
func widgetLanguage(r *http.Request) string {
	if lang := r.URL.Query().Get("lang"); lang != "" {
		return lang
	}
	first, _, _ := strings.Cut(r.Header.Get("Accept-Language"), ",")
	tag, _, _ := strings.Cut(first, ";")
	return strings.TrimSpace(tag)
}

// clientBinding is what challenges and passes are bound to: the client IP. The demo is
// reached directly, so RemoteAddr is the client; behind a proxy it would be a header the
// proxy sets, as banjax reads X-Client-IP from nginx.
func clientBinding(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func render(w http.ResponseWriter, status int, page string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := web.Pages[page].ExecuteTemplate(w, "layout", data); err != nil {
		log.Printf("render %s: %v", page, err)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("write json: %v", err)
	}
}
