// Command demo wires pkg/codechallenge to HTTP so the whole flow can be shown and bot-tested
// without banjax. It is a prototype test bed, not a production component: in production
// banjax links the package in and serves these routes itself.
//
//	GET  /               home page
//	GET  /protected      200 with a valid pass cookie, otherwise the challenge page
//	GET  /reset          drops the pass cookie
//	GET  /baskerville.gif  the dog on the challenge page
//	GET  /eqc/challenge  asks the widget for its human interaction signature (HIS)
//	POST /eqc/his        takes the HIS, returns proof of work + codeChallenge
//	GET  /eqc/audio?t=   the spoken code
//	POST /eqc/verify     checks the code, sets the pass cookie
//
// Config from env: EQC_SECRET (random per start if unset), EQC_LISTEN (default :8080),
// EQC_CODE_LENGTH, EQC_TTL_SECONDS, EQC_PASS_TTL_SECONDS, EQC_POW_MAX_NUMBER.
// Behaviour recording: EQC_FEATURES_FILE (JSONL, off if unset), EQC_LABEL (written on every
// line, e.g. "human" or "bot-headless"), EQC_FEATURES_RAW=1 (also the raw HIS traces),
// EQC_DEMO_SHOW_FEATURES=1 (show visitors their own features; demo only, it helps bots tune).
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/equalitie/eqchallenge_server/pkg/behavior"
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
	rec, err := openRecorder(os.Getenv("EQC_FEATURES_FILE"), os.Getenv("EQC_LABEL"), os.Getenv("EQC_FEATURES_RAW") == "1")
	if err != nil {
		log.Fatal(err)
	}
	if rec != nil {
		log.Printf("recording behaviour features to %s, label %q", os.Getenv("EQC_FEATURES_FILE"), os.Getenv("EQC_LABEL"))
	}
	addr := os.Getenv("EQC_LISTEN")
	if addr == "" {
		addr = ":8080"
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           newMux(issuer, rec, os.Getenv("EQC_DEMO_SHOW_FEATURES") == "1"),
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

// newMux serves the demo. showFeatures sends clients the behaviour features computed from
// what they sent, for the demo page to show; never do that in production.
func newMux(issuer *codechallenge.Issuer, rec *recorder, showFeatures bool) *http.ServeMux {
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
		// no verifyUrl: the page's verifyFunction posts the code with its code step features
		widgetConfig, _ := json.Marshal(map[string]any{
			"language":   widgetLanguage(r),
			"hideFooter": true,
			"hideLogo":   true,
		})
		// 429 like banjax's challenge pages
		render(w, http.StatusTooManyRequests, "challenge.html", map[string]any{
			"Widget":       web.Widget,
			"WidgetConfig": string(widgetConfig),
			"ShowFeatures": showFeatures,
		})
	})

	mux.HandleFunc("GET /baskerville.gif", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/gif")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.Write(web.Baskerville)
	})

	mux.HandleFunc("GET /reset", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: passCookie, Value: "", Path: "/", MaxAge: -1})
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})

	// The widget answers {"his": {"url": ...}} by posting its human interaction signature
	// there and taking the challenge from the response. This is where a score would choose
	// the challenge (PoW only, PoW + code, harder PoW); for now every client gets the code and
	// the features are only recorded.
	mux.HandleFunc("GET /eqc/challenge", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"his": map[string]string{"url": "/eqc/his"}})
	})

	mux.HandleFunc("POST /eqc/his", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 256<<10))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
			return
		}
		his, err := behavior.ParseHIS(body)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
			return
		}
		c, err := issuer.Mint(clientBinding(r))
		if err != nil {
			log.Printf("mint: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "cannot create a challenge"})
			return
		}
		features := behavior.Features(his)
		fields := map[string]any{"his": features}
		if rec != nil && rec.raw {
			fields["his_raw"] = his
		}
		rec.record("issued", c.ID(), fields)
		if showFeatures {
			if b, err := json.Marshal(features); err == nil {
				w.Header().Set("X-Eqc-Demo-Features", string(b))
			}
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
			Code     string             `json:"code"`
			Payload  string             `json:"payload"`
			Behavior *behavior.CodeStep `json:"behavior"`
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
		fields := map[string]any{"result": "passed"}
		if !res.Verified {
			fields["result"] = res.Reason
		}
		if req.Behavior != nil {
			// implausible features are dropped, not held against the code
			if f, err := req.Behavior.Summarise(); err == nil {
				fields["code_step"] = f
			}
		}
		rec.record("verify", res.ID, fields)
		resp := map[string]any{"verified": res.Verified}
		if showFeatures && fields["code_step"] != nil {
			resp["behavior"] = fields["code_step"]
		}
		if !res.Verified {
			log.Printf("verify: %s", res.Reason)
			resp["reason"] = reasonText[res.Reason]
			writeJSON(w, http.StatusOK, resp)
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
		resp["payload"] = res.Pass
		writeJSON(w, http.StatusOK, resp)
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
