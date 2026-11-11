# eqchallenge_server: our own ALTCHA code-challenge server (Sentinel replacement)

Status: draft for a prototype, 2026-11-11.

## 1. Why

Deflect needs an **interactive** step for browser botnets that solve any JavaScript they get
(November 2026: headless Chrome passes sha-inverse and ALTCHA proof of work).
Options we weighed (`baskervillehall/INTERACTIVE_CHALLENGE_OPTIONS.md`):

| Option | Verdict |
|---|---|
| Third party (Turnstile, reCAPTCHA, hCaptcha) | No: sends readers' data to Google/Cloudflare, blocked in Russia/China/Iran |
| ALTCHA Sentinel (closed, self-hosted) | €99/month for up to 3 central instances, €799/month for unlimited (one per edge). 30-day trial without a key. Central service: extra latency, single point of failure, has to be reachable from Russia |
| **ALTCHA + our own image/audio code server** | **This project.** Free, MIT widget, runs on every edge, no third party |
| Our own interaction challenge ("press and hold" + ML) | Long term (deflect-ca/eqchallenge prototype). Can reuse this server's plumbing |

Sentinel is the server that ALTCHA's widget talks to for the "enter the code from the image"
step (code challenge, with audio). The widget itself is open source and already renders that
step. Its README says the code challenge needs "ALTCHA Sentinel or a custom server
implementation". This project is the custom server.

Limits we accept from the start:
- An image code is a classic captcha. Vision models and captcha farms solve it. It filters
  botnets that only run stock headless Chrome, until the operator adds an OCR step.
- It hurts humans (accessibility, friction). Show it only as a last resort: on escalation, on
  the attacked site, after the invisible proof of work did not help.

## 2. What banjax already has (v0.13.2)

- ALTCHA v2 proof of work minted and verified inside banjax (`internal/altcha_challenge.go`,
  `github.com/altcha-org/altcha-lib-go/v2`): PBKDF2/SHA-256, HMAC-signed challenge, HMAC key
  signature for fast verification, `ExpiresAt` always set.
- The challenge's signed `data` carries `binding` (IP or UA) and `issued_at`. Verification
  checks the binding and `NotBefore`.
- The widget is altcha@3.5.0, inlined in `internal/altcha-challenge.html` (no CDN). Difficulty is
  per decision (`altcha_max_number` from Kafka). Decisions `AltChaChallenge` (solve on load) and
  `AltChaClickChallenge` (checkbox) exist.
- Cookie `deflect_altcha` holds the base64 payload; `TooManyFailedChallenges` counts failures;
  two-step escalation (nginx 403, then iptables).

So the proof-of-work half exists. Missing: generating the code, its image and audio, and
verifying the typed code.

## 3. Widget protocol (checked in the altcha@3.5.0 bundle that banjax inlines)

Verify this again against the unminified source (`altcha-org/altcha` tag v3.5.0) before
relying on edge cases.

1. **Challenge.** The page gives the widget the usual v2 challenge JSON
   `{parameters: {...}, signature: "..."}` through the `challenge` attribute (banjax inlines it)
   or `challengeurl`. Add an extra top-level field:
   ```json
   "codeChallenge": { "image": "<url or data: URI>", "audio": "<url>", "length": 6 }
   ```
   The widget also accepts `codeChallenge` in its configuration.
   - `image`: a value starting with `http(s):` or `/` is resolved as a URL; anything else
     (for example `data:image/png;base64,...`) is used as is.
   - `audio`: optional; if present the widget shows an audio button and loads the URL with a
     `language` query parameter added (`audioChallengeLanguage` config, else the UI language).
   - `length`: becomes the input's `maxlength`.
2. **Proof of work first.** The widget solves the PoW as today. If the challenge has a
   `codeChallenge`, it does not finish. It shows the code form: image, input, submit, reload,
   cancel and optional audio.
3. **Submit.** The widget POSTs JSON to `verifyUrl` (config option, required for a code
   challenge, or a JS `verifyFunction`):
   ```json
   { "code": "<typed code>", "payload": "<base64 PoW payload>" }
   ```
   It adds `fields` and `timeZone` only if `serverVerificationFields` / `serverVerificationTimeZone`
   are set. We leave them off.
4. **Response.** `{"verified": true, "payload": "<string>"}` marks it verified. The widget
   replaces its payload with ours and fires `verified`. `{"verified": false, "reason": "..."}`
   shows the reason. On HTTP >= 400 it shows `error` from a JSON body.
5. **Reload button.** Asks for a new challenge (new image).
6. Related, not needed now: the widget can send a "human interaction signature" (HIS) if the
   server asks for it in the challenge response (`his.url`). Possible later input for option 4.

## 4. Design

### 4.1 Shape

A Go module with:
- `pkg/codechallenge`: library. Mint a code challenge, render image and audio, verify a code.
  No HTTP, no global state. **banjax imports this later**, so it runs on every edge.
- `cmd/eqchallenge-server`: standalone HTTP server for the prototype and demos. It mints the
  ALTCHA PoW too, so the whole flow works without banjax.
- `web/`: demo page with the pinned altcha@3.5.0 widget, inlined like banjax does.

### 4.2 Stateless by default

Edges must not share state, so the challenge itself carries everything:

- **Code.** 5–6 characters from an unambiguous alphabet (no 0/O, 1/l/I), crypto/rand.
  Case-insensitive compare. Digits only if we use `dchest/captcha` audio as is.
- **Code hash in the signed data.** `parameters.data.code_hash = HMAC(secret, nonce || normalised code)`.
  The ALTCHA signature already covers `data`, so it cannot be changed, and a client can't
  invert the HMAC.
- **Image and audio.** Small enough to inline the image as a `data:` URI (target < 15 KB),
  so the page needs no second request. Audio is served from
  `/eqc/audio?t=<token>`, where `token = AES-GCM(secret, {code, exp, binding})`. The audio
  endpoint decrypts and renders, so no state is kept. The image endpoint works the same way if we
  stop inlining it.
- **Verify (`POST /eqc/verify`).**
  1. Verify the PoW payload exactly as banjax does (signature, expiry, binding, `NotBefore`).
  2. Compare `HMAC(secret, nonce || normalise(code))` with `data.code_hash` in constant time.
  3. Return `{"verified": true, "payload": <pass token>}`. The pass token is
     `base64(HMAC-signed {binding, exp, kind: "code", challenge_sig})`, and banjax sets it as
     the `deflect_altcha` cookie (or a new cookie) and accepts it for code-challenge decisions.
- **Replay and brute force** (the one place that needs local state, kept per edge in memory):
  - a TTL set of used challenge signatures, so one solved challenge gives one pass;
  - a wrong-code counter per challenge signature (max 3 attempts, then the reload button gets a
    new challenge) and per IP, feeding banjax's existing `TooManyFailedChallenges`.
  - Short challenge lifetime (2–5 min) keeps both sets small.

### 4.3 Binding

The pass is worthless if it can be copied to other clients. Bind it to the client IP at
least (banjax already binds the PoW cookie by IP or UA). Also binding to a TLS fingerprint (JA3/JA4 from
nginx) is an open question for Jeremy.

### 4.4 Image and audio generation

Prototype: **`github.com/dchest/captcha`** (MIT). It renders digit images (PNG) and spoken
digits (WAV). Audio languages are said to be en, ja, ru, zh: verify. Then evaluate whether
its distortion beats tesseract (section 6). If not, write our own renderer (`image/draw` + a
TTF font + warp, noise lines, per-character rotation). Plan for that, since the dchest style
is well known to OCR tools.

Accessibility:
- Audio for screen-reader users.
- Big enough image (≥ 200×70), good contrast, works in dark mode.
- Localised UI strings: the widget has i18n; banjax already localises the page.
- Keyboard-only use works with the stock widget.

### 4.5 banjax integration (after the prototype)

- New decision `AltChaCodeChallenge`. The Kafka command `altcha_challenge_*` gets
  `"altcha_code": true` (same pattern as `altcha_click`).
- The challenge page sets `verifyUrl` to a banjax path (for example `/eqc/verify`) and inlines
  `codeChallenge`.
- Escalation: invisible PoW → checkbox → code → block, driven by Baskerville or the First
  Responder per host, never global.
- Skip non-browser paths (RSS, API, apps): they would treat a code challenge as a block.

## 5. Prototype scope

Goal: a working end-to-end demo and a measured answer to "does it stop a browser botnet, and
how hard is it for people".

1. `pkg/codechallenge`: mint, render image (data URI), render audio, verify; unit tests
   (tampered data, wrong code, expired, wrong binding, replay).
2. `cmd/eqchallenge-server`:
   - `GET /` serves the demo page;
   - `GET /eqc/challenge` returns PoW + `codeChallenge`;
   - `GET /eqc/audio?t=` returns the audio;
   - `POST /eqc/verify` checks the code;
   - `GET /protected` returns 200 only with a valid pass cookie, otherwise the challenge page.
3. Docker image. Config via env: `EQC_SECRET`, `EQC_CODE_LENGTH`, `EQC_TTL_SECONDS`,
   `EQC_POW_MAX_NUMBER`, listen address.
4. Run `altcha-bot-tester` (banjax repo, `supporting-containers/altcha-bot-tester`) against
   `/protected`, plus the new scenarios in section 6.

Not in the prototype: banjax changes, Kafka, risk scoring, HIS, our own renderer (unless dchest
fails the OCR test badly), languages beyond what dchest has.

## 6. How we evaluate

| Scenario | Expected |
|---|---|
| Stock headless Chrome (Puppeteer/Playwright) solving any JS | Fails: PoW passes, code doesn't |
| Headless + tesseract on the image | Measure solve rate; target < 5% before we ship |
| Headless + vision model (an LLM with image input) | Will mostly pass; measure cost and latency per solve |
| Audio + speech-to-text (Whisper) | Will mostly pass; measure |
| Pass cookie copied to another IP | Rejected |
| Same solved payload sent twice | Second one rejected |
| Brute force on one challenge | Stopped after 3 tries |
| 10 people, desktop and phone, incl. one screen-reader user | Solve rate, time to solve, complaints |

## 7. Complexity estimate

| Part | Effort |
|---|---|
| `pkg/codechallenge` with dchest/captcha, stateless verify, tests | 2–3 days |
| Standalone server + demo page + Docker | 1–2 days |
| Bot-tester scenarios (OCR, vision, Whisper) and the human test | 2–3 days |
| Own image renderer, if dchest is too easy for OCR | +3–5 days |
| banjax integration (decision, Kafka field, verify route, cookie, escalation, tests) | 1–2 weeks (Jeremy) |

Prototype: about 1 week for one person. Production in banjax: 2–4 weeks in total.

## 8. Open questions

1. Can a TLS fingerprint be passed from nginx to banjax for binding the pass?
2. One cookie (`deflect_altcha` with a `kind`) or a separate code-pass cookie?
3. Pass lifetime after a code: shorter than the PoW cookie (8 h)? Per site?
4. Digits only (dchest audio) or letters too (own audio, more work)?
5. Do we inline the image (one request less) or serve it by token (smaller page)?
6. What metrics go to Kafka / Kibana: code shown, solved, failed, reloads, time to solve
   (also useful as labels for option 4).

## 9. References

- ALTCHA widget: https://github.com/altcha-org/altcha (MIT), pinned 3.5.0 in banjax.
- ALTCHA Go library: https://github.com/altcha-org/altcha-lib-go (v2).
- Sentinel adaptive captcha: https://altcha.org/docs/sentinel/features/adaptive-captcha/
- Sentinel plans: https://altcha.org/docs/sentinel/plans/
- dchest/captcha: https://github.com/dchest/captcha
- banjax: `internal/altcha_challenge.go`, `internal/altcha-challenge.html`,
  `supporting-containers/altcha-bot-tester`.
- `baskervillehall/INTERACTIVE_CHALLENGE_OPTIONS.md`, `baskervillehall/BANJAX_CHALLENGE_ESCALATION_PROPOSAL.md`.
