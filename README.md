# eqchallenge_server

Our own implementation of the ALTCHA code challenge ("enter the code from the image", with
audio), so the open-source [altcha](https://github.com/altcha-org/altcha) widget works
without ALTCHA Sentinel. See [SPEC.md](SPEC.md) for the design.

- `pkg/codechallenge`: the library. Mints a proof of work plus a code image and audio,
  verifies the typed code, issues a pass token. No HTTP, no global state; banjax links it in.
- `cmd/demo`: a small HTTP demo of the whole flow. Not a production component.
- `web/`: demo pages and the pinned altcha@3.5.0 widget (`dist/main/altcha.min.js`, MIT),
  inlined into the page, no CDN.

## Demo

```sh
docker compose up --build
```

Open http://localhost:8080/protected (use `localhost`: the widget needs a secure context).
The widget solves the proof of work, then asks for the code. A right code sets the
`eqc_pass` cookie and reloads into the protected page; `/reset` drops the cookie.
`/protected?lang=ru` speaks the code in Russian.

Settings (env): `EQC_SECRET` (random per start if unset; never commit one),
`EQC_CODE_LENGTH`, `EQC_TTL_SECONDS`, `EQC_PASS_TTL_SECONDS`, `EQC_POW_MAX_NUMBER`,
`EQC_LISTEN`.

Without Docker: `go run ./cmd/demo` (Go 1.25+).

## Tests

```sh
go test -race ./...
```
