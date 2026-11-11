# CLAUDE.md

Prototype of our own server for the ALTCHA code challenge ("enter the code from the image",
with audio), as a replacement for ALTCHA Sentinel. Read `SPEC.md` first: it has the widget
protocol (checked against altcha@3.5.0), the stateless design, the prototype scope and the
evaluation plan.

- Go. `pkg/codechallenge` must stay free of HTTP and global state: banjax will import it.
- Reuse banjax's ALTCHA code where possible (`../banjax/internal/altcha_challenge.go`,
  `github.com/altcha-org/altcha-lib-go/v2`), same algorithm and HMAC scheme.
- Pin the widget to altcha@3.5.0 and inline it like `../banjax/internal/altcha-challenge.html`;
  no CDN.
- Secrets come from env (`EQC_SECRET`), never from the repo.

## This repo is public

Commit only code, tests, generic docs. Never commit, not even in comments, test fixtures,
commit messages or example output:
- secrets, keys, tokens, passwords, `.env` files;
- names of Deflect clients or sites, and details of attacks on them;
- IPs, hostnames or config of Deflect infrastructure (edges, Kafka, dashboards);
- weaknesses in production Deflect/banjax that are not fixed yet;
- evaluation results: solve rates of OCR, vision models, speech-to-text or captcha farms
  against our challenge, sample solved images, bot-tester output. They go to internal reports,
  not here;
- logs or data from real visitors (IPs, user agents, cookies).

Before each commit, check the diff for these. If unsure, leave it out and ask.
