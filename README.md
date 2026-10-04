# websocket-go

This project is an agentically generated single-file implementation of
WebSockets in Go.

See [ws/ws.go](ws/ws.go) for the full implementation.

I wanted something that has no dependencies outside the standard library and
that was thoroughly tested. As such, most of this repository is actually test
code and supporting documentation. It implements custom branch coverage and
MCDC coverage tooling, and it tests end to end compatibility with Node.js,
Chromium, and Firefox.

Because this is agentically generated, I've provided it as free and
unencumbered software released into the public domain under the UNLICENSE
license (see [LICENSE](LICENSE)).

You can utilize this project as a go module, but everything you need is in
ws.go. Feel free to copy it into your own project.

Agentically generated documentation includes:

- `doc/USAGE.md` — design, API, running the test gates and the demo,
  the VNC-shaped example
- `doc/CONFIDENCE.md` — the layers of test evidence and the
  security-relevant invariants
- `doc/LINTING.md` — the lint gate, its exclusions, and why each exists

Repository rules for contributors and agents: `AGENTS.md`.
