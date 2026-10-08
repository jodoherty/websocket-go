# websocket-go

This project is an agentically generated single-file implementation of
WebSockets in Go.

See [ws/ws.go](ws/ws.go) for the full implementation.

I wanted something that has no dependencies outside the standard library and
that was thoroughly tested. As such, most of this repository is actually test
code and supporting documentation.

The test coverage includes custom branch and MCDC coverage tooling. End to end
compatibility testing is done with Node.js, Chromium, and Firefox websocket
implementations. Mutation tests and fuzzing stochastically discover more
robustness edge cases. Finally, model based testing is done based on an
RFC-derived formal model of the WebSocket protocol states.

The API started out with high-level usage in mind and then I split out and grew
a small, RFC-mapped core that can be layered on top of any transport and that
helps enforce model based testing.

Applications will typically want to use the higher level Session API, whereas
WebSocket protocol libraries should directly create and use the underlying
RawConn.

I've set the project up with fairly strict linting and staticcheck rules to
make it easier to add to any existing project by dropping in the implementation
file.

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
