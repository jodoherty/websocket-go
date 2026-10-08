# Linting

(Moved from `README.md`, which is reserved for the project owner's
hand-written editing.)

The library is a single file people drop into their own repos, so it is
held to the strictest standard lint, and held *repeatably*:

```sh
make lint        # golangci-lint with every linter enabled
make staticcheck # staticcheck -checks=all (a second, independent engine)
make gate        # the full validation gate: every target, including e2e
```

`lint` runs `golangci-lint` with `default: all` — every linter in the
release, not a curated subset. The result on `ws/ws.go`, the `cmd/` tools,
and the test suite is **zero findings**. That forces real refactors (the
frame codec splits into small single-purpose functions, `atomic.Int32`
for the conn state, static error bases wrapped with `%w`, no single-letter
names outside their natural scope) — and that is the point: the file that
gets copied into your project passes your linter config, not fights it.

`.golangci.yml` keeps the exclusion list short and each entry carries its
reason. The whole-repo disables are three linters that conflict with
deliberate choices:

| disabled | why |
|---|---|
| `wsl`, `wsl_v5` | whitespace-cuddle rules are not part of any mainstream strict config; gofmt stays the formatter, and "fixing" cuddles inserts blank lines that hurt readability |
| `exhaustruct` | forces every struct literal to spell out all fields, including meaningful zeros; for option-heavy types (`tls.Config`, `net.Dialer`, `Config`) that is anti-clarity |
| `funcorder` | wants all unexported methods after all exported ones; the file is organized by protocol concern instead, so each method sits with the behavior it belongs to |

One linter *setting* is also deliberate: `exhaustive` runs with
`default-signifies-exhaustive: true` because the read loops switch on the
named `Op` type with a `default` arm that is the data-message case
(`OpText`/`OpBinary`), while `OpContinuation` never surfaces from a read
loop and cannot be enumerated. A switch over `Op` that lacks that
`default` arm is still checked, so the setting narrows exactly the
intentional pattern and nothing else.

Test files (`_test.go`) get a second, documented exclusion rule — test
scaffolding is not the drop-in artifact, and stateful tests (shared ports,
synctest, table-driven literals) make a blanket strict set there noise.

There are no reason-less suppressions in the tree: every `//nolint:` in
`ws/` and `cmd/` carries the reason inline (the gosec ones, for instance,
mark the deliberate uses — the RFC-mandated SHA-1 handshake, the bounded
64-bit length read, the demo's peer-sourced log fields). The two newest
suppressions are gosec `#nosec` annotations in `cmd/mut` — the
scratch-module builder joins a file name into a path, and the name's taint
comes from `os.ReadDir` on the repo's own `ws/` directory. The join is made
safe by construction (`filepath.Base` plus an identity check rejects any
path component), and the `#nosec` carries that reason inline rather than
silencing the check.

`staticcheck -checks=all` enables every `ST`/`SA`/`S` check, including
several golangci-lint's staticcheck linter does not enable; it is a second
independent opinion on the same code and also passes clean.

Both gates are part of the local gate (`make lint staticcheck`), run
alongside the race-detector test suite, the fuzz target, and the browser e2e.
