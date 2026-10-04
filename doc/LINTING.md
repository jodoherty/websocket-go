# Linting

(Moved from `README.md`, which is reserved for the project owner's
hand-written editing.)

The library is a single file people drop into their own repos, so it is
held to the strictest standard lint, and held *repeatably*:

```sh
make lint        # golangci-lint with every linter enabled
make staticcheck # staticcheck -checks=all (a second, independent engine)
make all         # lint + staticcheck + tests, the full gate
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

Test files (`_test.go`) get a second, documented exclusion rule — test
scaffolding is not the drop-in artifact, and stateful tests (shared ports,
synctest, table-driven literals) make a blanket strict set there noise.

`staticcheck -checks=all` enables every `ST`/`SA`/`S` check, including
several golangci-lint's staticcheck linter does not enable; it is a second
independent opinion on the same code and also passes clean.

Both gates are part of the local gate (`make lint staticcheck`), run
alongside the race-detector test suite, the fuzz target, and the browser e2e.
