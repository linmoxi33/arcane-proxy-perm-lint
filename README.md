# arcane-proxy-perm-lint

Find the agent-proxy routes in [Arcane](https://github.com/getarcaneapp/arcane) that will 403 with **"no known permission mapping"** — before an operator hits them in production.

> Why now: Arcane v3 proxies requests for remote agents through a second, independent permission checker. The `arcane permissions` export and the runtime matcher do not agree on which endpoints are covered, and the disagreement is visible today as open issue #4821.

Upstream: https://github.com/getarcaneapp/arcane

## What the upstream is, and what it lacks

Arcane is a self-hosted Docker management UI/API (Go + React). In v3, requests to a remote agent are authorized by `authz.PermissionMatcher` before they are tunnelled.

The matcher is filled by `PermissionMatcher.CollectFromHumaAPI` ([`backend/pkg/authz/permission_matcher_huma.go`](https://github.com/getarcaneapp/arcane/blob/main/backend/pkg/authz/permission_matcher_huma.go)). It only registers a rule when an operation has:

- `arcane:requiredPermission` metadata, or
- `arcane:actionParam` + `arcane:actionPermissions` metadata, or
- an empty security list (public).

Anything else — an endpoint that is merely `authenticated`, or gated by `globalAdmin` / `sudo` / an agent token — is **silently skipped**. At request time the middleware calls `Lookup`; on a miss it logs and denies:

```go
// backend/internal/middleware/environment.go#L302-L306
perm, ok := m.matcher.Lookup(method, suffix, req.URL.Query()).Get()
if !ok {
    slog.WarnContext(ctx, "Denying proxied request with no known permission mapping", ...)
    return false
}
```

This is exactly the failure reported in open issue [#4821](https://github.com/getarcaneapp/arcane/issues/4821) — *"Agent-proxy routes 403 with 'no known permission mapping': /registries, /system/…"*. The exported contract says those endpoints exist; the runtime matcher has no rule for them. There is no tool that compares the two.

## What this tool does / does not do

Given the JSON from `arcane permissions`, it reconstructs the matcher's coverage rule and reports, for every endpoint on the agent surface:

- **uncovered** — the matcher will register no rule, so the proxy will answer 403 `no known permission mapping`;
- **dangling** — a permission cited by an endpoint but absent from the catalog resources.

It does **not** call the Arcane API, start a container, or modify anything. It is a read-only, offline consistency check. It does not decide what the "right" permission is; it only proves that one path grants access while the other cannot resolve it.

## Install

Python 3.8+, standard library only:

```bash
git clone git@github.com:linmoxi33/arcane-proxy-perm-lint.git
cd arcane-proxy-perm-lint
```

No dependencies to install.

## Usage

Produce the contract export with the upstream CLI (run inside an Arcane checkout or image):

```bash
arcane permissions -o perms.json
```

Then check it:

```bash
python3 bin/arcane-proxy-perm-lint examples/in/agent-api-perms.json
```

```text
agent endpoints: 7  covered: 4  uncovered: 3  dangling: 1
  UNCOVERED GET /agents/{id}/registries [authenticated]: authenticated endpoint carries no arcane:requiredPermission, so the proxy matcher registers no rule
  UNCOVERED GET /agents/{id}/system/info [globalAdmin]: globalAdmin-gated endpoint has no permission mapping; matcher skips it
  UNCOVERED POST /agents/{id}/system/prune [sudo]: sudo-gated endpoint has no permission mapping; matcher skips it
  DANGLING  GET /agents/{id}/legacy-report -> reports:read: permission is referenced by an endpoint but absent from the catalog
```

Machine-readable output (`--json`, always parseable):

```bash
python3 bin/arcane-proxy-perm-lint examples/in/agent-api-perms.json --json
```

The expected report is checked in at [`examples/out/agent-api-perms.report.json`](examples/out/agent-api-perms.report.json).

Options:

| flag | meaning |
| --- | --- |
| `--json` | emit the report as JSON on stdout |
| `--prefix` | agent-surface path prefix (default `/agents/{id}`) |

### Exit codes

| code | meaning |
| --- | --- |
| `0` | no uncovered and no dangling endpoints |
| `1` | at least one uncovered or dangling endpoint |
| `2` | usage or input error (missing file, invalid JSON, bad export shape) |

## Tests

```bash
python3 -m unittest discover -s tests -v
```

17 tests: 12 on the analysis rule and 5 on real CLI behaviour (exit codes 0/1/2, parseable `--json`).

## Limitations

- The export must be produced by the matching Arcane build; the tool trusts the `access`, `permission` and `actionPermissions` fields it is given.
- Coverage is inferred from the documented `CollectFromHumaAPI` rule. If upstream changes how the matcher is populated, this tool must be updated.
- `arcane:access` overrides are reflected in the export but the matcher ignores that metadata; the tool mirrors the matcher, not the override.
- The checked-in example catalog is a **constructed** excerpt that mirrors the real export schema and real permission keys (`containers:list`, `registries:list`, …). It is not a dump from a live instance, so the counts are illustrative, not a census of upstream.

## 与同类项目的差异

A GitHub search for `arcane permission`, `arcane agent 403`, and `no known permission mapping` returned no tool that compares Arcane's permission export with its proxy matcher. The closest things are generic OpenAPI linters, which only validate the spec in isolation and cannot see the matcher's registration rule. This tool's only job is the cross-implementation gap.

## 本轮创新

**B 档.** Prior Arcane tooling checks a single artifact in isolation. This is the first check that runs the *exported contract* and the *runtime matcher* against each other and names the exact agent routes that fall through — the #4821 failure mode. It is not a generic "doctor": it reimplements one specific Go registration rule (`requiredPermission` OR `actionPermissions` OR empty security) and reports the complement.

## License

MIT. Upstream Arcane is BSD-3-Clause; this repository contains no upstream code.