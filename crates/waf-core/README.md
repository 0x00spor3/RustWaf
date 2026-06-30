# waf-core

Core types for **[Light WAF](https://github.com/0x00spor3/Light-WAF)** — a fast, modular
Layer-7 Web Application Firewall reverse proxy in Rust.

This crate has **no internal dependencies** (only `serde` + `bytes`); every other crate in the
workspace depends on it. It defines the shared vocabulary and the extension seams.

## What it provides

- **`Decision`** — the verdict a module returns: `Allow`, `Block`, `Monitor`, `Score`/`Scores`
  (CRS-style cumulative anomaly contributions), `Reject` (explicit HTTP status, e.g. 429).
- **`WafModule`** — the contract every detection module implements (`inspect`, `phase`,
  `structural`); the stable seam for embedding your own modules without forking the core.
- **`RequestContext`** / **`Normalized`** — the normalized request a module inspects.
- **`Config`** and its sections (`#[non_exhaustive]`, so adding fields stays backward-compatible).
- **`Severity`** and the `severity → points` model.
- **client-IP resolution** — `ClientIpResolver`, `IpSource`, `ResolvedClientIp` (trusted-proxy /
  `X-Forwarded-For`).
- **`StateStore`** seam — `try_acquire` (atomic token-bucket), `InMemoryStateStore`,
  `RateLimitState`, `BucketParams`, `Acquired`, `Clock`. This is the injection point for a
  distributed (e.g. Redis) rate-limit store.
- **`testkit`** (feature, off by default) — `RequestContext` builders for tests and tooling.

## Stability

The public traits and constructors are treated as a **frozen ABI** (see `BOUNDARY.md` §5): a
breaking change to a seam requires a major version bump.

## Part of Light WAF

| Crate | Role |
|---|---|
| **waf-core** | Base types: `Config`, `Decision`, `RequestContext`, the `WafModule` contract, the `StateStore` seam |
| `waf-normalizer` | Request normalization: decode + NFKC + body/query/cookie parsing + limits |
| `waf-pipeline` | Phased orchestrator + cumulative anomaly scoring |
| `waf-detection` | Detection modules (SQLi/XSS/RCE/…) + fast-path prefilter |
| `waf-wasm` | Proxy-Wasm runtime (wasmi) loading `.wasm` filters as modules |
| `waf-proxy` | The `waf` binary: hyper/tokio reverse proxy |

See the [repository](https://github.com/0x00spor3/Light-WAF) for the full architecture and the
open-source/enterprise boundary (`BOUNDARY.md`).

## License

Apache-2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
