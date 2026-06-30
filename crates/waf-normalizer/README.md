# waf-normalizer

Request normalization and canonicalization for **[Light WAF](https://github.com/0x00spor3/Light-WAF)**
— a fast, modular Layer-7 Web Application Firewall reverse proxy in Rust.

This is **Phase 2** of the pipeline: it turns a raw HTTP request into the canonical, decoded
form the detection modules inspect, so anti-evasion happens **once**, before any rule runs.

## What it does

- **Percent-decoding, double-encoding-aware** — decodes to a fixed point so `%2527`-style
  layered encodings can't smuggle a payload past content rules.
- **Unicode NFKC** normalization (canonical/compatibility), plus a pipeline-wide
  overlong-UTF-8 collapse.
- **Parsing** of the query string, cookies, and request body — including JSON (recursive
  flatten), `multipart/form-data` (per-field, with overlong-decode), GraphQL documents, and
  gRPC framing (`body`, `url`, `graphql`, `grpc` submodules).
- **Defensive limits** — body size, header count/size, parameter/cookie count, JSON depth;
  an overrun surfaces as a typed `NormalizationError` so the proxy can reject (400) instead of
  inspecting an unbounded request.

The derived-channel anti-evasion transforms (base64, evasion HTML-entity decode, mid-token
tag/control strip, VBScript-concat de-obf — `decode-then-match-then-discard`) feed the
detection modules from here.

## Part of Light WAF

| Crate | Role |
|---|---|
| `waf-core` | Base types: `Config`, `Decision`, `RequestContext`, the `WafModule` contract, the `StateStore` seam |
| **waf-normalizer** | Request normalization: decode + NFKC + body/query/cookie parsing + limits |
| `waf-pipeline` | Phased orchestrator + cumulative anomaly scoring |
| `waf-detection` | Detection modules (SQLi/XSS/RCE/…) + fast-path prefilter |
| `waf-wasm` | Proxy-Wasm runtime (wasmi) loading `.wasm` filters as modules |
| `waf-proxy` | The `waf` binary: hyper/tokio reverse proxy |

See the [repository](https://github.com/0x00spor3/Light-WAF) for the full architecture.

## License

Apache-2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
