# waf-pipeline

The phased detection orchestrator for **[Light WAF](https://github.com/0x00spor3/Light-WAF)**
— a fast, modular Layer-7 Web Application Firewall reverse proxy in Rust.

It runs the registered [`WafModule`](https://docs.rs/waf-core)s **phase by phase**, accumulates
a **CRS-style cumulative anomaly score**, and resolves the final verdict.

## What it does

- **Phased execution** — modules declare a `Phase`; the pipeline runs each phase in order and
  can short-circuit on a decisive verdict.
- **Cumulative anomaly scoring** — every matched rule contributes points by `Severity` (resolved
  via `[waf.severity_scores]`); when the running score reaches `block_threshold` the request is
  blocked (403). Several low-severity matches can add up to a block, the CRS way.
- **Verdict** — a `PipelineVerdict`: `Allow`, `Block { rule_id, reason }`, or
  `Reject { status, retry_after }` (e.g. 429 from rate limiting).
- **Panic isolation** — each module runs under `catch_unwind`; per the `[resilience]` policy a
  panicking module is either skipped (`fail_open`, the default — a bug of ours must not drop
  availability below the no-WAF baseline) or turned into a deny (`fail_closed`).

## Part of Light WAF

| Crate | Role |
|---|---|
| `waf-core` | Base types: `Config`, `Decision`, `RequestContext`, the `WafModule` contract, the `StateStore` seam |
| `waf-normalizer` | Request normalization: decode + NFKC + body/query/cookie parsing + limits |
| **waf-pipeline** | Phased orchestrator + cumulative anomaly scoring |
| `waf-detection` | Detection modules (SQLi/XSS/RCE/…) + fast-path prefilter |
| `waf-wasm` | Proxy-Wasm runtime (wasmi) loading `.wasm` filters as modules |
| `waf-proxy` | The `waf` binary: hyper/tokio reverse proxy |

See the [repository](https://github.com/0x00spor3/Light-WAF) for the full architecture.

## License

Apache-2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
