# waf-wasm

A **[Proxy-Wasm](https://github.com/proxy-wasm/spec)** plugin runtime for
**[Light WAF](https://github.com/0x00spor3/Light-WAF)** — a fast, modular Layer-7 Web
Application Firewall reverse proxy in Rust.

It loads a `.wasm` filter and exposes it as a [`waf_core::WafModule`](https://docs.rs/waf-core),
so you can extend the WAF with custom logic **without forking the core** (`[modules.wasm]`,
default off).

## Design

- **Engine** — `wasmi`, a pure-Rust interpreter (no JIT, no C toolchain). Pinned to the exact
  version validated for reentrant `malloc` + fuel + memory-cap traps.
- **Execution model** — the WAF is buffer-then-inspect, so per request the host runs the
  Proxy-Wasm request-path callbacks in one shot (`end_of_stream = true`) and maps a captured
  `proxy_send_local_response` to a `Decision`. The plugin never writes the response itself —
  the pipeline decides (detection-only stays safe).
- **DoS posture** — fuel is reset per request (a **latency ceiling**, not just a kill-switch),
  memory is capped, and there are no network/filesystem host calls. Any trap **fails closed**
  (`Reject{500}`). Instances are pooled with a blocking-with-timeout acquire; each request gets
  an isolated instance.
- **Host ABI** — a declared subset of host functions is implemented; everything else returns
  `Unimplemented` and is surfaced in a boot **`ImportReport`** (never a silent partial).

A complete worked example (a custom denylist filter) lives in
[`examples/wasm-plugin/`](https://github.com/0x00spor3/Light-WAF/tree/main/examples/wasm-plugin)
in the repository.

> The runtime is open source; a plugin marketplace / signing is an enterprise concern
> (`BOUNDARY.md` §2.4).

## Part of Light WAF

| Crate | Role |
|---|---|
| `waf-core` | Base types: `Config`, `Decision`, `RequestContext`, the `WafModule` contract, the `StateStore` seam |
| `waf-normalizer` | Request normalization: decode + NFKC + body/query/cookie parsing + limits |
| `waf-pipeline` | Phased orchestrator + cumulative anomaly scoring |
| `waf-detection` | Detection modules (SQLi/XSS/RCE/…) + fast-path prefilter |
| **waf-wasm** | Proxy-Wasm runtime (wasmi) loading `.wasm` filters as modules |
| `waf-proxy` | The `waf` binary: hyper/tokio reverse proxy |

See the [repository](https://github.com/0x00spor3/Light-WAF) for the full architecture.

## License

Apache-2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
