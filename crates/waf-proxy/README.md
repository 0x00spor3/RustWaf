# waf-proxy — Light WAF

[![crates.io](https://img.shields.io/crates/v/waf-proxy.svg)](https://crates.io/crates/waf-proxy)
[![docs.rs](https://img.shields.io/docsrs/waf-core)](https://docs.rs/waf-core)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**Light WAF** is a Web Application Firewall in **Rust** operating as a **reverse proxy** at
Layer 7: it inspects every HTTP request, applies detection rules, accumulates a CRS-style
**anomaly score**, and decides **Allow / Block (403) / Reject (400 | 429)** before forwarding
to the backend.

Goals: *light* (few dependencies), *fast* (< 1 ms p99 on the common path; ~2 µs worst-case
inspection latency), *modular* (every detection is a plugin toggled from config), *observable*
(structured JSON logs + opt-in Prometheus), *secure by design* (explicit per-scenario
fail-open / fail-closed).

This crate ships the **`waf` binary** (and a `waf_proxy` library). It is the top of the
workspace: the hyper/tokio reverse proxy, config loading, hot reload, TLS termination, and the
embedding seams.

## Install

```sh
cargo install waf-proxy
```

## Run

Config path precedence: `--config` > env `WAF_CONFIG` > `./config.toml`.

```sh
waf                          # uses ./config.toml
waf --config /path/to/mine.toml
```

The default config listens on `0.0.0.0:8080`, forwards to `127.0.0.1:3000`, in
`mode = "detection-only"` (logs but does not block). Set `mode = "blocking"` to enforce.
Invalid or missing config → message on stderr + exit code 2 (fail-fast).

Quick check (with a backend on `:3000`):

```sh
curl "http://localhost:8080/?q=1%20UNION%20SELECT%20pass%20FROM%20users--"
```

## Capabilities (summary)

- **Detection** — SQLi, XSS, RCE/cmd-injection (incl. in the URL path), LFI/RFI, SSRF, LDAP,
  NoSQL, Mail, SSTI, SSI, XXE, path traversal, CRLF header injection, request smuggling
  (CL/TE), GraphQL & gRPC structural caps, scanner/tool fingerprinting, L7 rate limiting.
- **Anti-evasion** — double-encoding-aware percent-decode + NFKC + overlong-collapse +
  a multi-transform derived channel (base64, HTML-entity, tag/control strip, VBScript-concat).
- **TLS termination** — rustls, cert-from-file; one port serves HTTP/1.1 **and** HTTP/2 via
  ALPN/`auto`; opt-in `[tls]`, fail-closed (no cleartext downgrade).
- **Extensibility (default-off)** — WASM plugins ([`waf-wasm`](https://crates.io/crates/waf-wasm)),
  OWASP CRS / ModSecurity import, and a `Proxy::builder()` to inject your own modules,
  `StateStore`, or `TlsCertSource` without forking the core.
- **Observability** — structured JSON logs; opt-in Prometheus `/metrics` on a separate
  loopback listener (`[metrics]`).

## Part of Light WAF

| Crate | Role |
|---|---|
| [`waf-core`](https://crates.io/crates/waf-core) | Base types: `Config`, `Decision`, `RequestContext`, the `WafModule` contract, the `StateStore` seam |
| [`waf-normalizer`](https://crates.io/crates/waf-normalizer) | Request normalization: decode + NFKC + body/query/cookie parsing + limits |
| [`waf-pipeline`](https://crates.io/crates/waf-pipeline) | Phased orchestrator + cumulative anomaly scoring |
| [`waf-detection`](https://crates.io/crates/waf-detection) | Detection modules (SQLi/XSS/RCE/…) + fast-path prefilter |
| [`waf-wasm`](https://crates.io/crates/waf-wasm) | Proxy-Wasm runtime (wasmi) loading `.wasm` filters as modules |
| **waf-proxy** | The `waf` binary: hyper/tokio reverse proxy |

Full architecture, configuration schema, and the open-source/enterprise boundary are in the
[repository](https://github.com/0x00spor3/Light-WAF) (`ARCHITECTURE.md`, `BOUNDARY.md`).

## License

Apache-2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
