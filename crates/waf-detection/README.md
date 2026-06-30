# waf-detection

The detection modules for **[Light WAF](https://github.com/0x00spor3/Light-WAF)** — a fast,
modular Layer-7 Web Application Firewall reverse proxy in Rust.

Each module is a [`WafModule`](https://docs.rs/waf-core) carrying its rule tables (`*_RULES`),
toggled independently from config (`[modules.*]`).

## Modules

- **Content injection** — `sqli`, `xss`, `rce` (incl. command injection in the URL path,
  expression-language / SpEL, VBScript-ASP webshell), `ldap`, `nosql`, `mail` (SMTP/IMAP),
  `ssti`, `ssi`, `xxe`, `lfi_rfi`, `ssrf`.
- **Structural / transport** — `path_traversal`, `header_injection` (CRLF), `request_smuggling`
  (CL/TE framing), `graphql` (depth/alias/field/batch caps + introspection), `grpc` (message
  size / field count / nesting depth caps).
- **Reputation / abuse** — `scanner` (sqlmap/nuclei/OpenVAS/ffuf + OOB domains), `rate_limit`
  (L7 token bucket over the `StateStore`).
- **Import** — `crs`: an OWASP CRS / ModSecurity `seclang` parser + subset evaluator that runs
  imported `SecRule` files as a module (`[modules.crs]`).

## Fast-path prefilter

`ContentPrefilter` is a scope-aware, `RegexSet`-backed gate that decides whether **any** rule
could match a request; provably benign traffic skips full inspection entirely. ReDoS is
impossible by construction (linear-time `regex`, no backtracking). Worst-case inspection
latency is ~2 µs at paranoia level 3.

## Part of Light WAF

| Crate | Role |
|---|---|
| `waf-core` | Base types: `Config`, `Decision`, `RequestContext`, the `WafModule` contract, the `StateStore` seam |
| `waf-normalizer` | Request normalization: decode + NFKC + body/query/cookie parsing + limits |
| `waf-pipeline` | Phased orchestrator + cumulative anomaly scoring |
| **waf-detection** | Detection modules (SQLi/XSS/RCE/…) + fast-path prefilter |
| `waf-wasm` | Proxy-Wasm runtime (wasmi) loading `.wasm` filters as modules |
| `waf-proxy` | The `waf` binary: hyper/tokio reverse proxy |

See the [repository](https://github.com/0x00spor3/Light-WAF) for the full architecture.

## License

Apache-2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
