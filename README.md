# Light WAF (Layer 7)

Web Application Firewall in **Rust** che opera come **reverse proxy** al Layer 7:
ispeziona ogni richiesta HTTP, applica regole di detection, accumula uno **score di
anomalia** (modello CRS-style) e decide **Allow / Block (403) / Reject (400 | 429)**
prima di inoltrare al backend.

Obiettivi: *light* (poche dipendenze), *veloce* (< 1 ms p99 sul path comune),
*modulare* (ogni detection è un plugin attivabile da config), *osservabile* (log JSON
strutturato), *sicuro by design* (fail-open / fail-closed espliciti per-scenario).

---

## Capacità

| Detection | Fase | Note |
|---|---|---|
| SQLi, XSS, RCE/Cmd-inj, LFI/RFI, SSRF | body/query/cookie | content-inspection regex su dati canonicalizzati |
| Path traversal | request_line | path + query/cookie/body |
| Header injection (CRLF) | headers | field-aware (scope per regola) |
| Request smuggling (CL/TE) | connection | validazione strutturale del framing → 400 |
| Rate limiting L7 | connection | token bucket per IP risolto |

Più: normalizzazione anti-evasione (percent-decode anti-doppia-codifica + NFKC),
anomaly scoring cumulativo configurabile, livelli di paranoia (PL1–4), config esterna
con hot reload (SIGHUP, Unix), risoluzione IP client trusted-proxy, e un **fast-path**
che salta l'ispezione sul traffico provabilmente benigno (equivalenza testata).

---

## Struttura del workspace (6 crate)

```
waf-core ────────┐ (tipi base, nessuna dipendenza interna)
   ▲   ▲   ▲      │
   │   │   │      ▼
   │   │   └── waf-normalizer   (Fase 2: decode + NFKC + parsing + limiti)
   │   └────── waf-pipeline     (orchestratore a fasi + anomaly scoring)
   └────────── waf-detection    (moduli/regole + ContentPrefilter fast-path)
                   ▲
         ┌─────────┴──────────┐
   waf-proxy (il binario)   waf-corpus (validazione/tuning/fast-path: lib + test + example)
```

| Crate | Ruolo |
|---|---|
| **waf-core** | `Config`, `Decision`, `RequestContext`, `Severity`, `Normalized`; risoluzione IP client; `testkit` (builder per test, dietro feature) |
| **waf-normalizer** | Fase 2: percent-decode (anti-doppia-codifica), NFKC, parse query/cookie/body, limiti difensivi |
| **waf-pipeline** | `Pipeline`: esegue i moduli per fase, accumula lo score, decide il verdetto |
| **waf-detection** | I moduli con le tabelle `*_RULES`; `ContentPrefilter` (fast-path scope-aware) |
| **waf-proxy** | Il **binario**: reverse proxy hyper/tokio, caricamento config, fail-open/closed, hot reload |
| **waf-corpus** | I 79 casi di validazione + runner + metriche. **Non** è in produzione: è lo strumento di evidenza (oracolo) |

### Flusso di una richiesta (`waf-proxy/src/lib.rs::handle`)

1. **`build_context`** — risolve l'IP client reale (trusted-proxy / `X-Forwarded-For`).
2. **`run_connection`** — rate limit + request smuggling, **prima** del parsing → può
   rifiutare 429/400 senza pagare la normalizzazione.
3. **`normalize`** (Fase 2) — decode + NFKC + parse; sforamento limiti → 400 (policy `[resilience]`).
4. **Fast-path + ispezione** — il prefiltro decide se *qualche* regola potrebbe matchare;
   se no salta l'ispezione (Allow), altrimenti gira i moduli content e a `score ≥ block_threshold` → 403.
5. **Forward** al backend, risposta al client.

---

## Requisiti

- **Rust** stabile (toolchain con `cargo`).
- Per vedere il proxy lavorare davvero serve un **backend** in ascolto sull'indirizzo
  in `config.toml` (`backend = "http://127.0.0.1:3000"`).

## Build

```sh
cargo build              # debug
cargo build --release    # ottimizzato
```

## Run

Il binario è `waf-proxy`. Precedenza del path di config: `--config` > env `WAF_CONFIG` > `config.toml`.

```sh
# usa ./config.toml di default
cargo run -p waf-proxy

# config esplicita
cargo run -p waf-proxy -- --config /percorso/mio.toml
```

```powershell
# PowerShell: via env var, oppure alzando il livello di log (JSON, default "info")
$env:WAF_CONFIG = "E:\percorso\mio.toml"; cargo run -p waf-proxy
$env:RUST_LOG = "debug"; cargo run -p waf-proxy
```

Note:

- Il **default** (`config.toml`) ascolta `0.0.0.0:8080`, inoltra a `127.0.0.1:3000`,
  in **`mode = "detection-only"`** (logga ma non blocca). Per bloccare: `mode = "blocking"`.
- Config invalida o file mancante → messaggio su **stderr** + **exit code 2** (fail-fast).
- **Hot reload via SIGHUP** è `#[cfg(unix)]` → non disponibile su Windows (la logica
  validate-then-swap resta testata a parte).
- Prova rapida (con un backend su :3000):
  ```sh
  curl "http://localhost:8080/?q=1%20UNION%20SELECT%20pass%20FROM%20users--"
  ```
  e guarda il log della decisione.

## Test

```sh
cargo test --workspace                       # tutta la suite (unit + integration)
cargo test -p waf-detection                  # un crate solo
cargo test -p waf-corpus --test validation   # l'oracolo (recall/FP + ladder + equivalenza fast-path)
cargo clippy --workspace --all-targets       # lint (deve essere clean)
```

## Strumenti on-demand (report eseguibili, non test CI)

Gli `example` di `waf-corpus` producono l'evidenza di Fase 7:

```sh
cargo run -p waf-corpus --example report      # recall/FP per modulo + score-distribution + overlap
cargo run -p waf-corpus --example coverage     # mappa regola → caso(i) → min_pl
cargo run -p waf-corpus --example tuning       # sweep config soglie × paranoia (margini)
cargo run --release -p waf-corpus --example fastpath_bench   # benchmark fast-path
```

---

## Configurazione

`config.toml` (auto-documentato, ogni sezione commentata) raccoglie: `[proxy]` (listen/backend),
`[waf]` (mode, `block_threshold`, `paranoia_level`, `severity_scores`), `[resilience]`
(fail-open/closed per-scenario), `[rate_limit]`, `[network]` (trusted-proxy), `[limits]`,
`[modules.*]` (attiva/disattiva ogni detection). Dettaglio dello schema e dei default in
`ARCHITECTURE.md` §9.

## Dove leggere il codice

- `crates/waf-proxy/src/lib.rs` → `handle()` per il flusso end-to-end.
- `crates/waf-pipeline/src/lib.rs` → accumulo score e verdetto.
- `crates/waf-detection/src/<modulo>.rs` → le regole (`*_RULES`) di ciascun modulo.
