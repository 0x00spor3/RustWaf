// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! B1 — Prometheus metrics endpoint, end-to-end through the REAL proxy.
//!
//! Verifies the datapath records each decision (allowed/blocked/rate_limited) and serves them
//! as Prometheus text on the dedicated listener. The CARDINAL SECURITY BITE (the F12-style
//! fail-safe of this phase): the DATA port must NOT expose `/metrics` — internal posture is
//! served only on the separate loopback listener.

use std::convert::Infallible;

use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;
use waf_core::{Config, RateLimitAction, RateLimitConfig, RateLimitKey, WafMode};
use waf_proxy::Proxy;

type TestBody = BoxBody<Bytes, hyper::Error>;

fn empty_body() -> TestBody {
    Empty::new().map_err(|never| match never {}).boxed()
}

fn test_client() -> Client<HttpConnector, TestBody> {
    Client::builder(TokioExecutor::new()).build(HttpConnector::new())
}

async fn start_echo_backend() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(|req: Request<Incoming>| async move {
                            let pq = req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/").to_string();
                            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(format!("ok:{pq}")))))
                        }),
                    )
                    .await
                    .ok();
            });
        }
    });
    addr
}

/// Blocking WAF with metrics on (no rate limit) — for decision/separation/leak checks.
fn metrics_config(backend: std::net::SocketAddr) -> Config {
    let mut c = Config::default();
    c.proxy.listen = "127.0.0.1:0".parse().unwrap();
    c.proxy.backend = format!("http://{backend}");
    c.waf.mode = WafMode::Blocking;
    c.metrics.enabled = true;
    c.metrics.listen = "127.0.0.1:0".parse().unwrap();
    c
}

/// Same, plus a 1-token rate limit so the 2nd request 429s.
fn metrics_config_rate_limited(backend: std::net::SocketAddr) -> Config {
    let mut c = metrics_config(backend);
    c.rate_limit = RateLimitConfig {
        enabled: true,
        key: RateLimitKey::ClientIp,
        requests: 1,
        window_seconds: 60,
        burst: Some(1),
        action: RateLimitAction::Block,
        score: 5,
        max_tracked_keys: 1000,
    };
    c
}

/// `1 UNION SELECT ...` — Critical SQLi → blocked (403) in Blocking mode.
const SQLI: &str = "/?q=1%20UNION%20SELECT%20a%2Cb%20FROM%20users--";

async fn get_status(client: &Client<HttpConnector, TestBody>, url: String) -> u16 {
    client
        .request(Request::builder().method("GET").uri(url).body(empty_body()).unwrap())
        .await
        .unwrap()
        .status()
        .as_u16()
}

async fn get_text(client: &Client<HttpConnector, TestBody>, url: String) -> (u16, String) {
    let resp = client
        .request(Request::builder().method("GET").uri(url).body(empty_body()).unwrap())
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

#[tokio::test]
async fn metrics_record_decisions_separate_listener_no_leak() {
    let backend = start_echo_backend().await;
    let proxy = Proxy::bind(&metrics_config(backend)).await.unwrap();
    let data_addr = proxy.local_addr().unwrap();
    let metrics_addr = proxy.metrics_addr().expect("metrics enabled");
    assert_ne!(data_addr, metrics_addr, "metrics must be on a SEPARATE listener");
    tokio::spawn(proxy.run());

    let client = test_client();

    // One benign (200, allowed) + one SQLi (403, blocked). No rate limit → clean counts.
    assert_eq!(get_status(&client, format!("http://{data_addr}/a")).await, 200);
    assert_eq!(get_status(&client, format!("http://{data_addr}{SQLI}")).await, 403);

    // ── scrape the metrics endpoint (scrapes do NOT go through the datapath) ─────
    let (status, text) = get_text(&client, format!("http://{metrics_addr}/metrics")).await;
    assert_eq!(status, 200);
    assert!(text.contains("waf_requests_total{decision=\"allowed\"} 1"), "got:\n{text}");
    assert!(text.contains("waf_requests_total{decision=\"blocked\"} 1"), "got:\n{text}");
    assert!(text.contains("waf_requests_total{decision=\"rate_limited\"} 0"), "got:\n{text}");
    assert!(text.contains("waf_request_duration_seconds_count 2"), "got:\n{text}");
    assert!(text.contains("waf_request_duration_seconds_bucket{le=\"+Inf\"} 2"));
    assert!(text.contains("waf_up 1"));

    // ── the metrics listener 404s anything that is not GET /metrics ──────────────
    assert_eq!(get_text(&client, format!("http://{metrics_addr}/")).await.0, 404);
    assert_eq!(get_text(&client, format!("http://{metrics_addr}/metricz")).await.0, 404);

    // ── CARDINAL SECURITY BITE: the DATA port does NOT expose /metrics ───────────
    // On the data port `/metrics` is just a benign path → forwarded to the echo backend,
    // never the Prometheus exposition.
    let (data_status, data_body) = get_text(&client, format!("http://{data_addr}/metrics")).await;
    assert_eq!(data_status, 200);
    assert_eq!(data_body, "ok:/metrics", "data port must forward, not expose metrics");
    assert!(!data_body.contains("waf_requests_total"), "data port leaked metrics!");
}

#[tokio::test]
async fn rate_limited_decision_is_recorded() {
    let backend = start_echo_backend().await;
    let proxy = Proxy::bind(&metrics_config_rate_limited(backend)).await.unwrap();
    let data_addr = proxy.local_addr().unwrap();
    let metrics_addr = proxy.metrics_addr().expect("metrics enabled");
    tokio::spawn(proxy.run());

    let client = test_client();
    // 1 token: first benign 200 (allowed), second 429 (rate_limited).
    assert_eq!(get_status(&client, format!("http://{data_addr}/a")).await, 200);
    assert_eq!(get_status(&client, format!("http://{data_addr}/b")).await, 429);

    let (_, text) = get_text(&client, format!("http://{metrics_addr}/metrics")).await;
    assert!(text.contains("waf_requests_total{decision=\"allowed\"} 1"), "got:\n{text}");
    assert!(text.contains("waf_requests_total{decision=\"rate_limited\"} 1"), "got:\n{text}");
}

#[tokio::test]
async fn metrics_disabled_by_default_binds_no_endpoint() {
    let backend = start_echo_backend().await;
    let mut cfg = metrics_config(backend);
    cfg.metrics.enabled = false;
    let proxy = Proxy::bind(&cfg).await.unwrap();
    assert!(proxy.metrics_addr().is_none(), "no metrics listener when disabled");
}
