//! Header-injection (CRLF / response-splitting) corpus cases. Field-aware: rules
//! carry a scope (All / NonBody / HostHeaders / Body). The live surface is CRLF
//! percent-encoded in query/body params (hyper rejects raw CR/LF in headers) plus
//! Host absolute-URI injection. The normalizer trims header values, so CR/LF is
//! injected via %0d%0a in query/body.
//! Rules (paranoia): hdr-crlf-header-injection 1 (All), hdr-crlf-control-char 2
//! (NonBody), hdr-host-injection 2 (HostHeaders), hdr-crlf-in-body 3 (Body).

use crate::{Case, Expect, Field, Module};

pub static CASES: &[Case] = &[
    // ── malicious: one per rule ────────────────────────────────────────────────
    Case {
        id: "hdr-crlf-header-injection-query",
        module: Module::HeaderInjection,
        field: Field::RawQuery("x=%0d%0aSet-Cookie:%20sessionid=evil"),
        min_pl: 1,
        expect: Expect::Triggers,
        // also fires hdr-crlf-control-char (bare CR/LF, NonBody, PL2) at PL3.
        rules: &["hdr-crlf-header-injection"],
        desc: "CRLF + injected Set-Cookie response header in a query value",
    },
    Case {
        id: "hdr-crlf-control-char-query",
        module: Module::HeaderInjection,
        field: Field::RawQuery("x=line1%0d%0aline2"),
        min_pl: 2,
        expect: Expect::Triggers,
        rules: &["hdr-crlf-control-char"],
        desc: "bare CR/LF in a query value, no injectable header name (Warning/PL2)",
    },
    Case {
        id: "hdr-host-injection-header",
        module: Module::HeaderInjection,
        field: Field::Header { name: "host", value: "http://evil.example/" },
        min_pl: 2,
        expect: Expect::Triggers,
        rules: &["hdr-host-injection"],
        desc: "absolute-URI Host header (scheme + slash) — cache poisoning (Warning/PL2)",
    },
    Case {
        id: "hdr-crlf-in-body-form",
        module: Module::HeaderInjection,
        field: Field::FormBody("comment=line1%0d%0aline2"),
        min_pl: 3,
        expect: Expect::Triggers,
        rules: &["hdr-crlf-in-body"],
        desc: "bare CR/LF in a body field — legit in textareas, so Notice/PL3 only",
    },
    // ── benign / traps ─────────────────────────────────────────────────────────
    Case {
        id: "hdr-benign-host-port",
        module: Module::HeaderInjection,
        field: Field::Header { name: "host", value: "example.com:8080" },
        min_pl: 2,
        expect: Expect::Clean,
        rules: &[],
        desc: "legitimate host:port Host header (no scheme/slash/userinfo)",
    },
    Case {
        id: "hdr-benign-host-ipv6",
        module: Module::HeaderInjection,
        field: Field::Header { name: "host", value: "[2001:db8::1]:8080" },
        min_pl: 2,
        expect: Expect::Clean,
        rules: &[],
        desc: "IPv6-literal Host: colons only, must not be read as injection",
    },
    Case {
        id: "hdr-benign-body-text",
        module: Module::HeaderInjection,
        field: Field::FormBody("comment=hello world, thanks"),
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "ordinary single-line body field, no CR/LF",
    },
    Case {
        id: "hdr-benign-query-text",
        module: Module::HeaderInjection,
        field: Field::Query { name: "q", value: "normal search text" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "ordinary query value, no control characters",
    },
];
