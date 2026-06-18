//! Path-traversal corpus cases. Fields inspected: normalized.path, query,
//! cookies, body. `../` survives on query/body (the normalizer resolves it away
//! on the path); sensitive targets are detected on the resolved path.
//! Rules (paranoia): pt-dotdot-traversal 1, pt-sensitive-unix 1,
//! pt-sensitive-windows 1, pt-null-byte 2, pt-unc-path 3.

use crate::{Case, Expect, Field, Module};

pub static CASES: &[Case] = &[
    // ── malicious: one per rule ────────────────────────────────────────────────
    Case {
        id: "pt-dotdot-traversal-query",
        module: Module::PathTraversal,
        field: Field::Query { name: "file", value: "../../../foo/bar" },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["pt-dotdot-traversal"],
        desc: "../ sequence surviving on a query parameter",
    },
    Case {
        id: "pt-sensitive-unix-path",
        module: Module::PathTraversal,
        field: Field::Path("/etc/passwd"),
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["pt-sensitive-unix"],
        desc: "sensitive Unix target on the resolved path",
    },
    Case {
        id: "pt-sensitive-windows-path",
        module: Module::PathTraversal,
        field: Field::Path("/windows/system32/cmd"),
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["pt-sensitive-windows"],
        desc: "Windows system32 target on the resolved path",
    },
    Case {
        id: "pt-null-byte-query",
        module: Module::PathTraversal,
        field: Field::RawQuery("file=secret%00.png"),
        min_pl: 2,
        expect: Expect::Triggers,
        rules: &["pt-null-byte"],
        desc: "%00 decoded to a real NUL byte in a query value (Warning/PL2)",
    },
    Case {
        id: "pt-unc-path-query",
        module: Module::PathTraversal,
        field: Field::Query { name: "file", value: r"\\server\share\secret" },
        min_pl: 3,
        expect: Expect::Triggers,
        rules: &["pt-unc-path"],
        desc: "UNC network path (Notice/PL3)",
    },
    // ── benign / traps ─────────────────────────────────────────────────────────
    Case {
        id: "pt-trap-system32-token",
        module: Module::PathTraversal,
        field: Field::Query { name: "theme", value: "system32_dark" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "windows-target narrowing trap: 'system32_dark' must not match system32\\b",
    },
    Case {
        id: "pt-benign-normal-path",
        module: Module::PathTraversal,
        field: Field::Path("/api/v1/users/42"),
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "ordinary application path",
    },
    Case {
        id: "pt-benign-filename",
        module: Module::PathTraversal,
        field: Field::Query { name: "file", value: "quarterly_report.pdf" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "ordinary download filename",
    },
];
