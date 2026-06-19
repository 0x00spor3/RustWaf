//! LDAP injection corpus cases (Fase 10a). Field: query.
//! Rules (paranoia): ldap-logical-filter 1, ldap-extensible-match 1 (both Critical).
//! Source: gotestwaf `ldap-injection`. The URL/Plain payloads are 10a Triggers; the
//! Base64Flat duplicates are tracked as `ExpectedMiss{until_phase:"10c"}` — they must
//! flip to caught once §6 base64-decodes (the oracle enforces it at 10c).

use crate::{Case, Expect, Field, Module};

pub static CASES: &[Case] = &[
    // ── malicious (URL/Plain — 10a) ─────────────────────────────────────────────
    Case {
        id: "ldap-logical-filter-query",
        module: Module::Ldap,
        field: Field::Query {
            name: "user",
            value: "(&(uid=admin)(!(&(1=0)(userPassword=q))))",
        },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["ldap-logical-filter"],
        desc: "compound LDAP filter (auth-bypass) in a query value — gotestwaf ldap-injection (URL)",
    },
    Case {
        id: "ldap-objectclass-enum-query",
        module: Module::Ldap,
        field: Field::Query { name: "search", value: "*(|(objectclass=*))" },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["ldap-logical-filter"],
        desc: "wildcard-into-OR filter for objectclass enumeration — gotestwaf ldap-injection (URL)",
    },
    Case {
        id: "ldap-extensible-match-query",
        module: Module::Ldap,
        field: Field::Query { name: "attr", value: "userPassword:2.5.13.18:=123" },
        min_pl: 1,
        expect: Expect::Triggers,
        rules: &["ldap-extensible-match"],
        desc: "extensible-match OID injection — gotestwaf ldap-injection (URL)",
    },
    // ── Base64Flat duplicates → 10c (no base64-decode in §6 yet): must flip at 10c ─
    Case {
        id: "ldap-logical-filter-b64",
        module: Module::Ldap,
        field: Field::Query { name: "user", value: "KCYodWlkPWFkbWluKSghKCYoMT0wKSh1c2VyUGFzc3dvcmQ9cSkpKSk=" },
        min_pl: 1,
        expect: Expect::ExpectedMiss { until_phase: Some("10c") },
        rules: &[],
        desc: "base64 of the compound LDAP filter — fires once §6 base64-decodes (10c)",
    },
    Case {
        id: "ldap-objectclass-enum-b64",
        module: Module::Ldap,
        field: Field::Query { name: "search", value: "Kih8KG9iamVjdGNsYXNzPSopKQ==" },
        min_pl: 1,
        expect: Expect::ExpectedMiss { until_phase: Some("10c") },
        rules: &[],
        desc: "base64 of the objectclass-enum filter — fires once §6 base64-decodes (10c)",
    },
    Case {
        id: "ldap-extensible-match-b64",
        module: Module::Ldap,
        field: Field::Query { name: "attr", value: "dXNlclBhc3N3b3JkOjIuNS4xMy4xODo9MTIz" },
        min_pl: 1,
        expect: Expect::ExpectedMiss { until_phase: Some("10c") },
        rules: &[],
        desc: "base64 of the extensible-match OID — fires once §6 base64-decodes (10c)",
    },
    // ── benign guards (must stay 200): the FP traps of this class ────────────────
    Case {
        id: "ldap-benign-single-filter",
        module: Module::Ldap,
        field: Field::Query { name: "filter", value: "(cn=John Doe)" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "legitimate single LDAP filter — no boolean combinator, must NOT flag",
    },
    Case {
        id: "ldap-benign-wildcard",
        module: Module::Ldap,
        field: Field::Query { name: "q", value: "john*" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "literal `*` wildcard search term — a lone wildcard must NOT flag",
    },
    Case {
        id: "ldap-benign-oid",
        module: Module::Ldap,
        field: Field::Query { name: "oid", value: "2.5.4.3" },
        min_pl: 1,
        expect: Expect::Clean,
        rules: &[],
        desc: "bare OID value (no `(&(`/`(|(` combinator) — must NOT flag",
    },
];
