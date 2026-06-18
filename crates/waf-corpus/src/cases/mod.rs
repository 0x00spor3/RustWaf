//! The corpus itself: per-module case tables (Fase 7 / Pilastro 1).
//!
//! Each submodule exposes a `pub static CASES: &[Case]`. [`all`] concatenates them
//! in module order. The harvest target is ≥1 `Triggers` case per rule of every
//! module, plus benign traffic / FP traps and the documented `ExpectedMiss` gaps.

use crate::Case;

pub mod header_injection;
pub mod lfi_rfi;
pub mod path_traversal;
pub mod rce;
pub mod request_smuggling;
pub mod sqli;
pub mod ssrf;
pub mod xss;

/// All per-module case tables, in module order.
pub static MODULE_TABLES: &[&[Case]] = &[
    sqli::CASES,
    xss::CASES,
    path_traversal::CASES,
    rce::CASES,
    lfi_rfi::CASES,
    ssrf::CASES,
    header_injection::CASES,
    request_smuggling::CASES,
];

/// Every case in the corpus, flattened.
pub fn all() -> Vec<Case> {
    MODULE_TABLES.iter().flat_map(|t| t.iter().copied()).collect()
}
