//! Differential canonicalization — Fase 8, smoke (target DEC 2 #1: the custom
//! percent-decoder / `canonicalize_value`, the security-critical anti-evasion code).
//!
//! Cross-platform, runs in `cargo test` (the always-on guard; cargo-fuzz adds
//! coverage-guided depth in CI). The oracle is an INDEPENDENT naive decoder with no
//! shared code, so a shared bug cannot mask itself.
//!
//! Equivalence relation (the part where a bypass hides):
//!
//! - (A) single-pass decode == oracle, BYTE-EXACT — pure correctness of our loop.
//! - (B) the canonical is an NFKC fixed-point — proves NFKC was actually applied.
//! - (C) vs full `decode_until_stable`, our 2-pass canonical diverges ONLY on inputs
//!   encoded >2 times. The test FALSIFIES this in both directions: `<=2`-encoded must
//!   NOT diverge (property), and known `>2`-encoded MUST diverge as predicted (fixed
//!   cases) — so the §6 "2 passes" bound is itself under test.
//!
//! Overlong UTF-8 is neutralized to the replacement char (lossy): a documented
//! WAF-vs-backend residual, NOT a WAF-vs-oracle divergence (the oracle is lossy too).

use proptest::prelude::*;
use unicode_normalization::UnicodeNormalization;
use waf_normalizer::url::{canonicalize_value, percent_decode};

// ── independent oracle (no shared code with production) ───────────────────────

fn hexval(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Naive single-pass percent decoder. Uses slice `.get()` so its bounds logic does
/// not share production's `i + 2 < len` arithmetic — an off-by-one would surface.
fn naive_decode(input: &str, plus: bool) -> String {
    let b = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if plus && c == b'+' {
            out.push(b' ');
            i += 1;
        } else if c == b'%' {
            match (
                b.get(i + 1).copied().and_then(hexval),
                b.get(i + 2).copied().and_then(hexval),
            ) {
                (Some(h), Some(l)) => {
                    out.push((h << 4) | l);
                    i += 3;
                }
                _ => {
                    out.push(c);
                    i += 1;
                }
            }
        } else {
            out.push(c);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// True if another decode pass would still change the string (more `%XX` present).
fn has_decodable(s: &str) -> bool {
    naive_decode(s, false) != *s
}

/// Full, UNBOUNDED canonicalization mirroring `canonicalize_value`'s pass semantics:
/// first pass honours `plus`, subsequent passes use `plus=false` (re-decoding does
/// not treat `+` as space), until a fixed point, then NFKC.
fn oracle_full(input: &str, plus: bool) -> String {
    let mut cur = naive_decode(input, plus);
    loop {
        let next = naive_decode(&cur, false);
        if next == cur {
            break;
        }
        cur = next;
    }
    cur.nfkc().collect()
}

// ── (A) single-pass byte-exact equality ──────────────────────────────────────

proptest! {
    #[test]
    fn prop_a_single_pass_equals_oracle(
        s in "[%+0-9a-zA-Z<>'\"./ -]{0,48}",
        plus in any::<bool>(),
    ) {
        let (ours, _) = percent_decode(&s, plus);
        prop_assert_eq!(ours, naive_decode(&s, plus));
    }
}

// ── (B) canonical is an NFKC fixed-point ──────────────────────────────────────

proptest! {
    #[test]
    fn prop_b_canonical_is_nfkc_stable(
        // Include fullwidth forms (U+FF00..FF5E) so NFKC has work to do; if
        // canonicalize forgot NFKC, the re-normalization would differ.
        s in "[%+0-9a-zA-Z\u{ff10}-\u{ff5a}<>]{0,48}",
        plus in any::<bool>(),
    ) {
        let (canon, _) = canonicalize_value(&s, plus);
        let renorm: String = canon.nfkc().collect();
        prop_assert_eq!(canon, renorm);
    }
}

// ── (C) divergence is exactly the >2-encoded set ──────────────────────────────

proptest! {
    #[test]
    fn prop_c_le2_never_diverges(
        s in "[%+0-9a-zA-Z<>'./ ]{0,40}",
        plus in any::<bool>(),
    ) {
        // Does our bounded (<=2) decode already reach the stable form?
        let d1 = naive_decode(&s, plus);
        let converged = if has_decodable(&d1) {
            let d2 = naive_decode(&d1, false);
            !has_decodable(&d2)
        } else {
            true
        };
        // When the stable form is reached within 2 passes, the WAF canonical MUST
        // equal the full decode — no divergence allowed on <=2-encoded input.
        if converged {
            let (canon, _) = canonicalize_value(&s, plus);
            prop_assert_eq!(canon, oracle_full(&s, plus));
        }
    }
}

#[test]
fn prop_c_gt2_must_diverge() {
    // `%252527` triple-encodes `'`. Our bounded 2-pass stops at `%27`; the full
    // decode reaches `'`. The divergence MUST exist and look exactly like this.
    let (canon, _) = canonicalize_value("%252527", true);
    assert_eq!(canon, "%27", "2-pass bound: our canonical must stop at %27");
    assert_eq!(oracle_full("%252527", true), "'", "full decode reaches the quote");
    assert_ne!(canon, oracle_full("%252527", true), "the >2-encoding divergence must exist");

    // A second witness, with a different target char (`<`).
    let (canon2, _) = canonicalize_value("%25253C", true);
    assert_eq!(canon2, "%3C", "2-pass stops at %3C");
    assert_eq!(oracle_full("%25253C", true), "<", "full decode reaches <");
    // If a future refactor makes the decoder 3-pass, the asserts above go RED →
    // the §6 "2 passes" bound is itself under test, not just the <=2 inputs.
}

#[test]
fn overlong_utf8_is_neutralized_not_decoded() {
    // `%C0%AE` is an overlong encoding of `.`. We decode to bytes C0 AE — invalid
    // UTF-8 → from_utf8_lossy → replacement char, NOT `.`. A lax backend that
    // accepts overlong would see `.`: a documented WAF-vs-backend residual (§6),
    // NOT a WAF-vs-oracle divergence (the oracle is lossy too).
    let (canon, _) = canonicalize_value("%C0%AE", true);
    assert!(!canon.contains('.'), "overlong must NOT decode to '.', got {canon:?}");
    assert!(canon.contains('\u{FFFD}'), "overlong bytes become the replacement char, got {canon:?}");
    // And the WAF agrees with the (lossy) oracle here — no differential divergence.
    assert_eq!(canon, oracle_full("%C0%AE", true));
}
