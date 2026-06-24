// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use tracing::warn;
use waf_core::{
    BucketParams, Clock, Config, Decision, Phase, RateLimitAction, RateLimitKey, RateLimitState,
    RequestContext, WafModule,
};

// The token-bucket store, the `StateStore` seam, and the clock live in `waf-core`
// (`waf_core::state`) so the enterprise can inject a distributed store without a
// fork. This module is just the `WafModule` that drives that store from config.

pub struct RateLimitModule {
    enabled: bool,
    params: BucketParams,
    action: RateLimitAction,
    score: u32,
    key: RateLimitKey,
    state: RateLimitState,
}

impl Default for RateLimitModule {
    fn default() -> Self {
        Self::with_state(RateLimitState::new())
    }
}

impl RateLimitModule {
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct with a custom clock (used by tests): an in-memory store driven by
    /// that clock, default tracked-key cap.
    pub fn with_clock(clock: Arc<dyn Clock>) -> Self {
        Self::with_state(RateLimitState::in_memory_with_clock(clock, DEFAULT_MAX_TRACKED_KEYS))
    }

    /// Construct with a **shared** store, reinjected across reloads so the throttle
    /// state persists when only config parameters change.
    pub fn with_state(state: RateLimitState) -> Self {
        Self {
            enabled: false,
            params: BucketParams { capacity: 0.0, refill_per_sec: 0.0 },
            action: RateLimitAction::Block,
            score: 0,
            key: RateLimitKey::ClientIp,
            state,
        }
    }

    fn key_for(&self, ctx: &RequestContext) -> String {
        match self.key {
            // Peer socket address. Behind an LB/CDN this is the proxy IP — see
            // ARCHITECTURE §8 (X-Forwarded-For + trusted hops is the extension).
            RateLimitKey::ClientIp => ctx.client_ip.to_string(),
        }
    }

    /// Seconds until at least one token is available again (>= 1).
    fn retry_after(&self, tokens: f64) -> u64 {
        if self.params.refill_per_sec <= 0.0 {
            return 1;
        }
        ((1.0 - tokens) / self.params.refill_per_sec).ceil().max(1.0) as u64
    }
}

/// Default tracked-key cap used when constructing a test store via `with_clock`.
/// Mirrors `RateLimitConfig`'s default; the authoritative cap reaching production
/// comes from config through `RateLimitState::in_memory` at bind time.
const DEFAULT_MAX_TRACKED_KEYS: usize = 100_000;

impl WafModule for RateLimitModule {
    fn id(&self) -> &str {
        "rate_limit"
    }

    fn phase(&self) -> Phase {
        Phase::Connection
    }

    fn init(&mut self, cfg: &Config) {
        let rl = &cfg.rate_limit;
        self.enabled = rl.enabled;
        let window = rl.window_seconds.max(1) as f64;
        self.params = BucketParams {
            capacity: rl.burst.unwrap_or(rl.requests).max(1) as f64,
            refill_per_sec: rl.requests as f64 / window,
        };
        self.action = rl.action;
        self.score = rl.score;
        self.key = rl.key;
    }

    fn inspect(&self, ctx: &RequestContext) -> Decision {
        if !self.enabled {
            return Decision::Allow;
        }

        let key = self.key_for(ctx);

        // One atomic refill-then-consume against the (possibly distributed) store.
        let outcome = self.state.try_acquire(&key, 1.0, self.params);
        if outcome.allowed {
            return Decision::Allow;
        }
        let tokens_after = outcome.tokens_remaining;

        // Over budget.
        match self.action {
            RateLimitAction::Block => {
                let retry = self.retry_after(tokens_after);
                warn!(
                    request_id = %ctx.request_id,
                    key = %key,
                    retry_after = retry,
                    "rate limit exceeded (block)"
                );
                Decision::Reject {
                    rule_id: "rate-limit".to_string(),
                    reason: "rate limit exceeded".to_string(),
                    status: 429,
                    retry_after: Some(retry),
                }
            }
            RateLimitAction::Score => {
                warn!(
                    request_id = %ctx.request_id,
                    key = %key,
                    points = self.score,
                    "rate limit exceeded (score)"
                );
                Decision::Score {
                    rule_id: "rate-limit-exceeded".to_string(),
                    points: self.score,
                }
            }
        }
    }
}
