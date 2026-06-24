// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! Shared state seam (BOUNDARY §1.5/§4). The `StateStore` trait is the public ABI
//! onto which the enterprise multi-node store (Redis/shared) plugs in without a
//! fork; the in-memory token-bucket implementation is the OPEN single-node default.
//! Lives in `waf-core` (not a separate `waf-state` crate) because the consumers
//! (`waf-detection`'s rate limiter, `waf-proxy`'s wiring) already depend on
//! `waf-core` — placing it here introduces no dependency cycle.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// ── clock (injectable for deterministic tests) ────────────────────────────────

/// Monotonic time source. `Instant` is opaque in Rust, so `ManualClock` starts
/// from a real `Instant::now()` and advances by adding `Duration` — it never
/// constructs arbitrary instants.
pub trait Clock: Send + Sync {
    fn now(&self) -> Instant;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// Test clock: advances explicitly via `advance`.
pub struct ManualClock {
    base: Instant,
    offset: Mutex<Duration>,
}

impl ManualClock {
    pub fn new() -> Self {
        Self { base: Instant::now(), offset: Mutex::new(Duration::ZERO) }
    }
    pub fn advance(&self, by: Duration) {
        *self.offset.lock().unwrap() += by;
    }
}

impl Default for ManualClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Instant {
        self.base + *self.offset.lock().unwrap()
    }
}

// ── StateStore (the frozen extension seam — BOUNDARY §4) ───────────────────────

/// Parameters of one token bucket, passed **per call** so the store stays free of
/// config: a hot reload changes capacity/refill on the module while the store keeps
/// the live buckets, and the same key can be re-parameterised without a store reset.
#[derive(Clone, Copy)]
pub struct BucketParams {
    pub capacity: f64,
    pub refill_per_sec: f64,
}

/// Outcome of one `try_acquire`. `tokens_remaining` is the bucket level **after**
/// the attempt (post-refill, post-consume on success) and feeds `Retry-After`.
pub struct Acquired {
    pub allowed: bool,
    pub tokens_remaining: f64,
}

/// The extension seam onto which the enterprise multi-node store plugs in
/// (Redis/shared store — BOUNDARY §2.1/§4). **Public ABI, frozen before the first
/// release (§5).**
///
/// The contract is a single *atomic* operation, not a get/update pair: refilling a
/// bucket and consuming from it MUST be indivisible w.r.t. concurrent callers,
/// otherwise two nodes (or threads) read the same level and both allow — a
/// cluster-wide over-allow (TOCTOU). In-memory enforces this under one lock; a
/// Redis impl uses a single server-side script. Time and memory-bounding are the
/// store's concern (in-memory owns a `Clock` and a tracked-key cap; Redis uses its
/// own server time and TTL), so they never appear in the ABI.
pub trait StateStore: Send + Sync {
    /// Atomically refill `key`'s bucket for the elapsed time, then try to take
    /// `cost` tokens. Allowed iff at least `cost` tokens are available.
    fn try_acquire(&self, key: &str, cost: f64, params: BucketParams) -> Acquired;
}

// ── in-memory token-bucket store (the OPEN impl) ───────────────────────────────

#[derive(Clone, Copy)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

struct InMemState {
    buckets: HashMap<String, Bucket>,
}

/// Default tracked-key cap, mirrors `RateLimitConfig`'s default. The cap is a
/// memory bound on this single-process store; a distributed store bounds memory
/// with TTL/maxmemory instead, which is why the cap is not part of the ABI.
const DEFAULT_MAX_TRACKED_KEYS: usize = 100_000;

/// In-memory token-bucket `StateStore`: the OPEN single-node implementation. The
/// refill-then-consume critical section is a short, synchronous map update (never
/// held across `.await`), so `std::Mutex` is the right choice.
pub struct InMemoryStateStore {
    clock: Arc<dyn Clock>,
    max_tracked_keys: usize,
    inner: Mutex<InMemState>,
}

impl InMemoryStateStore {
    pub fn new() -> Self {
        Self::with_clock(Arc::new(SystemClock))
    }

    /// Construct with a custom clock (deterministic tests). The clock lives on the
    /// store — time is part of how state advances, so it belongs with atomicity.
    pub fn with_clock(clock: Arc<dyn Clock>) -> Self {
        Self::with_clock_and_cap(clock, DEFAULT_MAX_TRACKED_KEYS)
    }

    pub fn with_clock_and_cap(clock: Arc<dyn Clock>, max_tracked_keys: usize) -> Self {
        Self {
            clock,
            max_tracked_keys: max_tracked_keys.max(1),
            inner: Mutex::new(InMemState { buckets: HashMap::new() }),
        }
    }

    /// Number of currently tracked keys (tests/metrics). Concrete-only: a count is
    /// cheap here but meaningless/expensive for a distributed store, so it is not
    /// on the `StateStore` trait.
    pub fn tracked_keys(&self) -> usize {
        self.inner.lock().unwrap().buckets.len()
    }

    /// Drop idle (fully refilled) buckets. A bucket whose elapsed time exceeds the
    /// full-refill duration is back at capacity — indistinguishable from a fresh
    /// key — so it is safe to evict.
    fn sweep_full_buckets(buckets: &mut HashMap<String, Bucket>, now: Instant, params: BucketParams) {
        if params.refill_per_sec <= 0.0 {
            return;
        }
        let full_refill = Duration::from_secs_f64(params.capacity / params.refill_per_sec);
        buckets.retain(|_, b| now.duration_since(b.last) < full_refill);
    }
}

impl Default for InMemoryStateStore {
    fn default() -> Self {
        Self::new()
    }
}

impl StateStore for InMemoryStateStore {
    fn try_acquire(&self, key: &str, cost: f64, params: BucketParams) -> Acquired {
        let now = self.clock.now();
        let mut state = self.inner.lock().unwrap();

        // Bound memory: before tracking a brand-new key at the cap, evict idle
        // (fully refilled) buckets.
        if !state.buckets.contains_key(key) && state.buckets.len() >= self.max_tracked_keys {
            Self::sweep_full_buckets(&mut state.buckets, now, params);
        }

        let bucket = state
            .buckets
            .entry(key.to_string())
            .or_insert(Bucket { tokens: params.capacity, last: now });

        // Refill based on elapsed time, then attempt to consume.
        let elapsed = now.duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * params.refill_per_sec).min(params.capacity);
        bucket.last = now;

        if bucket.tokens >= cost {
            bucket.tokens -= cost;
            Acquired { allowed: true, tokens_remaining: bucket.tokens }
        } else {
            Acquired { allowed: false, tokens_remaining: bucket.tokens }
        }
    }
}

/// Shared, **non-reloadable** rate-limit store handle. Lives outside the module so
/// a config hot reload (Fase 6 / Pillar 3) rebuilds the module's *parameters*
/// (capacity/refill/action) while the buckets **survive** — otherwise an attacker
/// could clear their own throttle by triggering a reload. Holds an
/// `Arc<dyn StateStore>` so the enterprise can inject a distributed store without
/// forking (the seam of BOUNDARY §4).
#[derive(Clone)]
pub struct RateLimitState(Arc<dyn StateStore>);

impl RateLimitState {
    /// In-memory store with the default tracked-key cap.
    pub fn new() -> Self {
        Self::in_memory(DEFAULT_MAX_TRACKED_KEYS)
    }

    /// In-memory store with an explicit tracked-key cap (system clock).
    pub fn in_memory(max_tracked_keys: usize) -> Self {
        Self::in_memory_with_clock(Arc::new(SystemClock), max_tracked_keys)
    }

    /// In-memory store with a custom clock + cap (deterministic tests).
    pub fn in_memory_with_clock(clock: Arc<dyn Clock>, max_tracked_keys: usize) -> Self {
        Self(Arc::new(InMemoryStateStore::with_clock_and_cap(clock, max_tracked_keys)))
    }

    /// Wrap an arbitrary store (the enterprise injection point).
    pub fn with_store(store: Arc<dyn StateStore>) -> Self {
        Self(store)
    }

    /// Delegate one atomic acquire to the underlying store. Exists so consumers in
    /// other crates (the rate-limit module) reach the store without touching the
    /// private handle — the store stays the single owner of the bucket state.
    pub fn try_acquire(&self, key: &str, cost: f64, params: BucketParams) -> Acquired {
        self.0.try_acquire(key, cost, params)
    }
}

impl Default for RateLimitState {
    fn default() -> Self {
        Self::new()
    }
}
