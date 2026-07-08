//! Content-memo option accessors for `TreeWalkOptions`.
//!
//! Groups the knobs that govern the content-keyed memoization tiers: the
//! MEMO-1 in-process tables (L0 per-worker, L1 in-process shared), the
//! static-cost admission floor, capacity budgets, the shadow-check (CHECK)
//! modes, and the MEMO-2 durable tiers — the multi-location L2 disk
//! configuration (`AOS_NIX_MEMO_DISK`/`AOS_NIX_MEMO_L2`) and the L3 network
//! tier (`AOS_NIX_MEMO_NET*`). All of these are advisory performance
//! settings — none participate in the result-affecting options fingerprint,
//! and none may change evaluation output.

use super::*;

/// Access policy for the L3 network memo tier (`AOS_NIX_MEMO_NET_MODE`).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum MemoNetMode {
    /// Fetch-only (the default): the evaluator never publishes records.
    #[default]
    ReadOnly,
    /// Fetch and publish; intended for CI/trusted builders only.
    ReadWrite,
}

/// Configuration for the L3 network memo tier (RFC-0007 doc 29 §5.5).
///
/// The endpoint is a validation-shaped catalog, never an authority: a fetched
/// record is content-verified and its impure-input slice is revalidated
/// locally exactly like a local disk record before it can be used, and any
/// network failure is a cache miss, never an evaluation error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoNetOptions {
    /// Base endpoint URL (`AOS_NIX_MEMO_NET`), e.g. `http://host:port/memo`.
    pub endpoint: String,
    /// Fetch-only or fetch-and-publish (`AOS_NIX_MEMO_NET_MODE`).
    pub mode: MemoNetMode,
    /// Per-request timeout in milliseconds (`AOS_NIX_MEMO_NET_TIMEOUT_MS`).
    pub timeout_ms: u64,
}

impl TreeWalkOptions {
    /// Replaces the content-memo configuration.
    pub fn set_memo_options(&mut self, memo: MemoOptions) {
        self.memo = memo;
    }

    /// Returns the content-memo configuration.
    pub const fn memo_options(&self) -> &MemoOptions {
        &self.memo
    }

    /// Returns whether the per-worker L0 content-memo tier is active.
    ///
    /// True exactly when the master memo switch and the L0 tier switch are
    /// both enabled.
    pub const fn memo_l0_active(&self) -> bool {
        self.memo.enabled && self.memo.l0_enabled
    }

    /// Returns whether the in-process shared L1 content-memo tier is active.
    ///
    /// With the default (auto) policy the shared tier activates exactly when
    /// parallel workers are configured; an explicit `l1_enabled` override wins
    /// in either direction. The master memo switch always gates the tier.
    pub const fn memo_l1_active(&self) -> bool {
        self.memo.enabled
            && match self.memo.l1_enabled {
                Some(enabled) => enabled,
                None => self.parallel_workers.is_some(),
            }
    }

    /// Returns whether any content-memo tier is active.
    pub const fn memo_active(&self) -> bool {
        self.memo_l0_active() || self.memo_l1_active()
    }

    /// Replaces the secondary L2 disk locations (`AOS_NIX_MEMO_DISK`).
    ///
    /// The list should already be in probe order (fastest class first), as
    /// produced by `PersistDiskLocation::parse_list`.
    pub fn set_memo_disk_locations(&mut self, locations: Vec<PersistDiskLocation>) {
        self.memo_disk_locations = locations;
    }

    /// Returns the active secondary L2 disk locations in probe order.
    ///
    /// Empty when none are configured, when the `AOS_NIX_MEMO_L2` kill switch
    /// is off, or when no primary persist-cache root is set (secondaries are
    /// additive to the primary, never a replacement for it).
    pub fn memo_disk_locations(&self) -> &[PersistDiskLocation] {
        if self.memo.l2_enabled && self.persist_cache_root.is_some() {
            &self.memo_disk_locations
        } else {
            &[]
        }
    }

    /// Replaces the L3 network-tier configuration (`AOS_NIX_MEMO_NET*`).
    pub fn set_memo_net(&mut self, net: Option<MemoNetOptions>) {
        self.memo_net = net;
    }

    /// Returns the active L3 network-tier configuration.
    ///
    /// `None` when no endpoint is configured or when no primary persist-cache
    /// root is set: a network hit is installed into the primary location and
    /// revalidated through it, so the tier cannot operate without one.
    pub fn memo_net(&self) -> Option<&MemoNetOptions> {
        if self.persist_cache_root.is_some() {
            self.memo_net.as_ref()
        } else {
            None
        }
    }
}
