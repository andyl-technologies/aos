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

/// Configuration for the content-keyed memoization tiers.
///
/// The store is advisory: none of these performance settings participate in
/// the result-affecting options fingerprint. The master switch remains off by
/// default until corpus economics justify enabling it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoOptions {
    /// Master switch for the content memo (`AOS_NIX_MEMO`).
    pub enabled: bool,
    /// Enables the per-worker in-thread tier (`AOS_NIX_MEMO_L0`).
    pub l0_enabled: bool,
    /// Enables the in-process shared tier (`AOS_NIX_MEMO_L1`).
    ///
    /// `None` selects the default policy: on exactly under parallel evaluation.
    pub l1_enabled: Option<bool>,
    /// Static recompute-estimate admission floor (`AOS_NIX_MEMO_MIN_COST`).
    ///
    /// Def-sites below this lowered-IR cost estimate are never probed or
    /// recorded, keeping the memo off the force path for cheap subtrees.
    pub min_cost: u32,
    /// Per-worker L0 entry cap (`AOS_NIX_MEMO_L0_ENTRIES`).
    pub l0_entries: usize,
    /// L1 retained-bytes budget (`AOS_NIX_MEMO_L1_BYTES`).
    pub l1_bytes: u64,
    /// Hits at L1 before an entry also installs at L0.
    ///
    /// Configured by `AOS_NIX_MEMO_PROMOTE_HITS`.
    pub promote_hits: u32,
    /// Shadow-checks every L0 hit against a fresh evaluation.
    pub check_l0: bool,
    /// Shadow-checks every L1 hit against a fresh evaluation.
    pub check_l1: bool,
    /// Enables secondary L2 disk locations.
    ///
    /// This is the `AOS_NIX_MEMO_L2` kill switch. It governs only additive
    /// `AOS_NIX_MEMO_DISK` locations; the primary cache remains independent.
    pub l2_enabled: bool,
    /// Shadow-checks every secondary-location L2 hit.
    pub check_l2: bool,
    /// Shadow-checks every network-tier L3 hit.
    pub check_l3: bool,
    /// Enables potential-hit census and stage timing (`AOS_NIX_MEMO_STATS`).
    pub stats_enabled: bool,
}

impl Default for MemoOptions {
    fn default() -> Self {
        Self {
            enabled: false,
            l0_enabled: true,
            l1_enabled: None,
            min_cost: 64,
            l0_entries: 65_536,
            l1_bytes: 256 * 1024 * 1024,
            promote_hits: 2,
            check_l0: false,
            check_l1: false,
            l2_enabled: true,
            check_l2: false,
            check_l3: false,
            stats_enabled: false,
        }
    }
}

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
