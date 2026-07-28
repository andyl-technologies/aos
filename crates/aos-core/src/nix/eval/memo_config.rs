//! Native content-memo configuration types and environment snapshot.
//!
//! The plain settings types keep the advisory memo configuration available
//! when the native evaluator feature is disabled. Parsing stays on
//! `NixEvalConfig`, beside the other environment-backed evaluator knobs.

/// Parsed `AOS_NIX_MEMO*` settings for native content-keyed memo tiers.
///
/// Mirrors the native evaluator's memo options with plain types so the
/// configuration exists independently of the `native-eval` feature. Every
/// field is advisory and cannot affect evaluation results.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeMemoSettings {
    /// Master switch (`AOS_NIX_MEMO`).
    pub enabled: bool,
    /// Per-worker in-thread tier switch (`AOS_NIX_MEMO_L0`).
    pub l0_enabled: bool,
    /// In-process shared tier override (`AOS_NIX_MEMO_L1`).
    pub l1_enabled: Option<bool>,
    /// Static recompute-estimate admission floor (`AOS_NIX_MEMO_MIN_COST`).
    pub min_cost: u32,
    /// Per-worker L0 entry cap (`AOS_NIX_MEMO_L0_ENTRIES`).
    pub l0_entries: usize,
    /// L1 retained-bytes budget (`AOS_NIX_MEMO_L1_BYTES`).
    pub l1_bytes: u64,
    /// L1 hits required before promotion into L0 (`AOS_NIX_MEMO_PROMOTE_HITS`).
    pub promote_hits: u32,
    /// Whether every L0 hit is shadow-checked (`AOS_NIX_MEMO_CHECK`).
    pub check_l0: bool,
    /// Whether every L1 hit is shadow-checked (`AOS_NIX_MEMO_CHECK`).
    pub check_l1: bool,
    /// Secondary L2 disk-location kill switch (`AOS_NIX_MEMO_L2`).
    ///
    /// This governs only additive `AOS_NIX_MEMO_DISK` locations; the primary
    /// `AOS_NIX_CACHE` location retains its independent controls.
    pub l2_enabled: bool,
    /// Whether every secondary L2 hit is shadow-checked (`AOS_NIX_MEMO_CHECK`).
    pub check_l2: bool,
    /// Whether every network-tier L3 hit is shadow-checked (`AOS_NIX_MEMO_CHECK`).
    pub check_l3: bool,
    /// Whether potential-hit census and stage timing are enabled.
    pub stats_enabled: bool,
    /// Whether the worker-local one-way Ready-cell directory is enabled.
    pub local_ready_enabled: bool,
}

impl Default for NativeMemoSettings {
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
            local_ready_enabled: false,
        }
    }
}

/// Parsed `AOS_NIX_MEMO_NET*` settings for the L3 network tier.
///
/// The advisory tier is read-only by default and only activates alongside a
/// configured primary `AOS_NIX_CACHE` root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeMemoNetSettings {
    /// Base endpoint URL.
    pub endpoint: String,
    /// Whether publishing is allowed (`AOS_NIX_MEMO_NET_MODE=rw`).
    pub writable: bool,
    /// Per-request timeout in milliseconds.
    pub timeout_ms: u64,
}

pub(super) const NATIVE_MEMO_NET_DEFAULT_TIMEOUT_MS: u64 = 2_000;

/// One snapshot of raw `AOS_NIX_MEMO*` environment values.
#[derive(Clone, Debug, Default)]
pub(super) struct EnvMemoKnobs {
    pub(super) master: Option<String>,
    pub(super) l0: Option<String>,
    pub(super) l1: Option<String>,
    pub(super) l2: Option<String>,
    pub(super) min_cost: Option<String>,
    pub(super) l0_entries: Option<String>,
    pub(super) l1_bytes: Option<String>,
    pub(super) promote_hits: Option<String>,
    pub(super) check: Option<String>,
    pub(super) stats: Option<String>,
    pub(super) local_ready: Option<String>,
    pub(super) disk: Option<String>,
    pub(super) net: Option<String>,
    pub(super) net_mode: Option<String>,
    pub(super) net_timeout_ms: Option<String>,
}

impl EnvMemoKnobs {
    /// Captures the process environment's memo knobs.
    pub(super) fn from_process() -> Self {
        Self {
            master: std::env::var("AOS_NIX_MEMO").ok(),
            l0: std::env::var("AOS_NIX_MEMO_L0").ok(),
            l1: std::env::var("AOS_NIX_MEMO_L1").ok(),
            l2: std::env::var("AOS_NIX_MEMO_L2").ok(),
            min_cost: std::env::var("AOS_NIX_MEMO_MIN_COST").ok(),
            l0_entries: std::env::var("AOS_NIX_MEMO_L0_ENTRIES").ok(),
            l1_bytes: std::env::var("AOS_NIX_MEMO_L1_BYTES").ok(),
            promote_hits: std::env::var("AOS_NIX_MEMO_PROMOTE_HITS").ok(),
            check: std::env::var("AOS_NIX_MEMO_CHECK").ok(),
            stats: std::env::var("AOS_NIX_MEMO_STATS").ok(),
            local_ready: std::env::var("AOS_NIX_LOCAL_READY").ok(),
            disk: std::env::var("AOS_NIX_MEMO_DISK").ok(),
            net: std::env::var("AOS_NIX_MEMO_NET").ok(),
            net_mode: std::env::var("AOS_NIX_MEMO_NET_MODE").ok(),
            net_timeout_ms: std::env::var("AOS_NIX_MEMO_NET_TIMEOUT_MS").ok(),
        }
    }
}
