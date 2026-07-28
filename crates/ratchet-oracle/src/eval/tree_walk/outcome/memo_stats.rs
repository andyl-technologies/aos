//! Content-memo tier events and opt-in economics instrumentation.
//!
//! `MemoTierEvents` carries durable L2/L3 activity into evaluator statistics.
//! `MemoEconomicsStats` is populated only under `AOS_NIX_MEMO_STATS=1`; its
//! clock sampling and potential-hit census are deliberately absent from normal
//! parity and benchmark runs.

/// Durable-tier (L2 secondary-location and L3 network) memo event counts.
///
/// The root-cutoff orchestration in `aos-nix` runs outside the evaluator, so a
/// warm cutoff never constructs a tree walker. These events are folded into
/// the final evaluation statistics after root-cutoff orchestration completes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MemoTierEvents {
    /// Records served from a secondary L2 disk location.
    pub l2_secondary_hits: u64,
    /// Probes that consulted at least one secondary L2 location and missed.
    pub l2_secondary_misses: u64,
    /// Records copied into the primary location after a slower-tier hit.
    pub l2_promotions: u64,
    /// L2 records rejected because their impure-input slice failed validation.
    pub l2_reval_failures: u64,
    /// Records fetched, validated, and accepted from the L3 network tier.
    pub net_hits: u64,
    /// Network probes answered with "no such record".
    pub net_misses: u64,
    /// Network probes that failed transport or content validation.
    pub net_errors: u64,
    /// L3 records rejected because their impure-input slice failed validation.
    pub net_reval_failures: u64,
}

/// Opt-in cold-evaluation content-memo economics counters.
///
/// Potential-hit counters are collected even when the L0/L1 tables are off:
/// every successfully derived admitted key enters a census, and each repeated
/// key contributes one potential hit plus the def-site's static recompute cost.
/// The same census shadows Pending-to-Ready recipe transitions, conservative
/// avoidable work bytes, and derivation decline classes without changing force
/// semantics. Timing counters decompose key derivation, table probes,
/// resident-hit replay, and record construction. All durations are saturating
/// nanosecond totals.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MemoEconomicsStats {
    pub(crate) potential_candidates: u64,
    pub(crate) potential_unique_keys: u64,
    pub(crate) potential_hit_keys: u64,
    pub(crate) potential_hits: u64,
    pub(crate) potential_hit_static_cost_units: u64,
    pub(crate) ready_structural_hits: u64,
    pub(crate) recursive_structural_repeats: u64,
    pub(crate) ready_structural_work_bytes: u64,
    pub(crate) effect_or_unsafe_declines: u64,
    pub(crate) dynamic_scope_declines: u64,
    pub(crate) unknown_capture_declines: u64,
    pub(crate) key_samples: u64,
    pub(crate) key_nanos: u64,
    pub(crate) probe_samples: u64,
    pub(crate) probe_nanos: u64,
    pub(crate) hit_samples: u64,
    pub(crate) hit_nanos: u64,
    pub(crate) record_samples: u64,
    pub(crate) record_nanos: u64,
}

impl MemoEconomicsStats {
    /// Returns admitted key derivations observed by the potential-hit census.
    pub const fn potential_candidates(&self) -> u64 {
        self.potential_candidates
    }

    /// Returns distinct admitted keys observed by the census.
    pub const fn potential_unique_keys(&self) -> u64 {
        self.potential_unique_keys
    }

    /// Returns distinct keys observed at least twice.
    pub const fn potential_hit_keys(&self) -> u64 {
        self.potential_hit_keys
    }

    /// Returns admitted-key occurrences after each key's first occurrence.
    pub const fn potential_hits(&self) -> u64 {
        self.potential_hits
    }

    /// Returns static recompute-cost units represented by potential hits.
    pub const fn potential_hit_static_cost_units(&self) -> u64 {
        self.potential_hit_static_cost_units
    }

    /// Returns repeats whose earlier exact structural recipe was already Ready.
    pub const fn ready_structural_hits(&self) -> u64 {
        self.ready_structural_hits
    }

    /// Returns repeats overlapping an earlier incomplete congruent force.
    pub const fn recursive_structural_repeats(&self) -> u64 {
        self.recursive_structural_repeats
    }

    /// Returns the approximate suspended-work bytes avoidable by Ready hits.
    ///
    /// This is a deliberately conservative record-only estimate: one
    /// [`EvalThunk`](crate::eval::EvalThunk) payload per Ready repeat. It does
    /// not claim captured environment or result-payload savings.
    pub const fn ready_structural_work_bytes(&self) -> u64 {
        self.ready_structural_work_bytes
    }

    /// Returns sites declined because code is effectful or not lookup-safe.
    pub const fn effect_or_unsafe_declines(&self) -> u64 {
        self.effect_or_unsafe_declines
    }

    /// Returns candidates declined because they capture dynamic scopes.
    pub const fn dynamic_scope_declines(&self) -> u64 {
        self.dynamic_scope_declines
    }

    /// Returns candidates declined because a captured value has no stable hash.
    pub const fn unknown_capture_declines(&self) -> u64 {
        self.unknown_capture_declines
    }

    /// Returns timed key-derivation attempts.
    pub const fn key_samples(&self) -> u64 {
        self.key_samples
    }

    /// Returns nanoseconds spent deriving keys.
    pub const fn key_nanos(&self) -> u64 {
        self.key_nanos
    }

    /// Returns timed L0/L1 table probes.
    pub const fn probe_samples(&self) -> u64 {
        self.probe_samples
    }

    /// Returns nanoseconds spent probing L0/L1 tables.
    pub const fn probe_nanos(&self) -> u64 {
        self.probe_nanos
    }

    /// Returns timed resident-entry replay attempts.
    pub const fn hit_samples(&self) -> u64 {
        self.hit_samples
    }

    /// Returns nanoseconds spent revalidating and replaying resident entries.
    pub const fn hit_nanos(&self) -> u64 {
        self.hit_nanos
    }

    /// Returns timed memo record attempts.
    pub const fn record_samples(&self) -> u64 {
        self.record_samples
    }

    /// Returns nanoseconds spent constructing and publishing memo records.
    pub const fn record_nanos(&self) -> u64 {
        self.record_nanos
    }

    /// Returns the saturating sum of two worker-local statistics snapshots.
    pub(crate) const fn merged(self, other: Self) -> Self {
        Self {
            potential_candidates: self
                .potential_candidates
                .saturating_add(other.potential_candidates),
            potential_unique_keys: self
                .potential_unique_keys
                .saturating_add(other.potential_unique_keys),
            potential_hit_keys: self
                .potential_hit_keys
                .saturating_add(other.potential_hit_keys),
            potential_hits: self.potential_hits.saturating_add(other.potential_hits),
            potential_hit_static_cost_units: self
                .potential_hit_static_cost_units
                .saturating_add(other.potential_hit_static_cost_units),
            ready_structural_hits: self
                .ready_structural_hits
                .saturating_add(other.ready_structural_hits),
            recursive_structural_repeats: self
                .recursive_structural_repeats
                .saturating_add(other.recursive_structural_repeats),
            ready_structural_work_bytes: self
                .ready_structural_work_bytes
                .saturating_add(other.ready_structural_work_bytes),
            effect_or_unsafe_declines: self
                .effect_or_unsafe_declines
                .saturating_add(other.effect_or_unsafe_declines),
            dynamic_scope_declines: self
                .dynamic_scope_declines
                .saturating_add(other.dynamic_scope_declines),
            unknown_capture_declines: self
                .unknown_capture_declines
                .saturating_add(other.unknown_capture_declines),
            key_samples: self.key_samples.saturating_add(other.key_samples),
            key_nanos: self.key_nanos.saturating_add(other.key_nanos),
            probe_samples: self.probe_samples.saturating_add(other.probe_samples),
            probe_nanos: self.probe_nanos.saturating_add(other.probe_nanos),
            hit_samples: self.hit_samples.saturating_add(other.hit_samples),
            hit_nanos: self.hit_nanos.saturating_add(other.hit_nanos),
            record_samples: self.record_samples.saturating_add(other.record_samples),
            record_nanos: self.record_nanos.saturating_add(other.record_nanos),
        }
    }
}
