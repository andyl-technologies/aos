//! Production counters for persistent tier-2 compiled-body placement.
//!
//! The counters sit on cache operations, not force or dispatch paths. They are
//! therefore collected unconditionally without adding work to non-JIT package
//! evaluation and emitted only with the existing `AOS_NIX_EVAL_STATS=1` report.

/// One evaluator's persistent compiled-body cache activity.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(in crate::jit::engine) struct CompiledBodyCacheStats {
    /// Counts local and network lookup sequences.
    pub(in crate::jit::engine) lookups: u64,
    /// Counts records accepted from the primary L2 location.
    pub(in crate::jit::engine) primary_hits: u64,
    /// Counts absent or rejected primary L2 records.
    pub(in crate::jit::engine) primary_misses: u64,
    /// Counts records accepted from secondary L2 locations.
    pub(in crate::jit::engine) secondary_hits: u64,
    /// Counts lookup sequences with configured but unsuccessful secondary
    /// locations.
    pub(in crate::jit::engine) secondary_misses: u64,
    /// Counts records accepted from L3.
    pub(in crate::jit::engine) network_hits: u64,
    /// Counts authoritative L3 not-found responses.
    pub(in crate::jit::engine) network_misses: u64,
    /// Counts L3 transport or envelope failures.
    pub(in crate::jit::engine) network_errors: u64,
    /// Counts records rejected by semantic, codec, or CLIF validation.
    pub(in crate::jit::engine) validation_failures: u64,
    /// Counts successful secondary or network promotions into primary L2.
    pub(in crate::jit::engine) promotions: u64,
    /// Counts failed promotions into primary L2.
    pub(in crate::jit::engine) promotion_failures: u64,
    /// Counts successfully persisted newly compiled records.
    pub(in crate::jit::engine) writes: u64,
    /// Counts failed persistence attempts for newly compiled records.
    pub(in crate::jit::engine) write_failures: u64,
    /// Counts successful L3 publications.
    pub(in crate::jit::engine) publishes: u64,
    /// Counts failed L3 publication attempts.
    pub(in crate::jit::engine) publish_failures: u64,
    /// Sums accepted record bytes across every cache tier.
    pub(in crate::jit::engine) hit_bytes: u64,
    /// Sums newly compiled record bytes successfully persisted to primary L2.
    pub(in crate::jit::engine) written_bytes: u64,
    /// Tracks the largest accepted or newly persisted record.
    pub(in crate::jit::engine) maximum_record_bytes: u64,
}

impl CompiledBodyCacheStats {
    /// Adds an accepted record's size to the hit-byte counters.
    pub(super) fn observe_hit_bytes(&mut self, bytes: usize) {
        self.hit_bytes = self.hit_bytes.saturating_add(bytes as u64);
        self.maximum_record_bytes = self.maximum_record_bytes.max(bytes as u64);
    }

    /// Adds a newly persisted record's size to the write-byte counters.
    pub(super) fn observe_written_bytes(&mut self, bytes: usize) {
        self.written_bytes = self.written_bytes.saturating_add(bytes as u64);
        self.maximum_record_bytes = self.maximum_record_bytes.max(bytes as u64);
    }

    /// Renders the stable strict-JSON diagnostics object.
    pub(in crate::jit::engine) fn to_json(self) -> String {
        format!(
            "{{\"aos_nix_compiled_body_cache_stats\":{{\
             \"lookups\":{},\"primary_hits\":{},\"primary_misses\":{},\
             \"secondary_hits\":{},\"secondary_misses\":{},\
             \"network_hits\":{},\"network_misses\":{},\"network_errors\":{},\
             \"validation_failures\":{},\"promotions\":{},\"promotion_failures\":{},\
             \"writes\":{},\"write_failures\":{},\"publishes\":{},\
             \"publish_failures\":{},\"hit_bytes\":{},\"written_bytes\":{},\
             \"maximum_record_bytes\":{}\
             }}}}",
            self.lookups,
            self.primary_hits,
            self.primary_misses,
            self.secondary_hits,
            self.secondary_misses,
            self.network_hits,
            self.network_misses,
            self.network_errors,
            self.validation_failures,
            self.promotions,
            self.promotion_failures,
            self.writes,
            self.write_failures,
            self.publishes,
            self.publish_failures,
            self.hit_bytes,
            self.written_bytes,
            self.maximum_record_bytes,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_is_strict_json_with_stable_counter_names() {
        let stats = CompiledBodyCacheStats {
            lookups: 2,
            primary_hits: 1,
            written_bytes: 512,
            maximum_record_bytes: 384,
            ..CompiledBodyCacheStats::default()
        };
        let value: serde_json::Value =
            serde_json::from_str(&stats.to_json()).expect("cache stats are JSON");
        let report = &value["aos_nix_compiled_body_cache_stats"];
        assert_eq!(report["lookups"], 2);
        assert_eq!(report["primary_hits"], 1);
        assert_eq!(report["written_bytes"], 512);
    }
}
