//! Admits separate installed-factory banks without changing native source rows.

use super::{NativeArchiveLimits, StateError, refused};

/// Bounds a complete factory's own requested banks independently of native rows.
///
/// These are inert accounting values, not installation or capture permission.
/// The actual installed implementation counts its current owners and uses the
/// closed source record projector for future cache/dependency-reader scratch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompleteOriginalCaptureFactoryStorage {
    /// Counts actual retained factory/cache allocation capacities now.
    pub actual_retained_bytes: usize,
    /// Bounds the same retained owners after closed cache preparation.
    pub maximum_retained_bytes: usize,
    /// Bounds additional simultaneous projection and reader requested scratch.
    pub maximum_transient_bytes: usize,
}

impl CompleteOriginalCaptureFactoryStorage {
    /// Computes the conservative simultaneous requested factory peak.
    ///
    /// # Errors
    /// Refuses arithmetic overflow without allocating or creating authority.
    pub fn peak(&self) -> Result<usize, StateError> {
        self.maximum_retained_bytes
            .checked_add(self.maximum_transient_bytes)
            .ok_or_else(|| refused("complete factory allocation peak overflow"))
    }

    pub(super) fn validate(&self, limits: NativeArchiveLimits) -> Result<(), StateError> {
        if self.actual_retained_bytes > self.maximum_retained_bytes
            || self.peak()? > limits.state.maximum_total_content_bytes
            || self.peak()? > limits.native.maximum_total_record_bytes
        {
            return Err(refused(
                "complete factory allocation exceeds finite capture credit",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returned_factory_capacity_cannot_exceed_its_original_precharge() {
        let limits = NativeArchiveLimits::default();
        let demand = CompleteOriginalCaptureFactoryStorage {
            actual_retained_bytes: 8192,
            maximum_retained_bytes: 4096,
            maximum_transient_bytes: 0,
        };
        assert!(demand.validate(limits).is_err());
    }

    #[test]
    fn factory_peak_checks_both_independent_total_limits_and_overflow() {
        let mut limits = NativeArchiveLimits::default();
        limits.state.maximum_total_content_bytes = 100;
        limits.native.maximum_total_record_bytes = 200;
        let demand = CompleteOriginalCaptureFactoryStorage {
            actual_retained_bytes: 60,
            maximum_retained_bytes: 60,
            maximum_transient_bytes: 41,
        };
        assert!(demand.validate(limits).is_err());
        limits.state.maximum_total_content_bytes = 200;
        limits.native.maximum_total_record_bytes = 100;
        assert!(demand.validate(limits).is_err());
        let overflow = CompleteOriginalCaptureFactoryStorage {
            actual_retained_bytes: 0,
            maximum_retained_bytes: usize::MAX,
            maximum_transient_bytes: 1,
        };
        assert!(overflow.peak().is_err());
    }
}
