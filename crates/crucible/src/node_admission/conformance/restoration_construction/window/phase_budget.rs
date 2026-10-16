//! Keeps a whole-owner observation separate from the installed budget authority.
//!
//! The initial observed sum is not reserved, signed, serialized or exported as
//! an entitlement. Each later whole walk retains all original future rows and
//! charges current growth independently under the SAME installed policy. The
//! maximum observed sum is therefore DATA; it cannot replace per-owner native,
//! protocol, descriptor, proof, scratch or construction guards.

use super::*;

pub(super) fn observed_transaction_peak_data(
    installed: OriginalRestorationConstructionPolicy,
    current: OriginalRestorationConstructionPolicy,
    previous: Option<usize>,
    requested: usize,
) -> Result<usize, RuntimeError> {
    if installed != current {
        return Err(RuntimeError::ForeignAuthority);
    }
    let previous = previous.ok_or(RuntimeError::OwnerUnavailable)?;
    if previous > installed.maximum_requested_bytes || requested > installed.maximum_requested_bytes
    {
        return Err(RuntimeError::ResourceLimit);
    }
    Ok(previous.max(requested))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> OriginalRestorationConstructionPolicy {
        OriginalRestorationConstructionPolicy {
            maximum_requested_bytes: 1024,
            maximum_owned_descriptors: 7,
            declared_observer_scratch_bytes: 96,
        }
    }

    #[test]
    fn prepaid_retained_growth_uses_unchanged_policy_and_monotone_observation() {
        let policy = policy();
        // The complete future row stays in both sums. Actual current growth is
        // added rather than interpreted as a released commitment or new grant.
        let initial_current = 128usize;
        let all_future = 512usize;
        let initial = initial_current + all_future;
        let grown = initial_current + 64 + all_future;
        let high_water =
            observed_transaction_peak_data(policy, policy, Some(initial), grown).unwrap();
        assert_eq!(high_water, grown);
        assert_eq!(
            observed_transaction_peak_data(policy, policy, Some(high_water), initial).unwrap(),
            high_water
        );
        assert_eq!(
            observed_transaction_peak_data(policy, policy, Some(high_water), 1024).unwrap(),
            1024
        );
        assert!(matches!(
            observed_transaction_peak_data(policy, policy, Some(high_water), 1025),
            Err(RuntimeError::ResourceLimit)
        ));
    }

    #[test]
    fn another_policy_or_missing_original_admission_cannot_reuse_the_observation() {
        let original = policy();
        for changed in [
            OriginalRestorationConstructionPolicy {
                maximum_requested_bytes: 1025,
                ..original
            },
            OriginalRestorationConstructionPolicy {
                maximum_owned_descriptors: 8,
                ..original
            },
            OriginalRestorationConstructionPolicy {
                declared_observer_scratch_bytes: 97,
                ..original
            },
        ] {
            assert!(matches!(
                observed_transaction_peak_data(original, changed, Some(640), 704),
                Err(RuntimeError::ForeignAuthority)
            ));
        }
        assert!(matches!(
            observed_transaction_peak_data(original, original, None, 704),
            Err(RuntimeError::OwnerUnavailable)
        ));
    }
}
