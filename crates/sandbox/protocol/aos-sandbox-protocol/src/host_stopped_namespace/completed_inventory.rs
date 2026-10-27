//! Keeps completed Host inventory provenance separate from fresh native absence.
//!
//! Resident V4, historical V7 and authenticated cleanup-lineage observations
//! retain their literal formats. This fold produces comparison DATA only. In
//! particular, a cleanup lineage still needs the actual current C/A8 history
//! join before a native consumer may use its historical scope.

use super::HostStoppedNamespaceDataV4;
use crate::{
    ProtocolValidationError,
    host_cleanup_lineage::HostCleanupLineageDataV1,
    host_recovered_namespace::{HostRecoveredNamespaceDataV7, HostRecoveryStopPhaseDataV7},
};

/// Preserves the provenance of one stopped-runtime inventory observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostStoppedInventoryDataV1 {
    /// Carries the original resident Stop disposal scope.
    Resident(HostStoppedNamespaceDataV4),
    /// Carries historical Stop phase and separate fresh native absence.
    Recovered(HostRecoveredNamespaceDataV7),
    /// Carries a MAC-chain leaf and separate fresh native absence.
    Cleanup(HostCleanupLineageDataV1),
}

impl HostStoppedInventoryDataV1 {
    /// Decodes the sole selected inventory family without a legacy fallback.
    ///
    /// # Errors
    /// Refuses malformed, duplicate or mixed historical families. Present
    /// cleanup candidates remain outside this stopped-only fold.
    pub fn from_inventory_v1(
        inventory: &aos_sandbox_api::aos::sandbox::local::v1::InventoryRuntimeResponse,
    ) -> Result<Option<Self>, ProtocolValidationError> {
        if !inventory.present_stop_cleanup_candidates_v1.is_empty() {
            return Err(invalid());
        }
        if !inventory.cleanup_lineages_v1.is_empty() {
            return crate::host_cleanup_lineage::HostCleanupLineageDataV1::from_inventory_v1(
                inventory,
            )
            .map(|value| value.map(Self::Cleanup));
        }
        if !inventory.recovered_namespaces_v7.is_empty() {
            return HostRecoveredNamespaceDataV7::from_inventory_v7(inventory)
                .map(|value| value.map(Self::Recovered));
        }
        match inventory.stopped_namespaces_v4.as_slice() {
            [] => Ok(None),
            [scope] => {
                if !inventory.native_absence_v5.is_empty()
                    || !inventory.__buffa_unknown_fields.is_empty()
                {
                    return Err(invalid());
                }
                HostStoppedNamespaceDataV4::decode_v4(scope)
                    .map(|scope| Some(Self::Resident(scope)))
            }
            _ => Err(invalid()),
        }
    }

    /// Borrows the unchanged historical Launch/Stop identity.
    #[must_use]
    pub const fn historical_scope_v1(&self) -> &HostStoppedNamespaceDataV4 {
        match self {
            Self::Resident(scope) => scope,
            Self::Recovered(row) => row.historical_scope_v7(),
            Self::Cleanup(row) => row.subject_v1().historical_scope_v1(),
        }
    }

    /// Checks the fresh query interval while preserving historical boot identity.
    ///
    /// Cleanup DATA may name an older boot. Its consumer must additionally join
    /// actual current Controller completion and canonical Source A8 history;
    /// this comparison cannot grant that native permission. Legacy resident and
    /// V7 completion keep their existing same-boot restriction.
    ///
    /// # Errors
    /// Refuses noncomplete V7, foreign or reused queries, extended intervals,
    /// rollback, and observations outside the actual signed request deadline.
    pub fn require_completed_v1(
        &self,
        request: [u8; 16],
        boot: [u8; 16],
        not_before: u64,
        observed: u64,
        deadline: u64,
    ) -> Result<&HostStoppedNamespaceDataV4, ProtocolValidationError> {
        let scope = self.historical_scope_v1();
        if request == [0; 16]
            || request == scope.launch_v4().0
            || request == scope.stop_v4().0
            || observed >= deadline
            || not_before > observed
        {
            return Err(invalid());
        }
        let observation = match self {
            Self::Resident(_) => {
                if scope.boot_v4() != &boot {
                    return Err(invalid());
                }
                return Ok(scope);
            }
            Self::Recovered(row) => {
                if row.saved_phase_v7() != HostRecoveryStopPhaseDataV7::Complete
                    || scope.boot_v4() != &boot
                {
                    return Err(invalid());
                }
                row.observation_v7()
            }
            Self::Cleanup(row) => row.observation_v1(),
        };
        let (before, after) = observation.boottime_interval_v5();
        if observation.request_id_v5() != &request
            || observation.boot_v5() != &boot
            || before < not_before
            || after > observed
            || after >= deadline
        {
            return Err(invalid());
        }
        Ok(scope)
    }

    /// Commits stable cleanup-chain identity without a fresh query's nonce/clocks.
    ///
    /// The exact 648-byte observation remains separately retained. This digest
    /// is solely a physical-successor comparison, never a wire row or proof.
    #[must_use]
    pub fn cleanup_physical_commitment_v1(&self) -> Option<[u8; 32]> {
        use sha2::{Digest as _, Sha256};
        let Self::Cleanup(row) = self else {
            return None;
        };
        let bytes = row.encode_v1();
        Some(
            Sha256::new()
                .chain_update(b"aos.sandbox.host-cleanup.physical-inventory.v1\0")
                .chain_update(&bytes[..544])
                .chain_update(&bytes[616..])
                .finalize()
                .into(),
        )
    }

    /// Returns the fresh census interval, or the resident query's native point.
    ///
    /// The supplied scalar is comparison DATA from the actual signed/native
    /// inventory owner. This accessor neither samples nor authenticates it.
    #[must_use]
    pub fn observation_interval_v1(&self, resident_observed: u64) -> (u64, u64) {
        match self {
            Self::Resident(_) => (resident_observed, resident_observed),
            Self::Recovered(row) => row.observation_v7().boottime_interval_v5(),
            Self::Cleanup(row) => row.observation_v1().boottime_interval_v5(),
        }
    }
}

fn invalid() -> ProtocolValidationError {
    ProtocolValidationError::InvalidField("completed Host inventory comparison")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ValidatedAssignmentFence, host_inventory_absence::HostInventoryAbsenceDataV5,
        host_stop_cleanup::HostStopCleanupSubjectDataV1,
    };
    use aos_sandbox_api::aos::sandbox::local::v1::InventoryRuntimeResponse;

    fn lineage(request: u8, before: u64, after: u64) -> HostCleanupLineageDataV1 {
        let scope = HostStoppedNamespaceDataV4::from_data_v4(
            [1; 16],
            ValidatedAssignmentFence {
                sandbox_id: [2; 16],
                incarnation_id: [3; 16],
                assignment_epoch: 4,
                desired_generation: 5,
                assignment_digest: [6; 32],
            },
            [7; 32],
            ([8; 16], [9; 32], [10; 32]),
            ([11; 16], [12; 32], [13; 32]),
        )
        .unwrap();
        let subject = HostStopCleanupSubjectDataV1::from_data_v1(
            scope, [14; 16], [15; 16], [16; 32], [17; 16], [18; 32], 100,
        )
        .unwrap();
        HostCleanupLineageDataV1::from_data_v1(
            subject,
            ([15; 16], [19; 32], [20; 32]),
            HostInventoryAbsenceDataV5::from_data_v5(
                [request; 16],
                [21; 16],
                [22; 16],
                before,
                after,
            )
            .unwrap(),
            [23; 32],
        )
        .unwrap()
    }

    #[test]
    fn literal_cleanup_keeps_historical_boot_and_requires_the_actual_fresh_interval() {
        let row = lineage(24, 10, 12);
        let inventory = InventoryRuntimeResponse {
            cleanup_lineages_v1: vec![row.encode_v1().to_vec()],
            ..Default::default()
        };
        let selected = HostStoppedInventoryDataV1::from_inventory_v1(&inventory)
            .unwrap()
            .unwrap();

        assert_eq!(selected, HostStoppedInventoryDataV1::Cleanup(row));
        assert_eq!(
            selected
                .require_completed_v1([24; 16], [21; 16], 9, 13, 14)
                .unwrap()
                .boot_v4(),
            &[1; 16]
        );
        assert!(
            selected
                .require_completed_v1([25; 16], [21; 16], 9, 13, 14)
                .is_err()
        );
        assert!(
            selected
                .require_completed_v1([24; 16], [1; 16], 9, 13, 14)
                .is_err()
        );
        assert!(
            selected
                .require_completed_v1([24; 16], [21; 16], 11, 13, 14)
                .is_err()
        );
        assert!(
            selected
                .require_completed_v1([24; 16], [21; 16], 9, 11, 14)
                .is_err()
        );
        assert!(
            selected
                .require_completed_v1([24; 16], [21; 16], 9, 13, 12)
                .is_err()
        );

        // Decoding and currentness comparisons still supply no C/A8 or native
        // cleanup authority. The native consumer must join that separate owner.
        assert_eq!(row.encode_v1(), inventory.cleanup_lineages_v1[0].as_slice());
    }

    #[test]
    fn fresh_queries_share_only_stable_chain_identity_and_mixed_rows_refuse() {
        let first = lineage(24, 10, 12);
        let second = lineage(25, 13, 15);
        assert_ne!(first.encode_v1(), second.encode_v1());
        assert_eq!(
            HostStoppedInventoryDataV1::Cleanup(first).cleanup_physical_commitment_v1(),
            HostStoppedInventoryDataV1::Cleanup(second).cleanup_physical_commitment_v1()
        );
        let changed = HostCleanupLineageDataV1::from_data_v1(
            *second.subject_v1(),
            second.child_v1(),
            *second.observation_v1(),
            [26; 32],
        )
        .unwrap();
        assert_ne!(
            HostStoppedInventoryDataV1::Cleanup(first).cleanup_physical_commitment_v1(),
            HostStoppedInventoryDataV1::Cleanup(changed).cleanup_physical_commitment_v1()
        );

        let mut inventory = InventoryRuntimeResponse {
            cleanup_lineages_v1: vec![first.encode_v1().to_vec()],
            ..Default::default()
        };
        inventory.native_absence_v5 = first.observation_v1().encode_v5().to_vec();
        assert!(HostStoppedInventoryDataV1::from_inventory_v1(&inventory).is_err());
        inventory.cleanup_lineages_v1.clear();
        inventory.stopped_namespaces_v4.push(
            first
                .subject_v1()
                .historical_scope_v1()
                .encode_v4()
                .to_vec(),
        );
        assert!(HostStoppedInventoryDataV1::from_inventory_v1(&inventory).is_err());
    }

    #[test]
    fn historical_v7_does_not_gain_completion_or_cross_boot_permission() {
        let row = lineage(24, 10, 12);
        for phase in [
            HostRecoveryStopPhaseDataV7::AuthorizedAbsent,
            HostRecoveryStopPhaseDataV7::PayloadPending,
            HostRecoveryStopPhaseDataV7::Complete,
        ] {
            let recovered = HostRecoveredNamespaceDataV7::from_data_v7(
                *row.subject_v1().historical_scope_v1(),
                *row.observation_v1(),
                phase,
            );
            assert!(
                HostStoppedInventoryDataV1::Recovered(recovered)
                    .require_completed_v1([24; 16], [21; 16], 9, 13, 14)
                    .is_err()
            );
        }
    }
}
