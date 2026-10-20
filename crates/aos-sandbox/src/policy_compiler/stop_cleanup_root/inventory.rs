//! Selects effectful versus completed cleanup from authenticated Host inventory.
//!
//! The native issuer supplies this DATA only after full Session replay, current
//! Recover authorization and independent Source A7 selection. These predicates
//! cannot construct any of those owners, an old Stop, or a signing loan.

use aos_proto::aos::sandbox::local::v1::InventoryRuntimeResponse;
use aos_sandbox_core::{CanonicalAssignmentManifestV1, RawPairedClockSample};
use aos_sandbox_protocol::{
    host_cleanup_lineage::HostCleanupLineageDataV1,
    host_inventory_absence::HostInventoryAbsenceDataV5,
    host_launch_cleanup_candidate::HostLaunchCleanupCandidateDataV1,
    host_recovered_namespace::{HostRecoveredNamespaceDataV7, HostRecoveryStopPhaseDataV7},
    host_stop_cleanup::HostStopCleanupSubjectDataV1,
    host_stop_cleanup_candidate::HostStopCleanupCandidateDataV1,
    host_stopped_namespace::{HostStoppedNamespaceDataV4, HostStoppedRequestIdentityDataV4},
};

use crate::journal::JournalError;

/// Copies only coordinates from this issuer's actual signed Inventory3 request.
#[derive(Clone, Copy)]
pub(super) struct QueryData {
    pub(super) request: [u8; 16],
    pub(super) boot: [u8; 16],
    pub(super) recipient: Option<[u8; 16]>,
    pub(super) first: u64,
    pub(super) cutoff: u64,
    pub(super) observed: RawPairedClockSample,
}

/// Keeps only the new current Recover's already independently checked fields.
#[derive(Clone, Copy)]
pub(super) struct RecoveryData {
    pub(super) recovery: [u8; 16],
    pub(super) cleanup: [u8; 16],
    pub(super) request: [u8; 32],
    pub(super) revision: [u8; 32],
    pub(super) cutoff: u64,
}

/// Retains the literal completed evidence without fabricating a new child.
#[derive(Clone, Copy)]
pub(super) enum Completed {
    Historical(HostRecoveredNamespaceDataV7),
    Cleanup(HostCleanupLineageDataV1),
}

impl Completed {
    pub(super) fn scope(self) -> HostStoppedNamespaceDataV4 {
        match self {
            Self::Historical(value) => *value.historical_scope_v7(),
            Self::Cleanup(value) => *value.subject_v1().historical_scope_v1(),
        }
    }
}

/// Separates a new signed effect subject from prior complete observation DATA.
#[derive(Clone, Copy)]
pub(super) enum Selection {
    Effect(HostStopCleanupSubjectDataV1),
    Complete(Completed),
}

/// Compares the exact native-backed signed population and immutable Source tuple.
pub(super) fn select(
    inventory: &InventoryRuntimeResponse,
    query: QueryData,
    recovery: RecoveryData,
    manifest: &CanonicalAssignmentManifestV1,
    desired_generation: u64,
    dispatch: HostStoppedRequestIdentityDataV4,
) -> Result<(Selection, [u8; 16]), JournalError> {
    if !inventory.__buffa_unknown_fields.is_empty()
        || query.boot != query.observed.host_boot_id()
        || query.first > query.observed.boottime_nanoseconds()
        || query.observed.boottime_nanoseconds() >= query.cutoff
        || query.cutoff > recovery.cutoff
        || query.request == recovery.cleanup
        || query.request == recovery.recovery
    {
        return Err(JournalError::ProtectedBoundary);
    }

    // Select the explicit grammar before decoding. A malformed/mixed selected
    // branch never falls back to another population or legacy absence format.
    let selected = if !inventory.cleanup_lineages_v1.is_empty() {
        let value = HostCleanupLineageDataV1::from_inventory_v1(inventory)
            .map_err(|_| JournalError::ProtectedBoundary)?
            .ok_or(JournalError::ProtectedBoundary)?;
        let recipient = require_observation(*value.observation_v1(), query)?;
        // The prior cleanup's Recover ID remains historical. A new current
        // Recover does not rewrite it, fabricate another child or reissue Stop.
        (Selection::Complete(Completed::Cleanup(value)), recipient)
    } else if !inventory.recovered_namespaces_v7.is_empty() {
        let value = HostRecoveredNamespaceDataV7::from_inventory_v7(inventory)
            .map_err(|_| JournalError::ProtectedBoundary)?
            .ok_or(JournalError::ProtectedBoundary)?;
        let recipient = require_observation(*value.observation_v7(), query)?;
        let selected = if value.saved_phase_v7() == HostRecoveryStopPhaseDataV7::Complete {
            Selection::Complete(Completed::Historical(value))
        } else {
            Selection::Effect(pending_subject(
                *value.historical_scope_v7(),
                recovery,
                query.boot,
            )?)
        };
        (selected, recipient)
    } else if inventory.present_stop_cleanup_candidates_v1.len() == 1 {
        let encoded = &inventory.present_stop_cleanup_candidates_v1[0];
        if encoded.len() == aos_sandbox_protocol::host_launch_cleanup_candidate::HOST_LAUNCH_CLEANUP_CANDIDATE_BYTES_V1 {
            let value = HostLaunchCleanupCandidateDataV1::from_inventory_v1(inventory)
                .map_err(|_| JournalError::ProtectedBoundary)?
                .ok_or(JournalError::ProtectedBoundary)?;
            let recipient = require_interval(*value.request_id_v1(), *value.current_boot_v1(),
                *value.recipient_v1(), value.before_v1(), value.after_v1(), query)?;
            (Selection::Effect(HostStopCleanupSubjectDataV1::from_dispatched_data_v2(
                *value.launch_scope_v1(), dispatch, recovery.recovery, recovery.cleanup,
                recovery.request, query.boot, recovery.revision, recovery.cutoff,
            ).map_err(|_| JournalError::ProtectedBoundary)?), recipient)
        } else {
            let value = HostStopCleanupCandidateDataV1::from_inventory_v1(inventory)
                .map_err(|_| JournalError::ProtectedBoundary)?
                .ok_or(JournalError::ProtectedBoundary)?;
            let recipient = require_interval(*value.request_id_v1(), *value.current_boot_v1(),
                *value.recipient_v1(), value.before_v1(), value.after_v1(), query)?;
            (Selection::Effect(pending_subject(*value.historical_scope_v1(), recovery, query.boot)?), recipient)
        }
    } else {
        return Err(JournalError::ProtectedBoundary);
    };

    let (selected, recipient) = selected;
    let scope = match selected {
        Selection::Effect(subject) => *subject.historical_scope_v1(),
        Selection::Complete(completed) => completed.scope(),
    };
    require_scope(scope, manifest, desired_generation, dispatch)?;
    Ok((selected, recipient))
}

fn pending_subject(
    scope: HostStoppedNamespaceDataV4,
    recovery: RecoveryData,
    boot: [u8; 16],
) -> Result<HostStopCleanupSubjectDataV1, JournalError> {
    HostStopCleanupSubjectDataV1::from_data_v1(
        scope,
        recovery.recovery,
        recovery.cleanup,
        recovery.request,
        boot,
        recovery.revision,
        recovery.cutoff,
    )
    .map_err(|_| JournalError::ProtectedBoundary)
}

fn require_scope(
    scope: HostStoppedNamespaceDataV4,
    manifest: &CanonicalAssignmentManifestV1,
    desired_generation: u64,
    dispatch: HostStoppedRequestIdentityDataV4,
) -> Result<(), JournalError> {
    let current = manifest.manifest();
    let old = scope.fence_v4();
    if old.sandbox_id() != current.sandbox().as_bytes()
        || old.incarnation_id() != current.incarnation().as_bytes()
        || old.assignment_epoch() != current.epoch().get()
        || old.assignment_digest() != manifest.digest().as_bytes()
        || old.desired_generation() > desired_generation
        || scope.stop_v4() != dispatch
    {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

fn require_observation(
    value: HostInventoryAbsenceDataV5,
    query: QueryData,
) -> Result<[u8; 16], JournalError> {
    let (before, after) = value.boottime_interval_v5();
    require_interval(
        *value.request_id_v5(),
        *value.boot_v5(),
        *value.recipient_invocation_v5(),
        before,
        after,
        query,
    )
}

fn require_interval(
    request: [u8; 16],
    boot: [u8; 16],
    recipient: [u8; 16],
    before: u64,
    after: u64,
    query: QueryData,
) -> Result<[u8; 16], JournalError> {
    if request != query.request
        || boot != query.boot
        || recipient == [0; 16]
        || query
            .recipient
            .is_some_and(|expected| recipient != expected)
        || before < query.first
        || after < before
        || after > query.observed.boottime_nanoseconds()
        || after >= query.cutoff
    {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(recipient)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_core::RawClockProvenance;

    fn query() -> QueryData {
        QueryData {
            request: [1; 16],
            boot: [2; 16],
            recipient: Some([3; 16]),
            first: 10,
            cutoff: 30,
            observed: RawPairedClockSample::new_untrusted(
                RawClockProvenance::new_untrusted([4; 16]).unwrap(),
                [2; 16],
                100,
                25,
            )
            .unwrap(),
        }
    }

    #[test]
    fn strict_absence_joins_current_query_boot_recipient_and_both_native_rounds() {
        let positive =
            HostInventoryAbsenceDataV5::from_data_v5([1; 16], [2; 16], [3; 16], 11, 24).unwrap();
        let canonical = HostInventoryAbsenceDataV5::decode_v5(&positive.encode_v5()).unwrap();
        assert_eq!(require_observation(canonical, query()).unwrap(), [3; 16]);

        for changed in [
            HostInventoryAbsenceDataV5::from_data_v5([5; 16], [2; 16], [3; 16], 11, 24).unwrap(),
            HostInventoryAbsenceDataV5::from_data_v5([1; 16], [5; 16], [3; 16], 11, 24).unwrap(),
            HostInventoryAbsenceDataV5::from_data_v5([1; 16], [2; 16], [5; 16], 11, 24).unwrap(),
            HostInventoryAbsenceDataV5::from_data_v5([1; 16], [2; 16], [3; 16], 9, 24).unwrap(),
            HostInventoryAbsenceDataV5::from_data_v5([1; 16], [2; 16], [3; 16], 11, 26).unwrap(),
        ] {
            assert!(require_observation(changed, query()).is_err());
        }
        assert!(
            require_observation(
                canonical,
                QueryData {
                    cutoff: 24,
                    ..query()
                }
            )
            .is_err()
        );
    }
}
