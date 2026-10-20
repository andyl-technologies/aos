//! Binds a fresh native absence census to an immutable historical Stop scope.
//!
//! This canonical DATA never restores an old native owner, completes an old
//! request, writes State or grants a cleanup effect. Current observation and
//! historical boot remain distinct, including when their bytes are equal.
//!
//! ```text
//! AOSHIR07 | historical AOSHNS04(328) | current AOSHIC05(72) | savedPhase1
//! ```

use crate::{
    ProtocolValidationError, host_inventory_absence::HostInventoryAbsenceDataV5,
    host_stopped_namespace::HostStoppedNamespaceDataV4,
};

/// Gives the sole exact width of the recovery inventory row.
pub const HOST_RECOVERED_NAMESPACE_BYTES_V7: usize = 409;
const MAGIC: &[u8; 8] = b"AOSHIR07";

/// Names only the saved cleanup phases eligible for native absence comparison.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum HostRecoveryStopPhaseDataV7 {
    /// Retains an already completed historical Stop.
    Complete = 0,
    /// Retains the already-issued exact payload containment target.
    PayloadPending = 1,
    /// Retains the already-issued exact guardian containment target.
    GuardianPending = 2,
    /// Retains the issued payload's pending absence observation.
    PayloadAwaitingAbsence = 3,
    /// Retains the issued guardian's pending absence observation.
    GuardianAwaitingAbsence = 4,
    /// Observes total absence before any historical Stop effect was issued.
    ///
    /// This permits only current recovery comparison. It is neither a completed
    /// Stop nor evidence that its old authorization was exercised.
    AuthorizedAbsent = 5,
}

/// Keeps old resource identity beside a separate current native observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostRecoveredNamespaceDataV7 {
    historical: HostStoppedNamespaceDataV4,
    observation: HostInventoryAbsenceDataV5,
    phase: HostRecoveryStopPhaseDataV7,
}

impl HostRecoveredNamespaceDataV7 {
    /// Constructs passive DATA from separately checked historical/current scopes.
    #[must_use]
    pub const fn from_data_v7(
        historical: HostStoppedNamespaceDataV4,
        observation: HostInventoryAbsenceDataV5,
        phase: HostRecoveryStopPhaseDataV7,
    ) -> Self {
        Self {
            historical,
            observation,
            phase,
        }
    }

    /// Encodes both existing canonical grammars without rewriting either boot.
    #[must_use]
    pub fn encode_v7(self) -> [u8; HOST_RECOVERED_NAMESPACE_BYTES_V7] {
        let mut bytes = [0; HOST_RECOVERED_NAMESPACE_BYTES_V7];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..336].copy_from_slice(&self.historical.encode_v4());
        bytes[336..408].copy_from_slice(&self.observation.encode_v5());
        bytes[408] = self.phase as u8;
        bytes
    }

    /// Decodes the sole exact row, sharing the format-owned nested decoders.
    ///
    /// # Errors
    /// Rejects another version, width, phase or malformed nested scope.
    pub fn decode_v7(bytes: &[u8]) -> Result<Self, ProtocolValidationError> {
        if bytes.len() != HOST_RECOVERED_NAMESPACE_BYTES_V7 || &bytes[..8] != MAGIC {
            return Err(invalid());
        }
        let phase = match bytes[408] {
            0 => HostRecoveryStopPhaseDataV7::Complete,
            1 => HostRecoveryStopPhaseDataV7::PayloadPending,
            2 => HostRecoveryStopPhaseDataV7::GuardianPending,
            3 => HostRecoveryStopPhaseDataV7::PayloadAwaitingAbsence,
            4 => HostRecoveryStopPhaseDataV7::GuardianAwaitingAbsence,
            5 => HostRecoveryStopPhaseDataV7::AuthorizedAbsent,
            _ => return Err(invalid()),
        };
        Ok(Self::from_data_v7(
            HostStoppedNamespaceDataV4::decode_v4(&bytes[8..336])?,
            HostInventoryAbsenceDataV5::decode_v5(&bytes[336..408])?,
            phase,
        ))
    }

    /// Borrows the sole recovery row without accepting coexisting inventory kinds.
    ///
    /// # Errors
    /// Refuses multiple recovery rows, a mixed population or malformed DATA.
    pub fn from_inventory_v7(
        inventory: &aos_proto::aos::sandbox::local::v1::InventoryRuntimeResponse,
    ) -> Result<Option<Self>, ProtocolValidationError> {
        if !inventory.cleanup_lineages_v1.is_empty() { return Err(invalid()); }
        if inventory.recovered_namespaces_v7.is_empty() {
            return Ok(None);
        }
        if inventory.recovered_namespaces_v7.len() != 1
            || !inventory.runtimes.is_empty()
            || !inventory.stopped_namespaces_v4.is_empty()
            || !inventory.native_absence_v5.is_empty()
            || !inventory.present_stop_cleanup_candidates_v1.is_empty()
        {
            return Err(invalid());
        }
        Self::decode_v7(&inventory.recovered_namespaces_v7[0]).map(Some)
    }

    /// Borrows the unchanged historical resource scope, including its old boot.
    #[must_use]
    pub const fn historical_scope_v7(&self) -> &HostStoppedNamespaceDataV4 {
        &self.historical
    }

    /// Borrows the fresh query's observed current boot, request and native interval.
    #[must_use]
    pub const fn observation_v7(&self) -> &HostInventoryAbsenceDataV5 {
        &self.observation
    }

    /// Returns the authenticated saved Stop phase without claiming completion.
    #[must_use]
    pub const fn saved_phase_v7(&self) -> HostRecoveryStopPhaseDataV7 {
        self.phase
    }
}

fn invalid() -> ProtocolValidationError {
    ProtocolValidationError::InvalidField("Host recovered namespace scope")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(phase: HostRecoveryStopPhaseDataV7) -> HostRecoveredNamespaceDataV7 {
        let fence = crate::ValidatedAssignmentFence {
            sandbox_id: [1; 16],
            incarnation_id: [2; 16],
            assignment_epoch: 3,
            desired_generation: 4,
            assignment_digest: [5; 32],
        };
        let old = HostStoppedNamespaceDataV4::from_data_v4(
            [6; 16],
            fence,
            [7; 32],
            ([8; 16], [9; 32], [10; 32]),
            ([11; 16], [12; 32], [13; 32]),
        )
        .unwrap();
        let current =
            HostInventoryAbsenceDataV5::from_data_v5([14; 16], [15; 16], [16; 16], 17, 18).unwrap();
        HostRecoveredNamespaceDataV7::from_data_v7(old, current, phase)
    }

    #[test]
    fn all_saved_phases_keep_old_scope_and_current_boot_separate() {
        for phase in [
            HostRecoveryStopPhaseDataV7::Complete,
            HostRecoveryStopPhaseDataV7::PayloadPending,
            HostRecoveryStopPhaseDataV7::GuardianPending,
            HostRecoveryStopPhaseDataV7::PayloadAwaitingAbsence,
            HostRecoveryStopPhaseDataV7::GuardianAwaitingAbsence,
            HostRecoveryStopPhaseDataV7::AuthorizedAbsent,
        ] {
            let original = row(phase);
            let bytes = original.encode_v7();

            let decoded = HostRecoveredNamespaceDataV7::decode_v7(&bytes).unwrap();

            assert_eq!(decoded, original);
            assert_eq!(decoded.historical_scope_v7().boot_v4(), &[6; 16]);
            assert_eq!(decoded.observation_v7().boot_v5(), &[15; 16]);
            assert_eq!(
                &bytes[8..336],
                original.historical_scope_v7().encode_v4().as_slice()
            );
        }
    }

    #[test]
    fn malformed_or_mixed_recovery_evidence_is_rejected() {
        let original = row(HostRecoveryStopPhaseDataV7::Complete);
        let mut bytes = original.encode_v7();
        bytes[408] = 6;
        assert!(HostRecoveredNamespaceDataV7::decode_v7(&bytes).is_err());
        assert!(HostRecoveredNamespaceDataV7::decode_v7(&original.encode_v7()[..408]).is_err());
        let mut trailing = original.encode_v7().to_vec();
        trailing.push(0);
        assert!(HostRecoveredNamespaceDataV7::decode_v7(&trailing).is_err());

        let mut inventory = aos_proto::aos::sandbox::local::v1::InventoryRuntimeResponse::default();
        inventory
            .recovered_namespaces_v7
            .push(original.encode_v7().to_vec());
        assert_eq!(
            HostRecoveredNamespaceDataV7::from_inventory_v7(&inventory).unwrap(),
            Some(original)
        );
        inventory.native_absence_v5 = original.observation_v7().encode_v5().to_vec();
        assert!(HostRecoveredNamespaceDataV7::from_inventory_v7(&inventory).is_err());
        assert!(HostInventoryAbsenceDataV5::from_inventory_v5(&inventory).is_err());
        inventory.native_absence_v5.clear();
        inventory
            .stopped_namespaces_v4
            .push(original.historical_scope_v7().encode_v4().to_vec());
        assert!(HostRecoveredNamespaceDataV7::from_inventory_v7(&inventory).is_err());
    }

    #[test]
    fn authorized_absence_has_a_distinct_phase_and_preserves_both_scopes() {
        let complete = row(HostRecoveryStopPhaseDataV7::Complete).encode_v7();
        let absent = row(HostRecoveryStopPhaseDataV7::AuthorizedAbsent).encode_v7();

        assert_eq!(&absent[..408], &complete[..408]);
        assert_eq!(complete[408], 0);
        assert_eq!(absent[408], 5);
        assert_ne!(
            HostRecoveredNamespaceDataV7::decode_v7(&absent)
                .unwrap()
                .saved_phase_v7(),
            HostRecoveryStopPhaseDataV7::Complete
        );
    }
}
