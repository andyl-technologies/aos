//! Carries a fresh PresentOwned observation beside immutable pending Stop DATA.
//!
//! A strict decode supplies comparison coordinates only. The actual paid Host3
//! producer separately proves protected history and two complete native rounds;
//! Root verifies that signed answer, current Source/capability/desired state
//! before signing a fresh cleanup. The effect receiver rechecks ownership.
//!
//! ```text
//! AOSHIP08 | unchanged AOSHNS04(328) | query16 | currentBoot16 |
//! recipient16 | beforeBoot8le | afterBoot8le | savedPendingPhase1
//! ```

use crate::{ProtocolValidationError, host_stopped_namespace::HostStoppedNamespaceDataV4};

/// Gives the sole canonical PresentOwned candidate width.
pub const HOST_STOP_CLEANUP_CANDIDATE_BYTES_V1: usize = 401;
const MAGIC: &[u8; 8] = b"AOSHIP08";

/// Names immutable pending progress without completing the old Stop.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum HostStopCleanupSavedPhaseDataV1 {
    /// The exact target was authorized but its first effect was not issued.
    Authorized = 0,
    /// The exact payload containment was durably issued.
    PayloadPending = 1,
    /// The exact Guardian containment was durably issued.
    GuardianPending = 2,
    /// Payload Stop is awaiting independently observed absence.
    PayloadAwaitingAbsence = 3,
    /// Guardian Stop is awaiting independently observed absence.
    GuardianAwaitingAbsence = 4,
}

/// Describes PresentOwned, never absence or a recovered native/effect owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostStopCleanupCandidateDataV1 {
    historical: HostStoppedNamespaceDataV4,
    request: [u8; 16],
    boot: [u8; 16],
    recipient: [u8; 16],
    before: u64,
    after: u64,
    phase: HostStopCleanupSavedPhaseDataV1,
}

impl HostStopCleanupCandidateDataV1 {
    /// Checks the passive old/current scope and fresh paired-clock coordinates.
    ///
    /// # Errors
    /// Refuses zero/old query identities, missing samples or a backwards clock.
    #[allow(clippy::too_many_arguments)]
    pub fn from_data_v1(historical: HostStoppedNamespaceDataV4, request: [u8; 16],
        boot: [u8; 16], recipient: [u8; 16], before: u64, after: u64,
        phase: HostStopCleanupSavedPhaseDataV1,
    ) -> Result<Self, ProtocolValidationError> {
        if request == [0; 16] || request == historical.launch_v4().0 || request == historical.stop_v4().0
            || boot == [0; 16] || recipient == [0; 16] || before == 0 || after < before
        { return Err(invalid()); }
        Ok(Self { historical, request, boot, recipient, before, after, phase })
    }

    /// Encodes all canonical DATA without allocation or rewriting the old boot.
    #[must_use]
    pub fn encode_v1(self) -> [u8; HOST_STOP_CLEANUP_CANDIDATE_BYTES_V1] {
        let mut bytes = [0; HOST_STOP_CLEANUP_CANDIDATE_BYTES_V1];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..336].copy_from_slice(&self.historical.encode_v4());
        bytes[336..352].copy_from_slice(&self.request);
        bytes[352..368].copy_from_slice(&self.boot);
        bytes[368..384].copy_from_slice(&self.recipient);
        bytes[384..392].copy_from_slice(&self.before.to_le_bytes());
        bytes[392..400].copy_from_slice(&self.after.to_le_bytes());
        bytes[400] = self.phase as u8;
        bytes
    }

    /// Decodes the sole exact version, sharing the format-owned old-scope codec.
    ///
    /// # Errors
    /// Refuses another width/version, invalid pending phase or malformed scope.
    pub fn decode_v1(bytes: &[u8]) -> Result<Self, ProtocolValidationError> {
        if bytes.len() != HOST_STOP_CLEANUP_CANDIDATE_BYTES_V1 || &bytes[..8] != MAGIC {
            return Err(invalid());
        }
        let phase = match bytes[400] {
            0 => HostStopCleanupSavedPhaseDataV1::Authorized,
            1 => HostStopCleanupSavedPhaseDataV1::PayloadPending,
            2 => HostStopCleanupSavedPhaseDataV1::GuardianPending,
            3 => HostStopCleanupSavedPhaseDataV1::PayloadAwaitingAbsence,
            4 => HostStopCleanupSavedPhaseDataV1::GuardianAwaitingAbsence,
            _ => return Err(invalid()),
        };
        Self::from_data_v1(HostStoppedNamespaceDataV4::decode_v4(&bytes[8..336])?,
            field(bytes, 336)?, field(bytes, 352)?, field(bytes, 368)?,
            u64::from_le_bytes(field(bytes, 384)?), u64::from_le_bytes(field(bytes, 392)?), phase)
    }

    /// Selects the sole PresentOwned row without accepting any mixed population.
    ///
    /// # Errors
    /// Refuses duplicate/mixed rows, unknown fields or malformed candidate DATA.
    pub fn from_inventory_v1(inventory: &aos_proto::aos::sandbox::local::v1::InventoryRuntimeResponse)
        -> Result<Option<Self>, ProtocolValidationError> {
        if !inventory.cleanup_lineages_v1.is_empty() { return Err(invalid()); }
        if inventory.present_stop_cleanup_candidates_v1.is_empty() { return Ok(None); }
        if inventory.present_stop_cleanup_candidates_v1.len() != 1
            || !inventory.__buffa_unknown_fields.is_empty() || !inventory.runtimes.is_empty()
            || !inventory.stopped_namespaces_v4.is_empty() || !inventory.native_absence_v5.is_empty()
            || !inventory.recovered_namespaces_v7.is_empty()
        { return Err(invalid()); }
        Self::decode_v1(&inventory.present_stop_cleanup_candidates_v1[0]).map(Some)
    }

    /// Borrows the immutable old Launch/Stop/fence/anchor comparison.
    #[must_use]
    pub const fn historical_scope_v1(&self) -> &HostStoppedNamespaceDataV4 { &self.historical }

    /// Borrows the fresh authenticated Host3 query identifier.
    #[must_use]
    pub const fn request_id_v1(&self) -> &[u8; 16] { &self.request }

    /// Borrows the current observed boot, independently of the historical boot.
    #[must_use]
    pub const fn current_boot_v1(&self) -> &[u8; 16] { &self.boot }

    /// Borrows the actual current-Control recipient comparison.
    #[must_use]
    pub const fn recipient_v1(&self) -> &[u8; 16] { &self.recipient }

    /// Returns the current native interval's first boot-time sample.
    #[must_use]
    pub const fn before_v1(&self) -> u64 { self.before }

    /// Returns the current native interval's final boot-time sample.
    #[must_use]
    pub const fn after_v1(&self) -> u64 { self.after }

    /// Returns the immutable pending phase; Complete has no PresentOwned form.
    #[must_use]
    pub const fn saved_phase_v1(&self) -> HostStopCleanupSavedPhaseDataV1 { self.phase }
}

fn field<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], ProtocolValidationError> {
    bytes.get(offset .. offset.checked_add(N).ok_or_else(invalid)?)
        .ok_or_else(invalid)?.try_into().map_err(|_| invalid())
}

fn invalid() -> ProtocolValidationError {
    ProtocolValidationError::InvalidField("Host PresentOwned cleanup comparison")
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_proto::aos::sandbox::local::v1::InventoryRuntimeResponse;
    use buffa::Message as _;

    fn candidate(phase: HostStopCleanupSavedPhaseDataV1) -> HostStopCleanupCandidateDataV1 {
        let historical = HostStoppedNamespaceDataV4::from_data_v4([6; 16],
            crate::ValidatedAssignmentFence { sandbox_id: [1; 16], incarnation_id: [2; 16],
                assignment_epoch: 3, desired_generation: 4, assignment_digest: [5; 32] },
            [7; 32], ([8; 16], [9; 32], [10; 32]), ([11; 16], [12; 32], [13; 32])).unwrap();
        HostStopCleanupCandidateDataV1::from_data_v1(historical, [14; 16], [15; 16], [16; 16],
            17, 18, phase).unwrap()
    }

    #[test]
    fn every_pending_phase_preserves_old_scope_beside_distinct_current_boot() {
        for phase in [HostStopCleanupSavedPhaseDataV1::Authorized,
            HostStopCleanupSavedPhaseDataV1::PayloadPending,
            HostStopCleanupSavedPhaseDataV1::GuardianPending,
            HostStopCleanupSavedPhaseDataV1::PayloadAwaitingAbsence,
            HostStopCleanupSavedPhaseDataV1::GuardianAwaitingAbsence] {
            let row = candidate(phase);
            let bytes = row.encode_v1();
            assert_eq!(bytes.len(), HOST_STOP_CLEANUP_CANDIDATE_BYTES_V1);
            assert_eq!(&bytes[8..336], &row.historical_scope_v1().encode_v4());
            assert_eq!(row.historical_scope_v1().boot_v4(), &[6; 16]);
            assert_eq!(row.current_boot_v1(), &[15; 16]);
            assert_eq!(HostStopCleanupCandidateDataV1::decode_v1(&bytes).unwrap(), row);
        }
    }

    #[test]
    fn trailing_unknown_old_version_phase_and_query_alias_are_refused() {
        let row = candidate(HostStopCleanupSavedPhaseDataV1::PayloadPending);
        let original = row.encode_v1();
        for (offset, value) in [(7, b'7'), (400, 5)] {
            let mut bytes = original;
            bytes[offset] = value;
            assert!(HostStopCleanupCandidateDataV1::decode_v1(&bytes).is_err());
        }
        let mut trailing = original.to_vec();
        trailing.push(0);
        assert!(HostStopCleanupCandidateDataV1::decode_v1(&trailing).is_err());
        for query in [[0; 16], row.historical_scope_v1().launch_v4().0, row.historical_scope_v1().stop_v4().0] {
            assert!(HostStopCleanupCandidateDataV1::from_data_v1(*row.historical_scope_v1(), query,
                [15; 16], [16; 16], 17, 18, row.saved_phase_v1()).is_err());
        }
        assert!(HostStopCleanupCandidateDataV1::from_data_v1(*row.historical_scope_v1(), [14; 16],
            [15; 16], [16; 16], 18, 17, row.saved_phase_v1()).is_err());
    }

    #[test]
    fn candidate_is_exclusive_and_never_decodes_as_an_absence_scope() {
        let row = candidate(HostStopCleanupSavedPhaseDataV1::GuardianPending);
        let mut inventory = InventoryRuntimeResponse {
            present_stop_cleanup_candidates_v1: vec![row.encode_v1().to_vec()], ..Default::default()
        };
        assert_eq!(HostStopCleanupCandidateDataV1::from_inventory_v1(&inventory).unwrap(), Some(row));
        assert!(crate::host_inventory_absence::HostInventoryAbsenceDataV5::from_inventory_v5(&inventory)
            .unwrap().is_none());
        assert!(crate::host_recovered_namespace::HostRecoveredNamespaceDataV7::from_inventory_v7(&inventory)
            .unwrap().is_none());
        assert!(crate::host_inventory_absence::HostInventoryAbsenceDataV5::decode_v5(&row.encode_v1()).is_err());
        assert!(crate::host_recovered_namespace::HostRecoveredNamespaceDataV7::decode_v7(&row.encode_v1()).is_err());
        inventory.present_stop_cleanup_candidates_v1.push(row.encode_v1().to_vec());
        assert!(HostStopCleanupCandidateDataV1::from_inventory_v1(&inventory).is_err());
        inventory.present_stop_cleanup_candidates_v1.pop();
        inventory.stopped_namespaces_v4.push(row.historical_scope_v1().encode_v4().to_vec());
        assert!(HostStopCleanupCandidateDataV1::from_inventory_v1(&inventory).is_err());
    }

    #[test]
    fn sole_authenticated_host_decoder_binds_the_new_query_and_canonical_wire() {
        let row = candidate(HostStopCleanupSavedPhaseDataV1::Authorized);
        let inventory = InventoryRuntimeResponse {
            present_stop_cleanup_candidates_v1: vec![row.encode_v1().to_vec()], ..Default::default()
        };
        let bytes = inventory.encode_to_vec();
        let decode = crate::authenticated_session::all_methods::decode_host_runtime_inventory_data_v2;
        assert_eq!(decode(&bytes, *row.request_id_v1()).unwrap(), inventory);
        assert!(decode(&bytes, [99; 16]).is_err());
        let mut unknown = bytes;
        unknown.extend_from_slice(&[0x30, 1]);
        assert!(decode(&unknown, *row.request_id_v1()).is_err());
    }
}
