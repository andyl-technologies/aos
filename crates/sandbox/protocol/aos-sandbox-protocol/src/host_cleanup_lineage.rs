//! Compares fresh native absence with an authenticated cleanup chain's leaf.
//!
//! This is passive signed-inventory DATA. The Host producer must separately
//! authenticate the entire MAC-covered chain and complete two fresh native
//! rounds. Decoding cannot restore an old owner or complete a Source operation.
//!
//! ```text
//! AOSHRC09 | AOSHSC01(456) | childRequest16 | childSession32 | childSigned32 |
//! AOSHIC05(72) | authenticatedChainCommitment32
//! ```

use crate::{
    ProtocolValidationError, host_inventory_absence::HostInventoryAbsenceDataV5,
    host_stop_cleanup::HostStopCleanupSubjectDataV1,
};

/// Gives the sole canonical cleanup-lineage observation width.
pub const HOST_CLEANUP_LINEAGE_BYTES_V1: usize = 648;
const MAGIC: &[u8; 8] = b"AOSHRC09";

/// Keeps immutable old scope and fresh cleanup completion comparison distinct.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostCleanupLineageDataV1 {
    subject: HostStopCleanupSubjectDataV1,
    child: ([u8; 16], [u8; 32], [u8; 32]),
    observation: HostInventoryAbsenceDataV5,
    chain: [u8; 32],
}

impl HostCleanupLineageDataV1 {
    /// Checks passive leaf identity and an independently fresh native query.
    ///
    /// # Errors
    /// Refuses a foreign child, zero identity/commitment or a reused request.
    pub fn from_data_v1(
        subject: HostStopCleanupSubjectDataV1,
        child: ([u8; 16], [u8; 32], [u8; 32]),
        observation: HostInventoryAbsenceDataV5,
        chain: [u8; 32],
    ) -> Result<Self, ProtocolValidationError> {
        let old = subject.historical_scope_v1();
        if child.0 != *subject.cleanup_request_v1()
            || child.1 == [0; 32]
            || child.2 == [0; 32]
            || chain == [0; 32]
            || [
                child.0,
                *subject.recovery_operation_v1(),
                old.launch_v4().0,
                old.stop_v4().0,
            ]
            .contains(observation.request_id_v5())
        {
            return Err(invalid());
        }
        Ok(Self {
            subject,
            child,
            observation,
            chain,
        })
    }

    /// Encodes the exact nested canonical formats without allocation.
    #[must_use]
    pub fn encode_v1(self) -> [u8; HOST_CLEANUP_LINEAGE_BYTES_V1] {
        let mut bytes = [0; HOST_CLEANUP_LINEAGE_BYTES_V1];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..464].copy_from_slice(&self.subject.encode_v1());
        bytes[464..480].copy_from_slice(&self.child.0);
        bytes[480..512].copy_from_slice(&self.child.1);
        bytes[512..544].copy_from_slice(&self.child.2);
        bytes[544..616].copy_from_slice(&self.observation.encode_v5());
        bytes[616..648].copy_from_slice(&self.chain);
        bytes
    }

    /// Decodes only the exact version, sharing both nested format owners.
    ///
    /// # Errors
    /// Refuses wrong width/version, malformed nested DATA or inconsistent IDs.
    pub fn decode_v1(bytes: &[u8]) -> Result<Self, ProtocolValidationError> {
        if bytes.len() != HOST_CLEANUP_LINEAGE_BYTES_V1 || &bytes[..8] != MAGIC {
            return Err(invalid());
        }
        Self::from_data_v1(
            HostStopCleanupSubjectDataV1::decode_v1(&bytes[8..464])?,
            (field(bytes, 464)?, field(bytes, 480)?, field(bytes, 512)?),
            HostInventoryAbsenceDataV5::decode_v5(&bytes[544..616])?,
            field(bytes, 616)?,
        )
    }

    /// Selects a sole cleanup lineage without projecting it into legacy absence.
    ///
    /// # Errors
    /// Refuses mixed/duplicate rows, unknown fields or malformed fixed DATA.
    pub fn from_inventory_v1(
        inventory: &aos_sandbox_api::aos::sandbox::local::v1::InventoryRuntimeResponse,
    ) -> Result<Option<Self>, ProtocolValidationError> {
        if inventory.cleanup_lineages_v1.is_empty() {
            return Ok(None);
        }
        if inventory.cleanup_lineages_v1.len() != 1
            || !inventory.__buffa_unknown_fields.is_empty()
            || !inventory.runtimes.is_empty()
            || !inventory.stopped_namespaces_v4.is_empty()
            || !inventory.native_absence_v5.is_empty()
            || !inventory.recovered_namespaces_v7.is_empty()
            || !inventory.present_stop_cleanup_candidates_v1.is_empty()
        {
            return Err(invalid());
        }
        Self::decode_v1(&inventory.cleanup_lineages_v1[0]).map(Some)
    }

    /// Borrows the exact signed cleanup subject, including unchanged old scope.
    #[must_use]
    pub const fn subject_v1(&self) -> &HostStopCleanupSubjectDataV1 {
        &self.subject
    }

    /// Returns the genuine child request/Session/signed-request comparison.
    #[must_use]
    pub const fn child_v1(&self) -> ([u8; 16], [u8; 32], [u8; 32]) {
        self.child
    }

    /// Borrows the separate fresh native absence interval.
    #[must_use]
    pub const fn observation_v1(&self) -> &HostInventoryAbsenceDataV5 {
        &self.observation
    }

    /// Borrows the commitment computed over the entire authenticated chain.
    #[must_use]
    pub const fn chain_commitment_v1(&self) -> &[u8; 32] {
        &self.chain
    }
}

fn field<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], ProtocolValidationError> {
    bytes
        .get(offset..offset.checked_add(N).ok_or_else(invalid)?)
        .ok_or_else(invalid)?
        .try_into()
        .map_err(|_| invalid())
}

fn invalid() -> ProtocolValidationError {
    ProtocolValidationError::InvalidField("Host cleanup lineage observation")
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_api::aos::sandbox::local::v1::InventoryRuntimeResponse;
    use buffa::Message as _;

    fn row() -> HostCleanupLineageDataV1 {
        let old = crate::host_stopped_namespace::HostStoppedNamespaceDataV4::from_data_v4(
            [6; 16],
            crate::ValidatedAssignmentFence {
                sandbox_id: [1; 16],
                incarnation_id: [2; 16],
                assignment_epoch: 3,
                desired_generation: 4,
                assignment_digest: [5; 32],
            },
            [7; 32],
            ([8; 16], [9; 32], [10; 32]),
            ([11; 16], [12; 32], [13; 32]),
        )
        .unwrap();
        let subject = HostStopCleanupSubjectDataV1::from_data_v1(
            old, [14; 16], [15; 16], [16; 32], [17; 16], [18; 32], 19,
        )
        .unwrap();
        let observation =
            HostInventoryAbsenceDataV5::from_data_v5([20; 16], [21; 16], [22; 16], 23, 24).unwrap();
        HostCleanupLineageDataV1::from_data_v1(
            subject,
            ([15; 16], [25; 32], [26; 32]),
            observation,
            [27; 32],
        )
        .unwrap()
    }

    #[test]
    fn distinct_cleanup_preserves_old_scope_and_both_boots() {
        let row = row();
        let bytes = row.encode_v1();
        assert_eq!(bytes.len(), 648);
        assert_eq!(HostCleanupLineageDataV1::decode_v1(&bytes).unwrap(), row);
        assert_eq!(
            &bytes[16..344],
            &row.subject_v1().historical_scope_v1().encode_v4()
        );
        assert_eq!(row.subject_v1().current_boot_v1(), &[17; 16]);
        assert_eq!(row.observation_v1().boot_v5(), &[21; 16]);
    }

    #[test]
    fn malformed_child_and_noncanonical_frames_are_refused() {
        let row = row();
        assert!(
            HostCleanupLineageDataV1::from_data_v1(
                row.subject,
                ([30; 16], row.child.1, row.child.2),
                row.observation,
                row.chain
            )
            .is_err()
        );
        assert!(HostCleanupLineageDataV1::decode_v1(&row.encode_v1()[..647]).is_err());
        let mut bytes = row.encode_v1().to_vec();
        bytes.push(0);
        assert!(HostCleanupLineageDataV1::decode_v1(&bytes).is_err());
    }

    #[test]
    fn lineage_is_exclusive_and_never_projects_into_legacy_absence() {
        let row = row();
        let mut inventory = InventoryRuntimeResponse {
            cleanup_lineages_v1: vec![row.encode_v1().to_vec()],
            ..Default::default()
        };
        assert_eq!(
            HostCleanupLineageDataV1::from_inventory_v1(&inventory).unwrap(),
            Some(row)
        );
        assert!(HostInventoryAbsenceDataV5::from_inventory_v5(&inventory).is_err());
        assert!(
            crate::host_recovered_namespace::HostRecoveredNamespaceDataV7::from_inventory_v7(
                &inventory
            )
            .is_err()
        );
        assert!(
            crate::host_stop_cleanup_candidate::HostStopCleanupCandidateDataV1::from_inventory_v1(
                &inventory
            )
            .is_err()
        );
        inventory.native_absence_v5 = row.observation.encode_v5().to_vec();
        assert!(HostCleanupLineageDataV1::from_inventory_v1(&inventory).is_err());
    }

    #[test]
    fn actual_host3_decoder_accepts_only_the_canonical_lineage_for_the_exact_fresh_query() {
        let row = row();
        let mut inventory = InventoryRuntimeResponse {
            cleanup_lineages_v1: vec![row.encode_v1().to_vec()],
            ..Default::default()
        };
        let decode = crate::authenticated_session::all_methods::decode_host_runtime_inventory_data_v2;
        let request = *row.observation_v1().request_id_v5();
        let bytes = inventory.encode_to_vec();

        assert_eq!(decode(&bytes, request).unwrap(), inventory);
        assert!(decode(&bytes, *row.subject_v1().cleanup_request_v1()).is_err());
        assert!(decode(&bytes, [99; 16]).is_err());

        inventory.cleanup_lineages_v1.push(row.encode_v1().to_vec());
        assert!(decode(&inventory.encode_to_vec(), request).is_err());
        inventory.cleanup_lineages_v1.pop();
        inventory.native_absence_v5 = row.observation_v1().encode_v5().to_vec();
        assert!(decode(&inventory.encode_to_vec(), request).is_err());
        let mut unknown = bytes;
        unknown.extend_from_slice(&[0x38, 1]);
        assert!(decode(&unknown, request).is_err());
    }
}
