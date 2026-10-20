//! Compares LaunchReady history before a prepared Stop ever reached Host.
//!
//! The fresh paid Host3 census supplies native PresentOwned or total absence.
//! There is deliberately no old Stop tuple or phase. Root must independently
//! join the actual Source dispatch, Recover and current policy before signing
//! a new cleanup. This DATA creates no Pending row, native owner or permission.
//!
//! ```text
//! AOSHLC10 | LaunchScopeBody240 | query16 | currentBoot16 | recipient16 |
//! beforeBoot8le | afterBoot8le | population1
//! ```

use crate::{ProtocolValidationError, host_stopped_namespace::HostLaunchNamespaceDataV1};

/// Gives the exact LaunchReady-only cleanup comparison width.
pub const HOST_LAUNCH_CLEANUP_CANDIDATE_BYTES_V1: usize = 313;
const MAGIC: &[u8; 8] = b"AOSHLC10";

/// Names a fresh native population without claiming an old Stop was issued.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum HostLaunchCleanupPopulationDataV1 {
    /// The exact protected Launch target has fresh native ownership.
    PresentOwned = 0,
    /// Both complete native rounds observed total absence.
    Absent = 1,
}

/// Carries immutable LaunchReady comparison and its fresh native census.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostLaunchCleanupCandidateDataV1 {
    launch: HostLaunchNamespaceDataV1,
    request: [u8; 16],
    boot: [u8; 16],
    recipient: [u8; 16],
    before: u64,
    after: u64,
    population: HostLaunchCleanupPopulationDataV1,
}

impl HostLaunchCleanupCandidateDataV1 {
    /// Checks passive old/current identities and the fresh native clock interval.
    ///
    /// # Errors
    /// Refuses missing or reused query identities and absent/backwards clocks.
    #[allow(clippy::too_many_arguments)]
    pub fn from_data_v1(
        launch: HostLaunchNamespaceDataV1,
        request: [u8; 16],
        boot: [u8; 16],
        recipient: [u8; 16],
        before: u64,
        after: u64,
        population: HostLaunchCleanupPopulationDataV1,
    ) -> Result<Self, ProtocolValidationError> {
        if request == [0; 16]
            || request == launch.launch_v1().0
            || boot == [0; 16]
            || recipient == [0; 16]
            || before == 0
            || after < before
        {
            return Err(invalid());
        }
        Ok(Self {
            launch,
            request,
            boot,
            recipient,
            before,
            after,
            population,
        })
    }

    /// Encodes the exact Launch-only case without any Stop fields.
    #[must_use]
    pub fn encode_v1(self) -> [u8; HOST_LAUNCH_CLEANUP_CANDIDATE_BYTES_V1] {
        let mut bytes = [0; HOST_LAUNCH_CLEANUP_CANDIDATE_BYTES_V1];
        self.launch.encode_prefix_v1(MAGIC, &mut bytes[..248]);
        bytes[248..264].copy_from_slice(&self.request);
        bytes[264..280].copy_from_slice(&self.boot);
        bytes[280..296].copy_from_slice(&self.recipient);
        bytes[296..304].copy_from_slice(&self.before.to_le_bytes());
        bytes[304..312].copy_from_slice(&self.after.to_le_bytes());
        bytes[312] = self.population as u8;
        bytes
    }

    /// Decodes the closed version using the same format-owned Launch codec.
    ///
    /// # Errors
    /// Refuses another shape/version, malformed scope or unknown population.
    pub fn decode_v1(bytes: &[u8]) -> Result<Self, ProtocolValidationError> {
        if bytes.len() != HOST_LAUNCH_CLEANUP_CANDIDATE_BYTES_V1 || &bytes[..8] != MAGIC {
            return Err(invalid());
        }
        let population = match bytes[312] {
            0 => HostLaunchCleanupPopulationDataV1::PresentOwned,
            1 => HostLaunchCleanupPopulationDataV1::Absent,
            _ => return Err(invalid()),
        };
        Self::from_data_v1(
            HostLaunchNamespaceDataV1::decode_prefix_v1(&bytes[..248])?,
            field(bytes, 248)?,
            field(bytes, 264)?,
            field(bytes, 280)?,
            u64::from_le_bytes(field(bytes, 296)?),
            u64::from_le_bytes(field(bytes, 304)?),
            population,
        )
    }

    /// Selects only this exclusive case; existing Pending candidates stay distinct.
    ///
    /// # Errors
    /// Refuses malformed/mixed/duplicate cases or any unknown fields.
    pub fn from_inventory_v1(
        inventory: &aos_proto::aos::sandbox::local::v1::InventoryRuntimeResponse,
    ) -> Result<Option<Self>, ProtocolValidationError> {
        let rows = &inventory.present_stop_cleanup_candidates_v1;
        if rows.is_empty() {
            return Ok(None);
        }
        if rows.len() != 1
            || !inventory.__buffa_unknown_fields.is_empty()
            || !inventory.runtimes.is_empty()
            || !inventory.stopped_namespaces_v4.is_empty()
            || !inventory.native_absence_v5.is_empty()
            || !inventory.recovered_namespaces_v7.is_empty()
            || !inventory.cleanup_lineages_v1.is_empty()
        {
            return Err(invalid());
        }
        if rows[0].len() == crate::host_stop_cleanup_candidate::HOST_STOP_CLEANUP_CANDIDATE_BYTES_V1
        {
            crate::host_stop_cleanup_candidate::HostStopCleanupCandidateDataV1::decode_v1(
                &rows[0],
            )?;
            return Ok(None);
        }
        Self::decode_v1(&rows[0]).map(Some)
    }

    /// Borrows the immutable protected Launch-only comparison.
    #[must_use]
    pub const fn launch_scope_v1(&self) -> &HostLaunchNamespaceDataV1 {
        &self.launch
    }

    /// Borrows the fresh authenticated Host3 query identity.
    #[must_use]
    pub const fn request_id_v1(&self) -> &[u8; 16] {
        &self.request
    }

    /// Borrows the current observed kernel boot.
    #[must_use]
    pub const fn current_boot_v1(&self) -> &[u8; 16] {
        &self.boot
    }

    /// Borrows the actual current-Control recipient comparison.
    #[must_use]
    pub const fn recipient_v1(&self) -> &[u8; 16] {
        &self.recipient
    }

    /// Returns the first fresh native boot-time sample.
    #[must_use]
    pub const fn before_v1(&self) -> u64 {
        self.before
    }

    /// Returns the final fresh native boot-time sample.
    #[must_use]
    pub const fn after_v1(&self) -> u64 {
        self.after
    }

    /// Returns the explicit native population, never a Stop phase or permission.
    #[must_use]
    pub const fn population_v1(&self) -> HostLaunchCleanupPopulationDataV1 {
        self.population
    }
}

fn field<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], ProtocolValidationError> {
    bytes
        .get(offset..offset + N)
        .ok_or_else(invalid)?
        .try_into()
        .map_err(|_| invalid())
}

fn invalid() -> ProtocolValidationError {
    ProtocolValidationError::InvalidField("Host LaunchReady-only cleanup comparison")
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_proto::aos::sandbox::local::v1::InventoryRuntimeResponse;
    use buffa::Message as _;

    fn candidate(
        population: HostLaunchCleanupPopulationDataV1,
    ) -> HostLaunchCleanupCandidateDataV1 {
        let scope = HostLaunchNamespaceDataV1::from_data_v1(
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
        )
        .unwrap();
        HostLaunchCleanupCandidateDataV1::from_data_v1(
            scope, [11; 16], [12; 16], [13; 16], 14, 15, population,
        )
        .unwrap()
    }

    #[test]
    fn fresh_launch_only_census_has_no_pending_or_legacy_absence_projection() {
        for population in [
            HostLaunchCleanupPopulationDataV1::PresentOwned,
            HostLaunchCleanupPopulationDataV1::Absent,
        ] {
            let row = candidate(population);
            let bytes = row.encode_v1();
            assert_eq!(bytes.len(), 313);
            assert_eq!(
                HostLaunchCleanupCandidateDataV1::decode_v1(&bytes).unwrap(),
                row
            );
            assert_eq!(&bytes[8..248], &row.launch_scope_v1().encode_v1()[8..]);
            let inventory = InventoryRuntimeResponse {
                present_stop_cleanup_candidates_v1: vec![bytes.to_vec()],
                ..Default::default()
            };
            assert!(crate::host_stop_cleanup_candidate::HostStopCleanupCandidateDataV1::from_inventory_v1(&inventory).is_err());
            assert!(
                crate::host_recovered_namespace::HostRecoveredNamespaceDataV7::decode_v7(&bytes)
                    .is_err()
            );
            assert!(
                crate::host_inventory_absence::HostInventoryAbsenceDataV5::decode_v5(&bytes)
                    .is_err()
            );
            let decode =
                crate::authenticated_session::all_methods::decode_host_runtime_inventory_data_v2;
            assert_eq!(
                decode(&inventory.encode_to_vec(), *row.request_id_v1()).unwrap(),
                inventory
            );
            assert!(
                decode(
                    &inventory.encode_to_vec(),
                    row.launch_scope_v1().launch_v1().0
                )
                .is_err()
            );
        }
    }

    #[test]
    fn launch_only_census_refuses_mixed_duplicate_unknown_and_changed_shape() {
        let row = candidate(HostLaunchCleanupPopulationDataV1::PresentOwned);
        let mut bytes = row.encode_v1();
        bytes[312] = 2;
        assert!(HostLaunchCleanupCandidateDataV1::decode_v1(&bytes).is_err());
        assert!(HostLaunchCleanupCandidateDataV1::decode_v1(&row.encode_v1()[..312]).is_err());
        let mut inventory = InventoryRuntimeResponse {
            present_stop_cleanup_candidates_v1: vec![row.encode_v1().to_vec()],
            ..Default::default()
        };
        inventory
            .present_stop_cleanup_candidates_v1
            .push(row.encode_v1().to_vec());
        assert!(HostLaunchCleanupCandidateDataV1::from_inventory_v1(&inventory).is_err());
        inventory.present_stop_cleanup_candidates_v1.pop();
        inventory.cleanup_lineages_v1.push(vec![0; 648]);
        assert!(HostLaunchCleanupCandidateDataV1::from_inventory_v1(&inventory).is_err());
        inventory.cleanup_lineages_v1.clear();
        let mut unknown = inventory.encode_to_vec();
        unknown.extend_from_slice(&[0x38, 1]);
        assert!(
            crate::authenticated_session::all_methods::decode_host_runtime_inventory_data_v2(
                &unknown,
                *row.request_id_v1()
            )
            .is_err()
        );
    }
}
