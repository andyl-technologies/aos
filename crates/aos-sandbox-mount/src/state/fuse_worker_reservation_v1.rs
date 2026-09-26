//! Closed, Mount-owned reservation state for a future FUSE worker connection.
//!
//! A reservation fixes one attachment, immutable View revision, consumer scope,
//! and broker-minted connection generation before any worker launch or FUSE
//! effect. This module does not admit callers, launch workers, open `/dev/fuse`,
//! transfer descriptors, or establish readiness. In particular, a journal row
//! is not evidence that a FUSE descriptor exists or belongs to a worker.
//!
//! The value is a canonical, versioned JSON envelope:
//!
//! ```text
//! {"version":1,"reservation":{...}}
//! ```

use std::collections::{BTreeMap, BTreeSet};

use aos_sandbox::journal::{Journal, JournalRecord, RecordNamespace};
use aos_sandbox_protocol::mount_source_consumption_state::{
    AssignmentBindingV1, ObjectDescriptorV1,
};
use serde::{Deserialize, Serialize};

use super::mount_resource_v1::ObjectDescriptorV1Ext;
use crate::{MountError, Result};

const KEY_FAMILY: &[u8] = b"aos.mount.fuse.worker.";
const KEY_PREFIX: &[u8] = b"aos.mount.fuse.worker.v1\0";
const VERSION: u16 = 1;
const MAXIMUM_ROWS: usize = 16_384;
const MAXIMUM_VALUE_BYTES: usize = 4 * 1024;
const MAXIMUM_TABLE_BYTES: usize = 32 * 1024 * 1024;

/// Records a broker-authored pre-launch identity, not worker-supplied authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FuseWorkerReservationV1 {
    pub(crate) attachment_id: [u8; 16],
    pub(crate) connection_generation: u64,
    pub(crate) kernel_boot_id: [u8; 16],
    /// Unique unit-instance locator; the name itself is not a capability.
    pub(crate) worker_instance_id: [u8; 16],
    pub(crate) assignment: AssignmentBindingV1,
    pub(crate) attachment_generation: u64,
    pub(crate) destination_slot_id: [u8; 16],
    pub(crate) source_view_id: [u8; 16],
    pub(crate) source_view_revision: u64,
    pub(crate) view_revision: ObjectDescriptorV1,
    /// Fixed, independently verified consumer user-namespace identity.
    pub(crate) user_namespace_device: u64,
    pub(crate) user_namespace_inode: u64,
    pub(crate) user_namespace_generation: u64,
    pub(crate) presentation_plan_digest: [u8; 32],
    pub(crate) policy_digest: [u8; 32],
    pub(crate) lease_identity: [u8; 16],
    pub(crate) lease_expires_boottime_ns: u64,
    pub(crate) state: FuseWorkerReservationStateV1,
}

/// Distinguishes an unreconciled launch fence from a proven terminal generation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FuseWorkerReservationStateV1 {
    /// The broker has not yet proved whether a worker or FUSE effect occurred.
    Reserved,
    /// A future broker-authenticated terminal writer proved worker quiescence and mount absence.
    ///
    /// The codec checks the digest's shape only. Replaying this row alone does
    /// not verify the claimed evidence or permit a new connection generation.
    TeardownVerified { evidence_digest: [u8; 32] },
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredFuseWorkerReservationV1 {
    version: u16,
    reservation: FuseWorkerReservationV1,
}

/// Reconstructs bounded first-generation physical reservations from Mount's journal.
#[derive(Debug)]
pub(crate) struct FuseWorkerReservationTableV1 {
    current_kernel_boot_id: [u8; 16],
    rows: BTreeMap<([u8; 16], u64), FuseWorkerReservationV1>,
    materialized_bytes: usize,
}

impl FuseWorkerReservationTableV1 {
    /// Replays every reserved key and rejects successors, aliases, or unknown versions.
    pub(crate) fn recover(journal: &Journal, current_kernel_boot_id: [u8; 16]) -> Result<Self> {
        if current_kernel_boot_id == [0; 16] {
            return Err(state_error(
                "current FUSE kernel boot identity is a sentinel",
            ));
        }

        let mut rows = BTreeMap::new();
        let mut total_bytes = 0usize;
        for (key, value) in journal.records(RecordNamespace::Operation) {
            let Some(identity) = decode_key(key)? else {
                continue;
            };
            total_bytes = total_bytes
                .checked_add(value.len())
                .ok_or_else(|| state_error("FUSE reservation byte accounting overflowed"))?;
            if rows.len() >= MAXIMUM_ROWS || total_bytes > MAXIMUM_TABLE_BYTES {
                return Err(state_error("FUSE reservation table exceeds its bound"));
            }

            let reservation = decode_value(value)?;
            if identity != (reservation.attachment_id, reservation.connection_generation)
                || rows.insert(identity, reservation).is_some()
            {
                return Err(state_error("FUSE reservation key and value disagree"));
            }
        }

        let table = Self {
            current_kernel_boot_id,
            rows,
            materialized_bytes: total_bytes,
        };
        table.validate_table()?;
        Ok(table)
    }

    /// Prepares only a first-generation, pre-effect reservation for a journal commit.
    ///
    /// The caller must derive every field from separately authenticated
    /// Attachment, View, Host namespace, policy, and lease evidence. Returning
    /// this record neither commits it nor authorizes starting the worker. A
    /// later broker-authenticated terminal writer must gate generation reuse;
    /// this dormant slice cannot verify a recovered terminal claim.
    pub(crate) fn prepare_reservation(
        &self,
        reservation: &FuseWorkerReservationV1,
    ) -> Result<JournalRecord> {
        reservation.validate()?;
        let value = encode_value(reservation)?;
        let proposed_bytes = self
            .materialized_bytes
            .checked_add(value.len())
            .ok_or_else(|| state_error("FUSE reservation byte accounting overflowed"))?;
        if reservation.kernel_boot_id != self.current_kernel_boot_id
            || reservation.state != FuseWorkerReservationStateV1::Reserved
            || self.rows.len() >= MAXIMUM_ROWS
            || proposed_bytes > MAXIMUM_TABLE_BYTES
        {
            return Err(state_error(
                "FUSE reservation cannot be issued on this boot",
            ));
        }

        let previous = self
            .rows
            .range((reservation.attachment_id, 0)..=(reservation.attachment_id, u64::MAX))
            .next_back()
            .map(|(_, row)| row);
        let expected_generation = previous.is_none().then_some(1);
        if expected_generation != Some(reservation.connection_generation) {
            return Err(state_error(
                "FUSE connection generation lacks terminal authorization",
            ));
        }

        if self.rows.values().any(|row| {
            row.worker_instance_id == reservation.worker_instance_id
                || (row.assignment.sandbox_id == reservation.assignment.sandbox_id
                    && row.assignment.incarnation_id == reservation.assignment.incarnation_id
                    && row.destination_slot_id == reservation.destination_slot_id)
        }) {
            return Err(state_error(
                "FUSE worker instance or destination slot is aliased",
            ));
        }

        Ok(JournalRecord::put(
            RecordNamespace::Operation,
            encode_key(reservation.attachment_id, reservation.connection_generation),
            value,
        ))
    }

    /// Iterates every historical reservation, including untrusted terminal claims.
    pub(crate) fn rows(&self) -> impl Iterator<Item = &FuseWorkerReservationV1> {
        self.rows.values()
    }

    fn validate_table(&self) -> Result<()> {
        let mut worker_instances = BTreeSet::new();
        let mut claimed_slots = BTreeSet::new();

        for row in self.rows.values() {
            row.validate()?;
            // Materialized journal rows do not prove a prior authenticated
            // terminal transition, so no successor can be recovered yet.
            if row.connection_generation != 1 {
                return Err(state_error("FUSE connection generation is not first"));
            }
            if !worker_instances.insert(row.worker_instance_id) {
                return Err(state_error(
                    "FUSE worker instance appears in multiple reservations",
                ));
            }
            if !claimed_slots.insert((
                row.assignment.sandbox_id,
                row.assignment.incarnation_id,
                row.destination_slot_id,
            )) {
                return Err(state_error(
                    "FUSE destination slot has multiple reservations",
                ));
            }
        }
        Ok(())
    }
}

impl FuseWorkerReservationV1 {
    fn validate(&self) -> Result<()> {
        if self.attachment_id == [0; 16]
            || self.connection_generation == 0
            || self.kernel_boot_id == [0; 16]
            || self.worker_instance_id == [0; 16]
            || self.assignment.sandbox_id == [0; 16]
            || self.assignment.incarnation_id == [0; 16]
            || self.assignment.assignment_epoch == 0
            || self.assignment.desired_generation == 0
            || self.assignment.assignment_digest == [0; 32]
            || self.assignment.namespace_generation == 0
            || self.attachment_generation == 0
            || self.destination_slot_id == [0; 16]
            || self.source_view_id == [0; 16]
            || self.source_view_revision == 0
            || self.user_namespace_device == 0
            || self.user_namespace_inode == 0
            || self.user_namespace_generation == 0
            || self.user_namespace_generation != self.assignment.namespace_generation
            || self.presentation_plan_digest == [0; 32]
            || self.policy_digest == [0; 32]
            || self.lease_identity == [0; 16]
            || self.lease_expires_boottime_ns == 0
        {
            return Err(state_error(
                "FUSE reservation contains an incomplete identity",
            ));
        }
        self.view_revision.to_runtime()?;
        if matches!(
            self.state,
            FuseWorkerReservationStateV1::TeardownVerified {
                evidence_digest
            } if evidence_digest == [0; 32]
        ) {
            return Err(state_error("FUSE teardown evidence is a sentinel"));
        }
        Ok(())
    }
}

fn encode_key(attachment_id: [u8; 16], connection_generation: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(KEY_PREFIX.len() + 24);
    key.extend_from_slice(KEY_PREFIX);
    key.extend_from_slice(&attachment_id);
    key.extend_from_slice(&connection_generation.to_be_bytes());
    key
}

fn decode_key(key: &[u8]) -> Result<Option<([u8; 16], u64)>> {
    if key.starts_with(KEY_FAMILY) && !key.starts_with(KEY_PREFIX) {
        return Err(state_error("unknown FUSE worker reservation key version"));
    }
    let Some(suffix) = key.strip_prefix(KEY_PREFIX) else {
        return Ok(None);
    };
    if suffix.len() != 24 {
        return Err(state_error("FUSE worker reservation key length is invalid"));
    }
    let attachment_id: [u8; 16] = suffix[..16]
        .try_into()
        .map_err(|_| state_error("FUSE reservation attachment key is invalid"))?;
    let generation_bytes: [u8; 8] = suffix[16..]
        .try_into()
        .map_err(|_| state_error("FUSE reservation generation key is invalid"))?;
    let generation = u64::from_be_bytes(generation_bytes);
    if attachment_id == [0; 16] || generation == 0 {
        return Err(state_error(
            "FUSE worker reservation key contains a sentinel",
        ));
    }
    Ok(Some((attachment_id, generation)))
}

fn encode_value(reservation: &FuseWorkerReservationV1) -> Result<Vec<u8>> {
    reservation.validate()?;
    let value = serde_json::to_vec(&StoredFuseWorkerReservationV1 {
        version: VERSION,
        reservation: reservation.clone(),
    })
    .map_err(|error| state_error(error.to_string()))?;
    if value.len() > MAXIMUM_VALUE_BYTES {
        return Err(state_error("FUSE reservation value exceeds its bound"));
    }
    Ok(value)
}

fn decode_value(value: &[u8]) -> Result<FuseWorkerReservationV1> {
    if value.is_empty() || value.len() > MAXIMUM_VALUE_BYTES {
        return Err(state_error("FUSE reservation value length is invalid"));
    }
    let stored: StoredFuseWorkerReservationV1 =
        serde_json::from_slice(value).map_err(|error| state_error(error.to_string()))?;
    if stored.version != VERSION || encode_value(&stored.reservation)? != value {
        return Err(state_error(
            "FUSE reservation encoding or version is invalid",
        ));
    }
    Ok(stored.reservation)
}

fn state_error(message: impl Into<String>) -> MountError {
    MountError::State(message.into())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use aos_sandbox::journal::JournalTransaction;
    use aos_sandbox_core::PortableMediaType;

    use super::*;

    const BOOT: [u8; 16] = [9; 16];

    fn reservation(attachment: u8, generation: u64) -> FuseWorkerReservationV1 {
        FuseWorkerReservationV1 {
            attachment_id: [attachment; 16],
            connection_generation: generation,
            kernel_boot_id: BOOT,
            worker_instance_id: [attachment.wrapping_add(generation as u8); 16],
            assignment: AssignmentBindingV1 {
                sandbox_id: [3; 16],
                incarnation_id: [4; 16],
                assignment_epoch: 5,
                desired_generation: 6,
                assignment_digest: [7; 32],
                namespace_generation: 8,
            },
            attachment_generation: 9,
            destination_slot_id: [attachment; 16],
            source_view_id: [10; 16],
            source_view_revision: 11,
            view_revision: ObjectDescriptorV1 {
                media_type: PortableMediaType::View.as_str().to_owned(),
                sha256_digest: [12; 32],
                encoded_size: 13,
            },
            user_namespace_device: 14,
            user_namespace_inode: 15,
            user_namespace_generation: 8,
            presentation_plan_digest: [16; 32],
            policy_digest: [17; 32],
            lease_identity: [18; 16],
            lease_expires_boottime_ns: 19,
            state: FuseWorkerReservationStateV1::Reserved,
        }
    }

    fn new_journal() -> (tempfile::TempDir, Journal) {
        let directory = tempfile::tempdir().unwrap();
        let (journal, _) =
            Journal::open(directory.path().join("journal"), Default::default()).unwrap();
        (directory, journal)
    }

    fn commit(journal: &mut Journal, id: u8, records: Vec<JournalRecord>) {
        journal
            .commit(&JournalTransaction::new([id; 16], records).unwrap())
            .unwrap();
    }

    #[test]
    fn reservation_is_a_durable_prelaunch_fence_and_generations_are_monotone() {
        let (_directory, mut journal) = new_journal();
        let table = FuseWorkerReservationTableV1::recover(&journal, BOOT).unwrap();
        let first = reservation(1, 1);
        let record = table.prepare_reservation(&first).unwrap();
        commit(&mut journal, 1, vec![record]);

        let table = FuseWorkerReservationTableV1::recover(&journal, BOOT).unwrap();
        assert!(table.prepare_reservation(&reservation(1, 1)).is_err());
        assert!(table.prepare_reservation(&reservation(1, 2)).is_err());
        assert!(table.prepare_reservation(&reservation(1, 3)).is_err());

        let mut terminal = first.clone();
        terminal.state = FuseWorkerReservationStateV1::TeardownVerified {
            evidence_digest: [20; 32],
        };
        commit(
            &mut journal,
            2,
            vec![JournalRecord::put(
                RecordNamespace::Operation,
                encode_key(first.attachment_id, 1),
                encode_value(&terminal).unwrap(),
            )],
        );

        let table = FuseWorkerReservationTableV1::recover(&journal, BOOT).unwrap();
        assert!(table.prepare_reservation(&reservation(1, 1)).is_err());
        assert!(table.prepare_reservation(&reservation(1, 2)).is_err());
        assert!(table.prepare_reservation(&reservation(1, 3)).is_err());

        // A materialized terminal row cannot prove the prior transition, so
        // recovery itself rejects a forged successor history.
        commit(
            &mut journal,
            3,
            vec![JournalRecord::put(
                RecordNamespace::Operation,
                encode_key(first.attachment_id, 2),
                encode_value(&reservation(1, 2)).unwrap(),
            )],
        );
        assert!(FuseWorkerReservationTableV1::recover(&journal, BOOT).is_err());
    }

    #[test]
    fn recovery_rejects_gaps_overlaps_aliases_and_wrong_keys() {
        let (_directory, mut journal) = new_journal();
        commit(
            &mut journal,
            1,
            vec![JournalRecord::put(
                RecordNamespace::Operation,
                encode_key([1; 16], 2),
                encode_value(&reservation(1, 2)).unwrap(),
            )],
        );
        assert!(FuseWorkerReservationTableV1::recover(&journal, BOOT).is_err());

        let (_directory, mut journal) = new_journal();
        let mut first = reservation(1, 1);
        first.state = FuseWorkerReservationStateV1::TeardownVerified {
            evidence_digest: [20; 32],
        };
        let mut duplicate_instance = reservation(2, 1);
        duplicate_instance.worker_instance_id = first.worker_instance_id;
        commit(
            &mut journal,
            2,
            vec![
                JournalRecord::put(
                    RecordNamespace::Operation,
                    encode_key(first.attachment_id, 1),
                    encode_value(&first).unwrap(),
                ),
                JournalRecord::put(
                    RecordNamespace::Operation,
                    encode_key(duplicate_instance.attachment_id, 1),
                    encode_value(&duplicate_instance).unwrap(),
                ),
            ],
        );
        assert!(FuseWorkerReservationTableV1::recover(&journal, BOOT).is_err());

        let (_directory, mut journal) = new_journal();
        commit(
            &mut journal,
            3,
            vec![JournalRecord::put(
                RecordNamespace::Operation,
                encode_key([3; 16], 1),
                encode_value(&reservation(4, 1)).unwrap(),
            )],
        );
        assert!(FuseWorkerReservationTableV1::recover(&journal, BOOT).is_err());
    }

    #[test]
    fn unknown_versions_and_noncanonical_values_fail_closed() {
        let value = encode_value(&reservation(1, 1)).unwrap();
        let mut version: serde_json::Value = serde_json::from_slice(&value).unwrap();
        version["version"] = serde_json::Value::from(2);
        assert!(decode_value(&serde_json::to_vec(&version).unwrap()).is_err());

        let mut unknown: serde_json::Value = serde_json::from_slice(&value).unwrap();
        unknown["reservation"]["worker_claimed_fd"] = serde_json::Value::from(7);
        assert!(decode_value(&serde_json::to_vec(&unknown).unwrap()).is_err());

        let mut padded = value;
        padded.push(b' ');
        assert!(decode_value(&padded).is_err());
        assert!(decode_key(b"aos.mount.fuse.worker.v2\0future").is_err());
        assert!(decode_key(b"aos.mount.fuse.worker.v1\0short").is_err());
    }

    #[test]
    fn reservation_rejects_stale_boot_incomplete_scope_and_slot_reuse() {
        let (_directory, mut journal) = new_journal();
        let table = FuseWorkerReservationTableV1::recover(&journal, BOOT).unwrap();
        let mut wrong_boot = reservation(1, 1);
        wrong_boot.kernel_boot_id = [21; 16];
        assert!(table.prepare_reservation(&wrong_boot).is_err());

        let mut missing_namespace = reservation(1, 1);
        missing_namespace.user_namespace_generation = 0;
        assert!(table.prepare_reservation(&missing_namespace).is_err());

        let mut wrong_view = reservation(1, 1);
        wrong_view.view_revision.media_type = PortableMediaType::Tree.as_str().to_owned();
        assert!(table.prepare_reservation(&wrong_view).is_err());

        commit(
            &mut journal,
            1,
            vec![table.prepare_reservation(&reservation(1, 1)).unwrap()],
        );
        let table = FuseWorkerReservationTableV1::recover(&journal, BOOT).unwrap();
        let mut slot_alias = reservation(2, 1);
        slot_alias.destination_slot_id = [1; 16];
        assert!(table.prepare_reservation(&slot_alias).is_err());

        let mut terminal = reservation(1, 1);
        terminal.state = FuseWorkerReservationStateV1::TeardownVerified {
            evidence_digest: [20; 32],
        };
        commit(
            &mut journal,
            2,
            vec![JournalRecord::put(
                RecordNamespace::Operation,
                encode_key(terminal.attachment_id, 1),
                encode_value(&terminal).unwrap(),
            )],
        );
        let table = FuseWorkerReservationTableV1::recover(&journal, BOOT).unwrap();
        assert!(table.prepare_reservation(&slot_alias).is_err());
        slot_alias.assignment.namespace_generation = 9;
        slot_alias.user_namespace_generation = 9;
        assert!(table.prepare_reservation(&slot_alias).is_err());

        let mut wrong_namespace_generation = reservation(3, 1);
        wrong_namespace_generation.user_namespace_generation = 9;
        assert!(
            table
                .prepare_reservation(&wrong_namespace_generation)
                .is_err()
        );
    }
}
