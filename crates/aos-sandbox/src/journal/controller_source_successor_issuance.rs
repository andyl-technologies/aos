//! Exact Controller retention and publication of first-successor approvals.
//!
//! ```text
//! DesiredState[prefix || "packet"] = AOSCSA02[896]
//! DesiredState[prefix || "epoch"] = administrative-epoch:u64be
//! DesiredState[prefix || "pending"] = AOSCSI02[80]
//! DesiredState[prefix || "delivered"] = packet-commitment[32]
//! ```
//!
//! One outstanding fixed slot fences unrelated Controller mutations. Its
//! complete context lives in the signed packet, never in a reconstructed
//! current-head receipt. Both appends use the sole Journal transaction engine;
//! publication uses that SAME writer's retained directory and no-replace name.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write as _;
use std::os::fd::AsFd as _;

#[cfg(target_os = "linux")]
use aos_sandbox_linux::protected_file::{open_nofollow_child, read_exact_positioned};
use rustix::fs::{FileType, Mode, OFlags, RenameFlags};

use super::{
    CacheMutationGateV1, Journal, JournalError, JournalRecord, JournalTransaction, RecordNamespace,
};
use crate::hierarchy::genesis_profile::{digest_at, hash, take};
use crate::hierarchy::source_successor::{
    SOURCE_SUCCESSOR_APPROVAL_BYTES_V2, SourceSuccessorApprovalDataV2,
};

const PREFIX: &[u8] = b"\0aos-controller-source-successor-issuance-v2\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.source-successor.issuance.transaction.v2\0";
const OUTPUT_NAME: &str = "source-successor-input-v2";
const TEMPORARY_NAME: &str = ".source-successor-input-v2.tmp";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Transition {
    Save,
    Delivered,
}

pub(crate) struct RetainedIssuanceDataV2 {
    pub(crate) packet: SourceSuccessorApprovalDataV2,
    pub(crate) delivered: bool,
}

/// Keeps every opened publication description resident on partial failure.
pub(crate) struct PublicationCustodyV2 {
    staged: Option<File>,
    original: Option<File>,
    readbacks: Vec<[u8; SOURCE_SUCCESSOR_APPROVAL_BYTES_V2]>,
}

impl PublicationCustodyV2 {
    pub(crate) fn new() -> Self {
        Self {
            staged: None,
            original: None,
            readbacks: Vec::new(),
        }
    }
}

pub(crate) fn retained(journal: &Journal) -> Result<Option<RetainedIssuanceDataV2>, JournalError> {
    journal.ensure_protected_authority()?;
    validate_rows(&journal.state)
}

fn key(suffix: &[u8]) -> Vec<u8> {
    let mut key = PREFIX.to_vec();
    key.extend_from_slice(suffix);
    key
}

fn transaction(
    packet: &SourceSuccessorApprovalDataV2,
    transition: Transition,
) -> Result<JournalTransaction, JournalError> {
    let namespace = RecordNamespace::DesiredState;
    let (suffix, records) = match transition {
        Transition::Save => (
            b"save".as_slice(),
            vec![
                JournalRecord::put(namespace, key(b"packet"), packet.as_bytes().to_vec()),
                JournalRecord::put(
                    namespace,
                    key(b"epoch"),
                    packet.epoch().map_err(|_| JournalError::ProtectedBoundary)?
                        .to_be_bytes().to_vec(),
                ),
                JournalRecord::put(
                    namespace,
                    key(b"pending"),
                    packet.intent().map_err(|_| JournalError::ProtectedBoundary)?
                        .as_bytes().to_vec(),
                ),
            ],
        ),
        Transition::Delivered => (
            b"delivered".as_slice(),
            vec![JournalRecord::put(
                namespace, key(b"delivered"), packet.digest().as_bytes().to_vec(),
            )],
        ),
    };

    let mut identity = suffix.to_vec();
    identity.extend_from_slice(packet.digest().as_bytes());
    let id = take::<16>(hash(TRANSACTION_DOMAIN, &identity).as_bytes(), 0)
        .map_err(|_| JournalError::ProtectedBoundary)?;
    JournalTransaction::new(id, records)
}

pub(super) fn require_no_mutation(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    proposed: &JournalTransaction,
    transition: Option<Transition>,
) -> Result<(), JournalError> {
    let before = validate_rows(state)?;
    let touches_owned = proposed.records().iter().any(|record| {
        record.namespace() == RecordNamespace::DesiredState && record.key().starts_with(PREFIX)
    });
    let Some(transition) = transition else {
        return if before.is_some() || touches_owned {
            Err(JournalError::ProtectedBoundary)
        } else {
            Ok(())
        };
    };

    let packet = match transition {
        Transition::Save => {
            if before.is_some() {
                return Err(JournalError::ProtectedBoundary);
            }
            let record = proposed.records().first().ok_or(JournalError::ProtectedBoundary)?;
            let packet = SourceSuccessorApprovalDataV2::from_record_bytes(
                record.value().ok_or(JournalError::ProtectedBoundary)?,
            ).map_err(|_| JournalError::ProtectedBoundary)?;
            require_administrative_epoch(state, &packet)?;
            packet
        }
        Transition::Delivered => {
            let saved = before.ok_or(JournalError::ProtectedBoundary)?;
            if saved.delivered {
                return Err(JournalError::ProtectedBoundary);
            }
            saved.packet
        }
    };

    if proposed != &transaction(&packet, transition)? {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

fn validate_rows(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<Option<RetainedIssuanceDataV2>, JournalError> {
    let row_count = state.keys()
        .filter(|(namespace, key)| {
            *namespace == RecordNamespace::DesiredState && key.starts_with(PREFIX)
        })
        .count();
    if row_count == 0 {
        return Ok(None);
    }
    if row_count != 3 && row_count != 4 {
        return Err(JournalError::ProtectedBoundary);
    }

    let value = |suffix: &[u8]| state.get(&(RecordNamespace::DesiredState, key(suffix)));
    let packet = SourceSuccessorApprovalDataV2::from_record_bytes(
        value(b"packet").ok_or(JournalError::ProtectedBoundary)?,
    ).map_err(|_| JournalError::ProtectedBoundary)?;
    let epoch = packet.epoch().map_err(|_| JournalError::ProtectedBoundary)?;
    let intent = packet.intent().map_err(|_| JournalError::ProtectedBoundary)?;
    if value(b"epoch").map(Vec::as_slice) != Some(epoch.to_be_bytes().as_slice())
        || value(b"pending").map(Vec::as_slice) != Some(intent.as_bytes().as_slice())
    {
        return Err(JournalError::ProtectedBoundary);
    }

    let delivered = value(b"delivered");
    if delivered.is_some_and(|bytes| bytes.as_slice() != packet.digest().as_bytes())
        || row_count != 3 + usize::from(delivered.is_some())
    {
        return Err(JournalError::ProtectedBoundary);
    }
    require_administrative_epoch(state, &packet)?;
    Ok(Some(RetainedIssuanceDataV2 {
        packet,
        delivered: delivered.is_some(),
    }))
}

fn require_administrative_epoch(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    packet: &SourceSuccessorApprovalDataV2,
) -> Result<(), JournalError> {
    let project = packet.intent()
        .map_err(|_| JournalError::ProtectedBoundary)?.project();
    let current = super::controller_source_genesis::all_rows(state)?;
    let original = current.get(&project).ok_or(JournalError::ProtectedBoundary)?;
    let completed = original.complete.as_ref()
        .ok_or(JournalError::ProtectedBoundary)?;
    let original_epoch = original.acceptance.seed_claims()
        .map_err(|_| JournalError::ProtectedBoundary)?.epoch();
    if packet.epoch().map_err(|_| JournalError::ProtectedBoundary)?
        != original_epoch.checked_add(1).ok_or(JournalError::ProtectedBoundary)?
        || packet.body()[144..176] != *digest_at(completed, 80).as_bytes()
        || packet.body()[176..208] != *digest_at(completed, 112).as_bytes()
    {
        return Err(JournalError::ProtectedBoundary);
    }

    // Full Root roles and the two administrative roles use different domains.
    // The original received-floor/accepted-input join belongs to the real
    // coordinator; the administrative digest cannot stand in for that tuple.
    Ok(())
}

pub(super) fn require_no_compaction(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<(), JournalError> {
    if validate_rows(state)?.is_some() {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

impl Journal {
    /// Checks the complete two-append suffix with the existing native fold.
    pub(crate) fn preflight_source_successor_issuance_v2(
        &self,
        packet: &SourceSuccessorApprovalDataV2,
    ) -> Result<(), JournalError> {
        let saved = retained(self)?;
        let (transactions, transitions) = match saved {
            None => (
                vec![
                    transaction(packet, Transition::Save)?,
                    transaction(packet, Transition::Delivered)?,
                ],
                vec![Transition::Save, Transition::Delivered],
            ),
            Some(saved) if saved.packet == *packet && !saved.delivered => (
                vec![transaction(packet, Transition::Delivered)?],
                vec![Transition::Delivered],
            ),
            Some(saved) if saved.packet == *packet && saved.delivered => return Ok(()),
            Some(_) => return Err(JournalError::ProtectedBoundary),
        };
        self.preflight_with_cache_gate_and_successor_issuance(
            &transactions,
            None,
            false,
            false,
            None,
            None,
            None,
            None,
            CacheMutationGateV1::Ordinary,
            Some(&transitions),
        )
    }

    pub(crate) fn save_source_successor_issuance_v2(
        &mut self,
        packet: &SourceSuccessorApprovalDataV2,
    ) -> Result<(), JournalError> {
        if let Some(saved) = retained(self)? {
            return if saved.packet == *packet {
                Ok(())
            } else {
                Err(JournalError::ProtectedBoundary)
            };
        }

        self.commit_source_successor_transition_v2(packet, Transition::Save)?;
        if retained(self)?.is_none_or(|saved| saved.packet != *packet || saved.delivered) {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    pub(crate) fn complete_source_successor_delivery_v2(
        &mut self,
        packet: &SourceSuccessorApprovalDataV2,
    ) -> Result<(), JournalError> {
        let saved = retained(self)?.ok_or(JournalError::ProtectedBoundary)?;
        if saved.packet != *packet {
            return Err(JournalError::ProtectedBoundary);
        }
        if !saved.delivered {
            self.commit_source_successor_transition_v2(packet, Transition::Delivered)?;
        }
        if retained(self)?.is_none_or(|saved| saved.packet != *packet || !saved.delivered) {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    fn commit_source_successor_transition_v2(
        &mut self,
        packet: &SourceSuccessorApprovalDataV2,
        transition: Transition,
    ) -> Result<(), JournalError> {
        self.commit_with_cache_gate_and_successor_issuance(
            &transaction(packet, transition)?,
            None,
            false,
            false,
            false,
            false,
            false,
            super::SourceProjectAdmissionTransition::None,
            super::controller_source_genesis::ControllerSourceGenesisTransition::None,
            super::source_tree_genesis::SourceGenesisTransitionV1::None,
            super::RootSourceGenesisTransitionV1::None,
            None,
            CacheMutationGateV1::Ordinary,
            Some(transition),
        ).map(|_| ())
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn publish_source_successor_v2(
        &self,
        packet: &SourceSuccessorApprovalDataV2,
        custody: &mut PublicationCustodyV2,
    ) -> Result<(), JournalError> {
        self.ensure_protected_authority()?;
        if retained(self)?.is_none_or(|saved| saved.packet != *packet) {
            return Err(JournalError::ProtectedBoundary);
        }
        let directory = &self.protected.as_ref()
            .ok_or(JournalError::ProtectedBoundary)?.directory;
        match rustix::fs::statat(
            directory, TEMPORARY_NAME, rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Err(error) if error == rustix::io::Errno::NOENT => {}
            Err(error) => return Err(error.into()),
            Ok(_) => return Err(JournalError::ProtectedBoundary),
        }

        match open_nofollow_child(directory, OUTPUT_NAME) {
            Ok(file) => custody.original = Some(File::from(file)),
            Err(error) if error == rustix::io::Errno::NOENT => {
                if custody.staged.is_some() || custody.original.is_some() {
                    return Err(JournalError::ProtectedBoundary);
                }
                custody.staged = Some(File::from(rustix::fs::openat(
                    directory,
                    TEMPORARY_NAME,
                    OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::from_bits_truncate(0o600),
                )?));
                let staged = custody.staged.as_mut().ok_or(JournalError::ProtectedBoundary)?;
                staged.write_all(packet.as_bytes())?;
                staged.sync_all()?;
                self.ensure_protected_authority()?;
                rustix::fs::renameat_with(
                    directory, TEMPORARY_NAME, directory, OUTPUT_NAME, RenameFlags::NOREPLACE,
                )?;
                custody.original = Some(File::from(open_nofollow_child(directory, OUTPUT_NAME)?));
            }
            Err(error) => return Err(error.into()),
        }

        // Replay equality is not delivery durability. Both branches validate
        // and sync the same retained final description and original directory
        // before a Delivered append or SAME-flight Finish can follow.
        self.recheck_source_successor_publication_v2(packet, custody)?;

        let original = custody.original.as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        original.sync_all()?;
        self.ensure_protected_authority()?;
        rustix::fs::fsync(directory)?;

        self.recheck_source_successor_publication_v2(packet, custody)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn recheck_source_successor_publication_v2(
        &self,
        packet: &SourceSuccessorApprovalDataV2,
        custody: &mut PublicationCustodyV2,
    ) -> Result<(), JournalError> {
        self.ensure_protected_authority()?;
        let location = self.protected.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        let original = custody.original.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        let metadata = rustix::fs::fstat(original)?;
        if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
            || metadata.st_mode & 0o7777 != 0o600
            || metadata.st_uid != location.expected_uid
            || metadata.st_gid != rustix::process::getegid().as_raw()
            || metadata.st_nlink != 1
            || metadata.st_size != SOURCE_SUCCESSOR_APPROVAL_BYTES_V2 as i64
            || custody.readbacks.len() >= 16
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let named = open_nofollow_child(&location.directory, OUTPUT_NAME)?;
        let named_metadata = rustix::fs::fstat(&named)?;
        if named_metadata.st_dev != metadata.st_dev || named_metadata.st_ino != metadata.st_ino {
            return Err(JournalError::ProtectedBoundary);
        }

        custody.readbacks.push([0; SOURCE_SUCCESSOR_APPROVAL_BYTES_V2]);
        let readback = custody.readbacks.last_mut().ok_or(JournalError::ProtectedBoundary)?;
        read_exact_positioned(original.as_fd(), readback)
            .map_err(|_| JournalError::ProtectedBoundary)?;
        let after = rustix::fs::fstat(original)?;
        if readback != packet.as_bytes()
            || metadata.st_dev != after.st_dev
            || metadata.st_ino != after.st_ino
            || metadata.st_mode != after.st_mode
            || metadata.st_uid != after.st_uid
            || metadata.st_gid != after.st_gid
            || metadata.st_nlink != after.st_nlink
            || metadata.st_size != after.st_size
            || metadata.st_mtime != after.st_mtime
            || metadata.st_mtime_nsec != after.st_mtime_nsec
            || metadata.st_ctime != after.st_ctime
            || metadata.st_ctime_nsec != after.st_ctime_nsec
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let final_named = open_nofollow_child(&location.directory, OUTPUT_NAME)?;
        let final_metadata = rustix::fs::fstat(&final_named)?;
        if final_metadata.st_dev != metadata.st_dev || final_metadata.st_ino != metadata.st_ino {
            return Err(JournalError::ProtectedBoundary);
        }
        self.ensure_protected_authority()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hierarchy::source_genesis::tests as genesis_fixture;
    use crate::hierarchy::source_successor::tests::approval_fixture;

    type State = BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;

    fn apply(state: &mut State, transaction: &JournalTransaction) {
        for record in transaction.records() {
            state.insert(
                (record.namespace(), record.key().to_vec()),
                record.value().unwrap().to_vec(),
            );
        }
    }

    // Reuses canonical old records without constructing a protected owner.
    fn completed_fixture() -> (State, SourceSuccessorApprovalDataV2) {
        let (packet, _) = approval_fixture();
        let acceptance = genesis_fixture::acceptance(packet.intent().unwrap().project());
        let floor = aos_sandbox_core::ObjectDigest::from_bytes([71; 32]);
        let ack = super::super::controller_source_genesis::ack_bytes(
            acceptance.digest(), floor, aos_sandbox_core::ObjectDigest::from_bytes([72; 32]),
        ).unwrap();
        let complete = super::super::controller_source_genesis::complete_bytes(
            &ack, aos_sandbox_core::ObjectDigest::from_bytes([73; 32]), floor,
        ).unwrap();
        let mut state = State::new();
        for transaction in [
            super::super::controller_source_genesis::acceptance_transaction(&acceptance).unwrap(),
            super::super::controller_source_genesis::ack_transaction(acceptance.project(), &ack).unwrap(),
            super::super::controller_source_genesis::complete_transaction(acceptance.project(), &complete).unwrap(),
        ] {
            apply(&mut state, &transaction);
        }

        // The guard checks structural DATA, not this fixture's stale signature.
        let mut bytes = *packet.as_bytes();
        bytes[24..32].copy_from_slice(&(acceptance.seed_claims().unwrap().epoch() + 1).to_be_bytes());
        bytes[144..176].copy_from_slice(floor.as_bytes());
        bytes[176..208].copy_from_slice(digest_at(&complete, 112).as_bytes());
        let packet = SourceSuccessorApprovalDataV2::from_record_bytes(&bytes).unwrap();
        (state, packet)
    }

    #[test]
    fn exact_save_then_delivery_reuses_completed_genesis_and_fences_the_slot() {
        let (mut state, packet) = completed_fixture();
        let save = transaction(&packet, Transition::Save).unwrap();

        assert!(require_no_mutation(&state, &save, Some(Transition::Save)).is_ok());
        apply(&mut state, &save);
        assert!(!validate_rows(&state).unwrap().unwrap().delivered);
        assert!(require_no_mutation(&state, &save, Some(Transition::Save)).is_err());

        let delivered = transaction(&packet, Transition::Delivered).unwrap();
        assert!(require_no_mutation(&state, &delivered, Some(Transition::Delivered)).is_ok());
        apply(&mut state, &delivered);
        assert!(validate_rows(&state).unwrap().unwrap().delivered);
        assert!(require_no_mutation(&state, &delivered, Some(Transition::Delivered)).is_err());
        assert!(require_no_compaction(&state).is_err());
    }

    #[test]
    fn issuer_guard_rejects_reordering_interleaving_and_untyped_owned_mutations() {
        let (mut state, packet) = completed_fixture();
        let save = transaction(&packet, Transition::Save).unwrap();
        let unrelated = JournalRecord::put(RecordNamespace::DesiredState, b"unrelated".to_vec(), vec![1]);
        let ordinary = JournalTransaction::new([11; 16], vec![unrelated.clone()]).unwrap();

        assert!(require_no_mutation(&state, &ordinary, None).is_ok());
        assert!(require_no_mutation(&state, &save, None).is_err());
        let mut reordered = save.records().to_vec();
        reordered.swap(0, 1);
        let reordered = JournalTransaction::new([12; 16], reordered).unwrap();
        assert!(require_no_mutation(&state, &reordered, Some(Transition::Save)).is_err());
        let mut interleaved = save.records().to_vec();
        interleaved.insert(1, unrelated);
        let interleaved = JournalTransaction::new([13; 16], interleaved).unwrap();
        assert!(require_no_mutation(&state, &interleaved, Some(Transition::Save)).is_err());

        apply(&mut state, &save);
        assert!(require_no_mutation(&state, &ordinary, None).is_err());
        state.insert((RecordNamespace::DesiredState, key(b"foreign")), vec![1]);
        assert!(validate_rows(&state).is_err());
    }

    #[test]
    fn issuer_guard_requires_actual_completed_checksum_and_next_original_epoch() {
        let (state, packet) = completed_fixture();
        for offset in [24, 144, 176] {
            let mut bytes = *packet.as_bytes();
            bytes[offset] ^= 1;
            let substituted = SourceSuccessorApprovalDataV2::from_record_bytes(&bytes).unwrap();
            let save = transaction(&substituted, Transition::Save).unwrap();
            assert!(require_no_mutation(&state, &save, Some(Transition::Save)).is_err(), "{offset}");
        }

        let project = packet.intent().unwrap().project();
        let acceptance = genesis_fixture::acceptance(project);
        let mut pending = State::new();
        apply(&mut pending, &super::super::controller_source_genesis::acceptance_transaction(&acceptance).unwrap());
        let save = transaction(&packet, Transition::Save).unwrap();
        assert!(require_no_mutation(&pending, &save, Some(Transition::Save)).is_err());
        assert!(matches!(validate_rows(&pending), Ok(None)));

        let mut saved = state;
        apply(&mut saved, &transaction(&packet, Transition::Save).unwrap());
        saved.insert((RecordNamespace::DesiredState, key(b"epoch")), vec![0; 8]);
        assert!(matches!(validate_rows(&saved), Err(JournalError::ProtectedBoundary)));
    }
}
