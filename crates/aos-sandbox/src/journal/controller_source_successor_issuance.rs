//! Exact Controller retention and publication of first-successor approvals.
//!
//! ```text
//! DesiredState[prefix || "packet"] = AOSCSA02[896] or AOSCSA03[1072]
//! DesiredState[prefix || "epoch"] = administrative-epoch:u64be
//! DesiredState[prefix || "pending"] = AOSCSI02[80]
//! DesiredState[prefix || "delivered"] = packet-commitment[32]
//! DesiredState[prefix || "consumer-begin"] = AOSCSB02[296]
//! DesiredState[prefix || "consumer-anchored"] = AOSCSH02[144]
//! DesiredState[prefix || "consumer-complete"] = AOSCSC02[240]
//! ```
//!
//! One outstanding fixed slot fences unrelated Controller mutations. Its
//! complete context lives in the signed packet, never in a reconstructed
//! current-head receipt. Both appends use the sole Journal transaction engine;
//! publication uses that SAME writer's retained directory and no-replace name.
//! Consumer completion preserves every issuer row, including the immutable
//! issuance intent named `pending`; only the active consumer fence is released.

use crate::journal::PreflightTransactionViewV1;
use crate::journal::semantic_append::{AppendScope, PreflightScope};

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write as _;
use std::os::fd::AsFd as _;

#[cfg(target_os = "linux")]
use aos_sandbox_linux::protected_file::read_exact_positioned;
use rustix::fs::FileType;
use aos_sandbox_core::ProjectId;

use super::{
    CacheMutationGateV1, Journal, JournalError, JournalRecord, JournalTransaction, RecordNamespace,
};
use crate::hierarchy::genesis_profile::{digest_at, hash, take};
use aos_sandbox_ledger_replay::successor::{
    SourceSuccessorApprovalDataV2,
};
use aos_sandbox_ledger_replay::replay::phase_records::{
    ControllerFirstSourceSuccessorAnchoredV2, ControllerFirstSourceSuccessorBeginV2, ControllerFirstSourceSuccessorCompleteV2, SourceFirstSuccessorAckFieldsV2, SourceFirstSuccessorAckV2,
};
use super::source_tree_successor::{
    FirstSourceSuccessorNativePhaseV2, State, array,
    digest_at as successor_digest_at, transaction_id as successor_transaction_id,
};

const OUTPUT_NAME: &str = "source-successor-input-v2";
const TEMPORARY_NAME: &str = ".source-successor-input-v2.tmp";

pub(crate) use aos_sandbox_ledger_replay::replay::controller_source_successor_issuance::{
    IssuanceKeyRecipeV3, Transition, RetainedIssuanceDataV2,
};
use aos_sandbox_ledger_replay::replay::controller_source_successor_issuance::{
    PREFIX, TRANSACTION_DOMAIN, PROJECT_PREFIX, PROJECT_TRANSACTION_DOMAIN,
};

/// Keeps every opened publication description resident on partial failure.
pub(crate) struct PublicationCustodyV2 {
    staged: Option<File>,
    original: Option<File>,
    readbacks: Vec<Vec<u8>>,
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

fn project_publication_names_v3(project: ProjectId) -> (String, String) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::from("source-successor-input-v3-");
    for byte in project.as_bytes() {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 15)]));
    }
    let temporary = format!(".{output}.tmp");
    (output, temporary)
}

pub(crate) fn retained(journal: &Journal) -> Result<Option<RetainedIssuanceDataV2>, JournalError> {
    journal.ensure_protected_authority()?;
    validate_rows(journal.native.state())
}

pub(crate) fn retained_project_v3(journal: &Journal, project: ProjectId) -> Result<Option<RetainedIssuanceDataV2>, JournalError> {
    journal.ensure_protected_authority()?;
    Ok(validate_project_family_v3(journal.native.state())?.remove(&IssuanceKeyRecipeV3::ProjectV3(project)))
}

pub(crate) fn project_key_v3(project: ProjectId, suffix: &[u8]) -> Result<Vec<u8>, JournalError> {
    aos_sandbox_ledger_replay::replay::controller_source_successor_issuance::project_key_v3(project, suffix)
        .map_err(JournalError::from)
}

pub(crate) fn key(suffix: &[u8]) -> Vec<u8> {
    aos_sandbox_ledger_replay::replay::controller_source_successor_issuance::key(suffix)
}

fn transaction(
    packet: &SourceSuccessorApprovalDataV2,
    transition: Transition,
) -> Result<JournalTransaction, JournalError> {
    aos_sandbox_ledger_replay::replay::controller_source_successor_issuance::transaction(packet, transition)
        .map_err(JournalError::from)
}



pub(super) fn require_no_mutation(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    proposed: &JournalTransaction,
    transition: Option<Transition>,
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::controller_source_successor_issuance::require_no_mutation(state, proposed, transition)
        .map_err(JournalError::from)
}



pub(super) fn validate_rows(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<Option<RetainedIssuanceDataV2>, JournalError> {
    aos_sandbox_ledger_replay::replay::controller_source_successor_issuance::validate_rows(state)
        .map_err(JournalError::from)
}







/// Folds every real global/project row without constructing a filtered Journal.
pub(crate) fn validate_project_family_v3(
    state: &State,
) -> Result<BTreeMap<IssuanceKeyRecipeV3, RetainedIssuanceDataV2>, JournalError> {
    aos_sandbox_ledger_replay::replay::controller_source_successor_issuance::validate_project_family_v3(state)
        .map_err(JournalError::from)
}

/// Derives the exact conservative two-transaction Controller suffix budget.
pub(crate) fn controller_capacity_request(
    packet: &SourceSuccessorApprovalDataV2,
    begin: &ControllerFirstSourceSuccessorBeginV2,
) -> Result<super::GlobalCapacityReservationRequestV1, JournalError> {
    aos_sandbox_ledger_replay::replay::controller_source_successor_issuance::controller_capacity_request(packet, begin)
        .map_err(JournalError::from)
}

pub(crate) fn controller_capacity_request_with_recipe(
    packet: &SourceSuccessorApprovalDataV2,
    begin: &ControllerFirstSourceSuccessorBeginV2,
    recipe: IssuanceKeyRecipeV3,
) -> Result<super::GlobalCapacityReservationRequestV1, JournalError> {
    aos_sandbox_ledger_replay::replay::controller_source_successor_issuance::controller_capacity_request_with_recipe(packet, begin, recipe)
        .map_err(JournalError::from)
}





pub(super) fn consumer_settling(
    state: &State,
    transaction: &JournalTransaction,
    phase: Option<FirstSourceSuccessorNativePhaseV2>,
) -> Result<Option<[u8; 32]>, JournalError> {
    aos_sandbox_ledger_replay::replay::controller_source_successor_issuance::consumer_settling(state, transaction, phase)
        .map_err(JournalError::from)
}

pub(crate) fn recognize_replayed_transition(
    transaction: &JournalTransaction,
) -> Result<Option<Transition>, JournalError> {
    aos_sandbox_ledger_replay::replay::controller_source_successor_issuance::recognize_replayed_transition(transaction)
        .map_err(JournalError::from)
}



pub(super) fn require_no_compaction(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::controller_source_successor_issuance::require_no_compaction(state)
        .map_err(JournalError::from)
}

impl Journal {
    pub(crate) fn prepare_project_successor_issuance_v3(
        &self, packet: &SourceSuccessorApprovalDataV2, transition: Transition,
    ) -> Result<Option<JournalTransaction>, JournalError> {
        let project = packet.intent().map_err(|_| JournalError::ProtectedBoundary)?.project();
        if transition.recipe() != IssuanceKeyRecipeV3::ProjectV3(project)
            || !matches!(transition, Transition::ProjectSave(_) | Transition::ProjectDelivered(_))
        { return Err(JournalError::ProtectedBoundary); }
        let saved = retained_project_v3(self, project)?;
        let needed = match (transition, saved) {
            (Transition::ProjectSave(_), None) => true,
            (Transition::ProjectSave(_), Some(saved)) if saved.packet == *packet => false,
            (Transition::ProjectDelivered(_), Some(saved)) if saved.packet == *packet => !saved.delivered,
            _ => return Err(JournalError::ProtectedBoundary),
        };
        if !needed { return Ok(None); }
        let transaction = transaction(packet, transition)?;
        require_no_mutation(self.native.state(), &transaction, Some(transition))?;
        Ok(Some(transaction))
    }

    pub(crate) fn controller_first_successor_rows_v2(&self) -> Result<Option<RetainedIssuanceDataV2>, JournalError> {
        retained(self)
    }

    /// Checks the complete two-append suffix with the existing native fold.
    pub(crate) fn preflight_source_successor_issuance_v2(
        &self,
        packet: &SourceSuccessorApprovalDataV2,
    ) -> Result<(), JournalError> {
        self.preflight_successor_issuance_with_recipe(packet, IssuanceKeyRecipeV3::GlobalV2)
    }

    pub(crate) fn preflight_project_successor_issuance_v3(
        &self, packet: &SourceSuccessorApprovalDataV2,
    ) -> Result<(), JournalError> {
        let project = packet.intent().map_err(|_| JournalError::ProtectedBoundary)?.project();
        self.preflight_successor_issuance_with_recipe(packet, IssuanceKeyRecipeV3::ProjectV3(project))
    }

    fn preflight_successor_issuance_with_recipe(
        &self, packet: &SourceSuccessorApprovalDataV2, recipe: IssuanceKeyRecipeV3,
    ) -> Result<(), JournalError> {
        let saved = match recipe {
            IssuanceKeyRecipeV3::GlobalV2 => retained(self)?,
            IssuanceKeyRecipeV3::ProjectV3(project) => retained_project_v3(self, project)?,
        };
        let (save, delivered) = match recipe {
            IssuanceKeyRecipeV3::GlobalV2 => (Transition::Save, Transition::Delivered),
            IssuanceKeyRecipeV3::ProjectV3(project) => (Transition::ProjectSave(project), Transition::ProjectDelivered(project)),
        };
        let (transactions, transitions) = match saved {
            None => (
                vec![
                    transaction(packet, save)?,
                    transaction(packet, delivered)?,
                ],
                vec![save, delivered],
            ),
            Some(saved) if saved.packet == *packet && !saved.delivered => (
                vec![transaction(packet, delivered)?],
                vec![delivered],
            ),
            Some(saved) if saved.packet == *packet && saved.delivered => return Ok(()),
            Some(_) => return Err(JournalError::ProtectedBoundary),
        };
        self.preflight_in_scope(
            PreflightTransactionViewV1::Ordinary(&transactions),
            PreflightScope {
                successor_issuance_transitions: Some(&transitions),
                ..PreflightScope::default()
            },
            CacheMutationGateV1::Ordinary,
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
        self.commit_in_scope(
            &transaction(packet, transition)?,
            AppendScope {
                successor_issuance_transition: Some(transition),
                ..AppendScope::default()
            },
            CacheMutationGateV1::Ordinary,
        ).map(|_| ())
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn publish_source_successor_v2(
        &self,
        packet: &SourceSuccessorApprovalDataV2,
        custody: &mut PublicationCustodyV2,
    ) -> Result<(), JournalError> {
        self.publish_successor_with_names(packet, custody, IssuanceKeyRecipeV3::GlobalV2, OUTPUT_NAME, TEMPORARY_NAME)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn publish_project_successor_v3(
        &self, packet: &SourceSuccessorApprovalDataV2, custody: &mut PublicationCustodyV2,
    ) -> Result<(), JournalError> {
        let project = packet.intent().map_err(|_| JournalError::ProtectedBoundary)?.project();
        let (output, temporary) = project_publication_names_v3(project);
        self.publish_successor_with_names(packet, custody, IssuanceKeyRecipeV3::ProjectV3(project), &output, &temporary)
    }

    #[cfg(target_os = "linux")]
    fn publish_successor_with_names(
        &self, packet: &SourceSuccessorApprovalDataV2, custody: &mut PublicationCustodyV2,
        recipe: IssuanceKeyRecipeV3, output: &str, temporary: &str,
    ) -> Result<(), JournalError> {
        self.ensure_protected_authority()?;
        let saved = match recipe {
            IssuanceKeyRecipeV3::GlobalV2 => retained(self)?,
            IssuanceKeyRecipeV3::ProjectV3(project) => retained_project_v3(self, project)?,
        };
        if saved.is_none_or(|saved| saved.packet != *packet) {
            return Err(JournalError::ProtectedBoundary);
        }
        if !self.native.is_protected() { return Err(JournalError::ProtectedBoundary); }
        let directory = self.native.native_operations();
        match directory.inspect_staged_name(temporary) {
            Err(error) if error == rustix::io::Errno::NOENT => {}
            Err(error) => return Err(super::rustix_io::<crate::journal::JournalError>(error)),
            Ok(_) => return Err(JournalError::ProtectedBoundary),
        }

        match directory.open_named_child(output) {
            Ok(file) => custody.original = Some(File::from(file)),
            Err(error) if error == rustix::io::Errno::NOENT => {
                if custody.staged.is_some() || custody.original.is_some() {
                    return Err(JournalError::ProtectedBoundary);
                }
                custody.staged = Some(File::from(
                    directory
                        .open_exclusive_stage(temporary)
                        .map_err(super::rustix_io::<crate::journal::JournalError>)?,
                ));
                let staged = custody
                    .staged
                    .as_mut()
                    .ok_or(JournalError::ProtectedBoundary)?;
                staged.write_all(packet.as_bytes())?;
                staged.sync_all()?;
                self.ensure_protected_authority()?;
                directory
                    .publish_exclusive_stage(temporary, output)
                    .map_err(super::rustix_io::<crate::journal::JournalError>)?;
                custody.original = Some(File::from(
                    directory
                        .open_named_child(output)
                        .map_err(super::rustix_io::<crate::journal::JournalError>)?,
                ));
            }
            Err(error) => return Err(super::rustix_io::<crate::journal::JournalError>(error)),
        }

        // Replay equality is not delivery durability. Both branches validate
        // and sync the same retained final description and original directory
        // before a Delivered append or SAME-flight Finish can follow.
        self.recheck_successor_publication_with_name(packet, custody, output)?;

        let original = custody.original.as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        original.sync_all()?;
        self.ensure_protected_authority()?;
        directory
            .sync_directory()
            .map_err(super::rustix_io::<crate::journal::JournalError>)?;

        self.recheck_successor_publication_with_name(packet, custody, output)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn recheck_source_successor_publication_v2(
        &self,
        packet: &SourceSuccessorApprovalDataV2,
        custody: &mut PublicationCustodyV2,
    ) -> Result<(), JournalError> {
        self.recheck_successor_publication_with_name(packet, custody, OUTPUT_NAME)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn recheck_project_successor_publication_v3(
        &self, packet: &SourceSuccessorApprovalDataV2, custody: &mut PublicationCustodyV2,
    ) -> Result<(), JournalError> {
        let project = packet.intent().map_err(|_| JournalError::ProtectedBoundary)?.project();
        let (output, _) = project_publication_names_v3(project);
        self.recheck_successor_publication_with_name(packet, custody, &output)
    }

    #[cfg(target_os = "linux")]
    fn recheck_successor_publication_with_name(
        &self, packet: &SourceSuccessorApprovalDataV2, custody: &mut PublicationCustodyV2, output: &str,
    ) -> Result<(), JournalError> {
        self.ensure_protected_authority()?;
        let location = self.native.protected_view()
            .ok_or(JournalError::ProtectedBoundary)?;
        let original = custody
            .original
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        let metadata = rustix::fs::fstat(original)
            .map_err(super::rustix_io::<crate::journal::JournalError>)?;
        if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
            || metadata.st_mode & 0o7777 != 0o600
            || metadata.st_uid != location.expected_uid()
            || metadata.st_gid != rustix::process::getegid().as_raw()
            || metadata.st_nlink != 1
            || metadata.st_size != packet.as_bytes().len() as i64
            || custody.readbacks.len() >= 16
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let named = self.native.native_operations()
            .open_named_child(output)
            .map_err(super::rustix_io::<crate::journal::JournalError>)?;
        let named_metadata =
            rustix::fs::fstat(&named).map_err(super::rustix_io::<crate::journal::JournalError>)?;
        if named_metadata.st_dev != metadata.st_dev || named_metadata.st_ino != metadata.st_ino {
            return Err(JournalError::ProtectedBoundary);
        }

        custody.readbacks.push(vec![0; packet.as_bytes().len()]);
        let readback = custody
            .readbacks
            .last_mut()
            .ok_or(JournalError::ProtectedBoundary)?;
        read_exact_positioned(original.as_fd(), readback)
            .map_err(|_| JournalError::ProtectedBoundary)?;
        let after = rustix::fs::fstat(original)
            .map_err(super::rustix_io::<crate::journal::JournalError>)?;
        if readback.as_slice() != packet.as_bytes()
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
        let final_named = self.native.native_operations()
            .open_named_child(output)
            .map_err(super::rustix_io::<crate::journal::JournalError>)?;
        let final_metadata = rustix::fs::fstat(&final_named)
            .map_err(super::rustix_io::<crate::journal::JournalError>)?;
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
    use aos_sandbox_ledger_replay::successor::tests::approval_fixture;

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
        let ack = aos_sandbox_ledger_replay::replay::controller_source_genesis::ack_bytes(
            acceptance.digest(), floor, aos_sandbox_core::ObjectDigest::from_bytes([72; 32]),
        ).map_err(crate::hierarchy::genesis_profile::SourceGenesisErrorV1::from).unwrap();
        let complete = aos_sandbox_ledger_replay::replay::controller_source_genesis::complete_bytes(
            &ack, aos_sandbox_core::ObjectDigest::from_bytes([73; 32]), floor,
        ).map_err(crate::hierarchy::genesis_profile::SourceGenesisErrorV1::from).unwrap();
        let mut state = State::new();
        for transaction in [
            aos_sandbox_ledger_replay::replay::controller_source_genesis::acceptance_transaction(&acceptance).map_err(crate::journal::JournalError::from).unwrap(),
            aos_sandbox_ledger_replay::replay::controller_source_genesis::ack_transaction(acceptance.project(), &ack).map_err(crate::journal::JournalError::from).unwrap(),
            aos_sandbox_ledger_replay::replay::controller_source_genesis::complete_transaction(acceptance.project(), &complete).map_err(crate::journal::JournalError::from).unwrap(),
        ] {
            apply(&mut state, &transaction);
        }

        // The guard checks structural DATA, not this fixture's stale signature.
        let mut bytes = packet.as_bytes().to_vec();
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
            let mut bytes = packet.as_bytes().to_vec();
            bytes[offset] ^= 1;
            let substituted = SourceSuccessorApprovalDataV2::from_record_bytes(&bytes).unwrap();
            let save = transaction(&substituted, Transition::Save).unwrap();
            assert!(require_no_mutation(&state, &save, Some(Transition::Save)).is_err(), "{offset}");
        }

        let project = packet.intent().unwrap().project();
        let acceptance = genesis_fixture::acceptance(project);
        let mut pending = State::new();
        apply(&mut pending, &aos_sandbox_ledger_replay::replay::controller_source_genesis::acceptance_transaction(&acceptance).map_err(crate::journal::JournalError::from).unwrap());
        let save = transaction(&packet, Transition::Save).unwrap();
        assert!(require_no_mutation(&pending, &save, Some(Transition::Save)).is_err());
        assert!(matches!(validate_rows(&pending), Ok(None)));

        let mut saved = state;
        apply(&mut saved, &transaction(&packet, Transition::Save).unwrap());
        saved.insert((RecordNamespace::DesiredState, key(b"epoch")), vec![0; 8]);
        assert!(matches!(validate_rows(&saved), Err(JournalError::ProtectedBoundary)));
    }
}
