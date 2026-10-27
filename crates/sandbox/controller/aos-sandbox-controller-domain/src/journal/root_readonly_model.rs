//! Moves one completed Root cold replay into the existing readonly Journal model.
//!
//! Only the actual fixed native reader can supply this composition. It moves the
//! same read-only descriptors, maps, index and historical remainder after that
//! reader's independent native posts. It neither replays a second parser nor
//! creates a writer, authenticated request or accepted operation.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs::File;
use std::mem::size_of;
use std::path::Path;

use aos_sandbox_broker::canonical_journal::RecoveryReport;
use aos_sandbox_broker::canonical_journal::{
    CanonicalJournalInstanceDataV1, CanonicalOrdinaryHeldJournalV1, CanonicalOrdinaryReadonlyOpeningV1,
};
use aos_sandbox_model::{RecordNamespace, ResourceDimension as D, ResourceVector};
use aos_sandbox_journal::protected_storage::{ReadOnlyJournalNameWitness, ReadOnlyJournalNamesOriginalsV1};
use aos_sandbox_linux::signer_mount::{RootReadonlyViewV1, SignerMountReadbackAttemptV1,
    SignerMountReadbackClosedV1};
use aos_sandbox_ledger_replay::cold::ColdReplayRemainderDataV1;

use super::semantic_remainder::{ColdSemanticRemainderOriginalV1, DomainSemanticRemainderDataV1};
use super::{Journal, JournalAuthorityInstance, JournalError};
use super::native_backing::Selection;
use crate::policy_compiler::create_storage_current::controller_readonly::native_read::RootFixedNativeReadOriginalsV1;

type State = BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;
type Opening = CanonicalOrdinaryReadonlyOpeningV1<JournalError>;
type Held = CanonicalOrdinaryHeldJournalV1<Selection, JournalAuthorityInstance>;

// These transfer slots keep the actual opaque opening resident if conversion
// refuses. Only the completed fixed reader produces this private upper carrier;
// the common Journal constructor accepts its actual held owner, never raw rows.
pub(crate) struct RootReadonlyJournalModelInputsV1 {
    pub(crate) root: &'static str,
    pub(crate) name: &'static str,
    pub(crate) view: RootReadonlyViewV1,
    pub(crate) original_uid: u32,
    pub(crate) witness: Option<ReadOnlyJournalNameWitness>,
    pub(crate) report: RecoveryReport,
    pub(crate) opening: Option<Opening>,
    pub(crate) remainder: Option<ColdReplayRemainderDataV1>,
}

pub(crate) struct RootReadonlyJournalModelOriginalsV1 {
    inputs: Option<RootReadonlyJournalModelInputsV1>,
    conversion: ColdSemanticRemainderOriginalV1,
    semantic: Option<DomainSemanticRemainderDataV1>,
    native: Option<(Held, RecoveryReport)>,
    captured: Option<super::native_interval::captured::CapturedAppendOwnerV1>,
    journal: Option<Journal>,
    result: Option<Result<(), JournalError>>,
    reentered: bool,
    parent_mount: SignerMountReadbackAttemptV1,
    parent_mount_result: Option<Result<(), SignerMountReadbackClosedV1>>,
    parent_names: ReadOnlyJournalNamesOriginalsV1<JournalError>,
    parent_binding: Option<Result<(), JournalError>>,
    parent_attempted: bool,
}

impl RootReadonlyJournalModelOriginalsV1 {
    pub(crate) fn new() -> Self {
        Self {
            inputs: None, conversion: ColdSemanticRemainderOriginalV1::new(),
            semantic: None, native: None, captured: None, journal: None, result: None, reentered: false,
            parent_mount: SignerMountReadbackAttemptV1::new(), parent_mount_result: None,
            parent_names: ReadOnlyJournalNamesOriginalsV1::new(),
            parent_binding: None, parent_attempted: false,
        }
    }

    pub(crate) fn native_opening_receiving_bytes_v1() -> Option<usize> {
        Opening::receiving_construction_bytes_v1::<Selection, JournalAuthorityInstance>()
    }

    // Maps and descriptors are moved, not duplicated. This addition pays only
    // the actual lazy composition, name/path and authority-marker bytes.
    pub(crate) fn receiving_demand_v1(actual: &RootFixedNativeReadOriginalsV1) -> Result<ResourceVector, JournalError> {
        let (path_bytes, parent_files) = actual.captured_model_post_geometry_v1()?;
        let mount_bytes = SignerMountReadbackAttemptV1::receiving_memory_bound_v1()
            .ok_or(JournalError::JournalTooLarge)?;
        let bytes = size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(Journal::ordinary_materialization_receiving_bytes_v1()?))
            .and_then(|bytes| bytes.checked_add(size_of::<RootReadonlyJournalModelInputsV1>().checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(CanonicalJournalInstanceDataV1::<JournalAuthorityInstance>::
                payload_allocation_receiving_bytes_v1()?))
            .and_then(|bytes| bytes.checked_add(path_bytes.checked_mul(4)?))
            .and_then(|bytes| bytes.checked_add(mount_bytes))
            .and_then(|bytes| bytes.checked_add(parent_files.checked_mul(4096)?))
            .and_then(|bytes| bytes.checked_add(parent_files.checked_mul(3 * size_of::<File>())?))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(JournalError::JournalTooLarge)?;
        // One independent final rooted/name pass and mountinfo FD remain
        // resident through the outer purpose's model/compiler body.
        let files = u64::try_from(parent_files.checked_add(1)
            .ok_or(JournalError::JournalTooLarge)?).map_err(|_| JournalError::JournalTooLarge)?;
        ResourceVector::ZERO.with(D::MemoryBytes, bytes)
            .with(D::OpenFiles, files).with(D::MetadataEntries, files)
            .checked_add(ColdSemanticRemainderOriginalV1::receiving_demand_v1()?)
            .map_err(|_| JournalError::JournalTooLarge)
    }

    pub(crate) fn adopt_once(&mut self, actual: &mut RootFixedNativeReadOriginalsV1) {
        if self.result.is_some() {
            self.reentered = true;
            return;
        }
        self.result = Some(self.adopt_inner(actual));
    }

    fn adopt_inner(&mut self, actual: &mut RootFixedNativeReadOriginalsV1) -> Result<(), JournalError> {
        self.inputs = Some(actual.take_completed_model_inputs_v1()?);
        self.convert_remainder_once_v1()?;
        let inputs = self.inputs.as_mut().ok_or(JournalError::ProtectedBoundary)?;

        // Conversion readiness precedes the actual late identity allocation.
        // The common factory moves only its own physical/parser/index bundle.
        let opened = inputs.opening.as_mut().ok_or(JournalError::ProtectedBoundary)?;
        self.native = opened.take_held_with_late_payload_once_v1(
            super::runtime_deployment_history::OriginalCompactionSelectionV1::capture(
                Path::new(inputs.root), inputs.name),
            JournalAuthorityInstance,
        );
        if self.native.is_none() { return Err(JournalError::ProtectedBoundary); }
        let (journal, report) = Journal::from_actual_ordinary_held_v1(
            &mut self.native, &mut self.semantic, &mut self.captured,
        ).ok_or(JournalError::ProtectedBoundary)?;
        self.journal = Some(journal);
        if (report.committed_transactions, report.committed_records, report.truncated_bytes)
            != (inputs.report.committed_transactions, inputs.report.committed_records, inputs.report.truncated_bytes)
        { return Err(JournalError::ProtectedBoundary); }
        Ok(())
    }

    fn convert_remainder_once_v1(&mut self) -> Result<(), JournalError> {
        let inputs = self.inputs.as_mut().ok_or(JournalError::ProtectedBoundary)?;
        self.conversion.observe_once(&mut inputs.remainder);
        if !self.conversion.ready() { return Err(JournalError::ProtectedBoundary); }
        self.semantic = self.conversion.take_once();
        self.semantic.as_ref().map(|_| ()).ok_or(JournalError::ProtectedBoundary)
    }

    /// Runs the separately prepaid native post after the outer model body.
    /// No healthy entry, new debit or replay is performed on this owed path.
    pub(crate) fn finish_parent_post_once_v1(&mut self) {
        if self.parent_attempted {
            self.reentered = true;
            return;
        }
        self.parent_attempted = true;
        let Some(inputs) = &self.inputs else {
            self.parent_binding = Some(Err(JournalError::ProtectedBoundary));
            return;
        };
        let root = inputs.witness.as_ref().map(|witness| witness.physical_pairs().0);
        self.parent_mount_result = Some(self.parent_mount.observe_root_readonly_once(
            inputs.view, inputs.original_uid, rustix::process::getegid().as_raw(), root));
        // The independently owed names pass is not suppressed by mount refusal.
        if let Some(witness) = &inputs.witness {
            if let Some(journal) = &self.journal {
                if let Ok(held) = journal.native.ordinary_readonly_held_v1() {
                    held.capture_readonly_names_once_v1(&self.parent_names, witness);
                }
            } else if let Some((held, _)) = &self.native {
                held.capture_readonly_names_once_v1(&self.parent_names, witness);
            } else if let Some(opening) = &inputs.opening {
                opening.capture_readonly_names_once_v1(&self.parent_names, witness);
            }
        }
        self.parent_binding = Some(if matches!(self.parent_mount_result, Some(Ok(())))
            && self.parent_names.is_complete() {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        });
    }

    pub(crate) fn require_parent_post_v1(&self) -> Result<(), JournalError> {
        self.require_complete_v1()?;
        if matches!(self.parent_binding, Some(Ok(()))) {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    pub(crate) fn parent_post_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        if !self.parent_attempted { return None; }
        self.parent_mount.failure().or_else(|| cause(&self.parent_mount_result))
            .or_else(|| self.parent_names.failure().map(|error| error as _))
            .or_else(|| cause(&self.parent_binding))
    }

    pub(crate) fn journal_v1(&self) -> Result<&Journal, JournalError> {
        self.require_complete_v1()?;
        self.journal.as_ref().ok_or(JournalError::ProtectedBoundary)
    }

    pub(crate) fn journal_mut_v1(&mut self) -> Result<&mut Journal, JournalError> {
        self.require_complete_v1()?;
        self.journal.as_mut().ok_or(JournalError::ProtectedBoundary)
    }

    pub(crate) fn raw_state_v1(&self) -> Result<&State, JournalError> {
        Ok(self.journal_v1()?.native.state())
    }

    pub(crate) fn namespaces_v1(&self) -> Result<&BTreeSet<RecordNamespace>, JournalError> {
        Ok(self.journal_v1()?.native.read_view().committed_namespaces())
    }

    pub(crate) fn report_v1(&self) -> Result<RecoveryReport, JournalError> {
        self.require_complete_v1()?;
        Ok(self.inputs.as_ref().ok_or(JournalError::ProtectedBoundary)?.report)
    }

    pub(crate) fn require_complete_v1(&self) -> Result<(), JournalError> {
        if self.reentered || !matches!(self.result, Some(Ok(()))) || self.journal.is_none()
            || (self.parent_attempted && !matches!(self.parent_binding, Some(Ok(())))) {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.inputs.as_ref().and_then(|inputs| inputs.opening.as_ref())
            .and_then(|opening| opening.acquisition_failure_v1())
            .or_else(|| self.conversion.failure())
            .or_else(|| cause(&self.result))
            .or_else(|| self.parent_post_failure_v1())
            .or_else(|| self.reentered.then_some(&MODEL_CLOSED as &(dyn Error + 'static)))
    }
}

fn cause<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref()?.as_ref().err().map(|error| error as _)
}

const MODEL_CLOSED: JournalError = JournalError::ProtectedBoundary;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::JournalLimits;

    #[test]
    fn an_unentered_reader_cannot_materialize_a_journal_and_retains_first_refusal() {
        let mut reader = RootFixedNativeReadOriginalsV1::controller_current_v1();
        let mut model = RootReadonlyJournalModelOriginalsV1::new();

        model.adopt_once(&mut reader);
        let original = model.failure().unwrap() as *const dyn Error;

        assert!(model.journal_v1().is_err());
        assert!(model.inputs.is_none());
        assert!(model.journal.is_none());
        model.adopt_once(&mut reader);
        assert!(std::ptr::eq(original, model.failure().unwrap() as *const dyn Error));
        assert!(model.journal_v1().is_err());
    }

    #[test]
    fn saved_challenge_refusal_preserves_acquisition_and_owed_names_after_mount_failure() {
        use std::fs::{OpenOptions, Permissions};
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
        use std::sync::Arc;
        use aos_sandbox_ledger_replay::replay::challenge::SourceChallengeReplayWitnessDataV5;

        let executable = std::env::current_exe().unwrap();
        let directory = tempfile::Builder::new().prefix("readonly-model-refusal-")
            .tempdir_in(executable.parent().unwrap()).unwrap();
        std::fs::set_permissions(directory.path(), Permissions::from_mode(0o700)).unwrap();
        for name in ["history", "history.lock"] {
            OpenOptions::new().write(true).create_new(true).mode(0o600)
                .open(directory.path().join(name)).unwrap();
        }
        let uid = rustix::process::geteuid().as_raw();
        let mut opening = Opening::new();
        opening.prepare_rooted_once_v1(directory.path(), "history", JournalLimits::default(), uid).unwrap();
        let (root, file, lock) = opening.identities_data_v1().unwrap();
        let witness = ReadOnlyJournalNameWitness::from_original_parts((directory.path().to_path_buf(),
            "history".to_owned(), uid, root, file, lock));
        let identity = Arc::new(());
        // A saved challenge is DATA tied to its original identity. The actual
        // converter must refuse it before allocating any new Journal identity.
        let original_replay = aos_sandbox_ledger_replay::replay::source_original::cache::SourceOriginalReplayDataV5 {
            challenges: Some(SourceChallengeReplayWitnessDataV5::retain_rows(
                &Vec::new(), 0, &identity, 1).unwrap()),
            ..Default::default()
        };
        let mut model = RootReadonlyJournalModelOriginalsV1::new();
        // This negative-only fixture supplies no completed Root reader or
        // purpose. It exercises conversion and owed observation, never adopt.
        model.inputs = Some(RootReadonlyJournalModelInputsV1 {
            root: "/", name: "history", view: RootReadonlyViewV1::Controller,
            original_uid: uid, witness: Some(witness),
            report: RecoveryReport::default(), opening: Some(opening),
            remainder: Some(ColdReplayRemainderDataV1 {
                challenge_history: Vec::new(), original_replay,
                history_compacted: false, q04_lower_history_present: false,
            }),
        });

        assert!(model.convert_remainder_once_v1().is_err());
        model.finish_parent_post_once_v1();

        assert!(!model.conversion.ready());
        assert!(model.semantic.is_none());
        assert!(model.native.is_none());
        assert!(model.journal.is_none());
        assert!(model.inputs.as_ref().unwrap().opening.as_ref().unwrap().observe_metadata_v1().is_ok());
        assert!(model.parent_mount_result.as_ref().unwrap().is_err());
        assert!(model.parent_names.is_complete());
        assert!(model.require_parent_post_v1().is_err());
    }
}
