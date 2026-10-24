//! Retains the same completed Root readonly opening and semantic remainder.
//!
//! Only the sibling fixed reader can transfer its actual native graph here.
//! Conversion refuses saved challenge authority before allocating the late
//! identity. The containing purpose still owns its financial, clock and peer
//! checks, and separately completes this owner's independent parent posts.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs::{File, Metadata};
use std::io;
use std::mem::size_of;

use aos_sandbox_broker::canonical_journal::{
    CanonicalJournalInstanceDataV1,
    CanonicalOrdinaryHeldJournalV1, CanonicalOrdinaryReadonlyOpeningV1, RecoveryReport,
};
use aos_sandbox_broker::canonical_journal::coordinator::{CanonicalProtectedReadViewV1, CanonicalWriterReadViewV1};
use aos_sandbox_model::{RecordNamespace, ResourceDimension as D, ResourceVector};
use aos_sandbox_journal::protected_storage::{
    ReadOnlyJournalNameWitness, ReadOnlyJournalNamesOriginalsV1, ReadonlyNameArchiveV1,
};
use aos_sandbox_ledger_replay::cold::ColdReplayRemainderDataV1;
use aos_sandbox_linux::signer_mount::{
    RootReadonlyViewV1, SignerMountReadbackAttemptV1, SignerMountReadbackClosedV1,
};
use aos_sandbox_protocol::domain_ledger::readonly::HistoricalLedgerRowsDataV2;

use super::{RootFixedNativeReadOriginalsV1, RootFixedNativeTargetV1};
use super::error::RootReadonlyErrorV1 as ReadError;

type State = BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;
type Opening = CanonicalOrdinaryReadonlyOpeningV1<ReadError>;
type Held = CanonicalOrdinaryHeldJournalV1<RootFixedNativeTargetV1, ReadonlyInstanceV1>;

// This nominal payload belongs to the actual late allocation. It cannot be
// constructed outside this module or rebound from a historical DATA view.
struct ReadonlyInstanceV1;

pub(super) struct RootReadonlyModelInputsV1 {
    pub(super) target: RootFixedNativeTargetV1,
    pub(super) view: RootReadonlyViewV1,
    pub(super) original_uid: u32,
    pub(super) witness: Option<ReadOnlyJournalNameWitness>,
    pub(super) report: RecoveryReport,
    pub(super) opening: Option<Opening>,
    pub(super) remainder: Option<ColdReplayRemainderDataV1>,
    pub(super) current_names: Option<ReadonlyNameArchiveV1<ReadError>>,
}

/// Retains the actual fixed readonly opening, semantic model and owed posts.
///
/// Only native fixed-reader code constructs and adopts this owner. Its public
/// methods lend diagnostic comparison data from that same held model; supplied
/// historical rows cannot construct a completed owner or native mutation grant.
pub struct RootReadonlyModelOriginalsV1 {
    inputs: Option<RootReadonlyModelInputsV1>,
    remainder: Option<ColdReplayRemainderDataV1>,
    native: Option<(Held, RecoveryReport)>,
    result: Option<Result<(), ReadError>>,
    reentered: bool,
    initial_names: Option<Result<(), u8>>,
    initial_names_attempted: bool,
    after_names: Option<Result<(), u8>>,
    after_names_attempted: bool,
    current_name_failure: Option<ReadError>,
    parent_mount: SignerMountReadbackAttemptV1,
    parent_mount_result: Option<Result<(), SignerMountReadbackClosedV1>>,
    parent_names: ReadOnlyJournalNamesOriginalsV1<ReadError>,
    parent_binding: Option<Result<(), ReadError>>,
    parent_attempted: bool,
}

impl RootReadonlyModelOriginalsV1 {
    pub(crate) fn new() -> Self {
        Self {
            inputs: None,
            remainder: None,
            native: None,
            result: None,
            reentered: false,
            initial_names: None,
            initial_names_attempted: false,
            after_names: None,
            after_names_attempted: false,
            current_name_failure: None,
            parent_mount: SignerMountReadbackAttemptV1::new(),
            parent_mount_result: None,
            parent_names: ReadOnlyJournalNamesOriginalsV1::new(),
            parent_binding: None,
            parent_attempted: false,
        }
    }

    pub(super) fn native_opening_receiving_bytes_v1() -> Option<usize> {
        Opening::receiving_construction_bytes_v1::<RootFixedNativeTargetV1, ReadonlyInstanceV1>()
    }

    // These are concrete transient query frames, not another model or map.
    // Protected includes healthy and both held/complete calls; the independent
    // historical-row path includes its actual borrowed view and DATA return.
    // Other accessors have shallower call graphs but distinct typed results.
    fn query_receiving_bytes_v1() -> Option<usize> {
        let protected = size_of::<&Self>().checked_mul(6)?
            .checked_add(size_of::<Result<&Held, ReadError>>().checked_mul(6)?)?
            .checked_add(size_of::<CanonicalWriterReadViewV1<'_, RootFixedNativeTargetV1>>().checked_mul(4)?)?
            .checked_add(size_of::<Result<(), ReadError>>().checked_mul(12)?)?;
        let historical = size_of::<&Self>().checked_mul(3)?
            .checked_add(size_of::<Result<&Held, ReadError>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<(), ReadError>>().checked_mul(3)?)?
            .checked_add(size_of::<CanonicalWriterReadViewV1<'_, RootFixedNativeTargetV1>>().checked_mul(2)?)?
            .checked_add(size_of::<HistoricalLedgerRowsDataV2<'_>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<HistoricalLedgerRowsDataV2<'_>, ReadError>>().checked_mul(3)?)?
            // Constructor arguments borrow the same maps; no backing moves.
            .checked_add(size_of::<&State>().checked_mul(2)?)?
            .checked_add(size_of::<&BTreeMap<Vec<u8>, aos_sandbox_protocol::domain_ledger::readonly::IdempotencyDecisionV1>>().checked_mul(2)?)?;
        protected.max(historical)
            .checked_add(size_of::<bool>().checked_mul(4)?)?
            .checked_add(size_of::<Result<&State, ReadError>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<&BTreeSet<RecordNamespace>, ReadError>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<RecoveryReport, ReadError>>().checked_mul(3)?)?
            // The sequence getter shares the shallower held/complete/view
            // query chain above but has its own concrete result interface.
            .checked_add(size_of::<Result<u64, ReadError>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<&ColdReplayRemainderDataV1, ReadError>>().checked_mul(3)?)?
            .checked_add(size_of::<Option<usize>>().checked_mul(2)?)
    }

    // The shared adoption frame now receives the genuine factory's owning
    // Result. These transfer planes apply to both Common and Current; they do
    // not duplicate the maps or admit caller-supplied inputs.
    fn adoption_control_bytes_v1() -> Option<usize> {
        size_of::<Result<RootReadonlyModelInputsV1, ReadError>>()
            .checked_mul(3)?
            .checked_add(size_of::<&mut Self>().checked_mul(2)?)?
            .checked_add(size_of::<&mut RootFixedNativeReadOriginalsV1>().checked_mul(2)?)?
            .checked_add(size_of::<Result<(), ReadError>>().checked_mul(2)?)?
            .checked_add(size_of::<bool>().checked_mul(2)?)?
            // The new receiving quote closure borrows its actual target.
            .checked_add(size_of::<&&RootFixedNativeReadOriginalsV1>().checked_mul(3)?)?
            .checked_add(size_of::<Option<usize>>().checked_mul(2)?)
    }

    // Current's names and metadata remain owed on the actual Held or failed
    // Opening. This bounds both reached alternatives conservatively; it adds
    // no second archive, native files, namespace entries or model owner.
    fn current_post_control_bytes_v1() -> Option<usize> {
        type Names = ReadonlyNameArchiveV1<ReadError>;

        let arguments = size_of::<&mut Self>().checked_mul(4)?
            .checked_add(size_of::<&Self>().checked_mul(6)?)?
            .checked_add(size_of::<&mut RootFixedNativeReadOriginalsV1>().checked_mul(2)?)?
            .checked_add(size_of::<(&Held, &Names, &ReadOnlyJournalNameWitness)>()
                .checked_mul(2)?)?
            .checked_add(size_of::<(&Opening, &Names, &ReadOnlyJournalNameWitness)>()
                .checked_mul(2)?)?
            .checked_add(size_of::<(&Names, u8)>().checked_mul(2)?)?
            .checked_add(size_of::<&Opening>().checked_mul(2)?)?
            .checked_add(size_of::<&Held>().checked_mul(2)?)?;

        let names = size_of::<Option<Result<(), u8>>>().checked_mul(6)?
            .checked_add(size_of::<Result<(), u8>>().checked_mul(8)?)?
            .checked_add(size_of::<Option<&RootReadonlyModelInputsV1>>().checked_mul(4)?)?
            .checked_add(size_of::<Option<&Names>>().checked_mul(4)?)?
            .checked_add(size_of::<Option<&ReadOnlyJournalNameWitness>>().checked_mul(4)?)?
            .checked_add(size_of::<Option<&Opening>>().checked_mul(4)?)?
            .checked_add(size_of::<ReadError>().checked_mul(2)?)?;

        let metadata = size_of::<Option<io::Result<Metadata>>>().checked_mul(2)?
            .checked_add(size_of::<io::Result<Metadata>>().checked_mul(4)?)?
            .checked_add(size_of::<CanonicalWriterReadViewV1<'_, RootFixedNativeTargetV1>>()
                .checked_mul(2)?)?
            .checked_add(size_of::<bool>().checked_mul(2)?)?;

        let failures = size_of::<Option<&ReadError>>().checked_mul(4)?
            .checked_add(size_of::<Option<&(dyn Error + 'static)>>().checked_mul(4)?)?
            .checked_add(size_of::<u8>().checked_mul(2)?)?
            .checked_add(size_of::<Option<usize>>().checked_mul(2)?)?;

        // These are separate closure environments, not the native observer or
        // failure_at arguments above. Each borrowed capture is constructed,
        // retained at its call site and transferred into FnOnce.
        let closures = size_of::<&&Opening>().checked_mul(3)?
            .checked_add(size_of::<&&u8>().checked_mul(3)?)?;
        arguments.checked_add(names)?.checked_add(metadata)?
            .checked_add(failures)?.checked_add(closures)
    }

    // These are the new Controller guard's actual entry/return, same-held
    // view, protected-name Option/map and quote-selector planes. The enclosing
    // protected/held query graph keeps its existing complete bound above.
    fn controller_query_control_bytes_v1() -> Option<usize> {
        size_of::<&Self>().checked_mul(3)?
            .checked_add(size_of::<Result<(), ReadError>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<&Held, ReadError>>().checked_mul(3)?)?
            .checked_add(size_of::<CanonicalWriterReadViewV1<'_, RootFixedNativeTargetV1>>()
                .checked_mul(3)?)?
            .checked_add(size_of::<Option<CanonicalProtectedReadViewV1<'_, RootFixedNativeTargetV1>>>()
                .checked_mul(3)?)?
            .checked_add(size_of::<CanonicalProtectedReadViewV1<'_, RootFixedNativeTargetV1>>()
                .checked_mul(3)?)?
            .checked_add(size_of::<&str>().checked_mul(3)?)?
            .checked_add(size_of::<Option<&str>>().checked_mul(3)?)?
            // The NoApply CPU snapshot reads both diagnostic flags from
            // this same Held; no healthy gate may hide the poisoned flag.
            .checked_add(size_of::<&Self>().checked_mul(3)?)?
            .checked_add(size_of::<Result<&Held, ReadError>>().checked_mul(3)?)?
            .checked_add(size_of::<CanonicalWriterReadViewV1<'_, RootFixedNativeTargetV1>>()
                .checked_mul(3)?)?
            .checked_add(size_of::<(bool, bool)>().checked_mul(3)?)?
            .checked_add(size_of::<Result<(bool, bool), ReadError>>().checked_mul(3)?)?
            .checked_add(size_of::<Option<usize>>().checked_mul(3)?)?
            .checked_add(size_of::<bool>().checked_mul(3)?)?
            // The new receiving selector borrows the actual reader. The
            // runtime name-map closure captures nothing; its view argument
            // and returned borrowed name are explicitly included above.
            .checked_add(size_of::<&&RootFixedNativeReadOriginalsV1>().checked_mul(3)?)
    }

    pub(crate) fn receiving_demand_v1(
        actual: &RootFixedNativeReadOriginalsV1,
    ) -> Result<ResourceVector, ReadError> {
        let (path_bytes, parent_files) = actual.captured_model_post_geometry_v1()?;
        let mount_bytes = SignerMountReadbackAttemptV1::receiving_memory_bound_v1()
            .ok_or(ReadError::JournalTooLarge)?;
        // The maps, index and readonly descriptors move once. These are the
        // actual retained/working owners and late Arc, not a Domain Journal
        // header or a fictitious successful model-return carrier.
        let bytes = size_of::<Self>()
            .checked_mul(2)
            .and_then(|n| n.checked_add(size_of::<RootReadonlyModelInputsV1>().checked_mul(2)?))
            .and_then(|n| n.checked_add(size_of::<Result<(), ReadError>>()))
            .and_then(|n| n.checked_add(Self::query_receiving_bytes_v1()?))
            .and_then(|n| n.checked_add(Self::adoption_control_bytes_v1()?))
            .and_then(|n| {
                if matches!(actual.target, RootFixedNativeTargetV1::ControllerCurrent) {
                    n.checked_add(Self::controller_query_control_bytes_v1()?)
                } else {
                    Some(n)
                }
            })
            .and_then(|n| {
                if actual.current_io.is_some() {
                    n.checked_add(Self::current_post_control_bytes_v1()?)
                } else {
                    Some(n)
                }
            })
            .and_then(|n| {
                n.checked_add(CanonicalJournalInstanceDataV1::<ReadonlyInstanceV1>::
                    payload_allocation_receiving_bytes_v1()?)
            })
            .and_then(|n| n.checked_add(path_bytes.checked_mul(4)?))
            .and_then(|n| n.checked_add(mount_bytes))
            .and_then(|n| n.checked_add(parent_files.checked_mul(4096)?))
            .and_then(|n| n.checked_add(parent_files.checked_mul(3 * size_of::<File>())?))
            .and_then(|n| u64::try_from(n).ok())
            .ok_or(ReadError::JournalTooLarge)?;
        let files = parent_files.checked_add(1)
            .and_then(|n| u64::try_from(n).ok()).ok_or(ReadError::JournalTooLarge)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes)
            .with(D::OpenFiles, files).with(D::MetadataEntries, files))
    }

    pub(crate) fn adopt_once(&mut self, actual: &mut RootFixedNativeReadOriginalsV1) {
        if self.result.is_some() {
            self.reentered = true;
            return;
        }
        let inputs = actual.take_completed_model_inputs_v1();
        self.result = Some(self.adopt_inner(inputs));
    }

    pub(super) fn adopt_current_once(&mut self, actual: &mut RootFixedNativeReadOriginalsV1) {
        if self.result.is_some() {
            self.reentered = true;
            return;
        }

        let inputs = actual.take_current_model_inputs_once_v1();
        self.result = Some(self.adopt_inner(inputs));
    }

    // Both private factories transfer the same opening and remainder. Current
    // reaches this frontier before its independent late native posts.
    fn adopt_inner(&mut self, inputs: Result<RootReadonlyModelInputsV1, ReadError>)
        -> Result<(), ReadError>
    {
        self.inputs = Some(inputs?);
        let inputs = self.inputs.as_mut().ok_or(ReadError::ProtectedBoundary)?;
        self.remainder = inputs.remainder.take();
        let remainder = self.remainder.as_ref().ok_or(ReadError::ProtectedBoundary)?;
        if remainder.original_replay.challenges.is_some() {
            return Err(ReadError::ProtectedBoundary);
        }

        let opening = inputs.opening.as_mut().ok_or(ReadError::ProtectedBoundary)?;
        self.native = opening.take_held_with_late_payload_once_v1(
            inputs.target, ReadonlyInstanceV1,
        );
        let (_, report) = self.native.as_ref().ok_or(ReadError::ProtectedBoundary)?;
        if (report.committed_transactions, report.committed_records, report.truncated_bytes)
            != (inputs.report.committed_transactions, inputs.report.committed_records,
                inputs.report.truncated_bytes)
        {
            return Err(ReadError::ProtectedBoundary);
        }
        Ok(())
    }

    // These observations remain owed after failed conversion or poisoned
    // model state. They use the very same archive and remaining native file.
    fn observe_current_names_v1(&self) -> Option<Result<(), u8>> {
        let inputs = self.inputs.as_ref()?;
        let archive = inputs.current_names.as_ref()?;
        let witness = inputs.witness.as_ref()?;
        if let Some((held, _)) = &self.native {
            Some(held.observe_readonly_archive_v1(archive, witness))
        } else {
            Some(inputs.opening.as_ref()?.observe_archived_names_v1(archive, witness))
        }
    }

    pub(super) fn observe_initial_current_names_once_v1(&mut self) {
        if self.initial_names_attempted {
            self.reentered = true;
            return;
        }
        self.initial_names_attempted = true;

        self.initial_names = self.observe_current_names_v1();
        if let Some(Err(index)) = self.initial_names {
            if self.current_name_failure.is_none() {
                self.current_name_failure = Some(ReadError::ReadOnlyNameReceivingFailure(index));
            }
        }
    }

    pub(super) fn observe_current_names_after_once_v1(&mut self) {
        if self.after_names_attempted {
            self.reentered = true;
            return;
        }
        self.after_names_attempted = true;

        self.after_names = self.observe_current_names_v1();
        if let Some(Err(index)) = self.after_names {
            if self.current_name_failure.is_none() {
                self.current_name_failure = Some(ReadError::ReadOnlyNameReceivingFailure(index));
            }
        }
    }

    pub(super) fn observe_current_file_metadata_v1(&self) -> Option<io::Result<Metadata>> {
        if let Some((held, _)) = &self.native {
            Some(held.read_view_v1().metadata())
        } else {
            let opening = self.inputs.as_ref()?.opening.as_ref()?;
            opening.has_native_file_data_v1().then(|| opening.observe_metadata_v1())
        }
    }

    fn current_name_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        let failure = self.current_name_failure.as_ref()?;
        let ReadError::ReadOnlyNameReceivingFailure(index) = failure else {
            return Some(failure);
        };
        self.inputs.as_ref().and_then(|inputs| inputs.current_names.as_ref())
            .and_then(|archive| archive.failure_at(*index))
            .map(|cause| cause as &(dyn Error + 'static))
            .or(Some(failure))
    }

    // This is owed after the containing purpose's model work. Mount refusal
    // never suppresses names on the same remaining held/opening description.
    pub(crate) fn finish_parent_post_once_v1(&mut self) {
        if self.parent_attempted {
            self.reentered = true;
            return;
        }
        self.parent_attempted = true;
        let Some(inputs) = &self.inputs else {
            self.parent_binding = Some(Err(ReadError::ProtectedBoundary));
            return;
        };
        let root = inputs.witness.as_ref().map(|witness| witness.physical_pairs().0);
        self.parent_mount_result = Some(self.parent_mount.observe_root_readonly_once(
            inputs.view, inputs.original_uid, rustix::process::getegid().as_raw(), root,
        ));
        if let Some(witness) = &inputs.witness {
            if let Some((held, _)) = &self.native {
                held.capture_readonly_names_once_v1(&self.parent_names, witness);
            } else if let Some(opening) = &inputs.opening {
                opening.capture_readonly_names_once_v1(&self.parent_names, witness);
            }
        }
        self.parent_binding = Some(
            if matches!(self.parent_mount_result, Some(Ok(()))) && self.parent_names.is_complete() {
                Ok(())
            } else {
                Err(ReadError::ProtectedBoundary)
            },
        );
    }

    /// Requires this owner's completed adoption and all reached Current name checks.
    ///
    /// # Errors
    /// Returns a boundary refusal for incomplete, reentered or refused adoption.
    pub fn require_complete_v1(&self) -> Result<(), ReadError> {
        if self.reentered || !matches!(self.result, Some(Ok(()))) || self.native.is_none()
            || (self.parent_attempted && !matches!(self.parent_binding, Some(Ok(()))))
            || (self.inputs.as_ref().is_some_and(|inputs| inputs.current_names.is_some())
                && (!matches!(self.initial_names, Some(Ok(())))
                    || (self.after_names_attempted && !matches!(self.after_names, Some(Ok(()))))))
        {
            return Err(ReadError::ProtectedBoundary);
        }
        Ok(())
    }

    /// Requires the independently owed parent post on this same held model.
    ///
    /// # Errors
    /// Returns a boundary refusal when adoption or the owed parent post refused.
    pub fn require_parent_post_v1(&self) -> Result<(), ReadError> {
        self.require_complete_v1()?;
        if matches!(self.parent_binding, Some(Ok(()))) {
            Ok(())
        } else {
            Err(ReadError::ProtectedBoundary)
        }
    }

    fn held(&self) -> Result<&Held, ReadError> {
        self.require_complete_v1()?;
        self.native.as_ref().map(|(held, _)| held).ok_or(ReadError::ProtectedBoundary)
    }

    /// Checks the actual held journal's poison state.
    ///
    /// # Errors
    /// Returns an incomplete-model refusal or the original poisoned-journal class.
    pub fn require_healthy_v1(&self) -> Result<(), ReadError> {
        if self.held()?.read_view_v1().is_poisoned() {
            Err(ReadError::Poisoned)
        } else {
            Ok(())
        }
    }

    /// Checks health and the actual held journal's protected acquisition.
    ///
    /// # Errors
    /// Returns the reached health failure or a protected-boundary refusal.
    pub fn require_protected_v1(&self) -> Result<(), ReadError> {
        self.require_healthy_v1()?;
        if self.held()?.read_view_v1().is_protected() {
            Ok(())
        } else {
            Err(ReadError::ProtectedBoundary)
        }
    }

    /// Checks protection and the actual held Controller journal basename.
    ///
    /// # Errors
    /// Returns the reached health/protection failure or a boundary refusal when
    /// the actual protected basename differs from the fixed Controller name.
    pub fn require_controller_v1(&self) -> Result<(), ReadError> {
        self.require_protected_v1()?;
        if self.held()?.read_view_v1().protected_view().map(|location| location.name())
            != Some("controller.journal")
        {
            return Err(ReadError::ProtectedBoundary);
        }
        Ok(())
    }

    // This is the old readonly native-cut equality, on the SAME late Held.
    // It reads cached witness names and the actual coordinator view; there is
    // no named recheck, metadata syscall or DATA-to-model adoption here.
    pub(crate) fn require_current_controller_native_cut_v1(
        &self,
        audit: &super::audit::RootControllerReadonlyGeometryAuditV1,
        names: aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1,
        next: u64,
        end: u64,
    ) -> Result<(), ReadError> {
        self.require_healthy_v1()?;
        let extent = audit.captured_extent_v1().ok_or(ReadError::ProtectedBoundary)?;
        let native = audit.native_data_v1().ok_or(ReadError::ProtectedBoundary)?;
        let witness = self.inputs.as_ref().and_then(|inputs| inputs.witness.as_ref())
            .ok_or(ReadError::ProtectedBoundary)?;
        let (directory, journal, lock) = witness.physical_pairs();
        let actual_names = aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1::from_historical_fields(
            directory, journal, lock,
        );
        let view = self.held()?.read_view_v1();
        if actual_names != names
            || view.next_sequence() != next
            || extent.native_bytes != end
            || !native.matches_coordinator_view_v1(view)
        {
            return Err(ReadError::ProtectedBoundary);
        }
        Ok(())
    }

    // This is the old primary-only failure view. A late archived-name failure
    // remains owed and retained, but cannot hide an earlier purpose body cause.
    pub(crate) fn current_primary_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.inputs.as_ref().and_then(|inputs| inputs.opening.as_ref())
            .and_then(|opening| opening.acquisition_failure_v1())
            .or_else(|| cause(&self.result))
            .or_else(|| if matches!(self.initial_names, Some(Err(_))) {
                self.current_name_failure_v1()
            } else {
                None
            })
            .or_else(|| self.reentered.then_some(&MODEL_CLOSED as &(dyn Error + 'static)))
    }

    // Only the actual Current purpose's semantic quote consumes these new
    // private query interfaces. Common model callers do not reach this method.
    pub(crate) fn current_controller_query_control_bytes_v1() -> Option<usize> {
        let arguments = size_of::<(
            &RootReadonlyModelOriginalsV1,
            &super::audit::RootControllerReadonlyGeometryAuditV1,
            aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1,
            u64,
            u64,
        )>().checked_mul(3)?;
        let returned = size_of::<Result<(), ReadError>>().checked_mul(3)?;
        let views = size_of::<CanonicalWriterReadViewV1<'_, RootFixedNativeTargetV1>>().checked_mul(3)?;
        let names = size_of::<aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1>().checked_mul(2)?;
        let witness = size_of::<(&ReadOnlyJournalNameWitness, ((u64, u64), (u64, u64), (u64, u64)))>().checked_mul(3)?;
        let scalar = size_of::<Option<usize>>().checked_mul(3)?;

        let failure_views = size_of::<&RootReadonlyModelOriginalsV1>().checked_mul(3)?
            .checked_add(size_of::<Option<&(dyn Error + 'static)>>().checked_mul(6)?)?
            .checked_add(size_of::<(
                &Option<Result<(), ReadError>>,
                &RootReadonlyModelOriginalsV1,
                &bool,
            )>().checked_mul(3)?)?;
        arguments.checked_add(returned)?.checked_add(views)?.checked_add(names)?
            .checked_add(witness)?.checked_add(scalar)?.checked_add(failure_views)
    }

    /// Returns poison and protection flags from this same held historical model.
    ///
    /// These diagnostic flags are comparison DATA, not a supplied completion or
    /// role proof. The query deliberately performs no health check before reading
    /// the poison flag; the actual containing purpose retains its own live gates.
    ///
    /// # Errors
    /// Returns a boundary refusal when this same model is incomplete or refused.
    pub fn historical_status_data_v2(&self) -> Result<(bool, bool), ReadError> {
        let view = self.held()?.read_view_v1();
        Ok((view.is_poisoned(), view.is_protected()))
    }

    /// Borrows the materialized state retained by this actual completed model.
    ///
    /// # Errors
    /// Returns a boundary refusal when the same model is incomplete or refused.
    pub fn raw_state_v1(&self) -> Result<&State, ReadError> {
        Ok(self.held()?.read_view_v1().state())
    }

    /// Borrows historical rows and idempotency data from the same held index.
    ///
    /// # Errors
    /// Returns a boundary refusal when the same model is incomplete or refused.
    pub fn historical_rows_data_v2(&self)
        -> Result<HistoricalLedgerRowsDataV2<'_>, ReadError>
    {
        let view = self.held()?.read_view_v1();
        Ok(HistoricalLedgerRowsDataV2::new(view.state(), view.idempotency_index()))
    }

    /// Borrows committed namespaces from this same completed model.
    ///
    /// # Errors
    /// Returns a boundary refusal when the same model is incomplete or refused.
    pub fn namespaces_v1(&self) -> Result<&BTreeSet<RecordNamespace>, ReadError> {
        Ok(self.held()?.read_view_v1().committed_namespaces())
    }

    /// Returns the recovery report captured by this owner's genuine reader.
    ///
    /// # Errors
    /// Returns a boundary refusal when adoption or its retained input is absent.
    pub fn report_v1(&self) -> Result<RecoveryReport, ReadError> {
        self.require_complete_v1()?;
        Ok(self.inputs.as_ref().ok_or(ReadError::ProtectedBoundary)?.report)
    }

    /// Returns the same completed held journal's next native sequence as DATA.
    ///
    /// # Errors
    /// Refuses an incomplete model or a failed independently attempted post.
    /// Returns the durable next sequence from this same held journal.
    ///
    /// # Errors
    /// Returns a boundary refusal when the same model is incomplete or refused.
    pub fn next_sequence_v1(&self) -> Result<u64, ReadError> {
        Ok(self.held()?.read_view_v1().next_sequence())
    }

    /// Borrows the full semantic remainder retained from this owner's replay.
    ///
    /// # Errors
    /// Returns a boundary refusal when adoption or the remainder is absent.
    pub fn semantic_remainder_v1(&self) -> Result<&ColdReplayRemainderDataV1, ReadError> {
        self.require_complete_v1()?;
        self.remainder.as_ref().ok_or(ReadError::ProtectedBoundary)
    }

    /// Borrows the first actual reached parent-post failure, when present.
    pub fn parent_post_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        if !self.parent_attempted {
            return None;
        }
        self.parent_mount.failure().or_else(|| cause(&self.parent_mount_result))
            .or_else(|| self.parent_names.failure().map(|error| error as _))
            .or_else(|| cause(&self.parent_binding))
    }

    /// Borrows this owner's retained acquisition, adoption or post failure.
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.inputs.as_ref().and_then(|inputs| inputs.opening.as_ref())
            .and_then(|opening| opening.acquisition_failure_v1())
            .or_else(|| cause(&self.result))
            .or_else(|| self.current_name_failure_v1())
            .or_else(|| self.parent_post_failure_v1())
            .or_else(|| self.reentered.then_some(&MODEL_CLOSED as &(dyn Error + 'static)))
    }
}

fn cause<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref()?.as_ref().err().map(|error| error as _)
}

const MODEL_CLOSED: ReadError = ReadError::ProtectedBoundary;
