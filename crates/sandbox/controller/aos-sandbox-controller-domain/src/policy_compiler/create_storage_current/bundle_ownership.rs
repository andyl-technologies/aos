//! Verifies B's exact Ownership response using Root's own retained trust.
//!
//! This is one component of the later independent typed-B/current-cut verifier.
//! It grants no Use, Prepare, signing or release. Proposed Controller/MAC DATA
//! cannot supply Root's trust anchor, paired clock or receiving original.

use std::error::Error as StdError;
use std::mem::size_of;
use std::path::Path;

use aos_sandbox_model::{CanonicalAssignmentManifestV1, CanonicalCborError, DecodeLimits, RawPairedClockSample,
    ResourceDimension as D, ResourceVector};
use aos_sandbox_model::format::assignment_capture::CanonicalAssignmentDecodeCaptureV1;
use aos_sandbox_ownership_protocol::{OwnershipClaimError,
    OwnershipLeaseAcquisitionError, response_verification::{
        OwnershipClaimDecodeCaptureV1, OwnershipResponseVerifyCaptureV1}};
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    HistoryErrorV1,
    assignment_planned::AssignmentPlannedBodyDataV1,
    ready::ReadyBundleDataV1};

use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::journal::{JournalError, ProtectedJournalCurrentnessOriginalsV1};
use crate::normal_root::{NormalRootStartupErrorV1, RootPolicyAcceptedFlightV1};
use crate::policy_compiler::RetainedKernelPairedClockAttemptV1;
use super::{RootCreateStorageCurrentErrorV1 as Error,
    ownership_trust::RootCurrentOwnershipTrustStateV1, ready::RootCurrentReadyStateV1,
    root_open::{RootCurrentOpenStateV1, RootCurrentOpenReadbackV1},
    source_current::RootCurrentSourceExchangeStateV1};
use super::super::protected_owner::{PROTECTED_POLICY_ROOT, POLICY_AUTHORITY_JOURNAL, POLICY_STATE_JOURNAL};
use super::super::root_current_writers::RootCreateStorageCurrentWritersV1;
use aos_sandbox_policy::bundle_ownership_data::{
    planned_assignment_v1, ownership_bundle_typed_demand_v1,
};

type WriterResult = Option<Result<(), JournalError>>;

pub(crate) struct RootCurrentBundleOwnershipStateV1 {
    framing: Option<Result<(), HistoryErrorV1>>,
    geometry: Option<Result<ResourceVector, JournalError>>,
    typed: Option<Result<(), NormalRootStartupErrorV1>>,
    before: [ProtectedJournalCurrentnessOriginalsV1; 2],
    before_result: [WriterResult; 2],
    before_readback: Option<Result<RootCurrentOpenReadbackV1, JournalError>>,
    before_clock: RetainedKernelPairedClockAttemptV1,
    before_sample: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    before_cutoff: Option<Result<(), JournalError>>,
    assignment_framing: Option<Result<(), HistoryErrorV1>>,
    assignment: Option<Box<CanonicalAssignmentDecodeCaptureV1>>,
    assignment_decode: Option<Result<(), CanonicalCborError>>,
    claim: Option<Box<OwnershipClaimDecodeCaptureV1>>,
    claim_decode: Option<Result<(), OwnershipClaimError>>,
    association: Option<Result<(), HistoryErrorV1>>,
    response: Option<Box<OwnershipResponseVerifyCaptureV1>>,
    verification: Option<Result<(), OwnershipLeaseAcquisitionError>>,
    primary: Option<Result<(), Error>>,
    after: [ProtectedJournalCurrentnessOriginalsV1; 2],
    after_result: [WriterResult; 2],
    after_readback: Option<Result<RootCurrentOpenReadbackV1, JournalError>>,
    peer: Option<Result<(), NormalRootStartupErrorV1>>,
    after_clock: RetainedKernelPairedClockAttemptV1,
    after_sample: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    after_cutoff: Option<Result<(), JournalError>>,
    interval: Option<Result<(), aos_sandbox_model::OwnershipLeaseVerificationError>>,
    complete: bool,
    entered: bool,
    closed: Option<Error>,
}

impl RootCurrentBundleOwnershipStateV1 {
    pub(super) fn new() -> Self {
        Self {
            framing: None, geometry: None, typed: None,
            before: std::array::from_fn(|_| ProtectedJournalCurrentnessOriginalsV1::new()),
            before_result: [None, None], before_readback: None,
            before_clock: Default::default(), before_sample: None, before_cutoff: None,
            assignment_framing: None, assignment: None, assignment_decode: None,
            claim: None, claim_decode: None, association: None,
            response: None, verification: None, primary: None,
            after: std::array::from_fn(|_| ProtectedJournalCurrentnessOriginalsV1::new()),
            after_result: [None, None], after_readback: None, peer: None,
            after_clock: Default::default(), after_sample: None, after_cutoff: None,
            interval: None, complete: false, entered: false, closed: None,
        }
    }

    pub(crate) fn fixed_demand_v1() -> Result<ResourceVector, JournalError> {
        let invalid = || JournalError::JournalTooLarge;
        let mut demand = ResourceVector::ZERO;
        for name in [POLICY_AUTHORITY_JOURNAL, POLICY_STATE_JOURNAL] {
            let native = ProtectedJournalCurrentnessOriginalsV1::fixed_demand_v1(
                Path::new(PROTECTED_POLICY_ROOT), name)?;
            demand = demand.checked_add(native).and_then(|value| value.checked_add(native))
                .map_err(|_| invalid())?;
        }
        // Only fixed borrowed framing enters before typed admission. Actual
        // claim/response capsules are allocated after their own stage pays.
        let work = aos_sandbox_policy::bundle_ownership_data::fixed_prelude_work_receiving_bytes_v1()
            .ok_or_else(invalid)?;
        let pair = RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()
            .and_then(|bytes| bytes.checked_mul(2)).ok_or_else(invalid)?;
        let memory = size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(work))
            .and_then(|bytes| bytes.checked_add(pair))
            .and_then(|bytes| bytes.checked_add(2 * size_of::<usize>()))
            .and_then(|bytes| bytes.checked_add(aos_sandbox_policy::bundle_ownership_data::
                assignment_prelude_geometry_receiving_bytes_v1::<JournalError>()?)).ok_or_else(invalid)?;
        let interfaces = aos_sandbox_policy::bundle_ownership_data::
            fixed_interface_control_bytes_v1::<JournalError>().ok_or_else(invalid)?;
        let memory = memory.checked_add(interfaces).ok_or_else(invalid)?;
        let fixed = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(memory).map_err(|_| invalid())?)
            .with(D::OpenFiles, 2 * RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1 as u64);
        demand.checked_add(fixed).map_err(|_| invalid())
    }

    pub(crate) fn additional_typed_demand_v1(&self) -> Result<ResourceVector, JournalError> {
        self.geometry.as_ref().and_then(|value| value.as_ref().ok()).copied()
            .ok_or(JournalError::ProtectedBoundary)
    }

    pub(super) fn verify_once(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        writers: &mut RootCreateStorageCurrentWritersV1,
        root: &RootCurrentOpenStateV1,
        ready: &RootCurrentReadyStateV1,
        source: &RootCurrentSourceExchangeStateV1,
        trust: &RootCurrentOwnershipTrustStateV1,
    ) -> Result<(), Error> {
        if self.entered || self.closed.is_some() {
            self.closed.get_or_insert(Error::Original);
            return Err(Error::Original);
        }
        self.entered = true;
        self.primary = Some(self.verify_inner(flight, writers, root, ready, source, trust));
        // Framing, geometry and typed funding precede new native IO. Once
        // admitted, every reached primary refusal owes these independent posts.
        if matches!(self.typed, Some(Ok(()))) {
            observe_writers(writers, root, &mut self.after, &mut self.after_result,
                &mut self.after_readback);
            self.peer = Some(flight.recheck_current_controller_peer_once());
            self.after_sample = Some(self.after_clock.observe_once(None));
            self.after_cutoff = Some(require_clock(root, source, &self.after_sample));
            if let (Some(Ok(before)), Some(Ok(after))) = (&self.before_sample, &self.after_sample) {
                self.interval = Some(before.validate_later_sample(*after));
            }
        }
        self.complete = matches!(self.primary, Some(Ok(())))
            && self.after_result.iter().all(|value| matches!(value, Some(Ok(()))))
            && matches!(self.after_readback, Some(Ok(_))) && matches!(self.peer, Some(Ok(())))
            && matches!(self.after_cutoff, Some(Ok(()))) && matches!(self.interval, Some(Ok(())))
            && self.failure_with_original(flight).is_none();
        if self.complete { Ok(()) } else { Err(Error::History) }
    }

    fn verify_inner(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        writers: &mut RootCreateStorageCurrentWritersV1,
        root: &RootCurrentOpenStateV1,
        ready: &RootCurrentReadyStateV1,
        source: &RootCurrentSourceExchangeStateV1,
        trust: &RootCurrentOwnershipTrustStateV1,
    ) -> Result<(), Error> {
        let raw = ready.raw_ready_bytes()?;
        // This SAME immutable Ready passed complete historical framing in the
        // completed Source query. Only its field parser needs repeating here.
        source.require_complete_v1()?;
        let bundle = match ReadyBundleDataV1::borrow_field_framing_data_v1(raw) {
            Ok(value) => { self.framing = Some(Ok(())); value }
            Err(cause) => { self.framing = Some(Err(cause)); return Err(Error::History); }
        };
        let planned = match planned_assignment_v1(bundle) {
            Ok(value) => { self.assignment_framing = Some(Ok(())); value }
            Err(cause) => { self.assignment_framing = Some(Err(cause)); return Err(Error::History); }
        };
        self.geometry = Some(typed_demand(bundle, planned.manifest.len(), trust));
        positive(&self.geometry)?;
        self.typed = Some(flight.current_cut_startup().map_err(|_| Error::Original)?
            .prepay_create_storage_bundle_ownership_typed_once(root, self));
        positive(&self.typed)?;
        self.assignment = Some(Box::new(CanonicalAssignmentDecodeCaptureV1::new()));
        self.claim = Some(Box::new(OwnershipClaimDecodeCaptureV1::new()));
        self.response = Some(Box::new(OwnershipResponseVerifyCaptureV1::new()));

        observe_writers(writers, root, &mut self.before, &mut self.before_result,
            &mut self.before_readback);
        for result in &self.before_result { positive(result)?; }
        positive(&self.before_readback)?;
        self.before_sample = Some(self.before_clock.observe_once(None));
        self.before_cutoff = Some(require_clock(root, source, &self.before_sample));
        positive(&self.before_cutoff)?;
        self.assignment_decode = Some(self.assignment.as_mut().ok_or(Error::History)?
            .decode_once_v1(planned.manifest, DecodeLimits::default()));
        positive(&self.assignment_decode)?;
        let capture = self.claim.as_mut().ok_or(Error::History)?;
        self.claim_decode = Some(capture.decode_once_v1(bundle.ownership_claim));
        positive(&self.claim_decode)?;
        let claim = self.claim.as_ref().and_then(|capture| capture.value()).ok_or(Error::History)?;
        let manifest = self.assignment.as_ref().and_then(|capture| capture.value())
            .ok_or(Error::History)?;
        self.association = Some(require_claim_association(bundle, planned, manifest, claim, source, root));
        positive(&self.association)?;
        let verifier = trust.verifier_v1()?;
        let clock = positive(&self.before_sample)?;
        self.verification = Some(verifier.verify_response_bytes_retaining_v1(
            claim, bundle.ownership_lease, bundle.ownership_signature,
            bundle.ownership_receipt, bundle.ownership_receipt_signature, clock,
            self.response.as_mut().ok_or(Error::History)?,
        ));
        positive(&self.verification).map(|_| ())
    }

    pub(crate) fn require_complete_v1(&self) -> Result<(), Error> {
        if !self.complete || self.closed.is_some()
            || self.response.as_ref().and_then(|capture| capture.value()).is_none()
            || self.assignment.as_ref().and_then(|capture| capture.value()).is_none()
        {
            return Err(Error::History);
        }
        Ok(())
    }

    pub(super) fn completed_manifest_v1(&self) -> Result<&CanonicalAssignmentManifestV1, Error> {
        self.require_complete_v1()?;
        self.assignment.as_ref().and_then(|capture| capture.value()).ok_or(Error::History)
    }

    pub(super) fn completed_response_v1(&self) -> Result<&OwnershipResponseVerifyCaptureV1, Error> {
        self.require_complete_v1()?;
        self.response.as_deref().ok_or(Error::History)
    }

    pub(super) fn failure_with_original<'a>(
        &'a self,
        flight: &'a RootPolicyAcceptedFlightV1<'_, '_>,
    ) -> Option<&'a (dyn StdError + 'static)> {
        cause(&self.framing).or_else(|| cause(&self.assignment_framing))
            .or_else(|| cause(&self.geometry))
            .or_else(|| self.typed.as_ref().and_then(|result| result.as_ref().err())
                .and_then(|marker| flight.failure().or(Some(marker as _))))
            .or_else(|| self.before.iter().find_map(|original| original.failure()))
            .or_else(|| self.before_result.iter().find_map(cause))
            .or_else(|| cause(&self.before_readback)).or_else(|| self.before_clock.failure())
            .or_else(|| cause(&self.before_sample)).or_else(|| cause(&self.before_cutoff))
            .or_else(|| self.assignment.as_ref().and_then(|capture| capture.cause()))
            .or_else(|| cause(&self.assignment_decode))
            .or_else(|| self.claim.as_ref().and_then(|capture| capture.failure()).map(|cause| cause as _))
            .or_else(|| cause(&self.claim_decode)).or_else(|| cause(&self.association))
            .or_else(|| self.response.as_ref().and_then(|capture| capture.cause()))
            .or_else(|| cause(&self.verification)).or_else(|| cause(&self.primary))
            .or_else(|| self.after.iter().find_map(|original| original.failure()))
            .or_else(|| self.after_result.iter().find_map(cause))
            .or_else(|| cause(&self.after_readback)).or_else(|| cause(&self.peer))
            .or_else(|| self.after_clock.failure()).or_else(|| cause(&self.after_sample))
            .or_else(|| cause(&self.after_cutoff)).or_else(|| cause(&self.interval))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }
}

fn typed_demand(bundle: ReadyBundleDataV1<'_>, manifest_bytes: usize, trust: &RootCurrentOwnershipTrustStateV1)
    -> Result<ResourceVector, JournalError>
{
    ownership_bundle_typed_demand_v1(bundle, manifest_bytes,
        trust.verifier_v1().map_err(|_| JournalError::ProtectedBoundary)?)
        .map_err(|_| JournalError::JournalTooLarge)
}

fn require_claim_association(
    bundle: ReadyBundleDataV1<'_>, planned: AssignmentPlannedBodyDataV1<'_>,
    manifest: &CanonicalAssignmentManifestV1,
    claim: &aos_sandbox_ownership_protocol::OwnershipClaimV1,
    source: &RootCurrentSourceExchangeStateV1, root: &RootCurrentOpenStateV1,
) -> Result<(), HistoryErrorV1> {
    aos_sandbox_policy::require_root_bundle_ownership_association_data_v1!(
        bundle, planned, manifest, claim,
        source = source.fields_v1(), root = root.completed_body())
}

fn observe_writers(
    writers: &mut RootCreateStorageCurrentWritersV1,
    root: &RootCurrentOpenStateV1,
    originals: &mut [ProtectedJournalCurrentnessOriginalsV1; 2],
    results: &mut [WriterResult; 2],
    readback: &mut Option<Result<RootCurrentOpenReadbackV1, JournalError>>,
) {
    match writers.authority_and_policy() {
        Ok((authority, policy)) => {
            results[0] = Some(authority.validate_held_owned_at_for_uid_retaining(
                Path::new(PROTECTED_POLICY_ROOT), POLICY_AUTHORITY_JOURNAL, 0, &mut originals[0]));
            results[1] = Some(policy.validate_held_owned_at_for_uid_retaining(
                Path::new(PROTECTED_POLICY_ROOT), POLICY_STATE_JOURNAL, 0, &mut originals[1]));
            *readback = Some(root.readback_current(authority, policy));
        }
        Err(cause) => *readback = Some(Err(cause)),
    }
}

fn require_clock(root: &RootCurrentOpenStateV1, source: &RootCurrentSourceExchangeStateV1,
    sample: &Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>) -> Result<(), JournalError>
{
    let now = *positive(sample).map_err(|_| JournalError::ProtectedBoundary)?;
    root.require_clock(now)?;
    let cutoff = source.original_cutoff_v1().map_err(|_| JournalError::ProtectedBoundary)?;
    let source = source.fields_v1().map_err(|_| JournalError::ProtectedBoundary)?;
    if now.boottime_nanoseconds() >= cutoff || now.host_boot_id() != source.boot
        || now.boottime_nanoseconds() < source.boottime_nanoseconds || now.wall_seconds() < source.wall_seconds {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

fn positive<T, E>(value: &Option<Result<T, E>>) -> Result<&T, Error> {
    value.as_ref().and_then(|value| value.as_ref().ok()).ok_or(Error::History)
}

fn cause<T, E: StdError + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn StdError + 'static)> {
    value.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _)
}
