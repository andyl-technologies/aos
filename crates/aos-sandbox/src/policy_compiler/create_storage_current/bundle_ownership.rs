//! Verifies B's exact Ownership response using Root's own retained trust.
//!
//! This is one component of the later independent typed-B/current-cut verifier.
//! It grants no Use, Prepare, signing or release. Proposed Controller/MAC DATA
//! cannot supply Root's trust anchor, paired clock or receiving original.

use std::error::Error as StdError;
use std::mem::size_of;
use std::path::Path;

use aos_sandbox_core::{CanonicalAssignmentManifestV1, CanonicalCborError, DecodeLimits, RawPairedClockSample,
    ResourceDimension as D, ResourceVector};
use aos_sandbox_core::format::assignment_capture::CanonicalAssignmentDecodeCaptureV1;
use aos_sandbox_ownership_protocol::{OwnershipClaimAction, OwnershipClaimError,
    OwnershipLeaseAcquisitionError, response_verification::{
        OwnershipClaimDecodeCaptureV1, OwnershipResponseVerifyCaptureV1}};
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    HistoryErrorV1, KeyV1, OwnerV1, PhaseV1, RecordEnvelopeV1,
    assignment_planned::AssignmentPlannedBodyDataV1,
    controller_intent::ControllerIntentBodyDataV1, ready::ReadyBundleDataV1};

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
    interval: Option<Result<(), aos_sandbox_core::OwnershipLeaseVerificationError>>,
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
        let work = size_of::<FixedPreludeWorkV1>().checked_mul(2).ok_or_else(invalid)?;
        let pair = RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()
            .and_then(|bytes| bytes.checked_mul(2)).ok_or_else(invalid)?;
        let memory = size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(work))
            .and_then(|bytes| bytes.checked_add(pair))
            .and_then(|bytes| bytes.checked_add(2 * size_of::<usize>()))
            .and_then(|bytes| bytes.checked_add(2 * size_of::<AssignmentPreludeGeometryV1>())).ok_or_else(invalid)?;
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
}

pub(in crate::policy_compiler) fn ownership_bundle_typed_demand_v1(
    bundle: ReadyBundleDataV1<'_>, manifest_bytes: usize,
    verifier: &aos_sandbox_ownership_protocol::OwnershipAuthorityVerifier,
) -> Result<ResourceVector, JournalError> {
    let invalid = || JournalError::JournalTooLarge;
    let quartet = [bundle.ownership_lease, bundle.ownership_signature,
        bundle.ownership_receipt, bundle.ownership_receipt_signature].into_iter()
        .try_fold(0_usize, |sum, field| sum.checked_add(field.len())).ok_or_else(invalid)?;
    let response = ownership_response_receiving_bytes_v2(quartet, verifier).ok_or_else(invalid)?;
    let (assignment_dynamic, _) =
        CanonicalAssignmentDecodeCaptureV1::receiving_dynamic_footprint_v1(
            manifest_bytes, DecodeLimits::default(),
        ).ok_or_else(invalid)?;
    let assignment_fixed = CanonicalAssignmentDecodeCaptureV1::receiving_construction_bytes_v1()
        .ok_or_else(invalid)?;
    let memory = OwnershipClaimDecodeCaptureV1::receiving_construction_bytes_v1()
        .and_then(|bytes| bytes.checked_add(response))
        .and_then(|bytes| bytes.checked_add(assignment_fixed))
        .and_then(|bytes| bytes.checked_add(assignment_dynamic))
        .and_then(|bytes| bytes.checked_add(4 * size_of::<usize>())).ok_or_else(invalid)?;
    Ok(ResourceVector::ZERO
        .with(D::MemoryBytes, u64::try_from(memory).map_err(|_| invalid())?)
        .with(D::OutputBytes, u64::try_from(memory).map_err(|_| invalid())?))
}

// Both native resource purposes use the same actual verifier/capture recipe.
// The current Maintenance claim is already typed by the paid canonical current
// assignment/gate decoder; Start separately prices its incoming claim/manifest.
pub(in crate::policy_compiler) fn ownership_response_typed_demand_v2(
    quartet_bytes: usize,
    verifier: &aos_sandbox_ownership_protocol::OwnershipAuthorityVerifier,
) -> Result<ResourceVector, JournalError> {
    let memory = ownership_response_receiving_bytes_v2(quartet_bytes, verifier)
        .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
    Ok(ResourceVector::ZERO.with(D::MemoryBytes, memory).with(D::OutputBytes, memory))
}

fn ownership_response_receiving_bytes_v2(
    quartet_bytes: usize,
    verifier: &aos_sandbox_ownership_protocol::OwnershipAuthorityVerifier,
) -> Option<usize> {
    OwnershipResponseVerifyCaptureV1::receiving_construction_bytes_v1()?
        .checked_add(verifier.response_receiving_dynamic_bytes_v2(quartet_bytes)?)
}

fn require_claim_association(
    bundle: ReadyBundleDataV1<'_>, planned: AssignmentPlannedBodyDataV1<'_>,
    manifest: &CanonicalAssignmentManifestV1,
    claim: &aos_sandbox_ownership_protocol::OwnershipClaimV1,
    source: &RootCurrentSourceExchangeStateV1, root: &RootCurrentOpenStateV1,
) -> Result<(), HistoryErrorV1> {
    let intent = RecordEnvelopeV1::decode(bundle.intent_record,
        KeyV1::new(bundle.lane, OwnerV1::Controller, 1)?, PhaseV1::new(OwnerV1::Controller, 1)?)?;
    let accepted = ControllerIntentBodyDataV1::decode(intent.body())?;
    let head = aos_sandbox_protocol::domain_ledger::resource_bank::AccountHead::decode(accepted.j_head)
        .map_err(|_| HistoryErrorV1::Malformed)?;
    let current = source.fields_v1().map_err(|_| HistoryErrorV1::Correlation)?;
    let original = root.completed_body().map_err(|_| HistoryErrorV1::Correlation)?;
    require_claim_data_v1(claim, accepted.identity.operation, accepted.identity.sandbox,
        head.native_fields().enrollment.native_fields().node, planned.manifest)?;
    require_manifest_data_v1(manifest, claim, accepted.identity.project,
        &planned, bundle.specification)?;
    if bundle.lane != original.open.lane || accepted.identity.controller_nonce != original.open.controller_nonce
        || accepted.identity.boot != original.boot
        || current.project != accepted.identity.project || current.sandbox != accepted.identity.sandbox
        || current.released_operation != accepted.identity.operation
        || current.tree_head != planned.tree_head || current.lineage_head != planned.lineage_head
    {
        return Err(HistoryErrorV1::Correlation);
    }
    Ok(())
}

pub(in crate::policy_compiler) fn planned_assignment_v1(bundle: ReadyBundleDataV1<'_>)
    -> Result<AssignmentPlannedBodyDataV1<'_>, HistoryErrorV1>
{
    let record = RecordEnvelopeV1::decode(bundle.assignment_planned,
        KeyV1::new(bundle.lane, OwnerV1::Controller, 2)?,
        PhaseV1::new(OwnerV1::Controller, 12)?)?;
    AssignmentPlannedBodyDataV1::decode(record.body())
}

pub(in crate::policy_compiler) fn require_manifest_data_v1(
    canonical: &CanonicalAssignmentManifestV1,
    claim: &aos_sandbox_ownership_protocol::OwnershipClaimV1,
    project: [u8; 16],
    planned: &AssignmentPlannedBodyDataV1<'_>,
    specification: &[u8],
) -> Result<(), HistoryErrorV1> {
    let manifest = canonical.manifest();
    if canonical.canonical_bytes() != planned.manifest
        || canonical.digest() != claim.assignment().digest()
        || manifest.project().as_bytes() != &project
        || manifest.sandbox() != claim.assignment().sandbox()
        || manifest.node() != claim.node()
        || manifest.incarnation() != claim.assignment().incarnation()
        || manifest.epoch() != claim.assignment().epoch()
        || manifest.desired_generation() != claim.desired_generation()
        || manifest.epoch().get() != 1 || manifest.desired_generation().get() != 1
        || manifest.namespace_generation().get() != 1 || !manifest.ancestry().ancestors().is_empty()
        || !aos_sandbox_core::format::descriptor_matches_encoded_bytes_data_v1(
            manifest.sandbox_spec(), specification)
    {
        return Err(HistoryErrorV1::Correlation);
    }
    Ok(())
}


pub(in crate::policy_compiler) fn require_claim_data_v1(
    claim: &aos_sandbox_ownership_protocol::OwnershipClaimV1,
    operation: [u8; 16], sandbox: [u8; 16], node: [u8; 16], manifest: &[u8],
) -> Result<(), HistoryErrorV1> {
    if claim.action() != OwnershipClaimAction::Acquire || claim.request_id() != &operation
        || claim.assignment().sandbox().as_bytes() != &sandbox || claim.node().as_bytes() != &node
        || claim.assignment().digest() != CanonicalAssignmentManifestV1::digest_canonical_bytes_data_v1(manifest)
    {
        return Err(HistoryErrorV1::Correlation);
    }
    Ok(())
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

// Complete fixed prelude/association carriers, including return planes. This
// roster performs no nested heap decoder and reuses no unnamed spare credit.
#[allow(dead_code)]
struct FixedPreludeWorkV1 {
    bundles: [ReadyBundleDataV1<'static>; 4],
    fields: [[&'static [u8]; 25]; 2],
    intents: [ControllerIntentBodyDataV1<'static>; 4],
    intent_fields: [[&'static [u8]; 11]; 2],
    records: [RecordEnvelopeV1<'static>; 6],
    planned: [AssignmentPlannedBodyDataV1<'static>; 4],
    heads: [aos_sandbox_protocol::domain_ledger::resource_bank::AccountHead; 4],
    source: [aos_sandbox_protocol::domain_ledger::create_storage_history::source_current::SourceCurrentReplyFieldsV1; 2],
    root: [aos_sandbox_protocol::domain_ledger::create_storage_history::root_open::RootOpenBodyDataV1; 2],
    readers: [aos_sandbox_core::bounded_codec::BoundedReader<'static, HistoryErrorV1>; 8],
    vectors: [ResourceVector; 8],
    hashers: [sha2::Sha256; 4],
}


// Fixed geometry/return planes reached before typed admission. These fields
// name the actual two shared passive supplier calls and their checked fold.
#[allow(dead_code)]
struct AssignmentPreludeGeometryV1 {
    manifest_bytes: usize,
    limits: DecodeLimits,
    dynamic: Option<(usize, usize)>,
    construction: Option<usize>,
    bytes: usize,
    cells: usize,
    raw_depth: usize,
    planes: usize,
    ancestry_slots: usize,
    source_slots: usize,
    feature_slots: usize,
    output: ResourceVector,
    result: Result<ResourceVector, JournalError>,
}


#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_core::{AssignmentEpoch, DesiredGeneration, IncarnationId,
        LeaseAssignment, NodeId, SandboxId};
    use aos_sandbox_ownership_protocol::{OwnershipClaimV1, ExpectedOwnershipLease};

    #[test]
    fn claim_joins_exact_accepted_operation_node_and_manifest_bytes() {
        // This exercises only fixed comparison DATA, not a genuine Root/J loan,
        // valid canonical manifest or authority derived from these test bytes.
        let manifest = b"proposed manifest bytes";
        let digest = CanonicalAssignmentManifestV1::digest_canonical_bytes_data_v1(manifest);
        let assignment = LeaseAssignment::new(SandboxId::from_bytes([2; 16]),
            IncarnationId::from_bytes([3; 16]), AssignmentEpoch::new(1), digest).unwrap();
        let claim = OwnershipClaimV1::acquire([1; 16], assignment,
            DesiredGeneration::new(1), NodeId::from_bytes([4; 16]), 60).unwrap();

        assert!(require_claim_data_v1(&claim, [1; 16], [2; 16], [4; 16], manifest).is_ok());
        assert!(require_claim_data_v1(&claim, [9; 16], [2; 16], [4; 16], manifest).is_err());
        assert!(require_claim_data_v1(&claim, [1; 16], [2; 16], [9; 16], manifest).is_err());
        assert!(require_claim_data_v1(&claim, [1; 16], [2; 16], [4; 16], b"other manifest").is_err());

        let prior = ExpectedOwnershipLease::new(1, digest).unwrap();
        let renewal = OwnershipClaimV1::renew([1; 16], assignment,
            DesiredGeneration::new(1), NodeId::from_bytes([4; 16]), prior, 60).unwrap();
        assert!(require_claim_data_v1(&renewal, [1; 16], [2; 16], [4; 16], manifest).is_err());
    }

    fn manifest_fixture(ancestor: bool, generation: u64)
        -> (CanonicalAssignmentManifestV1, OwnershipClaimV1, Vec<u8>)
    {
        use aos_sandbox_core::{MediaType, NamespaceGeneration, ObjectDescriptor,
            ObjectDigest, PortableMediaType, ProjectId};
        use aos_sandbox_core::model::{AssignmentManifestV1, SandboxAncestry};

        let specification = b"exact original specification bytes".to_vec();
        let descriptor = |kind: PortableMediaType, byte| ObjectDescriptor::new(
            MediaType::new(kind.as_str().to_owned()).unwrap(),
            ObjectDigest::from_bytes([byte; 32]), 1,
        );
        let sandbox = SandboxId::from_bytes([1; 16]);
        let spec = aos_sandbox_core::format::descriptor_for_bytes(
            MediaType::new(PortableMediaType::SandboxSpec.as_str().to_owned()).unwrap(),
            &specification,
        );
        let ancestry = SandboxAncestry::new(sandbox,
            if ancestor { vec![SandboxId::from_bytes([9; 16])] } else { Vec::new() }).unwrap();
        let manifest = AssignmentManifestV1::new(
            sandbox, ProjectId::from_bytes([2; 16]), ancestry,
            IncarnationId::from_bytes([4; 16]), NodeId::from_bytes([5; 16]),
            AssignmentEpoch::new(1), DesiredGeneration::new(generation), NamespaceGeneration::new(1),
            spec, descriptor(PortableMediaType::Policy, 7),
            descriptor(PortableMediaType::Environment, 8), descriptor(PortableMediaType::View, 9),
            Vec::new(), ObjectDigest::from_bytes([10; 32]), ResourceVector::ZERO, Vec::new(),
        ).unwrap();
        let canonical = CanonicalAssignmentManifestV1::new(manifest);
        let assignment = LeaseAssignment::new(sandbox, IncarnationId::from_bytes([4; 16]),
            AssignmentEpoch::new(1), canonical.digest()).unwrap();
        let claim = OwnershipClaimV1::acquire([3; 16], assignment,
            DesiredGeneration::new(generation), NodeId::from_bytes([5; 16]), 60).unwrap();
        (canonical, claim, specification)
    }

    #[test]
    fn actual_manifest_model_joins_claim_project_and_exact_spec_commitment() {
        use aos_sandbox_protocol::domain_ledger::create_storage_history::association::AcceptedAssociationDataV1;
        let association = AcceptedAssociationDataV1 {
            operation: [3; 16], project: [2; 16], sandbox: [1; 16],
            accepted_request: [6; 32], coissuance_binding: [7; 32], seed: [8; 32],
            controller_nonce: [9; 16], boot: [10; 16], started: 1, cutoff: 2,
        };
        let (canonical, claim, specification) = manifest_fixture(false, 1);
        let planned = AssignmentPlannedBodyDataV1 { association,
            source_held: [11; 32], cache_held: [12; 32], input_origin: [13; 32],
            tree_head: [14; 32], lineage_head: [15; 32], manifest: canonical.canonical_bytes() };

        assert!(require_manifest_data_v1(&canonical, &claim, [2; 16], &planned, &specification).is_ok());
        assert!(require_manifest_data_v1(&canonical, &claim, [20; 16], &planned, &specification).is_err());
        let mut substituted = specification.clone();
        substituted[0] ^= 1;
        assert!(require_manifest_data_v1(&canonical, &claim, [2; 16], &planned, &substituted).is_err());

        // A valid canonical model and self-consistent claim cannot turn this
        // explicitly first/empty-tree recipe into a different assignment.
        for (ancestor, generation) in [(true, 1), (false, 2)] {
            let (other, other_claim, exact_spec) = manifest_fixture(ancestor, generation);
            let other_planned = AssignmentPlannedBodyDataV1 { manifest: other.canonical_bytes(), ..planned };
            assert!(require_manifest_data_v1(&other, &other_claim, [2; 16], &other_planned, &exact_spec).is_err());
        }
    }

}
