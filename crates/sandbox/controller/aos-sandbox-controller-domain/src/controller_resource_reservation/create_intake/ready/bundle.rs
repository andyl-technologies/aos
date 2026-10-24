//! Lends actual original Native B inputs while the same Ready/Cache stays held.
//!
//! These immutable comparison views do not validate authenticated Inventory,
//! fund encoding, or issue Root authority. The actual Security B producer must
//! retain its same signed terminal/currentness, admit complete output geometry,
//! and run its paid independent posts before transfer or any positive row.

use aos_sandbox_model::{CanonicalAssignmentManifestV1, ResourceDimension};
use aos_sandbox_model::model::{LimitDimension, LimitValue};
use aos_sandbox_protocol::cache_state::NodeCacheQuotaV1;
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    ready::IntentNativeReceiptDataV1,
    source_held::SOURCE_HELD_RECEIPT_BYTES_V1,
    cache_held::CACHE_HELD_RECEIPT_BYTES_V1,
};

use crate::journal::JournalError;

use super::*;

/// Borrows the actual original Native components of complete Ready input B.
///
/// None of these fields is a permission. The enclosing caller must keep the
/// SAME joined Ready and Security Inventory originals resident, fund all new
/// sorting/encoding before growth, and independently check currentness at the
/// real Root exchange. This type cannot create or replace a writer or loan.
#[doc(hidden)]
pub struct CreateStorageReadyNativeInputsV1<'held> {
    /// The actual continuation lane.
    pub lane: [u8; 16],
    /// The actual accepted Create operation, distinct from Spec publication.
    pub operation: [u8; 16],
    /// The full actual Controller Intent record containing A.
    pub intent_record: &'held [u8],
    /// Its actual returned/read-back native coordinates and atomic head.
    pub intent_native_receipt: IntentNativeReceiptDataV1,
    /// The exact original canonical Spec bytes.
    pub specification: &'held [u8],
    /// The real new Source Held record/head/native receipt.
    pub source_held: [u8; SOURCE_HELD_RECEIPT_BYTES_V1],
    /// The real new Cache Held record/head/native receipt.
    pub cache_held: [u8; CACHE_HELD_RECEIPT_BYTES_V1],
    /// All actual retained node quotas; sorting or copying remains separately paid.
    pub cache_node_quotas: &'held [NodeCacheQuotaV1],
    /// The actual completed phase12 row and its full assignment preimage.
    pub assignment_planned: &'held [u8],
    /// The same canonical assignment retained by that producer and Ownership.
    pub manifest: &'held CanonicalAssignmentManifestV1,
    /// The earliest actual sent Begin, never rebuilt from the canonical claim.
    pub ownership_begin_request: &'held [u8],
    /// Its actual response, absent only for that original ambiguous Begin.
    pub ownership_begin_response: Option<&'held [u8]>,
    /// The verified attempt's actual completed request frame.
    pub ownership_completed_request: &'held [u8],
    /// That attempt's actual completed response frame.
    pub ownership_completed_response: &'held [u8],
    /// The exact canonical acquisition claim.
    pub ownership_claim: &'held [u8],
    /// The actual verified lease's canonical bytes.
    pub ownership_lease: &'held [u8],
    /// Its actual detached canonical signature.
    pub ownership_signature: &'held [u8],
    /// The exact verified issuer transaction receipt.
    pub ownership_receipt: &'held [u8],
    /// The original transaction receipt's detached canonical signature.
    pub ownership_receipt_signature: &'held [u8],
    /// Current logical Controller account DATA from the same held writer.
    pub controller_head: &'held [u8],
    /// Current logical Sandbox C-child account DATA from that same held writer.
    pub sandbox_head: &'held [u8],
    /// The exact already-entered J claim retained on the same native writer.
    pub intake_claim: &'held [u8],
    /// The original signed policy-source transfer, including its exact inputs.
    pub policy_sources: &'held [u8],
    /// The complete existing compiler-origin record and proposed candidate.
    pub compiler_origin: &'held [u8],
    /// The resolved original Policy's finite Storage ceiling, as proposed DATA.
    pub proposed_quota_bytes: u64,
    /// The actual canonical manifest's Storage reservation, as proposed DATA.
    pub proposed_reservation_bytes: u64,
    /// The original accepted cutoff, never a new or extended deadline.
    pub proposed_expires_boottime_nanoseconds: u64,
}

impl OriginalCreateStorageReadyV1<'_, '_> {
    /// Borrows only the retained Native bundle cause for upper diagnostics.
    ///
    /// The caller combines this with its own chronological stage selector.
    /// This performs no IO, borrowing transition, admission or debt reset.
    #[doc(hidden)]
    #[must_use]
    pub fn bundle_original_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original.owner.bundle.failure()
    }

    /// Borrows the genuine retained components without allocating or observing IO.
    ///
    /// This validates only the already-completed original association. The
    /// actual Security B builder still needs its authenticated Inventory owner
    /// and fresh paid before/after observations for its new encoding interval.
    ///
    /// # Errors
    /// Refuses debt, incomplete Held/Assignment/Ownership/Native Inventory,
    /// missing original Begin, foreign bank identity or nonfinite proposed
    /// Storage limits. Earlier complete owners stay in their original fields.
    #[doc(hidden)]
    pub fn borrow_ready_native_inputs_v1(&self)
        -> Result<CreateStorageReadyNativeInputsV1<'_>, ResourceReservationErrorV1>
    {
        self.require_bundle_native_inputs_v1()?;
        let lane = self.original.create_storage_lane_v1()?;
        let (intent_record, intent_native_receipt) = self.original.owner.histories
            .intent_bundle_data_v1()?;
        let source_held = self.original.source_held_data_v1()?.encode(lane)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let cache_held = self.cache.held_receipt_data_v1()
            .map_err(|_| ResourceReservationErrorV1::Conflict)?.encode(lane)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let cache_node_quotas = self.cache.node_quotas_for_bundle_v1()
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let assignment = &self.original.owner.assignment;
        let assignment_planned = assignment.bundle_record_v1()?;
        let (origin, policy) = assignment.bundle_origin_v1()?;
        let verified = self.verified_ownership_v1()?;
        let wire = verified.wire_records_v1()?;
        let manifest = verified.manifest();
        let (specification, _) = self.original.owner.parent.create_storage_assignment_proposal_inputs_v1()?;
        let (sources, compiler_origin) = self.original.owner.parent.create_storage_policy_sources_v1()?;
        let sources = sources.preview()
            .map_err(|cause| ResourceReservationErrorV1::Terminal(Box::new(cause)))?;
        if origin.output_bytes()[0] != policy.canonical_policy()
            || manifest.manifest().sandbox().into_bytes() != self.original.accepted()?.sandbox {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let quota = policy.policy().limits().limits().iter()
            .find(|limit| limit.dimension() == LimitDimension::Bytes)
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let LimitValue::Bounded(proposed_quota_bytes) = quota.value() else {
            return Err(ResourceReservationErrorV1::Conflict);
        };
        let proposed_reservation_bytes = manifest.manifest().reservations().get(ResourceDimension::StorageBytes);
        if proposed_quota_bytes == 0 || proposed_reservation_bytes > proposed_quota_bytes {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let [controller_head, sandbox_head, intake_claim] = self.original.controller
            .create_storage_bundle_admission_data_v1(self)?;
        Ok(CreateStorageReadyNativeInputsV1 {
            lane, operation: self.original.accepted()?.operation, intent_record, intent_native_receipt,
            specification: specification.canonical_bytes(), source_held, cache_held,
            cache_node_quotas, assignment_planned, manifest,
            ownership_begin_request: wire.begin_request.raw,
            ownership_begin_response: wire.begin_response.map(|record| record.raw),
            ownership_completed_request: wire.completed_request.raw,
            ownership_completed_response: wire.completed_response.raw,
            ownership_claim: verified.claim().canonical_bytes(),
            ownership_lease: verified.lease().canonical_lease(),
            ownership_signature: verified.lease().canonical_signature(),
            ownership_receipt: verified.lease().canonical_receipt(),
            ownership_receipt_signature: verified.lease().canonical_receipt_signature(),
            controller_head, sandbox_head, intake_claim,
            policy_sources: sources.bytes(), compiler_origin,
            proposed_quota_bytes, proposed_reservation_bytes,
            proposed_expires_boottime_nanoseconds: self.original.accepted()?.original_cutoff,
        })
    }

    fn require_bundle_native_inputs_v1(&self) -> Result<(), ResourceReservationErrorV1> {
        if self.failure().is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.original.require_operation_currentness_peak_v1(&self.cache)?;
        self.original.owner.inventory.require_complete_bundle_predecessor_v1()?;
        self.cache.node_quotas_for_bundle_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        self.verified_ownership_v1()?.require_original()
    }

    // This fixed, private comparison is used only by the same Journal's pure
    // admission-byte borrow. The byte view grants no fresh native currentness.
    pub(crate) fn bundle_admission_accounts_data_v1(&self, journal: &Journal)
        -> Result<(super::super::super::EnrollmentIdentity, [u8; 16], [u8; 16]), JournalError>
    {
        if !std::ptr::eq(journal, &*self.original.controller) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.require_bundle_native_inputs_v1().map_err(|_| JournalError::ProtectedBoundary)?;
        let original = self.original.owner.intake.create_storage_j_data_v1()
            .map_err(|_| JournalError::ProtectedBoundary)?;
        let head = super::super::super::AccountHead::decode(original.head)
            .map_err(|_| JournalError::ProtectedBoundary)?;
        let claim = super::super::super::Claim::decode(original.claim)
            .map_err(|_| JournalError::ProtectedBoundary)?;
        let (enrollment, child) = self.original.owner.parent.create_storage_child_account_data_v1()
            .map_err(|_| JournalError::ProtectedBoundary)?;
        if head.native_fields().enrollment != enrollment
            || claim.native_fields().enrollment != enrollment {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok((enrollment, child, claim.native_fields().id))
    }
}

use aos_sandbox_model::ResourceVector;
use aos_sandbox_linux::seqpacket::SeqpacketSocket;
use aos_sandbox_broker_session_protocol::VerifiedBrokerSessionTranscriptV1;
use super::cache_receiving::{CacheControlOriginalsV1, CacheCurrentnessOriginalV1, OriginalCacheAssociationV1};
use super::outcome_receiving::{OutcomeReplayReceivingOriginalsV1, OutcomeReplayRosterV1};

/// Describes the actual new private B flight, excluding its already-held inputs.
///
/// The owning Security bridge compares this layout with its concrete type
/// before native or endpoint IO. It supplies no caller resource vector.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CreateStorageBundleShapeDataV1 {
    /// Actual private encoding-flight construction/resident overlap.
    pub flight_bytes: usize,
    /// Actual newly retained result/control heap destinations.
    pub flight_cells: usize,
    /// Actual retained before/after endpoint native observation destinations.
    pub endpoint_open_files: usize,
}

/// Reports a closed original B encoding interval with actual custody retained.
#[doc(hidden)]
#[derive(Debug, thiserror::Error)]
#[error("original Create Ready encoding is closed with its originals retained")]
pub struct CreateStorageBundleClosedV1;

#[derive(Default)]
pub(in crate::controller_resource_reservation::create_intake) struct BundleEncodingOriginalsV1 {
    borrowed: bool,
    closed: Option<CreateStorageBundleClosedV1>,
    shape: Option<CreateStorageBundleShapeDataV1>,
    expected: Option<OriginalCacheAssociationV1>,
    geometry: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    fixed: Option<Result<(), ResourceReservationErrorV1>>,
    before: CacheCurrentnessOriginalV1,
    before_association: Option<Result<(), super::client_session::ClientSessionAssociationErrorV1>>,
    before_result: Option<Result<(), ResourceReservationErrorV1>>,
    replay_association: Option<Result<(), super::client_session::ClientSessionAssociationErrorV1>>,
    replay_receiving: OutcomeReplayReceivingOriginalsV1,
    complete_bound: ResourceVector,
    encoded_geometry: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    encoded: Option<Result<(), ResourceReservationErrorV1>>,
    encoded_bytes: Option<usize>,
    after: CacheCurrentnessOriginalV1,
    after_association: Option<Result<(), super::client_session::ClientSessionAssociationErrorV1>>,
    after_result: Option<Result<(), ResourceReservationErrorV1>>,
    framing: Option<Result<(), aos_sandbox_protocol::domain_ledger::create_storage_history::HistoryErrorV1>>,
    native_binding: Option<Result<(), ResourceReservationErrorV1>>,
    prepared: Option<[u8; 32]>,
}

impl BundleEncodingOriginalsV1 {
    pub(in crate::controller_resource_reservation::create_intake) fn require_completed_bytes_v1(&self, bytes: &[u8]) -> Result<(), ResourceReservationErrorV1> {
        if self.failure().is_some() || self.encoded_bytes != Some(bytes.len())
            || self.prepared != Some(aos_sandbox_protocol::domain_ledger::create_storage_history::ready::ready_commitment_v1(bytes)) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }


    pub(in crate::controller_resource_reservation::create_intake) fn failure(&self)
        -> Option<&(dyn std::error::Error + 'static)>
    {
        bundle_error(&self.geometry).or_else(|| bundle_error(&self.fixed))
            .or_else(|| self.before.failure()).or_else(|| bundle_error(&self.before_association))
            .or_else(|| bundle_error(&self.before_result))
            .or_else(|| bundle_error(&self.replay_association))
            .or_else(|| self.replay_receiving.failure())
            .or_else(|| bundle_error(&self.encoded_geometry)).or_else(|| bundle_error(&self.encoded))
            .or_else(|| self.after.failure()).or_else(|| bundle_error(&self.after_association))
            .or_else(|| bundle_error(&self.after_result))
            .or_else(|| bundle_error(&self.framing)).or_else(|| bundle_error(&self.native_binding))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }
}

/// Borrows the same genuine J, Source, Cache and original inputs for B encoding.
///
/// Its completion is local encoding disposition. Security must retain its
/// actual signed Inventory terminal/currentness and the resulting full bytes;
/// neither completion nor a Ready digest grants Root U or Prepare authority.
#[doc(hidden)]
#[must_use = "retain the real joined borrower beside the complete Security B flight"]
pub struct OriginalCreateStorageBundleV1<'turn, 'original, 'cache> {
    ready: &'turn mut OriginalCreateStorageReadyV1<'original, 'cache>,
    completed: bool,
}

impl<'original, 'cache> OriginalCreateStorageReadyV1<'original, 'cache> {
    /// Borrows the original encoding interval after the actual preceding stages.
    ///
    /// # Errors
    /// Refuses debt, reentry or incomplete native/Held/Ownership sequencing.
    /// The actual authenticated Inventory owner remains an upper requirement.
    #[doc(hidden)]
    pub fn borrow_bundle_encoding_once<'turn>(&'turn mut self)
        -> Result<OriginalCreateStorageBundleV1<'turn, 'original, 'cache>, CreateStorageBundleClosedV1>
    {
        if self.require_bundle_native_inputs_v1().is_err() || self.original.owner.bundle.borrowed {
            return Err(CreateStorageBundleClosedV1);
        }
        self.original.owner.bundle.borrowed = true;
        Ok(OriginalCreateStorageBundleV1 { ready: self, completed: false })
    }
}

impl OriginalCreateStorageBundleV1<'_, '_, '_> {
    /// Admits fixed private output owners and the two named independent controls.
    ///
    /// # Errors
    /// Retains shape, checked arithmetic and genuine same-J reservation failures.
    /// No IO is entered when this fixed admission refuses.
    #[doc(hidden)]
    pub fn admit_fixed_once(&mut self, shape: CreateStorageBundleShapeDataV1)
        -> Result<(), CreateStorageBundleClosedV1>
    {
        if self.ready.original.owner.bundle.fixed.is_some() || self.failure().is_some() {
            return self.close();
        }
        self.ready.original.owner.bundle.shape = Some(shape);
        self.ready.original.owner.bundle.geometry = Some((|| {
            self.ready.original.require_operation_currentness_peak_v1(&self.ready.cache)?;
            self.ready.original.owner.bundle.expected = Some(self.ready.original.owner.cache_capture.currentness_association_v1()?);
            let native = self.ready.borrow_ready_native_inputs_v1()?;
            let quotas = native.cache_node_quotas.len();
            let quota_bytes = aos_sandbox_protocol::cache_state::complete_node_quotas::complete_node_quota_rows_encoded_bytes_v1(quotas)
                .map_err(|_| ResourceReservationErrorV1::Conflict)?;
            let clone_bytes = quotas.checked_add(4)
                .and_then(|count| count.checked_mul(std::mem::size_of::<NodeCacheQuotaV1>()))
                .and_then(|bytes| bytes.checked_mul(2)).ok_or(ResourceReservationErrorV1::Conflict)?;
            let admission_bytes = native.controller_head.len().checked_add(native.sandbox_head.len())
                .and_then(|bytes| bytes.checked_add(native.intake_claim.len()))
                .and_then(|bytes| bytes.checked_add(12)).ok_or(ResourceReservationErrorV1::Conflict)?;
            let bytes = shape.flight_bytes.checked_add(quota_bytes)
                .and_then(|bytes| bytes.checked_add(clone_bytes))
                .and_then(|bytes| bytes.checked_add(admission_bytes))
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            // Eleven direct Results (including the pure replay-Journal join)
            // and the closed cause coexist with two complete controls. The
            // sampler's eight cells are added by its own fixed recipe.
            let cells = shape.flight_cells.checked_add(quotas)
                .and_then(|cells| cells.checked_add(12)).ok_or(ResourceReservationErrorV1::Conflict)?;
            let private = ResourceVector::ZERO
                .with(ResourceDimension::MemoryBytes, u64::try_from(bytes).map_err(|_| ResourceReservationErrorV1::Conflict)?)
                .with(ResourceDimension::MetadataEntries, u64::try_from(cells).map_err(|_| ResourceReservationErrorV1::Conflict)?)
                .with(ResourceDimension::OpenFiles, u64::try_from(shape.endpoint_open_files)
                    .map_err(|_| ResourceReservationErrorV1::Conflict)?);
            let controls = CacheCurrentnessOriginalV1::receiving_backing_demand_v1(2)?;
            let receiving = OutcomeReplayReceivingOriginalsV1::fixed_receiving_demand_v1()?;
            Ok(private.checked_add(controls)?.checked_add(receiving)?)
        })());
        self.ready.original.owner.bundle.fixed = Some((|| {
            let demand = self.ready.original.owner.bundle.geometry.as_ref()
                .and_then(|result| result.as_ref().ok()).copied()
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            self.ready.original.owner.intake.reserve_create_capture_complete(
                crate::controller_resource_reservation::q04_intake::CreateContinuationCaptureOwnerV1::ReadyBundle,
                demand)?;
            self.ready.original.owner.bundle.complete_bound = demand;
            Ok(())
        })());
        self.status()
    }

    /// Checks the exact concrete private footprint before actual upper IO.
    ///
    /// # Errors
    /// Refuses a different shape, incomplete fixed admission or existing debt.
    #[doc(hidden)]
    pub fn require_fixed_preparation_v1(&self, shape: CreateStorageBundleShapeDataV1)
        -> Result<(), CreateStorageBundleClosedV1>
    {
        let progress = &self.ready.original.owner.bundle;
        if progress.shape != Some(shape) || !matches!(progress.fixed, Some(Ok(())))
            || progress.failure().is_some() {
            return Err(CreateStorageBundleClosedV1);
        }
        Ok(())
    }

    /// Observes the first actual same-Session/Controller/Source/profile/clock cut.
    ///
    /// # Errors
    /// Retains actual original, profile, names, paired-clock or Session mismatch.
    /// A funded entered interval still owes its independent `observe_after_once`.
    #[doc(hidden)]
    pub fn observe_before_once(&mut self, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1) -> Result<(), CreateStorageBundleClosedV1>
    {
        let progress = &self.ready.original.owner.bundle;
        if !matches!(progress.fixed, Some(Ok(()))) || progress.before_result.is_some()
            || progress.failure().is_some() {
            return self.close();
        }
        self.observe(journal, socket, transcript, false);
        self.status()
    }

    /// Prepays both whole retained predecessor validations from the same writer.
    ///
    /// The actual before association must already be positive. Both complete
    /// canonical replay/terminal destinations coexist, including after a later
    /// primary refusal; this uses the same original ReadyBundle highwater.
    ///
    /// # Errors
    /// Retains the actual metadata, resident-width, replay/method geometry and
    /// same-J reservation causes before any Security decoder may grow.
    #[doc(hidden)]
    pub fn admit_retained_validation_once(&mut self, journal: &Journal)
        -> Result<(), CreateStorageBundleClosedV1>
    {
        let progress = &self.ready.original.owner.bundle;
        if !matches!(progress.before_result, Some(Ok(())))
            || !matches!(progress.before_association, Some(Ok(())))
            || progress.replay_association.is_some() || progress.failure().is_some() {
            return self.close();
        }
        let association = self.ready.original.owner.client_session
            .require_completed_journal_v1(journal);
        let progress = &mut self.ready.original.owner.bundle;
        progress.replay_association = Some(association);
        if matches!(progress.replay_association, Some(Ok(()))) {
            let _ = progress.replay_receiving.capture_once(
                journal, OutcomeReplayRosterV1::BundleBeforeAndAfter,
            );
        }
        let admission = (|| {
            if !matches!(progress.replay_association, Some(Ok(()))) {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            let complete = progress.complete_bound
                .checked_add(progress.replay_receiving.demand_v1()?)?;
            self.ready.original.owner.intake.reserve_create_capture_complete(
                crate::controller_resource_reservation::q04_intake::CreateContinuationCaptureOwnerV1::ReadyBundle,
                complete,
            )?;
            progress.complete_bound = complete;
            Ok(())
        })();
        let _ = progress.replay_receiving.retain_admission_once(admission);
        self.status()
    }

    /// Requires only this already-paid validation roster, including owed posts.
    ///
    /// This pure check neither observes currentness nor renews a reservation.
    /// A later encoding/account error cannot erase its prepaid after lane.
    ///
    /// # Errors
    /// Refuses absent or failed original retained-validation admission.
    #[doc(hidden)]
    pub fn require_retained_validation_prepaid_v1(&self)
        -> Result<(), CreateStorageBundleClosedV1>
    {
        self.ready.original.owner.bundle.replay_receiving.require_admitted_v1()
            .map_err(|_| CreateStorageBundleClosedV1)
    }

    /// Borrows the actual original component views after fixed/currentness entry.
    ///
    /// # Errors
    /// Refuses incomplete or failed entry; the returned DATA grants no currentness.
    #[doc(hidden)]
    pub fn native_inputs_v1(&self) -> Result<CreateStorageReadyNativeInputsV1<'_>, CreateStorageBundleClosedV1> {
        if !matches!(self.ready.original.owner.bundle.before_result, Some(Ok(())))
            || self.failure().is_some() {
            return Err(CreateStorageBundleClosedV1);
        }
        self.ready.borrow_ready_native_inputs_v1().map_err(|_| CreateStorageBundleClosedV1)
    }

    /// Runs the separately prepaid after cut even after upper or later budget debt.
    ///
    /// # Errors
    /// Retains actual independent native/profile/clock or Session errors without
    /// replacing any earlier retained primary cause. It performs no new grant.
    #[doc(hidden)]
    pub fn observe_after_once(&mut self, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1) -> Result<(), CreateStorageBundleClosedV1>
    {
        let progress = &self.ready.original.owner.bundle;
        if !matches!(progress.fixed, Some(Ok(()))) || progress.before_result.is_none()
            || progress.after_result.is_some() {
            return self.close();
        }
        self.observe(journal, socket, transcript, true);
        self.status()
    }

    fn observe(&mut self, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1, after: bool)
    {
        let expected = self.ready.original.owner.bundle.expected.ok_or(ResourceReservationErrorV1::Conflict);
        let position = self.ready.original.current_controller_history_position_v1();
        let owner = &mut *self.ready.original.owner;
        let control = CacheControlOriginalsV1 {
            parent: &owner.parent, intake: &owner.intake,
            controller: self.ready.original.controller, source: self.ready.original.source,
            profile: self.ready.original.profile,
        };
        let (sample, association, result) = if after {
            (&mut owner.bundle.after, &mut owner.bundle.after_association, &mut owner.bundle.after_result)
        } else {
            (&mut owner.bundle.before, &mut owner.bundle.before_association, &mut owner.bundle.before_result)
        };
        *result = Some(match expected {
            Ok(expected) => sample.observe_operation_once(control, &self.ready.cache.currentness_original_v1(), expected, position),
            Err(cause) => Err(cause),
        });
        *association = Some(owner.client_session.require_completed_association_v1(journal, socket, transcript));
    }

    /// Borrows this interval's actual Native cause without releasing originals.
    #[doc(hidden)]
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.ready.original.owner.bundle.failure()
    }

    fn status(&mut self) -> Result<(), CreateStorageBundleClosedV1> {
        if self.failure().is_none() { Ok(()) } else { self.close() }
    }

    fn close<T>(&mut self) -> Result<T, CreateStorageBundleClosedV1> {
        self.ready.original.owner.bundle.closed.get_or_insert(CreateStorageBundleClosedV1);
        Err(CreateStorageBundleClosedV1)
    }
}

impl Drop for OriginalCreateStorageBundleV1<'_, '_, '_> {
    fn drop(&mut self) {
        if !self.completed {
            self.ready.original.owner.bundle.closed.get_or_insert(CreateStorageBundleClosedV1);
        }
    }
}

fn bundle_error<T, E: std::error::Error + 'static>(value: &Option<Result<T, E>>)
    -> Option<&(dyn std::error::Error + 'static)>
{
    value.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)
}

impl OriginalCreateStorageBundleV1<'_, '_, '_> {
    /// Admits the complete exact B output before the upper encoder allocates it.
    ///
    /// The fixed Security builder derives this DATA from every actual borrowed
    /// field and checks the same width again before allocating output. It also
    /// retains and checks its real Inventory/checkpoint/HELLO. Completion checks
    /// all actual Native-owned fields; a declared width grants no authority.
    ///
    /// # Errors
    /// Retains framing/association, checked geometry or same-J refusal before
    /// output growth. An entered interval still owes its prepaid after sample.
    #[doc(hidden)]
    pub fn admit_encoding_once(
        &mut self,
        encoded_bytes: usize,
    ) -> Result<(), CreateStorageBundleClosedV1> {
        let progress = &self.ready.original.owner.bundle;
        if !matches!(progress.before_result, Some(Ok(())))
            || progress.encoded.is_some() || progress.failure().is_some()
            || self.require_retained_validation_prepaid_v1().is_err() {
            return self.close();
        }
        self.ready.original.owner.bundle.encoded_geometry = Some((|| {
            // The fixed upper builder measures the complete borrowed frame,
            // releases those borrows, then admits its exact width before Vec
            // growth. Completion compares all actual Native-owned fields.
            let width = encoded_bytes;
            if width == 0 { return Err(ResourceReservationErrorV1::Conflict); }
            let bytes = width.checked_mul(2).ok_or(ResourceReservationErrorV1::Conflict)?;
            let output = ResourceVector::ZERO
                .with(ResourceDimension::MemoryBytes, u64::try_from(bytes).map_err(|_| ResourceReservationErrorV1::Conflict)?)
                .with(ResourceDimension::MetadataEntries, 2);
            self.ready.original.owner.bundle.encoded_bytes = Some(width);
            Ok(self.ready.original.owner.bundle.complete_bound.checked_add(output)?)
        })());
        self.ready.original.owner.bundle.encoded = Some((|| {
            let complete = self.ready.original.owner.bundle.encoded_geometry.as_ref()
                .and_then(|result| result.as_ref().ok()).copied()
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            self.ready.original.owner.intake.reserve_create_capture_complete(
                crate::controller_resource_reservation::q04_intake::CreateContinuationCaptureOwnerV1::ReadyBundle,
                complete)
        })());
        self.status()
    }

    /// Completes only the actual local encoding after all independent posts.
    ///
    /// The original actual bytes stay on the upper flight, and the same Ready
    /// still owns Source/Cache and every prior original through the Root work.
    /// A stored Ready hash is correlation DATA, not Root validation or a grant.
    ///
    /// # Errors
    /// Refuses failed/incomplete posts, another width or changed original fields.
    #[doc(hidden)]
    pub fn finish_encoded_once(&mut self, bytes: &[u8]) -> Result<(), CreateStorageBundleClosedV1> {
        let progress = &self.ready.original.owner.bundle;
        if progress.prepared.is_some() || progress.encoded_bytes != Some(bytes.len())
            || !matches!(progress.encoded, Some(Ok(())))
            || !matches!(progress.before_result, Some(Ok(())))
            || !matches!(progress.after_result, Some(Ok(())))
            || !matches!(progress.before_association, Some(Ok(())))
            || !matches!(progress.after_association, Some(Ok(())))
            || progress.failure().is_some()
            || self.require_retained_validation_prepaid_v1().is_err() {
            return self.close();
        }
        let decoded = aos_sandbox_protocol::domain_ledger::create_storage_history::ready::ReadyBundleDataV1::decode(bytes);
        let data = match decoded {
            Ok(data) => {
                self.ready.original.owner.bundle.framing = Some(Ok(()));
                data
            }
            Err(cause) => {
                self.ready.original.owner.bundle.framing = Some(Err(cause));
                return self.close();
            }
        };
        self.ready.original.owner.bundle.native_binding = Some(self.require_native_fields_v1(data));
        if self.ready.original.owner.bundle.native_binding.as_ref().is_some_and(Result::is_err) {
            return self.close();
        }
        self.ready.original.owner.bundle.prepared = Some(
            aos_sandbox_protocol::domain_ledger::create_storage_history::ready::ready_commitment_v1(bytes));
        self.completed = true;
        Ok(())
    }

    fn require_native_fields_v1(&self,
        data: aos_sandbox_protocol::domain_ledger::create_storage_history::ready::ReadyBundleDataV1<'_>)
        -> Result<(), ResourceReservationErrorV1>
    {
        let native = self.ready.borrow_ready_native_inputs_v1()?;
        let intent_native = native.intent_native_receipt.encode()
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let admission = aos_sandbox_protocol::domain_ledger::create_storage_history::ready::ControllerAdmissionDataV1::decode(
            data.controller_admission).map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let quotas = aos_sandbox_protocol::cache_state::complete_node_quotas::CompleteNodeQuotaRowsDataV1::decode(
            data.cache_node_quotas).map_err(|_| ResourceReservationErrorV1::Conflict)?;
        if data.lane != native.lane || data.intent_record != native.intent_record
            || data.intent_native_receipt != intent_native || data.specification != native.specification
            || data.source_held != native.source_held || data.cache_held != native.cache_held
            || data.assignment_planned != native.assignment_planned
            || data.ownership_begin_request != native.ownership_begin_request
            || data.ownership_begin_response != native.ownership_begin_response.unwrap_or(&[])
            || data.ownership_completed_request != native.ownership_completed_request
            || data.ownership_completed_response != native.ownership_completed_response
            || data.ownership_claim != native.ownership_claim
            || data.ownership_lease != native.ownership_lease
            || data.ownership_signature != native.ownership_signature
            || data.ownership_receipt != native.ownership_receipt
            || data.ownership_receipt_signature != native.ownership_receipt_signature
            || data.policy_sources != native.policy_sources || data.compiler_origin != native.compiler_origin
            || admission.controller != native.controller_head || admission.sandbox != native.sandbox_head
            || admission.intake != native.intake_claim
            || quotas.rows().len() != native.cache_node_quotas.len() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        // The frame has already checked exact quota commitment/selected row.
        // Authentic Inventory and proposal semantics are checked by the actual
        // upper owner and independently again by Root before any positive use.
        Ok(())
    }
}
