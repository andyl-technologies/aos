//! Produces C6 Signed through the original U-funded atomic history pair.
//!
//! The actual Root8 original and completed native signing phase stay resident.
//! The same verified signed plan fixes the canonical bundle and request ID;
//! Root, U, accepted J and the five original C predecessors remain joined at
//! the unchanged final native crossing and all independently owed posts.

use super::*;
use aos_sandbox_model::{CanonicalCborError, DecodeLimits, SignatureVerificationError};
use aos_sandbox_model::model::Signature;
use aos_sandbox_model::format::{decode_signature, encode_signature_statement};
use aos_sandbox_protocol::authorization_artifact::SignedBrokerPlan;
use aos_sandbox_protocol::semantics::{ProtectedStorageCreatePreparationV1,
    StoragePreparationSemanticsError};
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    continuation::{SignedPreparationBundleDataV1,
        SIGNED_PREPARATION_PREFIX_BYTES_V1},
    controller_use::{ControllerSignedBodyDataV1, SIGNED_BODY_PREFIX_BYTES_V1},
};
use super::super::ready::root_exchange::{RootExchangeOriginalsV1,
    OriginalCreateStorageRootUseAdmittedV1};
use super::super::ready::use_reserved::{completed_reserved_view_v1,
    reservation::UseReservationOriginalsV1};

#[derive(Default)]
pub(in crate::controller_resource_reservation::create_intake) struct SignedOriginalsV1 {
    entered: bool,
    demand: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    funding: Option<Result<(), ResourceReservationErrorV1>>,
    signature: Option<Result<Signature, CanonicalCborError>>,
    statement: Vec<u8>,
    request_body: Option<Result<Vec<u8>, StoragePreparationSemanticsError>>,
    request_id: Option<[u8; 16]>,
    bundle: Vec<u8>,
    bundle_encoding: Option<Result<(), HistoryErrorV1>>,
    body: Vec<u8>,
    body_encoding: Option<Result<(), HistoryErrorV1>>,
    pair: OriginalHistoryPairV1,
    primary: Option<ResultV1<()>>,
    validity: Option<Result<(), SignatureVerificationError>>,
    complete: bool,
}

impl SignedOriginalsV1 {
    pub(super) fn fixed_inline_receiving_bytes_v1() -> Result<usize, ResourceReservationErrorV1> {
        std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(
                std::mem::size_of::<SignedAppendBindingV1<'static>>().checked_mul(2)?))
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(in crate::controller_resource_reservation::create_intake) fn started(&self) -> bool { self.entered }

    pub(in crate::controller_resource_reservation::create_intake) fn produce_once(
        &mut self, parent: &ProjectPreparationReservationAttemptV1,
        intake: &mut Q04OriginalIntakeAttemptV1, histories: &CreateStorageOriginalHistoriesV1,
        assignment: &assignment::AssignmentPlannedOriginalV1,
        validated: &root_validated::RootValidatedOriginalsV1,
        reserved: &use_reserved::UseReservedOriginalsV1,
        reservation: &mut UseReservationOriginalsV1, root: &RootExchangeOriginalsV1,
        signed: &SignedBrokerPlan, protected: &ProtectedStorageCreatePreparationV1,
        controller: &mut Journal, source: &mut ProtectedSourceDomainJournalOwnerV1,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.entered { return Err(ResourceReservationErrorV1::Conflict); }
        self.entered = true;
        self.primary = Some(self.produce_inner(parent, intake, histories, assignment,
            validated, reserved, reservation, root, signed, protected, controller, source, profile));
        // The fixed gate pays this independent original post even when a
        // canonical signature/body/allocation refuses before pair production.
        if matches!(self.funding, Some(Ok(()))) && !self.pair.posts_attempted {
            if let (Ok(original_clock), Ok(original)) = (intake.create_storage_j_data_v1().map(|j| j.clock),
                completed_reserved_view_v1(reservation, reserved)) {
                if let Ok(admitted) = root.borrow_use_admitted_v1(&original) {
                    self.pair.finish_posts_once(intake, controller, source.journal_ref_v1(), profile,
                        original_clock, admitted.cutoff_v1(), HistoryRoleV1::Controller);
                }
            }
        }
        if let Some(Ok(sample)) = self.pair.clock.as_ref() {
            self.validity = Some(require_signed_clock_v1(signed, *sample));
        }
        self.complete = matches!(self.primary, Some(Ok(()))) && self.pair.complete
            && self.failure().is_none();
        if self.complete { Ok(()) } else { Err(ResourceReservationErrorV1::Conflict) }
    }

    fn produce_inner(&mut self, parent: &ProjectPreparationReservationAttemptV1,
        intake: &mut Q04OriginalIntakeAttemptV1, histories: &CreateStorageOriginalHistoriesV1,
        assignment: &assignment::AssignmentPlannedOriginalV1,
        validated: &root_validated::RootValidatedOriginalsV1,
        reserved: &use_reserved::UseReservedOriginalsV1,
        reservation: &mut UseReservationOriginalsV1, root: &RootExchangeOriginalsV1,
        signed: &SignedBrokerPlan, protected: &ProtectedStorageCreatePreparationV1,
        controller: &mut Journal, source: &mut ProtectedSourceDomainJournalOwnerV1,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> ResultV1<()> {
        root.require_completed_signing_v1()?;
        let maximum = reservation.request_shape_bytes_v1()?;
        let maximum_record = maximum.checked_mul(3)
            .and_then(|bytes| bytes.checked_add(SIGNED_PREPARATION_PREFIX_BYTES_V1))
            .and_then(|bytes| bytes.checked_add(SIGNED_BODY_PREFIX_BYTES_V1))
            .and_then(|bytes| bytes.checked_add(RECORD_OVERHEAD_BYTES))
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        self.demand = Some((|| {
            parent.require_create_storage_association(controller, source, profile)?;
            intake.require_create_history_names_peak_v1()?;
            use_history_pair_receiving_demand_v1(maximum_record,
                &controller.create_storage_semantic_append_demand_v1()?)
        })());
        self.funding = Some((|| {
            let demand = *self.demand.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            reservation.reserve_pair_receiving_once_v1(demand)?;
            intake.extend_create_storage_use_observers_once(profile, reservation.receiving_mut_v1()?, 6)
        })());
        retained(&self.funding)?;
        self.pair.enter_once(parent, intake, controller, source.journal_ref_v1(), profile,
            HistoryRoleV1::Controller)?;
        let original = completed_reserved_view_v1(reservation, reserved)?;
        let admitted = root.borrow_use_admitted_v1(&original)?;
        let lane = intake.create_lane()?;
        let before = reserved.position()?;
        if signed.canonical_plan() != admitted.plan_v1()?
            || signed.canonical_plan().len() > maximum
            || signed.canonical_signature().len() > maximum {
            return Err(HistoryErrorV1::Correlation.into());
        }
        self.signature = Some(decode_signature(signed.canonical_signature(), DecodeLimits::default()));
        self.statement = encode_signature_statement(retained(&self.signature)?.statement());
        if self.statement != admitted.statement_v1()? {
            return Err(HistoryErrorV1::Correlation.into());
        }
        let [grant] = signed.plan().grants() else { return Err(HistoryErrorV1::Correlation.into()); };
        if grant.argument_commitment() != protected.argument_commitment()
            || signed.plan().assignment() != protected.assignment() {
            return Err(HistoryErrorV1::Correlation.into());
        }
        self.request_id = Some(protected.signed_request_id_v1(signed.digest(), signed.canonical_signature()));
        self.request_body = Some(protected.signed_request_body_v1(
            signed.digest(), signed.canonical_signature(), admitted.cutoff_v1(),
        ));
        let request_body = retained(&self.request_body)?;
        if request_body.len() > maximum { return Err(HistoryErrorV1::Extent.into()); }
        let bundle = SignedPreparationBundleDataV1 { plan: signed.canonical_plan(),
            signature: signed.canonical_signature(), request_body };
        let bundle_bytes = bundle.encoded_bytes()?;
        self.bundle.try_reserve_exact(bundle_bytes)?;
        self.bundle.resize(bundle_bytes, 0);
        self.bundle_encoding = Some(bundle.encode_into(&mut self.bundle));
        retained(&self.bundle_encoding)?;
        let body = ControllerSignedBodyDataV1 { admitted: admitted.receipt_v1()?, bundle: &self.bundle };
        let body_bytes = body.encoded_bytes()?;
        self.body.try_reserve_exact(body_bytes)?;
        self.body.resize(body_bytes, 0);
        self.body_encoding = Some(body.encode_into(lane, maximum, &mut self.body));
        retained(&self.body_encoding)?;
        let inputs = root.inputs_ready_receipt_v1()?;
        let seed = RecordEnvelopeV1::decode(inputs.record,
            KeyV1::new(lane, OwnerV1::Controller, 3)?, PhaseV1::new(OwnerV1::Controller, 2)?)?
            .coordinates().correlation;
        let binding = SignedAppendBindingV1 { lane, seed, intent: &histories.intent.record,
            planned: assignment.bundle_record_v1()?, inputs,
            validated, reserved, reservation, admitted: &admitted, signed, body: &self.body,
            bundle: &self.bundle, request_body, funded: &self.funding,
            demand: *self.demand.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(ResourceReservationErrorV1::Conflict)? };
        let original_clock = intake.create_storage_j_data_v1()?.clock;
        self.pair.produce_once(parent, intake, controller, source.journal_ref_v1(), profile,
            HistoryRoleV1::Controller, lane, seed, original_clock,
            admitted.cutoff_v1(), Some((before.next, before.end)), &self.body,
            Some(HistorySuccessorBindingV1::Signed(&binding)))
    }

    pub(in crate::controller_resource_reservation::create_intake) fn position(&self)
        -> Result<CreateStorageWriterPositionV1, ResourceReservationErrorV1> {
        if !self.complete || self.failure().is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        self.pair.after.as_ref().and_then(|result| result.as_ref().ok()).copied()
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(in crate::controller_resource_reservation::create_intake) fn request_id_v1(&self) -> Result<[u8; 16], ResourceReservationErrorV1> {
        self.position()?;
        self.request_id.ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(in crate::controller_resource_reservation::create_intake) fn bundle_v1(&self) -> Result<&[u8], ResourceReservationErrorV1> {
        self.position()?;
        Ok(&self.bundle)
    }

    pub(in crate::controller_resource_reservation::create_intake) fn record_v1(&self) -> Result<&[u8], ResourceReservationErrorV1> {
        self.position()?;
        Ok(&self.pair.record)
    }

    pub(in crate::controller_resource_reservation::create_intake) fn head_v1(&self) -> Result<&[u8; HEAD_BYTES], ResourceReservationErrorV1> {
        self.position()?;
        Ok(&self.pair.head)
    }

    pub(in crate::controller_resource_reservation::create_intake) fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        cause(&self.demand).or_else(|| cause(&self.funding))
            .or_else(|| self.pair.primary_failure()).or_else(|| cause(&self.signature))
            .or_else(|| cause(&self.request_body)).or_else(|| cause(&self.bundle_encoding))
            .or_else(|| cause(&self.body_encoding)).or_else(|| cause(&self.primary))
            .or_else(|| self.pair.post_failure()).or_else(|| cause(&self.validity))
    }
}

fn require_signed_clock_v1(signed: &SignedBrokerPlan, sample: RawPairedClockSample)
    -> Result<(), SignatureVerificationError> {
    require_plan_clock_v1(signed.plan(), sample)
}

fn require_plan_clock_v1(plan: &aos_sandbox_model::BrokerAuthorizationPlan, sample: RawPairedClockSample)
    -> Result<(), SignatureVerificationError> {
    if sample.wall_seconds() < plan.issued_seconds() {
        Err(SignatureVerificationError::NotYetValid)
    } else if sample.wall_seconds() >= plan.expires_seconds() {
        Err(SignatureVerificationError::Expired)
    } else { Ok(()) }
}

pub(super) struct SignedAppendBindingV1<'held> {
    lane: [u8; 16],
    seed: [u8; 32],
    intent: &'held [u8],
    planned: &'held [u8],
    inputs: aos_sandbox_protocol::domain_ledger::create_storage_history::ready::InputsReadyNativeReceiptDataV1<'held>,
    validated: &'held root_validated::RootValidatedOriginalsV1,
    reserved: &'held use_reserved::UseReservedOriginalsV1,
    reservation: &'held UseReservationOriginalsV1,
    admitted: &'held OriginalCreateStorageRootUseAdmittedV1<'held>,
    signed: &'held SignedBrokerPlan,
    body: &'held [u8],
    bundle: &'held [u8],
    request_body: &'held [u8],
    funded: &'held Option<Result<(), ResourceReservationErrorV1>>,
    demand: ResourceVector,
}

impl SignedAppendBindingV1<'_> {
    pub(super) fn predecessor(&self) -> Result<[u8; 32], HistoryErrorV1> {
        let receipt = self.reserved.native_receipt_v1().map_err(|_| HistoryErrorV1::Correlation)?;
        RecordEnvelopeV1::decode(receipt.record, KeyV1::new(self.lane, OwnerV1::Controller, 5)?,
            PhaseV1::new(OwnerV1::Controller, 4)?).map(|record| record.checksum())
    }

    pub(super) fn require_prepaid_v1(&self, demand: ResourceVector) -> Result<(), ResourceReservationErrorV1> {
        if !matches!(self.funded, Some(Ok(()))) { return Err(ResourceReservationErrorV1::Conflict); }
        self.demand.checked_sub(demand)?;
        self.reservation.require_pair_receiving_v1(self.demand)
    }

    pub(super) fn require_clock_v1(&self, sample: RawPairedClockSample) -> Result<(), SignatureVerificationError> {
        require_signed_clock_v1(self.signed, sample)
    }

    pub(super) fn require_successor(&self, parent: &ProjectPreparationReservationAttemptV1,
        intake: &Q04OriginalIntakeAttemptV1, state: &super::super::super::State,
        journal: &Journal, transaction: &JournalTransaction) -> Result<(), JournalError> {
        journal.ensure_healthy()?;
        self.require_state_successor(parent, intake, state, transaction)
    }

    pub(super) fn require_state_successor(&self, parent: &ProjectPreparationReservationAttemptV1,
        intake: &Q04OriginalIntakeAttemptV1, state: &super::super::super::State,
        transaction: &JournalTransaction) -> Result<(), JournalError> {
        let closed = || JournalError::ProtectedBoundary;
        self.reservation.require_current_state_v1(parent, state).map_err(native_error)?;
        require_j_readback_members_v1(intake, state)?;
        let reserved = self.reserved.native_receipt_v1().map_err(native_error)?;
        require_exact_controller_prefix_v1(state, self.lane,
            &[(1, self.intent), (2, self.planned), (3, self.inputs.record),
                (4, self.validated.retained_record_v1().map_err(native_error)?),
                (5, reserved.record)], &reserved.latest_head)?;
        if intake.create_lane().map_err(native_error)? != self.lane { return Err(closed()); }
        let [member, head] = transaction.records() else { return Err(closed()); };
        let key = KeyV1::new(self.lane, OwnerV1::Controller, 6).map_err(|_| closed())?;
        let latest = KeyV1::new(self.lane, OwnerV1::Controller, 0).map_err(|_| closed())?;
        if member.namespace() != crate::RecordNamespace::CreateStorageHistory
            || head.namespace() != crate::RecordNamespace::CreateStorageHistory
            || member.key() != key.encode() || head.key() != latest.encode() {
            return Err(closed());
        }
        let envelope = RecordEnvelopeV1::decode(member.value().ok_or_else(closed)?, key,
            PhaseV1::new(OwnerV1::Controller, 5).map_err(|_| closed())?).map_err(|_| closed())?;
        if envelope.body() != self.body
            || envelope.coordinates().predecessor != self.predecessor().map_err(|_| closed())?
            || envelope.coordinates().correlation != self.seed {
            return Err(closed());
        }
        let parsed = ControllerSignedBodyDataV1::decode(envelope.body(), self.lane,
            self.reservation.request_shape_bytes_v1().map_err(native_error)?).map_err(|_| closed())?;
        let root = self.admitted.receipt_v1().map_err(native_error)?;
        if parsed.admitted.record != root.record || parsed.admitted.latest_head != root.latest_head
            || parsed.admitted.names != root.names || parsed.admitted.after_next != root.after_next
            || parsed.admitted.after_end != root.after_end || parsed.bundle != self.bundle {
            return Err(closed());
        }
        let body = parsed.bundle_data_v1(self.lane, self.reservation.request_shape_bytes_v1()
            .map_err(native_error)?).map_err(|_| closed())?;
        if body.plan != self.signed.canonical_plan() || body.signature != self.signed.canonical_signature()
            || body.request_body != self.request_body {
            return Err(closed());
        }
        let admitted = self.admitted.body_v1().map_err(native_error)?;
        let actual = self.reservation.returned_transition_v1().map_err(native_error)?;
        if admitted.use_claim != actual.claim.native_fields().id
            || admitted.use_reserved != self.predecessor().map_err(|_| closed())? {
            return Err(closed());
        }
        LatestHeadV1::decode(head.value().ok_or_else(closed)?, latest)
            .and_then(|value| value.check_record(latest, envelope)).map_err(|_| closed())
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_model::{AssignmentEpoch, BrokerArgumentCommitment, BrokerAssignment,
        BrokerAudience, BrokerAuthorizationPlan, BrokerGrant, BrokerGrantTarget, BrokerVerb,
        DesiredGeneration, IncarnationId, NodeId, ObjectDigest, ProtocolId,
        ProtocolVersion, RawClockProvenance, RevocationScopeId, SandboxId};
    use aos_sandbox_model::model::{KeyReference, KeyUsage, StableKeyId};

    #[test]
    fn actual_crossing_window_is_inclusive_at_issue_and_exclusive_at_expiry() {
        let assignment = BrokerAssignment::new(SandboxId::from_bytes([1; 16]),
            IncarnationId::from_bytes([2; 16]), AssignmentEpoch::new(1),
            DesiredGeneration::new(1), ObjectDigest::from_bytes([3; 32])).unwrap();
        let owner = KeyReference::new(StableKeyId::new("ownership".to_owned()).unwrap(),
            1, ObjectDigest::from_bytes([4; 32]), KeyUsage::OwnershipLease);
        let grant = BrokerGrant::new(BrokerVerb::StoragePrepareCatalog,
            BrokerGrantTarget::Assignment, BrokerArgumentCommitment::for_canonical_bytes(b"prepare"),
            400, 0).unwrap();
        let plan = BrokerAuthorizationPlan::new(BrokerAudience::Storage,
            ProtocolId::StorageBroker, ProtocolVersion::new(1, 0), assignment,
            NodeId::from_bytes([5; 16]), owner, vec![grant], ObjectDigest::from_bytes([6; 32]),
            RevocationScopeId::from_bytes([7; 16]), 100, 200, Vec::new()).unwrap();
        let sample = |wall| RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted([8; 16]).unwrap(), [9; 16], wall,
            10_000_000_000,
        ).unwrap();

        assert!(require_plan_clock_v1(&plan, sample(100)).is_ok());
        assert!(require_plan_clock_v1(&plan, sample(199)).is_ok());
        assert_eq!(require_plan_clock_v1(&plan, sample(99)), Err(SignatureVerificationError::NotYetValid));
        assert_eq!(require_plan_clock_v1(&plan, sample(200)), Err(SignatureVerificationError::Expired));
    }
}
