//! Retains the concrete components of the same-Session Create Prepare flight.
//!
//! Empty custody and its compiled layout are DATA. The genuine completed U
//! borrower must supply all signing/request/response/currentness admissions;
//! this layout alone cannot sign, send, receive, commit or report completion.

use super::*;

mod request;
mod io;
mod outcome_exchange;
mod outcome;
mod publication_inputs;
pub use publication_inputs::CreateStorageCompletedPreparationDataV1;
use aos_sandbox_protocol::authorization_artifact::SignedBrokerPlan;
use aos_sandbox::journal::broker_session_receiving::StorageCreateUseSecurityShapeDataV1;

/// Owns empty Create Prepare destinations without an authorization factory.
///
/// The common preparation engine retains the actual request and native receipt;
/// the distinct replay destination retains its terminal predecessor. No Session,
/// Journal, key or parsed Root receipt constructs a successful instance.
#[doc(hidden)]
#[must_use = "retain this flight beside the same genuine U and Session originals"]
pub struct OriginalStorageCreatePreparationFlightV1 {
    shared: OriginalStoragePreparationClientFlightV1,
    io: io::CreatePrepareIoOriginalsV1,
    predecessor: Option<Box<crate::recovery::OutcomeCurrentOriginalsV1>>,
    signed_plan: Option<SignedBrokerPlan>,
    request_predecessor_originals: Option<Box<crate::recovery::OutcomeCurrentOriginalsV1>>,
    request_admission: Option<Result<(), aos_sandbox::CreateStorageReadyClosedV1>>,
    request_predecessor: Option<Result<(), BrokerSessionSecurityError>>,
    request_window: Option<Result<(), aos_sandbox_core::SignatureVerificationError>>,
    request_clock: Option<Result<aos_sandbox_core::RawPairedClockSample, aos_sandbox::CreateStorageReadyClosedV1>>,
    request_encoded: Option<Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>>>,
    request_decoded: Option<Result<BrokerRequestEnvelope, buffa::DecodeError>>,
    request_header: Option<Result<aos_proto::aos::sandbox::local::v1::PrepareStorageCatalogRequest, buffa::DecodeError>>,
    request_prepared: Option<bool>,
    request_finish: Option<Result<(), aos_sandbox::CreateStorageReadyClosedV1>>,

    outcome_exchanged: Option<Result<(), outcome_exchange::OutcomeExchangeErrorV1>>,
    recorded_signed: Option<Result<(), aos_sandbox::CreateStorageReadyClosedV1>>,
    recorded_outcome: Option<Result<(), aos_sandbox::CreateStorageReadyClosedV1>>,
    signing: Option<Result<aos_sandbox_broker::prepared_plan_signing::PreparedBrokerPlanSigningV1,
        Box<dyn std::error::Error + Send + Sync>>>,
    admitted: Option<Result<Option<aos_sandbox_protocol::authorization_artifact::BrokerPlanPreparation>,
        Box<dyn std::error::Error + Send + Sync>>>,
    signing_predecessor: Option<Result<(), BrokerSessionSecurityError>>,
    signing_witness_before: Option<bool>,
    signing_witness_after: Option<bool>,
    key_check: Option<Result<(), aos_sandbox_core::SignatureVerificationError>>,
    signing_window: Option<Result<(), aos_sandbox_core::SignatureVerificationError>>,
    signature_completion: Option<Result<(), aos_sandbox_broker::prepared_plan_signing::PreparedBrokerPlanCompletionErrorV1>>,
    raw_signature: Option<aos_sandbox_core::model::SignatureBytes>,
    sizing: Option<Result<aos_sandbox_protocol::authorization_artifact::StorageCreatePlanPreparationDataV1,
        Box<dyn std::error::Error + Send + Sync>>>,
    use_first: Option<UsePreparationFailureV1>,
    unsigned: Option<BrokerRequestEnvelope>,
    native: [Option<Result<(), OutputPreparationClosedV1>>; 8],
    security: [Option<Result<(), BrokerSessionSecurityError>>; 4],
    first_native: Option<usize>,
    complete: bool,
}

impl OriginalStorageCreatePreparationFlightV1 {
    /// Constructs inert empty custody without allocation or IO.
    #[doc(hidden)]
    #[must_use]
    pub fn empty() -> Self {
        Self {
            shared: OriginalStoragePreparationClientFlightV1::empty(),
            io: Default::default(), predecessor: None,
            request_predecessor_originals: None, request_admission: None,
            request_predecessor: None, request_window: None, request_clock: None, request_encoded: None,
            request_decoded: None, request_header: None, request_prepared: None, request_finish: None,
            signed_plan: None, outcome_exchanged: None, recorded_signed: None, recorded_outcome: None, signing: None, admitted: None, signing_predecessor: None, signing_witness_before: None, signing_witness_after: None,
            key_check: None, signing_window: None, signature_completion: None, raw_signature: None, sizing: None, use_first: None, unsigned: None,
            native: std::array::from_fn(|_| None),
            security: std::array::from_fn(|_| None),
            first_native: None, complete: false,
        }
    }
}

/// Returns actual compiled Create flight component geometry as passive DATA.
///
/// This no-argument supplier observes no Session, policy, account or native
/// owner and admits no work. Dynamic plan/signature/body/history and later
/// transfer/terminal obligations belong to their separate common suppliers.
#[doc(hidden)]
#[must_use]
pub fn original_create_storage_use_security_shape_v1()
    -> Option<StorageCreateUseSecurityShapeDataV1>
{
    let (replay_bytes, _) = crate::recovery::OutcomeCurrentOriginalsV1::boxed_receiving_footprint_v2()?;
    Some(StorageCreateUseSecurityShapeDataV1 {
        actual_flight_bytes: std::mem::size_of::<OriginalStorageCreatePreparationFlightV1>(),
        actual_construction_bytes: super::storage_inventory::wait::InventoryWaitOriginalsV1::<aos_sandbox::CreateStorageInventoryClosedV1>::
            receiving_construction_bytes_v1()?
            .checked_add(aos_sandbox_broker::prepared_plan_signing::PreparedBrokerPlanSigningV1::
                receiving_construction_bytes_v1()?)?,
        actual_failure_bytes: replay_bytes.checked_mul(3)?,
        // Each earlier positive native endpoint prefix is disposed before
        // the next capsule; failure prevents the later stage from entering.
        actual_endpoint_open_files: crate::recovery::OutcomeCurrentOriginalsV1::
            retained_endpoint_open_files_v1()?,
    })
}

#[derive(Clone, Copy)]
enum UsePreparationFailureV1 {
    Native, Security, Plan, Closed, SigningNative, SigningSecurity, OutcomeExchange, OutcomeNative, OutcomeShared,
    IoNative, IoShared, IoWait, IoPredecessor, IoResponse, IoRejected, IoProjection,
    RequestNative, RequestClock, RequestPredecessor, RequestWindow, RequestEnvelope, RequestDecode, RequestHeader, RequestShared,
    SigningPredecessor, Admitted, Carrier, Key, Window, SignatureCompletion, SigningWitness,
}

impl OriginalStorageCreatePreparationFlightV1 {
    pub(crate) fn reserve_use_once(&mut self, session: &mut DormantAuthenticatedBrokerSessionV1,
        ready: &mut aos_sandbox::OriginalCreateStorageReadyV1<'_, '_>,
        bundle: &OriginalStorageReadyBundleFlightV1,
        authority: &aos_sandbox_protocol::authorization_artifact::SigningAuthority,
        scope: aos_sandbox_core::RevocationScopeId,
    ) -> bool {
        if self.native[0].is_some() || self.use_first.is_some() || self.shared.inner.closed {
            return self.close_use(UsePreparationFailureV1::Closed);
        }
        let Some(bytes) = bundle.encoded_bundle_v1() else {
            return self.close_use(UsePreparationFailureV1::Closed);
        };
        self.native[0] = Some(ready.produce_root_validated_once().map_err(|_| OutputPreparationClosedV1));
        if !matches!(self.native[0], Some(Ok(()))) { return self.close_use(UsePreparationFailureV1::Native); }
        self.native[1] = Some(ready.admit_storage_use_plan_once(bytes, authority).map_err(|_| OutputPreparationClosedV1));
        if !matches!(self.native[1], Some(Ok(()))) { return self.close_use(UsePreparationFailureV1::Native); }
        self.security[0] = Some(session.require_negotiated_client_method(
            BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG).and_then(|()| {
                if aos_sandbox_broker_session_protocol::profile::is_storage_preparation_transcript_v1(&session.transcript) {
                    Ok(())
                } else { Err(BrokerSessionSecurityError::Currentness) }
            }));
        if !matches!(self.security[0], Some(Ok(()))) { return self.close_use(UsePreparationFailureV1::Security); }
        let Some(proposed) = bundle.proposed_for_create_use_v1() else {
            return self.close_use(UsePreparationFailureV1::Closed);
        };
        self.sizing = Some((|| {
            let original = ready.borrow_storage_use_plan_inputs_v1()?;
            // This separate model is never signed or used as policy authority.
            // Shared normalization makes both time integers maximum-width.
            aos_sandbox_protocol::authorization_artifact::prepare_storage_create_plan_v1(
                proposed, original.policy_digest, original.lease, original.sizing_clock,
                original.cutoff, i64::MAX, authority.clone(), scope)
        })());
        let Some(Ok(sizing)) = self.sizing.as_ref() else { return self.close_use(UsePreparationFailureV1::Plan); };
        let Some(shape) = original_create_storage_use_security_shape_v1() else {
            return self.close_use(UsePreparationFailureV1::Closed);
        };
        self.native[2] = Some(match session.owner.retained_storage_client_journal_v1() {
            Ok(journal) => ready.reserve_storage_use_once(journal, &session.socket,
                &session.transcript, bytes, sizing.request_shape.len(), shape).map_err(|_| OutputPreparationClosedV1),
            Err(cause) => {
                self.shared.inner.protected_failure = Some(cause);
                self.use_first = Some(UsePreparationFailureV1::Security);
                Err(OutputPreparationClosedV1)
            }
        });
        if !matches!(self.native[2], Some(Ok(()))) { return self.close_use(UsePreparationFailureV1::Native); }
        self.native[3] = Some(ready.produce_use_reserved_once().map_err(|_| OutputPreparationClosedV1));
        if !matches!(self.native[3], Some(Ok(()))) { return self.close_use(UsePreparationFailureV1::Native); }
        true
    }

    fn close_use(&mut self, site: UsePreparationFailureV1) -> bool {
        self.use_first.get_or_insert(site);
        if matches!(self.use_first, Some(UsePreparationFailureV1::Closed)) {
            self.native[7].get_or_insert(Err(OutputPreparationClosedV1));
        }
        self.shared.inner.closed = true;
        false
    }

    pub(crate) fn use_failure_with_ready<'a>(&'a self, session: &'a DormantAuthenticatedBrokerSessionV1,
        ready: &'a aos_sandbox::OriginalCreateStorageReadyV1<'_, '_>,
    ) -> Option<&'a (dyn std::error::Error + 'static)> {
        let Some(first) = self.use_first else {
            return ready.original_storage_signing_failure_v1().or_else(|| ready.failure());
        };
        match first {
            UsePreparationFailureV1::OutcomeExchange => self.outcome_exchange_failure_v1(ready),
            UsePreparationFailureV1::OutcomeNative => ready.storage_use_original_failure_v1()
                .or_else(|| ready.original_root_exchange_failure())
                .or_else(|| self.recorded_outcome.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)),
            UsePreparationFailureV1::OutcomeShared => self.shared.failure_with_session(session),
            UsePreparationFailureV1::IoNative => ready.storage_use_original_failure_v1()
                .or_else(|| ready.original_root_exchange_failure())
                .or_else(|| self.io.native_failure()),
            UsePreparationFailureV1::IoShared => self.shared.failure_with_session(session),
            UsePreparationFailureV1::IoWait => self.io.wait.failure_with_native(
                ready.storage_use_original_failure_v1().or_else(|| ready.original_root_exchange_failure())),
            UsePreparationFailureV1::IoPredecessor => self.io.predecessor_originals
                .as_deref()
                .and_then(|originals| originals.failure())
                .or_else(|| self.io.predecessor.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)),
            UsePreparationFailureV1::IoProjection => self.io.projection.as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as _),
            UsePreparationFailureV1::IoRejected => self.io.rejected.as_ref().map(|cause| cause as _),
            UsePreparationFailureV1::IoResponse => self.io.response.as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as _),
            UsePreparationFailureV1::RequestNative => ready.storage_use_original_failure_v1()
                .or_else(|| ready.original_root_exchange_failure())
                .or_else(|| self.request_admission.as_ref().and_then(|r| r.as_ref().err()).map(|cause| cause as _))
                .or_else(|| self.request_finish.as_ref().and_then(|r| r.as_ref().err()).map(|cause| cause as _))
                .or_else(|| self.request_clock.as_ref().and_then(|r| r.as_ref().err()).map(|cause| cause as _)),
            UsePreparationFailureV1::RequestClock => self.request_clock.as_ref().and_then(|r| r.as_ref().err()).map(|cause| cause as _),
            UsePreparationFailureV1::RequestPredecessor => self.request_predecessor_originals
                .as_deref()
                .and_then(|originals| originals.failure())
                .or_else(|| self.request_predecessor.as_ref().and_then(|r| r.as_ref().err()).map(|cause| cause as _)),
            UsePreparationFailureV1::RequestWindow => self.request_window.as_ref().and_then(|r| r.as_ref().err()).map(|cause| cause as _),
            UsePreparationFailureV1::RequestEnvelope => self.request_encoded.as_ref().and_then(|r| r.as_ref().err()).map(|cause| cause.as_ref() as &(dyn std::error::Error + 'static)),
            UsePreparationFailureV1::RequestDecode => self.request_decoded.as_ref().and_then(|r| r.as_ref().err()).map(|cause| cause as _),
            UsePreparationFailureV1::RequestHeader => self.request_header.as_ref().and_then(|r| r.as_ref().err()).map(|cause| cause as _),
            UsePreparationFailureV1::RequestShared => self.shared.failure_with_session(session),
            UsePreparationFailureV1::Native => ready.storage_use_original_failure_v1()
                .or_else(|| self.native.iter().find_map(|result| result.as_ref()
                    .and_then(|result| result.as_ref().err()).map(|cause| cause as _))),
            UsePreparationFailureV1::Security => self.security[0].as_ref().and_then(|r| r.as_ref().err())
                .map(|cause| cause as _).or_else(|| self.shared.failure_with_session(session)),
            UsePreparationFailureV1::Plan => self.sizing.as_ref().and_then(|r| r.as_ref().err()).map(|cause| cause.as_ref() as &(dyn std::error::Error + 'static)),
            UsePreparationFailureV1::SigningNative => ready.original_storage_signing_failure_v1()
                .or_else(|| ready.failure()),
            UsePreparationFailureV1::SigningSecurity => {
                let returned = self.security[1..3].iter().find_map(|result|
                    result.as_ref().and_then(|result| result.as_ref().err()))
                    .or_else(|| self.shared.inner.protected_failure.as_ref())?;
                session.owner.retained_revalidation_failure_for(returned)
                    .or_else(|| session.owner.retained_storage_floor_revalidation_failure_for(returned))
                    .or(Some(returned as _))
            }
            UsePreparationFailureV1::SigningWitness => session.output_witness_failure()
                .or_else(|| self.native[7].as_ref().and_then(|result| result.as_ref().err())
                    .map(|cause| cause as _)),
            UsePreparationFailureV1::SigningPredecessor => self.predecessor
                .as_deref()
                .and_then(|originals| originals.failure())
                .or_else(|| self.signing_predecessor.as_ref().and_then(|result| result.as_ref().err())
                    .map(|cause| cause as _)),
            UsePreparationFailureV1::Admitted => self.admitted.as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause.as_ref() as &(dyn std::error::Error + 'static)),
            UsePreparationFailureV1::Carrier => self.signing.as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause.as_ref() as &(dyn std::error::Error + 'static)),
            UsePreparationFailureV1::Key => self.key_check.as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as _),
            UsePreparationFailureV1::Window => self.signing_window.as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as _),
            UsePreparationFailureV1::SignatureCompletion => self.signature_completion.as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as _),
            UsePreparationFailureV1::Closed => self.native[7].as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as _),
        }
    }
}


impl OriginalStorageCreatePreparationFlightV1 {
    pub(crate) fn prepare_admitted_plan_once(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        original: &mut aos_sandbox::OriginalCreateStorageUseSigningV1<'_, '_, '_>,
        bundle: &OriginalStorageReadyBundleFlightV1,
        inventory: &OriginalStorageInventoryClientFlightV1,
        authority: &aos_sandbox_protocol::authorization_artifact::SigningAuthority,
        scope: aos_sandbox_core::RevocationScopeId,
    ) -> Option<aos_sandbox_protocol::authorization_artifact::BrokerPlanPreparation> {
        if self.use_first.is_some()
            || self.admitted.is_some()
            || self.shared.inner.closed
            || self.predecessor.is_some()
            || self.request_predecessor_originals.is_some()
            || self.io.predecessor_originals.is_some()
        {
            self.close_use(UsePreparationFailureV1::Closed);
            return None;
        }

        let Some(endpoint) = crate::endpoint::endpoint_revalidation_footprint_v1() else {
            self.close_use(UsePreparationFailureV1::Closed);
            return None;
        };
        self.native[4] = Some(match session.owner.retained_storage_client_journal_v1() {
            Ok(journal) => original.admit_original_session_predecessor_once(journal, endpoint)
                .map_err(|_| OutputPreparationClosedV1),
            Err(cause) => {
                self.shared.inner.protected_failure = Some(cause);
                self.use_first = Some(UsePreparationFailureV1::SigningSecurity);
                Err(OutputPreparationClosedV1)
            }
        });
        if !matches!(self.native[4], Some(Ok(()))) {
            self.close_use(UsePreparationFailureV1::SigningNative);
            return None;
        }
        self.security[1] = Some((|| {
            original.require_original_session_predecessor_prepaid_v1()
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            session.owner.require_original_storage_revalidation_healthy()?;
            if !session.owner.healthy_original_storage_floor_revalidation_v1() {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            Ok(())
        })());
        if !matches!(self.security[1], Some(Ok(()))) {
            self.close_use(UsePreparationFailureV1::SigningSecurity);
            return None;
        }

        // Only the genuine U signing borrower reaches this point after its
        // full fixed funding and purpose checks. All three distinct future
        // predecessors were checked empty before allocating the first leaf.
        self.predecessor = Some(Box::new(Default::default()));
        self.request_predecessor_originals = Some(Box::new(Default::default()));
        self.io.predecessor_originals = Some(Box::new(Default::default()));

        self.signing_predecessor = Some(
            self.predecessor
                .as_deref_mut()
                .ok_or(BrokerSessionSecurityError::Currentness)
                .and_then(|originals| inventory.compare_bundle_predecessor_v1(session, originals)),
        );
        if !matches!(self.signing_predecessor, Some(Ok(()))) {
            self.close_use(UsePreparationFailureV1::SigningPredecessor);
            return None;
        }
        self.admitted = Some((|| {
            let protected = bundle.proposed_for_create_use_v1().ok_or(OutputPreparationClosedV1)?;
            let inputs = original.inputs_v1()?;
            let preparation = aos_sandbox_protocol::authorization_artifact::
                prepare_admitted_storage_create_plan_v1(
                    protected, inputs.policy_digest, inputs.lease, inputs.clock,
                    inputs.cutoff, authority.clone(), scope, inputs.plan, inputs.statement,
                )?;
            Ok(Some(preparation))
        })());
        match self.admitted.as_mut() {
            Some(Ok(preparation)) => preparation.take(),
            _ => {
                self.close_use(UsePreparationFailureV1::Admitted);
                None
            }
        }
    }

    pub(crate) fn sign_admitted_plan_once(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        original: &mut aos_sandbox::OriginalCreateStorageUseSigningV1<'_, '_, '_>,
        carrier: Result<aos_sandbox_broker::prepared_plan_signing::PreparedBrokerPlanSigningV1,
            Box<dyn std::error::Error + Send + Sync>>,
    ) -> bool {
        if self.use_first.is_some() || self.signing.is_some() || self.raw_signature.is_some()
            || !matches!(self.admitted, Some(Ok(None))) {
            return self.close_use(UsePreparationFailureV1::Closed);
        }
        // The real constructor ran first. Its whole cause must precede a
        // later peer/witness refusal, and no entered native stage is reset.
        self.signing = Some(carrier);
        if !matches!(self.signing, Some(Ok(_))) {
            return self.close_use(UsePreparationFailureV1::Carrier);
        }
        self.security[2] = Some((|| {
            let inputs = original.inputs_v1().map_err(|_| BrokerSessionSecurityError::Currentness)?;
            let carrier = self.signing.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(BrokerSessionSecurityError::Currentness)?;
            let preparation = carrier.preparation().ok_or(BrokerSessionSecurityError::Currentness)?;
            if preparation.canonical_plan() != inputs.plan
                || preparation.signing_request().canonical_statement() != inputs.statement {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            Ok(())
        })());
        if !matches!(self.security[2], Some(Ok(()))) {
            return self.close_use(UsePreparationFailureV1::SigningSecurity);
        }
        self.signing_witness_before = Some(session.revalidate_output_witnesses());
        if self.signing_witness_before != Some(true) {
            self.native[7].get_or_insert(Err(OutputPreparationClosedV1));
            self.close_use(UsePreparationFailureV1::SigningWitness);
        }
        let signed = self.use_first.is_none() && self.sign_admitted_plan_inner(original);
        // This actual same Session post remains owed after key/time/signature
        // failure. Its resident native cause never replaces the earlier site.
        self.signing_witness_after = Some(session.revalidate_output_witnesses());
        if self.signing_witness_after != Some(true) {
            self.native[7].get_or_insert(Err(OutputPreparationClosedV1));
            self.close_use(UsePreparationFailureV1::SigningWitness);
        }
        signed && self.use_first.is_none()
    }

    fn sign_admitted_plan_inner(
        &mut self,
        original: &mut aos_sandbox::OriginalCreateStorageUseSigningV1<'_, '_, '_>,
    ) -> bool {
        let Some(Ok(carrier)) = self.signing.as_ref() else {
            return self.close_use(UsePreparationFailureV1::Closed);
        };
        let Some(preparation) = carrier.preparation() else {
            return self.close_use(UsePreparationFailureV1::Closed);
        };
        let statement = preparation.signing_request().statement();
        // The key-message loan performs the unchanged Core fingerprint check.
        // Its actual error stays resident, distinct from later currentness debt.
        let key = match carrier.key_message_loan() {
            Ok(key) => { self.key_check = Some(Ok(())); key }
            Err(cause) => {
                self.key_check = Some(Err(cause));
                return self.close_use(UsePreparationFailureV1::Key);
            }
        };
        let clock = match original.final_clock_once() {
            Ok(clock) => clock,
            Err(_) => {
                self.native[6] = Some(Err(OutputPreparationClosedV1));
                return self.close_use(UsePreparationFailureV1::SigningNative);
            }
        };
        self.signing_window = Some(if clock.wall_seconds() < statement.issued_seconds() {
            Err(aos_sandbox_core::SignatureVerificationError::NotYetValid)
        } else if !statement.expires_seconds().is_some_and(|expires| clock.wall_seconds() < expires) {
            Err(aos_sandbox_core::SignatureVerificationError::Expired)
        } else { Ok(()) });
        if !matches!(self.signing_window, Some(Ok(()))) {
            return self.close_use(UsePreparationFailureV1::Window);
        }
        // No native effect occurs between that final retained clock and sign.
        // Store raw bytes before completion or any independently owed post.
        self.raw_signature = Some(key.sign());
        let signature = self.raw_signature.as_ref();
        let carrier = self.signing.as_mut().and_then(|result| result.as_mut().ok());
        let (Some(signature), Some(carrier)) = (signature, carrier) else {
            return self.close_use(UsePreparationFailureV1::Closed);
        };
        match carrier.complete_once(signature, clock.wall_seconds()) {
            Ok(signed) => {
                self.signed_plan = Some(signed);
                self.signature_completion = Some(Ok(()));
                true
            }
            Err(cause) => {
                self.signature_completion = Some(Err(cause));
                self.close_use(UsePreparationFailureV1::SignatureCompletion)
            }
        }
    }

    pub(crate) fn finish_native_signing_once(&mut self,
        ready: &aos_sandbox::OriginalCreateStorageReadyV1<'_, '_>,
    ) -> bool {
        if self.native[5].is_some() {
            return self.close_use(UsePreparationFailureV1::Closed);
        }
        self.native[5] = Some(ready.require_original_storage_signing_complete_v1()
            .map_err(|_| OutputPreparationClosedV1));
        if !matches!(self.native[5], Some(Ok(()))) {
            return self.close_use(UsePreparationFailureV1::SigningNative);
        }
        self.use_first.is_none() && self.signed_plan.is_some()
            && matches!(self.signature_completion, Some(Ok(())))
    }
}


#[cfg(test)]
mod create_signing_cause_tests {
    use super::*;

    #[test]
    fn actual_carrier_error_precedes_later_signing_witness_and_native_post_debt() {
        let mut flight = OriginalStorageCreatePreparationFlightV1::empty();
        flight.signing = Some(Err(Box::new(aos_sandbox_core::SignatureVerificationError::
            PublicKeyFingerprintMismatch)));
        flight.close_use(UsePreparationFailureV1::Carrier);

        flight.signing_witness_after = Some(false);
        flight.native[5] = Some(Err(OutputPreparationClosedV1));
        flight.close_use(UsePreparationFailureV1::SigningWitness);
        flight.close_use(UsePreparationFailureV1::SigningNative);

        assert!(matches!(flight.use_first, Some(UsePreparationFailureV1::Carrier)));
        let cause = flight.signing.as_ref().unwrap().as_ref().err().unwrap();
        assert_eq!(cause.downcast_ref::<aos_sandbox_core::SignatureVerificationError>(),
            Some(&aos_sandbox_core::SignatureVerificationError::PublicKeyFingerprintMismatch));
    }
}


impl OriginalStorageCreatePreparationFlightV1 {
    pub(crate) fn record_signed_once(&mut self,
        ready: &mut aos_sandbox::OriginalCreateStorageReadyV1<'_, '_>,
        bundle: &OriginalStorageReadyBundleFlightV1,
    ) -> bool {
        if self.use_first.is_some() || self.recorded_signed.is_some() || self.shared.inner.closed
            || !matches!(self.native[5], Some(Ok(())))
            || !matches!(self.signature_completion, Some(Ok(()))) {
            return self.close_use(UsePreparationFailureV1::Closed);
        }
        let (Some(signed), Some(protected)) =
            (self.signed_plan.as_ref(), bundle.proposed_for_create_use_v1()) else {
            return self.close_use(UsePreparationFailureV1::Closed);
        };
        self.recorded_signed = Some(ready.produce_original_storage_signed_once(signed, protected));
        if !matches!(self.recorded_signed, Some(Ok(()))) {
            return self.close_use(UsePreparationFailureV1::Native);
        }
        true
    }
}
