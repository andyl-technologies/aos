//! Retains actual Create Apply normalization and immutable publication issuance.
//!
//! The destination is inert until a genuine completed intake, active C23 and
//! same retained Root client jointly admit it. Every fallible model constructor
//! keeps its original inputs beside its whole Result. This owner neither opens
//! a Journal nor dispatches Storage; the actual Core/Session engines do that.

use std::error::Error;

use aos_sandbox_core::{BrokerAudience, BrokerGrantTarget, BrokerVerb, ObjectDigest,
    OperationId, ResourceDimension as D, ResourceId, ResourceVector, Revision};
use aos_sandbox_protocol::authorization_artifact::{BrokerPlanPreparation, SignedBrokerPlan,
    SigningAuthority};
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodResultV1};
use aos_sandbox_protocol::domain_ledger::provisioning_resources::{
    ProvisioningModeDataV1, ProvisioningResourceFieldsV1, ProvisioningResourceRecordsV1,
    provisioning_public_request_digest_v1};
use aos_sandbox_protocol::semantics::{ProtectedStorageCreateApplyDataV1,
    ProtectedStorageCreatePreparationV1};
use aos_sandbox_protocol::publication::{self, bind_authority_publication_effect};
use buffa::Message as _;
use rand::TryRngCore as _;
use sha2::{Digest as _, Sha256};

use crate::controller_resource_reservation::{OriginalCreateProvisioningRootLoanV1, ResourceReservationErrorV1};
use crate::normal_root::{RootStorageApplyAdmissionOriginalV1, RootStorageApplyClientOriginalV1,
    RootStorageApplyConstructionTurnV1};
use crate::{AuthorityPublicationDraftV1, BrokerDispatchSemanticIdentityV1,
    BrokerDispatchTemplateV1, IdempotencyKey, Journal, OperationPlan,
    PreparedAuthorityPublicationV1};
use crate::runtime_authority::RuntimeAuthorityIntentV1;
use super::action::{OriginalPublicationActionV1, OriginalPublicationActionConstructionFailureV1};

type Cause = Box<dyn Error + Send + Sync>;

/// Reports refusal while the actual issuing destination retains its causes.
#[doc(hidden)]
#[derive(Debug, thiserror::Error)]
#[error("the original Storage Apply issuance is closed")]
pub struct OriginalStorageApplyIssuanceClosedV1;

#[derive(Clone, Copy)]
enum First { ResponseShape, Admission, Entropy, Preparation, Models, Closed }

/// Owns the actual model-construction prefix before any publication Core turn.
#[doc(hidden)]
pub struct OriginalStorageApplyIssuanceV1 {
    parent: Option<OperationId>,
    entry: Option<Result<(), ResourceReservationErrorV1>>,
    model_entry: Option<Result<(), ResourceReservationErrorV1>>,
    complete: ResourceVector,
    funding_original: bool,
    root_admission: Option<[u8; 32]>,
    input_check: Option<Result<(), Cause>>,
    entropy: [u8; 64],
    entropy_result: Option<Result<(), rand::rand_core::OsError>>,
    response_shape: Option<Result<u32, buffa::EncodeError>>,
    response_encoding: Option<Vec<u8>>,
    normalization: Option<Result<BrokerPlanPreparation, Cause>>,
    body: Option<Result<Vec<u8>, Cause>>,
    signed: Option<SignedBrokerPlan>,
    signature_check: Option<Result<SignedBrokerPlan,
        aos_sandbox_protocol::authorization_artifact::AuthorizationPreparationError>>,
    template: Option<Result<BrokerDispatchTemplateV1, Cause>>,
    draft: Option<Result<AuthorityPublicationDraftV1, Cause>>,
    prepared: Option<Result<PreparedAuthorityPublicationV1, Cause>>,
    records: Option<Result<ProvisioningResourceRecordsV1, Cause>>,
    plan: Option<Result<OperationPlan, Cause>>,
    action: Option<Result<OriginalPublicationActionV1,
        OriginalPublicationActionConstructionFailureV1>>,
    first: Option<First>,
    closed: Option<OriginalStorageApplyIssuanceClosedV1>,
}

impl OriginalStorageApplyIssuanceV1 {
    /// Creates only an inert destination, before the actual C23 admission.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            parent: None,
            entry: None,
            model_entry: None,
            complete: ResourceVector::ZERO,
            funding_original: false,
            root_admission: None,
            input_check: None,
            entropy: [0; 64],
            entropy_result: None,
            response_shape: None,
            response_encoding: None,
            normalization: None,
            body: None,
            signed: None,
            signature_check: None,
            template: None,
            draft: None,
            prepared: None,
            records: None,
            plan: None,
            action: None,
            first: None,
            closed: None,
        }
    }

    /// Borrows the first actual refusal without disposing an issuing prefix.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::ResponseShape => self.response_shape.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Admission => self.entry.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Entropy => self.entropy_result.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Preparation => self.input_check.as_ref().and_then(|value| value.as_ref().err())
                .map(|cause| cause.as_ref() as _)
                .or_else(|| self.body.as_ref()?.as_ref().err().map(|cause| cause.as_ref() as _))
                .or_else(|| self.normalization.as_ref().and_then(|value| value.as_ref().err())
                    .map(|cause| cause.as_ref() as _)),
            First::Models => self.signature_check.as_ref().and_then(|value| value.as_ref().err())
                .map(|cause| cause as &(dyn Error + 'static))
                .or_else(|| self.model_entry.as_ref().and_then(|value| value.as_ref().err())
                .map(|cause| cause as &(dyn Error + 'static)))
                .or_else(|| self.template.as_ref().and_then(|value| value.as_ref().err())
                .map(|cause| cause.as_ref() as _))
                .or_else(|| self.draft.as_ref()?.as_ref().err().map(|cause| cause.as_ref() as _))
                .or_else(|| self.prepared.as_ref()?.as_ref().err().map(|cause| cause.as_ref() as _))
                .or_else(|| self.records.as_ref()?.as_ref().err().map(|cause| cause.as_ref() as _))
                .or_else(|| self.plan.as_ref()?.as_ref().err().map(|cause| cause.as_ref() as _))
                .or_else(|| self.action.as_ref()?.as_ref().err().map(|cause| cause as _))
                .or_else(|| self.closed.as_ref().map(|cause| cause as _)),
            First::Closed => self.closed.as_ref().map(|cause| cause as _),
        }
    }

    /// Borrows the same actual C debit cause only when that debit selected it.
    #[must_use]
    pub fn failure_with_original_v1<'cause>(&'cause self,
        original: &'cause crate::CreateProvisioningOriginalsV1,
    ) -> Option<&'cause (dyn Error + 'static)> {
        if self.funding_original
            && matches!(self.first, Some(First::Admission | First::Models))
            && self.parent.is_some_and(|parent| original.belongs_to_operation_v1(parent)) {
            original.failure().or_else(|| self.failure())
        } else { self.failure() }
    }

    fn refuse<T>(&mut self) -> Result<T, OriginalStorageApplyIssuanceClosedV1> {
        self.closed.get_or_insert(OriginalStorageApplyIssuanceClosedV1);
        self.first.get_or_insert(First::Closed);
        Err(OriginalStorageApplyIssuanceClosedV1)
    }
}

impl Default for OriginalStorageApplyIssuanceV1 {
    fn default() -> Self { Self::new() }
}

impl OriginalStorageApplyIssuanceV1 {
    /// Prepares the independently admitted Apply recipe under the actual C23.
    ///
    /// This is once-only. The original completed intake and retained Root client
    /// establish all authority; the explicit protocol operands are compared to
    /// that same authenticated Prepare before the shared unsigned normalizer.
    ///
    /// # Errors
    /// Retains the actual financial, entropy, input or normalization refusal.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_once_v1(
        &mut self,
        original: &mut OriginalCreateProvisioningRootLoanV1<'_, '_>,
        controller: &Journal,
        client: &RootStorageApplyClientOriginalV1,
        proposed: &ProtectedStorageCreatePreparationV1,
        ready_bytes: &[u8],
        specification: &[u8],
        outcome: &AuthenticatedBrokerMethodOutcomeV1,
        response: &aos_proto::aos::sandbox::local::v1::PrepareStorageCatalogResponse,
        authority: &SigningAuthority,
        scope: aos_sandbox_core::RevocationScopeId,
        co_resident: ResourceVector,
    ) -> Result<(), OriginalStorageApplyIssuanceClosedV1> {
        if self.parent.is_some() || self.first.is_some() { return self.refuse(); }
        self.parent = Some(original.parent_operation_v1());
        self.response_shape = Some(response.try_encoded_len());
        if !matches!(self.response_shape, Some(Ok(_))) {
            self.first = Some(First::ResponseShape);
            return Err(OriginalStorageApplyIssuanceClosedV1);
        }
        self.entry = Some((|| {
            original.require_current_v1(controller)?;
            original.require_storage_apply_inputs_v1(controller, ready_bytes, outcome)?;
            let completed = original.completed_original_v1();
            let (manifest, _, _) = completed.publication_material_v1()?;
            let exact_response_bytes = match outcome.result() {
                AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } => exact_body.len(),
                _ => return Err(ResourceReservationErrorV1::Conflict),
            };
            // A foreign typed response cannot enlarge its encoding allocation
            // beyond the actual already-authenticated body before comparison.
            if self.response_shape.as_ref().and_then(|shape| shape.as_ref().ok())
                .and_then(|bytes| usize::try_from(*bytes).ok()) != Some(exact_response_bytes) {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            let response_bytes = outcome.canonical_packet().len();
            let body = ProtectedStorageCreateApplyDataV1::encoded_body_bytes_from_lengths_v1(
                proposed, manifest.canonical_bytes().len(), specification.len(),
            ).map_err(|_| ResourceReservationErrorV1::Conflict)?;
            let admission = client.borrow_admission_v1(original, controller)
                .map_err(|_| ResourceReservationErrorV1::Conflict)?;
            let reply = admission.reply_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?;
            let raw = reply.canonical_plan.len().checked_add(reply.canonical_statement.len())
                .and_then(|size| size.checked_add(usize::try_from(authority.policy_descriptor().encoded_size()).ok()?))
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            let (authorization, _) = aos_sandbox_core::format::authorization_capture::
                authorization_artifact_dynamic_footprint_v1(raw)
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            let (metadata, _) = aos_sandbox_protocol::semantics::storage::
                workspace_metadata_receiving_obligations_v1(
                    manifest.canonical_bytes().len(), specification.len(),
                ).ok_or(ResourceReservationErrorV1::Conflict)?;
            let accepted = aos_sandbox_protocol::domain_ledger::effect_history::
                effect_decoding_receiving_bytes_v1(completed.accepted_context_v1()?.len())
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            // Four actual body planes cover protobuf assembly, retained
            // template, the normalization decode/encode overlap and its
            // deadline-injected copy. Fixed protobuf carriers are separate.
            let lookup = aos_sandbox_protocol::public_api::projection::PROJECTION_KEY_PREFIX.len()
                .checked_add(1 + 16)
                .and_then(|size| size.checked_add(std::mem::size_of::<Vec<u8>>()))
                .and_then(|size| size.checked_mul(2))
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            let bytes = std::mem::size_of::<Self>().checked_mul(2)
                .and_then(|size| size.checked_add(lookup))
                .and_then(|size| size.checked_add(body.checked_mul(4)?))
                .and_then(|size| size.checked_add(response_bytes.checked_mul(2)?))
                .and_then(|size| size.checked_add(accepted))
                .and_then(|size| size.checked_add(aos_sandbox_broker::prepared_plan_signing::
                    PreparedBrokerPlanSigningV1::receiving_construction_bytes_v1()?))
                .and_then(|size| size.checked_add(std::mem::size_of::<
                    aos_proto::aos::sandbox::local::v1::ApplyStorageRequest>().checked_mul(2)?))
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            let bytes = u64::try_from(bytes).map_err(|_| ResourceReservationErrorV1::Conflict)?
                .checked_add(authorization).and_then(|size| size.checked_add(u64::try_from(metadata).ok()?))
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            let named = publication::assignment_decoding_namespace_entries_v1(raw)
                .and_then(|rows| u64::try_from(rows).ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            let complete = co_resident.checked_add(client.active_turn_receiving_demand_v1()?)?
                .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes)
                    .with(D::MetadataEntries, named))?;
            self.complete = complete;
            let debit = original.require_complete_v1(controller, complete);
            if debit.is_err() && original.failure_v1().is_some() { self.funding_original = true; }
            debit
        })());
        if !matches!(self.entry, Some(Ok(()))) {
            self.first = Some(First::Admission);
            return Err(OriginalStorageApplyIssuanceClosedV1);
        }
        self.entropy_result = Some(rand::rngs::OsRng.try_fill_bytes(&mut self.entropy));
        if !matches!(self.entropy_result, Some(Ok(()))) {
            self.first = Some(First::Entropy);
            return Err(OriginalStorageApplyIssuanceClosedV1);
        }
        self.input_check = Some((|| -> Result<(), Cause> {
            let completed = original.completed_original_v1();
            let (manifest, _, _) = completed.publication_material_v1()?;
            let decoded = outcome.request().storage_create_preparation_data_v1()
                .ok_or(OriginalStorageApplyIssuanceClosedV1)?;
            if !proposed.matches_decoded(decoded) || proposed.operation_id() != completed.operation_v1()
                || manifest.broker_assignment()? != proposed.assignment()
                || response.operation_id.as_slice() != completed.operation_v1().as_bytes() {
                return Err(Box::new(OriginalStorageApplyIssuanceClosedV1));
            }
            self.response_encoding = Some(response.encode_to_vec());
            if !matches!(outcome.result(), AuthenticatedBrokerMethodResultV1::Success { exact_body, .. }
                if Some(exact_body.as_slice()) == self.response_encoding.as_deref()) {
                return Err(Box::new(OriginalStorageApplyIssuanceClosedV1));
            }
            // Exact Ready association was checked by the completed intake above.
            // Its specification is borrowed from that same framing, not supplied
            // independently by the caller as an authority-bearing object.
            let ready = aos_sandbox_protocol::domain_ledger::create_storage_history::ready::
                ReadyBundleDataV1::decode(ready_bytes)?;
            if ready.specification != specification {
                return Err(Box::new(OriginalStorageApplyIssuanceClosedV1));
            }
            Ok(())
        })());
        if !matches!(self.input_check, Some(Ok(()))) {
            self.first = Some(First::Preparation);
            return Err(OriginalStorageApplyIssuanceClosedV1);
        }
        self.normalization = Some((|| -> Result<BrokerPlanPreparation, Cause> {
            let admission = client.borrow_admission_v1(original, controller)?;
            let construction = client.borrow_construction_turn_v1(original, controller)?;
            construction.require_preparation_admission_v1(&admission)?;
            let (manifest, _, lease) = original.completed_original_v1().publication_material_v1()?;
            let digest: [u8; 32] = response.catalog_digest.as_slice().try_into()?;
            let catalog = aos_sandbox_protocol::semantics::CatalogBindingV1::from_publisher(
                response.catalog_generation, ObjectDigest::from_bytes(digest),
            )?;
            let protected = ProtectedStorageCreateApplyDataV1::from_preparation_data_v1(
                proposed, catalog, manifest.canonical_bytes(), specification,
            )?;
            self.body = Some(protected.deadline_free_request_body_v1(
                self.entropy[48..64].try_into()?,
            ).map_err(Into::into));
            if !matches!(self.body, Some(Ok(_))) { return Err(Box::new(OriginalStorageApplyIssuanceClosedV1)); }
            let reply = admission.reply_v1()?;
            self.root_admission = Some(reply.digest_v1()?);
            aos_sandbox_protocol::authorization_artifact::prepare_admitted_storage_create_apply_plan_v1(
                &protected, manifest.manifest().policy().digest(), lease,
                construction.actual_before_clock_v1()?, construction.cutoff_v1(),
                authority.clone(), scope, reply.canonical_plan, reply.canonical_statement,
            )
        })());
        if !matches!(self.normalization, Some(Ok(_))) {
            self.first = Some(First::Preparation);
            return Err(OriginalStorageApplyIssuanceClosedV1);
        }
        Ok(())
    }
}

impl OriginalStorageApplyIssuanceV1 {
    /// Borrows only the actual normalized preparation under the same live Root.
    ///
    /// Key preparation uses the before gate. The caller must reborrow the
    /// strict final-clock gate after message preparation and before signing.
    ///
    /// # Errors
    /// Refuses a failed issuer, different admission or noncurrent construction.
    pub fn signing_preparation_v1<'held>(
        &'held self,
        admission: &RootStorageApplyAdmissionOriginalV1<'_>,
        construction: &RootStorageApplyConstructionTurnV1<'_>,
    ) -> Result<&'held BrokerPlanPreparation, OriginalStorageApplyIssuanceClosedV1> {
        construction.require_preparation_admission_v1(admission)
            .map_err(|_| OriginalStorageApplyIssuanceClosedV1)?;
        let reply = admission.reply_v1().map_err(|_| OriginalStorageApplyIssuanceClosedV1)?;
        let commitment = reply.digest_v1().map_err(|_| OriginalStorageApplyIssuanceClosedV1)?;
        if self.first.is_some() || self.parent != Some(admission.parent_operation_v1())
            || self.root_admission != Some(commitment) {
            return Err(OriginalStorageApplyIssuanceClosedV1);
        }
        self.normalization.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(OriginalStorageApplyIssuanceClosedV1)
    }

    /// Constructs the real internal gated publication from the signed Apply.
    ///
    /// Fresh logical identities come only from this paid original's entropy.
    /// All draft, lease-binding and OperationPlan construction uses the same
    /// existing canonical engines. No transaction is accepted or dispatched here.
    ///
    /// # Errors
    /// Retains the actual C23 refusal and every original constructor input/result.
    pub fn build_action_once_v1(
        &mut self,
        original: &mut OriginalCreateProvisioningRootLoanV1<'_, '_>,
        controller: &Journal,
        client: &RootStorageApplyClientOriginalV1,
        signed: &SignedBrokerPlan,
    ) -> Result<(), OriginalStorageApplyIssuanceClosedV1> {
        if self.first.is_some() || self.signed.is_some() || self.model_entry.is_some() {
            return self.refuse();
        }
        self.model_entry = Some((|| {
            original.require_current_v1(controller)?;
            let completed = original.completed_original_v1();
            let (manifest, _, lease) = completed.publication_material_v1()?;
            let body = self.body.as_ref().and_then(|value| value.as_ref().ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            let bound = publication::publication_construction_encoded_bound_v1(
                manifest.canonical_bytes().len(), [lease.canonical_lease().len(),
                    lease.canonical_signature().len(), lease.canonical_receipt().len(),
                    lease.canonical_receipt_signature().len()],
                [(signed.canonical_plan().len(), signed.canonical_signature().len(), body.len(), 0)],
            ).map_err(|_| ResourceReservationErrorV1::Conflict)?;
            // Three retained constructor inputs (draft/prepared/plan gate)
            // coexist with their three actual Action-contract copies before
            // positive handoff. Each uses the canonical provider's own
            // constructor/decode/reencoding overlap; no field fees are added.
            let publication = publication::decoding_receiving_bytes_v1(bound)
                .and_then(|size| size.checked_mul(6)).ok_or(ResourceReservationErrorV1::Conflict)?;
            let assignment = aos_sandbox_core::format::assignment_capture::
                CanonicalAssignmentDecodeCaptureV1::receiving_dynamic_footprint_v1(
                    manifest.canonical_bytes().len(), aos_sandbox_core::DecodeLimits::default(),
                ).and_then(|(bytes, _)| usize::try_from(bytes).ok()?.checked_mul(3))
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            let key = aos_sandbox_protocol::public_api::projection::projection_key(
                aos_sandbox_protocol::public_api::projection::PublicProjectionKindV1::Sandbox,
                manifest.manifest().sandbox().into_bytes(),
            );
            let projection = controller.get(crate::RecordNamespace::DesiredState, &key)
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            let bytes = publication.checked_add(assignment)
                .and_then(|size| size.checked_add(body.len().checked_mul(3)?))
                .and_then(|size| size.checked_add(projection.len().checked_mul(3)?))
                .and_then(|size| size.checked_add(key.len().checked_mul(3)?))
                .and_then(|size| size.checked_add(std::mem::size_of::<OperationPlan>().checked_mul(3)?))
                .and_then(|size| size.checked_add(std::mem::size_of::<
                    aos_sandbox_protocol::publication::AuthorityBoundEffectPlanV1>().checked_mul(3)?))
                .and_then(|size| size.checked_add(std::mem::size_of::<
                    super::action::PublicationActionContractV1>().checked_mul(2)?))
                .and_then(|size| size.checked_add(std::mem::size_of::<usize>().checked_mul(2)?))
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            let bytes = u64::try_from(bytes).map_err(|_| ResourceReservationErrorV1::Conflict)?;
            let named = publication::decoding_receiving_namespace_entries_v1(bound)
                .and_then(|rows| rows.checked_mul(6)).and_then(|rows| u64::try_from(rows).ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            let complete = self.complete.checked_add(ResourceVector::ZERO
                .with(D::MemoryBytes, bytes).with(D::MetadataEntries, named))?
                .checked_add(ProvisioningResourceRecordsV1::receiving_demand_v1()
                    .ok_or(ResourceReservationErrorV1::Conflict)?)?;
            self.complete = complete;
            let debit = original.require_complete_v1(controller, complete);
            if debit.is_err() && original.failure_v1().is_some() { self.funding_original = true; }
            debit
        })());
        if !matches!(self.model_entry, Some(Ok(()))) {
            self.first = Some(First::Models);
            return Err(OriginalStorageApplyIssuanceClosedV1);
        }
        // The caller keeps the actual signing result. Its clone is created
        // only after the full canonical constructor planes have been admitted.
        self.signed = Some(signed.clone());
        let result = self.build_paid_action_v1(original, controller, client);
        if result.is_err() {
            self.closed.get_or_insert(OriginalStorageApplyIssuanceClosedV1);
            self.first.get_or_insert(First::Models);
        }
        result
    }

    fn build_paid_action_v1(
        &mut self,
        original: &OriginalCreateProvisioningRootLoanV1<'_, '_>,
        controller: &Journal,
        client: &RootStorageApplyClientOriginalV1,
    ) -> Result<(), OriginalStorageApplyIssuanceClosedV1> {
        let completed = original.completed_original_v1();
        let admission = client.borrow_admission_v1(original, controller)
            .map_err(|_| OriginalStorageApplyIssuanceClosedV1)?;
        let construction = client.borrow_construction_turn_v1(original, controller)
            .map_err(|_| OriginalStorageApplyIssuanceClosedV1)?;
        construction.require_admission_v1(&admission)
            .map_err(|_| OriginalStorageApplyIssuanceClosedV1)?;
        let preparation = self.signing_preparation_v1(&admission, &construction)?;
        let signed = self.signed.as_ref().ok_or(OriginalStorageApplyIssuanceClosedV1)?;
        if signed.canonical_plan() != preparation.canonical_plan() {
            return Err(OriginalStorageApplyIssuanceClosedV1);
        }
        self.signature_check = Some(preparation.clone().complete(
            aos_sandbox_protocol::authorization_artifact::ReturnedSignature::Envelope(
                signed.canonical_signature(),
            ), construction.actual_before_clock_v1()
                .map_err(|_| OriginalStorageApplyIssuanceClosedV1)?.wall_seconds(),
        ));
        let verified = self.signature_check.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(OriginalStorageApplyIssuanceClosedV1)?;
        let grant = verified.plan().grants().first().ok_or(OriginalStorageApplyIssuanceClosedV1)?;
        self.template = Some(BrokerDispatchTemplateV1::new(verified.clone(),
            aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_STORAGE_APPLY,
            self.body.as_ref().and_then(|value| value.as_ref().ok())
                .ok_or(OriginalStorageApplyIssuanceClosedV1)?.clone(), Vec::new(),
            BrokerDispatchSemanticIdentityV1::new(BrokerVerb::StorageCreateWorkspace,
                BrokerGrantTarget::Assignment, grant.argument_commitment()),
        ).map_err(Into::into));
        let template = self.template.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(OriginalStorageApplyIssuanceClosedV1)?;
        let (manifest, claim, lease) = completed.publication_material_v1()
            .map_err(|_| OriginalStorageApplyIssuanceClosedV1)?;
        self.draft = Some(AuthorityPublicationDraftV1::new(manifest.clone(),
            vec![BrokerAudience::Storage], vec![template.clone()]).map_err(Into::into));
        let draft = self.draft.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(OriginalStorageApplyIssuanceClosedV1)?;
        self.prepared = Some(crate::publication::bind_authority_publication_lease(
            draft.clone(), claim, lease.clone(),
        ).map_err(Into::into));
        let prepared = self.prepared.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(OriginalStorageApplyIssuanceClosedV1)?;
        let publication_operation = OperationId::from_bytes(self.entropy[..16].try_into()
            .map_err(|_| OriginalStorageApplyIssuanceClosedV1)?);
        self.records = Some((|| -> Result<ProvisioningResourceRecordsV1, Cause> {
            let accepted = aos_sandbox_protocol::domain_ledger::effect_history::
                PublicMutationEffectHistoryV1::decode(completed.accepted_context_v1()?)?
                .ok_or(OriginalStorageApplyIssuanceClosedV1)?;
            let (child_head, inclusive_grant) = completed.resource_members_v1(controller)?;
            let records = ProvisioningResourceRecordsV1::from_data_v1(ProvisioningResourceFieldsV1 {
                mode: ProvisioningModeDataV1::CreateStopped, parent: completed.operation_v1(),
                publication_operation, sandbox: manifest.manifest().sandbox(),
                project: manifest.manifest().project(),
                assignment: ResourceId::from_bytes(self.entropy[16..32].try_into()?),
                reservation: ResourceId::from_bytes(self.entropy[32..48].try_into()?),
                epoch: manifest.manifest().epoch(), reservation_revision: Revision::new(1),
                public_request: provisioning_public_request_digest_v1(accepted.canonical_request()),
                manifest: manifest.digest(), source_draft: draft.digest(),
                root_plan: ObjectDigest::from_bytes(Sha256::digest(admission.reply_v1()?.canonical_plan).into()),
                child_head: ObjectDigest::from_bytes(Sha256::digest(child_head).into()),
                inclusive_grant: ObjectDigest::from_bytes(Sha256::digest(inclusive_grant).into()),
            })?;
            for kind in [
                aos_sandbox_protocol::domain_ledger::provisioning_resources::ProvisioningResourceRowKindV1::Parent,
                aos_sandbox_protocol::domain_ledger::provisioning_resources::ProvisioningResourceRowKindV1::Assignment,
                aos_sandbox_protocol::domain_ledger::provisioning_resources::ProvisioningResourceRowKindV1::Reservation,
            ] {
                if controller.get(crate::RecordNamespace::DesiredState, &records.key_v1(kind)).is_some() {
                    return Err(Box::new(OriginalStorageApplyIssuanceClosedV1));
                }
            }
            if controller.get(crate::RecordNamespace::Operation, publication_operation.as_bytes()).is_some() {
                return Err(Box::new(OriginalStorageApplyIssuanceClosedV1));
            }
            Ok(records)
        })());
        let records = *self.records.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(OriginalStorageApplyIssuanceClosedV1)?;
        self.plan = Some((|| -> Result<OperationPlan, Cause> {
            let accepted = aos_sandbox_protocol::domain_ledger::effect_history::
                PublicMutationEffectHistoryV1::decode(completed.accepted_context_v1()?)?
                .ok_or(OriginalStorageApplyIssuanceClosedV1)?;
            let key = aos_sandbox_protocol::public_api::projection::projection_key(
                aos_sandbox_protocol::public_api::projection::PublicProjectionKindV1::Sandbox,
                manifest.manifest().sandbox().into_bytes(),
            );
            let value = controller.get(crate::RecordNamespace::DesiredState, &key)
                .ok_or(OriginalStorageApplyIssuanceClosedV1)?.to_vec();
            let effect = bind_authority_publication_effect(draft, template.digest())?;
            Ok(OperationPlan::ownership_gated(publication_operation,
                IdempotencyKey::new(publication_operation.as_bytes().to_vec())?,
                *records.commitment_v1().as_bytes(), key, value, vec![effect], claim.clone(), draft.clone(),
            )?.with_runtime_authority(RuntimeAuthorityIntentV1::bind_holder(accepted.caller(), None)?)?
                .with_provisioning_resource_records_v1(records)?)
        })());
        let plan = self.plan.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(OriginalStorageApplyIssuanceClosedV1)?;
        self.action = Some(OriginalPublicationActionV1::from_issued_plan_v1(completed,
            controller, &admission, &construction, plan.clone(), draft.clone(), prepared.clone(), records));
        if !matches!(self.action, Some(Ok(_))) { return Err(OriginalStorageApplyIssuanceClosedV1); }
        Ok(())
    }

    /// Borrows the real issued action solely for its owed construction after.
    #[must_use]
    pub fn action_for_construction_posts_v1(&self) -> Option<&OriginalPublicationActionV1> {
        if self.first.is_some() { return None; }
        self.action.as_ref().and_then(|value| value.as_ref().ok())
    }

    /// Moves the genuine action once, after actual construction native posts.
    ///
    /// # Errors
    /// Refuses failed or repeated handoff and requires the completed original.
    pub fn take_action_once_v1(&mut self,
        original: &crate::CreateProvisioningOriginalsV1,
        client: &RootStorageApplyClientOriginalV1,
        controller: &Journal,
    ) -> Result<OriginalPublicationActionV1, OriginalStorageApplyIssuanceClosedV1> {
        if self.first.is_some() { return Err(OriginalStorageApplyIssuanceClosedV1); }
        let action = self.action.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(OriginalStorageApplyIssuanceClosedV1)?;
        client.require_completed_construction_turn_v1(action, original, controller)
            .map_err(|_| OriginalStorageApplyIssuanceClosedV1)?;
        match self.action.take() {
            Some(Ok(action)) => {
                // These completed pure constructor copies are retired only
                // after BOTH genuine native owners positively disposed. The
                // exact action owns the durable plan/publication inputs now.
                drop(self.response_encoding.take());
                drop(self.normalization.take());
                drop(self.body.take());
                drop(self.signed.take());
                drop(self.signature_check.take());
                drop(self.template.take());
                drop(self.draft.take());
                drop(self.prepared.take());
                drop(self.records.take());
                drop(self.plan.take());
                Ok(action)
            },
            _ => self.refuse(),
        }
    }
}
