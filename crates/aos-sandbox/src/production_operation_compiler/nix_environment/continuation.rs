//! Owns current grant and assignment custody for one retained pending Start.
//!
//! The fixed Controller writer supplies the original accepted operation,
//! authorization, request, idempotency, Effect and Desired bytes. Those originals
//! select the inputs to the existing protected capability evaluator and genuine
//! assignment owner. Historical carrier data alone cannot construct this owner.
//! No TLS evidence, broker session, physical floor or Resolve permission is
//! created here. Future effect boundaries must join their own concrete owners.

use aos_sandbox_core::RawPairedClockSample;
use buffa::Message as _;
use aos_sandbox_ownership_protocol::SignedOwnershipLease;
use aos_proto::aos::sandbox::local::v1::{
    AssignmentFence, Audience, NixBuildRequestV2, RequestHeader,
};

use super::*;
use crate::cli_model::authorization_adapter::{
    CliAuthorizationAdapterError, CurrentCapabilityDecisionV1,
    evaluate_current_protected_capability,
};
use crate::cli_model::provenance::OriginalPublicMutationCoordinatesV2;
use crate::controller::ControllerProtectedClockV1;
use crate::controller_service::journal::{ControllerJournalError, validate_controller_journal};
use crate::publisher_authority::PublisherAuthorityLimits;
use crate::publisher_policy::PublisherPolicyLimits;
use crate::reconciler::EffectPlan;
use crate::runtime_scope::CurrentAssignmentTarget;

const CONTROLLER_DIRECTORY: &str = "/var/lib/aos/sandboxd";
const CONTROLLER_JOURNAL: &str = "controller.journal";

/// Reports failure to retain current custody for an original pending Start.
///
/// Typed underlying startup, journal, ledger, assignment, clock and protected
/// grant failures remain available through the standard error source chain.
#[derive(Debug, thiserror::Error)]
#[error("retained Nix Start current custody failed: {cause}")]
pub struct NixStartContinuationErrorV2 {
    #[source]
    cause: ContinuationFailureV2,
}

#[derive(Debug, thiserror::Error)]
enum ContinuationFailureV2 {
    #[error("original Start admission failed: {0}")]
    Admission(#[from] NixStartAdmissionErrorV2),
    #[error("fixed Controller journal failed: {0}")]
    Journal(#[from] crate::JournalError),
    #[error("retained Start ledger failed: {0}")]
    Ledger(#[from] crate::ReconcilerError),
    #[error("retained Controller node failed: {0}")]
    Controller(#[from] ControllerJournalError),
    #[error("protected paired clock failed: {0}")]
    Clock(#[from] crate::ProtectedOwnershipClockError),
    #[error("current protected grant failed: {0}")]
    Authorization(#[from] CliAuthorizationAdapterError),
    #[error("current assignment custody failed: {0}")]
    Assignment(#[from] crate::runtime_scope::CurrentRuntimeScopeError),
    #[error("protected runtime authority failed: {0}")]
    RuntimeAuthority(#[from] crate::runtime_authority::RuntimeAuthorityError),
    #[error("protected paired-clock ordering failed: {0}")]
    ClockPair(#[from] aos_sandbox_core::OwnershipLeaseVerificationError),
    #[error("original Start request failed: {0}")]
    Request(#[from] crate::public_mutation_compiler::PublicMutationResolutionErrorV1),
    #[error("canonical Nix request validation failed: {0}")]
    BrokerRequest(#[from] aos_sandbox_protocol::ProtocolValidationError),
    #[error("canonical Nix authorization plan failed: {0}")]
    BrokerPlan(#[from] aos_sandbox_core::InvalidBrokerAuthorizationPlan),
}

impl From<ContinuationFailureV2> for NixStartContinuationErrorV2 {
    fn from(cause: ContinuationFailureV2) -> Self {
        Self { cause }
    }
}

/// Retains genuine current custody for one exact accepted pending Start Effect.
///
/// The owner exclusively borrows the original fixed Controller journal and
/// retains the same protected clock and non-renewable assignment target. It is
/// neither cloneable nor serializable. Any failed recheck permanently closes
/// this instance; rechecking cannot renew its assignment deadline or replace
/// the original capability, policy, recipe, assignment or signed lease.
///
/// This owner does not grant broker endpoint, floor, build or publication access.
/// Its public projections are data, not transferable authorization evidence.
pub struct CurrentRetainedNixStartV2<'current> {
    selector: &'current ControllerNixStartRecipeSelectorV2,
    journal: &'current mut Journal,
    expected_plan: &'current EffectPlan,
    carrier: NixStartAdmissionCarrierV2,
    recipe: &'current VerifiedNixRecipeArtifactV2,
    target: CurrentAssignmentTarget,
    clock: ControllerProtectedClockV1,
    decision: CurrentCapabilityDecisionV1,
    failed: bool,
}

/// Retains one fresh unsigned Resolve50 plan beside its original signed lease.
///
/// This historical draft still requires the installed Controller signer,
/// authenticated Session, receiver admission and atomic physical-floor commit.
/// It is not a currentness token or an executable store permit.
pub struct NixResolveAuthorizationDraftV2 {
    plan: aos_sandbox_core::BrokerAuthorizationPlan,
    lease: SignedOwnershipLease,
    request: Vec<u8>,
    observed: RawPairedClockSample,
}

impl NixResolveAuthorizationDraftV2 {
    /// Borrows the exact newly constructed unsigned plan.
    #[must_use]
    pub fn plan(&self) -> &aos_sandbox_core::BrokerAuthorizationPlan {
        &self.plan
    }

    /// Borrows the original independently signed current assignment lease.
    #[must_use]
    pub fn lease(&self) -> &SignedOwnershipLease {
        &self.lease
    }

    /// Borrows the exact canonical method body matched by the grant.
    #[must_use]
    pub fn request_bytes(&self) -> &[u8] {
        &self.request
    }

    /// Returns the actual protected observation used to issue this draft.
    #[must_use]
    pub const fn observed(&self) -> RawPairedClockSample {
        self.observed
    }
}

impl std::fmt::Debug for CurrentRetainedNixStartV2<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CurrentRetainedNixStartV2(<borrowed current custody>)")
    }
}

impl ControllerNixStartRecipeSelectorV2 {
    /// Borrows genuine current custody for one exact retained pending Start.
    ///
    /// All authority inputs come from the original accepted ledger. The caller
    /// supplies only the operation/step and expected full Effect to compare;
    /// it cannot select a holder, capability, policy, clock, recipe or path.
    /// Existing protected time-floor advancement runs only after the complete
    /// original admission and fixed writer custody have been checked.
    ///
    /// # Errors
    /// Rejects changed startup or credentials; a wrong, poisoned or replaced
    /// fixed writer; missing/inconsistent admission, idempotency, Effect or
    /// Desired; a nonpending operation; denied or changed current grant; and
    /// changed, expired or unauthentic original assignment/lease custody.
    pub fn borrow_current_retained_start_v2<'current>(
        &'current self,
        journal: &'current mut Journal,
        operation: OperationId,
        step: u32,
        expected_plan: &'current EffectPlan,
    ) -> Result<CurrentRetainedNixStartV2<'current>, NixStartContinuationErrorV2> {
        self.require_fixed_writer(journal).map_err(ContinuationFailureV2::from)?;
        let carrier = crate::reconciler::accepted_nix_start_admission_v2(journal, operation)
            .map_err(ContinuationFailureV2::from)?
            .ok_or(NixStartAdmissionErrorV2::Invalid).map_err(ContinuationFailureV2::from)?;
        carrier.require_current_effect_v2(journal, operation, step, expected_plan)
            .map_err(ContinuationFailureV2::from)?;
        // Accepted originals make the empty-journal identity bootstrap branch
        // unreachable. This checks the existing node, never creates a new one.
        self.require_bound_writer(journal)?;
        let recipe = self.original_recipe(&carrier).map_err(ContinuationFailureV2::from)?;
        let binding = current_binding(journal, recipe.recipe().sandbox)
            .map_err(ContinuationFailureV2::from)?;
        self.require_original_assignment(journal, &carrier, recipe, &binding)
            .map_err(ContinuationFailureV2::from)?;

        let mut clock = ControllerProtectedClockV1::open_fixed()
            .map_err(ContinuationFailureV2::from)?;
        let decision = evaluate_original_grant(journal, &carrier, &mut clock)?;
        let target = crate::runtime_scope::acquire_current_assignment(
            journal,
            RuntimeScopeHolder { sandbox: recipe.recipe().sandbox, holder: carrier.authority.holder },
            self.assignment_policy().map_err(ContinuationFailureV2::from)?,
            &mut || clock.sample(),
        ).map_err(ContinuationFailureV2::from)?;
        if target.binding() != &binding {
            return Err(ContinuationFailureV2::Admission(NixStartAdmissionErrorV2::Invalid).into());
        }

        let mut owner = CurrentRetainedNixStartV2 {
            selector: self, journal, expected_plan, carrier, recipe, target, clock, decision,
            failed: false,
        };
        owner.recheck()?;
        Ok(owner)
    }

    fn require_fixed_writer(&self, journal: &Journal) -> Result<(), NixStartAdmissionErrorV2> {
        self.recheck()?;
        journal.validate_held_owned_at_for_uid(
            CONTROLLER_DIRECTORY, CONTROLLER_JOURNAL, self.pins.identities[0],
        )?;
        self.recheck()?;
        Ok(())
    }

    fn require_bound_writer(&self, journal: &mut Journal) -> Result<(), NixStartContinuationErrorV2> {
        self.require_fixed_writer(journal).map_err(ContinuationFailureV2::from)?;
        validate_controller_journal(journal, *self.pins.node.as_bytes())
            .map_err(ContinuationFailureV2::from)?;
        self.require_fixed_writer(journal).map_err(ContinuationFailureV2::from)?;
        Ok(())
    }

    fn original_recipe<'selector>(
        &'selector self,
        carrier: &NixStartAdmissionCarrierV2,
    ) -> Result<&'selector VerifiedNixRecipeArtifactV2, NixStartAdmissionErrorV2> {
        carrier.validate()?;
        if carrier.credential_commitments != self.commitments() {
            return Err(NixStartAdmissionErrorV2::Invalid);
        }
        let artifact = self.recipes.iter().find(|artifact| {
            artifact.digest() == carrier.recipe_digest && artifact.canonical_bytes() == carrier.recipe
        }).ok_or(NixStartAdmissionErrorV2::Invalid)?;
        self.require_recipe_pins(artifact)?;
        Ok(artifact)
    }

    fn require_original_assignment(
        &self,
        journal: &mut Journal,
        carrier: &NixStartAdmissionCarrierV2,
        recipe: &VerifiedNixRecipeArtifactV2,
        binding: &RuntimeAuthorityBindingV1,
    ) -> Result<(), NixStartAdmissionErrorV2> {
        require_recipe_assignment(recipe, binding, &carrier.authority)?;
        let manifest = binding.manifest().manifest();
        let claims = carrier.authority.capability.claims();
        if binding.holder() != Some(carrier.authority.holder)
            || manifest.node() != self.pins.node
            || manifest.desired_generation().get() != carrier.original_generation.checked_add(1)
                .ok_or(NixStartAdmissionErrorV2::Invalid)?
            || manifest.incarnation().as_bytes() != carrier.original_incarnation.as_slice()
            || claims.sandbox.is_some_and(|sandbox| sandbox != manifest.sandbox())
            || claims.incarnation.is_some_and(|incarnation| incarnation != manifest.incarnation())
            || claims.assignment_epoch.is_some_and(|epoch| epoch != manifest.epoch())
            || !checked_assignment_readback(journal, binding)?.matches_original(&carrier.assignment)
        {
            return Err(NixStartAdmissionErrorV2::Invalid);
        }
        require_desired_assignment(carrier, binding)
    }
}

impl CurrentRetainedNixStartV2<'_> {
    /// Computes purpose-separated input and predicted-output comparison data.
    ///
    /// Both fixed online owners use this same canonical typed serialization.
    /// The output digest does not attest that predicted outputs exist, and
    /// neither digest supplies local input, store, Session or floor authority.
    ///
    /// # Errors
    /// Rejects an invalid recipe or failure to encode its canonical maps.
    pub fn recipe_coordinate_digests_v2(
        recipe: &aos_sandbox_protocol::nix_build::NixPreadmittedRecipeV2,
    ) -> Result<([u8; 32], [u8; 32]), NixStartAdmissionErrorV2> {
        recipe.validate()?;
        let inputs = serde_json::to_vec(&recipe.inputs)?;
        let outputs = serde_json::to_vec(&recipe.outputs)?;
        Ok((
            Sha256::new()
                .chain_update(b"aos.sandbox.nix.resolve-input-map.v2\0")
                .chain_update((inputs.len() as u64).to_be_bytes())
                .chain_update(&inputs)
                .finalize()
                .into(),
            Sha256::new()
                .chain_update(b"aos.sandbox.nix.resolve-predicted-output-map.v2\0")
                .chain_update((outputs.len() as u64).to_be_bytes())
                .chain_update(&outputs)
                .finalize()
                .into(),
        ))
    }

    /// Forms the fixed Resolve50 body from this same genuine pending Start.
    ///
    /// Only the request identity is caller-selected comparison data. The
    /// assignment fence, admitted recipe, parent carrier and exclusive cutoff
    /// come from the retained originals, never a supplied lease or deadline.
    /// The body still delegates current-held evidence through the authenticated
    /// Controller role; its scalar coordinates are not a remote live lease.
    ///
    /// # Errors
    /// Rejects a closed owner, a sentinel request identity, any changed original
    /// custody or expired cutoff, and bounded carrier/map encoding failure.
    /// A returned error or caught unwind permanently closes this owner.
    pub fn prepare_resolve_request_v2(
        &mut self,
        request_id: [u8; 16],
    ) -> Result<NixBuildRequestV2, NixStartContinuationErrorV2> {
        if self.failed || request_id == [0; 16] || request_id == [0xff; 16] {
            return Err(ContinuationFailureV2::Admission(NixStartAdmissionErrorV2::Invalid).into());
        }

        // Pre-arm before the first check. Only this complete observation may
        // reopen the same owner; abandonment cannot produce a reusable target.
        self.failed = true;
        self.recheck_inner()?;
        let body = self.original_resolve_request_v2(request_id)?;
        self.recheck_inner()?;
        self.failed = false;
        Ok(body)
    }

    fn original_resolve_request_v2(
        &self,
        request_id: [u8; 16],
    ) -> Result<NixBuildRequestV2, NixStartContinuationErrorV2> {
        let (inputs, outputs) = Self::recipe_coordinate_digests_v2(self.recipe.recipe())
            .map_err(ContinuationFailureV2::from)?;
        let parent = self.carrier.encode().map_err(ContinuationFailureV2::from)?;
        let parent_digest: [u8; 32] = parent.get(parent.len().saturating_sub(32)..)
            .ok_or(ContinuationFailureV2::Admission(NixStartAdmissionErrorV2::Invalid))?
            .try_into()
            .map_err(|_| ContinuationFailureV2::Admission(NixStartAdmissionErrorV2::Invalid))?;
        let binding = self.target.binding();
        let manifest = binding.manifest().manifest();
        let recipe = self.recipe.recipe();
        let body = NixBuildRequestV2 {
            header: Some(RequestHeader {
                protocol_major: 1,
                protocol_minor: 0,
                request_id: request_id.to_vec(),
                audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
                deadline_boottime_nanoseconds: self.target.deadline_boottime_nanoseconds(),
                maximum_response_bytes: aos_sandbox_protocol::nix_build::NIX_RESPONSE_MAXIMUM_BYTES_V2 as u32,
                ..Default::default()
            }).into(),
            fence: Some(AssignmentFence {
                sandbox_id: manifest.sandbox().as_bytes().to_vec(),
                incarnation_id: manifest.incarnation().as_bytes().to_vec(),
                assignment_epoch: manifest.epoch().get(),
                desired_generation: manifest.desired_generation().get(),
                assignment_digest: binding.assignment_digest().as_bytes().to_vec(),
                ..Default::default()
            }).into(),
            operation_id: self.carrier.operation().as_bytes().to_vec(),
            recipe_digest: self.recipe.digest().as_bytes().to_vec(),
            domain_digest: recipe.domain_commitment.as_bytes().to_vec(),
            disclosure_digest: recipe.disclosure.as_bytes().to_vec(),
            environment_digest: recipe.environment.digest().as_bytes().to_vec(),
            parent_admission_digest: parent_digest.to_vec(),
            input_presentation_digest: inputs.to_vec(),
            expected_output_map_digest: outputs.to_vec(),
            ..Default::default()
        };
        Ok(body)
    }

    /// Stages a fresh canonical Resolve50 plan before the final original check.
    ///
    /// The body must equal the request constructed from this same Start. The
    /// genuine current lease and protected clock select the assignment, signer
    /// generation and exclusive expiry; the caller cannot nominate any of them.
    /// Only the original request identity is comparison DATA. The unsigned
    /// draft remains resident when the final check fails or unwinds.
    ///
    /// # Errors
    /// Preserves actual original-custody, request, plan and clock causes. Rejects
    /// a closed owner, occupied output, substituted request or expired bound.
    /// Failure or interruption permanently fences this owner.
    pub fn retain_resolve_authorization_into(
        &mut self,
        request: &NixBuildRequestV2,
        target: &mut Option<NixResolveAuthorizationDraftV2>,
    ) -> Result<(), NixStartContinuationErrorV2> {
        if self.failed {
            return Err(ContinuationFailureV2::Admission(NixStartAdmissionErrorV2::Invalid).into());
        }
        self.failed = true;
        if target.is_some() {
            return Err(ContinuationFailureV2::Admission(NixStartAdmissionErrorV2::Invalid).into());
        }
        self.recheck_inner()?;

        let request_id = request.header.as_option()
            .ok_or(ContinuationFailureV2::Admission(NixStartAdmissionErrorV2::Invalid))?
            .request_id.as_slice().try_into()
            .map_err(|_| ContinuationFailureV2::Admission(NixStartAdmissionErrorV2::Invalid))?;
        if request_id == [0; 16]
            || request_id == [0xff; 16]
            || request != &self.original_resolve_request_v2(request_id)?
        {
            return Err(ContinuationFailureV2::Admission(NixStartAdmissionErrorV2::Invalid).into());
        }
        let bytes = request.encode_to_vec();
        let (lease, observed) = self.target.verified_plan_lease(
            self.journal,
            &mut || self.clock.sample(),
        ).map_err(ContinuationFailureV2::from)?;
        require_original_lease(&self.carrier.assignment, &lease)
            .map_err(ContinuationFailureV2::from)?;

        let identities = self.selector.pins.identities;
        let checked = aos_sandbox_protocol::nix_build::decode_nix_build_request_v2(
            &bytes,
            aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_NIX_RESOLVE_PROTECTED_RECIPE_V2,
            aos_sandbox_protocol::PeerCredentials {
                uid: identities[0],
                gid: identities[1],
                pid: None,
            },
            aos_sandbox_protocol::PeerPolicy {
                uid: identities[0],
                gid: Some(identities[1]),
                audience: Audience::AUDIENCE_NODE_CONTROLLER,
            },
            observed.boottime_nanoseconds(),
        ).map_err(ContinuationFailureV2::from)?;
        let (policy_digest, revocation_scope) = {
            let loan = self.selector.recheck_and_borrow_publics()
                .map_err(ContinuationFailureV2::from)?;
            let credentials = loan.publics()
                .ok_or(ContinuationFailureV2::Admission(NixStartAdmissionErrorV2::CredentialCustodyClosed))?;
            let anchor = plan_anchor_from_publics(&credentials, 6)
                .map_err(ContinuationFailureV2::from)?;
            (ObjectDigest::from_bytes(Sha256::digest(credentials[6].bytes()).into()),
                anchor.revocation_scope())
        };

        let binding = self.target.binding();
        let manifest = binding.manifest().manifest();
        let assignment = aos_sandbox_core::BrokerAssignment::new(
            manifest.sandbox(),
            manifest.incarnation(),
            manifest.epoch(),
            manifest.desired_generation(),
            binding.assignment_digest(),
        ).map_err(ContinuationFailureV2::from)?;
        let target_handle = aos_sandbox_core::BrokerResourceHandle::from_bytes(
            *self.recipe.recipe().domain_commitment.as_bytes(),
        ).map_err(ContinuationFailureV2::from)?;
        let commitment = aos_sandbox_core::BrokerArgumentCommitment::from_digest(
            ObjectDigest::from_bytes(checked.commitment()),
        ).map_err(ContinuationFailureV2::from)?;
        let grant = aos_sandbox_core::BrokerGrant::new(
            aos_sandbox_core::BrokerVerb::NixResolveProtectedRecipe,
            aos_sandbox_core::BrokerGrantTarget::Resource(target_handle),
            commitment,
            aos_sandbox_protocol::nix_build::NIX_REQUEST_MAXIMUM_BYTES_V2 as u32,
            0,
        ).map_err(ContinuationFailureV2::from)?;
        let features = [
            "aos.sandbox.authorization.signed-plan-lease",
            aos_sandbox_core::NIX_NARROWING_PROXY_FEATURE_NAMESPACE,
        ].into_iter().map(|namespace| {
            aos_sandbox_core::FeatureRef::new(namespace, 1, 0)
                .map_err(|_| ContinuationFailureV2::Admission(NixStartAdmissionErrorV2::Invalid))
        }).collect::<Result<Vec<_>, _>>()?;
        let expires = self.target.expires_wall_seconds().min(lease.authority_expires_seconds());
        let plan = aos_sandbox_core::BrokerAuthorizationPlan::new(
            aos_sandbox_core::BrokerAudience::Nix,
            aos_sandbox_core::ProtocolId::NixBuildBroker,
            aos_sandbox_core::ProtocolVersion::new(1, 0),
            assignment,
            lease.node(),
            lease.signer().clone(),
            vec![grant],
            policy_digest,
            revocation_scope,
            observed.wall_seconds(),
            expires,
            features,
        ).map_err(ContinuationFailureV2::from)?;
        *target = Some(NixResolveAuthorizationDraftV2 {
            plan,
            lease,
            request: bytes,
            observed,
        });

        self.recheck_inner()?;
        self.failed = false;
        Ok(())
    }

    /// Returns the immutable accepted operation identity as data.
    #[must_use]
    pub fn operation_id(&self) -> OperationId {
        self.carrier.operation()
    }

    /// Returns the original signed recipe artifact as historical data.
    #[must_use]
    pub fn recipe_artifact(&self) -> &VerifiedNixRecipeArtifactV2 {
        self.recipe
    }

    /// Returns the original accepted time, never the latest observation time.
    #[must_use]
    pub fn accepted_wall_seconds(&self) -> i64 {
        self.carrier.authority.accepted_wall_seconds
    }

    /// Returns the assignment owner's exclusive, non-renewable BOOTTIME bound.
    #[must_use]
    pub fn deadline_boottime_nanoseconds(&self) -> u64 {
        self.target.deadline_boottime_nanoseconds()
    }

    /// Rechecks the same current grant, ledger, clock and original assignment.
    ///
    /// The existing grant evaluator advances only its existing protected time
    /// floor. This method never reacquires a target, refreshes a deadline,
    /// selects a replacement recipe, or settles an operation or Effect.
    ///
    /// # Errors
    /// Rejects any changed original/current custody or expired bound. Every
    /// failure permanently closes this instance, including subsequent calls.
    pub fn recheck(&mut self) -> Result<(), NixStartContinuationErrorV2> {
        if self.failed {
            return Err(ContinuationFailureV2::Admission(NixStartAdmissionErrorV2::Invalid).into());
        }
        let result = self.recheck_inner();
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn require_original_ledger(&mut self) -> Result<(), NixStartContinuationErrorV2> {
        self.selector.require_fixed_writer(self.journal).map_err(ContinuationFailureV2::from)?;
        self.carrier.require_current_effect_v2(
            self.journal, self.carrier.operation(), 0, self.expected_plan,
        ).map_err(ContinuationFailureV2::from)?;
        self.selector.require_bound_writer(self.journal)?;
        self.selector.original_recipe(&self.carrier).map_err(ContinuationFailureV2::from)?;
        Ok(())
    }

    fn recheck_inner(&mut self) -> Result<(), NixStartContinuationErrorV2> {
        self.require_original_ledger()?;
        let decision = evaluate_original_grant(self.journal, &self.carrier, &mut self.clock)?;
        self.decision.clock().validate_later_sample(decision.clock())
            .map_err(ContinuationFailureV2::from)?;
        let binding = current_binding(self.journal, self.recipe.recipe().sandbox)
            .map_err(ContinuationFailureV2::from)?;
        if &binding != self.target.binding() {
            return Err(ContinuationFailureV2::Admission(NixStartAdmissionErrorV2::Invalid).into());
        }
        self.selector.require_original_assignment(self.journal, &self.carrier, self.recipe, &binding)
            .map_err(ContinuationFailureV2::from)?;
        let (lease, observed) = self.target.verified_plan_lease(self.journal, &mut || self.clock.sample())
            .map_err(ContinuationFailureV2::from)?;
        require_original_lease(&self.carrier.assignment, &lease)
            .map_err(ContinuationFailureV2::from)?;
        require_observation(&self.carrier.authority, decision.clock(), observed)
            .map_err(ContinuationFailureV2::from)?;

        let after = self.clock.sample().map_err(ContinuationFailureV2::from)?;
        require_observation(&self.carrier.authority, observed, after)
            .map_err(ContinuationFailureV2::from)?;
        if after.wall_seconds() >= self.target.expires_wall_seconds()
            || after.wall_seconds() >= lease.authority_expires_seconds()
            || current_binding(self.journal, self.recipe.recipe().sandbox)
                .map_err(ContinuationFailureV2::from)? != binding
        {
            return Err(ContinuationFailureV2::Admission(NixStartAdmissionErrorV2::Invalid).into());
        }
        self.selector.require_original_assignment(self.journal, &self.carrier, self.recipe, &binding)
            .map_err(ContinuationFailureV2::from)?;
        self.target.recheck(self.journal, &mut || self.clock.sample())
            .map_err(ContinuationFailureV2::from)?;
        self.require_original_ledger()?;
        let final_sample = self.clock.sample().map_err(ContinuationFailureV2::from)?;
        require_observation(&self.carrier.authority, after, final_sample)
            .map_err(ContinuationFailureV2::from)?;
        if final_sample.wall_seconds() >= self.target.expires_wall_seconds()
            || final_sample.wall_seconds() >= lease.authority_expires_seconds()
            || final_sample.boottime_nanoseconds() >= self.target.deadline_boottime_nanoseconds()
        {
            return Err(ContinuationFailureV2::Admission(NixStartAdmissionErrorV2::Invalid).into());
        }
        self.selector.require_fixed_writer(self.journal).map_err(ContinuationFailureV2::from)?;
        self.decision = decision;
        Ok(())
    }
}

fn evaluate_original_grant(
    journal: &mut Journal,
    carrier: &NixStartAdmissionCarrierV2,
    clock: &mut ControllerProtectedClockV1,
) -> Result<CurrentCapabilityDecisionV1, NixStartContinuationErrorV2> {
    let original = &carrier.authority;
    let request = crate::public_mutation_compiler::ResolvedPublicMutationRequestV1::decode(
        original.original_request(),
    ).map_err(ContinuationFailureV2::from)?;
    let selector = request.selector()
        .ok_or(NixStartAdmissionErrorV2::Invalid).map_err(ContinuationFailureV2::from)?;
    let claims = original.capability.claims();
    let decision = evaluate_current_protected_capability(
        journal, PublisherAuthorityLimits::default(), PublisherPolicyLimits::default(),
        claims.id, original.project, original.holder, claims.channel_binding, clock,
        request.resource_kind(), request.operation(), selector,
    ).map_err(ContinuationFailureV2::from)?;
    let current = decision.original_coordinates(original.coordinates.session_commitment);
    require_coordinate_identity(original.coordinates, current)
        .map_err(ContinuationFailureV2::from)?;
    if decision.capability() != &original.capability
        || decision.policy().descriptor() != &original.policy
        || decision.policy().canonical_policy() != original.canonical_policy
        || decision.authorized_wall_seconds() < original.accepted_wall_seconds
    {
        return Err(ContinuationFailureV2::Admission(NixStartAdmissionErrorV2::Invalid).into());
    }
    Ok(decision)
}

fn require_coordinate_identity(
    original: OriginalPublicMutationCoordinatesV2,
    mut observed: OriginalPublicMutationCoordinatesV2,
) -> Result<(), NixStartAdmissionErrorV2> {
    // The common evaluator advances the observation's protected time floor.
    // Every signed authority coordinate and historical session remains exact.
    observed.authorization_revision = original.authorization_revision;
    if observed != original {
        return Err(NixStartAdmissionErrorV2::Invalid);
    }
    Ok(())
}

fn current_binding(
    journal: &mut Journal,
    sandbox: SandboxId,
) -> Result<RuntimeAuthorityBindingV1, ContinuationFailureV2> {
    RuntimeAuthorityStore::load(journal, RuntimeAuthorityLimits::default())
        .map_err(ContinuationFailureV2::from)?.current(sandbox)
        .map_err(ContinuationFailureV2::from)?
        .ok_or_else(|| ContinuationFailureV2::Admission(NixStartAdmissionErrorV2::Invalid))
}

fn require_original_lease(
    original: &OriginalAssignmentV2,
    lease: &SignedOwnershipLease,
) -> Result<(), NixStartAdmissionErrorV2> {
    if lease.canonical_lease() != original.lease
        || lease.canonical_signature() != original.signature
        || lease.canonical_receipt() != original.receipt
        || lease.canonical_receipt_signature() != original.receipt_signature
    {
        return Err(NixStartAdmissionErrorV2::Invalid);
    }
    Ok(())
}

fn require_observation(
    original: &CheckedStartAuthorityV2,
    before: RawPairedClockSample,
    after: RawPairedClockSample,
) -> Result<(), ContinuationFailureV2> {
    before.validate_later_sample(after).map_err(ContinuationFailureV2::from)?;
    if after.wall_seconds() < original.accepted_wall_seconds
        || after.wall_seconds() >= original.coordinates.capability_expires_at
        || after.wall_seconds() >= original.coordinates.policy_expires_at
    {
        return Err(ContinuationFailureV2::Admission(NixStartAdmissionErrorV2::Invalid));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // These coordinates are historical DATA used only to exercise equality.
    // They construct neither a decision, a selector nor a continuation owner.
    fn original_coordinates() -> OriginalPublicMutationCoordinatesV2 {
        OriginalPublicMutationCoordinatesV2 {
            capability: [1; 16], revocation_scope: [2; 16], revocation_generation: 3,
            policy_digest: [4; 32], policy_generation: 5, controller: [6; 16],
            controller_generation: 7, capability_not_before: 8, capability_expires_at: 9,
            policy_not_before: 10, policy_expires_at: 11, channel_binding: [12; 32],
            session_commitment: [13; 32], authorization_revision: [14; 32],
        }
    }

    #[test]
    fn only_the_observation_revision_may_change() {
        let original = original_coordinates();
        let observed = OriginalPublicMutationCoordinatesV2 {
            authorization_revision: [15; 32], ..original
        };

        assert!(require_coordinate_identity(original, original).is_ok());
        assert!(require_coordinate_identity(original, observed).is_ok());
        assert_eq!(original.authorization_revision, [14; 32]);
    }

    #[test]
    fn every_other_original_authority_coordinate_stays_exact() {
        let original = original_coordinates();
        let substitutions = [
            OriginalPublicMutationCoordinatesV2 { capability: [15; 16], ..original },
            OriginalPublicMutationCoordinatesV2 { revocation_scope: [15; 16], ..original },
            OriginalPublicMutationCoordinatesV2 { revocation_generation: 15, ..original },
            OriginalPublicMutationCoordinatesV2 { policy_digest: [15; 32], ..original },
            OriginalPublicMutationCoordinatesV2 { policy_generation: 15, ..original },
            OriginalPublicMutationCoordinatesV2 { controller: [15; 16], ..original },
            OriginalPublicMutationCoordinatesV2 { controller_generation: 15, ..original },
            OriginalPublicMutationCoordinatesV2 { capability_not_before: 15, ..original },
            OriginalPublicMutationCoordinatesV2 { capability_expires_at: 15, ..original },
            OriginalPublicMutationCoordinatesV2 { policy_not_before: 15, ..original },
            OriginalPublicMutationCoordinatesV2 { policy_expires_at: 15, ..original },
            OriginalPublicMutationCoordinatesV2 { channel_binding: [15; 32], ..original },
            OriginalPublicMutationCoordinatesV2 { session_commitment: [15; 32], ..original },
        ];

        for substitution in substitutions {
            assert!(require_coordinate_identity(original, substitution).is_err());
        }
    }
}
