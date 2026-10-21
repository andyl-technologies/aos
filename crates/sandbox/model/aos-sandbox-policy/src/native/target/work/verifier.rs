//! Rechecks signed compiler input under the genuine same-flight native loans.
//!
//! Only actual Target work constructs this private verifier. Prehold verifies
//! provenance without issuance; only Publication+Held can enter a publication
//! action. Terminal variants remain comparisons and effect observation remains
//! explicitly unavailable. No caller-implemented verifier crosses the boundary.

use super::{RootCurrentOwnerLoanV1, RootPolicyPublicationErrorV1 as ErrorV1};
use crate::controller_project_readback::VerifiedControllerProjectAdmissionV1;
use crate::controller_readback::VerifiedControllerHoldReadbackV1;
use crate::native::authority::RootAuthorityGen1LoanV1;
use crate::native::publication::{
    PolicyEffectObservationRequestV1, PolicyPublicationPrerequisitesV1,
    PolicyPublicationVerifierV1, VerifiedPolicyEffectObservationV1,
};
use crate::q04_data::{Q04AcknowledgementKindV1, Q04PreholdInputDataV1, Q04RootStageRecipeV1};
use crate::signed_inputs::{
    PolicyDeploymentHeadV1, PolicyDeploymentInputsV1, VerifiedSignedProjectPolicySourceV2,
};
use crate::{
    AuthenticatedCacheDomainV1, AuthenticatedSandboxProjectRelationV1, CacheDomainBindingV1,
    CacheDomainVerifierV1, CompiledPolicyCandidateV1, PolicyCompilerInputV1, PolicyCompilerV1,
    SandboxProjectRelationVerifierV1, normalized_policy_input_digest_v1,
};
use aos_sandbox_model::{
    MediaType, ObjectDescriptor, ObjectDigest, PortableMediaType, format::descriptor_for_bytes,
};
use aos_sandbox_protocol::cache_owner_readback::VerifiedClosedCacheOwnerReadbackV2;
use aos_sandbox_protocol::domain_ledger::create_q04_history::Q04CutIdentityV1;
use aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1;

// This closed verifier is constructed only above from the same Root loan,
// independently pinned packets and the actual original parent. Repeated
// checks are authority boundaries, not cached digest substitutions.
pub(in crate::native) struct RootCurrentInputVerifierV1<
    'cut,
    'flight,
    'origin,
    'packet,
    'startup,
> {
    pub(super) original: RootCurrentOwnerLoanV1<'cut, 'origin, 'startup>,
    pub(super) gen1: &'cut RootAuthorityGen1LoanV1<'flight, 'origin, 'startup>,
    pub(super) stage: &'cut Q04RootStageRecipeV1,
    pub(super) controller: VerifiedControllerProjectAdmissionV1,
    pub(super) project: &'cut VerifiedSignedProjectPolicySourceV2,
    pub(super) deployment_head: PolicyDeploymentHeadV1,
    pub(super) project_input: &'packet [u8],
    pub(super) deployment_inputs: PolicyDeploymentInputsV1<'packet>,
    pub(super) controller_packet: &'packet [u8],
    pub(super) proposed: &'packet [u8],
    pub(super) purpose: RootInputCurrentPurposeV1<'cut, 'packet>,
}

// Only Held carries real held/Cache evidence. Prehold is deliberately a
// separate, nonissuing DATA purpose; it cannot be used to authenticate a
// publication or drive a durable action through this shared model verifier.
pub(in crate::native) enum RootInputCurrentPurposeV1<'cut, 'packet> {
    Prehold {
        request_packet: &'packet [u8],
    },
    Held {
        identity: &'cut Q04CutIdentityV1,
        held: VerifiedControllerHoldReadbackV1,
        held_packet: &'packet [u8],
        cache_packet: &'packet [u8],
        cache: VerifiedClosedCacheOwnerReadbackV2,
        cache_uid: u32,
    },
    TerminalHeld {
        identity: &'cut Q04CutIdentityV1,
        held: VerifiedControllerHoldReadbackV1,
        held_packet: &'packet [u8],
        cache_packet: &'packet [u8],
        cache: VerifiedClosedCacheOwnerReadbackV2,
        cache_uid: u32,
        kind: Q04AcknowledgementKindV1,
        acknowledgement: &'packet [u8],
        original_next: u64,
        original_names: ProtectedJournalNamesV1,
    },
    TerminalReleased {
        identity: &'cut Q04CutIdentityV1,
        held: VerifiedControllerHoldReadbackV1,
        held_packet: &'packet [u8],
        cache_packet: &'packet [u8],
        cache: VerifiedClosedCacheOwnerReadbackV2,
        cache_uid: u32,
        kind: Q04AcknowledgementKindV1,
        acknowledgement: &'packet [u8],
        original_next: u64,
        original_names: ProtectedJournalNamesV1,
        observed: &'cut aos_sandbox_cache::CacheResidencyRootReadOnlyPolicyHoldV1,
    },
}

impl RootCurrentInputVerifierV1<'_, '_, '_, '_, '_> {
    pub(in crate::native) fn require_actual_append_current_v1(&self) -> Result<(), ()> {
        let eligible = matches!(
            (&self.original, &self.purpose),
            (RootCurrentOwnerLoanV1::Publication(_), RootInputCurrentPurposeV1::Held { .. })
        );
        let returned = if eligible {
            self.recheck().map(|()| true)
        } else {
            Err(ErrorV1::ChangedCut)
        };
        if self.original.require_model_verification(returned) { Ok(()) } else { Err(()) }
    }

    pub(super) fn recheck(&self) -> Result<(), ErrorV1> {
        let now = self.original.recheck()?.wall_seconds();
        self.gen1.recheck()?;
        match &self.purpose {
            RootInputCurrentPurposeV1::Prehold { .. } => {}
            RootInputCurrentPurposeV1::Held { cache_uid, .. }
            | RootInputCurrentPurposeV1::TerminalHeld { cache_uid, .. }
            | RootInputCurrentPurposeV1::TerminalReleased { cache_uid, .. } => {
                self.original.require_cache_uid_v1(*cache_uid)?;
            }
        }
        let (controller, observed_held) = match &self.purpose {
            RootInputCurrentPurposeV1::Prehold { request_packet } => {
                let (request, controller) = self.gen1.prehold_input(request_packet, self.stage)?;
                if request.fields()[5] != self.controller_packet
                    || request.fields()[4] != self.proposed
                {
                    return Err(ErrorV1::ChangedCut);
                }
                let metadata = request.fields()[0];
                let start = u64::from_be_bytes(crate::q04_data::fixed(metadata, 16));
                let cutoff = u64::from_be_bytes(crate::q04_data::fixed(metadata, 24));
                if metadata[..16] != self.original.clock().host_boot_id()
                    || start > self.original.clock().boottime_nanoseconds()
                    || self.original.recheck()?.boottime_nanoseconds() >= cutoff
                {
                    return Err(ErrorV1::Expired);
                }
                (controller, None)
            }
            RootInputCurrentPurposeV1::Held {
                identity,
                held_packet,
                ..
            } => {
                let (controller, observed_held) = self.gen1.controller_cut(
                    self.controller_packet,
                    held_packet,
                    self.proposed,
                    self.stage,
                    identity,
                )?;
                (controller, Some(observed_held))
            }
            RootInputCurrentPurposeV1::TerminalHeld {
                identity,
                held_packet,
                kind,
                acknowledgement,
                original_next,
                original_names,
                ..
            }
            | RootInputCurrentPurposeV1::TerminalReleased {
                identity,
                held_packet,
                kind,
                acknowledgement,
                original_next,
                original_names,
                ..
            } => {
                self.gen1
                    .acknowledgement(*kind, acknowledgement, identity, *original_names)?;
                let (controller, observed_held) = self.gen1.original_controller_provenance(
                    self.controller_packet,
                    held_packet,
                    self.proposed,
                    self.stage,
                    identity,
                    *original_next,
                )?;
                (controller, Some(observed_held))
            }
        };
        let (project, deployment, _) =
            self.gen1
                .signed_project_sources(self.project_input, &self.deployment_inputs, now)?;
        if let RootInputCurrentPurposeV1::Held {
            identity,
            held,
            cache_packet,
            cache,
            cache_uid,
            ..
        }
        | RootInputCurrentPurposeV1::TerminalHeld {
            identity,
            held,
            cache_packet,
            cache,
            cache_uid,
            ..
        } = &self.purpose
        {
            let observed_cache = self.gen1.cache_cut(
                cache_packet,
                self.proposed,
                self.stage,
                identity,
                *cache_uid,
            )?;
            if observed_held != Some(*held)
                || observed_cache != *cache
                || identity.bytes()[360..392] != *self.gen1.floor().tree_head().as_bytes()
            {
                return Err(ErrorV1::ChangedCut);
            }
        }
        if let RootInputCurrentPurposeV1::TerminalReleased {
            identity,
            held,
            cache_packet,
            cache,
            cache_uid,
            observed,
            ..
        } = &self.purpose
        {
            let original_cache = self.gen1.original_cache_provenance(
                cache_packet,
                self.proposed,
                self.stage,
                identity,
                *cache_uid,
            )?;
            if observed_held != Some(*held)
                || original_cache != *cache
                || observed.hold.is_held()
                || observed.hold.record_digest()?
                    != original_cache.hold().q04_released_record_digest()?
                || observed.replay.quota_digest != identity.cache_quota()
                || identity.bytes()[360..392] != *self.gen1.floor().tree_head().as_bytes()
            {
                return Err(ErrorV1::ChangedCut);
            }
        }
        let revocation = aos_sandbox_protocol::policy_data::project_revocation_digest(
            controller.project(),
            controller.revocation_scope(),
            controller.revocation_generation(),
        );
        if controller != self.controller
            || project.head() != self.project.head()
            || project.cache_domain() != self.project.cache_domain()
            || project.revocation() != self.project.revocation()
            || deployment != self.deployment_head
            || project.head().project() != controller.project()
            || project.head().publisher_generation() != controller.publisher_generation()
            || project.head().publisher_digest() != controller.publisher_digest()
            || project.head().prerequisite_claims()
                != [
                    self.gen1.floor().tree_head(),
                    deployment.packet_digest(),
                    controller.cache_domain_head(),
                    controller.revocation_head(),
                ]
            || controller.revocation_head() != revocation
            || project.revocation().mode() != controller.revocation_mode()
            || project.revocation().grace_nanos() != controller.revocation_grace_nanos()
        {
            return Err(ErrorV1::ChangedCut);
        }
        self.gen1.recheck()?;
        let current = self.original.recheck()?;
        match &self.purpose {
            RootInputCurrentPurposeV1::Prehold { request_packet } => {
                let request = Q04PreholdInputDataV1::decode(request_packet)?;
                let cutoff = u64::from_be_bytes(crate::q04_data::fixed(request.fields()[0], 24));
                if current.boottime_nanoseconds() >= cutoff {
                    return Err(ErrorV1::Expired);
                }
            }
            RootInputCurrentPurposeV1::Held { identity, .. }
            | RootInputCurrentPurposeV1::TerminalHeld { identity, .. }
            | RootInputCurrentPurposeV1::TerminalReleased { identity, .. } => {
                if current.host_boot_id() != crate::q04_data::fixed(identity.bytes(), 112)
                    || current.boottime_nanoseconds()
                        >= u64::from_be_bytes(crate::q04_data::fixed(identity.bytes(), 136))
                {
                    return Err(ErrorV1::Expired);
                }
            }
        }
        Ok(())
    }

    // Both purposes reuse the same authenticated layer/relation and compiler
    // constructors. The repeated purpose-specific checks are intentionally
    // kept around each brand/allocation boundary rather than cached once.
    pub(super) fn compile_authenticated_input(
        &self,
        deployment: &crate::signed_inputs::PolicyDeploymentSourcesV1,
    ) -> Result<
        (
            PolicyCompilerInputV1,
            PolicyPublicationPrerequisitesV1,
            ObjectDigest,
            CompiledPolicyCandidateV1,
        ),
        ErrorV1,
    > {
        let domain = AuthenticatedCacheDomainV1::authenticate(
            self.project.cache_domain(),
            CacheDomainBindingV1::Project(self.controller.project()),
            self,
        ).map_err(crate::parentless_input::ParentlessPolicyInputDataErrorV1::from)?;
        self.recheck()?;
        let layer = self
            .project
            .q04_layer_recipe()
            .materialize_with_authenticated_binding(domain)?;
        let relation = AuthenticatedSandboxProjectRelationV1::authenticate(
            self.controller.sandbox(),
            self.controller.project(),
            self,
        ).map_err(crate::parentless_input::ParentlessPolicyInputDataErrorV1::from)?;
        self.recheck()?;
        let input = crate::parentless_input::parentless_create_input_from_authenticated_layers_v1(
            relation, layer, deployment,
        )?;
        let prerequisites = PolicyPublicationPrerequisitesV1::new(
            self.gen1.floor().tree_head(),
            self.deployment_head.packet_digest(),
            self.controller.cache_domain_head(),
            self.controller.revocation_head(),
            self.stage.staged().base().next_generation(),
        )?;
        self.recheck()?;
        let normalized = normalized_policy_input_digest_v1(&input).map_err(|_| {
            crate::native::publication::PolicyCompilerJournalErrorV1::NonCanonicalPublication
        })?;
        let candidate = PolicyCompilerV1::compile_retained(&input)?;
        self.recheck()?;
        Ok((input, prerequisites, normalized, candidate))
    }

    fn verify_descriptor(
        &self,
        descriptor: &ObjectDescriptor,
        canonical_bytes: &[u8],
    ) -> Result<bool, ErrorV1> {
        self.recheck()?;
        let media =
            MediaType::new(PortableMediaType::Content.as_str()).map_err(|_| ErrorV1::ChangedCut)?;
        let matches = !canonical_bytes.is_empty()
            && descriptor_for_bytes(media, canonical_bytes) == *descriptor;
        self.recheck()?;
        Ok(matches)
    }
}

impl CacheDomainVerifierV1 for RootCurrentInputVerifierV1<'_, '_, '_, '_, '_> {
    fn verify(&self, descriptor: &ObjectDescriptor, canonical_bytes: &[u8]) -> bool {
        self.original
            .require_model_verification(self.verify_descriptor(descriptor, canonical_bytes))
    }
}

impl SandboxProjectRelationVerifierV1 for RootCurrentInputVerifierV1<'_, '_, '_, '_, '_> {
    fn verify(
        &self,
        sandbox: aos_sandbox_model::SandboxId,
        project: aos_sandbox_model::ProjectId,
        descriptor: &ObjectDescriptor,
        canonical_bytes: &[u8],
    ) -> bool {
        self.original.require_model_verification(
            if sandbox == self.controller.sandbox() && project == self.controller.project() {
                self.verify_descriptor(descriptor, canonical_bytes)
            } else {
                Ok(false)
            },
        )
    }
}

// Prehold supplies provenance only. The held publication position separately
// rejoins the real original Root/gen1/Controller/Cache cut; copied prerequisite
// fields cannot select it. Generic effect completion remains unavailable.
impl PolicyPublicationVerifierV1 for RootCurrentInputVerifierV1<'_, '_, '_, '_, '_> {
    fn prerequisite_evidence_is_authentic(
        &self,
        prerequisites: &PolicyPublicationPrerequisitesV1,
    ) -> bool {
        self.original
            .require_model_verification(self.recheck().map(|()| {
                prerequisites.ancestry_head() == self.gen1.floor().tree_head()
                    && prerequisites.compiler_authority_head()
                        == self.deployment_head.packet_digest()
                    && prerequisites.cache_domain_head() == self.controller.cache_domain_head()
                    && prerequisites.revocation_head() == self.controller.revocation_head()
                    && prerequisites.generation() == self.stage.staged().base().next_generation()
            }))
    }

    fn prerequisites_are_current(&self, prerequisites: &PolicyPublicationPrerequisitesV1) -> bool {
        if !matches!(&self.purpose, RootInputCurrentPurposeV1::Held { .. }) {
            return false;
        }
        self.prerequisite_evidence_is_authentic(prerequisites)
    }

    fn while_prerequisites_current<T>(
        &self,
        prerequisites: &PolicyPublicationPrerequisitesV1,
        action: impl FnOnce() -> T,
    ) -> Option<T> {
        if !matches!(&self.original, RootCurrentOwnerLoanV1::Publication(_))
            || !self.prerequisites_are_current(prerequisites)
        {
            return None;
        }
        // The same Root writer/current-floor loan and original external cut
        // remain borrowed through the action. Its actual returned ownership
        // must be parked by the enclosing fixed caller BEFORE postchecks;
        // adding a fallible postcheck here would drop an ambiguous outcome.
        Some(action())
    }

    fn while_effect_observation_current<T>(
        &self,
        _prerequisites: &PolicyPublicationPrerequisitesV1,
        _request: &PolicyEffectObservationRequestV1,
        _action: impl FnOnce(VerifiedPolicyEffectObservationV1) -> T,
    ) -> Option<T> {
        None
    }

    fn verify(
        &self,
        project: aos_sandbox_model::ProjectId,
        sandbox: aos_sandbox_model::SandboxId,
        normalized_input: ObjectDigest,
        candidate: ObjectDigest,
        prerequisites: &PolicyPublicationPrerequisitesV1,
    ) -> bool {
        let RootInputCurrentPurposeV1::Held { identity, .. } = &self.purpose else {
            return false;
        };
        self.original
            .require_model_verification(self.recheck().map(|()| {
                project == self.controller.project()
                    && sandbox == self.controller.sandbox()
                    && project == identity.project()
                    && sandbox == identity.sandbox()
                    && normalized_input.as_bytes() == &identity.bytes()[456..488]
                    && candidate.as_bytes() == &identity.bytes()[488..520]
                    && prerequisites.ancestry_head() == self.gen1.floor().tree_head()
                    && prerequisites.compiler_authority_head()
                        == self.deployment_head.packet_digest()
                    && prerequisites.cache_domain_head() == self.controller.cache_domain_head()
                    && prerequisites.revocation_head() == self.controller.revocation_head()
                    && prerequisites.generation() == identity.epoch()
            }))
    }
}
