//! Canonical closed-policy binding and Stage comparison DATA.
//!
//! AOSPCB02 and AOSPBS02 retain their exact existing bytes and checksums.
//! Their fields and recipes are unbranded DATA; native Authority independently
//! compares the current protected base, saved prior and actual original nonce.

use super::{PolicyQ04DataErrorV1, challenge::RootChallengeRecordCodec};
use crate::signed_inputs::PolicyDeploymentHeadV1;
use aos_sandbox_model::{
    ObjectDigest, OperationId, ProjectId, RecordNamespace, SandboxId,
};
use aos_sandbox_protocol::domain_ledger::cache_policy_hold::CachePolicyHoldV1;
use aos_sandbox_protocol::domain_ledger::controller_policy_hold::ControllerPolicyHoldV1;
use aos_sandbox_protocol::domain_ledger::source_policy_hold::SourceDomainPolicyHoldV1;
use aos_sandbox_protocol::domain_ledger::transaction::{JournalRecord, JournalTransaction};
use sha2::{Digest as _, Sha256};

pub use aos_sandbox_protocol::policy_data::binding_v2::{
    BINDING_V2_KEY_PREFIX, CLOSED_POLICY_BINDING_BYTES_V2, ROOT_BINDING_HEAD_KEY,
    HOLD_KEY, ClosedPolicyRootBindingV2, RootBindingHoldV1, RootQualifiedProofV1,
    ClosedCreateProposalFieldViewV2, closed_policy_binding_digest_v2,
    decode_closed_policy_binding_v2, current_root_binding_chain_v2, current_hold_v1, root_policy_issuer_owner_v2,
};
pub const STAGE_KEY: &[u8] = b"\0aos-policy-compiler-binding-stage-v2\0";
pub const STAGE_CODEC: RootChallengeRecordCodec = RootChallengeRecordCodec::new(
    b"AOSPBS02",
    b"aos.sandbox.policy-compiler.binding-stage-record.v2\0",
    b"aos.sandbox.policy-compiler.binding-stage-transaction.v2\0",
    STAGE_KEY,
);
const STAGED_SIGNER_CUT_DOMAIN: &[u8] =
    b"aos.sandbox.policy-compiler.staged-source-cache-signer-cut.v2\0";
const BARRIER_DOMAIN: &[u8] = b"aos.sandbox.policy-compiler.held-cut.v2\0";
const EFFECT_TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.policy-compiler.closed-handoff.v2\0";
/// Compares a closed proposal with the three exact held journal claims.
///
/// This is a necessary, non-authorizing comparison. The caller must obtain
/// each hold from its independent retained writer/readback, and must join the
/// physical Cache signer statement separately. Scalar copies from a Q04
/// request do not establish custody or permit admission.
///
/// # Errors
///
/// Rejects a malformed proposal, released or cross-bound holds, mismatched
/// Create, ancestry, Cache partition/head, binding, or handoff epoch.
pub fn compare_closed_policy_binding_hold_claims_v2(
    proposed: &[u8],
    controller: ControllerPolicyHoldV1,
    source: SourceDomainPolicyHoldV1,
    cache: CachePolicyHoldV1,
) -> Result<(), PolicyQ04DataErrorV1> {
    compare_closed_policy_binding_claims_with_cache_phase_v2(
        proposed, controller, source, cache, true,
    )
}

/// Compares a released Cache row to still-held Controller and Source claims.
///
/// # Errors
///
/// Rejects any noncanonical proposal or mismatched owner identity or phase.
pub fn compare_closed_policy_binding_released_cache_claims_v2(
    proposed: &[u8],
    controller: ControllerPolicyHoldV1,
    source: SourceDomainPolicyHoldV1,
    cache: CachePolicyHoldV1,
) -> Result<(), PolicyQ04DataErrorV1> {
    compare_closed_policy_binding_claims_with_cache_phase_v2(
        proposed, controller, source, cache, false,
    )
}

fn compare_closed_policy_binding_claims_with_cache_phase_v2(
    proposed: &[u8],
    controller: ControllerPolicyHoldV1,
    source: SourceDomainPolicyHoldV1,
    cache: CachePolicyHoldV1,
    cache_held: bool,
) -> Result<(), PolicyQ04DataErrorV1> {
    let binding = ClosedPolicyRootBindingV2::decode(proposed)?;
    let head = closed_policy_binding_digest_v2(proposed)?;
    if !controller.is_held()
        || !source.is_held()
        || cache.is_held() != cache_held
        || controller.operation() != binding.operation
        || controller.sandbox() != binding.sandbox
        || controller.binding() != head
        || controller.epoch() != binding.handoff_epoch
        || source.operation() != binding.operation
        || source.sandbox() != binding.sandbox
        || source.controller_source() != controller.source()
        || source.ancestry() != binding.ancestry_head
        || source.binding() != head
        || source.epoch() != binding.handoff_epoch
        || cache.project() != binding.project
        || cache.partition() != binding.physical_partition
        || cache.cache_head() != binding.physical_cache_head
        || cache.binding() != head
        || cache.epoch() != binding.handoff_epoch
    {
        return Err(PolicyQ04DataErrorV1::UnauthenticatedCandidate);
    }
    Ok(())
}

pub use aos_sandbox_protocol::domain_ledger::create_q04_history::transfer::{
    ClosedPolicyRootCasBaseV2, StagedClosedPolicyRootBaseV2,
};

// Reservation is comparison DATA. It owns the sole existing Stage encoding,
// not a Root lease or permission to commit after the original cut changes.
pub struct Q04RootStageRecipeV1 {
    pub project: ProjectId,
    pub staged: StagedClosedPolicyRootBaseV2,
    pub prior: Option<Vec<u8>>,
    pub cut: ObjectDigest,
    pub record: [u8; 96],
    pub transaction: JournalTransaction,
}

impl Q04RootStageRecipeV1 {
    pub const fn project(&self) -> ProjectId {
        self.project
    }

    pub const fn staged(&self) -> StagedClosedPolicyRootBaseV2 {
        self.staged
    }

    pub const fn cut(&self) -> ObjectDigest {
        self.cut
    }

    pub const fn transaction(&self) -> &JournalTransaction {
        &self.transaction
    }

    // The actual Q04 Root history has already proved the complete original
    // before-state and every intervening self-append. This checks its sole
    // reserved Stage row without restaging, renewing, or constructing a V8
    // proof. Ordinary Stage/CAS entry points retain their existing checks.
    pub fn require_original_row_data_v1(
        &self,
        row: Option<&[u8]>,
        committed: bool,
    ) -> Result<(), PolicyQ04DataErrorV1> {
        let expected = if committed {
            Some(self.record.as_slice())
        } else {
            self.prior.as_deref()
        };
        if row != expected {
            return Err(PolicyQ04DataErrorV1::UnauthenticatedCandidate);
        }
        Ok(())
    }

    // Capacity DATA reuses the sole old binding/head/hold record encoders.
    // It has no commit method or signer proof; the live Root action must
    // independently rejoin its real staged CAS base and held owners.
    pub fn q04_binding_capacity_records(
        &self,
        proposed: &[u8],
    ) -> Result<(Vec<JournalRecord>, JournalRecord), PolicyQ04DataErrorV1> {
        let binding = ClosedPolicyRootBindingV2::decode(proposed)?;
        let base = self.staged.base();
        if binding.project != self.project
            || binding.issuer_owner != base.issuer_owner()
            || binding.root_predecessor != base.predecessor()
            || binding.root_generation != base.next_generation()
            || binding.handoff_epoch != base.next_generation()
            || binding.barrier_epoch != base.next_generation()
            || binding.deployment_signer_generation != base.deployment_signer_generation()
            || binding.project_signer_generation != base.project_signer_generation()
        {
            return Err(PolicyQ04DataErrorV1::UnauthenticatedCandidate);
        }
        let key = binding.key()?;
        let head = closed_policy_binding_digest_v2(proposed)?;
        let held = RootBindingHoldV1 {
            issuer_owner: binding.issuer_owner,
            binding: head,
            epoch: binding.handoff_epoch,
            held: true,
        };
        let records = vec![
            JournalRecord::put(RecordNamespace::DesiredState, key, proposed.to_vec()),
            JournalRecord::put(
                RecordNamespace::DesiredState,
                ROOT_BINDING_HEAD_KEY.to_vec(),
                head.as_bytes().to_vec(),
            ),
            JournalRecord::put(
                RecordNamespace::DesiredState,
                HOLD_KEY.to_vec(),
                held.encode()?.to_vec(),
            ),
        ];
        let released = JournalRecord::put(
            RecordNamespace::DesiredState,
            HOLD_KEY.to_vec(),
            RootBindingHoldV1 {
                held: false,
                ..held
            }
            .encode()?
            .to_vec(),
        );
        Ok((records, released))
    }

    // The prehold transfer encodes the actual once-reserved base and Stage
    // fields. Its separate record cut is not the B664-derived signer cut.
    pub fn preview_fields(&self) -> [u8; 128] {
        let base = self.staged.base();
        let mut fields = [0; 128];
        fields[..16].copy_from_slice(&base.issuer_owner());
        fields[16..48].copy_from_slice(base.predecessor().as_bytes());
        fields[48..56].copy_from_slice(&base.next_generation().to_be_bytes());
        fields[56..64].copy_from_slice(&base.deployment_signer_generation().to_be_bytes());
        fields[64..72].copy_from_slice(&base.project_signer_generation().to_be_bytes());
        fields[72..88].copy_from_slice(&self.staged.challenge());
        fields[88..96].copy_from_slice(&self.staged.issue_epoch().to_be_bytes());
        fields[96..128].copy_from_slice(self.cut.as_bytes());
        fields
    }
}

// This borrowed view contains only comparison fields already selected by a
// caller's real owner engine. It is not a Controller source, brand or permission
// to publish. Root constructs it only after its independent original-cut join.
// Q04 may borrow its already compiled candidate/input commitments here only
// after its actual Root/current-owner verifier rechecks the full original cut.
// This sole serializer/barrier/effect recipe remains comparison DATA.
#[allow(clippy::too_many_arguments)]
pub fn encode_closed_proposal_fields(
    fields: &ClosedCreateProposalFieldViewV2<'_>,
    project_packet: ObjectDigest,
    project_input: ObjectDigest,
    deployment_head: PolicyDeploymentHeadV1,
    normalized_input: ObjectDigest,
    candidate: ObjectDigest,
    root_base: ClosedPolicyRootCasBaseV2,
    checked_draft: ObjectDigest,
) -> Result<Vec<u8>, PolicyQ04DataErrorV1> {
    let barrier_head = ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(BARRIER_DOMAIN)
            .chain_update(fields.source_commitment.as_bytes())
            .chain_update(checked_draft.as_bytes())
            .chain_update(fields.ancestry.as_bytes())
            .chain_update(fields.physical_partition.as_bytes())
            .chain_update(fields.physical_cache.as_bytes())
            .chain_update(project_packet.as_bytes())
            .chain_update(deployment_head.packet_digest().as_bytes())
            .chain_update(normalized_input.as_bytes())
            .chain_update(candidate.as_bytes())
            .chain_update(root_base.predecessor().as_bytes())
            .chain_update(root_base.next_generation().to_be_bytes())
            .finalize()
            .into(),
    );
    // The effect ID is deterministic across a lost response. A second root
    // generation cannot reuse it for the same accepted Create.
    let effect_digest = Sha256::new()
        .chain_update(EFFECT_TRANSACTION_DOMAIN)
        .chain_update(fields.operation.as_bytes())
        .chain_update(fields.operation_revision.as_bytes())
        .chain_update(normalized_input.as_bytes())
        .chain_update(candidate.as_bytes())
        .finalize();
    let effect_transaction: [u8; 16] = effect_digest[..16]
        .try_into()
        .map_err(|_| PolicyQ04DataErrorV1::UnauthenticatedCandidate)?;

    ClosedPolicyRootBindingV2 {
        issuer_owner: root_base.issuer_owner(),
        project: *fields.project,
        sandbox: *fields.sandbox,
        operation: *fields.operation,
        operation_revision: *fields.operation_revision,
        accepted_generation: *fields.accepted_generation,
        projection_revision: *fields.projection_revision,
        publisher_generation: *fields.publisher_generation,
        publisher_head: *fields.publisher_head,
        project_policy_head: project_packet,
        project_policy_input: project_input,
        ancestry_head: *fields.ancestry,
        compiler_head: deployment_head.packet_digest(),
        cache_domain_head: *fields.cache_domain_head,
        revocation_head: *fields.revocation_head,
        physical_partition: *fields.physical_partition,
        physical_cache_head: *fields.physical_cache,
        normalized_input,
        candidate,
        project_signer_generation: root_base.project_signer_generation(),
        deployment_signer_generation: root_base.deployment_signer_generation(),
        barrier_epoch: root_base.next_generation(),
        barrier_head,
        root_predecessor: root_base.predecessor(),
        root_generation: root_base.next_generation(),
        effect_transaction,
        handoff_epoch: root_base.next_generation(),
    }
    .encode().map_err(Into::into)
}

impl Q04RootStageRecipeV1 {
    /// Forms canonical Stage comparison DATA from untrusted source fields.
    ///
    /// Native Authority must independently prove the base, prior row and
    /// original nonce before any transaction or publication may be admitted.
    ///
    /// # Errors
    /// Rejects a noncanonical prior, reused nonce, zero cut or exhausted epoch.
    pub fn from_untrusted_fields_v1(
        project: ProjectId,
        base: ClosedPolicyRootCasBaseV2,
        prior: Option<&[u8]>,
        original_nonce: [u8; 16],
        cut: ObjectDigest,
    ) -> Result<Self, PolicyQ04DataErrorV1> {
        let (prior_epoch, prior_nonce) = STAGE_CODEC
            .read_prior(prior)
            .ok_or(PolicyQ04DataErrorV1::UnauthenticatedCandidate)?;
        let issue_epoch = prior_epoch
            .checked_add(1)
            .ok_or(PolicyQ04DataErrorV1::UnauthenticatedCandidate)?;
        if original_nonce == [0; 16] || original_nonce == prior_nonce || cut.as_bytes() == &[0; 32]
        {
            return Err(PolicyQ04DataErrorV1::UnauthenticatedCandidate);
        }
        let record = STAGE_CODEC.encode(issue_epoch, original_nonce, cut);
        let transaction = STAGE_CODEC.transaction(record)?;
        Ok(Self {
            project,
            staged: StagedClosedPolicyRootBaseV2 {
                base,
                challenge: original_nonce,
                issue_epoch,
            },
            prior: prior.map(<[u8]>::to_vec),
            cut,
            record,
            transaction,
        })
    }
}

/// Names one nonauthorizing challenge for both independent Q04 signer roles.
///
/// Root must revalidate the staged token before accepting packets on this cut.
/// The existing Cache V2 transport spends a different `AOSCRH02` challenge,
/// so it cannot supply a packet for this cut. V3 supplies it only within a
/// nonauthorizing Root-last held flight.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StagedClosedPolicySignerChallengeV2 {
    nonce: [u8; 16],
    cut: ObjectDigest,
    issue_epoch: u64,
}

impl StagedClosedPolicySignerChallengeV2 {
    /// Returns the Root-staged nonce shared by the Source and Cache packets.
    #[must_use]
    pub const fn nonce(self) -> [u8; 16] {
        self.nonce
    }

    /// Returns the exact staged-token and canonical-proposal commitment.
    #[must_use]
    pub const fn cut(self) -> ObjectDigest {
        self.cut
    }

    /// Returns the protected Root stage epoch for versioned signer transport.
    #[must_use]
    pub const fn issue_epoch(self) -> u64 {
        self.issue_epoch
    }
}

/// Derives one exact Source/Cache challenge from a Root stage and proposal.
///
/// This deterministic derivation does not authenticate the staged token.
/// Root revalidates its durable stage and protected signer pins during the
/// joined readback. The held-flight transport cannot open first CAS.
///
/// # Errors
///
/// Rejects a malformed proposal or noncanonical challenge.
pub fn staged_closed_policy_signer_challenge_v2(
    staged: StagedClosedPolicyRootBaseV2,
    proposed: &[u8],
) -> Result<StagedClosedPolicySignerChallengeV2, PolicyQ04DataErrorV1> {
    let binding = closed_policy_binding_digest_v2(proposed)?;
    let base = staged.base();
    let cut = ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(STAGED_SIGNER_CUT_DOMAIN)
            .chain_update(base.issuer_owner())
            .chain_update(base.predecessor().as_bytes())
            .chain_update(base.next_generation().to_be_bytes())
            .chain_update(base.deployment_signer_generation().to_be_bytes())
            .chain_update(base.project_signer_generation().to_be_bytes())
            .chain_update(staged.challenge())
            .chain_update(staged.issue_epoch().to_be_bytes())
            .chain_update(binding.as_bytes())
            .finalize()
            .into(),
    );
    if cut.as_bytes() == &[0; 32] {
        return Err(PolicyQ04DataErrorV1::UnauthenticatedCandidate);
    }
    Ok(StagedClosedPolicySignerChallengeV2 {
        nonce: staged.challenge(),
        cut,
        issue_epoch: staged.issue_epoch(),
    })
}

/// Carries canonical binding-source fields without authenticating their origin.
pub struct RootPolicyBindingIdentityV2 {
    pub deployment_head: ObjectDigest,
    pub project: ProjectId,
    pub publisher_generation: u64,
    pub publisher_head: ObjectDigest,
    pub project_policy_head: ObjectDigest,
    pub project_policy_input: ObjectDigest,
    pub prerequisite_claims: [ObjectDigest; 4],
    pub deployment_signer_generation: u64,
    pub project_signer_generation: u64,
    pub issuer_owner: [u8; 16],
}

impl RootPolicyBindingIdentityV2 {
    pub fn matches(&self, binding: &ClosedPolicyRootBindingV2) -> bool {
        let claims = self.prerequisite_claims;
        binding.issuer_owner == self.issuer_owner
            && binding.project == self.project
            && binding.publisher_generation == self.publisher_generation
            && binding.publisher_head == self.publisher_head
            && binding.project_policy_head == self.project_policy_head
            && binding.project_policy_input == self.project_policy_input
            && binding.ancestry_head == claims[0]
            && binding.compiler_head == self.deployment_head
            && binding.cache_domain_head == claims[2]
            && binding.revocation_head == claims[3]
            && binding.deployment_signer_generation == self.deployment_signer_generation
            && binding.project_signer_generation == self.project_signer_generation
    }

    pub fn stage_cut(&self, base: ClosedPolicyRootCasBaseV2) -> ObjectDigest {
        let mut digest = Sha256::new()
            .chain_update(STAGE_CUT_DOMAIN)
            .chain_update(base.issuer_owner)
            .chain_update(base.predecessor.as_bytes())
            .chain_update(base.next_generation.to_be_bytes())
            .chain_update(base.deployment_signer_generation.to_be_bytes())
            .chain_update(base.project_signer_generation.to_be_bytes())
            .chain_update(self.deployment_head.as_bytes())
            .chain_update(self.project.as_bytes())
            .chain_update(self.publisher_generation.to_be_bytes())
            .chain_update(self.publisher_head.as_bytes())
            .chain_update(self.project_policy_head.as_bytes())
            .chain_update(self.project_policy_input.as_bytes());
        for claim in self.prerequisite_claims {
            digest.update(claim.as_bytes());
        }
        ObjectDigest::from_bytes(digest.finalize().into())
    }
}

const STAGE_CUT_DOMAIN: &[u8] = b"aos.sandbox.policy-compiler.binding-stage-cut.v2\0";
