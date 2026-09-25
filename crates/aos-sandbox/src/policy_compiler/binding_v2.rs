//! Closed root-policy binding format for a future cross-owner issuer.
//!
//! `AOSPCB02` records bind the accepted Create, signed inputs, independent
//! owner heads, physical Cache partition, and one handoff epoch. The root
//! producer can durably compare-and-swap a closed record under its writer,
//! but no verifier grants publication from this format until a live ordered
//! barrier and recoverable effect handoff establish every independent field.
//!
//! ```text
//! AOSPCB02 | version=2 | reserved=0 | issuer/project/sandbox/Create |
//! accepted operation revision/generation | projection | publisher |
//! signed project | ancestry/compiler/cache-domain/revocation |
//! physical partition/replay head | normalized input/candidate |
//! signer generations | barrier/root CAS | effect handoff epoch | SHA-256
//! ```
//!
//! A staged, nonauthorizing Root base uses the separate protected record:
//!
//! ```text
//! AOSPBS02 | issue-epoch:u64 | root-nonce:16 | exact-root-source-cut:32 | SHA-256
//! ```

use std::{collections::BTreeSet, path::Path};

use aos_sandbox_core::{ObjectDigest, OperationId, ProjectId, SandboxId};
use ed25519_dalek::VerifyingKey;
use sha2::{Digest as _, Sha256};

use crate::cache_residency::release_fixed_closed_policy_cache_hold_after_root_readback_v1;
use crate::journal::{
    CachePolicyHoldV1, ControllerPolicyHoldV1, Journal, JournalRecord, JournalTransaction,
    ProtectedJournalAuthority, ProtectedJournalSnapshot, RecordNamespace, SourceDomainPolicyHoldV1,
};
use crate::lifecycle::protected_journal_adapter::ProtectedDomainJournalErrorV1;
use crate::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1;

use super::cache_journal_readback::read_fixed_policy_cache_hold_v1;
use super::deployment_head::{
    HEAD_KEY, PROJECT_HEAD_KEY, PROJECT_INPUT_KEY, SIGNER_PINS_KEY, encode_policy_signer_pins_v1,
};
use super::project_source_v2::{HEAD_KEY_V2, INPUT_KEY_V2};
use super::protected_owner::{
    MAXIMUM_POLICY_BINDINGS, POLICY_AUTHORITY_JOURNAL, POLICY_BINDING_KEY_PREFIX,
    PROTECTED_POLICY_ROOT, policy_authority_journal_limits,
};
use super::root_challenge_record::RootChallengeRecordCodec;
use super::{
    PolicyCompilerJournalErrorV1, SignedProjectPolicyHeadV1, SignedProjectPolicyHeadV2,
    verify_signed_project_policy_source_v2,
};

mod hold;
mod producer;

use hold::{HOLD_KEY, RootBindingHoldV1, current_hold, release_hold};

pub use producer::{
    propose_closed_current_create_explicit_policy_binding_v2,
    propose_closed_current_create_policy_binding_v2,
};

pub(super) const BINDING_V2_KEY_PREFIX: &[u8] = b"\0aos-policy-compiler-binding-v2\0";
const MAGIC: &[u8; 8] = b"AOSPCB02";
const CHECKSUM_DOMAIN: &[u8] = b"aos.sandbox.policy-compiler.protected-binding.v2\0";
const KEY_DOMAIN: &[u8] = b"aos.sandbox.policy-compiler.binding-key.v2\0";
const STAGE_KEY: &[u8] = b"\0aos-policy-compiler-binding-stage-v2\0";
const STAGE_MAGIC: &[u8; 8] = b"AOSPBS02";
const STAGE_CUT_DOMAIN: &[u8] = b"aos.sandbox.policy-compiler.binding-stage-cut.v2\0";
const STAGE_RECORD_DOMAIN: &[u8] = b"aos.sandbox.policy-compiler.binding-stage-record.v2\0";
const STAGE_TRANSACTION_DOMAIN: &[u8] =
    b"aos.sandbox.policy-compiler.binding-stage-transaction.v2\0";
const STAGE_CODEC: RootChallengeRecordCodec = RootChallengeRecordCodec::new(
    STAGE_MAGIC,
    STAGE_RECORD_DOMAIN,
    STAGE_TRANSACTION_DOMAIN,
    STAGE_KEY,
);
const RECORD_BYTES: usize = 664;
/// Bounds one closed AOSPCB02 record on the root controller socket.
pub const CLOSED_POLICY_BINDING_BYTES_V2: usize = RECORD_BYTES;
const BODY_BYTES: usize = RECORD_BYTES - 32;
const ROOT_BINDING_HEAD_KEY: &[u8] = b"\0aos-policy-compiler-binding-head-v2\0";
const ROOT_TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.policy-compiler-binding-cas.v2\0";
const ISSUER_DOMAIN: &[u8] = b"aos.sandbox.policy-controller-owner.v2\0";

/// Retains canonical fields without asserting that their independent owners held a barrier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ClosedPolicyRootBindingV2 {
    issuer_owner: [u8; 16],
    project: ProjectId,
    sandbox: SandboxId,
    operation: OperationId,
    operation_revision: ObjectDigest,
    accepted_generation: u64,
    projection_revision: ObjectDigest,
    publisher_generation: u64,
    publisher_head: ObjectDigest,
    project_policy_head: ObjectDigest,
    project_policy_input: ObjectDigest,
    ancestry_head: ObjectDigest,
    compiler_head: ObjectDigest,
    cache_domain_head: ObjectDigest,
    revocation_head: ObjectDigest,
    physical_partition: ObjectDigest,
    physical_cache_head: ObjectDigest,
    normalized_input: ObjectDigest,
    candidate: ObjectDigest,
    project_signer_generation: u64,
    deployment_signer_generation: u64,
    barrier_epoch: u64,
    barrier_head: ObjectDigest,
    root_predecessor: ObjectDigest,
    root_generation: u64,
    effect_transaction: [u8; 16],
    handoff_epoch: u64,
}

impl ClosedPolicyRootBindingV2 {
    fn canonical(&self) -> bool {
        self.issuer_owner != [0; 16]
            && self.project.as_bytes() != &[0; 16]
            && self.sandbox.as_bytes() != &[0; 16]
            && self.operation.as_bytes() != &[0; 16]
            && self.effect_transaction != [0; 16]
            && self.accepted_generation != 0
            && self.publisher_generation != 0
            && self.project_signer_generation != 0
            && self.deployment_signer_generation != 0
            && self.barrier_epoch != 0
            && self.root_generation != 0
            && self.handoff_epoch == self.barrier_epoch
            && (self.root_predecessor.as_bytes() == &[0; 32]) == (self.root_generation == 1)
            && [
                self.operation_revision,
                self.projection_revision,
                self.publisher_head,
                self.project_policy_head,
                self.project_policy_input,
                self.ancestry_head,
                self.compiler_head,
                self.cache_domain_head,
                self.revocation_head,
                self.physical_partition,
                self.physical_cache_head,
                self.normalized_input,
                self.candidate,
                self.barrier_head,
            ]
            .iter()
            .all(|digest| digest.as_bytes() != &[0; 32])
    }

    fn encode(&self) -> Result<Vec<u8>, PolicyCompilerJournalErrorV1> {
        if !self.canonical() {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }

        let mut bytes = Vec::with_capacity(RECORD_BYTES);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&2_u16.to_be_bytes());
        bytes.extend_from_slice(&[0; 6]);
        bytes.extend_from_slice(&self.issuer_owner);
        bytes.extend_from_slice(self.project.as_bytes());
        bytes.extend_from_slice(self.sandbox.as_bytes());
        bytes.extend_from_slice(self.operation.as_bytes());
        bytes.extend_from_slice(self.operation_revision.as_bytes());
        bytes.extend_from_slice(&self.accepted_generation.to_be_bytes());
        bytes.extend_from_slice(self.projection_revision.as_bytes());
        bytes.extend_from_slice(&self.publisher_generation.to_be_bytes());
        bytes.extend_from_slice(self.publisher_head.as_bytes());
        bytes.extend_from_slice(self.project_policy_head.as_bytes());
        bytes.extend_from_slice(self.project_policy_input.as_bytes());
        bytes.extend_from_slice(self.ancestry_head.as_bytes());
        bytes.extend_from_slice(self.compiler_head.as_bytes());
        bytes.extend_from_slice(self.cache_domain_head.as_bytes());
        bytes.extend_from_slice(self.revocation_head.as_bytes());
        bytes.extend_from_slice(self.physical_partition.as_bytes());
        bytes.extend_from_slice(self.physical_cache_head.as_bytes());
        bytes.extend_from_slice(self.normalized_input.as_bytes());
        bytes.extend_from_slice(self.candidate.as_bytes());
        bytes.extend_from_slice(&self.project_signer_generation.to_be_bytes());
        bytes.extend_from_slice(&self.deployment_signer_generation.to_be_bytes());
        bytes.extend_from_slice(&self.barrier_epoch.to_be_bytes());
        bytes.extend_from_slice(self.barrier_head.as_bytes());
        bytes.extend_from_slice(self.root_predecessor.as_bytes());
        bytes.extend_from_slice(&self.root_generation.to_be_bytes());
        bytes.extend_from_slice(&self.effect_transaction);
        bytes.extend_from_slice(&self.handoff_epoch.to_be_bytes());
        if bytes.len() != BODY_BYTES {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }
        let checksum = Sha256::new()
            .chain_update(CHECKSUM_DOMAIN)
            .chain_update(&bytes)
            .finalize();
        bytes.extend_from_slice(&checksum);
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, PolicyCompilerJournalErrorV1> {
        if bytes.len() != RECORD_BYTES {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }
        let mut reader = BindingReaderV2 { bytes, offset: 0 };
        if reader.take::<8>()? != *MAGIC
            || reader.take::<2>()? != 2_u16.to_be_bytes()
            || reader.take::<6>()? != [0; 6]
        {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }
        let binding = Self {
            issuer_owner: reader.take()?,
            project: ProjectId::from_bytes(reader.take()?),
            sandbox: SandboxId::from_bytes(reader.take()?),
            operation: OperationId::from_bytes(reader.take()?),
            operation_revision: reader.digest()?,
            accepted_generation: reader.u64()?,
            projection_revision: reader.digest()?,
            publisher_generation: reader.u64()?,
            publisher_head: reader.digest()?,
            project_policy_head: reader.digest()?,
            project_policy_input: reader.digest()?,
            ancestry_head: reader.digest()?,
            compiler_head: reader.digest()?,
            cache_domain_head: reader.digest()?,
            revocation_head: reader.digest()?,
            physical_partition: reader.digest()?,
            physical_cache_head: reader.digest()?,
            normalized_input: reader.digest()?,
            candidate: reader.digest()?,
            project_signer_generation: reader.u64()?,
            deployment_signer_generation: reader.u64()?,
            barrier_epoch: reader.u64()?,
            barrier_head: reader.digest()?,
            root_predecessor: reader.digest()?,
            root_generation: reader.u64()?,
            effect_transaction: reader.take()?,
            handoff_epoch: reader.u64()?,
        };
        if reader.offset != BODY_BYTES || binding.encode()?.as_slice() != bytes {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }
        Ok(binding)
    }

    fn key(&self) -> Result<Vec<u8>, PolicyCompilerJournalErrorV1> {
        let encoded = self.encode()?;
        let digest = Sha256::new()
            .chain_update(KEY_DOMAIN)
            .chain_update(encoded)
            .finalize();
        let mut key = Vec::with_capacity(BINDING_V2_KEY_PREFIX.len() + 32);
        key.extend_from_slice(BINDING_V2_KEY_PREFIX);
        key.extend_from_slice(&digest);
        Ok(key)
    }
}

/// Decodes an exact root-journal key/value pair without granting publication authority.
pub(super) fn decode_closed_policy_binding_v2(
    key: &[u8],
    value: &[u8],
) -> Result<ClosedPolicyRootBindingV2, PolicyCompilerJournalErrorV1> {
    let binding = ClosedPolicyRootBindingV2::decode(value)?;
    if binding.key()?.as_slice() != key {
        return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
    }
    Ok(binding)
}

/// Validates one closed AOSPCB02 record and returns its content-addressed head.
///
/// The digest is framing evidence only; it cannot authorize publication or
/// an effect without the independent protected owner barrier.
///
/// # Errors
///
/// Rejects a malformed or noncanonical closed record.
pub fn closed_policy_binding_digest_v2(
    value: &[u8],
) -> Result<ObjectDigest, PolicyCompilerJournalErrorV1> {
    let binding = ClosedPolicyRootBindingV2::decode(value)?;
    let key = binding.key()?;
    let suffix: [u8; 32] = key[BINDING_V2_KEY_PREFIX.len()..]
        .try_into()
        .map_err(|_| PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?;
    Ok(ObjectDigest::from_bytes(suffix))
}

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
) -> Result<(), PolicyCompilerJournalErrorV1> {
    let binding = ClosedPolicyRootBindingV2::decode(proposed)?;
    let head = closed_policy_binding_digest_v2(proposed)?;
    if !controller.is_held()
        || !source.is_held()
        || !cache.is_held()
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
        return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
    }
    Ok(())
}

/// Reports a durable but non-authorizing root CAS and retained handoff epoch.
///
/// Publication replay still rejects every AOSPCB02 binding. This observation
/// must never be passed to an effect owner as a capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClosedPolicyRootCasObservationV2 {
    binding: ObjectDigest,
    root_generation: u64,
    handoff_epoch: u64,
}

/// Reports an exact inert Q04 decision recovered under the Root writer.
///
/// A committed decision is the atomic binding/head/hold transaction, not a
/// policy-publication or effect capability. `Absent` is returned only at the
/// still-current proposed epoch; later Root history is deliberately ambiguous.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClosedPolicyBindingDecisionV2 {
    /// The exact binding has not committed at the still-current Root epoch.
    Absent,
    /// The exact binding committed and its Root hold remains unresolved.
    CommittedHeld(ClosedPolicyRootCasObservationV2),
    /// The exact binding committed and its inert Root hold was durably retired.
    CommittedReleased(ClosedPolicyRootCasObservationV2),
}

/// Records a Cache-only comparison made under the root writer.
///
/// This is deliberately not an all-owner cut: root has not independently
/// observed the Controller or source-domain holds, so it cannot commit Q04 or
/// authorize Create from this value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub struct ClosedPolicyRootCacheCutV2 {
    binding: ObjectDigest,
    epoch: u64,
    project: ProjectId,
    partition: ObjectDigest,
    cache_head: ObjectDigest,
}

impl ClosedPolicyRootCacheCutV2 {
    /// Returns the exact proposed binding observed in protected Cache custody.
    #[must_use]
    pub const fn binding(self) -> ObjectDigest {
        self.binding
    }

    /// Returns the root-next epoch observed in protected Cache custody.
    #[must_use]
    pub const fn epoch(self) -> u64 {
        self.epoch
    }

    /// Returns the root-pinned project whose protected Cache hold was checked.
    #[must_use]
    pub const fn project(self) -> ProjectId {
        self.project
    }

    /// Returns the protected physical partition checked against the proposal.
    #[must_use]
    pub const fn partition(self) -> ObjectDigest {
        self.partition
    }

    /// Returns the protected physical Cache head checked against the proposal.
    #[must_use]
    pub const fn cache_head(self) -> ObjectDigest {
        self.cache_head
    }
}

/// Supplies root-derived CAS fields while the protected writer remains held.
///
/// A controller may use these bytes to construct a proposal, but the root
/// session rechecks every field at commit. This value is not an authority
/// token and cannot establish the other owners' current heads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClosedPolicyRootCasBaseV2 {
    issuer_owner: [u8; 16],
    predecessor: ObjectDigest,
    next_generation: u64,
    deployment_signer_generation: u64,
    project_signer_generation: u64,
}

/// Retains one Root-issued base and challenge before other writers are acquired.
///
/// This token is authenticated by the Root socket but is not a CAS, owner-cut,
/// publication, or effect authority. Root rechecks its protected stage and
/// exact signed-source identity after acquiring its writer last.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StagedClosedPolicyRootBaseV2 {
    base: ClosedPolicyRootCasBaseV2,
    challenge: [u8; 16],
    issue_epoch: u64,
}

impl StagedClosedPolicyRootBaseV2 {
    /// Reconstructs an untrusted socket stage for later Root revalidation.
    ///
    /// # Errors
    ///
    /// Rejects a zero challenge or issuance epoch.
    pub fn from_untrusted_remote_fields(
        base: ClosedPolicyRootCasBaseV2,
        challenge: [u8; 16],
        issue_epoch: u64,
    ) -> Result<Self, PolicyCompilerJournalErrorV1> {
        if challenge == [0; 16] || issue_epoch == 0 {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }
        Ok(Self {
            base,
            challenge,
            issue_epoch,
        })
    }

    /// Returns the Root-supplied CAS base for nonauthorizing proposal construction.
    #[must_use]
    pub const fn base(self) -> ClosedPolicyRootCasBaseV2 {
        self.base
    }

    /// Returns the Root-minted challenge bound to the protected stage.
    #[must_use]
    pub const fn challenge(self) -> [u8; 16] {
        self.challenge
    }

    /// Returns the monotone Root stage issuance epoch.
    #[must_use]
    pub const fn issue_epoch(self) -> u64 {
        self.issue_epoch
    }
}

impl ClosedPolicyRootCasBaseV2 {
    /// Decodes root-supplied CAS fields without treating them as authority.
    ///
    /// The root session compares these fields to its protected journal when
    /// committing the proposal. A caller cannot authorize a binding by
    /// constructing this value.
    ///
    /// # Errors
    ///
    /// Rejects missing identities, generations, or an impossible predecessor.
    pub fn from_untrusted_remote_fields(
        issuer_owner: [u8; 16],
        predecessor: ObjectDigest,
        next_generation: u64,
        deployment_signer_generation: u64,
        project_signer_generation: u64,
    ) -> Result<Self, PolicyCompilerJournalErrorV1> {
        if issuer_owner == [0; 16]
            || next_generation == 0
            || deployment_signer_generation == 0
            || project_signer_generation == 0
            || (next_generation == 1) != (predecessor.as_bytes() == &[0; 32])
        {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }
        Ok(Self {
            issuer_owner,
            predecessor,
            next_generation,
            deployment_signer_generation,
            project_signer_generation,
        })
    }

    /// Returns the root-derived controller owner commitment.
    #[must_use]
    pub const fn issuer_owner(self) -> [u8; 16] {
        self.issuer_owner
    }

    /// Returns the exact current root predecessor commitment.
    #[must_use]
    pub const fn predecessor(self) -> ObjectDigest {
        self.predecessor
    }

    /// Returns the required next root CAS and handoff epoch.
    #[must_use]
    pub const fn next_generation(self) -> u64 {
        self.next_generation
    }

    /// Returns the root-pinned deployment signer generation.
    #[must_use]
    pub const fn deployment_signer_generation(self) -> u64 {
        self.deployment_signer_generation
    }

    /// Returns the root-pinned project signer generation.
    #[must_use]
    pub const fn project_signer_generation(self) -> u64 {
        self.project_signer_generation
    }
}

impl ClosedPolicyRootCasObservationV2 {
    /// Reconstructs an inert observation from an exact protected replay reply.
    ///
    /// The caller must authenticate the Root peer and compare the complete
    /// response frame before invoking this constructor.
    ///
    /// # Errors
    ///
    /// Rejects a zero binding or epoch.
    pub fn from_replayed_fields(
        binding: ObjectDigest,
        epoch: u64,
    ) -> Result<Self, PolicyCompilerJournalErrorV1> {
        if binding.as_bytes() == &[0; 32] || epoch == 0 {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }
        Ok(Self {
            binding,
            root_generation: epoch,
            handoff_epoch: epoch,
        })
    }

    /// Returns the content-addressed root binding head.
    #[must_use]
    pub const fn binding(self) -> ObjectDigest {
        self.binding
    }

    /// Returns the root journal's checked monotone binding generation.
    #[must_use]
    pub const fn root_generation(self) -> u64 {
        self.root_generation
    }

    /// Returns the epoch retained in the closed handoff record.
    #[must_use]
    pub const fn handoff_epoch(self) -> u64 {
        self.handoff_epoch
    }
}

struct RootPolicyBindingIdentityV2 {
    deployment_head: ObjectDigest,
    project: ProjectId,
    publisher_generation: u64,
    publisher_head: ObjectDigest,
    project_policy_head: ObjectDigest,
    project_policy_input: ObjectDigest,
    prerequisite_claims: [ObjectDigest; 4],
    deployment_signer_generation: u64,
    project_signer_generation: u64,
    issuer_owner: [u8; 16],
}

impl RootPolicyBindingIdentityV2 {
    fn matches(&self, binding: &ClosedPolicyRootBindingV2) -> bool {
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

    fn stage_cut(&self, base: ClosedPolicyRootCasBaseV2) -> ObjectDigest {
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

#[derive(Clone, Copy)]
struct RootProjectHeadFieldsV2 {
    project: ProjectId,
    publisher_generation: u64,
    publisher_head: ObjectDigest,
    packet_digest: ObjectDigest,
    input_digest: ObjectDigest,
    prerequisite_claims: [ObjectDigest; 4],
}

impl From<SignedProjectPolicyHeadV1> for RootProjectHeadFieldsV2 {
    fn from(head: SignedProjectPolicyHeadV1) -> Self {
        Self {
            project: head.project(),
            publisher_generation: head.publisher_generation(),
            publisher_head: head.publisher_digest(),
            packet_digest: head.packet_digest(),
            input_digest: head.input_digest(),
            prerequisite_claims: head.prerequisite_claims(),
        }
    }
}

impl From<SignedProjectPolicyHeadV2> for RootProjectHeadFieldsV2 {
    fn from(head: SignedProjectPolicyHeadV2) -> Self {
        Self {
            project: head.project(),
            publisher_generation: head.publisher_generation(),
            publisher_head: head.publisher_digest(),
            packet_digest: head.packet_digest(),
            input_digest: head.input_digest(),
            prerequisite_claims: head.prerequisite_claims(),
        }
    }
}

/// Retains the root writer for one authenticated, closed CAS exchange.
///
/// Only the fixed root service can open the protected journal. The service
/// must authenticate the controller peer and obtain all expected policy bytes
/// and signer pins from its own fixed deployment credentials. No value
/// returned by this session grants policy publication or an effect.
pub struct ClosedPolicyRootSessionV2<'journal> {
    authority: ProtectedJournalAuthority<'journal>,
    identity: RootPolicyBindingIdentityV2,
    postcommit: Option<ProtectedJournalSnapshot>,
}

impl ClosedPolicyRootSessionV2<'_> {
    /// Reads the current root CAS base under the same held writer.
    ///
    /// # Errors
    ///
    /// Rejects malformed or diverged protected binding history.
    pub fn current_base(&self) -> Result<ClosedPolicyRootCasBaseV2, PolicyCompilerJournalErrorV1> {
        let (predecessor, next_generation, _) = current_root_binding_chain(&self.authority)?;
        Ok(ClosedPolicyRootCasBaseV2 {
            issuer_owner: self.identity.issuer_owner,
            predecessor,
            next_generation,
            deployment_signer_generation: self.identity.deployment_signer_generation,
            project_signer_generation: self.identity.project_signer_generation,
        })
    }

    /// Durably stages one exact Root base and fresh challenge before other owners lock.
    ///
    /// Restaging supersedes the prior nonce. An ambiguous stage reply may be
    /// retried only before acquiring Controller, Source, or Cache holds. The
    /// later Root-last CAS must match this stage under the same Root writer;
    /// the stage itself cannot authorize a CAS or effect.
    ///
    /// # Errors
    ///
    /// Rejects an unresolved Root hold, unsafe history, failed entropy,
    /// repeated or zero nonce, overflowed issuance epoch, or failed commit.
    pub fn stage_closed_binding_base(
        &mut self,
        fresh_nonce: impl FnOnce() -> std::io::Result<[u8; 16]>,
    ) -> Result<StagedClosedPolicyRootBaseV2, PolicyCompilerJournalErrorV1> {
        if self.postcommit.is_some() {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }
        let (predecessor, next_generation, count) = current_root_binding_chain(&self.authority)?;
        if count >= MAXIMUM_POLICY_BINDINGS
            || current_hold(&self.authority, predecessor, next_generation, count)?
                .is_some_and(|hold| hold.held)
        {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }
        let base = self.current_base()?;
        let (prior_epoch, prior_nonce) = STAGE_CODEC
            .read_prior(self.authority.get(STAGE_KEY)?)
            .ok_or(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?;
        let issue_epoch = prior_epoch
            .checked_add(1)
            .ok_or(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?;
        let challenge =
            fresh_nonce().map_err(|_| PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?;
        if challenge == [0; 16] || challenge == prior_nonce {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }

        let cut = self.identity.stage_cut(base);
        if cut.as_bytes() == &[0; 32] {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }
        let record = STAGE_CODEC.encode(issue_epoch, challenge, cut);
        let transaction = STAGE_CODEC.transaction(record)?;
        self.authority.commit(&transaction)?;
        if self.authority.get(STAGE_KEY)? != Some(record.as_slice()) {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }
        self.postcommit = Some(self.authority.snapshot()?);
        Ok(StagedClosedPolicyRootBaseV2 {
            base,
            challenge,
            issue_epoch,
        })
    }

    /// Checks a staged Root base and challenge after acquiring Root last.
    ///
    /// This comparison is inert until the caller also holds and verifies the
    /// independent Controller, Source, Cache, and signer currentness cut.
    ///
    /// # Errors
    ///
    /// Rejects a superseded challenge, changed signed source or signer pins,
    /// advanced Root chain, or unresolved Root hold.
    pub fn validate_staged_closed_binding_base(
        &self,
        staged: StagedClosedPolicyRootBaseV2,
    ) -> Result<(), PolicyCompilerJournalErrorV1> {
        let (predecessor, next_generation, count) = current_root_binding_chain(&self.authority)?;
        if current_hold(&self.authority, predecessor, next_generation, count)?
            .is_some_and(|hold| hold.held)
            || self.current_base()? != staged.base
        {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }
        let record = self
            .authority
            .get(STAGE_KEY)?
            .ok_or(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?;
        let (issue_epoch, challenge) = STAGE_CODEC
            .read_prior(Some(record))
            .ok_or(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?;
        if issue_epoch != staged.issue_epoch
            || challenge != staged.challenge
            || record[32..64] != *self.identity.stage_cut(staged.base).as_bytes()
        {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }
        Ok(())
    }

    /// Commits an inert Q04 binding only against the exact staged Root base.
    ///
    /// This method holds the Root writer across stage validation and the
    /// binding/head/hold transaction. It does not verify other owner writers
    /// or signer readbacks; the first-submit service gate remains closed until
    /// that complete cut is independently established.
    ///
    /// # Errors
    ///
    /// Rejects a superseded or changed stage, stale proposal, conflicting
    /// Root history, or failed durable transaction/readback.
    pub fn commit_staged_closed_binding(
        &mut self,
        proposed: &[u8],
        staged: StagedClosedPolicyRootBaseV2,
    ) -> Result<ClosedPolicyRootCasObservationV2, PolicyCompilerJournalErrorV1> {
        self.validate_staged_closed_binding_base(staged)?;
        self.commit_closed_binding(proposed)
    }

    /// Compares a proposed AOSPCB02 record with root and protected Cache state.
    ///
    /// The fixed, root-only Cache view independently replays the protected
    /// state, authority, clock, and hold journals. This read-only comparison
    /// does not observe Controller or source-domain holds and cannot permit
    /// SUBMIT, publication, or an effect. The root writer remains held for the
    /// duration of the comparison.
    ///
    /// # Errors
    ///
    /// Rejects a malformed or stale proposal, occupied root CAS, unsafe Cache
    /// view, absent/released Cache hold, or any mismatched held field.
    pub fn prepare_cache_cut(
        &self,
        proposed: &[u8],
    ) -> Result<ClosedPolicyRootCacheCutV2, PolicyCompilerJournalErrorV1> {
        let binding = ClosedPolicyRootBindingV2::decode(proposed)?;
        let observed = read_fixed_policy_cache_hold_v1()
            .map_err(|_| PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?;
        self.prepare_cache_cut_with_observation(&binding, observed.hold)
    }

    fn prepare_cache_cut_with_observation(
        &self,
        binding: &ClosedPolicyRootBindingV2,
        held: CachePolicyHoldV1,
    ) -> Result<ClosedPolicyRootCacheCutV2, PolicyCompilerJournalErrorV1> {
        if self.postcommit.is_some() {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }
        if !self.identity.matches(binding) {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }

        let (predecessor, next_generation, count) = current_root_binding_chain(&self.authority)?;
        if !new_root_cas_matches(binding, predecessor, next_generation, count)
            || current_hold(&self.authority, predecessor, next_generation, count)?
                .is_some_and(|hold| hold.held)
        {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }
        let key = binding.key()?;
        if self.authority.get(&key)?.is_some() {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }
        require_unique_root_binding_identity(&self.authority, binding)?;

        compare_cache_hold(binding, held)
    }

    /// Compares and durably retains one exact closed AOSPCB02 binding.
    ///
    /// The signed and root-owned fields are compared to the fixed session
    /// identity. Controller-supplied Create, ancestry, Cache, and candidate
    /// claims remain untrusted historical evidence until their own writers
    /// are held through a production callsite and replay/handoff verifier.
    ///
    /// # Errors
    ///
    /// Rejects a malformed record, foreign signer or signed head, stale root
    /// predecessor/generation/epoch, conflicting replay, ambiguous commit,
    /// or failed exact readback.
    pub fn commit_closed_binding(
        &mut self,
        proposed: &[u8],
    ) -> Result<ClosedPolicyRootCasObservationV2, PolicyCompilerJournalErrorV1> {
        if self.postcommit.is_some() {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }
        let binding = ClosedPolicyRootBindingV2::decode(proposed)?;
        if !self.identity.matches(&binding) {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }

        let (predecessor, next_generation, count) = current_root_binding_chain(&self.authority)?;
        let key = binding.key()?;
        let binding_head = ObjectDigest::from_bytes(
            key[BINDING_V2_KEY_PREFIX.len()..]
                .try_into()
                .map_err(|_| PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?,
        );
        let exact_replay = predecessor == binding_head;
        let prior_hold = current_hold(&self.authority, predecessor, next_generation, count)?;
        if exact_replay {
            if self.authority.get(&key)? != Some(proposed)
                || !prior_hold.is_some_and(|hold| hold.held && hold.binding == binding_head)
            {
                return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
            }
        } else {
            if prior_hold.is_some_and(|hold| hold.held) {
                return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
            }
            require_unique_root_binding_identity(&self.authority, &binding)?;
            if !new_root_cas_matches(&binding, predecessor, next_generation, count)
                || self.authority.get(&key)?.is_some()
            {
                return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
            }

            let digest = Sha256::new()
                .chain_update(ROOT_TRANSACTION_DOMAIN)
                .chain_update(proposed)
                .finalize();
            let transaction_id: [u8; 16] = digest[..16]
                .try_into()
                .map_err(|_| PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?;
            let held = RootBindingHoldV1 {
                issuer_owner: binding.issuer_owner,
                binding: binding_head,
                epoch: binding.handoff_epoch,
                held: true,
            }
            .encode()?;
            let transaction = JournalTransaction::new(
                transaction_id,
                vec![
                    JournalRecord::put(
                        RecordNamespace::DesiredState,
                        key.clone(),
                        proposed.to_vec(),
                    ),
                    JournalRecord::put(
                        RecordNamespace::DesiredState,
                        ROOT_BINDING_HEAD_KEY.to_vec(),
                        binding_head.as_bytes().to_vec(),
                    ),
                    JournalRecord::put(
                        RecordNamespace::DesiredState,
                        HOLD_KEY.to_vec(),
                        held.to_vec(),
                    ),
                ],
            )?;
            // The binding, head pointer, and held decision become durable in
            // one transaction before any Q04 response or release is possible.
            self.authority.commit(&transaction)?;
            if self.authority.get(&key)? != Some(proposed)
                || self.authority.get(ROOT_BINDING_HEAD_KEY)? != Some(binding_head.as_bytes())
                || self.authority.get(HOLD_KEY)? != Some(held.as_slice())
            {
                return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
            }
        }

        self.postcommit = Some(self.authority.snapshot()?);
        Ok(ClosedPolicyRootCasObservationV2 {
            binding: binding_head,
            root_generation: binding.root_generation,
            handoff_epoch: binding.handoff_epoch,
        })
    }

    /// Releases an inert Q04 custody record after its exact response ACK.
    ///
    /// This does not authorize publication or effects. The Q04 exchange has
    /// no effect handoff, so a successful ACK may retire this local guard.
    /// A lost ACK leaves it held for explicit cold resolution.
    ///
    /// # Errors
    ///
    /// Rejects a stale binding or epoch, absent hold, or failed durable write.
    pub fn release_inert_hold(
        &mut self,
        committed: ClosedPolicyRootCasObservationV2,
    ) -> Result<(), PolicyCompilerJournalErrorV1> {
        let (head, next_epoch, count) = current_root_binding_chain(&self.authority)?;
        let held = current_hold(&self.authority, head, next_epoch, count)?
            .ok_or(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?;
        if !held.held
            || held.binding != committed.binding
            || held.epoch != committed.handoff_epoch
            || held.epoch != committed.root_generation
            || held.issuer_owner != self.identity.issuer_owner
            || self.postcommit.is_none()
        {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }
        release_hold(&mut self.authority, held)?;
        self.postcommit = Some(self.authority.snapshot()?);
        Ok(())
    }
}

// Preparation and a first CAS share these checks but apply them in their
// original order. The durable exact-replay branch intentionally does not.
fn new_root_cas_matches(
    binding: &ClosedPolicyRootBindingV2,
    predecessor: ObjectDigest,
    next_generation: u64,
    count: usize,
) -> bool {
    count < MAXIMUM_POLICY_BINDINGS
        && binding.root_predecessor == predecessor
        && binding.root_generation == next_generation
        && binding.barrier_epoch == next_generation
        && binding.handoff_epoch == next_generation
}

fn require_unique_root_binding_identity(
    authority: &ProtectedJournalAuthority<'_>,
    binding: &ClosedPolicyRootBindingV2,
) -> Result<(), PolicyCompilerJournalErrorV1> {
    for (current_key, current_value) in authority.records()? {
        if current_key.starts_with(BINDING_V2_KEY_PREFIX) {
            let current = decode_closed_policy_binding_v2(current_key, current_value)?;
            if current.operation == binding.operation
                || current.effect_transaction == binding.effect_transaction
            {
                return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
            }
        }
    }
    Ok(())
}

fn compare_cache_hold(
    binding: &ClosedPolicyRootBindingV2,
    held: CachePolicyHoldV1,
) -> Result<ClosedPolicyRootCacheCutV2, PolicyCompilerJournalErrorV1> {
    let binding_head = closed_policy_binding_digest_v2(&binding.encode()?)?;
    if !held.is_held()
        || held.binding() != binding_head
        || held.epoch() != binding.handoff_epoch
        || held.project() != binding.project
        || held.partition() != binding.physical_partition
        || held.cache_head() != binding.physical_cache_head
    {
        return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
    }

    Ok(ClosedPolicyRootCacheCutV2 {
        binding: binding_head,
        epoch: held.epoch(),
        project: held.project(),
        partition: held.partition(),
        cache_head: held.cache_head(),
    })
}

/// Opens one fixed root session and retains its lock through a closed exchange.
///
/// The role keys and generations must come from root-owned deployment
/// credentials. The fixed journal independently retains their exact pins and
/// deployment head. The controller UID/GID must come from protected service
/// configuration; the root daemon must verify kernel peer credentials before
/// invoking this function. The callback may perform one closed CAS and a
/// nonce-bound transport ACK, but no policy publication or effect.
///
/// # Errors
///
/// Rejects unsafe root custody, missing/changed signer pins or deployment
/// head, signed-project mismatch, absent CAS, or failed post-action snapshot.
pub fn with_fixed_closed_policy_binding_session_v2<R>(
    expected_deployment_packet: &[u8],
    deployment_signer_generation: u64,
    deployment_key: &VerifyingKey,
    project_head: SignedProjectPolicyHeadV1,
    project_signer_generation: u64,
    project_key: &VerifyingKey,
    controller_uid: u32,
    controller_gid: u32,
    exchange: impl FnOnce(&mut ClosedPolicyRootSessionV2<'_>) -> R,
) -> Result<R, PolicyCompilerJournalErrorV1> {
    let (mut journal, _) = Journal::open_protected_at(
        Path::new(PROTECTED_POLICY_ROOT),
        POLICY_AUTHORITY_JOURNAL,
        policy_authority_journal_limits(),
    )?;
    with_closed_policy_binding_session_in_journal_v2(
        &mut journal,
        expected_deployment_packet,
        deployment_signer_generation,
        deployment_key,
        project_head.into(),
        None,
        project_signer_generation,
        project_key,
        controller_uid,
        controller_gid,
        exchange,
    )
}

/// Opens a root-held closed session only for the exact admitted V2 project source.
///
/// The project packet and canonical input are reverified under the pinned
/// project key, then compared to the protected V2 root records under the same
/// writer used for CAS. This still does not establish that the controller,
/// ancestry, or physical Cache heads are current and grants no effect.
///
/// # Errors
///
/// Rejects a stale or malformed signed source, changed signer generations,
/// missing or mixed V1/V2 root records, an unsafe root writer, or a failed
/// closed CAS/readback.
#[allow(clippy::too_many_arguments)]
pub fn with_fixed_explicit_closed_policy_binding_session_v2<R>(
    expected_deployment_packet: &[u8],
    deployment_signer_generation: u64,
    deployment_key: &VerifyingKey,
    project_packet: &[u8],
    project_input: &[u8],
    project_signer_generation: u64,
    project_key: &VerifyingKey,
    controller_uid: u32,
    controller_gid: u32,
    now_unix_seconds: i64,
    exchange: impl FnOnce(&mut ClosedPolicyRootSessionV2<'_>) -> R,
) -> Result<R, PolicyCompilerJournalErrorV1> {
    let verified = verify_signed_project_policy_source_v2(
        project_packet,
        project_input,
        project_key,
        now_unix_seconds,
    )
    .map_err(|_| PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?;
    let head = verified.head();
    if head.deployment_signer_generation() != deployment_signer_generation
        || head.project_signer_generation() != project_signer_generation
    {
        return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
    }
    let (mut journal, _) = Journal::open_protected_at(
        Path::new(PROTECTED_POLICY_ROOT),
        POLICY_AUTHORITY_JOURNAL,
        policy_authority_journal_limits(),
    )?;
    with_closed_policy_binding_session_in_journal_v2(
        &mut journal,
        expected_deployment_packet,
        deployment_signer_generation,
        deployment_key,
        head.into(),
        Some((project_packet, project_input)),
        project_signer_generation,
        project_key,
        controller_uid,
        controller_gid,
        exchange,
    )
}

#[allow(clippy::too_many_arguments)]
fn with_closed_policy_binding_session_in_journal_v2<R>(
    journal: &mut Journal,
    expected_deployment_packet: &[u8],
    deployment_signer_generation: u64,
    deployment_key: &VerifyingKey,
    project_head: RootProjectHeadFieldsV2,
    project_record: Option<(&[u8], &[u8])>,
    project_signer_generation: u64,
    project_key: &VerifyingKey,
    controller_uid: u32,
    controller_gid: u32,
    exchange: impl FnOnce(&mut ClosedPolicyRootSessionV2<'_>) -> R,
) -> Result<R, PolicyCompilerJournalErrorV1> {
    if controller_uid == 0 || controller_gid == 0 {
        return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
    }
    let pins = encode_policy_signer_pins_v1(
        deployment_signer_generation,
        deployment_key,
        project_signer_generation,
        project_key,
    )
    .map_err(|_| PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?;
    let authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    if authority.get(SIGNER_PINS_KEY)? != Some(pins.as_slice())
        || authority.get(HEAD_KEY)? != Some(expected_deployment_packet)
        || project_head.prerequisite_claims[1].as_bytes()
            != Sha256::digest(expected_deployment_packet).as_slice()
    {
        return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
    }
    let project_is_current = match project_record {
        None => {
            let legacy_source = authority
                .get(PROJECT_HEAD_KEY)?
                .zip(authority.get(PROJECT_INPUT_KEY)?);
            legacy_source.is_some_and(|(packet, input)| {
                project_head.packet_digest.as_bytes() == Sha256::digest(packet).as_slice()
                    && project_head.input_digest.as_bytes() == Sha256::digest(input).as_slice()
            }) && authority.get(HEAD_KEY_V2)?.is_none()
                && authority.get(INPUT_KEY_V2)?.is_none()
        }
        Some((packet, input)) => {
            authority.get(HEAD_KEY_V2)? == Some(packet)
                && authority.get(INPUT_KEY_V2)? == Some(input)
                && authority.get(PROJECT_HEAD_KEY)?.is_none()
                && authority.get(PROJECT_INPUT_KEY)?.is_none()
        }
    };
    if !project_is_current {
        return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
    }
    let issuer_digest = Sha256::new()
        .chain_update(ISSUER_DOMAIN)
        .chain_update(controller_uid.to_be_bytes())
        .chain_update(controller_gid.to_be_bytes())
        .finalize();
    let issuer_owner: [u8; 16] = issuer_digest[..16]
        .try_into()
        .map_err(|_| PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?;
    let identity = RootPolicyBindingIdentityV2 {
        deployment_head: ObjectDigest::from_bytes(
            Sha256::digest(expected_deployment_packet).into(),
        ),
        project: project_head.project,
        publisher_generation: project_head.publisher_generation,
        publisher_head: project_head.publisher_head,
        project_policy_head: project_head.packet_digest,
        project_policy_input: project_head.input_digest,
        prerequisite_claims: project_head.prerequisite_claims,
        deployment_signer_generation,
        project_signer_generation,
        issuer_owner,
    };
    let mut session = ClosedPolicyRootSessionV2 {
        authority,
        identity,
        postcommit: None,
    };
    let result = exchange(&mut session);
    let snapshot = session
        .postcommit
        .as_ref()
        .ok_or(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?;
    session.authority.validate_snapshot_for_effect(snapshot)?;
    Ok(result)
}

fn current_root_binding_chain(
    authority: &ProtectedJournalAuthority<'_>,
) -> Result<(ObjectDigest, u64, usize), PolicyCompilerJournalErrorV1> {
    let mut bindings = Vec::new();
    for (key, value) in authority.records()? {
        if key.starts_with(POLICY_BINDING_KEY_PREFIX) {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }
        if key.starts_with(BINDING_V2_KEY_PREFIX) {
            let binding = decode_closed_policy_binding_v2(key, value)?;
            let head: [u8; 32] = key[BINDING_V2_KEY_PREFIX.len()..]
                .try_into()
                .map_err(|_| PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?;
            bindings.push((binding, ObjectDigest::from_bytes(head)));
        }
    }
    if bindings.len() > MAXIMUM_POLICY_BINDINGS {
        return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
    }
    bindings.sort_by_key(|(binding, _)| binding.root_generation);
    let mut predecessor = ObjectDigest::from_bytes([0; 32]);
    let mut operations = BTreeSet::new();
    let mut effect_transactions = BTreeSet::new();
    for (index, (binding, head)) in bindings.iter().enumerate() {
        let generation = u64::try_from(index + 1)
            .map_err(|_| PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?;
        if binding.root_generation != generation
            || binding.root_predecessor != predecessor
            || binding.barrier_epoch != generation
            || binding.handoff_epoch != generation
            || !operations.insert(*binding.operation.as_bytes())
            || !effect_transactions.insert(binding.effect_transaction)
        {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }
        predecessor = *head;
    }
    let pointer = authority.get(ROOT_BINDING_HEAD_KEY)?;
    if (bindings.is_empty() && pointer.is_some())
        || (!bindings.is_empty() && pointer != Some(predecessor.as_bytes()))
    {
        return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
    }
    let next_generation = u64::try_from(bindings.len())
        .ok()
        .and_then(|count| count.checked_add(1))
        .ok_or(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?;
    let held = current_hold(authority, predecessor, next_generation, bindings.len())?;
    if held.map(|record| record.issuer_owner)
        != bindings.last().map(|(binding, _)| binding.issuer_owner)
    {
        return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
    }
    Ok((predecessor, next_generation, bindings.len()))
}

// Root writers call this under their own authority claim, so the checked hold
// cannot change between this test and their journal commit.
pub(super) fn ensure_root_binding_unheld(
    authority: &ProtectedJournalAuthority<'_>,
) -> Result<(), PolicyCompilerJournalErrorV1> {
    let (head, next_epoch, count) = current_root_binding_chain(authority)?;
    if current_hold(authority, head, next_epoch, count)?.is_some_and(|hold| hold.held) {
        return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
    }
    Ok(())
}

/// Refuses startup while an inert root binding has unresolved custody.
///
/// A returned success says only that this root-local guard is clear. It does
/// not establish Controller, source-domain, Cache, or effect currentness.
///
/// # Errors
///
/// Rejects a held binding, malformed or legacy binding history, or unsafe
/// protected root journal custody.
pub fn require_no_fixed_closed_policy_binding_hold_v1() -> Result<(), PolicyCompilerJournalErrorV1>
{
    if read_fixed_inert_closed_policy_binding_hold_v1()?.is_some() {
        return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
    }
    Ok(())
}

/// Reads the exact unresolved inert Q04 hold from protected root custody.
///
/// This gives an operator the binding head and epoch needed for cold recovery.
/// It is an observation, never a publication or effect capability.
///
/// # Errors
///
/// Rejects malformed, legacy, or diverged history and unsafe root custody.
pub fn read_fixed_inert_closed_policy_binding_hold_v1()
-> Result<Option<ClosedPolicyRootCasObservationV2>, PolicyCompilerJournalErrorV1> {
    let (mut journal, _) = Journal::open_protected_at(
        Path::new(PROTECTED_POLICY_ROOT),
        POLICY_AUTHORITY_JOURNAL,
        policy_authority_journal_limits(),
    )?;
    let authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    let (head, next_epoch, count) = current_root_binding_chain(&authority)?;
    Ok(current_hold(&authority, head, next_epoch, count)?
        .filter(|hold| hold.held)
        .map(|hold| ClosedPolicyRootCasObservationV2 {
            binding: hold.binding,
            root_generation: hold.epoch,
            handoff_epoch: hold.epoch,
        }))
}

/// Replays an exact inert Q04 decision after an ambiguous response.
///
/// The caller must retain Controller, Source, and Cache custody before this
/// function acquires the Root writer last. A committed decision carries the
/// exact protected proposal bytes for cross-owner comparison after restart;
/// an absent decision carries no proposal. Neither can release another owner's
/// hold or authorize Create.
///
/// # Errors
///
/// Rejects zero claims, unsafe or malformed Root history, a different current
/// binding, an unresolved earlier hold, or a proposed epoch overtaken by later
/// Root history.
pub fn recover_fixed_closed_policy_binding_decision_v2(
    binding: ObjectDigest,
    epoch: u64,
) -> Result<(ClosedPolicyBindingDecisionV2, Option<Vec<u8>>), PolicyCompilerJournalErrorV1> {
    let (mut journal, _) = Journal::open_protected_at(
        Path::new(PROTECTED_POLICY_ROOT),
        POLICY_AUTHORITY_JOURNAL,
        policy_authority_journal_limits(),
    )?;
    let authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    recover_closed_binding_decision_from_authority(&authority, binding, epoch)
}

fn recover_closed_binding_decision_from_authority(
    authority: &ProtectedJournalAuthority<'_>,
    binding: ObjectDigest,
    epoch: u64,
) -> Result<(ClosedPolicyBindingDecisionV2, Option<Vec<u8>>), PolicyCompilerJournalErrorV1> {
    if binding.as_bytes() == &[0; 32] || epoch == 0 {
        return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
    }
    let (head, next_epoch, count) = current_root_binding_chain(authority)?;
    let hold = current_hold(authority, head, next_epoch, count)?;
    let mut key = BINDING_V2_KEY_PREFIX.to_vec();
    key.extend_from_slice(binding.as_bytes());

    if next_epoch == epoch {
        if authority.get(&key)?.is_some() || hold.is_some_and(|prior| prior.held) {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }
        return Ok((ClosedPolicyBindingDecisionV2::Absent, None));
    }
    if epoch.checked_add(1) != Some(next_epoch) || head != binding {
        return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
    }
    let encoded = authority
        .get(&key)?
        .ok_or(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?;
    let record = decode_closed_policy_binding_v2(&key, encoded)?;
    let hold = hold.ok_or(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?;
    if record.root_generation != epoch
        || hold.binding != binding
        || hold.epoch != epoch
        || hold.issuer_owner != record.issuer_owner
    {
        return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
    }
    let observation = ClosedPolicyRootCasObservationV2 {
        binding,
        root_generation: epoch,
        handoff_epoch: epoch,
    };
    let decision = if hold.held {
        ClosedPolicyBindingDecisionV2::CommittedHeld(observation)
    } else {
        ClosedPolicyBindingDecisionV2::CommittedReleased(observation)
    };
    Ok((decision, Some(encoded.to_vec())))
}

/// Resolves a cold, inert Q04 hold after independent offline review.
///
/// The current Q04 service has no effect handoff. Its root owner may therefore
/// retire an exact abandoned hold before admitting another closed proposal.
/// This must not be used as an effect-success claim or reused if Q04 gains an
/// effect handoff. The caller must run as the privileged root owner.
///
/// # Errors
///
/// Rejects a different head or epoch, a previously released hold, malformed
/// history, or failed durable release/readback.
pub fn release_fixed_inert_closed_policy_binding_hold_v1(
    binding: ObjectDigest,
    epoch: u64,
) -> Result<(), PolicyCompilerJournalErrorV1> {
    let (mut journal, _) = Journal::open_protected_at(
        Path::new(PROTECTED_POLICY_ROOT),
        POLICY_AUTHORITY_JOURNAL,
        policy_authority_journal_limits(),
    )?;
    let mut authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    let (head, next_epoch, count) = current_root_binding_chain(&authority)?;
    let held = current_hold(&authority, head, next_epoch, count)?
        .ok_or(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?;
    if !held.held || held.binding != binding || held.epoch != epoch {
        return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
    }
    release_hold(&mut authority, held)?;
    current_root_binding_chain(&authority)?;
    Ok(())
}

/// Releases one Controller freeze only after exact root cold readback.
///
/// The caller retains Controller and source-domain writers in that order;
/// this function opens root custody last. A held source-domain record blocks
/// Controller release. Q04 remains inert: this releases neither source-domain
/// nor Cache custody and authorizes no effect.
/// Root must show either that this proposal never committed at its epoch, or
/// that its exact AOSPCH01 was durably released. A terminal-ACK write, local
/// receipt, or caller-supplied status is not proof of either condition.
///
/// # Errors
///
/// Rejects a retained source-domain hold, different root binding/epoch, an
/// unresolved root hold, malformed root history, stale Controller custody,
/// or a failed durable release.
pub fn release_fixed_closed_policy_controller_hold_v1(
    controller: &mut Journal,
    source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
    expected: crate::journal::ControllerPolicyHoldV1,
) -> Result<(), PolicyCompilerJournalErrorV1> {
    let (mut root, _) = Journal::open_protected_at(
        Path::new(PROTECTED_POLICY_ROOT),
        POLICY_AUTHORITY_JOURNAL,
        policy_authority_journal_limits(),
    )?;
    let authority = root.claim_protected_authority(RecordNamespace::DesiredState)?;
    release_controller_hold_against_root_authority(controller, source_domains, expected, &authority)
}

fn require_source_domain_released_for_controller_release(
    source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
) -> Result<(), PolicyCompilerJournalErrorV1> {
    if source_domains
        .closed_policy_source_hold_v1()?
        .is_some_and(SourceDomainPolicyHoldV1::is_held)
    {
        return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
    }
    Ok(())
}

/// Releases one source-domain freeze after exact Controller and root readback.
///
/// The caller retains the Controller writer before the source-domain writer;
/// this function opens root last. A matching released root hold or a strictly
/// absent commit at the proposed epoch is required. This is only cold custody
/// recovery for inert Q04, not Create publication or effect authority.
///
/// # Errors
///
/// Rejects missing or mismatched Controller custody, unresolved or ambiguous
/// root history, a mismatched source hold, or failed durable release.
pub fn release_fixed_closed_policy_source_domain_hold_v1(
    controller: &mut Journal,
    source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
    expected: SourceDomainPolicyHoldV1,
) -> Result<(), PolicyCompilerJournalErrorV1> {
    let controller_hold = controller
        .controller_policy_hold_v1()?
        .ok_or(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?;
    if !matching_controller_and_source_holds(controller_hold, expected) {
        return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
    }

    let (mut root, _) = Journal::open_protected_at(
        Path::new(PROTECTED_POLICY_ROOT),
        POLICY_AUTHORITY_JOURNAL,
        policy_authority_journal_limits(),
    )?;
    let authority = root.claim_protected_authority(RecordNamespace::DesiredState)?;
    release_source_hold_against_root_authority(
        source_domains,
        expected,
        controller_hold,
        &authority,
    )
}

fn matching_controller_and_source_holds(
    controller: ControllerPolicyHoldV1,
    source: SourceDomainPolicyHoldV1,
) -> bool {
    controller.is_held()
        && source.is_held()
        && controller.operation() == source.operation()
        && controller.sandbox() == source.sandbox()
        && controller.source() == source.controller_source()
        && controller.binding() == source.binding()
        && controller.epoch() == source.epoch()
}

fn release_source_hold_against_root_authority(
    source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
    expected: SourceDomainPolicyHoldV1,
    controller_hold: ControllerPolicyHoldV1,
    authority: &ProtectedJournalAuthority<'_>,
) -> Result<(), PolicyCompilerJournalErrorV1> {
    if !matching_controller_and_source_holds(controller_hold, expected) {
        return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
    }
    let (head, next_epoch, count) = current_root_binding_chain(authority)?;
    let root_hold = current_hold(authority, head, next_epoch, count)?;
    if !controller_hold_can_retire_at_root_cut(controller_hold, next_epoch, root_hold) {
        return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
    }

    source_domains.release_closed_policy_source_hold_after_root_readback_v1(expected)?;
    Ok(())
}

/// Releases an exact protected Cache freeze during privileged offline recovery.
///
/// The release-only Cache verifier retains its clock, manifest, and state
/// locks, then its hold lock, before opening root custody. It checks complete
/// immutable history even after Replay authority expires; it cannot mint a
/// live Cache owner or authorize normal mutation. Root must show that the
/// proposal did not commit at this epoch, or that its exact inert hold was
/// durably retired.
/// No current daemon has both writable Cache custody and root journal access;
/// this helper is not a live Q04 recovery exchange. It does not release
/// Controller or source-domain custody or authorize an effect. `owner_uid`
/// must be deployment-pinned by the privileged offline caller.
///
/// # Errors
///
/// Rejects a root UID, stale Cache quota/domain/head, a different root binding
/// or epoch, unresolved root custody, or an ambiguous durable release.
pub fn release_fixed_closed_policy_cache_hold_v1(
    owner_uid: u32,
    expected: CachePolicyHoldV1,
) -> Result<(), PolicyCompilerJournalErrorV1> {
    release_fixed_closed_policy_cache_hold_after_root_readback_v1(owner_uid, expected, || {
        let (mut root, _) = Journal::open_protected_at(
            Path::new(PROTECTED_POLICY_ROOT),
            POLICY_AUTHORITY_JOURNAL,
            policy_authority_journal_limits(),
        )
        .map_err(ProtectedDomainJournalErrorV1::from)?;
        let authority = root
            .claim_protected_authority(RecordNamespace::DesiredState)
            .map_err(ProtectedDomainJournalErrorV1::from)?;
        let (head, next_epoch, count) = current_root_binding_chain(&authority)
            .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
        let root_hold = current_hold(&authority, head, next_epoch, count)
            .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
        if !cache_hold_can_retire_at_root_cut(expected, next_epoch, root_hold) {
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
        }
        Ok(())
    })?;
    Ok(())
}

fn cache_hold_can_retire_at_root_cut(
    expected: CachePolicyHoldV1,
    next_epoch: u64,
    root_hold: Option<RootBindingHoldV1>,
) -> bool {
    if next_epoch == expected.epoch() {
        return root_hold.is_none_or(|hold| !hold.held);
    }
    root_hold.is_some_and(|hold| {
        !hold.held && hold.binding == expected.binding() && hold.epoch == expected.epoch()
    })
}

fn release_controller_hold_against_root_authority(
    controller: &mut Journal,
    source_domains: &mut ProtectedSourceDomainJournalOwnerV1,
    expected: crate::journal::ControllerPolicyHoldV1,
    authority: &ProtectedJournalAuthority<'_>,
) -> Result<(), PolicyCompilerJournalErrorV1> {
    require_source_domain_released_for_controller_release(source_domains)?;
    let (head, next_epoch, count) = current_root_binding_chain(authority)?;
    let root_hold = current_hold(authority, head, next_epoch, count)?;
    if !controller_hold_can_retire_at_root_cut(expected, next_epoch, root_hold) {
        return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
    }
    controller.release_controller_policy_hold_after_root_readback_v1(expected)?;
    Ok(())
}

fn controller_hold_can_retire_at_root_cut(
    expected: crate::journal::ControllerPolicyHoldV1,
    next_epoch: u64,
    root_hold: Option<RootBindingHoldV1>,
) -> bool {
    if next_epoch == expected.epoch() {
        // This epoch has not committed, but an earlier unresolved root hold
        // must not be bypassed while retiring Controller custody.
        return root_hold.is_none_or(|hold| !hold.held);
    }
    root_hold.is_some_and(|hold| {
        !hold.held && hold.binding == expected.binding() && hold.epoch == expected.epoch()
    })
}

struct BindingReaderV2<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl BindingReaderV2<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], PolicyCompilerJournalErrorV1> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .and_then(|value| value.try_into().ok())
            .ok_or(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?;
        self.offset = end;
        Ok(value)
    }

    fn digest(&mut self) -> Result<ObjectDigest, PolicyCompilerJournalErrorV1> {
        Ok(ObjectDigest::from_bytes(self.take()?))
    }

    fn u64(&mut self) -> Result<u64, PolicyCompilerJournalErrorV1> {
        Ok(u64::from_be_bytes(self.take()?))
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::journal::{Journal, JournalRecord, JournalTransaction, RecordNamespace};
    use crate::policy_compiler::protected_owner::{
        ProtectedPolicyPublicationVerifierV1, policy_authority_journal_limits,
    };

    fn fixture() -> ClosedPolicyRootBindingV2 {
        ClosedPolicyRootBindingV2 {
            issuer_owner: [1; 16],
            project: ProjectId::from_bytes([2; 16]),
            sandbox: SandboxId::from_bytes([3; 16]),
            operation: OperationId::from_bytes([4; 16]),
            operation_revision: ObjectDigest::from_bytes([5; 32]),
            accepted_generation: 6,
            projection_revision: ObjectDigest::from_bytes([7; 32]),
            publisher_generation: 8,
            publisher_head: ObjectDigest::from_bytes([9; 32]),
            project_policy_head: ObjectDigest::from_bytes([10; 32]),
            project_policy_input: ObjectDigest::from_bytes([11; 32]),
            ancestry_head: ObjectDigest::from_bytes([12; 32]),
            compiler_head: ObjectDigest::from_bytes([13; 32]),
            cache_domain_head: ObjectDigest::from_bytes([14; 32]),
            revocation_head: ObjectDigest::from_bytes([15; 32]),
            physical_partition: ObjectDigest::from_bytes([16; 32]),
            physical_cache_head: ObjectDigest::from_bytes([17; 32]),
            normalized_input: ObjectDigest::from_bytes([18; 32]),
            candidate: ObjectDigest::from_bytes([19; 32]),
            project_signer_generation: 20,
            deployment_signer_generation: 21,
            barrier_epoch: 22,
            barrier_head: ObjectDigest::from_bytes([23; 32]),
            root_predecessor: ObjectDigest::from_bytes([0; 32]),
            root_generation: 1,
            effect_transaction: [24; 16],
            handoff_epoch: 22,
        }
    }

    fn cas_fixture() -> ClosedPolicyRootBindingV2 {
        let mut binding = fixture();
        binding.barrier_epoch = 1;
        binding.handoff_epoch = 1;
        binding
    }

    fn matching_cache_hold(binding: &ClosedPolicyRootBindingV2) -> CachePolicyHoldV1 {
        CachePolicyHoldV1::new(
            binding.project,
            binding.physical_partition,
            binding.physical_cache_head,
            closed_policy_binding_digest_v2(&binding.encode().expect("binding"))
                .expect("binding head"),
            binding.handoff_epoch,
        )
        .expect("matching Cache hold")
    }

    #[test]
    fn closed_claim_comparison_rejects_cross_owner_substitution() {
        let binding = cas_fixture();
        let proposed = binding.encode().expect("closed proposal");
        let head = closed_policy_binding_digest_v2(&proposed).expect("binding head");
        let source_commitment = ObjectDigest::from_bytes([31; 32]);
        let controller = ControllerPolicyHoldV1::new(
            binding.operation,
            binding.sandbox,
            source_commitment,
            head,
            binding.handoff_epoch,
        )
        .expect("Controller hold");
        let source = SourceDomainPolicyHoldV1::new(
            binding.operation,
            binding.sandbox,
            source_commitment,
            binding.ancestry_head,
            head,
            binding.handoff_epoch,
        )
        .expect("Source hold");
        let cache = matching_cache_hold(&binding);
        assert!(
            compare_closed_policy_binding_hold_claims_v2(&proposed, controller, source, cache)
                .is_ok()
        );

        let wrong_source = SourceDomainPolicyHoldV1::new(
            binding.operation,
            binding.sandbox,
            source_commitment,
            ObjectDigest::from_bytes([32; 32]),
            head,
            binding.handoff_epoch,
        )
        .expect("wrong ancestry");
        assert!(
            compare_closed_policy_binding_hold_claims_v2(
                &proposed,
                controller,
                wrong_source,
                cache
            )
            .is_err()
        );
        let wrong_cache = CachePolicyHoldV1::new(
            binding.project,
            ObjectDigest::from_bytes([33; 32]),
            binding.physical_cache_head,
            head,
            binding.handoff_epoch,
        )
        .expect("wrong partition");
        assert!(
            compare_closed_policy_binding_hold_claims_v2(
                &proposed,
                controller,
                source,
                wrong_cache
            )
            .is_err()
        );
        let wrong_controller = ControllerPolicyHoldV1::new(
            binding.operation,
            binding.sandbox,
            source_commitment,
            head,
            binding.handoff_epoch + 1,
        )
        .expect("wrong epoch");
        assert!(
            compare_closed_policy_binding_hold_claims_v2(
                &proposed,
                wrong_controller,
                source,
                cache
            )
            .is_err()
        );
    }

    #[test]
    fn remote_root_base_rejects_missing_generations_and_predecessor_shape() {
        let zero = ObjectDigest::from_bytes([0; 32]);
        let prior = ObjectDigest::from_bytes([7; 32]);
        assert!(
            ClosedPolicyRootCasBaseV2::from_untrusted_remote_fields([1; 16], zero, 1, 2, 3).is_ok()
        );
        assert!(
            ClosedPolicyRootCasBaseV2::from_untrusted_remote_fields([1; 16], prior, 2, 2, 3)
                .is_ok()
        );
        assert!(
            ClosedPolicyRootCasBaseV2::from_untrusted_remote_fields([0; 16], zero, 1, 2, 3)
                .is_err()
        );
        assert!(
            ClosedPolicyRootCasBaseV2::from_untrusted_remote_fields([1; 16], zero, 2, 2, 3)
                .is_err()
        );
        assert!(
            ClosedPolicyRootCasBaseV2::from_untrusted_remote_fields([1; 16], prior, 1, 2, 3)
                .is_err()
        );
        assert!(
            ClosedPolicyRootCasBaseV2::from_untrusted_remote_fields([1; 16], zero, 1, 0, 3)
                .is_err()
        );
        assert!(
            ClosedPolicyRootCasBaseV2::from_untrusted_remote_fields([1; 16], zero, 1, 2, 0)
                .is_err()
        );
    }

    fn identity(binding: &ClosedPolicyRootBindingV2) -> RootPolicyBindingIdentityV2 {
        RootPolicyBindingIdentityV2 {
            deployment_head: binding.compiler_head,
            project: binding.project,
            publisher_generation: binding.publisher_generation,
            publisher_head: binding.publisher_head,
            project_policy_head: binding.project_policy_head,
            project_policy_input: binding.project_policy_input,
            prerequisite_claims: [
                binding.ancestry_head,
                binding.compiler_head,
                binding.cache_domain_head,
                binding.revocation_head,
            ],
            deployment_signer_generation: binding.deployment_signer_generation,
            project_signer_generation: binding.project_signer_generation,
            issuer_owner: binding.issuer_owner,
        }
    }

    fn open_test_root(directory: &std::path::Path) -> Journal {
        let uid = fs::metadata(directory).expect("directory owner").uid();
        Journal::open_protected_at_uid(
            directory,
            "closed-binding.journal",
            policy_authority_journal_limits(),
            uid,
        )
        .expect("protected root journal")
        .0
    }

    #[test]
    fn cache_only_cut_requires_root_cas_and_every_protected_hold_field() {
        let directory = tempfile::tempdir().expect("protected test directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private directory");
        let mut journal = open_test_root(directory.path());
        let authority = journal
            .claim_protected_authority(RecordNamespace::DesiredState)
            .expect("root writer");
        let binding = cas_fixture();
        let binding_head = closed_policy_binding_digest_v2(&binding.encode().expect("binding"))
            .expect("binding head");
        let session = ClosedPolicyRootSessionV2 {
            authority,
            identity: identity(&binding),
            postcommit: None,
        };
        let hold = |project, partition, cache_head, head, epoch| {
            CachePolicyHoldV1::new(project, partition, cache_head, head, epoch).expect("Cache hold")
        };
        let matching = hold(
            binding.project,
            binding.physical_partition,
            binding.physical_cache_head,
            binding_head,
            binding.handoff_epoch,
        );

        let cut = session
            .prepare_cache_cut_with_observation(&binding, matching)
            .expect("Cache-only comparison");
        assert_eq!(cut.binding(), binding_head);
        assert_eq!(cut.epoch(), binding.handoff_epoch);
        assert_eq!(cut.project(), binding.project);
        assert_eq!(cut.partition(), binding.physical_partition);
        assert_eq!(cut.cache_head(), binding.physical_cache_head);
        assert_eq!(
            session
                .current_base()
                .expect("unchanged root")
                .next_generation(),
            1
        );

        let wrong_holds = [
            hold(
                ProjectId::from_bytes([90; 16]),
                binding.physical_partition,
                binding.physical_cache_head,
                binding_head,
                binding.handoff_epoch,
            ),
            hold(
                binding.project,
                ObjectDigest::from_bytes([91; 32]),
                binding.physical_cache_head,
                binding_head,
                binding.handoff_epoch,
            ),
            hold(
                binding.project,
                binding.physical_partition,
                ObjectDigest::from_bytes([92; 32]),
                binding_head,
                binding.handoff_epoch,
            ),
            hold(
                binding.project,
                binding.physical_partition,
                binding.physical_cache_head,
                ObjectDigest::from_bytes([93; 32]),
                binding.handoff_epoch,
            ),
            hold(
                binding.project,
                binding.physical_partition,
                binding.physical_cache_head,
                binding_head,
                binding.handoff_epoch + 1,
            ),
        ];
        for wrong in wrong_holds {
            assert!(
                session
                    .prepare_cache_cut_with_observation(&binding, wrong)
                    .is_err()
            );
        }

        let mut stale_root = binding.clone();
        stale_root.root_generation += 1;
        stale_root.barrier_epoch += 1;
        stale_root.handoff_epoch += 1;
        stale_root.root_predecessor = ObjectDigest::from_bytes([94; 32]);
        assert!(
            session
                .prepare_cache_cut_with_observation(&stale_root, matching)
                .is_err()
        );

        let mut wrong_identity = binding.clone();
        wrong_identity.publisher_head = ObjectDigest::from_bytes([95; 32]);
        assert!(
            session
                .prepare_cache_cut_with_observation(&wrong_identity, matching)
                .is_err()
        );
        assert_eq!(
            session
                .current_base()
                .expect("rejected cuts do not advance root")
                .next_generation(),
            1
        );
    }

    #[test]
    fn legacy_root_session_rejects_an_admitted_explicit_project_source() {
        let directory = tempfile::tempdir().expect("protected test directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private directory");
        let mut journal = open_test_root(directory.path());
        let deployment_key = SigningKey::from_bytes(&[3; 32]).verifying_key();
        let project_key = SigningKey::from_bytes(&[4; 32]).verifying_key();
        let deployment_packet = b"current-deployment";
        let legacy_packet = b"legacy-project-packet";
        let legacy_input = b"legacy-project-input";
        let pins = encode_policy_signer_pins_v1(2, &deployment_key, 3, &project_key)
            .expect("root signer pins");
        let transaction = JournalTransaction::new(
            [31; 16],
            vec![
                JournalRecord::put(
                    RecordNamespace::DesiredState,
                    HEAD_KEY.to_vec(),
                    deployment_packet.to_vec(),
                ),
                JournalRecord::put(
                    RecordNamespace::DesiredState,
                    SIGNER_PINS_KEY.to_vec(),
                    pins,
                ),
                JournalRecord::put(
                    RecordNamespace::DesiredState,
                    HEAD_KEY_V2.to_vec(),
                    b"explicit-source".to_vec(),
                ),
                JournalRecord::put(
                    RecordNamespace::DesiredState,
                    PROJECT_HEAD_KEY.to_vec(),
                    legacy_packet.to_vec(),
                ),
                JournalRecord::put(
                    RecordNamespace::DesiredState,
                    PROJECT_INPUT_KEY.to_vec(),
                    legacy_input.to_vec(),
                ),
            ],
        )
        .expect("root transaction");
        journal
            .commit(&transaction)
            .expect("protected source record");
        let project_head = SignedProjectPolicyHeadV1 {
            project: ProjectId::from_bytes([1; 16]),
            generation: 1,
            packet_digest: ObjectDigest::from_bytes(Sha256::digest(legacy_packet).into()),
            input_digest: ObjectDigest::from_bytes(Sha256::digest(legacy_input).into()),
            publisher_generation: 1,
            publisher_digest: ObjectDigest::from_bytes([7; 32]),
            prerequisites: [
                ObjectDigest::from_bytes([8; 32]),
                ObjectDigest::from_bytes(Sha256::digest(deployment_packet).into()),
                ObjectDigest::from_bytes([9; 32]),
                ObjectDigest::from_bytes([10; 32]),
            ],
            expires_at: 30,
        };

        assert!(matches!(
            with_closed_policy_binding_session_in_journal_v2(
                &mut journal,
                deployment_packet,
                2,
                &deployment_key,
                project_head.into(),
                None,
                3,
                &project_key,
                1000,
                1000,
                |_| (),
            ),
            Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)
        ));
    }

    #[test]
    fn explicit_root_session_cas_requires_exact_source_bytes_and_pinned_generations() {
        let directory = tempfile::tempdir().expect("protected test directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private directory");
        let mut journal = open_test_root(directory.path());
        let deployment_key = SigningKey::from_bytes(&[13; 32]).verifying_key();
        let project_key = SigningKey::from_bytes(&[14; 32]).verifying_key();
        let deployment_packet = b"current-deployment";
        let project_packet = b"signed-explicit-project";
        let project_input = b"canonical-explicit-input";
        let pins = encode_policy_signer_pins_v1(2, &deployment_key, 3, &project_key)
            .expect("root signer pins");
        let transaction = JournalTransaction::new(
            [32; 16],
            vec![
                JournalRecord::put(
                    RecordNamespace::DesiredState,
                    HEAD_KEY.to_vec(),
                    deployment_packet.to_vec(),
                ),
                JournalRecord::put(
                    RecordNamespace::DesiredState,
                    SIGNER_PINS_KEY.to_vec(),
                    pins,
                ),
                JournalRecord::put(
                    RecordNamespace::DesiredState,
                    HEAD_KEY_V2.to_vec(),
                    project_packet.to_vec(),
                ),
                JournalRecord::put(
                    RecordNamespace::DesiredState,
                    INPUT_KEY_V2.to_vec(),
                    project_input.to_vec(),
                ),
            ],
        )
        .expect("root source transaction");
        journal.commit(&transaction).expect("current root source");

        let issuer = Sha256::new()
            .chain_update(ISSUER_DOMAIN)
            .chain_update(1000_u32.to_be_bytes())
            .chain_update(1000_u32.to_be_bytes())
            .finalize();
        let mut binding = cas_fixture();
        binding.issuer_owner.copy_from_slice(&issuer[..16]);
        binding.compiler_head = ObjectDigest::from_bytes(Sha256::digest(deployment_packet).into());
        binding.project_policy_head =
            ObjectDigest::from_bytes(Sha256::digest(project_packet).into());
        binding.project_policy_input =
            ObjectDigest::from_bytes(Sha256::digest(project_input).into());
        binding.deployment_signer_generation = 2;
        binding.project_signer_generation = 3;
        let head = RootProjectHeadFieldsV2 {
            project: binding.project,
            publisher_generation: binding.publisher_generation,
            publisher_head: binding.publisher_head,
            packet_digest: binding.project_policy_head,
            input_digest: binding.project_policy_input,
            prerequisite_claims: [
                binding.ancestry_head,
                binding.compiler_head,
                binding.cache_domain_head,
                binding.revocation_head,
            ],
        };
        let encoded = binding.encode().expect("closed binding");
        let committed = with_closed_policy_binding_session_in_journal_v2(
            &mut journal,
            deployment_packet,
            2,
            &deployment_key,
            head,
            Some((project_packet, project_input)),
            3,
            &project_key,
            1000,
            1000,
            |session| session.commit_closed_binding(&encoded),
        )
        .expect("root currentness and readback")
        .expect("closed root CAS");
        assert_eq!(committed.root_generation(), 1);
        assert!(matches!(
            with_closed_policy_binding_session_in_journal_v2(
                &mut journal,
                deployment_packet,
                2,
                &deployment_key,
                head,
                Some((project_packet, b"substituted-input")),
                3,
                &project_key,
                1000,
                1000,
                |_| panic!("substituted source reached CAS"),
            ),
            Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)
        ));
        assert!(matches!(
            with_closed_policy_binding_session_in_journal_v2(
                &mut journal,
                deployment_packet,
                4,
                &deployment_key,
                head,
                Some((project_packet, project_input)),
                3,
                &project_key,
                1000,
                1000,
                |_| panic!("rotated signer reached CAS"),
            ),
            Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)
        ));
    }

    #[test]
    fn protected_closed_cas_replays_exactly_and_fences_root_predecessor() {
        let directory = tempfile::tempdir().expect("protected test directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private directory");
        let first = cas_fixture();
        let first_bytes = first.encode().expect("first binding");
        let mut journal = open_test_root(directory.path());

        let authority = journal
            .claim_protected_authority(RecordNamespace::DesiredState)
            .expect("root authority");
        let mut session = ClosedPolicyRootSessionV2 {
            authority,
            identity: identity(&first),
            postcommit: None,
        };
        let first_head = closed_policy_binding_digest_v2(&first_bytes).expect("first head");
        assert_eq!(
            recover_closed_binding_decision_from_authority(&session.authority, first_head, 1)
                .expect("uncommitted current epoch"),
            (ClosedPolicyBindingDecisionV2::Absent, None)
        );
        let first_commit = session
            .commit_closed_binding(&first_bytes)
            .expect("first root CAS");
        assert_eq!(first_commit.root_generation(), 1);
        assert_eq!(first_commit.handoff_epoch(), 1);
        assert_eq!(
            recover_closed_binding_decision_from_authority(&session.authority, first_head, 1)
                .expect("durable decision before reply"),
            (
                ClosedPolicyBindingDecisionV2::CommittedHeld(first_commit),
                Some(first_bytes.clone())
            )
        );
        assert!(session.commit_closed_binding(&first_bytes).is_err());
        drop(session);
        drop(journal);

        let mut journal = open_test_root(directory.path());
        let authority = journal
            .claim_protected_authority(RecordNamespace::DesiredState)
            .expect("recovered root authority");
        let mut session = ClosedPolicyRootSessionV2 {
            authority,
            identity: identity(&first),
            postcommit: None,
        };
        assert_eq!(
            session
                .commit_closed_binding(&first_bytes)
                .expect("exact durable replay"),
            first_commit
        );
        assert_eq!(
            current_hold(&session.authority, first_commit.binding(), 2, 1)
                .expect("cold hold readback")
                .expect("durable hold")
                .epoch,
            first_commit.handoff_epoch()
        );
        assert!(session.release_inert_hold(first_commit).is_ok());
        assert_eq!(
            recover_closed_binding_decision_from_authority(&session.authority, first_head, 1)
                .expect("released decision"),
            (
                ClosedPolicyBindingDecisionV2::CommittedReleased(first_commit),
                Some(first_bytes.clone())
            )
        );
        assert!(
            recover_closed_binding_decision_from_authority(
                &session.authority,
                ObjectDigest::from_bytes([99; 32]),
                1
            )
            .is_err()
        );
        assert!(session.release_inert_hold(first_commit).is_err());
        drop(session);

        let mut second = first.clone();
        second.operation = OperationId::from_bytes([25; 16]);
        second.sandbox = SandboxId::from_bytes([26; 16]);
        second.root_predecessor = first_commit.binding();
        second.root_generation = 2;
        second.barrier_epoch = 2;
        second.handoff_epoch = 2;
        second.effect_transaction = [27; 16];
        let second_bytes = second.encode().expect("second binding");
        let authority = journal
            .claim_protected_authority(RecordNamespace::DesiredState)
            .expect("root successor authority");
        let mut session = ClosedPolicyRootSessionV2 {
            authority,
            identity: identity(&second),
            postcommit: None,
        };
        let second_commit = session
            .commit_closed_binding(&second_bytes)
            .expect("successor root CAS");
        assert_eq!(second_commit.root_generation(), 2);
        drop(session);
        drop(journal);

        let mut recovered = open_test_root(directory.path());
        let authority = recovered
            .claim_protected_authority(RecordNamespace::DesiredState)
            .expect("recovered root chain");
        assert_eq!(
            current_root_binding_chain(&authority).expect("exact recovered chain"),
            (second_commit.binding(), 3, 2)
        );
        drop(authority);
        let authority = recovered
            .claim_protected_authority(RecordNamespace::DesiredState)
            .expect("stale replay authority");
        let mut stale_session = ClosedPolicyRootSessionV2 {
            authority,
            identity: identity(&first),
            postcommit: None,
        };
        assert!(stale_session.commit_closed_binding(&first_bytes).is_err());
        drop(stale_session);
        assert!(matches!(
            ProtectedPolicyPublicationVerifierV1::from_journal(recovered),
            Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)
        ));
    }

    #[test]
    fn staged_root_base_survives_reopen_and_fences_superseded_or_changed_identity() {
        let directory = tempfile::tempdir().expect("protected test directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private directory");
        let binding = cas_fixture();
        let mut root = open_test_root(directory.path());
        let authority = root
            .claim_protected_authority(RecordNamespace::DesiredState)
            .expect("root authority");
        let mut session = ClosedPolicyRootSessionV2 {
            authority,
            identity: identity(&binding),
            postcommit: None,
        };
        let first = session
            .stage_closed_binding_base(|| Ok([7; 16]))
            .expect("durable first stage");
        assert_eq!(first.base().next_generation(), 1);
        assert_eq!(first.issue_epoch(), 1);
        assert_eq!(first.challenge(), [7; 16]);
        assert!(session.validate_staged_closed_binding_base(first).is_ok());
        drop(session);
        drop(root);

        let mut root = open_test_root(directory.path());
        let authority = root
            .claim_protected_authority(RecordNamespace::DesiredState)
            .expect("reopened root authority");
        let mut session = ClosedPolicyRootSessionV2 {
            authority,
            identity: identity(&binding),
            postcommit: None,
        };
        assert!(session.validate_staged_closed_binding_base(first).is_ok());
        assert!(session.stage_closed_binding_base(|| Ok([7; 16])).is_err());
        let second = session
            .stage_closed_binding_base(|| Ok([8; 16]))
            .expect("superseding stage");
        assert_eq!(second.issue_epoch(), 2);
        assert!(session.validate_staged_closed_binding_base(first).is_err());
        drop(session);

        let authority = root
            .claim_protected_authority(RecordNamespace::DesiredState)
            .expect("changed source authority");
        let mut changed_identity = identity(&binding);
        changed_identity.project_policy_input = ObjectDigest::from_bytes([41; 32]);
        let changed = ClosedPolicyRootSessionV2 {
            authority,
            identity: changed_identity,
            postcommit: None,
        };
        assert!(changed.validate_staged_closed_binding_base(second).is_err());
        drop(changed);

        let authority = root
            .claim_protected_authority(RecordNamespace::DesiredState)
            .expect("matching source authority");
        let mut session = ClosedPolicyRootSessionV2 {
            authority,
            identity: identity(&binding),
            postcommit: None,
        };
        assert!(session.validate_staged_closed_binding_base(second).is_ok());
        let proposed = binding.encode().expect("closed proposal");
        assert!(
            session
                .commit_staged_closed_binding(&proposed, first)
                .is_err()
        );
        session
            .commit_staged_closed_binding(&proposed, second)
            .expect("staged Root CAS advances chain");
        assert!(session.validate_staged_closed_binding_base(second).is_err());
        assert!(session.stage_closed_binding_base(|| Ok([9; 16])).is_err());
    }

    #[test]
    fn lost_ack_keeps_exact_custody_and_rejects_new_root_binding_after_reopen() {
        let directory = tempfile::tempdir().expect("protected test directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private directory");
        let first = cas_fixture();
        let first_bytes = first.encode().expect("first binding");
        let mut journal = open_test_root(directory.path());
        let authority = journal
            .claim_protected_authority(RecordNamespace::DesiredState)
            .expect("root authority");
        let mut session = ClosedPolicyRootSessionV2 {
            authority,
            identity: identity(&first),
            postcommit: None,
        };
        let first_commit = session
            .commit_closed_binding(&first_bytes)
            .expect("durable CAS and hold");
        drop(session);
        drop(journal);

        let mut recovered = open_test_root(directory.path());
        let authority = recovered
            .claim_protected_authority(RecordNamespace::DesiredState)
            .expect("cold root authority");
        let (head, next_epoch, count) =
            current_root_binding_chain(&authority).expect("cold chain and hold readback");
        assert!(ensure_root_binding_unheld(&authority).is_err());
        let held = current_hold(&authority, head, next_epoch, count)
            .expect("held record")
            .expect("held after lost ACK");
        assert!(held.held);
        assert_eq!(held.binding, first_commit.binding());
        assert_eq!(held.epoch, first_commit.handoff_epoch());
        drop(authority);

        let mut second = first.clone();
        second.operation = OperationId::from_bytes([25; 16]);
        second.sandbox = SandboxId::from_bytes([26; 16]);
        second.root_predecessor = first_commit.binding();
        second.root_generation = 2;
        second.barrier_epoch = 2;
        second.handoff_epoch = 2;
        second.effect_transaction = [27; 16];
        let authority = recovered
            .claim_protected_authority(RecordNamespace::DesiredState)
            .expect("second root authority");
        let mut session = ClosedPolicyRootSessionV2 {
            authority,
            identity: identity(&second),
            postcommit: None,
        };
        assert!(
            session
                .commit_closed_binding(&second.encode().expect("second binding"))
                .is_err()
        );
        drop(session);

        let mut authority = recovered
            .claim_protected_authority(RecordNamespace::DesiredState)
            .expect("recovery authority");
        assert!(release_hold(&mut authority, RootBindingHoldV1 { epoch: 2, ..held }).is_err());
        release_hold(&mut authority, held).expect("exact cold release");
        assert!(release_hold(&mut authority, held).is_err());
        assert!(current_root_binding_chain(&authority).is_ok());
        assert!(ensure_root_binding_unheld(&authority).is_ok());
    }

    #[test]
    fn controller_cold_release_distinguishes_absent_released_and_lost_root_reply() {
        let controller = crate::journal::ControllerPolicyHoldV1::new(
            OperationId::from_bytes([1; 16]),
            SandboxId::from_bytes([2; 16]),
            ObjectDigest::from_bytes([3; 32]),
            ObjectDigest::from_bytes([4; 32]),
            1,
        )
        .expect("controller hold");
        let root = RootBindingHoldV1 {
            issuer_owner: [5; 16],
            binding: controller.binding(),
            epoch: controller.epoch(),
            held: true,
        };

        assert!(controller_hold_can_retire_at_root_cut(controller, 1, None));
        let next_controller = crate::journal::ControllerPolicyHoldV1::new(
            OperationId::from_bytes([1; 16]),
            SandboxId::from_bytes([2; 16]),
            ObjectDigest::from_bytes([3; 32]),
            ObjectDigest::from_bytes([8; 32]),
            2,
        )
        .expect("next Controller hold");
        let earlier_unresolved = RootBindingHoldV1 {
            binding: ObjectDigest::from_bytes([7; 32]),
            ..root
        };
        assert!(!controller_hold_can_retire_at_root_cut(
            next_controller,
            2,
            Some(earlier_unresolved)
        ));
        assert!(controller_hold_can_retire_at_root_cut(
            next_controller,
            2,
            Some(RootBindingHoldV1 {
                held: false,
                ..earlier_unresolved
            })
        ));
        assert!(!controller_hold_can_retire_at_root_cut(
            controller,
            2,
            Some(root)
        ));
        assert!(controller_hold_can_retire_at_root_cut(
            controller,
            2,
            Some(RootBindingHoldV1 {
                held: false,
                ..root
            })
        ));
        assert!(!controller_hold_can_retire_at_root_cut(
            controller,
            2,
            Some(RootBindingHoldV1 {
                binding: ObjectDigest::from_bytes([6; 32]),
                held: false,
                ..root
            })
        ));
        assert!(!controller_hold_can_retire_at_root_cut(controller, 3, None));
    }

    #[test]
    fn cache_cold_release_requires_exact_root_binding_and_epoch() {
        let cache = CachePolicyHoldV1::new(
            ProjectId::from_bytes([1; 16]),
            ObjectDigest::from_bytes([2; 32]),
            ObjectDigest::from_bytes([3; 32]),
            ObjectDigest::from_bytes([4; 32]),
            7,
        )
        .expect("protected Cache hold");
        let root = RootBindingHoldV1 {
            issuer_owner: [5; 16],
            binding: cache.binding(),
            epoch: cache.epoch(),
            held: true,
        };

        assert!(cache_hold_can_retire_at_root_cut(cache, 7, None));
        assert!(!cache_hold_can_retire_at_root_cut(cache, 8, Some(root)));
        assert!(cache_hold_can_retire_at_root_cut(
            cache,
            8,
            Some(RootBindingHoldV1 {
                held: false,
                ..root
            })
        ));
        assert!(!cache_hold_can_retire_at_root_cut(
            cache,
            8,
            Some(RootBindingHoldV1 {
                binding: ObjectDigest::from_bytes([9; 32]),
                held: false,
                ..root
            })
        ));
        assert!(!cache_hold_can_retire_at_root_cut(cache, 9, None));
    }

    #[test]
    fn lost_root_reply_keeps_controller_frozen_until_exact_root_release() {
        let directory = tempfile::tempdir().expect("protected test directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private directory");
        let binding = cas_fixture();
        let mut root = open_test_root(directory.path());
        let authority = root
            .claim_protected_authority(RecordNamespace::DesiredState)
            .expect("root authority");
        let mut session = ClosedPolicyRootSessionV2 {
            authority,
            identity: identity(&binding),
            postcommit: None,
        };
        let committed = session
            .commit_closed_binding(&binding.encode().expect("binding bytes"))
            .expect("root CAS and hold");
        drop(session);
        drop(root);

        let uid = fs::metadata(directory.path())
            .expect("directory owner")
            .uid();
        let open_controller = || {
            Journal::open_protected_at_uid(
                directory.path(),
                "controller.journal",
                crate::journal::JournalLimits::default(),
                uid,
            )
            .expect("protected Controller")
            .0
        };
        let open_source = || {
            let journal = Journal::open_protected_at_uid(
                directory.path(),
                "source-domains-v1.journal",
                crate::journal::JournalLimits::default(),
                uid,
            )
            .expect("protected source domains")
            .0;
            ProtectedSourceDomainJournalOwnerV1::from_test_journal(journal)
        };
        let hold = crate::journal::ControllerPolicyHoldV1::new(
            binding.operation,
            binding.sandbox,
            binding.operation_revision,
            committed.binding(),
            committed.handoff_epoch(),
        )
        .expect("Controller hold");
        let mut controller = open_controller();
        controller
            .acquire_controller_policy_hold_v1(hold)
            .expect("durable hold");
        drop(controller);

        let mut controller = open_controller();
        let mut source = open_source();
        let source_hold = SourceDomainPolicyHoldV1::new(
            binding.operation,
            binding.sandbox,
            binding.operation_revision,
            binding.ancestry_head,
            committed.binding(),
            committed.handoff_epoch(),
        )
        .expect("source hold");
        source
            .acquire_closed_policy_source_hold_v1(source_hold)
            .unwrap();
        let mut root = open_test_root(directory.path());
        let mut authority = root
            .claim_protected_authority(RecordNamespace::DesiredState)
            .expect("cold root authority");
        assert!(
            release_controller_hold_against_root_authority(
                &mut controller,
                &mut source,
                hold,
                &authority,
            )
            .is_err()
        );
        assert!(
            controller
                .controller_policy_hold_v1()
                .unwrap()
                .unwrap()
                .is_held()
        );

        let (head, next_epoch, count) = current_root_binding_chain(&authority).unwrap();
        let root_hold = current_hold(&authority, head, next_epoch, count)
            .unwrap()
            .expect("root hold after lost reply");
        release_hold(&mut authority, root_hold).expect("exact root cold release");
        assert!(
            release_controller_hold_against_root_authority(
                &mut controller,
                &mut source,
                hold,
                &authority,
            )
            .is_err()
        );
        assert!(
            controller
                .controller_policy_hold_v1()
                .unwrap()
                .unwrap()
                .is_held()
        );
        source
            .release_closed_policy_source_hold_after_root_readback_v1(source_hold)
            .unwrap();
        release_controller_hold_against_root_authority(
            &mut controller,
            &mut source,
            hold,
            &authority,
        )
        .expect("root-released readback permits Controller release");
        assert!(
            !controller
                .controller_policy_hold_v1()
                .unwrap()
                .unwrap()
                .is_held()
        );
    }

    #[test]
    fn lost_root_reply_keeps_source_domains_frozen_until_exact_root_release() {
        let directory = tempfile::tempdir().expect("protected test directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private directory");
        let binding = cas_fixture();
        let mut root = open_test_root(directory.path());
        let authority = root
            .claim_protected_authority(RecordNamespace::DesiredState)
            .expect("root authority");
        let mut session = ClosedPolicyRootSessionV2 {
            authority,
            identity: identity(&binding),
            postcommit: None,
        };
        let committed = session
            .commit_closed_binding(&binding.encode().expect("binding bytes"))
            .expect("root CAS and hold");
        drop(session);
        drop(root);

        let uid = fs::metadata(directory.path())
            .expect("directory owner")
            .uid();
        let open_controller = || {
            Journal::open_protected_at_uid(
                directory.path(),
                "controller.journal",
                crate::journal::JournalLimits::default(),
                uid,
            )
            .expect("protected Controller")
            .0
        };
        let open_source = || {
            let journal = Journal::open_protected_at_uid(
                directory.path(),
                "source-domains-v1.journal",
                crate::journal::JournalLimits::default(),
                uid,
            )
            .expect("protected source domains")
            .0;
            ProtectedSourceDomainJournalOwnerV1::from_test_journal(journal)
        };
        let controller_hold = ControllerPolicyHoldV1::new(
            binding.operation,
            binding.sandbox,
            binding.operation_revision,
            committed.binding(),
            committed.handoff_epoch(),
        )
        .expect("Controller hold");
        let source_hold = SourceDomainPolicyHoldV1::new(
            binding.operation,
            binding.sandbox,
            binding.operation_revision,
            binding.ancestry_head,
            committed.binding(),
            committed.handoff_epoch(),
        )
        .expect("source-domain hold");
        let mut controller = open_controller();
        controller
            .acquire_controller_policy_hold_v1(controller_hold)
            .unwrap();
        let mut source = open_source();
        source
            .acquire_closed_policy_source_hold_v1(source_hold)
            .unwrap();
        drop(source);
        drop(controller);

        let controller = open_controller();
        let mut source = open_source();
        let mut root = open_test_root(directory.path());
        let mut authority = root
            .claim_protected_authority(RecordNamespace::DesiredState)
            .unwrap();
        assert!(
            source
                .closed_policy_source_hold_v1()
                .unwrap()
                .unwrap()
                .is_held()
        );
        assert!(
            release_source_hold_against_root_authority(
                &mut source,
                source_hold,
                controller.controller_policy_hold_v1().unwrap().unwrap(),
                &authority,
            )
            .is_err()
        );
        let (head, next_epoch, count) = current_root_binding_chain(&authority).unwrap();
        let root_hold = current_hold(&authority, head, next_epoch, count)
            .unwrap()
            .unwrap();
        release_hold(&mut authority, root_hold).expect("exact root cold release");
        release_source_hold_against_root_authority(
            &mut source,
            source_hold,
            controller.controller_policy_hold_v1().unwrap().unwrap(),
            &authority,
        )
        .expect("root-released readback permits source release");
        assert!(
            !source
                .closed_policy_source_hold_v1()
                .unwrap()
                .unwrap()
                .is_held()
        );
        assert!(
            controller
                .controller_policy_hold_v1()
                .unwrap()
                .unwrap()
                .is_held()
        );
    }

    #[test]
    fn closed_cas_rejects_foreign_signer_epoch_and_duplicate_create() {
        let directory = tempfile::tempdir().expect("protected test directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private directory");
        let first = cas_fixture();
        let mut journal = open_test_root(directory.path());
        let authority = journal
            .claim_protected_authority(RecordNamespace::DesiredState)
            .expect("root authority");
        let mut foreign = identity(&first);
        foreign.project_signer_generation += 1;
        let mut session = ClosedPolicyRootSessionV2 {
            authority,
            identity: foreign,
            postcommit: None,
        };
        assert!(
            session
                .commit_closed_binding(&first.encode().unwrap())
                .is_err()
        );
        drop(session);

        let authority = journal
            .claim_protected_authority(RecordNamespace::DesiredState)
            .expect("root authority");
        let mut session = ClosedPolicyRootSessionV2 {
            authority,
            identity: identity(&first),
            postcommit: None,
        };
        let committed = session
            .commit_closed_binding(&first.encode().unwrap())
            .expect("first root CAS");
        session
            .release_inert_hold(committed)
            .expect("release first inert hold before testing uniqueness");
        drop(session);

        let mut duplicate = first.clone();
        duplicate.root_predecessor = committed.binding();
        duplicate.root_generation = 2;
        duplicate.barrier_epoch = 2;
        duplicate.handoff_epoch = 2;
        duplicate.candidate = ObjectDigest::from_bytes([28; 32]);
        let authority = journal
            .claim_protected_authority(RecordNamespace::DesiredState)
            .expect("root authority");
        let mut session = ClosedPolicyRootSessionV2 {
            authority,
            identity: identity(&duplicate),
            postcommit: None,
        };
        let duplicate_hold = matching_cache_hold(&duplicate);
        assert!(
            session
                .prepare_cache_cut_with_observation(&duplicate, duplicate_hold)
                .is_err()
        );
        assert!(
            session
                .commit_closed_binding(&duplicate.encode().unwrap())
                .is_err()
        );
        drop(session);

        duplicate.operation = OperationId::from_bytes([31; 16]);
        let authority = journal
            .claim_protected_authority(RecordNamespace::DesiredState)
            .expect("root authority");
        let mut session = ClosedPolicyRootSessionV2 {
            authority,
            identity: identity(&duplicate),
            postcommit: None,
        };
        let duplicate_hold = matching_cache_hold(&duplicate);
        assert!(
            session
                .prepare_cache_cut_with_observation(&duplicate, duplicate_hold)
                .is_err()
        );
        assert!(
            session
                .commit_closed_binding(&duplicate.encode().unwrap())
                .is_err()
        );
        drop(session);

        let authority = journal
            .claim_protected_authority(RecordNamespace::DesiredState)
            .expect("unchanged root authority");
        assert_eq!(
            current_root_binding_chain(&authority).expect("no duplicate committed"),
            (committed.binding(), 2, 1)
        );
        drop(authority);

        let transaction = JournalTransaction::new(
            [29; 16],
            vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                ROOT_BINDING_HEAD_KEY.to_vec(),
                vec![30; 32],
            )],
        )
        .expect("substituted pointer transaction");
        journal
            .claim_protected_authority(RecordNamespace::DesiredState)
            .expect("root authority")
            .commit(&transaction)
            .expect("protected substitution");
        let authority = journal
            .claim_protected_authority(RecordNamespace::DesiredState)
            .expect("root authority");
        assert!(current_root_binding_chain(&authority).is_err());
    }

    #[test]
    fn canonical_binding_round_trips_and_rejects_every_substituted_head() {
        let binding = fixture();
        let encoded = binding.encode().expect("canonical binding");
        let key = binding.key().expect("content-addressed key");
        assert_eq!(encoded.len(), RECORD_BYTES);
        assert_eq!(
            decode_closed_policy_binding_v2(&key, &encoded).expect("readback"),
            binding
        );

        for offset in [
            0, 8, 10, 16, 32, 48, 64, 80, 104, 120, 144, 160, 192, 224, 256, 288, 320, 352, 384,
            416, 448, 480, 496, 512, 528, 536, 568, 600, 608, 624, 632,
        ] {
            let mut changed = encoded.clone();
            changed[offset] ^= 1;
            assert!(
                decode_closed_policy_binding_v2(&key, &changed).is_err(),
                "offset {offset}"
            );
        }
        let mut wrong_key = key.clone();
        *wrong_key.last_mut().expect("digest suffix") ^= 1;
        assert!(decode_closed_policy_binding_v2(&wrong_key, &encoded).is_err());

        let mut substituted = encoded.clone();
        substituted[384] ^= 1;
        let checksum = Sha256::new()
            .chain_update(CHECKSUM_DOMAIN)
            .chain_update(&substituted[..BODY_BYTES])
            .finalize();
        substituted[BODY_BYTES..].copy_from_slice(&checksum);
        assert!(decode_closed_policy_binding_v2(&key, &substituted).is_err());
    }

    #[test]
    fn barrier_epoch_and_root_predecessor_shape_fail_closed() {
        let mut binding = fixture();
        binding.handoff_epoch += 1;
        assert!(binding.encode().is_err());

        binding = fixture();
        binding.root_generation = 2;
        assert!(binding.encode().is_err());

        binding.root_predecessor = ObjectDigest::from_bytes([25; 32]);
        assert!(binding.encode().is_ok());
    }

    #[test]
    fn protected_root_readback_still_cannot_authorize_v2_publication() {
        let directory = tempfile::tempdir().expect("protected test directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private directory");
        let uid = fs::metadata(directory.path())
            .expect("directory owner")
            .uid();
        let (mut journal, _) = Journal::open_protected_at_uid(
            directory.path(),
            "authority.journal",
            policy_authority_journal_limits(),
            uid,
        )
        .expect("protected root journal");
        let binding = fixture();
        let key = binding.key().expect("binding key");
        let encoded = binding.encode().expect("binding bytes");
        let transaction = JournalTransaction::new(
            [26; 16],
            vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                key.clone(),
                encoded.clone(),
            )],
        )
        .expect("root transaction");
        journal
            .claim_protected_authority(RecordNamespace::DesiredState)
            .expect("root claim")
            .commit(&transaction)
            .expect("durable write");
        assert_eq!(
            decode_closed_policy_binding_v2(
                &key,
                journal
                    .get(RecordNamespace::DesiredState, &key)
                    .expect("durable readback"),
            )
            .expect("canonical readback"),
            binding
        );
        assert!(matches!(
            ProtectedPolicyPublicationVerifierV1::from_journal(journal),
            Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)
        ));
    }
}
