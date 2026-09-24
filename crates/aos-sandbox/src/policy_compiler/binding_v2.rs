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

use std::{collections::BTreeSet, path::Path};

use aos_sandbox_core::{ObjectDigest, OperationId, ProjectId, SandboxId};
use ed25519_dalek::VerifyingKey;
use sha2::{Digest as _, Sha256};

use crate::journal::{
    Journal, JournalRecord, JournalTransaction, ProtectedJournalAuthority,
    ProtectedJournalSnapshot, RecordNamespace,
};

use super::deployment_head::{
    HEAD_KEY, PROJECT_HEAD_KEY, PROJECT_INPUT_KEY, SIGNER_PINS_KEY, encode_policy_signer_pins_v1,
};
use super::project_source_v2::{HEAD_KEY_V2, INPUT_KEY_V2};
use super::protected_owner::{
    MAXIMUM_POLICY_BINDINGS, POLICY_AUTHORITY_JOURNAL, POLICY_BINDING_KEY_PREFIX,
    PROTECTED_POLICY_ROOT, policy_authority_journal_limits,
};
use super::{
    PolicyCompilerJournalErrorV1, SignedProjectPolicyHeadV1, SignedProjectPolicyHeadV2,
    verify_signed_project_policy_source_v2,
};

mod producer;

pub use producer::{
    propose_closed_current_create_explicit_policy_binding_v2,
    propose_closed_current_create_policy_binding_v2,
};

pub(super) const BINDING_V2_KEY_PREFIX: &[u8] = b"\0aos-policy-compiler-binding-v2\0";
const MAGIC: &[u8; 8] = b"AOSPCB02";
const CHECKSUM_DOMAIN: &[u8] = b"aos.sandbox.policy-compiler.protected-binding.v2\0";
const KEY_DOMAIN: &[u8] = b"aos.sandbox.policy-compiler.binding-key.v2\0";
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
        let claims = self.identity.prerequisite_claims;
        if binding.issuer_owner != self.identity.issuer_owner
            || binding.project != self.identity.project
            || binding.publisher_generation != self.identity.publisher_generation
            || binding.publisher_head != self.identity.publisher_head
            || binding.project_policy_head != self.identity.project_policy_head
            || binding.project_policy_input != self.identity.project_policy_input
            || binding.ancestry_head != claims[0]
            || binding.compiler_head != self.identity.deployment_head
            || binding.cache_domain_head != claims[2]
            || binding.revocation_head != claims[3]
            || binding.deployment_signer_generation != self.identity.deployment_signer_generation
            || binding.project_signer_generation != self.identity.project_signer_generation
        {
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
        if exact_replay {
            if self.authority.get(&key)? != Some(proposed) {
                return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
            }
        } else {
            for (current_key, current_value) in self.authority.records()? {
                if current_key.starts_with(BINDING_V2_KEY_PREFIX) {
                    let current = decode_closed_policy_binding_v2(current_key, current_value)?;
                    if current.operation == binding.operation
                        || current.effect_transaction == binding.effect_transaction
                    {
                        return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
                    }
                }
            }
            if count >= MAXIMUM_POLICY_BINDINGS
                || binding.root_predecessor != predecessor
                || binding.root_generation != next_generation
                || binding.barrier_epoch != next_generation
                || binding.handoff_epoch != next_generation
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
                ],
            )?;
            self.authority.commit(&transaction)?;
            if self.authority.get(&key)? != Some(proposed)
                || self.authority.get(ROOT_BINDING_HEAD_KEY)? != Some(binding_head.as_bytes())
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
    Ok((predecessor, next_generation, bindings.len()))
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
        let first_commit = session
            .commit_closed_binding(&first_bytes)
            .expect("first root CAS");
        assert_eq!(first_commit.root_generation(), 1);
        assert_eq!(first_commit.handoff_epoch(), 1);
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
