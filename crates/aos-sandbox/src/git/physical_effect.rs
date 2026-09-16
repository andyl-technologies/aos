//! Injectable dormant Git protocol-v2 and sanitized-pack physical effects.
//!
//! Neither adapter is registered by the runtime. Physical implementations own
//! endpoint routing, descriptors, process confinement, and immutable naming;
//! callers can supply only validated logical records and cannot select a host
//! repository path or executable.
//!
//! ```text
//! AOSGSF01 || v1 || phase || project || repository || operation || intention
//!          || backend-receipt || readback-receipt || sha256
//! AOSGSR01 || v1 || present || project || repository || operation || intention
//!          || backend-receipt || boot || observed || expiry || receipt || sha256
//! ```

use std::path::Path;

use aos_sandbox_core::{ObjectDigest, ProjectId, ResourceId};
use sha2::{Digest as _, Sha256};

use crate::environment::{FixedLiveAuthorityClockV1, fixed_live_authority_clock_v1};
use crate::journal::{Journal, JournalError, JournalLimits, RecordNamespace, RecoveryReport};

use super::{
    DormantGitSmartEffectV1, GitCheapForkStatusV1, GitCheapForkV1, GitPackLeaseStatusV1,
    GitSmartAuthorityFenceV1, GitSmartDispatchStateV1, GitSmartEffectHandoffV1,
    GitSmartEffectOutcomeV1, GitSmartTransportErrorV1, ImmutablePackGenerationV1,
};

/// Advertises the truthful production status of sanitized-pack physical effects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitSanitizedForkPhysicalCapabilityV1 {
    /// No qualified installed backend and confinement policy are available.
    Unavailable {
        /// Stable source-only qualification gap commitment.
        reason: ObjectDigest,
    },
}

impl GitSanitizedForkPhysicalCapabilityV1 {
    /// Constructs the only v1 capability state exposed before qualification.
    ///
    /// # Errors
    ///
    /// Returns [`GitSmartTransportErrorV1::InvalidRequest`] for a sentinel reason.
    pub fn unavailable(reason: ObjectDigest) -> Result<Self, GitSmartTransportErrorV1> {
        if reason.as_bytes() == &[0; 32] {
            return Err(GitSmartTransportErrorV1::InvalidRequest);
        }
        Ok(Self::Unavailable { reason })
    }
}

const SANITIZED_READBACK_ROOT: &str = "/var/lib/aos/sandbox/source-evidence";
const SANITIZED_READBACK_JOURNAL: &str = "git-sanitized-fork-readback-v1.journal";
const SANITIZED_READBACK_PREFIX: &[u8] = b"git-sanitized-fork-readback-v1/";

/// Reports unavailable, stale, or substituted protected physical readback.
#[derive(Debug, thiserror::Error)]
pub enum GitSanitizedForkReadbackErrorV1 {
    /// Protected storage could not be opened or read.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// The exact current readback record was absent, expired, or noncanonical.
    #[error("protected sanitized-fork readback is invalid or unavailable")]
    InvalidEvidence,
}

/// Owns fixed protected, boot-scoped physical readback records.
pub struct GitSanitizedForkProtectedReadbackOwnerV1 {
    journal: Journal,
    pinned: Vec<(Vec<u8>, Vec<u8>)>,
    clock: FixedLiveAuthorityClockV1,
}

/// Seals one exact current physical readback for terminal settlement.
pub(crate) struct CurrentGitSanitizedForkReadbackV1<'current> {
    project: ProjectId,
    repository: ResourceId,
    operation: ResourceId,
    intention: ObjectDigest,
    backend_receipt: Option<ObjectDigest>,
    present: bool,
    readback_receipt: ObjectDigest,
    _current: std::marker::PhantomData<&'current mut ()>,
}

impl CurrentGitSanitizedForkReadbackV1<'_> {
    pub(crate) fn matches(
        &self,
        project: ProjectId,
        repository: ResourceId,
        operation: ResourceId,
        intention: ObjectDigest,
        backend_receipt: Option<ObjectDigest>,
    ) -> bool {
        self.project == project
            && self.repository == repository
            && self.operation == operation
            && self.intention == intention
            && self.backend_receipt == backend_receipt
    }

    pub(crate) const fn present(&self) -> bool {
        self.present
    }

    pub(crate) const fn receipt(&self) -> ObjectDigest {
        self.readback_receipt
    }
}

impl GitSanitizedForkProtectedReadbackOwnerV1 {
    /// Opens and pins the fixed protected physical-readback journal.
    ///
    /// # Errors
    ///
    /// Returns [`GitSanitizedForkReadbackErrorV1`] for foreign records,
    /// unavailable fixed clock evidence, or protected journal failure.
    pub fn open_fixed_protected() -> Result<(Self, RecoveryReport), GitSanitizedForkReadbackErrorV1>
    {
        let mut clock = fixed_live_authority_clock_v1();
        let before = clock
            .sample()
            .map_err(|_| GitSanitizedForkReadbackErrorV1::InvalidEvidence)?;
        let (mut journal, report) = Journal::open_protected_at(
            Path::new(SANITIZED_READBACK_ROOT),
            SANITIZED_READBACK_JOURNAL,
            sanitized_readback_limits(),
        )?;
        let pinned = read_sanitized_readbacks(&mut journal)?;
        if pinned
            .iter()
            .any(|(key, _)| !key.starts_with(SANITIZED_READBACK_PREFIX))
        {
            return Err(GitSanitizedForkReadbackErrorV1::InvalidEvidence);
        }
        let after = clock
            .sample()
            .map_err(|_| GitSanitizedForkReadbackErrorV1::InvalidEvidence)?;
        crate::environment::validate_bracketed_samples_v1(before, after)
            .map_err(|_| GitSanitizedForkReadbackErrorV1::InvalidEvidence)?;
        Ok((
            Self {
                journal,
                pinned,
                clock,
            },
            report,
        ))
    }

    pub(crate) fn claim<'current>(
        &'current mut self,
        project: ProjectId,
        repository: ResourceId,
        operation: ResourceId,
        intention: ObjectDigest,
        backend_receipt: Option<ObjectDigest>,
    ) -> Result<CurrentGitSanitizedForkReadbackV1<'current>, GitSanitizedForkReadbackErrorV1> {
        let before = self
            .clock
            .sample()
            .map_err(|_| GitSanitizedForkReadbackErrorV1::InvalidEvidence)?;
        let current = read_sanitized_readbacks(&mut self.journal)?;
        if current != self.pinned {
            return Err(GitSanitizedForkReadbackErrorV1::InvalidEvidence);
        }
        let mut key = Vec::with_capacity(SANITIZED_READBACK_PREFIX.len() + 16);
        key.extend_from_slice(SANITIZED_READBACK_PREFIX);
        key.extend_from_slice(operation.as_bytes());
        let mut candidates = current
            .iter()
            .filter(|(candidate, _)| candidate == &key)
            .map(|(_, bytes)| decode_sanitized_readback(bytes));
        let readback = candidates
            .next()
            .ok_or(GitSanitizedForkReadbackErrorV1::InvalidEvidence)??;
        if candidates.next().is_some()
            || readback.project != project
            || readback.repository != repository
            || readback.operation != operation
            || readback.intention != intention
            || readback.backend_receipt != backend_receipt
        {
            return Err(GitSanitizedForkReadbackErrorV1::InvalidEvidence);
        }
        let after = self
            .clock
            .sample()
            .map_err(|_| GitSanitizedForkReadbackErrorV1::InvalidEvidence)?;
        let live = crate::environment::validate_bracketed_samples_v1(before, after)
            .map_err(|_| GitSanitizedForkReadbackErrorV1::InvalidEvidence)?;
        if live.boot() != readback.boot
            || live.boottime_nanoseconds() < readback.observed_at
            || live.boottime_nanoseconds() >= readback.valid_until
        {
            return Err(GitSanitizedForkReadbackErrorV1::InvalidEvidence);
        }
        Ok(CurrentGitSanitizedForkReadbackV1 {
            project,
            repository,
            operation,
            intention,
            backend_receipt,
            present: readback.present,
            readback_receipt: readback.readback_receipt,
            _current: std::marker::PhantomData,
        })
    }
}

struct DecodedSanitizedReadbackV1 {
    project: ProjectId,
    repository: ResourceId,
    operation: ResourceId,
    intention: ObjectDigest,
    backend_receipt: Option<ObjectDigest>,
    boot: ObjectDigest,
    observed_at: u64,
    valid_until: u64,
    present: bool,
    readback_receipt: ObjectDigest,
}

fn decode_sanitized_readback(
    bytes: &[u8],
) -> Result<DecodedSanitizedReadbackV1, GitSanitizedForkReadbackErrorV1> {
    if bytes.len() != 240 {
        return Err(GitSanitizedForkReadbackErrorV1::InvalidEvidence);
    }
    let (body, stored) = bytes.split_at(208);
    let digest = Sha256::new()
        .chain_update(b"aos.sandbox.git.sanitized-fork-readback.v1\0")
        .chain_update(body)
        .finalize();
    if stored != digest.as_slice()
        || &body[..8] != b"AOSGSR01"
        || body[8] != 1
        || !matches!(body[9], 1 | 2)
        || body[10..16] != [0; 6]
    {
        return Err(GitSanitizedForkReadbackErrorV1::InvalidEvidence);
    }
    let backend = ObjectDigest::from_bytes(readback_array(&body[96..128])?);
    let decoded = DecodedSanitizedReadbackV1 {
        project: ProjectId::from_bytes(readback_array(&body[16..32])?),
        repository: ResourceId::from_bytes(readback_array(&body[32..48])?),
        operation: ResourceId::from_bytes(readback_array(&body[48..64])?),
        intention: ObjectDigest::from_bytes(readback_array(&body[64..96])?),
        backend_receipt: (backend.as_bytes() != &[0; 32]).then_some(backend),
        boot: ObjectDigest::from_bytes(readback_array(&body[128..160])?),
        observed_at: u64::from_be_bytes(readback_array(&body[160..168])?),
        valid_until: u64::from_be_bytes(readback_array(&body[168..176])?),
        present: body[9] == 1,
        readback_receipt: ObjectDigest::from_bytes(readback_array(&body[176..208])?),
    };
    if decoded.project.as_bytes() == &[0; 16]
        || decoded.repository.as_bytes() == &[0; 16]
        || decoded.operation.as_bytes() == &[0; 16]
        || decoded.intention.as_bytes() == &[0; 32]
        || decoded.boot.as_bytes() == &[0; 32]
        || decoded.observed_at == 0
        || decoded.valid_until <= decoded.observed_at
        || decoded.valid_until == u64::MAX
        || decoded.readback_receipt.as_bytes() == &[0; 32]
    {
        return Err(GitSanitizedForkReadbackErrorV1::InvalidEvidence);
    }
    Ok(decoded)
}

fn read_sanitized_readbacks(
    journal: &mut Journal,
) -> Result<Vec<(Vec<u8>, Vec<u8>)>, JournalError> {
    let authority = journal.claim_protected_authority(RecordNamespace::RuntimeAuthority)?;
    Ok(authority
        .records()?
        .map(|(key, value)| (key.to_vec(), value.to_vec()))
        .collect())
}

fn sanitized_readback_limits() -> JournalLimits {
    JournalLimits {
        maximum_journal_bytes: 256 * 1024 * 1024,
        maximum_record_bytes: 1024,
        maximum_key_bytes: 96,
        maximum_records_per_transaction: 1,
        maximum_transaction_bytes: 2048,
        maximum_transactions: 262_144,
        maximum_materialized_bytes: 128 * 1024 * 1024,
        maximum_materialized_records: 262_144,
    }
}

fn readback_array<const N: usize>(
    bytes: &[u8],
) -> Result<[u8; N], GitSanitizedForkReadbackErrorV1> {
    bytes
        .try_into()
        .map_err(|_| GitSanitizedForkReadbackErrorV1::InvalidEvidence)
}

/// Presents one exact standard Git exchange to an injected protocol-v2 backend.
pub struct ProtectedGitSmartInvocationV1<'handoff> {
    state: &'handoff GitSmartDispatchStateV1,
    fence: GitSmartAuthorityFenceV1,
    transaction: ObjectDigest,
}

impl ProtectedGitSmartInvocationV1<'_> {
    /// Borrows the exact request and protocol-v2 exchange plan.
    #[must_use]
    pub const fn state(&self) -> &GitSmartDispatchStateV1 {
        self.state
    }

    /// Returns the boot-scoped authenticated-session fence.
    #[must_use]
    pub const fn authority_fence(&self) -> GitSmartAuthorityFenceV1 {
        self.fence
    }

    /// Returns the committed pre-effect transaction.
    #[must_use]
    pub const fn transaction_commitment(&self) -> ObjectDigest {
        self.transaction
    }
}

/// Defines a constructible standard Git protocol-v2 physical backend.
pub trait GitSmartProtocolV2BackendV1 {
    /// Backend diagnostic retained only with outcome-unknown state.
    type Error;

    /// Starts one upload-pack or receive-pack exchange selected by the plan.
    ///
    /// # Errors
    ///
    /// Returns a backend diagnostic only while the exchange remains
    /// outcome-unknown and requires protected observation.
    fn apply(&mut self, invocation: ProtectedGitSmartInvocationV1<'_>) -> Result<(), Self::Error>;
}

/// Identifies why a Git smart effect remains outcome-unknown.
#[derive(Debug)]
pub enum ProtectedGitSmartEffectErrorV1<E> {
    /// Live boot-clock sampling failed.
    Clock,
    /// The session expired, the boot changed, or monotonic time regressed.
    AuthorityFence,
    /// The backend returned without a protected terminal observation.
    Backend(E),
}

/// Adapts an injected protocol-v2 backend to the protected smart-effect seam.
pub struct ProtectedGitSmartEffectAdapterV1<B> {
    backend: B,
    clock: FixedLiveAuthorityClockV1,
}

impl<B> ProtectedGitSmartEffectAdapterV1<B> {
    /// Constructs a dormant adapter without registering a route or capability.
    #[must_use]
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            clock: fixed_live_authority_clock_v1(),
        }
    }

    /// Returns the injected components without applying an effect.
    #[must_use]
    pub fn into_backend(self) -> B {
        self.backend
    }
}

impl<B> DormantGitSmartEffectV1 for ProtectedGitSmartEffectAdapterV1<B>
where
    B: GitSmartProtocolV2BackendV1,
{
    type Error = ProtectedGitSmartEffectErrorV1<B::Error>;

    fn apply(
        &mut self,
        handoff: GitSmartEffectHandoffV1<'_>,
    ) -> Result<GitSmartEffectOutcomeV1<Self::Error>, GitSmartTransportErrorV1> {
        let before = match self.clock.sample() {
            Ok(sample) => sample,
            Err(_) => {
                return GitSmartEffectOutcomeV1::outcome_unknown(
                    handoff,
                    ProtectedGitSmartEffectErrorV1::Clock,
                );
            }
        };
        if !handoff.authority_fence().admits(before) {
            return GitSmartEffectOutcomeV1::outcome_unknown(
                handoff,
                ProtectedGitSmartEffectErrorV1::AuthorityFence,
            );
        }

        let invocation = ProtectedGitSmartInvocationV1 {
            state: handoff.state(),
            fence: handoff.authority_fence(),
            transaction: handoff.transaction_commitment(),
        };
        let backend = self.backend.apply(invocation);
        let after = self.clock.sample();
        match (backend, after) {
            (Ok(()), Ok(sample))
                if sample.boot() == before.boot()
                    && sample.boottime_nanoseconds() >= before.boottime_nanoseconds()
                    && handoff.authority_fence().admits(sample) =>
            {
                GitSmartEffectOutcomeV1::observation_required(handoff)
            }
            (Err(error), _) => GitSmartEffectOutcomeV1::outcome_unknown(
                handoff,
                ProtectedGitSmartEffectErrorV1::Backend(error),
            ),
            (Ok(()), Err(_)) => GitSmartEffectOutcomeV1::outcome_unknown(
                handoff,
                ProtectedGitSmartEffectErrorV1::Clock,
            ),
            (Ok(()), Ok(_)) => GitSmartEffectOutcomeV1::outcome_unknown(
                handoff,
                ProtectedGitSmartEffectErrorV1::AuthorityFence,
            ),
        }
    }
}

/// Binds the only physical endpoint and confinement policy admitted by one effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GitSanitizedForkConfigurationV1 {
    endpoint: ResourceId,
    confinement_policy: ObjectDigest,
    maximum_pack_bytes: u64,
}

impl GitSanitizedForkConfigurationV1 {
    /// Constructs a path-free physical configuration commitment.
    ///
    /// # Errors
    ///
    /// Returns [`GitSmartTransportErrorV1::InvalidRequest`] for sentinel fields.
    pub fn new(
        endpoint: ResourceId,
        confinement_policy: ObjectDigest,
        maximum_pack_bytes: u64,
    ) -> Result<Self, GitSmartTransportErrorV1> {
        if endpoint.as_bytes() == &[0; 16]
            || confinement_policy.as_bytes() == &[0; 32]
            || maximum_pack_bytes == 0
            || maximum_pack_bytes == u64::MAX
        {
            return Err(GitSmartTransportErrorV1::InvalidRequest);
        }
        Ok(Self {
            endpoint,
            confinement_policy,
            maximum_pack_bytes,
        })
    }

    /// Returns the logical endpoint; no host path is accepted by this model.
    #[must_use]
    pub const fn endpoint(self) -> ResourceId {
        self.endpoint
    }

    /// Returns the comprehensive writer/key/MAC confinement commitment.
    #[must_use]
    pub const fn confinement_policy(self) -> ObjectDigest {
        self.confinement_policy
    }

    /// Returns the physical byte ceiling.
    #[must_use]
    pub const fn maximum_pack_bytes(self) -> u64 {
        self.maximum_pack_bytes
    }

    /// Commits every physical configuration field.
    #[must_use]
    pub fn commitment(self) -> ObjectDigest {
        ObjectDigest::from_bytes(
            Sha256::new()
                .chain_update(b"aos.sandbox.git.sanitized-fork-configuration.v1\0")
                .chain_update(self.endpoint.as_bytes())
                .chain_update(self.confinement_policy.as_bytes())
                .chain_update(self.maximum_pack_bytes.to_be_bytes())
                .finalize()
                .into(),
        )
    }
}

/// Names the durable phase of one exact sanitized-pack/fork intention.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum GitSanitizedForkJournalPhaseV1 {
    Prepared = 1,
    Completed = 2,
    Rejected = 3,
}

/// Is the canonical protected pre-effect or terminal physical intention record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct GitSanitizedForkJournalRecordV1 {
    project: ProjectId,
    repository: ResourceId,
    operation: ResourceId,
    intention: ObjectDigest,
    phase: GitSanitizedForkJournalPhaseV1,
    backend_receipt: Option<ObjectDigest>,
    receipt: Option<ObjectDigest>,
}

impl GitSanitizedForkJournalRecordV1 {
    pub(crate) fn prepared(
        operation: ResourceId,
        pack: &ImmutablePackGenerationV1,
        fork: &GitCheapForkV1,
        configuration: GitSanitizedForkConfigurationV1,
    ) -> Result<Self, GitSmartTransportErrorV1> {
        if operation.as_bytes() == &[0; 16] {
            return Err(GitSmartTransportErrorV1::InvalidRequest);
        }
        Ok(Self {
            project: pack.project(),
            repository: pack.repository(),
            operation,
            intention: sanitized_fork_intention(pack, fork, configuration)?,
            phase: GitSanitizedForkJournalPhaseV1::Prepared,
            backend_receipt: None,
            receipt: None,
        })
    }

    pub(crate) fn terminal(
        prepared: Self,
        accepted: bool,
        backend_receipt: Option<ObjectDigest>,
        receipt: ObjectDigest,
    ) -> Result<Self, GitSmartTransportErrorV1> {
        if !matches!(
            prepared.phase,
            GitSanitizedForkJournalPhaseV1::Prepared | GitSanitizedForkJournalPhaseV1::Rejected
        ) || receipt.as_bytes() == &[0; 32]
            || backend_receipt.is_some_and(|value| value.as_bytes() == &[0; 32])
        {
            return Err(GitSmartTransportErrorV1::InvalidRequest);
        }
        Ok(Self {
            phase: if accepted {
                GitSanitizedForkJournalPhaseV1::Completed
            } else {
                GitSanitizedForkJournalPhaseV1::Rejected
            },
            backend_receipt,
            receipt: Some(receipt),
            ..prepared
        })
    }

    pub(crate) const fn project(self) -> ProjectId {
        self.project
    }

    pub(crate) const fn repository(self) -> ResourceId {
        self.repository
    }

    pub(crate) const fn operation(self) -> ResourceId {
        self.operation
    }

    pub(crate) const fn intention(self) -> ObjectDigest {
        self.intention
    }

    pub(crate) const fn phase(self) -> GitSanitizedForkJournalPhaseV1 {
        self.phase
    }

    pub(crate) const fn receipt(self) -> Option<ObjectDigest> {
        self.receipt
    }

    pub(crate) const fn backend_receipt(self) -> Option<ObjectDigest> {
        self.backend_receipt
    }
}

pub(crate) fn encode_sanitized_fork_journal_record_v1(
    record: GitSanitizedForkJournalRecordV1,
) -> Vec<u8> {
    let mut body = Vec::with_capacity(160);
    body.extend_from_slice(b"AOSGSF01");
    body.push(1);
    body.push(record.phase as u8);
    body.extend_from_slice(&[0; 6]);
    body.extend_from_slice(record.project.as_bytes());
    body.extend_from_slice(record.repository.as_bytes());
    body.extend_from_slice(record.operation.as_bytes());
    body.extend_from_slice(record.intention.as_bytes());
    body.extend_from_slice(
        record
            .backend_receipt
            .unwrap_or_else(|| ObjectDigest::from_bytes([0; 32]))
            .as_bytes(),
    );
    body.extend_from_slice(
        record
            .receipt
            .unwrap_or_else(|| ObjectDigest::from_bytes([0; 32]))
            .as_bytes(),
    );
    let digest = Sha256::new()
        .chain_update(b"aos.sandbox.git.sanitized-fork-journal.v1\0")
        .chain_update(&body)
        .finalize();
    body.extend_from_slice(&digest);
    body
}

pub(crate) fn decode_sanitized_fork_journal_record_v1(
    bytes: &[u8],
) -> Result<GitSanitizedForkJournalRecordV1, GitSmartTransportErrorV1> {
    if bytes.len() != 192 {
        return Err(GitSmartTransportErrorV1::InvalidRequest);
    }
    let (body, stored) = bytes.split_at(160);
    let digest = Sha256::new()
        .chain_update(b"aos.sandbox.git.sanitized-fork-journal.v1\0")
        .chain_update(body)
        .finalize();
    if stored != digest.as_slice()
        || &body[..8] != b"AOSGSF01"
        || body[8] != 1
        || body[10..16] != [0; 6]
    {
        return Err(GitSmartTransportErrorV1::InvalidRequest);
    }
    let phase = match body[9] {
        1 => GitSanitizedForkJournalPhaseV1::Prepared,
        2 => GitSanitizedForkJournalPhaseV1::Completed,
        3 => GitSanitizedForkJournalPhaseV1::Rejected,
        _ => return Err(GitSmartTransportErrorV1::InvalidRequest),
    };
    let backend_receipt = ObjectDigest::from_bytes(array(&body[96..128])?);
    let receipt = ObjectDigest::from_bytes(array(&body[128..160])?);
    if (phase == GitSanitizedForkJournalPhaseV1::Prepared) != (receipt.as_bytes() == &[0; 32])
        || (phase == GitSanitizedForkJournalPhaseV1::Prepared
            && backend_receipt.as_bytes() != &[0; 32])
    {
        return Err(GitSmartTransportErrorV1::InvalidRequest);
    }
    let record = GitSanitizedForkJournalRecordV1 {
        project: ProjectId::from_bytes(array(&body[16..32])?),
        repository: ResourceId::from_bytes(array(&body[32..48])?),
        operation: ResourceId::from_bytes(array(&body[48..64])?),
        intention: ObjectDigest::from_bytes(array(&body[64..96])?),
        phase,
        backend_receipt: (backend_receipt.as_bytes() != &[0; 32]).then_some(backend_receipt),
        receipt: (receipt.as_bytes() != &[0; 32]).then_some(receipt),
    };
    if record.project.as_bytes() == &[0; 16]
        || record.repository.as_bytes() == &[0; 16]
        || record.operation.as_bytes() == &[0; 16]
        || record.intention.as_bytes() == &[0; 32]
        || encode_sanitized_fork_journal_record_v1(record) != bytes
    {
        return Err(GitSmartTransportErrorV1::InvalidRequest);
    }
    Ok(record)
}

/// Seals protected durable pre-effect authority and its exact intention.
pub(crate) struct GitSanitizedForkDurableAuthorityV1<'current> {
    postcommit: super::protected_journal::ValidatedGitPostcommitV1<'current>,
    predecessor: GitSanitizedForkJournalRecordV1,
    predecessor_digest: ObjectDigest,
    predecessor_transaction: [u8; 16],
}

impl<'current> GitSanitizedForkDurableAuthorityV1<'current> {
    pub(crate) fn new(
        postcommit: super::protected_journal::ValidatedGitPostcommitV1<'current>,
        predecessor: GitSanitizedForkJournalRecordV1,
        predecessor_digest: ObjectDigest,
        predecessor_transaction: [u8; 16],
    ) -> Self {
        Self {
            postcommit,
            predecessor,
            predecessor_digest,
            predecessor_transaction,
        }
    }
}

/// Carries one non-replayable exact protected physical-effect handoff.
#[must_use]
pub struct GitSanitizedForkEffectHandoffV1<'current> {
    operation: ResourceId,
    pack: ImmutablePackGenerationV1,
    fork: GitCheapForkV1,
    configuration: GitSanitizedForkConfigurationV1,
    authority: GitSanitizedForkDurableAuthorityV1<'current>,
}

/// Reports durable preparation of one sanitized-pack physical effect.
#[must_use]
pub enum GitSanitizedForkPrepareOutcomeV1<'current> {
    /// Exact durable readback minted the sole physical handoff.
    Prepared(GitSanitizedForkEffectHandoffV1<'current>),
    /// Commit durability is unknown and no physical handoff exists.
    OutcomeUnknown(GitSanitizedForkPrepareUnknownV1),
    /// Commit preflight failed without consuming the exact prepared transaction.
    RetryableError {
        /// Sole exact transaction retry and bound inputs.
        retry: GitSanitizedForkPrepareRetryV1,
        /// Fail-closed diagnostic.
        error: GitSmartTransportErrorV1,
    },
    /// Durable application is known but handoff reconstruction requires cold reopen.
    ReopenRequired {
        /// Opaque one-shot custody issued only after durable ambiguity.
        custody: GitSanitizedForkPrepareReopenV1,
        /// Fail-closed diagnostic.
        error: GitSmartTransportErrorV1,
    },
}

/// Retains one opaque, non-cloneable preparation reopen capability.
#[must_use]
pub struct GitSanitizedForkPrepareReopenV1 {
    pub(crate) operation: ResourceId,
    pub(crate) pack: ImmutablePackGenerationV1,
    pub(crate) fork: GitCheapForkV1,
    pub(crate) configuration: GitSanitizedForkConfigurationV1,
}

/// Retains ambiguous preparation plus every exact input needed for cold replay.
#[must_use]
pub struct GitSanitizedForkPrepareUnknownV1 {
    pub(crate) pending: super::protected_journal::GitJournalOutcomeUnknownV1,
    pub(crate) operation: ResourceId,
    pub(crate) pack: ImmutablePackGenerationV1,
    pub(crate) fork: GitCheapForkV1,
    pub(crate) configuration: GitSanitizedForkConfigurationV1,
}

/// Retains the sole exact retry returned by ambiguous preparation readback.
#[must_use]
pub struct GitSanitizedForkPrepareRetryV1 {
    pub(crate) prepared: super::protected_journal::PreparedGitJournalTransactionV1,
    pub(crate) operation: ResourceId,
    pub(crate) pack: ImmutablePackGenerationV1,
    pub(crate) fork: GitCheapForkV1,
    pub(crate) configuration: GitSanitizedForkConfigurationV1,
}

/// Classifies cold exact readback of an ambiguous durable intention commit.
#[must_use]
pub enum GitSanitizedForkPrepareRecoveryV1<'current> {
    /// The exact durable intention was present and yielded its sole handoff.
    Prepared(GitSanitizedForkEffectHandoffV1<'current>),
    /// All exact predecessors survived and permit only this retained retry.
    Retry(GitSanitizedForkPrepareRetryV1),
    /// State was mixed or substituted and retains the exact pending custody.
    Diverged(GitSanitizedForkPrepareUnknownV1),
    /// Transient validation failed before consuming the exact pending token.
    RetryableError {
        /// Exact ambiguous preparation remains available for cold retry.
        custody: GitSanitizedForkPrepareUnknownV1,
        /// Fail-closed diagnostic.
        error: GitSmartTransportErrorV1,
    },
    /// Durable application is known but current handoff reconstruction must reopen.
    ReopenRequired {
        /// Opaque one-shot custody issued only after durable ambiguity.
        custody: GitSanitizedForkPrepareReopenV1,
        /// Fail-closed diagnostic.
        error: GitSmartTransportErrorV1,
    },
}

impl<'current> GitSanitizedForkEffectHandoffV1<'current> {
    /// Constructs from authority whose exact intention was already decoded and checked.
    pub(crate) fn from_validated(
        operation: ResourceId,
        pack: ImmutablePackGenerationV1,
        fork: GitCheapForkV1,
        configuration: GitSanitizedForkConfigurationV1,
        authority: GitSanitizedForkDurableAuthorityV1<'current>,
    ) -> Self {
        Self {
            operation,
            pack,
            fork,
            configuration,
            authority,
        }
    }
}

/// Binds a complete sanitized pack, active lease, target fork, and configuration.
pub struct GitSanitizedForkPhysicalPlanV1<'record> {
    pack: &'record ImmutablePackGenerationV1,
    fork: &'record GitCheapForkV1,
    configuration: GitSanitizedForkConfigurationV1,
    durable_transaction: ObjectDigest,
}

impl<'record> GitSanitizedForkPhysicalPlanV1<'record> {
    /// Constructs one nonauthorizing physical-effect plan.
    ///
    /// # Errors
    ///
    /// Returns [`GitSmartTransportErrorV1::InvalidRequest`] unless the pack,
    /// audience-bound fork, and current live lease reproduce one another.
    fn from_handoff(
        handoff: &'record GitSanitizedForkEffectHandoffV1<'_>,
        live: crate::environment::LiveAuthorityClockSampleV1,
    ) -> Result<Self, GitSmartTransportErrorV1> {
        let pack = &handoff.pack;
        let fork = &handoff.fork;
        let lease = fork.lease();
        if fork.status() != GitCheapForkStatusV1::Attached
            || fork.pack() != pack.generation_digest()
            || lease.generation_digest() != pack.generation_digest()
            || lease.pack_generation() != pack.pack_generation()
            || lease.project() != pack.project()
            || lease.repository() != pack.repository()
            || lease.export() != pack.export()
            || lease.export_generation() != pack.export_generation()
            || lease.export_digest() != pack.export_digest()
            || lease.status() != GitPackLeaseStatusV1::Active
            || lease.boot().digest() != live.boot()
            || lease.observed_at().get() > live.boottime_nanoseconds()
            || lease.expires_at() <= live.boottime_nanoseconds()
        {
            return Err(GitSmartTransportErrorV1::InvalidRequest);
        }
        let pack_bytes = super::encode_pack_generation_v1(pack)
            .map_err(|_| GitSmartTransportErrorV1::InvalidRequest)?;
        if u64::try_from(pack_bytes.len()).map_err(|_| GitSmartTransportErrorV1::InvalidRequest)?
            > handoff.configuration.maximum_pack_bytes()
        {
            return Err(GitSmartTransportErrorV1::InvalidRequest);
        }
        if sanitized_fork_intention(pack, fork, handoff.configuration)?
            != handoff.authority.predecessor.intention()
        {
            return Err(GitSmartTransportErrorV1::InvalidRequest);
        }
        Ok(Self {
            pack,
            fork,
            configuration: handoff.configuration,
            durable_transaction: handoff.authority.postcommit.transaction_digest(),
        })
    }

    /// Borrows the complete immutable pack generation.
    #[must_use]
    pub const fn pack(&self) -> &ImmutablePackGenerationV1 {
        self.pack
    }

    /// Borrows the target fork and its exact active lease.
    #[must_use]
    pub const fn fork(&self) -> &GitCheapForkV1 {
        self.fork
    }

    /// Returns the exact protected endpoint and confinement configuration.
    #[must_use]
    pub const fn configuration(&self) -> GitSanitizedForkConfigurationV1 {
        self.configuration
    }

    /// Returns the protected durable pre-effect transaction commitment.
    #[must_use]
    pub const fn durable_transaction(&self) -> ObjectDigest {
        self.durable_transaction
    }
}

/// Defines the physical immutable-pack publication and alternate attachment seam.
pub trait DormantSanitizedGitForkPhysicalEffectV1 {
    /// Backend error; callers must retain the pack lease on every error.
    type Error;

    /// Publishes and attaches one exact audience-private immutable generation.
    ///
    /// # Errors
    ///
    /// Returns a backend diagnostic while the caller retains the active pack
    /// lease and treats physical publication or attachment as indeterminate.
    fn apply(
        &mut self,
        plan: &GitSanitizedForkPhysicalPlanV1<'_>,
    ) -> Result<ObjectDigest, Self::Error>;
}

/// Reports fail-closed physical sanitized-fork effect failure.
#[derive(Debug)]
pub enum GitSanitizedForkPhysicalEffectErrorV1<E> {
    /// Live boot-clock evidence was unavailable or changed around the effect.
    Clock,
    /// The pack lease was not current under the live boot-time sample.
    LeaseFence,
    /// The backend returned a sentinel instead of a seal/attach receipt.
    InvalidReceipt,
    /// The physical effect returned a diagnostic with unknown durable outcome.
    Backend(E),
}

/// Retains exact inputs and durable custody while physical outcome is resolved.
#[must_use]
pub struct GitSanitizedForkRecoveryTokenV1 {
    operation: ResourceId,
    pack: ImmutablePackGenerationV1,
    fork: GitCheapForkV1,
    configuration: GitSanitizedForkConfigurationV1,
    intention: ObjectDigest,
    backend_receipt: Option<ObjectDigest>,
    predecessor: GitSanitizedForkJournalRecordV1,
    predecessor_digest: ObjectDigest,
    predecessor_transaction: [u8; 16],
}

impl GitSanitizedForkRecoveryTokenV1 {
    pub(crate) const fn operation(&self) -> ResourceId {
        self.operation
    }

    pub(crate) const fn intention(&self) -> ObjectDigest {
        self.intention
    }

    pub(crate) const fn predecessor(&self) -> GitSanitizedForkJournalRecordV1 {
        self.predecessor
    }

    pub(crate) const fn predecessor_digest(&self) -> ObjectDigest {
        self.predecessor_digest
    }

    pub(crate) const fn predecessor_transaction(&self) -> [u8; 16] {
        self.predecessor_transaction
    }
    /// Borrows the exact pack required for protected cold readback.
    #[must_use]
    pub const fn pack(&self) -> &ImmutablePackGenerationV1 {
        &self.pack
    }

    /// Borrows the exact fork required for protected cold readback.
    #[must_use]
    pub const fn fork(&self) -> &GitCheapForkV1 {
        &self.fork
    }

    /// Returns the exact physical configuration commitment.
    #[must_use]
    pub const fn configuration(&self) -> GitSanitizedForkConfigurationV1 {
        self.configuration
    }

    /// Returns an untrusted backend receipt retained only for readback matching.
    #[must_use]
    pub const fn backend_receipt(&self) -> Option<ObjectDigest> {
        self.backend_receipt
    }
}

/// Is the sole replayable value produced by exact protected cold readback.
#[must_use]
pub struct GitSanitizedForkExactRetryV1<'current> {
    handoff: GitSanitizedForkEffectHandoffV1<'current>,
}

impl<'current> GitSanitizedForkExactRetryV1<'current> {
    pub(crate) fn from_validated(
        operation: ResourceId,
        pack: ImmutablePackGenerationV1,
        fork: GitCheapForkV1,
        configuration: GitSanitizedForkConfigurationV1,
        authority: GitSanitizedForkDurableAuthorityV1<'current>,
    ) -> Self {
        Self {
            handoff: GitSanitizedForkEffectHandoffV1::from_validated(
                operation,
                pack,
                fork,
                configuration,
                authority,
            ),
        }
    }
}

/// Classifies exact protected cold readback of an outcome-unknown effect.
#[must_use]
pub enum GitSanitizedForkRecoveryV1<'current> {
    /// A protected terminal receipt proves that retry is forbidden.
    Observed(ObjectDigest),
    /// Fresh protected authority admits one exact retry of unchanged inputs.
    ExactRetry(GitSanitizedForkExactRetryV1<'current>),
    /// Readback did not reproduce the exact intention; custody remains held.
    Diverged(GitSanitizedForkRecoveryTokenV1),
    /// Transient protected validation failed while exact custody was retained.
    RetryableError {
        /// Exact physical inputs remain available for cold reopen.
        recovery: GitSanitizedForkRecoveryTokenV1,
        /// Fail-closed diagnostic.
        error: GitSmartTransportErrorV1,
    },
    /// Terminal replacement durability remains unknown with exact custody.
    SettlementOutcomeUnknown(GitSanitizedForkSettlementUnknownV1),
    /// Terminal settlement may be retried only through the retained token.
    SettlementRetryable {
        /// Sole exact settlement retry.
        retry: GitSanitizedForkSettlementRetryV1,
        /// Fail-closed diagnostic.
        error: GitSmartTransportErrorV1,
    },
}

/// Reports durable terminal replacement after protected physical readback.
#[must_use]
pub enum GitSanitizedForkSettlementOutcomeV1<'current> {
    /// Protected readback proves the exact physical state is present.
    Observed {
        /// Protected readback receipt.
        receipt: ObjectDigest,
    },
    /// Protected absence and terminal replacement permit one exact retry.
    ExactRetry(GitSanitizedForkExactRetryV1<'current>),
    /// Terminal replacement durability is unknown and custody is retained.
    OutcomeUnknown {
        /// Exact terminal transaction and physical input custody.
        custody: GitSanitizedForkSettlementUnknownV1,
    },
    /// A retryable validation or journal failure retained exact custody.
    RetryableError {
        /// Sole retry path, including whether terminal planning already occurred.
        retry: GitSanitizedForkSettlementRetryV1,
        /// Fail-closed diagnostic.
        error: GitSmartTransportErrorV1,
    },
}

/// Retains the sole valid settlement retry and physical custody.
#[must_use]
pub struct GitSanitizedForkSettlementRetryV1 {
    pub(crate) recovery: GitSanitizedForkRecoveryTokenV1,
    pub(crate) pending: GitSanitizedForkSettlementRetryKindV1,
}

pub(crate) enum GitSanitizedForkSettlementRetryKindV1 {
    Revalidate,
    Terminal {
        prepared: super::protected_journal::PreparedGitJournalTransactionV1,
        terminal: GitSanitizedForkJournalRecordV1,
    },
}

/// Retains an ambiguous terminal replacement and exact physical input custody.
#[must_use]
pub struct GitSanitizedForkSettlementUnknownV1 {
    pub(crate) recovery: GitSanitizedForkRecoveryTokenV1,
    pub(crate) pending: GitSanitizedForkTerminalPendingV1,
    pub(crate) terminal: GitSanitizedForkJournalRecordV1,
}

/// Retains either ambiguous terminal durability or its sole exact retry.
#[must_use]
pub(crate) enum GitSanitizedForkTerminalPendingV1 {
    OutcomeUnknown(super::protected_journal::GitJournalOutcomeUnknownV1),
    Retry(super::protected_journal::PreparedGitJournalTransactionV1),
    Reopen,
}

/// Classifies cold recovery of an ambiguous terminal replacement.
#[must_use]
pub enum GitSanitizedForkSettlementRecoveryV1<'current> {
    /// Current protected readback proves the exact physical effect is present.
    Observed(ObjectDigest),
    /// Current protected absence permits one exact physical retry.
    ExactRetry(GitSanitizedForkExactRetryV1<'current>),
    /// Another terminal durability ambiguity retains both opaque tokens.
    OutcomeUnknown(GitSanitizedForkSettlementUnknownV1),
    /// Terminal retry preflight failed while both custody tokens were retained.
    RetryableError {
        /// Sole exact terminal replacement retry.
        retry: GitSanitizedForkSettlementRetryV1,
        /// Fail-closed diagnostic.
        error: GitSmartTransportErrorV1,
    },
    /// Substituted or mixed state retains journal and physical custody.
    Diverged(GitSanitizedForkSettlementUnknownV1),
}

/// Reports the post-dispatch state without making the original inputs replayable.
#[must_use]
pub enum GitSanitizedForkEffectOutcomeV1<E> {
    /// Dispatch returned; protected cold observation is still mandatory.
    ObservationRequired {
        /// Exact input custody and the untrusted backend receipt.
        recovery: GitSanitizedForkRecoveryTokenV1,
    },
    /// Dispatch or its clock bracket was ambiguous; blind retry is forbidden.
    OutcomeUnknown {
        /// Exact inputs remain held for cold reopen and readback.
        recovery: GitSanitizedForkRecoveryTokenV1,
        /// Effect-specific diagnostic.
        error: GitSanitizedForkPhysicalEffectErrorV1<E>,
    },
}

/// Holds an injected sanitized-fork backend without advertising availability.
pub struct DormantSanitizedGitForkEffectAdapterV1<B> {
    backend: B,
    clock: FixedLiveAuthorityClockV1,
}

impl<B> DormantSanitizedGitForkEffectAdapterV1<B>
where
    B: DormantSanitizedGitForkPhysicalEffectV1,
{
    /// Constructs the dormant seam; this does not qualify or advertise it.
    #[must_use]
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            clock: fixed_live_authority_clock_v1(),
        }
    }

    /// Applies one exact logical pack/fork pair through the injected backend.
    ///
    /// The adapter samples the live clock on both sides of the physical effect.
    /// It never converts success into capability advertisement; offline
    /// qualification and production wiring remain separate gates.
    ///
    pub fn apply<'current>(
        &mut self,
        handoff: GitSanitizedForkEffectHandoffV1<'current>,
    ) -> GitSanitizedForkEffectOutcomeV1<B::Error> {
        let before = match self.clock.sample() {
            Ok(sample) => sample,
            Err(_) => return unknown(handoff, None, GitSanitizedForkPhysicalEffectErrorV1::Clock),
        };
        let plan = match GitSanitizedForkPhysicalPlanV1::from_handoff(&handoff, before) {
            Ok(plan) => plan,
            Err(_) => {
                return unknown(
                    handoff,
                    None,
                    GitSanitizedForkPhysicalEffectErrorV1::LeaseFence,
                );
            }
        };
        let backend = self.backend.apply(&plan);
        // This sample is intentionally unconditional, including backend Err.
        drop(plan);
        let after = self.clock.sample();
        let receipt = match backend {
            Ok(receipt) => receipt,
            Err(error) => {
                return unknown(
                    handoff,
                    None,
                    GitSanitizedForkPhysicalEffectErrorV1::Backend(error),
                );
            }
        };
        let after = match after {
            Ok(sample) => sample,
            Err(_) => {
                return unknown(
                    handoff,
                    Some(receipt),
                    GitSanitizedForkPhysicalEffectErrorV1::Clock,
                );
            }
        };
        if after.boot() != before.boot()
            || after.boottime_nanoseconds() < before.boottime_nanoseconds()
            || GitSanitizedForkPhysicalPlanV1::from_handoff(&handoff, after).is_err()
        {
            return unknown(
                handoff,
                Some(receipt),
                GitSanitizedForkPhysicalEffectErrorV1::LeaseFence,
            );
        }
        if receipt.as_bytes() == &[0; 32] {
            return unknown(
                handoff,
                None,
                GitSanitizedForkPhysicalEffectErrorV1::InvalidReceipt,
            );
        }
        GitSanitizedForkEffectOutcomeV1::ObservationRequired {
            recovery: recovery_token(handoff, Some(receipt)),
        }
    }

    /// Applies only the exact retry minted by protected cold reopen/readback.
    pub fn apply_exact_retry<'current>(
        &mut self,
        retry: GitSanitizedForkExactRetryV1<'current>,
    ) -> GitSanitizedForkEffectOutcomeV1<B::Error> {
        self.apply(retry.handoff)
    }

    /// Returns the injected backend without applying an effect.
    #[must_use]
    pub fn into_backend(self) -> B {
        self.backend
    }
}

fn unknown<'current, E>(
    handoff: GitSanitizedForkEffectHandoffV1<'current>,
    backend_receipt: Option<ObjectDigest>,
    error: GitSanitizedForkPhysicalEffectErrorV1<E>,
) -> GitSanitizedForkEffectOutcomeV1<E> {
    GitSanitizedForkEffectOutcomeV1::OutcomeUnknown {
        recovery: recovery_token(handoff, backend_receipt),
        error,
    }
}

fn recovery_token(
    handoff: GitSanitizedForkEffectHandoffV1<'_>,
    backend_receipt: Option<ObjectDigest>,
) -> GitSanitizedForkRecoveryTokenV1 {
    GitSanitizedForkRecoveryTokenV1 {
        operation: handoff.operation,
        pack: handoff.pack,
        fork: handoff.fork,
        configuration: handoff.configuration,
        intention: handoff.authority.predecessor.intention(),
        backend_receipt,
        predecessor: handoff.authority.predecessor,
        predecessor_digest: handoff.authority.predecessor_digest,
        predecessor_transaction: handoff.authority.predecessor_transaction,
    }
}

pub(crate) fn sanitized_fork_intention(
    pack: &ImmutablePackGenerationV1,
    fork: &GitCheapForkV1,
    configuration: GitSanitizedForkConfigurationV1,
) -> Result<ObjectDigest, GitSmartTransportErrorV1> {
    let encoded_pack = super::encode_pack_generation_v1(pack)
        .map_err(|_| GitSmartTransportErrorV1::InvalidRequest)?;
    Ok(ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.git.sanitized-fork-effect-intention.v1\0")
            .chain_update((encoded_pack.len() as u64).to_be_bytes())
            .chain_update(encoded_pack)
            .chain_update(fork.complete_digest().as_bytes())
            .chain_update(configuration.commitment().as_bytes())
            .finalize()
            .into(),
    ))
}

fn array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], GitSmartTransportErrorV1> {
    bytes
        .try_into()
        .map_err(|_| GitSmartTransportErrorV1::InvalidRequest)
}
