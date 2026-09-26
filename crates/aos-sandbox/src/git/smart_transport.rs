//! Standard Git smart-transport parsing and dormant effect handoff.
//!
//! The endpoint grammar maps `git-upload-pack` and `git-receive-pack` to a
//! project/repository identity. It never accepts a host path, command option,
//! shell escape, or implementation-specific executable. Parsed requests and
//! plans remain nonauthorizing until a fixed protected Git owner has replayed
//! and lifetime-bound them.
//!
//! ```text
//! AOSGSJ01 || v1 || phase || command || plan-length || canonical-plan ||
//! attempt || observation || receipt || sha256
//! ```

use aos_proto::aos::sandbox::v1::{Feature, SemanticCapability};
use aos_sandbox_core::{ObjectDigest, PrincipalId, ProjectId, ResourceId, Revision};
use sha2::{Digest as _, Sha256};

use super::protected_journal::{
    GitJournalOutcomeUnknownV1, PreparedGitJournalTransactionV1, ValidatedGitPostcommitV1,
};
use super::{
    GitChannelBindingDigestV1, GitExchangePlanV1, GitProtocolV2ServiceV1, GitTrustedValidatorV1,
    decode_git_exchange_plan_v1, encode_git_exchange_plan_v1,
};

/// Ownership-namespaced feature used for immutable-pack fork acceleration.
pub const CHEAP_SANITIZED_GIT_FORK_FEATURE_NAMESPACE_V1: &str =
    "aos.sandbox.git.cheap-sanitized-git-fork";
/// Major version of the cheap sanitized Git fork contract.
pub const CHEAP_SANITIZED_GIT_FORK_FEATURE_MAJOR_V1: u32 = 1;
/// Minor version of the cheap sanitized Git fork contract.
pub const CHEAP_SANITIZED_GIT_FORK_FEATURE_MINOR_V1: u32 = 0;
/// Canonical source fixture committed by every advertisement of the feature.
pub const CHEAP_SANITIZED_GIT_FORK_FIXTURE_V1: &[u8] =
    b"AOSCGF01\0immutable-pack\0sanitized-audience\0lease-before-attach\0";
/// Fixed public reason used while no physical backend is qualified.
pub const CHEAP_SANITIZED_GIT_FORK_UNQUALIFIED_REASON_V1: &str =
    "source model only; physical pack, crash, disclosure, and enforcing-MAC qualification pending";
/// Maximum bytes accepted in one standard Git command line.
pub const MAXIMUM_GIT_SMART_COMMAND_BYTES: usize = 256;

/// Reports malformed smart-transport input or unavailable protected state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitSmartTransportErrorV1 {
    /// The endpoint, command, plan, or transition is invalid.
    InvalidRequest,
    /// The standard command does not address the exact endpoint.
    EndpointMismatch,
    /// Current protected Git state does not contain the plan's exact base.
    CurrentStateMismatch,
    /// Protected evidence or typed replay is unavailable.
    ProtectedEvidenceUnavailable,
}

impl std::fmt::Display for GitSmartTransportErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidRequest => "invalid Git smart-transport request",
            Self::EndpointMismatch => "Git smart-transport endpoint mismatch",
            Self::CurrentStateMismatch => "protected Git current state mismatch",
            Self::ProtectedEvidenceUnavailable => "protected Git evidence is unavailable",
        })
    }
}

impl std::error::Error for GitSmartTransportErrorV1 {}

/// Names one path-free standard Git smart-protocol endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GitSmartEndpointV1 {
    project: ProjectId,
    repository: ResourceId,
    service: GitProtocolV2ServiceV1,
}

impl GitSmartEndpointV1 {
    /// Constructs one logical endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`GitSmartTransportErrorV1::InvalidRequest`] for sentinel
    /// project or repository identities.
    pub fn new(
        project: ProjectId,
        repository: ResourceId,
        service: GitProtocolV2ServiceV1,
    ) -> Result<Self, GitSmartTransportErrorV1> {
        if project.as_bytes() == &[0; 16] || repository.as_bytes() == &[0; 16] {
            return Err(GitSmartTransportErrorV1::InvalidRequest);
        }
        Ok(Self {
            project,
            repository,
            service,
        })
    }

    /// Returns the owning project.
    #[must_use]
    pub const fn project(self) -> ProjectId {
        self.project
    }

    /// Returns the logical repository.
    #[must_use]
    pub const fn repository(self) -> ResourceId {
        self.repository
    }

    /// Returns the standard Git service.
    #[must_use]
    pub const fn service(self) -> GitProtocolV2ServiceV1 {
        self.service
    }

    /// Encodes the exact shell-free standard command accepted by the parser.
    #[must_use]
    pub fn command(self) -> Vec<u8> {
        let service = service_name(self.service);
        let mut command = Vec::with_capacity(service.len() + 75);
        command.extend_from_slice(service);
        command.extend_from_slice(b" 'aos/");
        append_hex(&mut command, self.project.as_bytes());
        command.push(b'/');
        append_hex(&mut command, self.repository.as_bytes());
        command.push(b'\'');
        command
    }
}

/// Stores one exactly parsed standard smart-transport request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GitSmartRequestV1 {
    endpoint: GitSmartEndpointV1,
    command_digest: ObjectDigest,
}

/// Carries sealed authenticated-session facts into protected dispatch.
///
/// The type has no public constructor and is not cloneable. A future
/// authenticated transport owner must issue it from peer and channel evidence;
/// the source-only controller does not currently issue one.
pub(crate) struct GitSmartSessionEvidenceV1 {
    endpoint: GitSmartEndpointV1,
    principal: PrincipalId,
    channel_binding: GitChannelBindingDigestV1,
    expires_at_unix_seconds: u64,
    maximum_input_bytes: u64,
    maximum_output_bytes: u64,
    authority_fence: GitSmartAuthorityFenceV1,
}

impl GitSmartSessionEvidenceV1 {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn from_protected(
        endpoint: GitSmartEndpointV1,
        principal: PrincipalId,
        channel_binding: GitChannelBindingDigestV1,
        expires_at_unix_seconds: u64,
        maximum_input_bytes: u64,
        maximum_output_bytes: u64,
        authority_fence: GitSmartAuthorityFenceV1,
    ) -> Result<Self, GitSmartTransportErrorV1> {
        if principal.as_bytes() == &[0; 16]
            || channel_binding.digest().as_bytes() == &[0; 32]
            || expires_at_unix_seconds == 0
            || expires_at_unix_seconds == u64::MAX
            || maximum_input_bytes == 0
            || maximum_input_bytes == u64::MAX
            || maximum_output_bytes == 0
            || maximum_output_bytes == u64::MAX
        {
            return Err(GitSmartTransportErrorV1::InvalidRequest);
        }
        Ok(Self {
            endpoint,
            principal,
            channel_binding,
            expires_at_unix_seconds,
            maximum_input_bytes,
            maximum_output_bytes,
            authority_fence,
        })
    }

    pub(super) const fn authority_fence(&self) -> GitSmartAuthorityFenceV1 {
        self.authority_fence
    }
}

/// Binds one authenticated Git session to a live boot-time interval.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GitSmartAuthorityFenceV1 {
    boot: ObjectDigest,
    valid_from_boottime_nanoseconds: u64,
    valid_until_boottime_nanoseconds: u64,
}

impl GitSmartAuthorityFenceV1 {
    pub(super) fn from_protected(
        boot: ObjectDigest,
        valid_from_boottime_nanoseconds: u64,
        valid_until_boottime_nanoseconds: u64,
    ) -> Result<Self, GitSmartTransportErrorV1> {
        if boot.as_bytes() == &[0; 32]
            || valid_from_boottime_nanoseconds == 0
            || valid_until_boottime_nanoseconds <= valid_from_boottime_nanoseconds
            || valid_until_boottime_nanoseconds == u64::MAX
        {
            return Err(GitSmartTransportErrorV1::InvalidRequest);
        }
        Ok(Self {
            boot,
            valid_from_boottime_nanoseconds,
            valid_until_boottime_nanoseconds,
        })
    }

    /// Reports whether a live sample remains inside the authenticated session.
    #[must_use]
    pub(crate) fn admits(self, sample: crate::environment::LiveAuthorityClockSampleV1) -> bool {
        sample.boot() == self.boot
            && sample.boottime_nanoseconds() >= self.valid_from_boottime_nanoseconds
            && sample.boottime_nanoseconds() < self.valid_until_boottime_nanoseconds
    }

    /// Returns the session's boot identity.
    #[must_use]
    pub const fn boot(self) -> ObjectDigest {
        self.boot
    }

    /// Returns the exclusive `CLOCK_BOOTTIME` expiry in nanoseconds.
    #[must_use]
    pub const fn valid_until_boottime_nanoseconds(self) -> u64 {
        self.valid_until_boottime_nanoseconds
    }
}

impl GitSmartRequestV1 {
    /// Parses an exact `git-upload-pack` or `git-receive-pack` command.
    ///
    /// The only accepted repository operand is the fixed logical form
    /// `'aos/<project-id-hex>/<repository-id-hex>'`.
    ///
    /// # Errors
    ///
    /// Returns [`GitSmartTransportErrorV1::InvalidRequest`] for whitespace,
    /// quoting, length, hexadecimal, command, or sentinel-identity failures.
    pub fn parse(command: &[u8]) -> Result<Self, GitSmartTransportErrorV1> {
        if command.len() > MAXIMUM_GIT_SMART_COMMAND_BYTES {
            return Err(GitSmartTransportErrorV1::InvalidRequest);
        }
        let (service, operand) = if let Some(operand) = command.strip_prefix(b"git-upload-pack ") {
            (GitProtocolV2ServiceV1::UploadPack, operand)
        } else if let Some(operand) = command.strip_prefix(b"git-receive-pack ") {
            (GitProtocolV2ServiceV1::ReceivePack, operand)
        } else {
            return Err(GitSmartTransportErrorV1::InvalidRequest);
        };
        if operand.len() != 71
            || operand.first() != Some(&b'\'')
            || operand.last() != Some(&b'\'')
            || &operand[1..5] != b"aos/"
            || operand[37] != b'/'
        {
            return Err(GitSmartTransportErrorV1::InvalidRequest);
        }
        let project = ProjectId::from_bytes(decode_hex_16(&operand[5..37])?);
        let repository = ResourceId::from_bytes(decode_hex_16(&operand[38..70])?);
        let endpoint = GitSmartEndpointV1::new(project, repository, service)?;
        if endpoint.command() != command {
            return Err(GitSmartTransportErrorV1::InvalidRequest);
        }
        Ok(Self {
            endpoint,
            command_digest: ObjectDigest::from_bytes(
                Sha256::new()
                    .chain_update(b"aos.sandbox.git.smart-command.v1\0")
                    .chain_update(command)
                    .finalize()
                    .into(),
            ),
        })
    }

    /// Returns the exact logical endpoint.
    #[must_use]
    pub const fn endpoint(self) -> GitSmartEndpointV1 {
        self.endpoint
    }

    /// Returns the commitment to the reproduced command bytes.
    #[must_use]
    pub const fn command_digest(self) -> ObjectDigest {
        self.command_digest
    }

    pub(super) fn from_protected(
        endpoint: GitSmartEndpointV1,
        command_digest: ObjectDigest,
    ) -> Result<Self, GitSmartTransportErrorV1> {
        let parsed = Self::parse(&endpoint.command())?;
        if parsed.command_digest != command_digest {
            return Err(GitSmartTransportErrorV1::InvalidRequest);
        }
        Ok(parsed)
    }
}

/// Selects one closed smart-transport dispatch phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum GitSmartDispatchPhaseV1 {
    /// Protected current state and the exact plan were checked pre-effect.
    Prepared = 1,
    /// The effect may have started and must be observed before retry.
    Indeterminate = 2,
    /// The exact standard exchange completed.
    Completed = 3,
    /// The exchange was definitively rejected.
    Rejected = 4,
}

/// Retains one exact standard exchange for fixed-owner ambiguity recovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitSmartDispatchStateV1 {
    request: GitSmartRequestV1,
    plan: GitExchangePlanV1,
    attempt: Revision,
    phase: GitSmartDispatchPhaseV1,
    terminal_receipt: Option<ObjectDigest>,
}

impl GitSmartDispatchStateV1 {
    pub(super) fn prepared(request: GitSmartRequestV1, plan: GitExchangePlanV1) -> Self {
        Self {
            request,
            plan,
            attempt: Revision::new(1),
            phase: GitSmartDispatchPhaseV1::Prepared,
            terminal_receipt: None,
        }
    }

    /// Marks a possibly started exchange outcome-unknown without permitting retry.
    ///
    /// # Errors
    ///
    /// Returns [`GitSmartTransportErrorV1::InvalidRequest`] unless prepared.
    pub fn mark_indeterminate(mut self) -> Result<Self, GitSmartTransportErrorV1> {
        if self.phase != GitSmartDispatchPhaseV1::Prepared {
            return Err(GitSmartTransportErrorV1::InvalidRequest);
        }
        self.phase = GitSmartDispatchPhaseV1::Indeterminate;
        Ok(self)
    }

    /// Resolves a prepared or indeterminate exchange from exact observation.
    ///
    /// # Errors
    ///
    /// Returns [`GitSmartTransportErrorV1::InvalidRequest`] for terminal state,
    /// plan mismatch, or sentinel receipt.
    pub(super) fn resolve(
        mut self,
        observation: GitSmartObservationV1,
    ) -> Result<Self, GitSmartTransportErrorV1> {
        if !matches!(
            self.phase,
            GitSmartDispatchPhaseV1::Prepared | GitSmartDispatchPhaseV1::Indeterminate
        ) || observation.exchange != exchange_id(&self.plan)
            || observation.receipt.as_bytes() == &[0; 32]
        {
            return Err(GitSmartTransportErrorV1::InvalidRequest);
        }
        self.phase = if observation.accepted {
            GitSmartDispatchPhaseV1::Completed
        } else {
            GitSmartDispatchPhaseV1::Rejected
        };
        self.terminal_receipt = Some(observation.receipt);
        Ok(self)
    }

    /// Returns the parsed standard request.
    #[must_use]
    pub const fn request(&self) -> GitSmartRequestV1 {
        self.request
    }

    /// Borrows the exact protocol-v2 plan.
    #[must_use]
    pub const fn plan(&self) -> &GitExchangePlanV1 {
        &self.plan
    }

    /// Returns the attempt revision.
    #[must_use]
    pub const fn attempt(&self) -> Revision {
        self.attempt
    }

    /// Returns the dispatch phase.
    #[must_use]
    pub const fn phase(&self) -> GitSmartDispatchPhaseV1 {
        self.phase
    }

    /// Returns the terminal effect receipt, when known.
    #[must_use]
    pub const fn terminal_receipt(&self) -> Option<ObjectDigest> {
        self.terminal_receipt
    }
}

/// Reports an exact standard exchange observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct GitSmartObservationV1 {
    exchange: ResourceId,
    accepted: bool,
    receipt: ObjectDigest,
}

impl GitSmartObservationV1 {
    pub(super) fn from_protected(
        exchange: ResourceId,
        accepted: bool,
        receipt: ObjectDigest,
    ) -> Result<Self, GitSmartTransportErrorV1> {
        if exchange.as_bytes() == &[0; 16] || receipt.as_bytes() == &[0; 32] {
            return Err(GitSmartTransportErrorV1::InvalidRequest);
        }
        Ok(Self {
            exchange,
            accepted,
            receipt,
        })
    }
}

/// Stores one canonical pre-effect or terminal smart-transport member.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GitSmartJournalRecordV1 {
    state: GitSmartDispatchStateV1,
    observation: Option<ObjectDigest>,
}

impl GitSmartJournalRecordV1 {
    pub(super) fn prepared(request: GitSmartRequestV1, plan: GitExchangePlanV1) -> Self {
        Self {
            state: GitSmartDispatchStateV1::prepared(request, plan),
            observation: None,
        }
    }

    pub(super) fn terminal(
        prepared: &Self,
        observation: GitSmartObservationV1,
        observation_commitment: ObjectDigest,
    ) -> Result<Self, GitSmartTransportErrorV1> {
        if prepared.observation.is_some()
            || prepared.state.phase() != GitSmartDispatchPhaseV1::Prepared
        {
            return Err(GitSmartTransportErrorV1::InvalidRequest);
        }
        Ok(Self {
            state: prepared.state.clone().resolve(observation)?,
            observation: Some(observation_commitment),
        })
    }

    pub(super) const fn state(&self) -> &GitSmartDispatchStateV1 {
        &self.state
    }
}

pub(crate) fn encode_git_smart_journal_record_v1(
    record: &GitSmartJournalRecordV1,
) -> Result<Vec<u8>, GitSmartTransportErrorV1> {
    let plan = encode_git_exchange_plan_v1(record.state.plan())
        .map_err(|_| GitSmartTransportErrorV1::InvalidRequest)?;
    let plan_len =
        u32::try_from(plan.len()).map_err(|_| GitSmartTransportErrorV1::InvalidRequest)?;
    let observation = record
        .observation
        .unwrap_or(ObjectDigest::from_bytes([0; 32]));
    let receipt = record
        .state
        .terminal_receipt()
        .unwrap_or(ObjectDigest::from_bytes([0; 32]));
    let mut body = Vec::new();
    body.try_reserve_exact(100_usize.saturating_add(plan.len()))
        .map_err(|_| GitSmartTransportErrorV1::InvalidRequest)?;
    body.extend_from_slice(b"AOSGSJ01");
    body.push(1);
    body.push(record.state.phase() as u8);
    body.extend_from_slice(&[0; 6]);
    body.extend_from_slice(record.state.request().command_digest().as_bytes());
    body.extend_from_slice(&plan_len.to_be_bytes());
    body.extend_from_slice(&plan);
    body.extend_from_slice(&record.state.attempt().get().to_be_bytes());
    body.extend_from_slice(observation.as_bytes());
    body.extend_from_slice(receipt.as_bytes());
    let digest = Sha256::new()
        .chain_update(b"aos.sandbox.git.smart-journal.v1\0")
        .chain_update(&body)
        .finalize();
    body.extend_from_slice(&digest);
    Ok(body)
}

pub(crate) fn decode_git_smart_journal_record_v1(
    bytes: &[u8],
    validator: &GitTrustedValidatorV1,
) -> Result<GitSmartJournalRecordV1, GitSmartTransportErrorV1> {
    if bytes.len() < 156 {
        return Err(GitSmartTransportErrorV1::InvalidRequest);
    }
    let (body, stored) = bytes.split_at(bytes.len() - 32);
    let digest = Sha256::new()
        .chain_update(b"aos.sandbox.git.smart-journal.v1\0")
        .chain_update(body)
        .finalize();
    if stored != digest.as_slice()
        || &body[..8] != b"AOSGSJ01"
        || body[8] != 1
        || body[10..16] != [0; 6]
    {
        return Err(GitSmartTransportErrorV1::InvalidRequest);
    }
    let plan_len = usize::try_from(u32::from_be_bytes(array_4(&body[48..52])?))
        .map_err(|_| GitSmartTransportErrorV1::InvalidRequest)?;
    let plan_end = 52_usize
        .checked_add(plan_len)
        .ok_or(GitSmartTransportErrorV1::InvalidRequest)?;
    let terminal_end = plan_end
        .checked_add(72)
        .ok_or(GitSmartTransportErrorV1::InvalidRequest)?;
    if terminal_end != body.len() {
        return Err(GitSmartTransportErrorV1::InvalidRequest);
    }
    let plan = decode_git_exchange_plan_v1(&body[52..plan_end], validator)
        .map_err(|_| GitSmartTransportErrorV1::InvalidRequest)?;
    let endpoint = endpoint_for_plan(&plan)?;
    let request = GitSmartRequestV1::from_protected(
        endpoint,
        ObjectDigest::from_bytes(array_32(&body[16..48])?),
    )?;
    let mut state = GitSmartDispatchStateV1::prepared(request, plan);
    state.attempt = Revision::new(u64::from_be_bytes(array_8(&body[plan_end..plan_end + 8])?));
    let observation = ObjectDigest::from_bytes(array_32(&body[plan_end + 8..plan_end + 40])?);
    let receipt = ObjectDigest::from_bytes(array_32(&body[plan_end + 40..terminal_end])?);
    if state.attempt().get() != 1 {
        return Err(GitSmartTransportErrorV1::InvalidRequest);
    }
    match body[9] {
        1 if observation.as_bytes() == &[0; 32] && receipt.as_bytes() == &[0; 32] => {}
        3 | 4 if observation.as_bytes() != &[0; 32] && receipt.as_bytes() != &[0; 32] => {
            state.phase = if body[9] == 3 {
                GitSmartDispatchPhaseV1::Completed
            } else {
                GitSmartDispatchPhaseV1::Rejected
            };
            state.terminal_receipt = Some(receipt);
        }
        _ => return Err(GitSmartTransportErrorV1::InvalidRequest),
    }
    let record = GitSmartJournalRecordV1 {
        state,
        observation: (observation.as_bytes() != &[0; 32]).then_some(observation),
    };
    if encode_git_smart_journal_record_v1(&record)? != bytes {
        return Err(GitSmartTransportErrorV1::InvalidRequest);
    }
    Ok(record)
}

/// Carries a lifetime-bound exact exchange to a future Git effect owner.
#[must_use]
pub struct GitSmartEffectHandoffV1<'current> {
    state: GitSmartDispatchStateV1,
    authority_fence: GitSmartAuthorityFenceV1,
    journal_authority: ValidatedGitPostcommitV1<'current>,
}

impl<'current> GitSmartEffectHandoffV1<'current> {
    pub(super) fn new(
        state: GitSmartDispatchStateV1,
        authority_fence: GitSmartAuthorityFenceV1,
        journal_authority: ValidatedGitPostcommitV1<'current>,
    ) -> Self {
        Self {
            state,
            authority_fence,
            journal_authority,
        }
    }

    /// Borrows the exact pre-effect state.
    #[must_use]
    pub const fn state(&self) -> &GitSmartDispatchStateV1 {
        &self.state
    }

    /// Returns the exact committed pre-effect transaction commitment.
    #[must_use]
    pub const fn transaction_commitment(&self) -> ObjectDigest {
        self.journal_authority.transaction_digest()
    }

    /// Returns the live boot-time session fence.
    #[must_use]
    pub const fn authority_fence(&self) -> GitSmartAuthorityFenceV1 {
        self.authority_fence
    }

    /// Consumes the handoff into ambiguity-retaining recovery state.
    ///
    /// # Errors
    ///
    /// Returns [`GitSmartTransportErrorV1`] unless the state is prepared.
    pub fn into_indeterminate(self) -> Result<GitSmartDispatchStateV1, GitSmartTransportErrorV1> {
        self.state.mark_indeterminate()
    }
}

/// Distinguishes a durable Git effect handoff from ambiguous pre-effect state.
#[must_use]
pub enum GitSmartPrepareOutcomeV1<'current> {
    /// Exact readback and current session revalidation authorize the effect.
    Prepared(GitSmartEffectHandoffV1<'current>),
    /// Durability is unknown and the exact recovery token is retained.
    OutcomeUnknown(GitJournalOutcomeUnknownV1),
}

/// Classifies protected recovery of one exact pre-effect Git transaction.
#[must_use]
pub enum GitSmartPrepareRecoveryV1<'current> {
    /// Reopen proved the exact successor and reminted current authority.
    Prepared(GitSmartEffectHandoffV1<'current>),
    /// Reopen proved the exact predecessor and retained the sole retry.
    Retry(PreparedGitJournalTransactionV1),
    /// Reopen found mixed or substituted state and retained ambiguity.
    Diverged(GitJournalOutcomeUnknownV1),
}

/// Distinguishes terminal Git publication from ambiguous durability.
#[must_use]
pub enum GitSmartSettlementOutcomeV1 {
    /// The protected terminal successor was read back exactly.
    Applied(GitSmartDispatchStateV1),
    /// Durability is unknown and the exact token remains attached to state.
    OutcomeUnknown(GitSmartSettlementUnknownV1),
}

/// Retains the exact terminal Git record and ambiguity token as one unit.
#[must_use]
pub struct GitSmartSettlementUnknownV1 {
    terminal: GitSmartJournalRecordV1,
    pending: GitJournalOutcomeUnknownV1,
}

impl GitSmartSettlementUnknownV1 {
    pub(super) fn new(
        terminal: GitSmartJournalRecordV1,
        pending: GitJournalOutcomeUnknownV1,
    ) -> Self {
        Self { terminal, pending }
    }

    pub(super) fn into_parts(self) -> (GitSmartJournalRecordV1, GitJournalOutcomeUnknownV1) {
        (self.terminal, self.pending)
    }
}

/// Classifies protected recovery of one terminal Git publication.
#[must_use]
pub enum GitSmartSettlementRecoveryV1 {
    /// Reopen proved the exact terminal successor.
    Applied(GitSmartDispatchStateV1),
    /// Reopen proved the predecessor and retained the sole retry.
    Retry(GitSmartSettlementRetryV1),
    /// Reopen found mixed or substituted state and retained ambiguity.
    Diverged(GitSmartSettlementUnknownV1),
}

/// Retains the exact terminal Git record and sole retry as one unit.
#[must_use]
pub struct GitSmartSettlementRetryV1 {
    terminal: GitSmartJournalRecordV1,
    prepared: PreparedGitJournalTransactionV1,
}

impl GitSmartSettlementRetryV1 {
    pub(super) fn new(
        terminal: GitSmartJournalRecordV1,
        prepared: PreparedGitJournalTransactionV1,
    ) -> Self {
        Self { terminal, prepared }
    }

    pub(super) fn into_parts(self) -> (GitSmartJournalRecordV1, PreparedGitJournalTransactionV1) {
        (self.terminal, self.prepared)
    }
}

/// Defines the future effect boundary for standard Git protocol-v2 exchange.
///
/// This source-only tranche intentionally supplies no implementation.
pub trait DormantGitSmartEffectV1 {
    /// Effect-specific failure that does not classify durable outcome.
    type Error;

    /// Observes or applies one lifetime-bound exact standard exchange.
    ///
    /// The outcome must preserve either the exact observation or an
    /// indeterminate state; it cannot treat an implementation error as retry.
    ///
    /// # Errors
    ///
    /// Returns [`GitSmartTransportErrorV1`] if the one-shot handoff cannot be
    /// converted into ambiguity-retaining state.
    fn apply(
        &mut self,
        handoff: GitSmartEffectHandoffV1<'_>,
    ) -> Result<GitSmartEffectOutcomeV1<Self::Error>, GitSmartTransportErrorV1>;
}

/// Retains either an exact Git observation or outcome-unknown recovery.
#[must_use]
pub enum GitSmartEffectOutcomeV1<E> {
    /// The effect returned and now requires sealed protected observation.
    ObservationRequired {
        /// Indeterminate state retained for protected observation.
        state: GitSmartDispatchStateV1,
    },
    /// The effect outcome is unknown and cannot be treated as retryable.
    OutcomeUnknown {
        /// Indeterminate state retained for protected recovery.
        state: GitSmartDispatchStateV1,
        /// Effect-specific diagnostic.
        error: E,
    },
}

impl<E> GitSmartEffectOutcomeV1<E> {
    /// Requires fixed protected observation after an effect returned.
    ///
    /// # Errors
    ///
    /// Returns [`GitSmartTransportErrorV1`] unless the retained state was
    /// prepared and can move to indeterminate recovery.
    pub fn observation_required(
        handoff: GitSmartEffectHandoffV1<'_>,
    ) -> Result<Self, GitSmartTransportErrorV1> {
        Ok(Self::ObservationRequired {
            state: handoff.state.mark_indeterminate()?,
        })
    }

    /// Constructs an ambiguous outcome by consuming the one-shot handoff.
    ///
    /// # Errors
    ///
    /// Returns [`GitSmartTransportErrorV1`] unless the retained state was
    /// prepared and can move to indeterminate recovery.
    pub fn outcome_unknown(
        handoff: GitSmartEffectHandoffV1<'_>,
        error: E,
    ) -> Result<Self, GitSmartTransportErrorV1> {
        Ok(Self::OutcomeUnknown {
            state: handoff.state.mark_indeterminate()?,
            error,
        })
    }
}

/// Converts the cheap-fork source contract into a public node advertisement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitCheapForkCapabilityAdvertisementV1 {
    available: bool,
    unavailable_reason: String,
}

impl GitCheapForkCapabilityAdvertisementV1 {
    /// Constructs the canonical source-only unavailable advertisement.
    #[must_use]
    pub fn dormant_unqualified() -> Self {
        Self {
            available: false,
            unavailable_reason: CHEAP_SANITIZED_GIT_FORK_UNQUALIFIED_REASON_V1.to_owned(),
        }
    }

    /// Constructs the dormant, explicitly unavailable advertisement.
    ///
    /// # Errors
    ///
    /// Returns [`GitSmartTransportErrorV1::InvalidRequest`] for an empty,
    /// oversized, or control-bearing public reason.
    pub fn unavailable(reason: String) -> Result<Self, GitSmartTransportErrorV1> {
        if reason.is_empty() || reason.len() > 1_024 || reason.chars().any(char::is_control) {
            return Err(GitSmartTransportErrorV1::InvalidRequest);
        }
        Ok(Self {
            available: false,
            unavailable_reason: reason,
        })
    }

    /// Reports whether an installed effect owner passed conformance.
    #[must_use]
    pub const fn available(&self) -> bool {
        self.available
    }

    /// Borrows the precise public reason the feature is unavailable.
    #[must_use]
    pub fn unavailable_reason(&self) -> &str {
        &self.unavailable_reason
    }

    /// Commits the full public feature identity and advertised status.
    #[must_use]
    pub fn resource_version_binding(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(
            Sha256::new()
                .chain_update(b"aos.sandbox.git.cheap-fork-advertisement.v1\0")
                .chain_update(
                    (CHEAP_SANITIZED_GIT_FORK_FEATURE_NAMESPACE_V1.len() as u32).to_be_bytes(),
                )
                .chain_update(CHEAP_SANITIZED_GIT_FORK_FEATURE_NAMESPACE_V1.as_bytes())
                .chain_update(CHEAP_SANITIZED_GIT_FORK_FEATURE_MAJOR_V1.to_be_bytes())
                .chain_update(CHEAP_SANITIZED_GIT_FORK_FEATURE_MINOR_V1.to_be_bytes())
                .chain_update([u8::from(self.available)])
                .chain_update((self.unavailable_reason.len() as u32).to_be_bytes())
                .chain_update(self.unavailable_reason.as_bytes())
                .chain_update(cheap_sanitized_git_fork_fixture_digest_v1().as_bytes())
                .finalize()
                .into(),
        )
    }
}

impl From<GitCheapForkCapabilityAdvertisementV1> for SemanticCapability {
    fn from(advertisement: GitCheapForkCapabilityAdvertisementV1) -> Self {
        Self {
            feature: Some(Feature {
                namespace: CHEAP_SANITIZED_GIT_FORK_FEATURE_NAMESPACE_V1.to_owned(),
                major: CHEAP_SANITIZED_GIT_FORK_FEATURE_MAJOR_V1,
                minor: CHEAP_SANITIZED_GIT_FORK_FEATURE_MINOR_V1,
                ..Default::default()
            })
            .into(),
            available: advertisement.available,
            unavailable_reason: advertisement.unavailable_reason,
            conformance_fixture_digest: cheap_sanitized_git_fork_fixture_digest_v1()
                .as_bytes()
                .to_vec(),
            ..Default::default()
        }
    }
}

/// Returns the checked-in cheap-fork conformance fixture commitment.
#[must_use]
pub fn cheap_sanitized_git_fork_fixture_digest_v1() -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.git.cheap-sanitized-fork.fixture.v1\0")
            .chain_update(CHEAP_SANITIZED_GIT_FORK_FIXTURE_V1)
            .finalize()
            .into(),
    )
}

pub(super) fn plan_matches_endpoint(request: GitSmartRequestV1, plan: &GitExchangePlanV1) -> bool {
    let endpoint = request.endpoint();
    match plan {
        GitExchangePlanV1::Upload(upload) => {
            endpoint.service() == GitProtocolV2ServiceV1::UploadPack
                && endpoint.project() == upload.export().project()
                && endpoint.repository() == upload.export().repository()
        }
        GitExchangePlanV1::Receive(receive) => {
            endpoint.service() == GitProtocolV2ServiceV1::ReceivePack
                && endpoint.project() == receive.repository().project()
                && endpoint.repository() == receive.repository().repository()
        }
    }
}

pub(super) fn session_matches_plan(
    session: &GitSmartSessionEvidenceV1,
    request: GitSmartRequestV1,
    plan: &GitExchangePlanV1,
) -> bool {
    if session.endpoint != request.endpoint() {
        return false;
    }
    match plan {
        GitExchangePlanV1::Upload(upload) => {
            session.principal == upload.principal()
                && session.channel_binding == upload.channel_binding()
                && session.expires_at_unix_seconds == upload.expires_at_unix_seconds()
                && session.maximum_input_bytes == upload.maximum_input_bytes()
                && session.maximum_output_bytes == upload.maximum_output_bytes()
        }
        GitExchangePlanV1::Receive(receive) => {
            session.principal == receive.principal()
                && session.channel_binding == receive.channel_binding()
                && session.expires_at_unix_seconds == receive.expires_at_unix_seconds()
                && session.maximum_input_bytes == receive.maximum_input_bytes()
                && session.maximum_output_bytes == receive.maximum_output_bytes()
        }
    }
}

pub(super) const fn exchange_id(plan: &GitExchangePlanV1) -> ResourceId {
    match plan {
        GitExchangePlanV1::Upload(upload) => upload.exchange(),
        GitExchangePlanV1::Receive(receive) => receive.exchange(),
    }
}

pub(super) fn plan_commitment_v1(
    plan: &GitExchangePlanV1,
) -> Result<ObjectDigest, super::GitModelError> {
    let encoded = encode_git_exchange_plan_v1(plan)?;
    Ok(ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.git.smart-plan.v1\0")
            .chain_update(encoded)
            .finalize()
            .into(),
    ))
}

fn endpoint_for_plan(
    plan: &GitExchangePlanV1,
) -> Result<GitSmartEndpointV1, GitSmartTransportErrorV1> {
    match plan {
        GitExchangePlanV1::Upload(upload) => GitSmartEndpointV1::new(
            upload.export().project(),
            upload.export().repository(),
            GitProtocolV2ServiceV1::UploadPack,
        ),
        GitExchangePlanV1::Receive(receive) => GitSmartEndpointV1::new(
            receive.repository().project(),
            receive.repository().repository(),
            GitProtocolV2ServiceV1::ReceivePack,
        ),
    }
}

fn array_4(bytes: &[u8]) -> Result<[u8; 4], GitSmartTransportErrorV1> {
    bytes
        .try_into()
        .map_err(|_| GitSmartTransportErrorV1::InvalidRequest)
}

fn array_8(bytes: &[u8]) -> Result<[u8; 8], GitSmartTransportErrorV1> {
    bytes
        .try_into()
        .map_err(|_| GitSmartTransportErrorV1::InvalidRequest)
}

fn array_32(bytes: &[u8]) -> Result<[u8; 32], GitSmartTransportErrorV1> {
    bytes
        .try_into()
        .map_err(|_| GitSmartTransportErrorV1::InvalidRequest)
}

fn service_name(service: GitProtocolV2ServiceV1) -> &'static [u8] {
    match service {
        GitProtocolV2ServiceV1::UploadPack => b"git-upload-pack",
        GitProtocolV2ServiceV1::ReceivePack => b"git-receive-pack",
    }
}

fn append_hex(output: &mut Vec<u8>, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        output.push(HEX[usize::from(byte >> 4)]);
        output.push(HEX[usize::from(byte & 0x0f)]);
    }
}

fn decode_hex_16(bytes: &[u8]) -> Result<[u8; 16], GitSmartTransportErrorV1> {
    if bytes.len() != 32 {
        return Err(GitSmartTransportErrorV1::InvalidRequest);
    }
    let mut decoded = [0_u8; 16];
    for (index, pair) in bytes.chunks_exact(2).enumerate() {
        decoded[index] = hex_digit(pair[0])?
            .checked_mul(16)
            .and_then(|high| high.checked_add(hex_digit(pair[1]).ok()?))
            .ok_or(GitSmartTransportErrorV1::InvalidRequest)?;
    }
    Ok(decoded)
}

fn hex_digit(byte: u8) -> Result<u8, GitSmartTransportErrorV1> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(GitSmartTransportErrorV1::InvalidRequest),
    }
}
