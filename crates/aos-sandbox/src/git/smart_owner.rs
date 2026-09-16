//! Fixed protected session, clock, and observation ownership for Git smart transport.
//!
//! ```text
//! AOSGSC01 || v1 || authority || boot || generation || boottime-nanoseconds ||
//! authenticated-at || valid-until || predecessor-head || sha256-as-head
//! AOSGSS01 || v1 || endpoint || exchange || principal || channel || bounds || plan || sha256
//! AOSGSO01 || v1 || accepted || exchange || plan || receipt || sha256
//! ```

use std::path::Path;

use aos_sandbox_core::{ObjectDigest, PrincipalId, ResourceId};
use sha2::{Digest as _, Sha256};

use crate::environment::{
    FixedLiveAuthorityClockV1, LiveAuthorityClockSampleV1,
    authority_clock::validate_bracketed_samples_v1, fixed_live_authority_clock_v1,
};
use crate::journal::{Journal, JournalError, JournalLimits, RecordNamespace, RecoveryReport};

use super::smart_transport::{GitSmartSessionEvidenceV1, plan_commitment_v1, session_matches_plan};
use super::{
    GitChannelBindingDigestV1, GitExchangePlanV1, GitProtocolV2ServiceV1, GitSmartAuthorityFenceV1,
    GitSmartEndpointV1, GitSmartRequestV1, GitSmartTransportErrorV1,
};

const ROOT: &str = "/var/lib/aos/sandbox/source-evidence";
const SESSION_JOURNAL: &str = "git-smart-session-v1.journal";
const OBSERVATION_JOURNAL: &str = "git-smart-observation-v1.journal";
const CLOCK_KEY: &[u8] = b"git-smart-protected-clock-v1";
const SESSION_PREFIX: &[u8] = b"git-smart-session-v1/";
const OBSERVATION_PREFIX: &[u8] = b"git-smart-observation-v1/";
const SESSION_MAGIC: &[u8; 8] = b"AOSGSS01";
const OBSERVATION_MAGIC: &[u8; 8] = b"AOSGSO01";
const CLOCK_MAGIC: &[u8; 8] = b"AOSGSC01";
const CLOCK_DOMAIN: &[u8] = b"aos.sandbox.git.smart-protected-clock.v1\0";
const SESSION_DOMAIN: &[u8] = b"aos.sandbox.git.smart-protected-session.v1\0";
const OBSERVATION_DOMAIN: &[u8] = b"aos.sandbox.git.smart-protected-observation.v1\0";

/// Reports unavailable or noncanonical fixed Git smart-transport evidence.
#[derive(Debug, thiserror::Error)]
pub enum GitSmartProtectedOwnerErrorV1 {
    /// A fixed protected journal could not be opened or read.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// Session, clock, or observation evidence is absent or invalid.
    #[error("protected Git smart-transport evidence is invalid or unavailable")]
    InvalidEvidence,
}

/// Owns fixed authenticated Git sessions and a monotone protected live clock head.
pub struct GitSmartProtectedSessionOwnerV1 {
    journal: Journal,
    pinned_sessions: Vec<(Vec<u8>, Vec<u8>)>,
    protected_clock: GitSmartProtectedClockV1,
    live_clock: FixedLiveAuthorityClockV1,
    last_sample: LiveAuthorityClockSampleV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct GitSmartProtectedClockV1 {
    authority: ObjectDigest,
    boot: ObjectDigest,
    generation: u64,
    protected_now: u64,
    authenticated_at: u64,
    valid_until: u64,
    predecessor: ObjectDigest,
    head: ObjectDigest,
}

/// Owns sealed observations produced by a future Git effect boundary.
pub struct GitSmartProtectedObservationOwnerV1 {
    journal: Journal,
    pinned: Vec<(Vec<u8>, Vec<u8>)>,
}

/// Carries one sealed exact Git effect observation.
#[must_use]
pub(crate) struct CurrentGitSmartObservationV1<'current> {
    exchange: ResourceId,
    accepted: bool,
    receipt: ObjectDigest,
    commitment: ObjectDigest,
    _current: std::marker::PhantomData<&'current mut ()>,
}

impl CurrentGitSmartObservationV1<'_> {
    pub(super) const fn exchange(&self) -> ResourceId {
        self.exchange
    }

    pub(super) const fn accepted(&self) -> bool {
        self.accepted
    }

    pub(super) const fn receipt(&self) -> ObjectDigest {
        self.receipt
    }

    pub(super) const fn commitment(&self) -> ObjectDigest {
        self.commitment
    }
}

impl GitSmartProtectedSessionOwnerV1 {
    /// Opens fixed authenticated sessions and establishes the live clock head.
    ///
    /// # Errors
    ///
    /// Returns [`GitSmartProtectedOwnerErrorV1`] unless the journal contains
    /// one canonical current clock head and only canonical session-family keys.
    pub fn open_fixed_protected() -> Result<(Self, RecoveryReport), GitSmartProtectedOwnerErrorV1> {
        Self::open_fixed_protected_with_clock(fixed_live_authority_clock_v1())
    }

    /// Opens protected sessions with an explicitly injected live clock source.
    ///
    /// # Errors
    ///
    /// Returns [`GitSmartProtectedOwnerErrorV1`] unless the protected read is
    /// bracketed by current non-regressing samples from the recorded boot.
    fn open_fixed_protected_with_clock(
        mut live_clock: FixedLiveAuthorityClockV1,
    ) -> Result<(Self, RecoveryReport), GitSmartProtectedOwnerErrorV1> {
        let before = live_clock
            .sample()
            .map_err(|_| GitSmartProtectedOwnerErrorV1::InvalidEvidence)?;
        let (mut journal, report) =
            Journal::open_protected_at(Path::new(ROOT), SESSION_JOURNAL, limits())?;
        let pinned = read_all(&mut journal)?;
        if pinned.iter().filter(|(key, _)| key == CLOCK_KEY).count() != 1
            || pinned
                .iter()
                .any(|(key, _)| key != CLOCK_KEY && !key.starts_with(SESSION_PREFIX))
        {
            return Err(GitSmartProtectedOwnerErrorV1::InvalidEvidence);
        }
        let clock = decode_clock(
            &pinned
                .iter()
                .find(|(key, _)| key == CLOCK_KEY)
                .ok_or(GitSmartProtectedOwnerErrorV1::InvalidEvidence)?
                .1,
        )?;
        let after = live_clock
            .sample()
            .map_err(|_| GitSmartProtectedOwnerErrorV1::InvalidEvidence)?;
        let last_sample = validate_bracketed_samples_v1(before, after)
            .map_err(|_| GitSmartProtectedOwnerErrorV1::InvalidEvidence)?;
        validate_clock_currentness(&clock, last_sample)?;
        let pinned_sessions = pinned
            .into_iter()
            .filter(|(key, _)| key != CLOCK_KEY)
            .collect();
        Ok((
            Self {
                journal,
                pinned_sessions,
                protected_clock: clock,
                live_clock,
                last_sample,
            },
            report,
        ))
    }

    /// Claims the unique authenticated session for one exact exchange plan.
    ///
    /// # Errors
    ///
    /// Returns [`GitSmartProtectedOwnerErrorV1`] when evidence changed, is
    /// expired under the protected clock, or mismatches the exact request/plan.
    pub(crate) fn claim(
        &mut self,
        request: GitSmartRequestV1,
        plan: &GitExchangePlanV1,
    ) -> Result<GitSmartSessionEvidenceV1, GitSmartProtectedOwnerErrorV1> {
        let (protected_clock, live_now) = self.sample_clock()?;
        let exchange = super::smart_transport::exchange_id(plan);
        let mut key = Vec::with_capacity(SESSION_PREFIX.len() + 16);
        key.extend_from_slice(SESSION_PREFIX);
        key.extend_from_slice(exchange.as_bytes());
        let encoded = unique_value(&self.pinned_sessions, &key)?;
        let session = decode_session(encoded, request, plan, protected_clock, live_now)?;
        if !session_matches_plan(&session, request, plan) {
            return Err(GitSmartProtectedOwnerErrorV1::InvalidEvidence);
        }
        Ok(session)
    }

    fn sample_clock(
        &mut self,
    ) -> Result<(GitSmartProtectedClockV1, LiveAuthorityClockSampleV1), GitSmartProtectedOwnerErrorV1>
    {
        let before = self
            .live_clock
            .sample()
            .map_err(|_| GitSmartProtectedOwnerErrorV1::InvalidEvidence)?;
        if before.boot() != self.last_sample.boot()
            || before.boottime_nanoseconds() < self.last_sample.boottime_nanoseconds()
        {
            return Err(GitSmartProtectedOwnerErrorV1::InvalidEvidence);
        }
        let current = read_all(&mut self.journal)?;
        if current.iter().filter(|(key, _)| key == CLOCK_KEY).count() != 1
            || current
                .iter()
                .any(|(key, _)| key != CLOCK_KEY && !key.starts_with(SESSION_PREFIX))
        {
            return Err(GitSmartProtectedOwnerErrorV1::InvalidEvidence);
        }
        let sessions = current
            .iter()
            .filter(|(key, _)| key != CLOCK_KEY)
            .cloned()
            .collect::<Vec<_>>();
        if sessions != self.pinned_sessions {
            return Err(GitSmartProtectedOwnerErrorV1::InvalidEvidence);
        }
        let sampled = decode_clock(unique_value(&current, CLOCK_KEY)?)?;
        if sampled != self.protected_clock {
            let successor_generation = self
                .protected_clock
                .generation
                .checked_add(1)
                .ok_or(GitSmartProtectedOwnerErrorV1::InvalidEvidence)?;
            if sampled.authority != self.protected_clock.authority
                || sampled.boot != self.protected_clock.boot
                || sampled.generation != successor_generation
                || sampled.protected_now <= self.protected_clock.protected_now
                || sampled.authenticated_at < self.protected_clock.authenticated_at
                || sampled.predecessor != self.protected_clock.head
            {
                return Err(GitSmartProtectedOwnerErrorV1::InvalidEvidence);
            }
            self.protected_clock = sampled;
        }
        let after = self
            .live_clock
            .sample()
            .map_err(|_| GitSmartProtectedOwnerErrorV1::InvalidEvidence)?;
        let live_now = validate_bracketed_samples_v1(before, after)
            .map_err(|_| GitSmartProtectedOwnerErrorV1::InvalidEvidence)?;
        validate_clock_currentness(&sampled, live_now)?;
        self.last_sample = live_now;
        Ok((sampled, live_now))
    }
}

impl GitSmartProtectedObservationOwnerV1 {
    /// Opens and pins the fixed Git effect-observation journal.
    ///
    /// # Errors
    ///
    /// Returns [`GitSmartProtectedOwnerErrorV1`] for unavailable protected
    /// storage or a foreign record family.
    pub fn open_fixed_protected() -> Result<(Self, RecoveryReport), GitSmartProtectedOwnerErrorV1> {
        let (mut journal, report) =
            Journal::open_protected_at(Path::new(ROOT), OBSERVATION_JOURNAL, limits())?;
        let pinned = read_all(&mut journal)?;
        if pinned
            .iter()
            .any(|(key, _)| !key.starts_with(OBSERVATION_PREFIX))
        {
            return Err(GitSmartProtectedOwnerErrorV1::InvalidEvidence);
        }
        Ok((Self { journal, pinned }, report))
    }

    /// Claims the unique sealed observation for an exact exchange plan.
    ///
    /// # Errors
    ///
    /// Returns [`GitSmartProtectedOwnerErrorV1`] when evidence changed or no
    /// unique canonical observation reproduces the plan commitment.
    pub(crate) fn claim<'current>(
        &'current mut self,
        plan: &GitExchangePlanV1,
    ) -> Result<CurrentGitSmartObservationV1<'current>, GitSmartProtectedOwnerErrorV1> {
        let current = read_all(&mut self.journal)?;
        if current != self.pinned {
            return Err(GitSmartProtectedOwnerErrorV1::InvalidEvidence);
        }
        let exchange = super::smart_transport::exchange_id(plan);
        let mut key = Vec::with_capacity(OBSERVATION_PREFIX.len() + 16);
        key.extend_from_slice(OBSERVATION_PREFIX);
        key.extend_from_slice(exchange.as_bytes());
        decode_observation(unique_value(&self.pinned, &key)?, plan)
    }
}

fn decode_clock(encoded: &[u8]) -> Result<GitSmartProtectedClockV1, GitSmartProtectedOwnerErrorV1> {
    if encoded.len() != 176 {
        return Err(GitSmartProtectedOwnerErrorV1::InvalidEvidence);
    }
    let (body, stored) = encoded.split_at(144);
    if &body[..8] != CLOCK_MAGIC || body[8] != 1 || body[9..16] != [0; 7] {
        return Err(GitSmartProtectedOwnerErrorV1::InvalidEvidence);
    }
    let authority = ObjectDigest::from_bytes(array(&body[16..48])?);
    let boot = ObjectDigest::from_bytes(array(&body[48..80])?);
    let generation = u64::from_be_bytes(array(&body[80..88])?);
    let protected_now = u64::from_be_bytes(array(&body[88..96])?);
    let authenticated_at = u64::from_be_bytes(array(&body[96..104])?);
    let valid_until = u64::from_be_bytes(array(&body[104..112])?);
    let predecessor = ObjectDigest::from_bytes(array(&body[112..144])?);
    let head = ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(CLOCK_DOMAIN)
            .chain_update(body)
            .finalize()
            .into(),
    );
    let predecessor_shape = (generation == 1 && predecessor.as_bytes() == &[0; 32])
        || (generation > 1 && predecessor.as_bytes() != &[0; 32]);
    if authority.as_bytes() == &[0; 32]
        || boot.as_bytes() == &[0; 32]
        || generation == 0
        || generation == u64::MAX
        || protected_now == 0
        || authenticated_at == 0
        || valid_until == u64::MAX
        || valid_until <= authenticated_at
        || !predecessor_shape
        || stored != head.as_bytes()
    {
        return Err(GitSmartProtectedOwnerErrorV1::InvalidEvidence);
    }
    Ok(GitSmartProtectedClockV1 {
        authority,
        boot,
        generation,
        protected_now,
        authenticated_at,
        valid_until,
        predecessor,
        head,
    })
}

fn decode_session(
    encoded: &[u8],
    request: GitSmartRequestV1,
    plan: &GitExchangePlanV1,
    protected_clock: GitSmartProtectedClockV1,
    live_now: LiveAuthorityClockSampleV1,
) -> Result<GitSmartSessionEvidenceV1, GitSmartProtectedOwnerErrorV1> {
    if encoded.len() != 240 {
        return Err(GitSmartProtectedOwnerErrorV1::InvalidEvidence);
    }
    let (body, stored) = encoded.split_at(208);
    let commitment = Sha256::new()
        .chain_update(SESSION_DOMAIN)
        .chain_update(body)
        .finalize();
    let service = match body[9] {
        1 => GitProtocolV2ServiceV1::UploadPack,
        2 => GitProtocolV2ServiceV1::ReceivePack,
        _ => return Err(GitSmartProtectedOwnerErrorV1::InvalidEvidence),
    };
    let endpoint = request.endpoint();
    if stored != commitment.as_slice()
        || &body[..8] != SESSION_MAGIC
        || body[8] != 1
        || body[10..16] != [0; 6]
        || service != endpoint.service()
        || &body[16..32] != endpoint.project().as_bytes()
        || &body[32..48] != endpoint.repository().as_bytes()
        || &body[48..64] != super::smart_transport::exchange_id(plan).as_bytes()
        || &body[176..208]
            != plan_commitment_v1(plan)
                .map_err(|_| GitSmartProtectedOwnerErrorV1::InvalidEvidence)?
                .as_bytes()
        || &body[144..176] != request.command_digest().as_bytes()
    {
        return Err(GitSmartProtectedOwnerErrorV1::InvalidEvidence);
    }
    let authenticated_at = u64::from_be_bytes(array(&body[112..120])?);
    let expires_at = u64::from_be_bytes(array(&body[120..128])?);
    let elapsed_seconds = live_now
        .boottime_nanoseconds()
        .checked_sub(protected_clock.protected_now)
        .ok_or(GitSmartProtectedOwnerErrorV1::InvalidEvidence)?
        / 1_000_000_000;
    let estimated_wall = protected_clock
        .authenticated_at
        .checked_add(elapsed_seconds)
        .ok_or(GitSmartProtectedOwnerErrorV1::InvalidEvidence)?;
    let remaining_nanoseconds = expires_at
        .checked_sub(estimated_wall)
        .and_then(|seconds| seconds.checked_mul(1_000_000_000))
        .ok_or(GitSmartProtectedOwnerErrorV1::InvalidEvidence)?;
    let session_deadline = live_now
        .boottime_nanoseconds()
        .checked_add(remaining_nanoseconds)
        .ok_or(GitSmartProtectedOwnerErrorV1::InvalidEvidence)?;
    let clock_deadline = protected_clock_deadline(&protected_clock)?;
    let authority_fence = GitSmartAuthorityFenceV1::from_protected(
        live_now.boot(),
        live_now.boottime_nanoseconds(),
        session_deadline.min(clock_deadline),
    )
    .map_err(|_| GitSmartProtectedOwnerErrorV1::InvalidEvidence)?;
    if authenticated_at == 0
        || authenticated_at > estimated_wall
        || estimated_wall >= expires_at
        || expires_at == u64::MAX
    {
        return Err(GitSmartProtectedOwnerErrorV1::InvalidEvidence);
    }
    GitSmartSessionEvidenceV1::from_protected(
        endpoint,
        PrincipalId::from_bytes(array(&body[64..80])?),
        GitChannelBindingDigestV1::from_stored(ObjectDigest::from_bytes(array(&body[80..112])?))
            .map_err(|_| GitSmartProtectedOwnerErrorV1::InvalidEvidence)?,
        expires_at,
        u64::from_be_bytes(array(&body[128..136])?),
        u64::from_be_bytes(array(&body[136..144])?),
        authority_fence,
    )
    .map_err(|_| GitSmartProtectedOwnerErrorV1::InvalidEvidence)
}

fn decode_observation<'current>(
    encoded: &[u8],
    plan: &GitExchangePlanV1,
) -> Result<CurrentGitSmartObservationV1<'current>, GitSmartProtectedOwnerErrorV1> {
    if encoded.len() != 128 {
        return Err(GitSmartProtectedOwnerErrorV1::InvalidEvidence);
    }
    let (body, stored) = encoded.split_at(96);
    let commitment = ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(OBSERVATION_DOMAIN)
            .chain_update(body)
            .finalize()
            .into(),
    );
    let exchange = super::smart_transport::exchange_id(plan);
    if stored != commitment.as_bytes()
        || &body[..8] != OBSERVATION_MAGIC
        || body[8] != 1
        || body[9] > 1
        || body[10..16] != [0; 6]
        || &body[16..32] != exchange.as_bytes()
        || &body[32..64]
            != plan_commitment_v1(plan)
                .map_err(|_| GitSmartProtectedOwnerErrorV1::InvalidEvidence)?
                .as_bytes()
    {
        return Err(GitSmartProtectedOwnerErrorV1::InvalidEvidence);
    }
    let receipt = ObjectDigest::from_bytes(array(&body[64..96])?);
    if receipt.as_bytes() == &[0; 32] {
        return Err(GitSmartProtectedOwnerErrorV1::InvalidEvidence);
    }
    Ok(CurrentGitSmartObservationV1 {
        exchange,
        accepted: body[9] == 1,
        receipt,
        commitment,
        _current: std::marker::PhantomData,
    })
}

fn validate_clock_currentness(
    clock: &GitSmartProtectedClockV1,
    live: LiveAuthorityClockSampleV1,
) -> Result<(), GitSmartProtectedOwnerErrorV1> {
    if live.boot() != clock.boot
        || live.boottime_nanoseconds() < clock.protected_now
        || live.boottime_nanoseconds() >= protected_clock_deadline(clock)?
    {
        return Err(GitSmartProtectedOwnerErrorV1::InvalidEvidence);
    }
    Ok(())
}

fn protected_clock_deadline(
    clock: &GitSmartProtectedClockV1,
) -> Result<u64, GitSmartProtectedOwnerErrorV1> {
    clock
        .valid_until
        .checked_sub(clock.authenticated_at)
        .and_then(|seconds| seconds.checked_mul(1_000_000_000))
        .and_then(|width| clock.protected_now.checked_add(width))
        .ok_or(GitSmartProtectedOwnerErrorV1::InvalidEvidence)
}

fn read_all(journal: &mut Journal) -> Result<Vec<(Vec<u8>, Vec<u8>)>, JournalError> {
    let authority = journal.claim_protected_authority(RecordNamespace::RuntimeAuthority)?;
    Ok(authority
        .records()?
        .map(|(key, value)| (key.to_vec(), value.to_vec()))
        .collect())
}

fn unique_value<'record>(
    records: &'record [(Vec<u8>, Vec<u8>)],
    key: &[u8],
) -> Result<&'record [u8], GitSmartProtectedOwnerErrorV1> {
    let mut matching = records
        .iter()
        .filter(|(candidate, _)| candidate == key)
        .map(|(_, value)| value.as_slice());
    let value = matching
        .next()
        .ok_or(GitSmartProtectedOwnerErrorV1::InvalidEvidence)?;
    if matching.next().is_some() {
        return Err(GitSmartProtectedOwnerErrorV1::InvalidEvidence);
    }
    Ok(value)
}

fn limits() -> JournalLimits {
    JournalLimits {
        maximum_journal_bytes: 4 * 1024 * 1024 * 1024,
        maximum_record_bytes: 4 * 1024 * 1024,
        maximum_key_bytes: 96,
        maximum_records_per_transaction: 1,
        maximum_transaction_bytes: 4 * 1024 * 1024 + 512,
        maximum_transactions: 1_048_576,
        maximum_materialized_bytes: 1024 * 1024 * 1024,
        maximum_materialized_records: 1_048_576,
    }
}

fn array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], GitSmartProtectedOwnerErrorV1> {
    bytes
        .try_into()
        .map_err(|_| GitSmartProtectedOwnerErrorV1::InvalidEvidence)
}
