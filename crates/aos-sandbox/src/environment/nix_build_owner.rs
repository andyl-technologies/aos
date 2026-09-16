//! Fixed protected Nix-build capability and store-presentation ownership.
//!
//! ```text
//! AOSNXA01 || v1 || transport || bounds || boot || monotonic-interval || client-config || sha256
//! AOSNSP01 || v1 || kind || project || sandbox || generation || manifest || entries || sha256
//! AOSNXO01 || v1 || accepted || operation || request || outputs || receipt || sha256
//! ```

use std::path::Path;

use aos_sandbox_core::{
    MediaType, ObjectDescriptor, ObjectDigest, ProjectId, ResourceId, Revision, SandboxId,
};
use sha2::{Digest as _, Sha256};

use crate::journal::{Journal, JournalError, JournalLimits, RecordNamespace, RecoveryReport};

use super::{
    EnvironmentExecutionErrorV1, EnvironmentSelectorV1, FixedLiveAuthorityClockV1,
    LiveAuthorityClockSampleV1, NixBuildAuthorityFenceV1, NixBuildPolicyV1, NixBuildTransportV1,
    NixClientBoundaryV1, NixStorePathV1, NixStorePresentationEntryV1, NixStorePresentationKindV1,
    ReadOnlyNixStorePresentationV1, authority_clock::validate_bracketed_samples_v1,
    fixed_live_authority_clock_v1, nix_client::decode_nix_client_boundary_v1,
};

const ROOT: &str = "/var/lib/aos/sandbox/source-evidence";
const JOURNAL: &str = "nix-build-authority-v1.journal";
const OBSERVATION_JOURNAL: &str = "nix-build-observation-v1.journal";
const CAPABILITY_KEY: &[u8] = b"nix-build-capability-v1";
const PRESENTATION_PREFIX: &[u8] = b"nix-store-presentation-v1/";
const CAPABILITY_MAGIC: &[u8; 8] = b"AOSNXA01";
const PRESENTATION_MAGIC: &[u8; 8] = b"AOSNSP01";
const CAPABILITY_DOMAIN: &[u8] = b"aos.sandbox.environment.nix-build-capability.v1\0";
const PRESENTATION_DOMAIN: &[u8] = b"aos.sandbox.environment.nix-store-observation.v1\0";
const OBSERVATION_PREFIX: &[u8] = b"nix-build-observation-v1/";
const OBSERVATION_MAGIC: &[u8; 8] = b"AOSNXO01";
const OBSERVATION_DOMAIN: &[u8] = b"aos.sandbox.environment.nix-build-observation.v1\0";

/// Reports fixed Nix capability or store-observation failure.
#[derive(Debug, thiserror::Error)]
pub enum NixBuildProtectedOwnerErrorV1 {
    /// The fixed protected journal could not be opened or read.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// Capability or store observation is absent, stale, or noncanonical.
    #[error("protected Nix build capability is invalid or unavailable")]
    InvalidEvidence,
}

/// Owns the fixed Nix-build policy and exact observed store-path index.
pub struct NixBuildProtectedCapabilityOwnerV1 {
    journal: Journal,
    pinned: Vec<(Vec<u8>, Vec<u8>)>,
    policy: NixBuildPolicyV1,
    policy_commitment: ObjectDigest,
    authority_fence: NixBuildAuthorityFenceV1,
    client_boundary: NixClientBoundaryV1,
    clock: FixedLiveAuthorityClockV1,
    last_sample: LiveAuthorityClockSampleV1,
}

/// Carries one non-cloneable current policy and exact protected presentation.
#[must_use]
pub(crate) struct CurrentNixBuildCapabilityV1<'current> {
    policy: NixBuildPolicyV1,
    policy_commitment: ObjectDigest,
    authority_fence: NixBuildAuthorityFenceV1,
    client_boundary: NixClientBoundaryV1,
    presentation: ReadOnlyNixStorePresentationV1,
    _current: std::marker::PhantomData<&'current mut ()>,
}

/// Owns protected observations emitted by the future constrained build effect.
pub struct NixBuildProtectedObservationOwnerV1 {
    journal: Journal,
    pinned: Vec<(Vec<u8>, Vec<u8>)>,
}

/// Carries one sealed exact build observation.
#[must_use]
pub(crate) struct CurrentNixBuildObservationV1<'current> {
    request: ObjectDigest,
    operation: ResourceId,
    accepted: bool,
    outputs: Vec<ObjectDescriptor>,
    receipt: ObjectDigest,
    commitment: ObjectDigest,
    _current: std::marker::PhantomData<&'current mut ()>,
}

impl CurrentNixBuildObservationV1<'_> {
    pub(super) const fn request(&self) -> ObjectDigest {
        self.request
    }

    pub(super) const fn operation(&self) -> ResourceId {
        self.operation
    }

    pub(super) const fn accepted(&self) -> bool {
        self.accepted
    }

    pub(super) fn outputs(&self) -> &[ObjectDescriptor] {
        &self.outputs
    }

    pub(super) const fn receipt(&self) -> ObjectDigest {
        self.receipt
    }

    pub(super) const fn commitment(&self) -> ObjectDigest {
        self.commitment
    }
}

impl CurrentNixBuildCapabilityV1<'_> {
    pub(super) fn into_parts(
        self,
    ) -> (
        NixBuildPolicyV1,
        ObjectDigest,
        NixBuildAuthorityFenceV1,
        NixClientBoundaryV1,
        ReadOnlyNixStorePresentationV1,
    ) {
        (
            self.policy,
            self.policy_commitment,
            self.authority_fence,
            self.client_boundary,
            self.presentation,
        )
    }
}

impl NixBuildProtectedCapabilityOwnerV1 {
    /// Opens and pins the dedicated protected Nix authority journal.
    ///
    /// # Errors
    ///
    /// Returns [`NixBuildProtectedOwnerErrorV1`] unless exactly one current
    /// bounded capability and canonical presentation index are protected.
    pub fn open_fixed_protected() -> Result<(Self, RecoveryReport), NixBuildProtectedOwnerErrorV1> {
        Self::open_fixed_protected_with_clock(fixed_live_authority_clock_v1())
    }

    /// Opens protected Nix authority with an injected live boot-clock source.
    ///
    /// # Errors
    ///
    /// Returns [`NixBuildProtectedOwnerErrorV1`] unless the protected read is
    /// bracketed by current, non-regressing samples inside the recorded fence.
    fn open_fixed_protected_with_clock(
        mut clock: FixedLiveAuthorityClockV1,
    ) -> Result<(Self, RecoveryReport), NixBuildProtectedOwnerErrorV1> {
        let before = clock
            .sample()
            .map_err(|_| NixBuildProtectedOwnerErrorV1::InvalidEvidence)?;
        let (mut journal, report) = Journal::open_protected_at(Path::new(ROOT), JOURNAL, limits())?;
        let pinned = read_all(&mut journal)?;
        let capability = pinned
            .iter()
            .find(|(key, _)| key == CAPABILITY_KEY)
            .ok_or(NixBuildProtectedOwnerErrorV1::InvalidEvidence)?;
        if pinned
            .iter()
            .filter(|(key, _)| key == CAPABILITY_KEY)
            .count()
            != 1
            || pinned
                .iter()
                .any(|(key, _)| key != CAPABILITY_KEY && !key.starts_with(PRESENTATION_PREFIX))
        {
            return Err(NixBuildProtectedOwnerErrorV1::InvalidEvidence);
        }
        let after = clock
            .sample()
            .map_err(|_| NixBuildProtectedOwnerErrorV1::InvalidEvidence)?;
        let last_sample = validate_bracketed_samples_v1(before, after)
            .map_err(|_| NixBuildProtectedOwnerErrorV1::InvalidEvidence)?;
        let (policy, policy_commitment, authority_fence, client_boundary) =
            decode_capability(&capability.1, last_sample)?;
        Ok((
            Self {
                journal,
                pinned,
                policy,
                policy_commitment,
                authority_fence,
                client_boundary,
                clock,
                last_sample,
            },
            report,
        ))
    }

    /// Claims one exact current store presentation and fixed build policy.
    ///
    /// # Errors
    ///
    /// Returns [`NixBuildProtectedOwnerErrorV1`] when the fixed journal changed,
    /// expired, lacks the selector, or contains a substituted store path.
    pub(crate) fn claim<'current>(
        &'current mut self,
        selector: &EnvironmentSelectorV1,
    ) -> Result<CurrentNixBuildCapabilityV1<'current>, NixBuildProtectedOwnerErrorV1> {
        self.revalidate()?;
        let mut key = Vec::with_capacity(PRESENTATION_PREFIX.len() + 32);
        key.extend_from_slice(PRESENTATION_PREFIX);
        key.extend_from_slice(selector.manifest().digest().as_bytes());
        let encoded = self
            .pinned
            .iter()
            .find(|(candidate, _)| candidate == &key)
            .map(|(_, value)| value.as_slice())
            .ok_or(NixBuildProtectedOwnerErrorV1::InvalidEvidence)?;
        let presentation = decode_presentation(encoded, selector)?;
        Ok(CurrentNixBuildCapabilityV1 {
            policy: self.policy,
            policy_commitment: self.policy_commitment,
            authority_fence: self.authority_fence,
            client_boundary: self.client_boundary,
            presentation,
            _current: std::marker::PhantomData,
        })
    }

    pub(super) fn revalidate(&mut self) -> Result<(), NixBuildProtectedOwnerErrorV1> {
        let before = self
            .clock
            .sample()
            .map_err(|_| NixBuildProtectedOwnerErrorV1::InvalidEvidence)?;
        if before.boot() != self.last_sample.boot()
            || before.boottime_nanoseconds() < self.last_sample.boottime_nanoseconds()
        {
            return Err(NixBuildProtectedOwnerErrorV1::InvalidEvidence);
        }
        let current = read_all(&mut self.journal)?;
        if current != self.pinned {
            return Err(NixBuildProtectedOwnerErrorV1::InvalidEvidence);
        }
        let after = self
            .clock
            .sample()
            .map_err(|_| NixBuildProtectedOwnerErrorV1::InvalidEvidence)?;
        let current_sample = validate_bracketed_samples_v1(before, after)
            .map_err(|_| NixBuildProtectedOwnerErrorV1::InvalidEvidence)?;
        let (_, commitment, fence, client_boundary) = decode_capability(
            &current
                .iter()
                .find(|(key, _)| key == CAPABILITY_KEY)
                .ok_or(NixBuildProtectedOwnerErrorV1::InvalidEvidence)?
                .1,
            current_sample,
        )?;
        if commitment != self.policy_commitment
            || fence != self.authority_fence
            || client_boundary != self.client_boundary
        {
            return Err(NixBuildProtectedOwnerErrorV1::InvalidEvidence);
        }
        self.last_sample = current_sample;
        Ok(())
    }
}

impl NixBuildProtectedObservationOwnerV1 {
    /// Opens and pins the dedicated protected Nix effect-observation journal.
    ///
    /// # Errors
    ///
    /// Returns [`NixBuildProtectedOwnerErrorV1`] when protected storage is
    /// unavailable or contains a foreign record family.
    pub fn open_fixed_protected() -> Result<(Self, RecoveryReport), NixBuildProtectedOwnerErrorV1> {
        let (mut journal, report) =
            Journal::open_protected_at(Path::new(ROOT), OBSERVATION_JOURNAL, limits())?;
        let pinned = read_all(&mut journal)?;
        if pinned
            .iter()
            .any(|(key, _)| !key.starts_with(OBSERVATION_PREFIX))
        {
            return Err(NixBuildProtectedOwnerErrorV1::InvalidEvidence);
        }
        Ok((Self { journal, pinned }, report))
    }

    /// Claims the unique exact observation for one durable build operation.
    ///
    /// # Errors
    ///
    /// Returns [`NixBuildProtectedOwnerErrorV1`] when the fixed journal changed
    /// or the operation has no unique canonical observation.
    pub(crate) fn claim<'current>(
        &'current mut self,
        operation: ResourceId,
        request: ObjectDigest,
    ) -> Result<CurrentNixBuildObservationV1<'current>, NixBuildProtectedOwnerErrorV1> {
        let current = read_all(&mut self.journal)?;
        if current != self.pinned {
            return Err(NixBuildProtectedOwnerErrorV1::InvalidEvidence);
        }
        let mut key = Vec::with_capacity(OBSERVATION_PREFIX.len() + 16);
        key.extend_from_slice(OBSERVATION_PREFIX);
        key.extend_from_slice(operation.as_bytes());
        let mut matching = self
            .pinned
            .iter()
            .filter(|(candidate, _)| candidate == &key)
            .map(|(_, encoded)| decode_observation(encoded, operation, request));
        let observation = matching
            .next()
            .ok_or(NixBuildProtectedOwnerErrorV1::InvalidEvidence)??;
        if matching.next().is_some() {
            return Err(NixBuildProtectedOwnerErrorV1::InvalidEvidence);
        }
        Ok(observation)
    }
}

fn read_all(journal: &mut Journal) -> Result<Vec<(Vec<u8>, Vec<u8>)>, JournalError> {
    let authority = journal.claim_protected_authority(RecordNamespace::RuntimeAuthority)?;
    Ok(authority
        .records()?
        .map(|(key, value)| (key.to_vec(), value.to_vec()))
        .collect())
}

fn decode_capability(
    encoded: &[u8],
    current: LiveAuthorityClockSampleV1,
) -> Result<
    (
        NixBuildPolicyV1,
        ObjectDigest,
        NixBuildAuthorityFenceV1,
        NixClientBoundaryV1,
    ),
    NixBuildProtectedOwnerErrorV1,
> {
    if encoded.len() < 197 {
        return Err(NixBuildProtectedOwnerErrorV1::InvalidEvidence);
    }
    let (body, stored) = encoded.split_at(encoded.len() - 32);
    let commitment = ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(CAPABILITY_DOMAIN)
            .chain_update(body)
            .finalize()
            .into(),
    );
    if stored != commitment.as_bytes() || &body[..8] != CAPABILITY_MAGIC || body[8] != 1 {
        return Err(NixBuildProtectedOwnerErrorV1::InvalidEvidence);
    }
    let transport = match body[9] {
        1 => NixBuildTransportV1::UntrustedDaemonClient,
        2 => NixBuildTransportV1::NarrowingProxy,
        _ => return Err(NixBuildProtectedOwnerErrorV1::InvalidEvidence),
    };
    if body[10..16] != [0; 6] || body[28..32] != [0; 4] {
        return Err(NixBuildProtectedOwnerErrorV1::InvalidEvidence);
    }
    let maximum_control_bytes = u64::from_be_bytes(array(&body[16..24])?);
    let maximum_output_objects = u32::from_be_bytes(array(&body[24..28])?);
    let boot = ObjectDigest::from_bytes(array(&body[32..64])?);
    let valid_from = u64::from_be_bytes(array(&body[64..72])?);
    let valid_until = u64::from_be_bytes(array(&body[72..80])?);
    let client_length = usize::try_from(u32::from_be_bytes(array(&body[80..84])?))
        .map_err(|_| NixBuildProtectedOwnerErrorV1::InvalidEvidence)?;
    if client_length != body.len().saturating_sub(84) {
        return Err(NixBuildProtectedOwnerErrorV1::InvalidEvidence);
    }
    let client_boundary = decode_nix_client_boundary_v1(&body[84..])
        .map_err(|_| NixBuildProtectedOwnerErrorV1::InvalidEvidence)?;
    let authority_fence = NixBuildAuthorityFenceV1::from_protected(boot, valid_from, valid_until)
        .map_err(|_| NixBuildProtectedOwnerErrorV1::InvalidEvidence)?;
    if !authority_fence.admits(current) {
        return Err(NixBuildProtectedOwnerErrorV1::InvalidEvidence);
    }
    let policy = NixBuildPolicyV1::from_protected(
        transport,
        maximum_control_bytes,
        maximum_output_objects,
        false,
    )
    .map_err(|_| NixBuildProtectedOwnerErrorV1::InvalidEvidence)?;
    if !client_boundary.matches_policy(policy) {
        return Err(NixBuildProtectedOwnerErrorV1::InvalidEvidence);
    }
    Ok((policy, commitment, authority_fence, client_boundary))
}

fn decode_presentation(
    encoded: &[u8],
    selector: &EnvironmentSelectorV1,
) -> Result<ReadOnlyNixStorePresentationV1, NixBuildProtectedOwnerErrorV1> {
    if encoded.len() < 125 {
        return Err(NixBuildProtectedOwnerErrorV1::InvalidEvidence);
    }
    let (body, stored) = encoded.split_at(encoded.len() - 32);
    let digest = Sha256::new()
        .chain_update(PRESENTATION_DOMAIN)
        .chain_update(body)
        .finalize();
    if stored != digest.as_slice() {
        return Err(NixBuildProtectedOwnerErrorV1::InvalidEvidence);
    }
    let mut cursor = Cursor::new(body);
    if cursor.take::<8>()? != *PRESENTATION_MAGIC || cursor.take::<1>()? != [1] {
        return Err(NixBuildProtectedOwnerErrorV1::InvalidEvidence);
    }
    let kind = match cursor.take::<1>()?[0] {
        1 => NixStorePresentationKindV1::ReadOnlyClosureView,
        2 => NixStorePresentationKindV1::ReadOnlyUserspaceView,
        _ => return Err(NixBuildProtectedOwnerErrorV1::InvalidEvidence),
    };
    if cursor.take::<6>()? != [0; 6]
        || ProjectId::from_bytes(cursor.take::<16>()?) != selector.manifest_record().project()
        || SandboxId::from_bytes(cursor.take::<16>()?) != selector.manifest_record().sandbox()
        || Revision::new(u64::from_be_bytes(cursor.take::<8>()?)) != selector.generation()
        || ObjectDigest::from_bytes(cursor.take::<32>()?) != selector.manifest().digest()
    {
        return Err(NixBuildProtectedOwnerErrorV1::InvalidEvidence);
    }
    let count = usize::try_from(u32::from_be_bytes(cursor.take::<4>()?))
        .map_err(|_| NixBuildProtectedOwnerErrorV1::InvalidEvidence)?;
    if count == 0 || count > super::MAXIMUM_NIX_STORE_PRESENTATION_OBJECTS {
        return Err(NixBuildProtectedOwnerErrorV1::InvalidEvidence);
    }
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(count)
        .map_err(|_| NixBuildProtectedOwnerErrorV1::InvalidEvidence)?;
    for _ in 0..count {
        let media_len = usize::from(u16::from_be_bytes(cursor.take::<2>()?));
        let media = std::str::from_utf8(cursor.take_slice(media_len)?)
            .map_err(|_| NixBuildProtectedOwnerErrorV1::InvalidEvidence)?;
        let descriptor = ObjectDescriptor::new(
            MediaType::new(media.to_owned())
                .map_err(|_| NixBuildProtectedOwnerErrorV1::InvalidEvidence)?,
            ObjectDigest::from_bytes(cursor.take::<32>()?),
            u64::from_be_bytes(cursor.take::<8>()?),
        );
        let path_len = usize::from(u16::from_be_bytes(cursor.take::<2>()?));
        let path = std::str::from_utf8(cursor.take_slice(path_len)?)
            .map_err(|_| NixBuildProtectedOwnerErrorV1::InvalidEvidence)?;
        entries.push(
            NixStorePresentationEntryV1::from_protected(
                descriptor,
                NixStorePathV1::from_protected(path.to_owned())
                    .map_err(|_| NixBuildProtectedOwnerErrorV1::InvalidEvidence)?,
            )
            .map_err(|_| NixBuildProtectedOwnerErrorV1::InvalidEvidence)?,
        );
    }
    if !cursor.is_empty() {
        return Err(NixBuildProtectedOwnerErrorV1::InvalidEvidence);
    }
    ReadOnlyNixStorePresentationV1::from_protected(selector, kind, entries)
        .map_err(|_| NixBuildProtectedOwnerErrorV1::InvalidEvidence)
}

fn decode_observation<'current>(
    encoded: &[u8],
    operation: ResourceId,
    request: ObjectDigest,
) -> Result<CurrentNixBuildObservationV1<'current>, NixBuildProtectedOwnerErrorV1> {
    if encoded.len() < 132 {
        return Err(NixBuildProtectedOwnerErrorV1::InvalidEvidence);
    }
    let (body, stored) = encoded.split_at(encoded.len() - 32);
    let commitment = ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(OBSERVATION_DOMAIN)
            .chain_update(body)
            .finalize()
            .into(),
    );
    if stored != commitment.as_bytes() {
        return Err(NixBuildProtectedOwnerErrorV1::InvalidEvidence);
    }
    let mut cursor = Cursor::new(body);
    if cursor.take::<8>()? != *OBSERVATION_MAGIC
        || cursor.take::<1>()? != [1]
        || cursor.take::<1>()?[0] > 1
        || cursor.take::<6>()? != [0; 6]
        || ResourceId::from_bytes(cursor.take::<16>()?) != operation
        || ObjectDigest::from_bytes(cursor.take::<32>()?) != request
    {
        return Err(NixBuildProtectedOwnerErrorV1::InvalidEvidence);
    }
    let accepted = body[9] == 1;
    let count = usize::try_from(u32::from_be_bytes(cursor.take::<4>()?))
        .map_err(|_| NixBuildProtectedOwnerErrorV1::InvalidEvidence)?;
    if count > super::MAXIMUM_NIX_STORE_PRESENTATION_OBJECTS
        || (accepted && count == 0)
        || (!accepted && count != 0)
    {
        return Err(NixBuildProtectedOwnerErrorV1::InvalidEvidence);
    }
    let mut outputs = Vec::new();
    outputs
        .try_reserve_exact(count)
        .map_err(|_| NixBuildProtectedOwnerErrorV1::InvalidEvidence)?;
    for _ in 0..count {
        let media_len = usize::from(u16::from_be_bytes(cursor.take::<2>()?));
        let media = std::str::from_utf8(cursor.take_slice(media_len)?)
            .map_err(|_| NixBuildProtectedOwnerErrorV1::InvalidEvidence)?;
        outputs.push(ObjectDescriptor::new(
            MediaType::new(media.to_owned())
                .map_err(|_| NixBuildProtectedOwnerErrorV1::InvalidEvidence)?,
            ObjectDigest::from_bytes(cursor.take::<32>()?),
            u64::from_be_bytes(cursor.take::<8>()?),
        ));
    }
    let receipt = ObjectDigest::from_bytes(cursor.take::<32>()?);
    if !cursor.is_empty()
        || receipt.as_bytes() == &[0; 32]
        || outputs
            .iter()
            .any(|output| output.digest().as_bytes() == &[0; 32] || output.encoded_size() == 0)
        || !outputs.windows(2).all(|pair| pair[0] < pair[1])
    {
        return Err(NixBuildProtectedOwnerErrorV1::InvalidEvidence);
    }
    Ok(CurrentNixBuildObservationV1 {
        request,
        operation,
        accepted,
        outputs,
        receipt,
        commitment,
        _current: std::marker::PhantomData,
    })
}

fn limits() -> JournalLimits {
    JournalLimits {
        maximum_journal_bytes: 4 * 1024 * 1024 * 1024,
        maximum_record_bytes: 96 * 1024 * 1024,
        maximum_key_bytes: 96,
        maximum_records_per_transaction: 1,
        maximum_transaction_bytes: 96 * 1024 * 1024 + 512,
        maximum_transactions: 262_144,
        maximum_materialized_bytes: 512 * 1024 * 1024,
        maximum_materialized_records: super::MAXIMUM_NIX_STORE_PRESENTATION_OBJECTS + 1,
    }
}

fn array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], NixBuildProtectedOwnerErrorV1> {
    bytes
        .try_into()
        .map_err(|_| NixBuildProtectedOwnerErrorV1::InvalidEvidence)
}

struct Cursor<'a> {
    bytes: &'a [u8],
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], NixBuildProtectedOwnerErrorV1> {
        let Some((value, rest)) = self.bytes.split_at_checked(N) else {
            return Err(NixBuildProtectedOwnerErrorV1::InvalidEvidence);
        };
        self.bytes = rest;
        array(value)
    }

    fn take_slice(&mut self, length: usize) -> Result<&'a [u8], NixBuildProtectedOwnerErrorV1> {
        let Some((value, rest)) = self.bytes.split_at_checked(length) else {
            return Err(NixBuildProtectedOwnerErrorV1::InvalidEvidence);
        };
        self.bytes = rest;
        Ok(value)
    }

    const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}
