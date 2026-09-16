//! Protected fixed-owner lease issuance for dormant multi-node coordination.
//!
//! The authority commits an unsigned claim before contacting its contained
//! issuer, verifies the returned generation, nonce, interval, signatures, and
//! exact prior-lease CAS against a live paired clock, and commits all returned
//! artifacts before exposing them. An opaque recovery value names the durable
//! intent across restart; retry always uses the original claim binding.
//!
//! ```text
//! bootstrap = "AOSMOL01" || policy-len:u32be || canonical-policy ||
//!             ownership-public-key[32] || sha256(domain || preceding-bytes)
//! response  = "AOSMOI01" || request-id[16] || claim-digest[32] ||
//!             sized-lease || sized-signature || sized-receipt ||
//!             sized-receipt-signature || sha256(domain || preceding-bytes)
//! ```

use std::fs::File;
use std::io::Read as _;
use std::os::fd::AsFd as _;
use std::path::Path;

use aos_proto::aos::sandbox::coordinator::v1 as wire;
use aos_sandbox_core::format::{decode_ownership_lease, decode_trust_policy};
use aos_sandbox_core::{
    DecodeLimits, KeyUsage, MediaType, OwnershipLeaseTrustAnchor, PortableMediaType,
    RawClockProvenance, RawPairedClockSample, SignaturePurpose, descriptor_for_bytes,
};
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_ownership_protocol::OwnershipAuthorityError;
use aos_sandbox_ownership_protocol::protocol::OwnershipTransactionReferenceV1;
use sha2::{Digest as _, Sha256};

use crate::ownership_authority::{
    DurableOwnershipAuthority, DurableOwnershipAuthorityError, DurableOwnershipBeginOutcome,
    DurableOwnershipQueryOutcome, OwnershipAuthority, OwnershipAuthorityVerifier, OwnershipClaimV1,
    ProtectedOwnershipClockError, UnverifiedOwnershipLeaseResponse,
};

const PROTECTED_MULTI_NODE_DIRECTORY: &str = "/var/lib/aos/sandbox/multi-node";
const PROTECTED_LEASE_JOURNAL: &str = "coordinator-ownership-v1.journal";
const PROTECTED_LEASE_BOOTSTRAP: &str = "coordinator-ownership-bootstrap-v1.bin";
const PROTECTED_LEASE_RESPONSE_INBOX: &str = "coordinator-ownership-response-v1.bin";
const PROTECTED_CLOCK_PROVENANCE: [u8; 16] = *b"AOSMULTICLOCKV1!";
const MAXIMUM_BOOTSTRAP_BYTES: usize = 128 * 1024;
const MAXIMUM_RESPONSE_INBOX_BYTES: usize = 256 * 1024;

/// Reports failure before an issuance attempt can retain a durable recovery handle.
#[derive(Debug, thiserror::Error)]
pub enum ProtectedLeaseAuthorityErrorV1 {
    /// The fixed protected journal could not be opened or authenticated.
    #[error("protected multi-node lease authority failed: {0}")]
    Authority(#[from] DurableOwnershipAuthorityError),
}

/// Names one exact durable unsigned intent without exposing mutable claim fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectedLeaseRecoveryV1 {
    reference: OwnershipTransactionReferenceV1,
}

impl ProtectedLeaseRecoveryV1 {
    fn for_claim(claim: &OwnershipClaimV1) -> Self {
        Self {
            reference: OwnershipTransactionReferenceV1::from_claim(claim),
        }
    }
}

/// Owns exact lease artifacts that were read back from committed protected state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedCommittedLeaseV1 {
    response: UnverifiedOwnershipLeaseResponse,
}

impl ProtectedCommittedLeaseV1 {
    fn from_durable(response: UnverifiedOwnershipLeaseResponse) -> Self {
        Self { response }
    }

    /// Returns the generated, typed protobuf representation of the committed lease.
    ///
    /// # Errors
    ///
    /// Returns [`super::InvalidMultiNodeProtocol::NonCanonicalFrame`] if the
    /// protected canonical lease cannot be decoded exactly. This would indicate
    /// protected-state corruption because the authority verifies it before commit.
    pub fn protobuf(&self) -> Result<wire::AssignmentLease, super::InvalidMultiNodeProtocol> {
        let lease = decode_ownership_lease(
            self.response.lease(),
            DecodeLimits {
                maximum_bytes: self.response.lease().len(),
                ..DecodeLimits::default()
            },
        )
        .map_err(|_| super::InvalidMultiNodeProtocol::NonCanonicalFrame)?;
        let assignment = lease.assignment();
        Ok(wire::AssignmentLease {
            sandbox_uid: assignment.sandbox().as_bytes().to_vec(),
            incarnation_uid: assignment.incarnation().as_bytes().to_vec(),
            assignment_epoch: assignment.epoch().get(),
            assignment_sha256: assignment.digest().as_bytes().to_vec(),
            node_uid: lease.node().as_bytes().to_vec(),
            generation: lease.lease_generation(),
            issued_at_unix_seconds: lease.authority_issued_seconds(),
            expires_at_unix_seconds: lease.authority_expires_seconds(),
            maximum_clock_skew_seconds: lease.maximum_clock_skew_seconds(),
            renewal_nonce: lease.renewal_nonce().to_vec(),
            canonical_lease: self.response.lease().to_vec(),
            canonical_signature: self.response.signature().to_vec(),
            canonical_receipt: self.response.receipt().to_vec(),
            canonical_receipt_signature: self.response.receipt_signature().to_vec(),
        })
    }

    /// Returns the exact committed canonical lease bytes.
    #[must_use]
    pub fn lease(&self) -> &[u8] {
        self.response.lease()
    }

    /// Returns the exact committed canonical detached signature bytes.
    #[must_use]
    pub fn signature(&self) -> &[u8] {
        self.response.signature()
    }

    /// Returns the exact committed authority receipt bytes.
    #[must_use]
    pub fn receipt(&self) -> &[u8] {
        self.response.receipt()
    }

    /// Returns the exact committed receipt-signature bytes.
    #[must_use]
    pub fn receipt_signature(&self) -> &[u8] {
        self.response.receipt_signature()
    }
}

/// Classifies lease issuance without ever discarding an ambiguous durable intent.
#[must_use]
pub enum ProtectedLeaseIssueOutcomeV1 {
    /// Exact issuer artifacts are present in protected state and may be read.
    Committed(ProtectedCommittedLeaseV1),
    /// The durable intent must be reopened and resolved using the retained token.
    RecoveryRequired {
        /// Opaque exact request-and-claim binding retained across restart.
        recovery: ProtectedLeaseRecoveryV1,
        /// Opaque failure from issuance, clock validation, verification, or commit.
        error: DurableOwnershipAuthorityError,
    },
}

/// Owns the fixed protected ownership bootstrap, issuer inbox, and lease journal.
///
/// Construction accepts no trust anchor, public key, issuer, clock, path, or
/// generation from its caller. The ownership policy and exact issuer response
/// are loaded from root-owned fixed files; the durable reducer independently
/// verifies every response before making its bytes observable.
pub struct ProtectedFixedMultiNodeLeaseOwnerV1 {
    authority: ProtectedMultiNodeLeaseAuthorityV1<FixedProtectedOwnershipIssuerV1>,
}

impl ProtectedFixedMultiNodeLeaseOwnerV1 {
    /// Opens the complete fixed-root dormant ownership composition.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedLeaseAuthorityErrorV1`] unless the protected
    /// bootstrap, pinned ownership key, issuer inbox root, lease journal, and
    /// live clock owner all open and authenticate exactly.
    pub fn open_fixed_protected() -> Result<Self, ProtectedLeaseAuthorityErrorV1> {
        let (verifier, issuer) = load_fixed_ownership_bootstrap()?;
        Ok(Self {
            authority: ProtectedMultiNodeLeaseAuthorityV1::open_fixed_protected(verifier, issuer)?,
        })
    }

    /// Durably issues one caller-authored claim through the fixed protected issuer.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedLeaseAuthorityErrorV1`] only before a durable intent
    /// exists; later ambiguity is retained in the returned recovery value.
    pub fn issue(
        &mut self,
        claim: &OwnershipClaimV1,
    ) -> Result<ProtectedLeaseIssueOutcomeV1, ProtectedLeaseAuthorityErrorV1> {
        self.authority.issue(claim)
    }

    /// Resolves or exactly retries a previously retained durable intent.
    #[must_use]
    pub fn recover(&mut self, recovery: ProtectedLeaseRecoveryV1) -> ProtectedLeaseIssueOutcomeV1 {
        self.authority.recover(recovery)
    }
}

struct FixedProtectedOwnershipIssuerV1 {
    directory: File,
}

impl OwnershipAuthority for FixedProtectedOwnershipIssuerV1 {
    fn acquire(
        &mut self,
        claim: &OwnershipClaimV1,
    ) -> Result<UnverifiedOwnershipLeaseResponse, OwnershipAuthorityError> {
        self.read_exact_response(claim)
    }

    fn renew(
        &mut self,
        claim: &OwnershipClaimV1,
    ) -> Result<UnverifiedOwnershipLeaseResponse, OwnershipAuthorityError> {
        self.read_exact_response(claim)
    }

    fn advance(
        &mut self,
        claim: &OwnershipClaimV1,
    ) -> Result<UnverifiedOwnershipLeaseResponse, OwnershipAuthorityError> {
        self.read_exact_response(claim)
    }
}

impl FixedProtectedOwnershipIssuerV1 {
    fn read_exact_response(
        &self,
        claim: &OwnershipClaimV1,
    ) -> Result<UnverifiedOwnershipLeaseResponse, OwnershipAuthorityError> {
        let bytes = read_protected_regular_at(
            &self.directory,
            PROTECTED_LEASE_RESPONSE_INBOX,
            MAXIMUM_RESPONSE_INBOX_BYTES,
        )
        .map_err(|_| OwnershipAuthorityError::Unavailable)?;
        decode_fixed_issuer_response(&bytes, claim)
    }
}

/// Owns one fixed protected lease journal, issuer, and live paired clock source.
///
/// The issuer is deliberately private and has no signing method on this API.
/// Claims can reach it only after durable admission and exact CAS validation.
pub(crate) struct ProtectedMultiNodeLeaseAuthorityV1<I> {
    durable: DurableOwnershipAuthority,
    issuer: I,
    clock: ProtectedLeaseClockV1,
}

impl<I: OwnershipAuthority> ProtectedMultiNodeLeaseAuthorityV1<I> {
    /// Opens the dormant fixed-root owner with one protected verifier generation.
    ///
    /// This constructs no socket, listener, task, readiness marker, or service
    /// registration. The supplied issuer becomes inaccessible except through
    /// the durable issue and recovery operations below.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedLeaseAuthorityErrorV1`] when the fixed protected
    /// journal cannot be opened or its full history fails authentication.
    fn open_fixed_protected(
        verifier: OwnershipAuthorityVerifier,
        issuer: I,
    ) -> Result<Self, ProtectedLeaseAuthorityErrorV1> {
        let (durable, _) = DurableOwnershipAuthority::open_protected(
            Path::new(PROTECTED_MULTI_NODE_DIRECTORY),
            PROTECTED_LEASE_JOURNAL,
            verifier,
        )?;
        Ok(Self {
            durable,
            issuer,
            clock: ProtectedLeaseClockV1::open()?,
        })
    }

    /// Durably admits, issues, verifies, commits, and reads back one exact claim.
    ///
    /// The claim cannot choose lease generation, renewal nonce, issue time, or
    /// expiry. Acquire is expected-absence CAS; renewal and advancement require
    /// the exact prior generation and signed-lease digest and are checked by the
    /// protected reducer before and after issuer contact.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedLeaseAuthorityErrorV1`] only when durable admission
    /// itself fails. Every failure after admission retains the opaque recovery
    /// binding in [`ProtectedLeaseIssueOutcomeV1::RecoveryRequired`].
    pub(crate) fn issue(
        &mut self,
        claim: &OwnershipClaimV1,
    ) -> Result<ProtectedLeaseIssueOutcomeV1, ProtectedLeaseAuthorityErrorV1> {
        let recovery = ProtectedLeaseRecoveryV1::for_claim(claim);
        match self.durable.begin(claim)? {
            DurableOwnershipBeginOutcome::Replay(response) => {
                Ok(ProtectedLeaseIssueOutcomeV1::Committed(
                    ProtectedCommittedLeaseV1::from_durable(*response),
                ))
            }
            DurableOwnershipBeginOutcome::Pending => Ok(self.complete(recovery)),
        }
    }

    /// Resolves or exactly retries a retained durable intent after reopen.
    ///
    /// The recovery value cannot alter the claim, prior lease, generation, or
    /// issuer inputs. A committed readback returns the original exact artifacts;
    /// a pending readback invokes the issuer's required exact idempotent retry.
    #[must_use]
    pub(crate) fn recover(
        &mut self,
        recovery: ProtectedLeaseRecoveryV1,
    ) -> ProtectedLeaseIssueOutcomeV1 {
        match self.durable.query(recovery.reference) {
            Ok(DurableOwnershipQueryOutcome::Completed(response)) => {
                ProtectedLeaseIssueOutcomeV1::Committed(ProtectedCommittedLeaseV1::from_durable(
                    *response,
                ))
            }
            Ok(DurableOwnershipQueryOutcome::Pending { .. }) => self.complete(recovery),
            Ok(DurableOwnershipQueryOutcome::Absent) => {
                ProtectedLeaseIssueOutcomeV1::RecoveryRequired {
                    recovery,
                    error: DurableOwnershipAuthorityError::IntentNotFound,
                }
            }
            Err(error) => ProtectedLeaseIssueOutcomeV1::RecoveryRequired { recovery, error },
        }
    }

    /// Reopens and resolves one exact transaction binding retained by a controller.
    ///
    /// The protected journal contains the authoritative claim bytes. Supplying
    /// only a request ID and claim digest cannot create or alter an intent, and
    /// exact query rejects rebinding before an issuer can be contacted. This is
    /// the restart entry point for a recovery token retained outside the process.
    #[must_use]
    pub(crate) fn recover_exact(
        &mut self,
        reference: OwnershipTransactionReferenceV1,
    ) -> ProtectedLeaseIssueOutcomeV1 {
        self.recover(ProtectedLeaseRecoveryV1 { reference })
    }

    fn complete(&mut self, recovery: ProtectedLeaseRecoveryV1) -> ProtectedLeaseIssueOutcomeV1 {
        let result = self.durable.complete(
            *recovery.reference.request_id(),
            &mut self.issuer,
            &mut || self.clock.sample(),
        );
        match result {
            Ok(response) => ProtectedLeaseIssueOutcomeV1::Committed(
                ProtectedCommittedLeaseV1::from_durable(response),
            ),
            Err(error) => ProtectedLeaseIssueOutcomeV1::RecoveryRequired { recovery, error },
        }
    }
}

fn load_fixed_ownership_bootstrap() -> Result<
    (OwnershipAuthorityVerifier, FixedProtectedOwnershipIssuerV1),
    ProtectedLeaseAuthorityErrorV1,
> {
    let descriptor = rustix::fs::open(
        PROTECTED_MULTI_NODE_DIRECTORY,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| fixed_bootstrap_error())?;
    let metadata = rustix::fs::fstat(&descriptor).map_err(|_| fixed_bootstrap_error())?;
    if metadata.st_uid != 0
        || metadata.st_mode & 0o022 != 0
        || rustix::fs::FileType::from_raw_mode(metadata.st_mode) != rustix::fs::FileType::Directory
    {
        return Err(fixed_bootstrap_error());
    }
    let directory = File::from(descriptor);
    let bytes = read_protected_regular_at(
        &directory,
        PROTECTED_LEASE_BOOTSTRAP,
        MAXIMUM_BOOTSTRAP_BYTES,
    )
    .map_err(|_| fixed_bootstrap_error())?;
    if bytes.len() < 8 + 4 + 32 + 32 || &bytes[..8] != b"AOSMOL01" {
        return Err(fixed_bootstrap_error());
    }
    let (payload, retained_checksum) = bytes.split_at(bytes.len() - 32);
    let expected_checksum: [u8; 32] = Sha256::new()
        .chain_update(b"aos.sandbox.multi-node.ownership-bootstrap.v1\0")
        .chain_update(payload)
        .finalize()
        .into();
    if retained_checksum != expected_checksum {
        return Err(fixed_bootstrap_error());
    }
    let mut cursor = 8;
    let policy_length =
        usize::try_from(read_u32(payload, &mut cursor)?).map_err(|_| fixed_bootstrap_error())?;
    if policy_length == 0 || policy_length > 64 * 1024 {
        return Err(fixed_bootstrap_error());
    }
    let policy_bytes = take_slice(payload, &mut cursor, policy_length)?.to_vec();
    let public_key: [u8; 32] = take_slice(payload, &mut cursor, 32)?
        .try_into()
        .map_err(|_| fixed_bootstrap_error())?;
    if cursor != payload.len() {
        return Err(fixed_bootstrap_error());
    }
    let policy = decode_trust_policy(&policy_bytes, DecodeLimits::default())
        .map_err(|_| fixed_bootstrap_error())?;
    aos_sandbox_core::validate_required_features(policy.required_features())
        .map_err(|_| fixed_bootstrap_error())?;
    let [authority] = policy.allowed_keys() else {
        return Err(fixed_bootstrap_error());
    };
    let authority = authority.clone();
    if policy.purpose() != SignaturePurpose::OwnershipLease
        || authority.usage() != KeyUsage::OwnershipLease
    {
        return Err(fixed_bootstrap_error());
    }
    let media_type = MediaType::new(PortableMediaType::TrustPolicy.as_str().to_owned())
        .map_err(|_| fixed_bootstrap_error())?;
    let descriptor = descriptor_for_bytes(media_type, &policy_bytes);
    let anchor = OwnershipLeaseTrustAnchor::from_trusted_configuration(
        policy_bytes,
        descriptor,
        policy.trust_scope(),
        authority.clone(),
        public_key,
        DecodeLimits::default(),
    )
    .map_err(|_| fixed_bootstrap_error())?;
    Ok((
        OwnershipAuthorityVerifier::new(anchor, authority),
        FixedProtectedOwnershipIssuerV1 { directory },
    ))
}

fn read_protected_regular_at(
    directory: &File,
    name: &str,
    maximum_bytes: usize,
) -> Result<Vec<u8>, ()> {
    let descriptor = rustix::fs::openat(
        directory.as_fd(),
        name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| ())?;
    let metadata = rustix::fs::fstat(&descriptor).map_err(|_| ())?;
    let size = usize::try_from(metadata.st_size).map_err(|_| ())?;
    if rustix::fs::FileType::from_raw_mode(metadata.st_mode) != rustix::fs::FileType::RegularFile
        || metadata.st_uid != 0
        || metadata.st_nlink != 1
        || metadata.st_mode & 0o7777 != 0o600
        || size == 0
        || size > maximum_bytes
    {
        return Err(());
    }
    let mut bytes = Vec::with_capacity(size);
    File::from(descriptor)
        .take(u64::try_from(maximum_bytes).map_err(|_| ())? + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.len() != size {
        return Err(());
    }
    Ok(bytes)
}

fn decode_fixed_issuer_response(
    bytes: &[u8],
    claim: &OwnershipClaimV1,
) -> Result<UnverifiedOwnershipLeaseResponse, OwnershipAuthorityError> {
    if bytes.len() < 8 + 16 + 32 + 16 + 32 || &bytes[..8] != b"AOSMOI01" {
        return Err(OwnershipAuthorityError::Unavailable);
    }
    let (payload, retained_checksum) = bytes.split_at(bytes.len() - 32);
    let expected_checksum: [u8; 32] = Sha256::new()
        .chain_update(b"aos.sandbox.multi-node.ownership-response.v1\0")
        .chain_update(payload)
        .finalize()
        .into();
    if retained_checksum != expected_checksum {
        return Err(OwnershipAuthorityError::Unavailable);
    }
    let mut cursor = 8;
    let request_id: [u8; 16] = take_slice(payload, &mut cursor, 16)
        .map_err(|_| OwnershipAuthorityError::Unavailable)?
        .try_into()
        .map_err(|_| OwnershipAuthorityError::Unavailable)?;
    let claim_digest: [u8; 32] = take_slice(payload, &mut cursor, 32)
        .map_err(|_| OwnershipAuthorityError::Unavailable)?
        .try_into()
        .map_err(|_| OwnershipAuthorityError::Unavailable)?;
    if &request_id != claim.request_id() || claim_digest != *claim.digest().as_bytes() {
        return Err(OwnershipAuthorityError::IdempotencyConflict);
    }
    let lease = take_length_prefixed(payload, &mut cursor, 64 * 1024)?;
    let signature = take_length_prefixed(payload, &mut cursor, 64 * 1024)?;
    let receipt = take_length_prefixed(payload, &mut cursor, 1024)?;
    let receipt_signature = take_length_prefixed(payload, &mut cursor, 64 * 1024)?;
    if cursor != payload.len() {
        return Err(OwnershipAuthorityError::Unavailable);
    }
    UnverifiedOwnershipLeaseResponse::from_transport(
        lease.to_vec(),
        signature.to_vec(),
        receipt.to_vec(),
        receipt_signature.to_vec(),
    )
    .map_err(|_| OwnershipAuthorityError::Internal)
}

fn take_length_prefixed<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    maximum: usize,
) -> Result<&'a [u8], OwnershipAuthorityError> {
    let length =
        usize::try_from(read_u32(bytes, cursor).map_err(|_| OwnershipAuthorityError::Unavailable)?)
            .map_err(|_| OwnershipAuthorityError::Unavailable)?;
    if length == 0 || length > maximum {
        return Err(OwnershipAuthorityError::Unavailable);
    }
    take_slice(bytes, cursor, length).map_err(|_| OwnershipAuthorityError::Unavailable)
}

fn read_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32, ProtectedLeaseAuthorityErrorV1> {
    let raw: [u8; 4] = take_slice(bytes, cursor, 4)?
        .try_into()
        .map_err(|_| fixed_bootstrap_error())?;
    Ok(u32::from_be_bytes(raw))
}

fn take_slice<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    length: usize,
) -> Result<&'a [u8], ProtectedLeaseAuthorityErrorV1> {
    let end = cursor
        .checked_add(length)
        .ok_or_else(fixed_bootstrap_error)?;
    let value = bytes.get(*cursor..end).ok_or_else(fixed_bootstrap_error)?;
    *cursor = end;
    Ok(value)
}

fn fixed_bootstrap_error() -> ProtectedLeaseAuthorityErrorV1 {
    ProtectedLeaseAuthorityErrorV1::Authority(DurableOwnershipAuthorityError::CorruptState)
}

struct ProtectedLeaseClockV1 {
    provenance: RawClockProvenance,
    boot: [u8; 16],
    last_boottime_nanoseconds: u64,
}

impl ProtectedLeaseClockV1 {
    fn open() -> Result<Self, DurableOwnershipAuthorityError> {
        let provenance = RawClockProvenance::new_untrusted(PROTECTED_CLOCK_PROVENANCE)
            .map_err(|_| ProtectedOwnershipClockError)?;
        let boot = KernelBootId::current()
            .map_err(|_| ProtectedOwnershipClockError)?
            .into_bytes();
        Ok(Self {
            provenance,
            boot,
            last_boottime_nanoseconds: 0,
        })
    }

    fn sample(&mut self) -> Result<RawPairedClockSample, ProtectedOwnershipClockError> {
        let boot_before = KernelBootId::current()
            .map_err(|_| ProtectedOwnershipClockError)?
            .into_bytes();
        let boottime = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
        let realtime = rustix::time::clock_gettime(rustix::time::ClockId::Realtime);
        let boot_after = KernelBootId::current()
            .map_err(|_| ProtectedOwnershipClockError)?
            .into_bytes();
        let seconds = u64::try_from(boottime.tv_sec).map_err(|_| ProtectedOwnershipClockError)?;
        let nanoseconds =
            u64::try_from(boottime.tv_nsec).map_err(|_| ProtectedOwnershipClockError)?;
        let boottime_nanoseconds = seconds
            .checked_mul(1_000_000_000)
            .and_then(|value| value.checked_add(nanoseconds))
            .ok_or(ProtectedOwnershipClockError)?;
        if boot_before != self.boot
            || boot_after != self.boot
            || boottime_nanoseconds < self.last_boottime_nanoseconds
        {
            return Err(ProtectedOwnershipClockError);
        }
        let sample = RawPairedClockSample::new_untrusted(
            self.provenance,
            self.boot,
            realtime.tv_sec,
            boottime_nanoseconds,
        )
        .map_err(|_| ProtectedOwnershipClockError)?;
        self.last_boottime_nanoseconds = boottime_nanoseconds;
        Ok(sample)
    }
}
