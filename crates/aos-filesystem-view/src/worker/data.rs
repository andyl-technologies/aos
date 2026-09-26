//! Backend-neutral immutable regular-file open, read, and release planning.
//!
//! This module never opens an OS file, performs network I/O, sleeps, or creates
//! a FUSE reply. It plans exact whole/sparse reads, fills holes, admits bounded
//! retries through a verified-object provider, and withholds caller-visible
//! output until every byte has passed integrity checks.

use std::mem::size_of;

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest, Sha256};

use crate::{
    FileContentAuthority, IndexContentView, IndexObjectDescriptorView, OpenFileReply,
    PendingFileReply, RequestCheckpoint, RequestControl, RequestControlState,
};

use super::durable::{Cursor, DurableStateError, Writer};

/// Bounds one connection's fallback read and open-resolution work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DataPlaneLimits {
    /// Maximum bytes returned by one fallback read.
    pub maximum_read_bytes: usize,
    /// Maximum hole/object segments in one planned read.
    pub maximum_read_segments: usize,
    /// Maximum heap bytes retained by one read plan.
    pub maximum_plan_heap_bytes: u64,
    /// Maximum provider calls for one object segment, including the first.
    pub maximum_attempts_per_segment: u16,
    /// Maximum retry delay a provider may request.
    pub maximum_retry_delay_ns: u64,
    /// Maximum retained fallback scratch allocation.
    pub maximum_scratch_heap_bytes: u64,
}

/// Selects the authorized open realization for immutable data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DataOpenPolicy {
    /// A qualified immutable backing is mandatory.
    PassthroughRequired,
    /// A qualified backing is preferred, with verified fallback permitted.
    PreferPassthrough,
    /// Only bounded verified fallback reads are permitted.
    FallbackOnly,
}

/// Carries opaque evidence issued by the fs-verity backing verifier.
///
/// The verifier owns regular-file, read-only-open, seal/immutability, filesystem
/// provenance, fs-verity measurement, and access-policy checks. Callers cannot
/// construct this evidence from boolean claims or an ordinary descriptor hash.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedBackingEvidence {
    /// Commitment to the complete logical content layout.
    logical_content: [u8; 32],
    /// Exact logical byte size.
    logical_size: u64,
    /// Independently measured fs-verity digest.
    verity_digest: ObjectDigest,
    /// Device identity of the already-qualified backing descriptor.
    device: u64,
    /// Inode identity of the already-qualified backing descriptor.
    inode: u64,
    /// Catalog publication generation that pins this identity.
    publication_generation: u64,
    /// Verified backing-filesystem identity.
    filesystem_identity: [u8; 32],
    /// Verified owner, mode, ID-map, ACL, and execute-policy commitment.
    access_policy_binding: [u8; 32],
    /// Revocation generation observed while the object was pinned.
    revocation_generation: u64,
}

impl VerifiedBackingEvidence {
    /// Accepts the complete result of the crate-owned fs-verity verifier.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_fs_verity_verifier(
        logical_content: [u8; 32],
        logical_size: u64,
        verity_digest: ObjectDigest,
        device: u64,
        inode: u64,
        publication_generation: u64,
        filesystem_identity: [u8; 32],
        access_policy_binding: [u8; 32],
        revocation_generation: u64,
    ) -> Result<Self, DataError> {
        if logical_content == [0; 32]
            || verity_digest.as_bytes() == &[0; 32]
            || device == 0
            || inode == 0
            || publication_generation == 0
            || filesystem_identity == [0; 32]
            || access_policy_binding == [0; 32]
            || revocation_generation == 0
        {
            return Err(DataError::IntegrityFailure);
        }
        Ok(Self {
            logical_content,
            logical_size,
            verity_digest,
            device,
            inode,
            publication_generation,
            filesystem_identity,
            access_policy_binding,
            revocation_generation,
        })
    }
}

/// Identifies one connection-qualified immutable backing without an OS descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackingIdentity {
    evidence: VerifiedBackingEvidence,
    authority_binding: [u8; 32],
    cache_disclosure_binding: [u8; 32],
}

impl BackingIdentity {
    /// Binds verifier-issued evidence to one connection and cache-disclosure domain.
    pub(crate) fn from_verified_object(
        evidence: VerifiedBackingEvidence,
        authority_binding: [u8; 32],
        cache_disclosure_binding: [u8; 32],
    ) -> Result<Self, DataError> {
        if authority_binding == [0; 32] || cache_disclosure_binding == [0; 32] {
            return Err(DataError::IntegrityFailure);
        }
        Ok(Self {
            evidence,
            authority_binding,
            cache_disclosure_binding,
        })
    }

    /// Returns the logical layout commitment for audit and coalescing.
    #[must_use]
    pub const fn logical_content(&self) -> [u8; 32] {
        self.evidence.logical_content
    }

    /// Returns the catalog generation authenticated with this backing.
    #[must_use]
    pub const fn publication_generation(&self) -> u64 {
        self.evidence.publication_generation
    }

    pub(super) const fn authority_binding(&self) -> [u8; 32] {
        self.authority_binding
    }

    /// Returns the complete non-authorizing identity commitment.
    ///
    /// This digest is suitable for exact broker-operation binding. It does not
    /// expose or substitute for the verifier-issued backing evidence.
    #[must_use]
    pub fn evidence_commitment(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"aos-filesystem-verified-backing-v1\0");
        hasher.update(self.evidence.logical_content);
        hasher.update(self.evidence.logical_size.to_be_bytes());
        hasher.update(self.evidence.verity_digest.as_bytes());
        hasher.update(self.evidence.device.to_be_bytes());
        hasher.update(self.evidence.inode.to_be_bytes());
        hasher.update(self.evidence.publication_generation.to_be_bytes());
        hasher.update(self.authority_binding);
        hasher.update(self.evidence.filesystem_identity);
        hasher.update(self.cache_disclosure_binding);
        hasher.update(self.evidence.access_policy_binding);
        hasher.update(self.evidence.revocation_generation.to_be_bytes());
        hasher.finalize().into()
    }

    pub(super) fn encode_canonical(self, writer: &mut Writer) -> Result<(), DurableStateError> {
        writer.bytes(&self.evidence.logical_content)?;
        writer.u64(self.evidence.logical_size)?;
        writer.bytes(self.evidence.verity_digest.as_bytes())?;
        writer.u64(self.evidence.device)?;
        writer.u64(self.evidence.inode)?;
        writer.u64(self.evidence.publication_generation)?;
        writer.bytes(&self.evidence.filesystem_identity)?;
        writer.bytes(&self.evidence.access_policy_binding)?;
        writer.u64(self.evidence.revocation_generation)?;
        writer.bytes(&self.cache_disclosure_binding)
    }

    pub(super) fn decode_canonical(
        cursor: &mut Cursor<'_>,
        authority_binding: [u8; 32],
    ) -> Result<Self, DurableStateError> {
        let evidence = VerifiedBackingEvidence::from_fs_verity_verifier(
            cursor.array()?,
            cursor.u64()?,
            ObjectDigest::from_bytes(cursor.array()?),
            cursor.u64()?,
            cursor.u64()?,
            cursor.u64()?,
            cursor.array()?,
            cursor.array()?,
            cursor.u64()?,
        )?;
        Ok(Self::from_verified_object(
            evidence,
            authority_binding,
            cursor.array()?,
        )?)
    }
}

/// Selects how an accepted file open will serve bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackingDisposition {
    /// A broker may register this exact qualified backing for passthrough.
    Passthrough(BackingIdentity),
    /// Userspace must use the bounded verified read path.
    VerifiedFallback,
}

/// Describes external cleanup required after a final release.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseDisposition {
    /// No external backing selector was retained.
    FallbackComplete,
    /// A coalesced passthrough registration remains live for another open.
    SharedBackingRetained,
    /// The broker must close the selector associated with this backing identity.
    CloseBacking(BackingIdentity),
}

/// Binds data disposition to one still-pending worker OPEN reservation.
#[must_use = "publish, abort, or fault the associated pending OPEN"]
pub struct PreparedDataOpen {
    raw_handle: u64,
    node_id: u64,
    logical_content: [u8; 32],
    disposition: BackingDisposition,
    authority_binding: [u8; 32],
}

impl PreparedDataOpen {
    /// Returns the raw pending worker handle.
    #[must_use]
    pub const fn raw_handle(&self) -> u64 {
        self.raw_handle
    }

    /// Returns the exact connection inode.
    #[must_use]
    pub const fn node_id(&self) -> u64 {
        self.node_id
    }

    /// Returns the complete logical-content commitment.
    #[must_use]
    pub const fn logical_content(&self) -> [u8; 32] {
        self.logical_content
    }

    /// Returns the authorized data disposition.
    #[must_use]
    pub const fn disposition(&self) -> BackingDisposition {
        self.disposition
    }

    /// Returns cleanup required after the final RELEASE.
    #[must_use]
    pub const fn release_disposition(&self) -> ReleaseDisposition {
        match self.disposition {
            BackingDisposition::Passthrough(identity) => ReleaseDisposition::CloseBacking(identity),
            BackingDisposition::VerifiedFallback => ReleaseDisposition::FallbackComplete,
        }
    }
}

/// Describes one exact fallback read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DataReadRequest {
    /// Logical byte offset.
    pub offset: u64,
    /// Requested byte count before EOF truncation.
    pub length: usize,
    /// Exclusive absolute monotonic deadline.
    pub deadline_ns: u64,
}

/// Borrows one exact object slice requested from a verified provider.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectReadRequest<'a> {
    /// Authenticated object descriptor.
    pub descriptor: IndexObjectDescriptorView<'a>,
    /// Byte offset within the stored object.
    pub object_offset: u64,
    /// Exact requested length.
    pub length: usize,
    /// Exclusive absolute monotonic deadline inherited from the FUSE request.
    pub deadline_ns: u64,
}

/// Reports one provider attempt after writing only to private scratch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectReadResult {
    /// The provider verified the complete containing object before returning this slice.
    Complete {
        /// Verified containing-object digest.
        digest: ObjectDigest,
        /// Verified containing-object encoded size.
        encoded_size: u64,
        /// Verified slice offset.
        object_offset: u64,
        /// Exact bytes initialized in the supplied destination.
        bytes: usize,
    },
    /// The immutable source asked for another bounded attempt.
    Retryable {
        /// Provider-required delay, used for deadline admission.
        retry_after_ns: u64,
    },
    /// The source bytes or their publication proof failed integrity validation.
    IntegrityFailure,
}

/// Supplies slices only from completely verified immutable objects.
pub trait VerifiedObjectReader {
    /// Fills the complete destination or returns an explicit retry/failure result.
    ///
    /// Implementations must verify the containing object's exact descriptor
    /// before returning [`ObjectReadResult::Complete`]. The destination is
    /// private staging; writing a prefix before failure cannot publish bytes.
    ///
    /// # Errors
    ///
    /// Returns [`DataError`] for backend authority, cancellation, deadline,
    /// resource, or integrity failure. Retryable source conditions should use
    /// [`ObjectReadResult::Retryable`] so the caller enforces its attempt bound.
    fn read_verified(
        &mut self,
        request: ObjectReadRequest<'_>,
        destination: &mut [u8],
    ) -> Result<ObjectReadResult, DataError>;
}

/// Supplies the backend-independent monotonic clock used for absolute deadlines.
pub trait MonotonicClock {
    /// Returns the current monotonic-clock nanosecond value.
    fn now_ns(&self) -> u64;

    /// Waits until an absolute retry instant while observing request control.
    ///
    /// The implementation owns scheduling and must return promptly after
    /// cancellation or deadline expiry. It must not report success before
    /// `ready_at_ns` and must never wait through `deadline_ns`.
    ///
    /// # Errors
    ///
    /// Returns [`DataError::Cancelled`] or [`DataError::DeadlineExpired`] for
    /// interruption, or another closed data error for scheduling failure.
    fn wait_until(
        &self,
        ready_at_ns: u64,
        deadline_ns: u64,
        control: &dyn RequestControl,
    ) -> Result<(), DataError>;
}

/// Classifies one planned output interval.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadSegment<'a> {
    /// Produces zero bytes without consulting storage.
    Hole {
        /// Offset in the final reply scratch.
        output_offset: usize,
        /// Positive zero-filled byte count.
        length: usize,
    },
    /// Reads one exact slice of one authenticated stored object.
    Object {
        /// Authenticated stored object.
        descriptor: IndexObjectDescriptorView<'a>,
        /// Offset within the stored object.
        object_offset: u64,
        /// Offset in the final reply scratch.
        output_offset: usize,
        /// Positive requested byte count.
        length: usize,
    },
}

/// Owns reusable private staging for fallback replies.
pub struct DataReadScratch {
    bytes: Vec<u8>,
    maximum_heap_bytes: u64,
}

impl DataReadScratch {
    /// Creates zero-capacity staging with a hard retained-heap ceiling.
    ///
    /// Use [`Self::allocate`] before serving nonempty reads. This constructor is
    /// suitable for configurations that deliberately admit only empty reads.
    #[must_use]
    pub const fn new(maximum_heap_bytes: u64) -> Self {
        Self {
            bytes: Vec::new(),
            maximum_heap_bytes,
        }
    }

    /// Preallocates the complete reusable read capacity before dispatch.
    ///
    /// # Errors
    ///
    /// Returns [`DataError::ResourceExhausted`] when capacity exceeds the heap
    /// ceiling or [`DataError::AllocationRefused`] if allocation fails.
    pub fn allocate(maximum_heap_bytes: u64, capacity: usize) -> Result<Self, DataError> {
        if capacity as u64 > maximum_heap_bytes {
            return Err(DataError::ResourceExhausted);
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| DataError::AllocationRefused)?;
        if bytes.capacity() as u64 > maximum_heap_bytes {
            return Err(DataError::ResourceExhausted);
        }
        Ok(Self {
            bytes,
            maximum_heap_bytes,
        })
    }

    /// Returns currently retained heap bytes for accounting.
    #[must_use]
    pub fn retained_heap_bytes(&self) -> u64 {
        self.bytes.capacity() as u64
    }

    fn prepare(&mut self, length: usize) -> Result<(), DataError> {
        if length as u64 > self.maximum_heap_bytes {
            return Err(DataError::ResourceExhausted);
        }
        self.bytes.clear();
        if self.bytes.capacity() < length {
            return Err(DataError::ResourceExhausted);
        }
        self.bytes.resize(length, 0);
        Ok(())
    }

    fn discard(&mut self) {
        self.bytes.fill(0);
        self.bytes.clear();
    }
}

/// Borrows a fully initialized fallback reply from private scratch.
pub struct DataReadResult<'a> {
    bytes: &'a [u8],
    eof: bool,
}

impl<'a> DataReadResult<'a> {
    /// Returns the complete verified reply bytes.
    #[must_use]
    pub const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Reports whether the request reached logical EOF.
    #[must_use]
    pub const fn is_eof(&self) -> bool {
        self.eof
    }
}

/// Reports immutable data-plane admission or execution failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DataError {
    /// A configured data-plane limit is invalid.
    #[error("invalid data-plane limit")]
    InvalidLimit,
    /// Request arithmetic overflowed or used an invalid deadline.
    #[error("invalid immutable data request")]
    InvalidRequest,
    /// The operation exceeded an admitted byte, segment, retry, or heap ceiling.
    #[error("immutable data request exceeds its resource ceiling")]
    ResourceExhausted,
    /// An admitted allocation was refused.
    #[error("immutable data allocation was refused")]
    AllocationRefused,
    /// The caller cancelled the request.
    #[error("immutable data request was cancelled")]
    Cancelled,
    /// The request's absolute deadline expired.
    #[error("immutable data request deadline expired")]
    DeadlineExpired,
    /// The selected open requires passthrough and cannot issue fallback reads.
    #[error("open is owned by immutable backing passthrough")]
    PassthroughRequired,
    /// No policy-authorized open realization is available.
    #[error("no authorized immutable data realization is available")]
    RealizationUnavailable,
    /// Provider output did not exactly match the authenticated object slice.
    #[error("immutable data integrity validation failed")]
    IntegrityFailure,
}

/// Executes bounded backend-neutral data-plane planning.
#[derive(Debug)]
pub struct DataPlane {
    limits: DataPlaneLimits,
    policy: DataOpenPolicy,
    authority_binding: [u8; 32],
    lease_valid_from_ns: u64,
    lease_expires_at_ns: u64,
}

impl DataPlane {
    /// Creates a connection-bound immutable data plane.
    ///
    /// # Errors
    ///
    /// Returns [`DataError::InvalidLimit`] when any mandatory bound is zero.
    pub(crate) fn new(
        limits: DataPlaneLimits,
        policy: DataOpenPolicy,
        authority_binding: [u8; 32],
        lease_valid_from_ns: u64,
        lease_expires_at_ns: u64,
    ) -> Result<Self, DataError> {
        if limits.maximum_read_bytes == 0
            || limits.maximum_read_segments == 0
            || limits.maximum_plan_heap_bytes == 0
            || limits.maximum_attempts_per_segment == 0
            || limits.maximum_scratch_heap_bytes == 0
            || lease_valid_from_ns >= lease_expires_at_ns
        {
            return Err(DataError::InvalidLimit);
        }
        let maximum_plan_bytes = u64::try_from(limits.maximum_read_segments)
            .ok()
            .and_then(|segments| segments.checked_mul(size_of::<ReadSegment<'static>>() as u64))
            .ok_or(DataError::InvalidLimit)?;
        if maximum_plan_bytes > limits.maximum_plan_heap_bytes {
            return Err(DataError::InvalidLimit);
        }
        Ok(Self {
            limits,
            policy,
            authority_binding,
            lease_valid_from_ns,
            lease_expires_at_ns,
        })
    }

    /// Qualifies fallback or an independently verified immutable backing.
    ///
    /// `backing` carries no descriptor and grants no registration authority. A
    /// broker must still bind and register it after this pure admission step.
    ///
    /// # Errors
    ///
    /// Returns [`DataError::IntegrityFailure`] for a backing whose logical
    /// content, size, physical identity, publication, access policy, cache
    /// disclosure, revocation, or connection authority differs.
    /// Returns [`DataError::RealizationUnavailable`] when policy requires a
    /// backing and none is supplied.
    pub fn prepare_open(
        &self,
        pending: &PendingFileReply<'_>,
        backing: Option<BackingIdentity>,
        monotonic_now_ns: u64,
    ) -> Result<PreparedDataOpen, DataError> {
        if monotonic_now_ns < self.lease_valid_from_ns
            || monotonic_now_ns >= self.lease_expires_at_ns
        {
            return Err(DataError::DeadlineExpired);
        }
        let logical_content = content_commitment(pending.content())?;
        let logical_size = pending.content().logical_size();
        let backing = backing
            .map(|candidate| {
                if candidate.evidence.logical_content != logical_content
                    || candidate.evidence.logical_size != logical_size
                    || candidate.evidence.device == 0
                    || candidate.evidence.inode == 0
                    || candidate.evidence.publication_generation == 0
                    || candidate.authority_binding != self.authority_binding
                    || candidate.evidence.filesystem_identity == [0; 32]
                    || candidate.cache_disclosure_binding == [0; 32]
                    || candidate.evidence.access_policy_binding == [0; 32]
                    || candidate.evidence.revocation_generation == 0
                {
                    return Err(DataError::IntegrityFailure);
                }
                Ok(candidate)
            })
            .transpose()?;
        let disposition = match (self.policy, backing) {
            (DataOpenPolicy::PassthroughRequired, Some(identity))
            | (DataOpenPolicy::PreferPassthrough, Some(identity)) => {
                BackingDisposition::Passthrough(identity)
            }
            (DataOpenPolicy::PassthroughRequired, None) => {
                return Err(DataError::RealizationUnavailable);
            }
            (DataOpenPolicy::PreferPassthrough | DataOpenPolicy::FallbackOnly, _) => {
                BackingDisposition::VerifiedFallback
            }
        };
        Ok(PreparedDataOpen {
            raw_handle: pending.raw_handle(),
            node_id: pending.node_id(),
            logical_content,
            disposition,
            authority_binding: self.authority_binding,
        })
    }

    /// Plans a bounded logical read without touching a provider.
    ///
    /// Reads at or beyond EOF succeed with an empty plan. The returned length is
    /// truncated at EOF and every planned segment has positive length.
    ///
    /// # Errors
    ///
    /// Returns [`DataError`] for invalid request arithmetic, an expired absolute
    /// deadline, passthrough disposition, cancellation, or exceeded byte/segment
    /// ceiling.
    pub fn plan_read<'a>(
        &self,
        open: &OpenFileReply<'a>,
        disposition: BackingDisposition,
        request: DataReadRequest,
        clock: &impl MonotonicClock,
        control: &impl RequestControl,
    ) -> Result<(Vec<ReadSegment<'a>>, bool), DataError> {
        if disposition != BackingDisposition::VerifiedFallback {
            return Err(DataError::PassthroughRequired);
        }
        let effective_deadline = request.deadline_ns.min(self.lease_expires_at_ns);
        check_request(
            request,
            self.lease_valid_from_ns,
            effective_deadline,
            self.limits,
            clock,
            control,
        )?;
        let logical_size = open.content().logical_size();
        if request.offset >= logical_size {
            return Ok((Vec::new(), true));
        }
        let requested = u64::try_from(request.length).map_err(|_| DataError::InvalidRequest)?;
        let end = request
            .offset
            .checked_add(requested)
            .ok_or(DataError::InvalidRequest)?
            .min(logical_size);
        let output_length =
            usize::try_from(end - request.offset).map_err(|_| DataError::ResourceExhausted)?;
        if output_length > self.limits.maximum_read_bytes {
            return Err(DataError::ResourceExhausted);
        }
        let segments = plan_segments(
            open.content(),
            request.offset,
            end,
            self.limits.maximum_read_segments,
            self.limits.maximum_plan_heap_bytes,
        )?;
        Ok((segments, end == logical_size))
    }

    /// Executes a complete verified fallback read into private reusable scratch.
    ///
    /// No borrowed reply is returned until every object slice has supplied an
    /// exact containing-object verification result. Every error zeroes and
    /// clears scratch, so provider-written prefixes cannot become replies.
    ///
    /// # Errors
    ///
    /// Returns [`DataError`] for passthrough selection, malformed or oversized
    /// reads, cancellation, deadline expiry, bounded retry exhaustion, provider
    /// error, allocation refusal, or any mismatched verification result.
    pub fn read<'scratch>(
        &self,
        open: &OpenFileReply<'_>,
        prepared: &PreparedDataOpen,
        request: DataReadRequest,
        scratch: &'scratch mut DataReadScratch,
        provider: &mut impl VerifiedObjectReader,
        clock: &impl MonotonicClock,
        control: &impl RequestControl,
    ) -> Result<DataReadResult<'scratch>, DataError> {
        if scratch.maximum_heap_bytes > self.limits.maximum_scratch_heap_bytes {
            return Err(DataError::ResourceExhausted);
        }
        self.validate_prepared_open(open, prepared)?;
        let (segments, eof) =
            self.plan_read(open, prepared.disposition, request, clock, control)?;
        let effective_deadline = request.deadline_ns.min(self.lease_expires_at_ns);
        let output_length = segments.iter().try_fold(0_usize, |maximum, segment| {
            let (offset, length) = segment_output(*segment);
            offset
                .checked_add(length)
                .map(|end| maximum.max(end))
                .ok_or(DataError::InvalidRequest)
        })?;
        scratch.prepare(output_length)?;

        let result = execute_segments(
            &segments,
            effective_deadline,
            self.limits,
            &mut scratch.bytes,
            provider,
            clock,
            control,
        );
        if let Err(error) = result {
            scratch.discard();
            return Err(error);
        }
        check_control(control, RequestCheckpoint::AfterReadOnlyWork)
            .inspect_err(|_| scratch.discard())?;
        if clock.now_ns() >= effective_deadline {
            scratch.discard();
            return Err(DataError::DeadlineExpired);
        }
        Ok(DataReadResult {
            bytes: &scratch.bytes,
            eof,
        })
    }

    /// Validates release state and returns required external cleanup.
    ///
    /// # Errors
    ///
    /// Returns [`DataError::IntegrityFailure`] if the active worker handle and
    /// prepared open differ. The caller must release worker state separately,
    /// after preserving this cleanup disposition.
    pub fn prepare_release(
        &self,
        open: &OpenFileReply<'_>,
        prepared: &PreparedDataOpen,
    ) -> Result<ReleaseDisposition, DataError> {
        self.validate_prepared_open(open, prepared)?;
        Ok(prepared.release_disposition())
    }

    fn validate_prepared_open(
        &self,
        open: &OpenFileReply<'_>,
        prepared: &PreparedDataOpen,
    ) -> Result<(), DataError> {
        if open.raw_handle() != prepared.raw_handle
            || open.node_id() != prepared.node_id
            || content_commitment(open.content())? != prepared.logical_content
            || prepared.authority_binding != self.authority_binding
        {
            return Err(DataError::IntegrityFailure);
        }
        Ok(())
    }
}

fn check_request(
    request: DataReadRequest,
    lease_valid_from_ns: u64,
    effective_deadline_ns: u64,
    limits: DataPlaneLimits,
    clock: &impl MonotonicClock,
    control: &impl RequestControl,
) -> Result<(), DataError> {
    if request.deadline_ns == 0 {
        return Err(DataError::InvalidRequest);
    }
    if request.length > limits.maximum_read_bytes {
        return Err(DataError::ResourceExhausted);
    }
    check_control(control, RequestCheckpoint::BeforeWork)?;
    let monotonic_now_ns = clock.now_ns();
    if monotonic_now_ns < lease_valid_from_ns || monotonic_now_ns >= effective_deadline_ns {
        return Err(DataError::DeadlineExpired);
    }
    Ok(())
}

fn plan_segments<'a>(
    content: FileContentAuthority<'a>,
    start: u64,
    end: u64,
    maximum_segments: usize,
    maximum_plan_heap_bytes: u64,
) -> Result<Vec<ReadSegment<'a>>, DataError> {
    if start == end {
        return Ok(Vec::new());
    }
    let modeled_bytes = (maximum_segments as u64)
        .checked_mul(size_of::<ReadSegment<'a>>() as u64)
        .ok_or(DataError::ResourceExhausted)?;
    if modeled_bytes > maximum_plan_heap_bytes {
        return Err(DataError::ResourceExhausted);
    }
    let mut result = Vec::new();
    result
        .try_reserve_exact(maximum_segments)
        .map_err(|_| DataError::AllocationRefused)?;
    let retained_bytes = (result.capacity() as u64)
        .checked_mul(size_of::<ReadSegment<'a>>() as u64)
        .ok_or(DataError::ResourceExhausted)?;
    if retained_bytes > maximum_plan_heap_bytes {
        return Err(DataError::ResourceExhausted);
    }
    match content.content() {
        IndexContentView::Whole { content } => push_segment(
            &mut result,
            maximum_segments,
            ReadSegment::Object {
                descriptor: content,
                object_offset: start,
                output_offset: 0,
                length: usize::try_from(end - start).map_err(|_| DataError::ResourceExhausted)?,
            },
        )?,
        IndexContentView::Sparse(sparse) => {
            let mut cursor = start;
            for extent in sparse.extents() {
                let extent = extent.map_err(|_| DataError::IntegrityFailure)?;
                if extent.end() <= start {
                    continue;
                }
                if extent.offset() >= end {
                    break;
                }
                if cursor < extent.offset() {
                    let hole_end = extent.offset().min(end);
                    push_hole(&mut result, maximum_segments, start, cursor, hole_end)?;
                    cursor = hole_end;
                }
                let overlap_start = cursor.max(extent.offset()).max(start);
                let overlap_end = extent.end().min(end);
                if overlap_start < overlap_end {
                    push_segment(
                        &mut result,
                        maximum_segments,
                        ReadSegment::Object {
                            descriptor: extent.content(),
                            object_offset: overlap_start - extent.offset(),
                            output_offset: usize::try_from(overlap_start - start)
                                .map_err(|_| DataError::ResourceExhausted)?,
                            length: usize::try_from(overlap_end - overlap_start)
                                .map_err(|_| DataError::ResourceExhausted)?,
                        },
                    )?;
                    cursor = overlap_end;
                }
                if cursor == end {
                    break;
                }
            }
            if cursor < end {
                push_hole(&mut result, maximum_segments, start, cursor, end)?;
            }
        }
    }
    Ok(result)
}

fn push_hole<'a>(
    result: &mut Vec<ReadSegment<'a>>,
    maximum_segments: usize,
    request_start: u64,
    start: u64,
    end: u64,
) -> Result<(), DataError> {
    if start < end {
        push_segment(
            result,
            maximum_segments,
            ReadSegment::Hole {
                output_offset: usize::try_from(start - request_start)
                    .map_err(|_| DataError::ResourceExhausted)?,
                length: usize::try_from(end - start).map_err(|_| DataError::ResourceExhausted)?,
            },
        )?;
    }
    Ok(())
}

fn push_segment<'a>(
    result: &mut Vec<ReadSegment<'a>>,
    maximum_segments: usize,
    segment: ReadSegment<'a>,
) -> Result<(), DataError> {
    if result.len() == maximum_segments {
        return Err(DataError::ResourceExhausted);
    }
    result.push(segment);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn execute_segments(
    segments: &[ReadSegment<'_>],
    deadline_ns: u64,
    limits: DataPlaneLimits,
    output: &mut [u8],
    provider: &mut impl VerifiedObjectReader,
    clock: &impl MonotonicClock,
    control: &impl RequestControl,
) -> Result<(), DataError> {
    for segment in segments {
        check_control(control, RequestCheckpoint::DuringReadOnlyWork)?;
        if clock.now_ns() >= deadline_ns {
            return Err(DataError::DeadlineExpired);
        }
        let ReadSegment::Object {
            descriptor,
            object_offset,
            output_offset,
            length,
        } = *segment
        else {
            continue;
        };
        let end = output_offset
            .checked_add(length)
            .ok_or(DataError::IntegrityFailure)?;
        let destination = output
            .get_mut(output_offset..end)
            .ok_or(DataError::IntegrityFailure)?;
        let request = ObjectReadRequest {
            descriptor,
            object_offset,
            length,
            deadline_ns,
        };
        let mut attempts = 0_u16;
        loop {
            attempts = attempts
                .checked_add(1)
                .ok_or(DataError::ResourceExhausted)?;
            if attempts > limits.maximum_attempts_per_segment {
                return Err(DataError::ResourceExhausted);
            }
            check_control(control, RequestCheckpoint::DuringReadOnlyWork)?;
            let now = clock.now_ns();
            if now >= deadline_ns {
                return Err(DataError::DeadlineExpired);
            }
            match provider.read_verified(request, destination)? {
                ObjectReadResult::Complete {
                    digest,
                    encoded_size,
                    object_offset: verified_offset,
                    bytes,
                } if digest == descriptor.digest()
                    && encoded_size == descriptor.encoded_size()
                    && verified_offset == object_offset
                    && bytes == length =>
                {
                    break;
                }
                ObjectReadResult::Complete { .. } | ObjectReadResult::IntegrityFailure => {
                    return Err(DataError::IntegrityFailure);
                }
                ObjectReadResult::Retryable { retry_after_ns } => {
                    let ready_at_ns = now
                        .checked_add(retry_after_ns)
                        .ok_or(DataError::DeadlineExpired)?;
                    if retry_after_ns > limits.maximum_retry_delay_ns || ready_at_ns >= deadline_ns
                    {
                        return Err(DataError::DeadlineExpired);
                    }
                    clock.wait_until(ready_at_ns, deadline_ns, control)?;
                }
            }
        }
    }
    check_control(control, RequestCheckpoint::AfterReadOnlyWork)
}

fn check_control(
    control: &impl RequestControl,
    checkpoint: RequestCheckpoint,
) -> Result<(), DataError> {
    match control.state(checkpoint) {
        RequestControlState::Continue => Ok(()),
        RequestControlState::Cancelled => Err(DataError::Cancelled),
        RequestControlState::DeadlineExpired => Err(DataError::DeadlineExpired),
    }
}

const fn segment_output(segment: ReadSegment<'_>) -> (usize, usize) {
    match segment {
        ReadSegment::Hole {
            output_offset,
            length,
        }
        | ReadSegment::Object {
            output_offset,
            length,
            ..
        } => (output_offset, length),
    }
}

fn content_commitment(content: FileContentAuthority<'_>) -> Result<[u8; 32], DataError> {
    let mut hasher = Sha256::new();
    hasher.update(b"aos-filesystem-logical-content-v1\0");
    hasher.update(content.logical_size().to_be_bytes());
    match content.content() {
        IndexContentView::Whole { content } => {
            hasher.update([0]);
            hash_object(&mut hasher, content);
        }
        IndexContentView::Sparse(sparse) => {
            hasher.update([1]);
            hasher.update((sparse.extents().len() as u64).to_be_bytes());
            for extent in sparse.extents() {
                let extent = extent.map_err(|_| DataError::IntegrityFailure)?;
                hasher.update(extent.offset().to_be_bytes());
                hasher.update(extent.length().to_be_bytes());
                hash_object(&mut hasher, extent.content());
            }
        }
    }
    Ok(hasher.finalize().into())
}

fn hash_object(hasher: &mut Sha256, object: IndexObjectDescriptorView<'_>) {
    hasher.update((object.media_type().len() as u64).to_be_bytes());
    hasher.update(object.media_type().as_bytes());
    hasher.update(object.digest().as_bytes());
    hasher.update(object.encoded_size().to_be_bytes());
}

const _: () = {
    // Keep the per-segment admission model honest as this pure type evolves.
    assert!(size_of::<ReadSegment<'static>>() <= 128);
};
