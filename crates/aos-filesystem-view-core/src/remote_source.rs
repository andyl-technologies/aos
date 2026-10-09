//! Dormant immutable remote-source fetch, retry, and ambiguity recovery.
//!
//! The adapter owns bounded buffering and verifies the complete descriptor
//! before bytes become usable. A transport is an explicitly trusted effect
//! boundary: retry and ambiguous results carry exact request receipts, and an
//! ambiguous attempt can only be resumed through its non-cloneable token.
//! No concrete network client, endpoint, credential source, or task is
//! installed by this crate.

use std::error::Error as StdError;

use aos_sandbox_core::{ObjectDescriptor, ObjectDigest, descriptor_for_bytes};
use sha2::{Digest as _, Sha256};

use crate::ExactObject;

const READ_BUFFER_BYTES: usize = 16 * 1024;

/// Bounds memory, attempts, transport chunks, and retry delay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FetchLimits {
    /// Maximum accepted immutable object size.
    pub maximum_object_bytes: u64,
    /// Maximum transport attempts, including the first.
    pub maximum_attempts: u16,
    /// Maximum delay accepted from one retry response.
    pub maximum_retry_delay_ns: u64,
    /// Maximum bytes requested by one nonblocking transport poll.
    pub maximum_poll_bytes: usize,
}

impl FetchLimits {
    fn validate(self) -> Result<Self, RemoteFetchError> {
        if self.maximum_object_bytes == 0
            || self.maximum_attempts == 0
            || self.maximum_retry_delay_ns == 0
            || self.maximum_poll_bytes == 0
            || self.maximum_poll_bytes > READ_BUFFER_BYTES
        {
            return Err(RemoteFetchError::InvalidRequest);
        }
        Ok(self)
    }
}

/// Reports cooperative fetch control state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FetchControlState {
    /// Fetching may continue.
    Continue,
    /// The caller cancelled the operation.
    Cancelled,
    /// The absolute deadline expired.
    DeadlineExpired,
}

/// Supplies trusted time, cancellation, and bounded retry waiting.
pub trait FetchControl {
    /// Returns the current state without blocking.
    fn state(&self) -> FetchControlState;

    /// Returns current monotonic nanoseconds.
    fn now_ns(&self) -> u64;

    /// Waits until an absolute retry instant while honoring the deadline.
    ///
    /// # Errors
    ///
    /// Returns a closed fetch error on cancellation, expiry, or scheduler
    /// failure.
    fn wait_until(&self, ready_at_ns: u64, deadline_ns: u64) -> Result<(), RemoteFetchError>;
}

/// Authenticates one transport attempt to the exact immutable request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FetchReceipt {
    request_digest: ObjectDigest,
    attempt: u16,
    transport_evidence: ObjectDigest,
}

impl FetchReceipt {
    /// Creates evidence at the trusted transport boundary.
    ///
    /// # Errors
    ///
    /// Returns [`RemoteFetchError::InvalidReceipt`] for sentinel fields.
    pub fn from_transport(
        request_digest: ObjectDigest,
        attempt: u16,
        transport_evidence: ObjectDigest,
    ) -> Result<Self, RemoteFetchError> {
        if request_digest.as_bytes() == &[0; 32]
            || attempt == 0
            || transport_evidence.as_bytes() == &[0; 32]
        {
            return Err(RemoteFetchError::InvalidReceipt);
        }
        Ok(Self {
            request_digest,
            attempt,
            transport_evidence,
        })
    }

    /// Returns the exact request and attempt identity.
    #[must_use]
    pub const fn identity(self) -> (ObjectDigest, u16) {
        (self.request_digest, self.attempt)
    }
}

/// Reports one immutable-source transport attempt.
pub enum FetchAttempt<R> {
    /// Supplies a stream and exact completed-attempt receipt.
    Complete {
        /// Streaming immutable response body.
        reader: R,
        /// Transport-authenticated exact attempt receipt.
        receipt: FetchReceipt,
    },
    /// Definitely performed no publication and requests a bounded retry.
    Retryable {
        /// Relative delay requested before another attempt.
        retry_after_ns: u64,
        /// Transport-authenticated no-effect receipt.
        receipt: FetchReceipt,
    },
    /// The transport outcome is unknown and must be recovered exactly.
    Ambiguous {
        /// Transport-authenticated identity of the unknown attempt.
        receipt: FetchReceipt,
    },
    /// The remote publication or transport proof failed integrity validation.
    IntegrityFailure {
        /// Transport-authenticated terminal failure receipt.
        receipt: FetchReceipt,
    },
}

/// Reports exact recovery of one ambiguous transport attempt.
pub enum FetchRecovery<R> {
    /// The original attempt completed and supplies its original stream.
    Complete {
        /// Streaming body retained or replayed for the original attempt.
        reader: R,
        /// Exact original receipt.
        receipt: FetchReceipt,
    },
    /// The original attempt definitely had no effect, permitting the next attempt.
    NoEffect {
        /// Exact original receipt.
        receipt: FetchReceipt,
    },
    /// The original outcome is still unknown.
    StillAmbiguous {
        /// Exact original receipt.
        receipt: FetchReceipt,
    },
    /// Recovery established an integrity failure.
    IntegrityFailure {
        /// Exact original receipt.
        receipt: FetchReceipt,
    },
}

/// Reports one deadline-aware, nonblocking body poll.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FetchRead {
    /// This many bytes were initialized at the start of the supplied destination.
    Data { bytes: usize },
    /// The response reached exact EOF.
    Eof,
    /// No bytes are ready; poll again after this bounded relative delay.
    Pending { retry_after_ns: u64 },
}

/// Reports one nonblocking poll of attempt creation.
pub enum FetchBeginPoll<R> {
    /// No terminal attempt state is ready yet.
    Pending { retry_after_ns: u64 },
    /// The attempt reached a classified state.
    Ready(FetchAttempt<R>),
}

/// Reports one nonblocking poll of ambiguity recovery.
pub enum FetchRecoveryPoll<R> {
    /// No authoritative recovery state is ready yet.
    Pending { retry_after_ns: u64 },
    /// Recovery reached a classified state.
    Ready(FetchRecovery<R>),
}

/// Performs one exact immutable-source effect and its recovery observation.
pub trait ImmutableFetchTransport {
    /// Streaming body type with bounded implementation-owned buffering.
    type Reader;
    /// Transport-specific error.
    type Error: StdError + Send + Sync + 'static;

    /// Begins one exact numbered attempt.
    ///
    /// This operation must itself be bounded and nonblocking through the
    /// supplied deadline and cancellation control; those guarantees do not
    /// begin only after a response body exists.
    ///
    /// # Errors
    ///
    /// Returns a transport error only before an ambiguous effect is possible.
    fn poll_fetch(
        &mut self,
        descriptor: &ObjectDescriptor,
        request_digest: ObjectDigest,
        attempt: u16,
        deadline_ns: u64,
        control: &dyn FetchControl,
    ) -> Result<FetchBeginPoll<Self::Reader>, Self::Error>;

    /// Reobserves the exact attempt named by an ambiguity token.
    ///
    /// Recovery must itself be bounded and nonblocking through the supplied
    /// deadline and cancellation control.
    ///
    /// # Errors
    ///
    /// Returns a transport error when no authoritative observation is available.
    fn poll_recover(
        &mut self,
        descriptor: &ObjectDescriptor,
        receipt: FetchReceipt,
        deadline_ns: u64,
        control: &dyn FetchControl,
    ) -> Result<FetchRecoveryPoll<Self::Reader>, Self::Error>;

    /// Polls one bounded response chunk without blocking through `deadline_ns`.
    ///
    /// Implementations return promptly, consult `control` while their bounded
    /// operation is pending, and use [`FetchRead::Pending`] when no bytes are
    /// ready. They must never delegate this method to an unbounded synchronous
    /// [`std::io::Read`] call. The adapter also checks cancellation before every
    /// poll, including the final EOF confirmation.
    ///
    /// # Errors
    ///
    /// Returns a transport error for a terminal response-body failure.
    fn poll_read(
        &mut self,
        reader: &mut Self::Reader,
        destination: &mut [u8],
        deadline_ns: u64,
        control: &dyn FetchControl,
    ) -> Result<FetchRead, Self::Error>;
}

/// Retains exact recovery authority for one unknown fetch attempt.
#[derive(Debug)]
#[must_use = "recover the exact attempt or retain its ambiguity"]
pub struct FetchAmbiguity {
    descriptor: ObjectDescriptor,
    request_digest: ObjectDigest,
    attempt: u16,
    deadline_ns: u64,
    receipt: FetchReceipt,
}

/// Retains ambiguity custody whenever recovery has not reached a terminal classification.
#[derive(Debug)]
pub struct FetchRecoveryError {
    ambiguity: Option<FetchAmbiguity>,
    source: RemoteFetchError,
}

impl FetchRecoveryError {
    /// Separates a retryable ambiguity token from the underlying failure.
    #[must_use]
    pub fn into_parts(self) -> (Option<FetchAmbiguity>, RemoteFetchError) {
        (self.ambiguity, self.source)
    }
}

/// Owns bounded immutable fetch verification around one dormant transport.
pub struct DormantRemoteSource<T> {
    transport: T,
    limits: FetchLimits,
}

impl<T: ImmutableFetchTransport> DormantRemoteSource<T> {
    /// Constructs the dormant adapter without initiating network work.
    ///
    /// # Errors
    ///
    /// Returns [`RemoteFetchError::InvalidRequest`] for zero bounds.
    pub fn new(transport: T, limits: FetchLimits) -> Result<Self, RemoteFetchError> {
        Ok(Self {
            transport,
            limits: limits.validate()?,
        })
    }

    /// Fetches and verifies one complete immutable object with bounded retries.
    ///
    /// # Errors
    ///
    /// Returns [`RemoteFetchError`] for cancellation, deadline, retry exhaustion,
    /// transport failure, malformed receipts, ambiguity, allocation refusal, or
    /// descriptor mismatch.
    pub fn fetch_exact(
        &mut self,
        descriptor: &ObjectDescriptor,
        operation_binding: [u8; 32],
        deadline_ns: u64,
        control: &impl FetchControl,
    ) -> Result<ExactObject, RemoteFetchError> {
        let request_digest = request_digest(descriptor, operation_binding, deadline_ns)?;
        let mut attempt = 1_u16;
        loop {
            check_control(control, deadline_ns)?;
            let outcome =
                self.poll_begin(descriptor, request_digest, attempt, deadline_ns, control)?;
            match outcome {
                FetchAttempt::Complete { reader, receipt } => {
                    validate_receipt(receipt, request_digest, attempt)?;
                    return self.read_exact(reader, descriptor, control, deadline_ns);
                }
                FetchAttempt::Retryable {
                    retry_after_ns,
                    receipt,
                } => {
                    validate_receipt(receipt, request_digest, attempt)?;
                    attempt = next_attempt(attempt, self.limits.maximum_attempts)?;
                    wait_retry(control, retry_after_ns, deadline_ns, self.limits)?;
                }
                FetchAttempt::Ambiguous { receipt } => {
                    validate_receipt(receipt, request_digest, attempt)?;
                    return Err(RemoteFetchError::Ambiguous(FetchAmbiguity {
                        descriptor: descriptor.clone(),
                        request_digest,
                        attempt,
                        deadline_ns,
                        receipt,
                    }));
                }
                FetchAttempt::IntegrityFailure { receipt } => {
                    validate_receipt(receipt, request_digest, attempt)?;
                    return Err(RemoteFetchError::IntegrityFailure);
                }
            }
        }
    }

    /// Reobserves an exact ambiguous attempt and resumes only after no-effect proof.
    ///
    /// # Errors
    ///
    /// Returns the ordinary fetch errors, retaining a fresh ambiguity token when
    /// the original effect remains unknown.
    pub fn recover_exact(
        &mut self,
        ambiguity: FetchAmbiguity,
        control: &impl FetchControl,
    ) -> Result<ExactObject, FetchRecoveryError> {
        if let Err(source) = check_control(control, ambiguity.deadline_ns) {
            return Err(FetchRecoveryError {
                ambiguity: Some(ambiguity),
                source,
            });
        }
        let outcome = match self.poll_recovery(&ambiguity, control) {
            Ok(outcome) => outcome,
            Err(source) => {
                return Err(FetchRecoveryError {
                    ambiguity: Some(ambiguity),
                    source,
                });
            }
        };
        match outcome {
            FetchRecovery::Complete { reader, receipt } => {
                if let Err(source) = validate_recovery_receipt(receipt, &ambiguity) {
                    return Err(FetchRecoveryError {
                        ambiguity: Some(ambiguity),
                        source,
                    });
                }
                self.read_exact(
                    reader,
                    &ambiguity.descriptor,
                    control,
                    ambiguity.deadline_ns,
                )
                .map_err(|source| FetchRecoveryError {
                    // A verified Complete receipt identifies a replayable
                    // original body. Retain it through cancellation, deadline,
                    // transport, and final integrity/read-control failures.
                    ambiguity: Some(ambiguity),
                    source,
                })
            }
            FetchRecovery::NoEffect { receipt } => {
                if let Err(source) = validate_recovery_receipt(receipt, &ambiguity) {
                    return Err(FetchRecoveryError {
                        ambiguity: Some(ambiguity),
                        source,
                    });
                }
                let next = next_attempt(ambiguity.attempt, self.limits.maximum_attempts).map_err(
                    |source| FetchRecoveryError {
                        ambiguity: None,
                        source,
                    },
                )?;
                match self.resume_after_no_effect(ambiguity, next, control) {
                    Ok(object) => Ok(object),
                    Err(RemoteFetchError::Ambiguous(next_ambiguity)) => Err(FetchRecoveryError {
                        ambiguity: Some(next_ambiguity),
                        source: RemoteFetchError::RecoveryStillAmbiguous,
                    }),
                    Err(source) => Err(FetchRecoveryError {
                        ambiguity: None,
                        source,
                    }),
                }
            }
            FetchRecovery::StillAmbiguous { receipt } => {
                if let Err(source) = validate_recovery_receipt(receipt, &ambiguity) {
                    return Err(FetchRecoveryError {
                        ambiguity: Some(ambiguity),
                        source,
                    });
                }
                Err(FetchRecoveryError {
                    ambiguity: Some(FetchAmbiguity {
                        receipt,
                        ..ambiguity
                    }),
                    source: RemoteFetchError::RecoveryStillAmbiguous,
                })
            }
            FetchRecovery::IntegrityFailure { receipt } => {
                if let Err(source) = validate_recovery_receipt(receipt, &ambiguity) {
                    return Err(FetchRecoveryError {
                        ambiguity: Some(ambiguity),
                        source,
                    });
                }
                Err(FetchRecoveryError {
                    ambiguity: None,
                    source: RemoteFetchError::IntegrityFailure,
                })
            }
        }
    }

    fn resume_after_no_effect(
        &mut self,
        ambiguity: FetchAmbiguity,
        attempt: u16,
        control: &impl FetchControl,
    ) -> Result<ExactObject, RemoteFetchError> {
        let mut attempt = attempt;
        loop {
            check_control(control, ambiguity.deadline_ns)?;
            let outcome = self.poll_begin(
                &ambiguity.descriptor,
                ambiguity.request_digest,
                attempt,
                ambiguity.deadline_ns,
                control,
            )?;
            match outcome {
                FetchAttempt::Complete { reader, receipt } => {
                    validate_receipt(receipt, ambiguity.request_digest, attempt)?;
                    return self.read_exact(
                        reader,
                        &ambiguity.descriptor,
                        control,
                        ambiguity.deadline_ns,
                    );
                }
                FetchAttempt::Retryable {
                    retry_after_ns,
                    receipt,
                } => {
                    validate_receipt(receipt, ambiguity.request_digest, attempt)?;
                    attempt = next_attempt(attempt, self.limits.maximum_attempts)?;
                    wait_retry(control, retry_after_ns, ambiguity.deadline_ns, self.limits)?;
                }
                FetchAttempt::Ambiguous { receipt } => {
                    validate_receipt(receipt, ambiguity.request_digest, attempt)?;
                    return Err(RemoteFetchError::Ambiguous(FetchAmbiguity {
                        attempt,
                        receipt,
                        ..ambiguity
                    }));
                }
                FetchAttempt::IntegrityFailure { receipt } => {
                    validate_receipt(receipt, ambiguity.request_digest, attempt)?;
                    return Err(RemoteFetchError::IntegrityFailure);
                }
            }
        }
    }

    fn read_exact(
        &mut self,
        mut reader: T::Reader,
        descriptor: &ObjectDescriptor,
        control: &impl FetchControl,
        deadline_ns: u64,
    ) -> Result<ExactObject, RemoteFetchError> {
        if descriptor.encoded_size() > self.limits.maximum_object_bytes {
            return Err(RemoteFetchError::ObjectTooLarge);
        }
        let length = usize::try_from(descriptor.encoded_size())
            .map_err(|_| RemoteFetchError::ObjectTooLarge)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| RemoteFetchError::AllocationRefused)?;
        let mut scratch = [0_u8; READ_BUFFER_BYTES];
        while bytes.len() < length {
            check_control(control, deadline_ns)?;
            let remaining = (length - bytes.len())
                .min(scratch.len())
                .min(self.limits.maximum_poll_bytes);
            match self
                .transport
                .poll_read(&mut reader, &mut scratch[..remaining], deadline_ns, control)
                .map_err(|error| RemoteFetchError::Transport(Box::new(error)))?
            {
                FetchRead::Data { bytes: read } if read > 0 && read <= remaining => {
                    bytes.extend_from_slice(&scratch[..read]);
                }
                FetchRead::Data { .. } | FetchRead::Eof => {
                    return Err(RemoteFetchError::LengthMismatch);
                }
                FetchRead::Pending { retry_after_ns } => {
                    wait_retry(control, retry_after_ns, deadline_ns, self.limits)?;
                }
            }
        }

        loop {
            check_control(control, deadline_ns)?;
            match self
                .transport
                .poll_read(&mut reader, &mut scratch[..1], deadline_ns, control)
                .map_err(|error| RemoteFetchError::Transport(Box::new(error)))?
            {
                FetchRead::Eof => break,
                FetchRead::Data { .. } => return Err(RemoteFetchError::LengthMismatch),
                FetchRead::Pending { retry_after_ns } => {
                    wait_retry(control, retry_after_ns, deadline_ns, self.limits)?;
                }
            }
        }
        if descriptor_for_bytes(descriptor.media_type().clone(), &bytes) != *descriptor {
            return Err(RemoteFetchError::IntegrityFailure);
        }
        Ok(ExactObject::from_verified(bytes))
    }

    fn poll_begin(
        &mut self,
        descriptor: &ObjectDescriptor,
        request_digest: ObjectDigest,
        attempt: u16,
        deadline_ns: u64,
        control: &impl FetchControl,
    ) -> Result<FetchAttempt<T::Reader>, RemoteFetchError> {
        loop {
            check_control(control, deadline_ns)?;
            match self
                .transport
                .poll_fetch(descriptor, request_digest, attempt, deadline_ns, control)
                .map_err(|error| RemoteFetchError::Transport(Box::new(error)))?
            {
                FetchBeginPoll::Ready(outcome) => {
                    // Once the transport reports ambiguity, its token is the
                    // only safe next authority even if cancellation raced the
                    // completed poll.
                    if matches!(outcome, FetchAttempt::Ambiguous { .. }) {
                        return Ok(outcome);
                    }
                    check_control(control, deadline_ns)?;
                    return Ok(outcome);
                }
                FetchBeginPoll::Pending { retry_after_ns } => {
                    wait_retry(control, retry_after_ns, deadline_ns, self.limits)?;
                }
            }
        }
    }

    fn poll_recovery(
        &mut self,
        ambiguity: &FetchAmbiguity,
        control: &impl FetchControl,
    ) -> Result<FetchRecovery<T::Reader>, RemoteFetchError> {
        loop {
            check_control(control, ambiguity.deadline_ns)?;
            match self
                .transport
                .poll_recover(
                    &ambiguity.descriptor,
                    ambiguity.receipt,
                    ambiguity.deadline_ns,
                    control,
                )
                .map_err(|error| RemoteFetchError::Transport(Box::new(error)))?
            {
                FetchRecoveryPoll::Ready(outcome) => {
                    check_control(control, ambiguity.deadline_ns)?;
                    return Ok(outcome);
                }
                FetchRecoveryPoll::Pending { retry_after_ns } => {
                    wait_retry(control, retry_after_ns, ambiguity.deadline_ns, self.limits)?;
                }
            }
        }
    }
}

fn request_digest(
    descriptor: &ObjectDescriptor,
    operation_binding: [u8; 32],
    deadline_ns: u64,
) -> Result<ObjectDigest, RemoteFetchError> {
    if operation_binding == [0; 32] || deadline_ns == 0 || descriptor.encoded_size() == 0 {
        return Err(RemoteFetchError::InvalidRequest);
    }
    let mut hasher = Sha256::new();
    hasher.update(b"aos.filesystem-view.remote-fetch.v1\0");
    hasher.update(operation_binding);
    hasher.update((descriptor.media_type().as_str().len() as u16).to_be_bytes());
    hasher.update(descriptor.media_type().as_str().as_bytes());
    hasher.update(descriptor.digest().as_bytes());
    hasher.update(descriptor.encoded_size().to_be_bytes());
    hasher.update(deadline_ns.to_be_bytes());
    Ok(ObjectDigest::from_bytes(hasher.finalize().into()))
}

fn validate_receipt(
    receipt: FetchReceipt,
    request: ObjectDigest,
    attempt: u16,
) -> Result<(), RemoteFetchError> {
    if receipt.request_digest != request || receipt.attempt != attempt {
        return Err(RemoteFetchError::InvalidReceipt);
    }
    Ok(())
}

fn validate_recovery_receipt(
    receipt: FetchReceipt,
    ambiguity: &FetchAmbiguity,
) -> Result<(), RemoteFetchError> {
    validate_receipt(receipt, ambiguity.request_digest, ambiguity.attempt)?;
    if receipt != ambiguity.receipt {
        return Err(RemoteFetchError::InvalidReceipt);
    }
    Ok(())
}

fn check_control(control: &impl FetchControl, deadline_ns: u64) -> Result<(), RemoteFetchError> {
    match control.state() {
        FetchControlState::Continue if control.now_ns() < deadline_ns => Ok(()),
        FetchControlState::Continue | FetchControlState::DeadlineExpired => {
            Err(RemoteFetchError::DeadlineExpired)
        }
        FetchControlState::Cancelled => Err(RemoteFetchError::Cancelled),
    }
}

fn wait_retry(
    control: &impl FetchControl,
    retry_after_ns: u64,
    deadline_ns: u64,
    limits: FetchLimits,
) -> Result<(), RemoteFetchError> {
    if retry_after_ns == 0 || retry_after_ns > limits.maximum_retry_delay_ns {
        return Err(RemoteFetchError::InvalidReceipt);
    }
    let ready = control
        .now_ns()
        .checked_add(retry_after_ns)
        .ok_or(RemoteFetchError::DeadlineExpired)?;
    if ready >= deadline_ns {
        return Err(RemoteFetchError::DeadlineExpired);
    }
    control.wait_until(ready, deadline_ns)
}

fn next_attempt(current: u16, maximum: u16) -> Result<u16, RemoteFetchError> {
    let next = current
        .checked_add(1)
        .ok_or(RemoteFetchError::RetryExhausted)?;
    if next > maximum {
        return Err(RemoteFetchError::RetryExhausted);
    }
    Ok(next)
}

/// Reports bounded immutable remote-source failure.
#[derive(Debug, thiserror::Error)]
pub enum RemoteFetchError {
    /// Request identity, deadline, or configured limits are invalid.
    #[error("invalid remote fetch request")]
    InvalidRequest,
    /// The immutable descriptor exceeds its hard object ceiling.
    #[error("remote object exceeds the configured byte ceiling")]
    ObjectTooLarge,
    /// Exact object-buffer allocation was refused.
    #[error("remote object allocation was refused")]
    AllocationRefused,
    /// The trusted transport failed before an ambiguous effect.
    #[error("immutable transport failed: {0}")]
    Transport(#[source] Box<dyn StdError + Send + Sync>),
    /// Receipt request or attempt identity did not match.
    #[error("immutable transport returned a foreign or malformed receipt")]
    InvalidReceipt,
    /// Exact stream length differed from the descriptor.
    #[error("immutable transport returned a different object length")]
    LengthMismatch,
    /// Digest, size, or remote proof failed closed.
    #[error("immutable remote object failed integrity validation")]
    IntegrityFailure,
    /// The bounded attempt count was exhausted.
    #[error("immutable remote fetch exhausted its retry bound")]
    RetryExhausted,
    /// Caller cancellation was observed.
    #[error("immutable remote fetch was cancelled")]
    Cancelled,
    /// The absolute monotonic deadline expired.
    #[error("immutable remote fetch deadline expired")]
    DeadlineExpired,
    /// One exact transport outcome remains unknown.
    #[error("immutable remote fetch outcome is ambiguous")]
    Ambiguous(FetchAmbiguity),
    /// Exact recovery remains nonterminal and retains its ambiguity token.
    #[error("immutable remote recovery remains ambiguous")]
    RecoveryStillAmbiguous,
}
