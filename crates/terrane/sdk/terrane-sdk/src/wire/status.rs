//! Maps explicit service outcomes to the normative Distribution error contract.
//!
//! Callers authorize and classify an operation before selecting an [`Outcome`].
//! Raw store diagnostics cannot select a disclosure policy here. Every produced
//! status carries `terrane.v1.ErrorInfo`; public messages contain no backend
//! diagnostics, credentials, paths or existence information beyond the outcome.

use std::{fmt, time::Duration};

use super::v1;

/// Names the error codes used by the normative outcome table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StatusCode {
    /// The caller cancelled the operation.
    Cancelled,
    /// The request is malformed or exceeds a request limit.
    InvalidArgument,
    /// The request's deadline expired.
    DeadlineExceeded,
    /// The requested value is absent or cannot be disclosed.
    NotFound,
    /// The exact uploaded pack is already held.
    AlreadyExists,
    /// The authenticated grant does not cover the operation.
    PermissionDenied,
    /// A quota, admission budget or advertised pack-size limit is exhausted.
    ResourceExhausted,
    /// The operation cannot proceed under its current preconditions.
    FailedPrecondition,
    /// A merge or bounded rebase failed.
    Aborted,
    /// A pack range or reflog resume point is unavailable.
    OutOfRange,
    /// A method or advertised encoding is unsupported.
    Unimplemented,
    /// An internal failure prevented completion.
    Internal,
    /// A transient failure prevents completion.
    Unavailable,
    /// Authentication is missing or invalid.
    Unauthenticated,
}

impl StatusCode {
    /// Returns the standard gRPC numeric status code.
    pub const fn grpc_code(self) -> u32 {
        match self {
            Self::Cancelled => 1,
            Self::InvalidArgument => 3,
            Self::DeadlineExceeded => 4,
            Self::NotFound => 5,
            Self::AlreadyExists => 6,
            Self::PermissionDenied => 7,
            Self::ResourceExhausted => 8,
            Self::FailedPrecondition => 9,
            Self::Aborted => 10,
            Self::OutOfRange => 11,
            Self::Unimplemented => 12,
            Self::Internal => 13,
            Self::Unavailable => 14,
            Self::Unauthenticated => 16,
        }
    }
}

/// Retains a nonnegative retry minimum representable by protobuf Duration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryDelay(Duration);

impl RetryDelay {
    /// Validates a retry minimum without truncating or wrapping its value.
    ///
    /// # Errors
    /// Rejects durations whose seconds exceed protobuf's 10,000-year bound.
    pub fn new(duration: Duration) -> Result<Self, InvalidRetryDelay> {
        if duration.as_secs() > 315_576_000_000 {
            return Err(InvalidRetryDelay);
        }

        Ok(Self(duration))
    }

    /// Returns the original minimum backoff.
    pub const fn duration(self) -> Duration {
        self.0
    }

    fn into_wire(self) -> buffa_types::google::protobuf::Duration {
        // Construction proves the seconds fit i64 and nanos are below 10^9.
        buffa_types::google::protobuf::Duration {
            seconds: self.0.as_secs() as i64,
            nanos: self.0.subsec_nanos() as i32,
            ..Default::default()
        }
    }
}

/// Rejects a retry minimum outside protobuf Duration's representable range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidRetryDelay;

impl fmt::Display for InvalidRetryDelay {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("retry minimum exceeds protobuf Duration range")
    }
}

impl std::error::Error for InvalidRetryDelay {}

/// Carries the additional typed detail required for a classified outcome.
#[derive(Clone, Debug, PartialEq)]
pub enum StatusDetail {
    /// Identifies an exceeded request or pack-size limit.
    Limit(v1::Limit),
    /// Retains the backend's actual idempotent pack acknowledgement.
    PackAck(v1::PackAck),
    /// Retains the actual current ref state or a fenced state.
    RefState(v1::RefState),
    /// Names packs that the authority cannot locate.
    MissingPacks(v1::MissingPacks),
    /// Retains the request's exhausted hop budget and observed path.
    HopLimit(v1::HopLimit),
    /// Retains the conflict paths and attempted rebase count.
    Conflict(v1::Conflict),
    /// Identifies the exhausted root quota.
    Quota(v1::Quota),
    /// Identifies the exhausted admission budget.
    Budget(v1::Budget),
    /// Identifies an unreachable home authority.
    Home(v1::Home),
    /// Retains the requested and observed freshness bounds.
    Staleness(v1::Staleness),
    /// Retains the backend's conditional-write probe result.
    BackendProbe(v1::BackendProbe),
    /// Lists supported pack and tree encoding versions.
    Versions(v1::Versions),
}

/// Describes an already authorized and classified service failure.
///
/// Local-only reservation, exposure and chunk-verification outcomes are absent:
/// the normative table does not send those directly over Distribution. Supplying
/// a detail is not proof that a backend acknowledged or durably stored anything.
#[derive(Clone, Debug)]
pub enum Outcome {
    /// Reports malformed requests or exceeded hash/frame count limits.
    Malformed(v1::Limit),
    /// Rejects an unknown enum in a field the service must act upon.
    UnknownEnum,
    /// Requires valid authentication, potentially after credential refresh.
    Unauthenticated,
    /// Denies a verb without disclosing whether protected content exists.
    GrantDenied,
    /// Uses the identical response for absent and undisclosed content or refs.
    NotFound,
    /// Retains an actual already-held pack acknowledgement.
    PackAlreadyHeld(v1::PackAck),
    /// Requires the client to re-read the actual current ref before another CAS.
    CasMismatch(v1::RefState),
    /// Requires missing dependencies to be uploaded before another ref advance.
    MissingPacks(v1::MissingPacks),
    /// Rejects forwarding beyond the configured hop limit.
    HopLimit(v1::HopLimit),
    /// Permanently fences the exposure's writer.
    WriterFenced(v1::RefState),
    /// Reports an expired exposure lease with a fenced ref state.
    LeaseExpired(v1::RefState),
    /// Reports an unresolved merge conflict.
    MergeConflict(v1::Conflict),
    /// Reports exhausted bounded rebase attempts.
    RebaseExhausted(v1::Conflict),
    /// Requires re-reading the ref after the resume point was truncated.
    ReflogTruncated,
    /// Rejects a range beyond the pack's end.
    RangeBeyondEnd,
    /// Refuses a commit exceeding its root quota.
    RootQuota(v1::Quota),
    /// Refuses warming or serving after its admission budget is spent.
    AdmissionBudget(v1::Budget, RetryDelay),
    /// Rejects a pack larger than the server's advertised limit.
    PackTooLarge(v1::Limit),
    /// Reports an unreachable home authority and an optional retry minimum.
    HomeUnavailable(v1::Home, Option<RetryDelay>),
    /// Reports unsatisfied freshness and an optional retry minimum.
    FreshnessUnavailable(v1::Staleness, Option<RetryDelay>),
    /// Rejects multiple writers when the backend lacks conditional writes.
    ConditionalWritesUnavailable(v1::BackendProbe),
    /// Reports a transient backend or transport failure.
    Transient(Option<RetryDelay>),
    /// Reports an expired request deadline.
    DeadlineExceeded,
    /// Reports explicit caller cancellation.
    Cancelled,
    /// Rejects an unadvertised pack or tree encoding version.
    UnsupportedVersion(v1::Versions),
    /// Reports a method unavailable in this service implementation.
    MethodUnavailable,
    /// Reports an internal failure without publishing backend diagnostics.
    Internal,
}

/// Holds one error code, its mandatory ErrorInfo and its required typed detail.
#[derive(Clone, Debug, PartialEq)]
pub struct ProtocolError {
    code: StatusCode,
    message: &'static str,
    info: v1::ErrorInfo,
    detail: Option<StatusDetail>,
}

impl ProtocolError {
    /// Maps an explicit outcome using the normative error mapping table.
    ///
    /// `trace_id` is the caller's existing trace context. Only outcomes whose
    /// table Retry column says `yes` enable automatic retry; re-read, upload,
    /// refresh and rebase instructions do not authorize blind retries.
    pub fn from_outcome(outcome: Outcome, trace_id: &str) -> Self {
        use Outcome as O;
        use StatusCode as C;
        use StatusDetail as D;

        let retryable = matches!(
            &outcome,
            O::HomeUnavailable(..)
                | O::FreshnessUnavailable(..)
                | O::Transient(..)
                | O::DeadlineExceeded
        );
        let retry_after = match &outcome {
            O::HomeUnavailable(_, delay)
            | O::FreshnessUnavailable(_, delay)
            | O::Transient(delay) => *delay,
            O::AdmissionBudget(_, delay) => Some(*delay),
            _ => None,
        };
        let (code, message, detail) = match outcome {
            O::Malformed(detail) => (
                C::InvalidArgument,
                "invalid request",
                Some(D::Limit(detail)),
            ),
            O::UnknownEnum => (C::InvalidArgument, "unknown enum value", None),
            O::Unauthenticated => (C::Unauthenticated, "authentication required", None),
            O::GrantDenied => (C::PermissionDenied, "operation denied", None),
            O::NotFound => (C::NotFound, "not found", None),
            O::PackAlreadyHeld(detail) => (
                C::AlreadyExists,
                "pack already held",
                Some(D::PackAck(detail)),
            ),
            O::CasMismatch(detail) => (
                C::FailedPrecondition,
                "ref precondition failed",
                Some(D::RefState(detail)),
            ),
            O::MissingPacks(detail) => (
                C::FailedPrecondition,
                "required packs unavailable",
                Some(D::MissingPacks(detail)),
            ),
            O::HopLimit(detail) => (
                C::FailedPrecondition,
                "hop limit reached",
                Some(D::HopLimit(detail)),
            ),
            O::WriterFenced(mut detail) | O::LeaseExpired(mut detail) => {
                detail.fenced = true;
                (
                    C::FailedPrecondition,
                    "writer fenced",
                    Some(D::RefState(detail)),
                )
            }
            O::MergeConflict(detail) | O::RebaseExhausted(detail) => {
                (C::Aborted, "conflict unresolved", Some(D::Conflict(detail)))
            }
            O::ReflogTruncated => (C::OutOfRange, "reflog resume point unavailable", None),
            O::RangeBeyondEnd => (C::OutOfRange, "range beyond pack end", None),
            O::RootQuota(detail) => (
                C::ResourceExhausted,
                "root quota exceeded",
                Some(D::Quota(detail)),
            ),
            O::AdmissionBudget(detail, _) => (
                C::ResourceExhausted,
                "admission budget exhausted",
                Some(D::Budget(detail)),
            ),
            O::PackTooLarge(detail) => (
                C::ResourceExhausted,
                "pack size limit exceeded",
                Some(D::Limit(detail)),
            ),
            O::HomeUnavailable(detail, _) => (
                C::Unavailable,
                "home authority unavailable",
                Some(D::Home(detail)),
            ),
            O::FreshnessUnavailable(detail, _) => (
                C::Unavailable,
                "freshness bound unavailable",
                Some(D::Staleness(detail)),
            ),
            O::ConditionalWritesUnavailable(detail) => (
                C::FailedPrecondition,
                "conditional writes unavailable",
                Some(D::BackendProbe(detail)),
            ),
            O::Transient(_) => (C::Unavailable, "service unavailable", None),
            O::DeadlineExceeded => (C::DeadlineExceeded, "deadline exceeded", None),
            O::Cancelled => (C::Cancelled, "cancelled", None),
            O::UnsupportedVersion(detail) => (
                C::Unimplemented,
                "encoding version unsupported",
                Some(D::Versions(detail)),
            ),
            O::MethodUnavailable => (C::Unimplemented, "method unavailable", None),
            O::Internal => (C::Internal, "internal error", None),
        };
        let mut info = v1::ErrorInfo {
            retryable,
            trace_id: trace_id.to_owned(),
            ..Default::default()
        };
        if let Some(delay) = retry_after {
            info.retry_after = delay.into_wire().into();
        }

        Self {
            code,
            message,
            info,
            detail,
        }
    }

    /// Returns the normative status code.
    pub const fn code(&self) -> StatusCode {
        self.code
    }

    /// Returns the fixed public message without backend diagnostic text.
    pub const fn message(&self) -> &'static str {
        self.message
    }

    /// Returns the mandatory structured retry and trace context detail.
    pub fn error_info(&self) -> &v1::ErrorInfo {
        &self.info
    }

    /// Returns the additional detail required for this outcome, when any.
    pub fn detail(&self) -> Option<&StatusDetail> {
        self.detail.as_ref()
    }
}

#[cfg(feature = "tokio")]
mod native {
    use super::*;
    use connectrpc::{ConnectError, ErrorCode, ErrorDetail};

    impl From<ProtocolError> for ConnectError {
        fn from(status: ProtocolError) -> Self {
            let code = match status.code {
                StatusCode::Cancelled => ErrorCode::Canceled,
                StatusCode::InvalidArgument => ErrorCode::InvalidArgument,
                StatusCode::DeadlineExceeded => ErrorCode::DeadlineExceeded,
                StatusCode::NotFound => ErrorCode::NotFound,
                StatusCode::AlreadyExists => ErrorCode::AlreadyExists,
                StatusCode::PermissionDenied => ErrorCode::PermissionDenied,
                StatusCode::ResourceExhausted => ErrorCode::ResourceExhausted,
                StatusCode::FailedPrecondition => ErrorCode::FailedPrecondition,
                StatusCode::Aborted => ErrorCode::Aborted,
                StatusCode::OutOfRange => ErrorCode::OutOfRange,
                StatusCode::Unimplemented => ErrorCode::Unimplemented,
                StatusCode::Internal => ErrorCode::Internal,
                StatusCode::Unavailable => ErrorCode::Unavailable,
                StatusCode::Unauthenticated => ErrorCode::Unauthenticated,
            };
            let mut error = ConnectError::new(code, status.message).with_detail(
                ErrorDetail::from_message("terrane.v1.ErrorInfo", &status.info),
            );
            if let Some(detail) = status.detail {
                let detail = match detail {
                    StatusDetail::Limit(value) => {
                        ErrorDetail::from_message("terrane.v1.Limit", &value)
                    }
                    StatusDetail::PackAck(value) => {
                        ErrorDetail::from_message("terrane.v1.PackAck", &value)
                    }
                    StatusDetail::RefState(value) => {
                        ErrorDetail::from_message("terrane.v1.RefState", &value)
                    }
                    StatusDetail::MissingPacks(value) => {
                        ErrorDetail::from_message("terrane.v1.MissingPacks", &value)
                    }
                    StatusDetail::HopLimit(value) => {
                        ErrorDetail::from_message("terrane.v1.HopLimit", &value)
                    }
                    StatusDetail::Conflict(value) => {
                        ErrorDetail::from_message("terrane.v1.Conflict", &value)
                    }
                    StatusDetail::Quota(value) => {
                        ErrorDetail::from_message("terrane.v1.Quota", &value)
                    }
                    StatusDetail::Budget(value) => {
                        ErrorDetail::from_message("terrane.v1.Budget", &value)
                    }
                    StatusDetail::Home(value) => {
                        ErrorDetail::from_message("terrane.v1.Home", &value)
                    }
                    StatusDetail::Staleness(value) => {
                        ErrorDetail::from_message("terrane.v1.Staleness", &value)
                    }
                    StatusDetail::BackendProbe(value) => {
                        ErrorDetail::from_message("terrane.v1.BackendProbe", &value)
                    }
                    StatusDetail::Versions(value) => {
                        ErrorDetail::from_message("terrane.v1.Versions", &value)
                    }
                };
                error = error.with_detail(detail);
            }
            error
        }
    }
}
