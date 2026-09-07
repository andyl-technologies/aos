//! Transport-neutral service adapter for durable ownership transactions.
//!
//! This module maps validated ownership protocol envelopes onto the protected
//! durable authority. It does not define a socket, peer identity, or wire
//! codec. A process boundary must authenticate and authorize its peer, enforce
//! negotiated frame bounds before allocation, and call the protocol's hostile
//! request validator before dispatch. The in-process client is intentionally a
//! same-TCB composition aid and does not claim to create a security boundary.

use aos_sandbox_core::{ProtocolVersion, RawPairedClockSample};
use aos_sandbox_ownership_protocol::protocol::{
    MAXIMUM_OWNERSHIP_REQUEST_BYTES, MAXIMUM_OWNERSHIP_RESPONSE_BYTES,
    MINIMUM_OWNERSHIP_RESPONSE_BYTES, NegotiatedOwnershipSessionV1, OwnershipMethodV1,
    OwnershipProtocolErrorCodeV1, OwnershipProtocolValidationError, OwnershipRequestBodyV1,
    OwnershipRequestEnvelopeV1, OwnershipResponseEnvelopeV1, OwnershipResponseOutcomeV1,
    OwnershipTransactionStatusV1,
};

use crate::{
    DurableOwnershipAuthority, DurableOwnershipAuthorityError, DurableOwnershipBeginOutcome,
    DurableOwnershipQueryOutcome, OwnershipAuthority, OwnershipAuthorityError,
    OwnershipAuthoritySessionClient, OwnershipClaimAction, OwnershipLeaseAcquisitionError,
    OwnershipSessionTransportError, ProtectedOwnershipClockError,
    UntrustedOwnershipResponsePartsV1,
};

const SERVICE_METHODS: [OwnershipMethodV1; 3] = [
    OwnershipMethodV1::Begin,
    OwnershipMethodV1::CompleteOrResume,
    OwnershipMethodV1::Query,
];

/// Reports invalid service composition or request-session substitution.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum OwnershipProtocolServiceError {
    /// The session does not exactly select this authority and V1 service shape.
    #[error("ownership protocol service session is invalid")]
    InvalidSession,
    /// A request or response violates the negotiated semantic protocol.
    #[error("ownership protocol service envelope is invalid: {0}")]
    Protocol(#[from] OwnershipProtocolValidationError),
}

/// Dispatches one negotiated session onto a protected durable authority.
///
/// The adapter must be constructed only after its carrier authenticates and
/// authorizes the peer. The carrier retains responsibility for framing and
/// pre-allocation bounds. This type owns only portable semantic dispatch.
pub struct DurableOwnershipProtocolService<'a, I, C> {
    session: NegotiatedOwnershipSessionV1,
    authority: &'a mut DurableOwnershipAuthority,
    issuer: &'a mut I,
    protected_clock: &'a mut C,
}

impl<'a, I, C> DurableOwnershipProtocolService<'a, I, C>
where
    I: OwnershipAuthority,
    C: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    /// Binds one exact negotiated session to its protected authority backend.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipProtocolServiceError::InvalidSession`] unless the
    /// session selects protocol 1.0, the authority's exact key generation, all
    /// three canonical methods, the fixed request bound, a sufficient response
    /// bound, and the fixed lease-duration bound.
    pub fn new(
        session: NegotiatedOwnershipSessionV1,
        authority: &'a mut DurableOwnershipAuthority,
        issuer: &'a mut I,
        protected_clock: &'a mut C,
    ) -> Result<Self, OwnershipProtocolServiceError> {
        if (session.version() != ProtocolVersion::new(1, 0)
            && session.version() != ProtocolVersion::new(1, 1))
            || session.authority() != authority.authority()
            || session.methods() != SERVICE_METHODS
            || session.maximum_request_bytes() != MAXIMUM_OWNERSHIP_REQUEST_BYTES
            || !(MINIMUM_OWNERSHIP_RESPONSE_BYTES..=MAXIMUM_OWNERSHIP_RESPONSE_BYTES)
                .contains(&session.maximum_response_bytes())
            || session.maximum_requested_lease_seconds()
                != aos_sandbox_ownership_protocol::MAXIMUM_REQUESTED_DURATION_SECONDS
        {
            return Err(OwnershipProtocolServiceError::InvalidSession);
        }
        Ok(Self {
            session,
            authority,
            issuer,
            protected_clock,
        })
    }

    /// Returns the immutable negotiated semantic session.
    #[must_use]
    pub const fn session(&self) -> &NegotiatedOwnershipSessionV1 {
        &self.session
    }

    /// Handles one already-authenticated, independently validated request.
    ///
    /// Query reads only protected durable state. Begin writes only an unsigned
    /// intent. CompleteOrResume first queries the exact binding while holding
    /// the authority's exclusive mutable borrow and contacts the issuer only
    /// when that exact transaction remains pending.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipProtocolServiceError::Protocol`] for a foreign
    /// session, method/body substitution, or an impossible response shape.
    pub fn handle(
        &mut self,
        request: &OwnershipRequestEnvelopeV1,
    ) -> Result<OwnershipResponseEnvelopeV1, OwnershipProtocolServiceError> {
        let request = self.session.validate_request_parts(
            *request.session_binding(),
            request.method(),
            request.body().clone(),
        )?;
        // Follow-up requests carry only a reference. Check the retained
        // action before Query reveals its state or Complete contacts an issuer;
        // a 1.0 reconnect cannot resume a transaction requiring 1.1.
        let retained_action = self.authority.transaction_action(request.transaction());
        let version_error = match retained_action {
            Ok(Some(action))
                if action.minimum_protocol_version().minor() > self.session.version().minor() =>
            {
                Some(OwnershipProtocolErrorCodeV1::RequiredCapabilityUnavailable)
            }
            Err(error) => Some(map_durable_error(error, None)),
            _ => None,
        };
        if let Some(error) = version_error {
            return self
                .session
                .response(&request, protocol_error(error))
                .map_err(OwnershipProtocolServiceError::Protocol);
        }
        let outcome = match request.body() {
            OwnershipRequestBodyV1::Query(reference) => self.query(*reference),
            OwnershipRequestBodyV1::Begin(claim) => self.begin(claim),
            OwnershipRequestBodyV1::CompleteOrResume(reference) => self.complete(*reference),
        };
        self.session
            .response(&request, outcome)
            .map_err(OwnershipProtocolServiceError::Protocol)
    }

    fn query(
        &self,
        reference: aos_sandbox_ownership_protocol::protocol::OwnershipTransactionReferenceV1,
    ) -> OwnershipResponseOutcomeV1 {
        match self.authority.query(reference) {
            Ok(DurableOwnershipQueryOutcome::Absent) => {
                status(OwnershipTransactionStatusV1::Absent)
            }
            Ok(DurableOwnershipQueryOutcome::Pending { .. }) => {
                status(OwnershipTransactionStatusV1::Pending)
            }
            Ok(DurableOwnershipQueryOutcome::Completed(response)) => {
                status(OwnershipTransactionStatusV1::Completed(*response))
            }
            Err(error) => protocol_error(map_durable_error(error, None)),
        }
    }

    fn begin(
        &mut self,
        claim: &aos_sandbox_ownership_protocol::OwnershipClaimV1,
    ) -> OwnershipResponseOutcomeV1 {
        match self.authority.begin(claim) {
            Ok(DurableOwnershipBeginOutcome::Pending) => {
                status(OwnershipTransactionStatusV1::Pending)
            }
            Ok(DurableOwnershipBeginOutcome::Replay(response)) => {
                status(OwnershipTransactionStatusV1::Completed(*response))
            }
            Err(error) => protocol_error(map_durable_error(error, Some(claim.action()))),
        }
    }

    fn complete(
        &mut self,
        reference: aos_sandbox_ownership_protocol::protocol::OwnershipTransactionReferenceV1,
    ) -> OwnershipResponseOutcomeV1 {
        let action = match self.authority.query(reference) {
            Ok(DurableOwnershipQueryOutcome::Absent) => {
                return protocol_error(OwnershipProtocolErrorCodeV1::NotFound);
            }
            Ok(DurableOwnershipQueryOutcome::Completed(response)) => {
                return status(OwnershipTransactionStatusV1::Completed(*response));
            }
            Ok(DurableOwnershipQueryOutcome::Pending { action }) => action,
            Err(error) => return protocol_error(map_durable_error(error, None)),
        };
        match self
            .authority
            .complete(*reference.request_id(), self.issuer, self.protected_clock)
        {
            Ok(response) => status(OwnershipTransactionStatusV1::Completed(response)),
            Err(error) => protocol_error(map_durable_error(error, Some(action))),
        }
    }
}

/// Bridges a same-process controller and durable ownership service.
///
/// This adapter is valid only when both endpoints share one trusted computing
/// base. It deliberately provides no peer-authentication claim. A process or
/// machine boundary must replace it with an authenticated carrier while
/// retaining the same negotiated session and service handler.
pub struct InProcessOwnershipSessionClient<'a, I, C> {
    service: DurableOwnershipProtocolService<'a, I, C>,
}

impl<'a, I, C> InProcessOwnershipSessionClient<'a, I, C>
where
    I: OwnershipAuthority,
    C: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    /// Constructs a same-TCB client and service composition.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipProtocolServiceError::InvalidSession`] when the
    /// negotiated session does not exactly match the durable authority.
    pub fn new(
        session: NegotiatedOwnershipSessionV1,
        authority: &'a mut DurableOwnershipAuthority,
        issuer: &'a mut I,
        protected_clock: &'a mut C,
    ) -> Result<Self, OwnershipProtocolServiceError> {
        Ok(Self {
            service: DurableOwnershipProtocolService::new(
                session,
                authority,
                issuer,
                protected_clock,
            )?,
        })
    }
}

impl<I, C> OwnershipAuthoritySessionClient for InProcessOwnershipSessionClient<'_, I, C>
where
    I: OwnershipAuthority,
    C: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    fn session(&self) -> &NegotiatedOwnershipSessionV1 {
        self.service.session()
    }

    fn exchange(
        &mut self,
        request: &OwnershipRequestEnvelopeV1,
    ) -> Result<UntrustedOwnershipResponsePartsV1, OwnershipSessionTransportError> {
        let response = self
            .service
            .handle(request)
            .map_err(|_| OwnershipSessionTransportError::IntegrityFailure)?;
        Ok(UntrustedOwnershipResponsePartsV1::new(
            *response.session_binding(),
            response.method(),
            response.transaction(),
            response.outcome().clone(),
        ))
    }
}

fn status(status: OwnershipTransactionStatusV1) -> OwnershipResponseOutcomeV1 {
    OwnershipResponseOutcomeV1::Status(status)
}

fn protocol_error(error: OwnershipProtocolErrorCodeV1) -> OwnershipResponseOutcomeV1 {
    OwnershipResponseOutcomeV1::Error(error)
}

fn map_durable_error(
    error: DurableOwnershipAuthorityError,
    action: Option<OwnershipClaimAction>,
) -> OwnershipProtocolErrorCodeV1 {
    match error {
        DurableOwnershipAuthorityError::Journal(_)
        | DurableOwnershipAuthorityError::ProtectedClockUnavailable(_) => {
            OwnershipProtocolErrorCodeV1::Unavailable
        }
        DurableOwnershipAuthorityError::CorruptState => {
            OwnershipProtocolErrorCodeV1::IntegrityFailure
        }
        DurableOwnershipAuthorityError::MigrationRequired => {
            OwnershipProtocolErrorCodeV1::RequiredCapabilityUnavailable
        }
        DurableOwnershipAuthorityError::IdempotencyConflict => {
            OwnershipProtocolErrorCodeV1::IdempotencyConflict
        }
        DurableOwnershipAuthorityError::CompareAndSwapConflict => match action {
            Some(OwnershipClaimAction::Acquire) => OwnershipProtocolErrorCodeV1::AlreadyOwned,
            Some(OwnershipClaimAction::Renew | OwnershipClaimAction::Advance) => {
                OwnershipProtocolErrorCodeV1::StaleExpectedPrior
            }
            None => OwnershipProtocolErrorCodeV1::IntegrityFailure,
        },
        DurableOwnershipAuthorityError::IntentNotFound => OwnershipProtocolErrorCodeV1::NotFound,
        DurableOwnershipAuthorityError::Acquisition(error) => map_acquisition_error(error),
        DurableOwnershipAuthorityError::ResourceExhausted => {
            OwnershipProtocolErrorCodeV1::ResourceExhausted
        }
    }
}

fn map_acquisition_error(error: OwnershipLeaseAcquisitionError) -> OwnershipProtocolErrorCodeV1 {
    match error {
        OwnershipLeaseAcquisitionError::WrongClaimAction => {
            OwnershipProtocolErrorCodeV1::InvalidRequest
        }
        OwnershipLeaseAcquisitionError::InvalidIssuerResponse => {
            OwnershipProtocolErrorCodeV1::IntegrityFailure
        }
        OwnershipLeaseAcquisitionError::Authority(error) => match error {
            OwnershipAuthorityError::AlreadyOwned => OwnershipProtocolErrorCodeV1::AlreadyOwned,
            OwnershipAuthorityError::StaleExpectedPrior => {
                OwnershipProtocolErrorCodeV1::StaleExpectedPrior
            }
            OwnershipAuthorityError::IdempotencyConflict => {
                OwnershipProtocolErrorCodeV1::IdempotencyConflict
            }
            OwnershipAuthorityError::Unavailable => OwnershipProtocolErrorCodeV1::Unavailable,
            OwnershipAuthorityError::Internal => OwnershipProtocolErrorCodeV1::Internal,
        },
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use crate::JournalError;

    use super::*;

    #[test]
    fn durable_failures_have_closed_protocol_mappings() {
        let cases = [
            (
                DurableOwnershipAuthorityError::Journal(JournalError::Io(io::Error::other(
                    "test failure",
                ))),
                None,
                OwnershipProtocolErrorCodeV1::Unavailable,
            ),
            (
                DurableOwnershipAuthorityError::CorruptState,
                None,
                OwnershipProtocolErrorCodeV1::IntegrityFailure,
            ),
            (
                DurableOwnershipAuthorityError::MigrationRequired,
                None,
                OwnershipProtocolErrorCodeV1::RequiredCapabilityUnavailable,
            ),
            (
                DurableOwnershipAuthorityError::IdempotencyConflict,
                None,
                OwnershipProtocolErrorCodeV1::IdempotencyConflict,
            ),
            (
                DurableOwnershipAuthorityError::CompareAndSwapConflict,
                Some(OwnershipClaimAction::Acquire),
                OwnershipProtocolErrorCodeV1::AlreadyOwned,
            ),
            (
                DurableOwnershipAuthorityError::CompareAndSwapConflict,
                Some(OwnershipClaimAction::Renew),
                OwnershipProtocolErrorCodeV1::StaleExpectedPrior,
            ),
            (
                DurableOwnershipAuthorityError::CompareAndSwapConflict,
                None,
                OwnershipProtocolErrorCodeV1::IntegrityFailure,
            ),
            (
                DurableOwnershipAuthorityError::IntentNotFound,
                None,
                OwnershipProtocolErrorCodeV1::NotFound,
            ),
            (
                DurableOwnershipAuthorityError::ResourceExhausted,
                None,
                OwnershipProtocolErrorCodeV1::ResourceExhausted,
            ),
            (
                DurableOwnershipAuthorityError::Acquisition(
                    OwnershipLeaseAcquisitionError::InvalidIssuerResponse,
                ),
                None,
                OwnershipProtocolErrorCodeV1::IntegrityFailure,
            ),
            (
                DurableOwnershipAuthorityError::Acquisition(
                    OwnershipLeaseAcquisitionError::Authority(OwnershipAuthorityError::Unavailable),
                ),
                None,
                OwnershipProtocolErrorCodeV1::Unavailable,
            ),
        ];
        for (error, action, expected) in cases {
            assert_eq!(map_durable_error(error, action), expected);
        }
    }
}
