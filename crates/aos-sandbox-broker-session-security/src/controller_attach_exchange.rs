//! Retained authenticated controller-to-Host attach-gate broker exchange.
//!
//! Exact install, readiness, and accepted-route query requests remain in
//! protected broker-session custody across send, response, and commit
//! ambiguity. This owner never treats unauthenticated bytes as route evidence.

use aos_proto::aos::sandbox::local::v1::{
    BrokerAuthorizationArtifactsV1, BrokerMethod, BrokerRequestEnvelope,
    InstallHostAttachGateRequestV1, QueryHostAttachGateReadinessRequestV1,
    QueryHostAttachGateRouteRequestV1, RequestHeader,
};
use aos_sandbox::EffectFailure;
use aos_sandbox_core::public_attach_grant::PUBLIC_ATTACH_GRANT_BYTES;
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1;
use buffa::Message as _;

use crate::controller_retained_exchange::{RetainedBrokerExchangeV1, RetainedExchangeErrorsV1};
use crate::{DormantAuthenticatedBrokerSessionV1, DormantBrokerRequestCoordinatesV1};

const RETAINED_RECOVERY: &str = "attach gate request retains protected Host session recovery";
const SESSION_UNUSABLE: &str = "attach gate Host session is unusable";
const ERRORS: RetainedExchangeErrorsV1 = RetainedExchangeErrorsV1 {
    absent: "attach request custody is absent",
    retained: RETAINED_RECOVERY,
    unusable: SESSION_UNUSABLE,
};

#[derive(Clone, Debug, Eq, PartialEq)]
enum HostAttachIntentV1 {
    Install([u8; PUBLIC_ATTACH_GRANT_BYTES]),
    Readiness,
    Route {
        operation_id: [u8; 16],
        execution_id: [u8; 16],
    },
}

impl HostAttachIntentV1 {
    fn install(grant: &[u8]) -> Result<Self, EffectFailure> {
        let grant: [u8; PUBLIC_ATTACH_GRANT_BYTES] = grant.try_into().map_err(|_| {
            EffectFailure::Permanent("attach pending grant length is invalid".to_owned())
        })?;
        if &grant[..8] != b"AOSAPG01" {
            return Err(EffectFailure::Permanent(
                "attach pending grant magic is invalid".to_owned(),
            ));
        }
        Ok(Self::Install(grant))
    }

    fn method(&self) -> BrokerMethod {
        match self {
            Self::Install(_) => BrokerMethod::BROKER_METHOD_HOST_INSTALL_ATTACH_GATE,
            Self::Readiness => BrokerMethod::BROKER_METHOD_HOST_QUERY_ATTACH_GATE_READINESS,
            Self::Route { .. } => BrokerMethod::BROKER_METHOD_HOST_QUERY_ATTACH_GATE_ROUTE,
        }
    }

    fn envelope(
        &self,
        coordinates: DormantBrokerRequestCoordinatesV1,
        authorization: &BrokerAuthorizationArtifactsV1,
    ) -> BrokerRequestEnvelope {
        let header = RequestHeader {
            protocol_major: u32::from(coordinates.protocol_version().major()),
            protocol_minor: u32::from(coordinates.protocol_version().minor()),
            request_id: coordinates.request_id().to_vec(),
            audience: coordinates.audience().into(),
            deadline_boottime_nanoseconds: coordinates.deadline_boottime_nanoseconds(),
            maximum_response_bytes: coordinates.maximum_response_bytes(),
            ..Default::default()
        };
        let body = match self {
            Self::Install(grant) => InstallHostAttachGateRequestV1 {
                header: Some(header).into(),
                pending_grant: grant.to_vec(),
                ..Default::default()
            }
            .encode_to_vec(),
            Self::Readiness => QueryHostAttachGateReadinessRequestV1 {
                header: Some(header).into(),
                ..Default::default()
            }
            .encode_to_vec(),
            Self::Route {
                operation_id,
                execution_id,
            } => QueryHostAttachGateRouteRequestV1 {
                header: Some(header).into(),
                operation_id: operation_id.to_vec(),
                execution_id: execution_id.to_vec(),
                ..Default::default()
            }
            .encode_to_vec(),
        };
        BrokerRequestEnvelope {
            method: self.method().into(),
            body,
            authorization: Some(authorization.clone()).into(),
            ..Default::default()
        }
    }
}

/// Retains one exact method-28 request until its signed outcome is committed.
#[derive(Default)]
pub(crate) struct ControllerHostAttachGateExchangeV1 {
    exchange: RetainedBrokerExchangeV1<HostAttachIntentV1>,
}

impl ControllerHostAttachGateExchangeV1 {
    /// Reports whether this exchange currently owns protected Host custody.
    pub(crate) const fn has_pending(&self) -> bool {
        self.exchange.has_pending()
    }

    /// Reports whether the transport must be reopened before further work.
    pub(crate) const fn requires_reconnect(&self) -> bool {
        self.exchange.requires_reconnect()
    }

    /// Resolves retained prior custody before the controller renews its expiry.
    pub(crate) fn drain_pending(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
    ) -> Result<Option<AuthenticatedBrokerMethodOutcomeV1>, EffectFailure> {
        if self.requires_reconnect() {
            return Err(EffectFailure::Retryable(SESSION_UNUSABLE.to_owned()));
        }
        if self.exchange.context().is_none() {
            return Ok(None);
        }
        self.exchange
            .drive(session, &ERRORS)
            .map(|(_, outcome)| Some(outcome))
    }

    /// Installs one exact signed grant through the retained Host session.
    ///
    /// # Errors
    ///
    /// Returns a retryable error while exact protected recovery is retained or
    /// the authenticated transport is unavailable. It never interprets a Host
    /// success body as route evidence; the worker applies the shared decoder.
    pub(crate) fn install(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        grant: &[u8],
        authorization: Option<&BrokerAuthorizationArtifactsV1>,
    ) -> Result<AuthenticatedBrokerMethodOutcomeV1, EffectFailure> {
        if self.requires_reconnect() {
            return Err(EffectFailure::Retryable(SESSION_UNUSABLE.to_owned()));
        }
        let intent = HostAttachIntentV1::install(grant)?;
        self.exchange(session, intent, authorization)
    }

    /// Queries live Host readiness without creating a public reservation.
    pub(crate) fn query_readiness(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        authorization: Option<&BrokerAuthorizationArtifactsV1>,
    ) -> Result<AuthenticatedBrokerMethodOutcomeV1, EffectFailure> {
        self.exchange(session, HostAttachIntentV1::Readiness, authorization)
    }

    /// Reads an accepted route with a fresh signed guest gate observation.
    pub(crate) fn query_route(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        operation_id: [u8; 16],
        execution_id: [u8; 16],
        authorization: Option<&BrokerAuthorizationArtifactsV1>,
    ) -> Result<AuthenticatedBrokerMethodOutcomeV1, EffectFailure> {
        if operation_id == [0; 16] || execution_id == [0; 16] {
            return Err(EffectFailure::Permanent(
                "attach route selector is invalid".to_owned(),
            ));
        }
        self.exchange(
            session,
            HostAttachIntentV1::Route {
                operation_id,
                execution_id,
            },
            authorization,
        )
    }

    fn exchange(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        intent: HostAttachIntentV1,
        authorization: Option<&BrokerAuthorizationArtifactsV1>,
    ) -> Result<AuthenticatedBrokerMethodOutcomeV1, EffectFailure> {
        if self
            .exchange
            .context()
            .is_some_and(|pending| pending != &intent)
        {
            return Err(EffectFailure::Retryable(
                "another exact attach request retains Host session custody".to_owned(),
            ));
        }
        if self.exchange.context().is_none() {
            let authorization = authorization.ok_or_else(|| {
                EffectFailure::Retryable("current attach Host authorization is absent".to_owned())
            })?;
            let preparation = session
                .prepare_authenticated_request_checked(
                    intent.method(),
                    |coordinates| intent.envelope(coordinates, authorization),
                    |request| {
                        request.exact_body().len()
                            <= aos_sandbox_protocol::HOST_ATTACH_GATE_MAXIMUM_REQUEST_BODY_BYTES
                    },
                )
                .map_err(|_| {
                    self.exchange.mark_failed();
                    EffectFailure::Retryable(
                        "attach request could not enter protected Host custody".to_owned(),
                    )
                })?;
            self.exchange.start(intent, preparation);
        }
        self.exchange
            .drive(session, &ERRORS)
            .map(|(_, outcome)| outcome)
    }
}
