//! Explicit pure injected transports for untrusted public request proposals.
//!
//! These ports select no production endpoint and perform no IO. They never
//! receive Controller-adopted provenance or return verified effect authority.

use aos_proto::aos::sandbox::v1 as wire;

use super::{
    DormantClientStatePlanV1, DormantPublicApiRequestV1, DormantPublicApiRouteV1,
    DormantSandboxOutputV1, DormantSandboxRequestKindV1, DormantSandboxRoutingErrorV1,
};

/// Preserves a fully validated request as non-effect deferred work.
#[derive(Clone, Debug, PartialEq)]
pub struct DormantDeferredSandboxRequestV1 {
    request: DormantPublicApiRequestV1,
}

impl DormantDeferredSandboxRequestV1 {
    /// Returns the exact validated request retained by the non-effect sink.
    #[must_use]
    pub const fn request(&self) -> &DormantPublicApiRequestV1 {
        &self.request
    }
}

/// Abstracts one explicitly supplied dormant command transport.
pub trait DormantSandboxTransportV1 {
    /// Output returned without assuming text, JSON, or terminal framing.
    type Output;

    /// Routes one complete typed request.
    ///
    /// # Errors
    ///
    /// Returns [`DormantSandboxRoutingErrorV1`] when validation or the supplied
    /// transport fails closed.
    fn route(
        &mut self,
        request: DormantPublicApiRequestV1,
    ) -> Result<Self::Output, DormantSandboxRoutingErrorV1>;
}

/// Abstracts an explicitly injected transport for the established public API.
pub trait DormantPublicApiWireTransportV1 {
    /// Output returned by the concrete unary or streaming client implementation.
    type Output;

    /// Sends one method-preserving request to its exact generated API path.
    ///
    /// The transport must authenticate any supplied opaque context before it
    /// sends an effect request. No implementation is selected by production.
    ///
    /// # Errors
    ///
    /// Returns [`DormantSandboxRoutingErrorV1::TransportRejected`] when the
    /// endpoint, authentication, encoding, or response contract fails.
    fn call(
        &mut self,
        route: DormantPublicApiRouteV1,
        request: DormantPublicApiRequestV1,
    ) -> Result<Self::Output, DormantSandboxRoutingErrorV1>;
}

/// Routes validated CLI requests through one explicitly supplied public API client.
pub struct DormantPublicApiClientV1<T> {
    transport: T,
}

impl<T> DormantPublicApiClientV1<T> {
    /// Constructs a dormant client without registering or selecting an endpoint.
    #[must_use]
    pub const fn new(transport: T) -> Self {
        Self { transport }
    }

    /// Returns the injected transport after the dormant client is dismantled.
    #[must_use]
    pub fn into_transport(self) -> T {
        self.transport
    }
}

impl<T> DormantSandboxTransportV1 for DormantPublicApiClientV1<T>
where
    T: DormantPublicApiWireTransportV1,
{
    type Output = T::Output;

    fn route(
        &mut self,
        request: DormantPublicApiRequestV1,
    ) -> Result<Self::Output, DormantSandboxRoutingErrorV1> {
        request.validate()?;
        if request.kind().requires_authorization() && request.public_api_authorization().is_none() {
            return Err(DormantSandboxRoutingErrorV1::AuthorizationRequired);
        }
        let route = request
            .kind()
            .public_api_route()
            .ok_or(DormantSandboxRoutingErrorV1::TransportRejected)?;
        self.transport.call(route, request)
    }
}

/// Owns a supplied transport without selecting a production implementation.
pub struct DormantSandboxCommandExecutorV1<T> {
    transport: T,
}

impl<T> DormantSandboxCommandExecutorV1<T>
where
    T: DormantSandboxTransportV1,
{
    /// Constructs an executor around an explicit transport.
    #[must_use]
    pub const fn new(transport: T) -> Self {
        Self { transport }
    }

    /// Routes one typed request through the explicitly supplied transport.
    ///
    /// # Errors
    ///
    /// Returns the transport's stable routing error.
    pub fn execute(
        &mut self,
        request: DormantPublicApiRequestV1,
    ) -> Result<T::Output, DormantSandboxRoutingErrorV1> {
        request.validate()?;
        if request.kind().requires_authorization() && !request.has_authorization() {
            return Err(DormantSandboxRoutingErrorV1::AuthorizationRequired);
        }
        self.transport.route(request)
    }
}

/// Provides the concrete validating, non-effect sink used by the CLI binary.
#[derive(Clone, Copy, Debug, Default)]
pub struct DormantValidatedRequestSinkV1;

impl DormantSandboxTransportV1 for DormantValidatedRequestSinkV1 {
    type Output = DormantDeferredSandboxRequestV1;

    fn route(
        &mut self,
        request: DormantPublicApiRequestV1,
    ) -> Result<Self::Output, DormantSandboxRoutingErrorV1> {
        request.validate()?;
        if request.kind().requires_authorization() && !request.has_authorization() {
            return Err(DormantSandboxRoutingErrorV1::AuthorizationRequired);
        }
        Ok(DormantDeferredSandboxRequestV1 { request })
    }
}

/// Provides the callable pure PlanCreate handler without service registration.
#[derive(Clone, Copy, Debug, Default)]
pub struct DormantPlanCreateHandlerV1;

impl DormantPlanCreateHandlerV1 {
    /// Validates and retains one callable protobuf PlanCreate request.
    ///
    /// # Errors
    ///
    /// Returns [`DormantSandboxRoutingErrorV1::InvalidRequest`] for any invalid
    /// project/parent fence, descriptor, feature, or accidental effect field.
    pub fn handle(
        self,
        request: wire::PlanCreateSandboxRequest,
    ) -> Result<DormantDeferredSandboxRequestV1, DormantSandboxRoutingErrorV1> {
        let client_state = DormantClientStatePlanV1::new(1, 1, None)?;
        let request = DormantPublicApiRequestV1::from_parsed_command(
            DormantSandboxRequestKindV1::PlanCreate(request),
            DormantSandboxOutputV1::Json,
            client_state,
        )?;
        DormantValidatedRequestSinkV1.route(request)
    }
}

/// Maps stable routing outcomes to public process exit codes.
#[must_use]
pub const fn dormant_sandbox_exit_code(result: Result<(), DormantSandboxRoutingErrorV1>) -> i32 {
    match result {
        Ok(()) => 0,
        Err(DormantSandboxRoutingErrorV1::InvalidRequest) => 2,
        Err(DormantSandboxRoutingErrorV1::AuthorizationRequired) => 3,
        Err(DormantSandboxRoutingErrorV1::TransportRejected) => 1,
    }
}
