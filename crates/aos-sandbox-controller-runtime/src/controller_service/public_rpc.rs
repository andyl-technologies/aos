//! Public RPC adapters for the sole Controller worker.
//!
//! This group owns registered-peer and capability-header checks, bounded worker
//! requests, and public response/error projections. It never opens the journal
//! or supplies mutation authority; the existing worker performs admission.
//! Diagnostic capability status uses display-only wall time and advertises no
//! unavailable semantic feature. Startup alone constructs the opaque handlers.

use std::pin::Pin;
use std::sync::{Arc, Mutex, mpsc};
use std::time::Instant;

use aos_proto::aos::sandbox::v1::{
    CancelOperationRequest, CancelOperationResponse, DiscoveryService, Event,
    GetNodeCapabilitiesRequest, GetNodeCapabilitiesRequestView, GetNodeCapabilitiesResponse,
    GetOperationRequest, GetOperationResponse, GetPublicFeatureRegistryRequest,
    GetPublicFeatureRegistryResponse, NodeCapabilities, Operation, OperationService, PolicyPlan,
    Timestamp, WatchRequest,
};
use aos_sandbox::cli_model::{AuditAuthorizationV1, PublicApiAuditMethodV1};
use aos_sandbox::controller_service::public_projection::{
    AuthorizedPublicProjectionReadV1, PublicProjectionQueryV1,
};
use aos_sandbox_core::{
    CapabilityId, ObjectDigest, Operation as CapabilityOperation, OperationId, ResourceKind,
    Selector,
};
use connectrpc::{
    ConnectError, Encodable, ErrorCode, RequestContext, Response, ServiceRequest, ServiceResult,
};
use futures::Stream;
use sha2::{Digest as _, Sha256};

#[cfg(test)]
use super::UNAVAILABLE_REASON;
use super::{
    AdmittedPublicAttachV1, AdmittedPublicMutationV1, CONTROLLER_COMMAND_TIMEOUT,
    ControllerCommand, ControllerCommandFailure, ControllerCommandResponse,
};

mod public_hierarchy;
mod public_services;
mod public_watch;

const PUBLIC_CAPABILITY_HEADER: &str = "aos-capability-id";
const PUBLIC_CAPABILITY_HANDLE_HEADER: &str = "aos-capability-handle";

pub(in crate::controller_service) struct CapabilityState {
    node_id: [u8; 16],
    capability_generation: u64,
    catalog_generation: u64,
    catalog_digest: ObjectDigest,
    observation_available: bool,
    retryable_failure: Option<String>,
    observed_at: rustix::time::Timespec,
}

impl CapabilityState {
    pub(in crate::controller_service) fn starting(node_id: [u8; 16]) -> Self {
        Self {
            node_id,
            capability_generation: 1,
            catalog_generation: 0,
            catalog_digest: ObjectDigest::from_bytes([0; 32]),
            observation_available: false,
            retryable_failure: Some("initial authenticated inventory is pending".to_owned()),
            observed_at: diagnostic_wall_time(),
        }
    }

    pub(in crate::controller_service) fn record_success(
        &mut self,
        generation: u64,
        digest: ObjectDigest,
    ) {
        let changed = !self.observation_available
            || self.catalog_generation != generation
            || self.catalog_digest != digest;
        self.catalog_generation = generation;
        self.catalog_digest = digest;
        self.observation_available = true;
        self.retryable_failure = None;
        self.observed_at = diagnostic_wall_time();
        if changed {
            self.capability_generation = self.capability_generation.saturating_add(1);
        }
    }

    pub(in crate::controller_service) fn record_retryable_failure(&mut self, message: String) {
        let changed = self.observation_available
            || self.retryable_failure.as_deref() != Some(message.as_str());
        self.observation_available = false;
        self.retryable_failure = Some(message);
        self.observed_at = diagnostic_wall_time();
        if changed {
            self.capability_generation = self.capability_generation.saturating_add(1);
        }
    }

    #[allow(
        clippy::result_large_err,
        reason = "ConnectRPC fixes the service error type and this is not a hot path."
    )]
    fn response(&self) -> Result<GetNodeCapabilitiesResponse, ConnectError> {
        let observed_at = timestamp(self.observed_at)?;
        let resource_version = capability_resource_version(
            self.node_id,
            self.capability_generation,
            self.catalog_generation,
            self.catalog_digest,
            self.observation_available,
        );
        Ok(GetNodeCapabilitiesResponse {
            capabilities: Some(NodeCapabilities {
                node_id: self.node_id.to_vec(),
                resource_version: resource_version.to_vec(),
                capability_generation: self.capability_generation,
                capabilities: Vec::new(),
                observed_at: Some(observed_at).into(),
                ..Default::default()
            })
            .into(),
            ..Default::default()
        })
    }
}

fn capability_resource_version(
    node_id: [u8; 16],
    capability_generation: u64,
    catalog_generation: u64,
    catalog_digest: ObjectDigest,
    available: bool,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.controller-capabilities.v1\0");
    digest.update(node_id);
    digest.update(capability_generation.to_be_bytes());
    digest.update(catalog_generation.to_be_bytes());
    digest.update(catalog_digest.as_bytes());
    digest.update([u8::from(available)]);
    digest.finalize().into()
}

fn diagnostic_wall_time() -> rustix::time::Timespec {
    // This display-only sample never enters durable state, authority,
    // deadlines, inventory continuity, or readiness decisions.
    rustix::time::clock_gettime(rustix::time::ClockId::Realtime)
}

#[allow(
    clippy::result_large_err,
    reason = "ConnectRPC fixes the service error type and this is not a hot path."
)]
fn timestamp(value: rustix::time::Timespec) -> Result<Timestamp, ConnectError> {
    let error = if value.tv_sec < 0 {
        ConnectError::new(
            ErrorCode::Internal,
            "controller wall clock precedes the Unix epoch",
        )
    } else if !(0..1_000_000_000).contains(&value.tv_nsec) {
        ConnectError::new(ErrorCode::Internal, "controller wall clock is out of range")
    } else {
        return Ok(Timestamp {
            seconds: value.tv_sec,
            nanoseconds: u32::try_from(value.tv_nsec).map_err(|_| {
                ConnectError::new(ErrorCode::Internal, "controller wall clock is out of range")
            })?,
            ..Default::default()
        });
    };

    Err(error)
}

/// Handles Controller requests through the sole protected worker command channel.
///
/// Assembly may register this opaque handler, but cannot construct it, access
/// its command channel, or substitute verified identity/admission evidence.
pub struct CapabilityService {
    pub(in crate::controller_service) capabilities: Arc<Mutex<CapabilityState>>,
    pub(in crate::controller_service) commands: mpsc::SyncSender<ControllerCommand>,
    pub(in crate::controller_service) endpoint: ControllerEndpoint,
}

#[derive(Clone, Copy)]
pub(in crate::controller_service) enum ControllerEndpoint {
    RootDiagnostic,
    RegisteredPublic,
}

/// Carries the generated service's owned server-streaming responses.
type ResponseStream<T> = Pin<Box<dyn Stream<Item = Result<T, ConnectError>> + Send>>;

impl DiscoveryService for CapabilityService {
    async fn get_public_feature_registry<'a>(
        &'a self,
        _context: RequestContext,
        _request: ServiceRequest<'_, GetPublicFeatureRegistryRequest>,
    ) -> ServiceResult<impl Encodable<GetPublicFeatureRegistryResponse> + Send + use<'a>> {
        Response::ok(GetPublicFeatureRegistryResponse {
            registry: Some(aos_sandbox_protocol::public_api::public_feature_registry_v1()).into(),
            ..Default::default()
        })
    }

    async fn get_node_capabilities<'a>(
        &'a self,
        _context: RequestContext,
        request: ServiceRequest<'_, GetNodeCapabilitiesRequest>,
    ) -> ServiceResult<impl Encodable<GetNodeCapabilitiesResponse> + Send + use<'a>> {
        Response::ok(self.node_capabilities(request.view())?)
    }
}

impl CapabilityService {
    async fn bootstrap_public_capability(
        &self,
        context: &RequestContext,
        idempotency_key: &[u8],
    ) -> Result<(CapabilityId, [u8; 32]), ConnectError> {
        let peer = self.registered_public_peer(
            context,
            "capability bootstrap is unavailable on the diagnostic endpoint",
            "capability bootstrap requires registered TLS peer evidence",
        )?;
        if !(16..=128).contains(&idempotency_key.len()) {
            return Err(ConnectError::new(
                ErrorCode::InvalidArgument,
                "capability bootstrap idempotency key must contain 16..=128 bytes",
            ));
        }
        let (reply, response) = tokio::sync::oneshot::channel();
        self.commands
            .try_send(ControllerCommand::BootstrapPublicCapability {
                peer: peer.clone(),
                idempotency_key: idempotency_key.to_vec(),
                expires_at: Instant::now() + CONTROLLER_COMMAND_TIMEOUT,
                reply,
            })
            .map_err(controller_command_send_error)?;
        let result =
            await_public_controller_reply(response, "capability bootstrap timed out").await?;
        match result {
            Ok(issued) => {
                peer.recheck().map_err(|_| {
                    ConnectError::new(
                        ErrorCode::PermissionDenied,
                        "capability bootstrap peer is no longer current",
                    )
                })?;
                Ok(issued)
            }
            Err(ControllerCommandFailure::DeadlineExceeded) => Err(ConnectError::new(
                ErrorCode::DeadlineExceeded,
                "capability bootstrap expired",
            )),
            Err(ControllerCommandFailure::Rejected) => Err(ConnectError::new(
                ErrorCode::PermissionDenied,
                "capability bootstrap rejected",
            )),
            Err(ControllerCommandFailure::InvalidRequest) => Err(ConnectError::new(
                ErrorCode::InvalidArgument,
                "capability bootstrap request is invalid",
            )),
            Err(ControllerCommandFailure::ControllerUnavailable) => Err(ConnectError::new(
                ErrorCode::Unavailable,
                "capability bootstrap authority is unavailable",
            )),
        }
    }

    fn registered_public_peer<'a>(
        &self,
        context: &'a RequestContext,
        diagnostic_message: &'static str,
        unauthenticated_message: &'static str,
    ) -> Result<&'a aos_sandbox::public_api_session::PublicApiPeer, ConnectError> {
        if !matches!(self.endpoint, ControllerEndpoint::RegisteredPublic) {
            return Err(ConnectError::new(
                ErrorCode::PermissionDenied,
                diagnostic_message,
            ));
        }
        context
            .extensions()
            .get::<aos_sandbox::public_api_session::PublicApiPeer>()
            .ok_or_else(|| ConnectError::new(ErrorCode::Unauthenticated, unauthenticated_message))
    }

    async fn resolve_public_capability_target(
        &self,
        context: &RequestContext,
        handle: &[u8],
    ) -> Result<CapabilityId, ConnectError> {
        let peer = self.registered_public_peer(
            context,
            "capability inspection is unavailable on the diagnostic endpoint",
            "capability inspection requires registered TLS peer evidence",
        )?;
        let handle: [u8; 32] = handle.try_into().map_err(|_| {
            ConnectError::new(
                ErrorCode::InvalidArgument,
                "capability handle must contain exactly 32 bytes",
            )
        })?;
        if handle == [0; 32] {
            return Err(ConnectError::new(
                ErrorCode::InvalidArgument,
                "capability handle must be nonzero",
            ));
        }

        let (reply, response) = tokio::sync::oneshot::channel();
        self.commands
            .try_send(ControllerCommand::ResolvePublicCapabilityTarget {
                peer: peer.clone(),
                handle,
                expires_at: Instant::now() + CONTROLLER_COMMAND_TIMEOUT,
                reply,
            })
            .map_err(controller_command_send_error)?;
        let result =
            await_public_controller_reply(response, "capability handle lookup timed out").await?;
        match result {
            Ok(id) => Ok(id),
            Err(ControllerCommandFailure::DeadlineExceeded) => Err(ConnectError::new(
                ErrorCode::DeadlineExceeded,
                "capability handle lookup expired",
            )),
            Err(ControllerCommandFailure::Rejected) => Err(ConnectError::new(
                ErrorCode::PermissionDenied,
                "capability handle was rejected",
            )),
            Err(_) => Err(ConnectError::new(
                ErrorCode::Unavailable,
                "capability handle lookup is unavailable",
            )),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn read_public_projection(
        &self,
        context: &RequestContext,
        method: PublicApiAuditMethodV1,
        resource_kind: ResourceKind,
        operation: CapabilityOperation,
        selector: Selector,
        protobuf_body: &[u8],
        query: PublicProjectionQueryV1,
    ) -> Result<AuthorizedPublicProjectionReadV1, ConnectError> {
        let peer = self.registered_public_peer(
            context,
            "public resource reads are unavailable on the diagnostic endpoint",
            "public resource read requires registered TLS peer evidence",
        )?;
        let (reply, response) = tokio::sync::oneshot::channel();
        self.commands
            .try_send(ControllerCommand::ReadPublicProjection {
                peer: peer.clone(),
                capability_id: public_capability_id(context)?,
                capability_handle: public_capability_handle(context)?,
                method,
                resource_kind,
                operation,
                selector,
                protobuf_body: protobuf_body.to_vec(),
                query,
                expires_at: Instant::now() + CONTROLLER_COMMAND_TIMEOUT,
                reply,
            })
            .map_err(controller_command_send_error)?;
        let result =
            await_public_controller_reply(response, "controller public resource read timed out")
                .await?;

        match result {
            Ok(Some(read)) => Ok(read),
            Ok(None) => Err(ConnectError::new(
                ErrorCode::NotFound,
                "authorized resource was not found",
            )),
            Err(ControllerCommandFailure::DeadlineExceeded) => Err(ConnectError::new(
                ErrorCode::DeadlineExceeded,
                "controller public resource read expired",
            )),
            Err(ControllerCommandFailure::ControllerUnavailable) => Err(ConnectError::new(
                ErrorCode::Unavailable,
                "controller public resource state is unavailable",
            )),
            Err(ControllerCommandFailure::InvalidRequest) => Err(ConnectError::new(
                ErrorCode::InvalidArgument,
                "public resource request is invalid",
            )),
            Err(ControllerCommandFailure::Rejected) => Err(ConnectError::new(
                ErrorCode::PermissionDenied,
                "public resource read was rejected",
            )),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn authorize_public_read(
        &self,
        context: &RequestContext,
        method: PublicApiAuditMethodV1,
        resource_kind: ResourceKind,
        operation: CapabilityOperation,
        selector: Selector,
        protobuf_body: &[u8],
    ) -> Result<AuditAuthorizationV1, ConnectError> {
        let peer = self.registered_public_peer(
            context,
            "public read authorization is unavailable on the diagnostic endpoint",
            "public read requires registered TLS peer evidence",
        )?;
        let (reply, response) = tokio::sync::oneshot::channel();
        self.commands
            .try_send(ControllerCommand::AuthorizePublicRead {
                peer: peer.clone(),
                capability_id: public_capability_id(context)?,
                capability_handle: public_capability_handle(context)?,
                method,
                resource_kind,
                operation,
                selector,
                protobuf_body: protobuf_body.to_vec(),
                expires_at: Instant::now() + CONTROLLER_COMMAND_TIMEOUT,
                reply,
            })
            .map_err(controller_command_send_error)?;
        let result = await_public_controller_reply(
            response,
            "controller public-read authorization timed out",
        )
        .await?;

        match result {
            Ok(Some(authorization)) => Ok(authorization),
            Ok(None) => Err(ConnectError::new(
                ErrorCode::NotFound,
                "authorized resource was not found",
            )),
            Err(ControllerCommandFailure::DeadlineExceeded) => Err(ConnectError::new(
                ErrorCode::DeadlineExceeded,
                "controller public-read authorization expired",
            )),
            Err(ControllerCommandFailure::ControllerUnavailable) => Err(ConnectError::new(
                ErrorCode::Unavailable,
                "controller authorization state is unavailable",
            )),
            Err(ControllerCommandFailure::InvalidRequest) => Err(ConnectError::new(
                ErrorCode::InvalidArgument,
                "public read request is invalid",
            )),
            Err(ControllerCommandFailure::Rejected) => Err(ConnectError::new(
                ErrorCode::PermissionDenied,
                "public read was rejected",
            )),
        }
    }

    async fn plan_public_policy(
        &self,
        context: &RequestContext,
        method: PublicApiAuditMethodV1,
        protobuf_body: &[u8],
    ) -> Result<PolicyPlan, ConnectError> {
        let peer = self.registered_public_peer(
            context,
            "public policy planning is unavailable on the diagnostic endpoint",
            "public policy planning requires registered TLS peer evidence",
        )?;
        let (reply, response) = tokio::sync::oneshot::channel();
        self.commands
            .try_send(ControllerCommand::PlanPublicPolicy {
                peer: peer.clone(),
                capability_id: public_capability_id(context)?,
                capability_handle: public_capability_handle(context)?,
                method,
                protobuf_body: protobuf_body.to_vec(),
                expires_at: Instant::now() + CONTROLLER_COMMAND_TIMEOUT,
                reply,
            })
            .map_err(controller_command_send_error)?;
        let result =
            await_public_controller_reply(response, "controller public policy planning timed out")
                .await?;

        result.map_err(|failure| {
            public_controller_command_error(
                failure,
                "controller public policy planning expired",
                "public policy-planning request is invalid",
                "public policy-planning request was rejected",
                "controller public policy planner is unavailable",
            )
        })
    }

    async fn admit_public_operator_recovery(
        &self,
        context: &RequestContext,
        canonical_request: Vec<u8>,
    ) -> Result<Operation, ConnectError> {
        let peer = self.registered_public_peer(
            context,
            "operator recovery is unavailable on the diagnostic endpoint",
            "operator recovery requires registered TLS peer evidence",
        )?;
        let (reply, response) = tokio::sync::oneshot::channel();
        self.commands
            .try_send(ControllerCommand::AdmitPublicOperatorRecovery {
                peer: peer.clone(),
                capability_id: public_capability_id(context)?,
                capability_handle: public_capability_handle(context)?,
                canonical_request,
                expires_at: Instant::now() + CONTROLLER_COMMAND_TIMEOUT,
                reply,
            })
            .map_err(controller_command_send_error)?;
        let result = await_public_controller_reply(
            response,
            "controller operator-recovery admission timed out",
        )
        .await?;

        result.map_err(|failure| {
            public_controller_command_error(
                failure,
                "controller operator-recovery admission expired",
                "operator-recovery request is invalid",
                "operator-recovery request was rejected",
                "controller operator-recovery state is unavailable",
            )
        })
    }

    async fn admit_public_mutation(
        &self,
        context: &RequestContext,
        canonical_request: Vec<u8>,
    ) -> Result<AdmittedPublicMutationV1, ConnectError> {
        let peer = self.registered_public_peer(
            context,
            "public mutations are unavailable on the diagnostic endpoint",
            "public mutation requires registered TLS peer evidence",
        )?;
        let (reply, response) = tokio::sync::oneshot::channel();
        self.commands
            .try_send(ControllerCommand::AdmitPublicMutation {
                peer: peer.clone(),
                capability_id: public_capability_id(context)?,
                capability_handle: public_capability_handle(context)?,
                canonical_request,
                expires_at: Instant::now() + CONTROLLER_COMMAND_TIMEOUT,
                reply,
            })
            .map_err(controller_command_send_error)?;
        let result = await_public_controller_reply(
            response,
            "controller public mutation admission timed out",
        )
        .await?;

        result.map_err(|failure| {
            public_controller_command_error(
                failure,
                "controller public mutation admission expired",
                "public mutation request is invalid",
                "public mutation was rejected",
                "controller public mutation state is unavailable",
            )
        })
    }

    async fn admit_public_attach(
        &self,
        context: &RequestContext,
        canonical_request: Vec<u8>,
    ) -> Result<AdmittedPublicAttachV1, ConnectError> {
        let peer = self.registered_public_peer(
            context,
            "public attachment is unavailable on the diagnostic endpoint",
            "public attachment requires registered TLS peer evidence",
        )?;
        let (reply, response) = tokio::sync::oneshot::channel();
        self.commands
            .try_send(ControllerCommand::AdmitPublicAttach {
                peer: peer.clone(),
                capability_id: public_capability_id(context)?,
                capability_handle: public_capability_handle(context)?,
                canonical_request,
                expires_at: Instant::now() + CONTROLLER_COMMAND_TIMEOUT,
                reply,
            })
            .map_err(controller_command_send_error)?;
        let result =
            await_public_controller_reply(response, "controller attachment admission timed out")
                .await?;

        result.map_err(|failure| {
            public_controller_command_error(
                failure,
                "controller attachment admission expired",
                "public attachment request is invalid",
                "public attachment was rejected",
                "authenticated Host attachment route is unavailable",
            )
        })
    }

    fn node_capabilities(
        &self,
        request: &GetNodeCapabilitiesRequestView<'_>,
    ) -> Result<GetNodeCapabilitiesResponse, ConnectError> {
        let capabilities = self.capabilities.lock().map_err(|_| {
            ConnectError::new(
                ErrorCode::Internal,
                "controller capability state is unavailable",
            )
        })?;
        if request.node_id != capabilities.node_id {
            return Err(ConnectError::new(
                ErrorCode::NotFound,
                "requested node does not match this controller",
            ));
        }
        capabilities.response()
    }

    async fn operation(
        &self,
        context: &RequestContext,
        operation_identity: &[u8],
        protobuf_body: &[u8],
    ) -> Result<GetOperationResponse, ConnectError> {
        let operation_id: [u8; 16] = operation_identity.try_into().map_err(|_| {
            ConnectError::new(
                ErrorCode::InvalidArgument,
                "operation identity must contain exactly 16 bytes",
            )
        })?;
        if operation_id == [0; 16] {
            return Err(ConnectError::new(
                ErrorCode::InvalidArgument,
                "operation identity must be nonzero",
            ));
        }

        let (reply, response) = tokio::sync::oneshot::channel();
        let operation_id = OperationId::from_bytes(operation_id);
        let expires_at = Instant::now() + CONTROLLER_COMMAND_TIMEOUT;
        let command = match self.endpoint {
            ControllerEndpoint::RootDiagnostic => ControllerCommand::GetOperation {
                operation_id,
                expires_at,
                reply,
            },
            ControllerEndpoint::RegisteredPublic => {
                let peer = context
                    .extensions()
                    .get::<aos_sandbox::public_api_session::PublicApiPeer>()
                    .ok_or_else(|| {
                        ConnectError::new(
                            ErrorCode::Unauthenticated,
                            "public operation lookup requires registered TLS peer evidence",
                        )
                    })?;
                ControllerCommand::GetAuthorizedOperation {
                    peer: peer.clone(),
                    capability_id: public_capability_id(context)?,
                    capability_handle: public_capability_handle(context)?,
                    operation_id,
                    protobuf_body: protobuf_body.to_vec(),
                    expires_at,
                    reply,
                }
            }
        };
        self.commands
            .try_send(command)
            .map_err(controller_command_send_error)?;
        let result =
            await_public_controller_reply(response, "controller operation lookup timed out")
                .await?;
        let operation = match result {
            Ok(Some(operation)) => operation,
            Ok(None) => {
                return Err(ConnectError::new(
                    ErrorCode::NotFound,
                    "operation was not found",
                ));
            }
            Err(ControllerCommandFailure::DeadlineExceeded) => {
                return Err(ConnectError::new(
                    ErrorCode::DeadlineExceeded,
                    "controller operation lookup expired",
                ));
            }
            Err(ControllerCommandFailure::ControllerUnavailable) => {
                return Err(ConnectError::new(
                    ErrorCode::Unavailable,
                    "controller operation state is unavailable",
                ));
            }
            Err(ControllerCommandFailure::InvalidRequest) => {
                return Err(ConnectError::new(
                    ErrorCode::InvalidArgument,
                    "operation lookup request is invalid",
                ));
            }
            Err(ControllerCommandFailure::Rejected) => {
                return Err(ConnectError::new(
                    ErrorCode::PermissionDenied,
                    "operation lookup was rejected",
                ));
            }
        };

        Ok(GetOperationResponse {
            operation: Some(operation).into(),
            ..Default::default()
        })
    }
}

async fn await_public_controller_reply<T>(
    response: tokio::sync::oneshot::Receiver<ControllerCommandResponse<T>>,
    timeout_message: &'static str,
) -> Result<ControllerCommandResponse<T>, ConnectError> {
    tokio::time::timeout(CONTROLLER_COMMAND_TIMEOUT, response)
        .await
        .map_err(|_| ConnectError::new(ErrorCode::DeadlineExceeded, timeout_message))?
        .map_err(|_| {
            ConnectError::new(
                ErrorCode::Unavailable,
                "controller worker ended before replying",
            )
        })
}

// Projects only a worker's negative reply; transport and timeout errors stay
// at their original call sites.
fn public_controller_command_error(
    failure: ControllerCommandFailure,
    expired: &'static str,
    invalid_request: &'static str,
    rejected: &'static str,
    unavailable: &'static str,
) -> ConnectError {
    let (code, message) = match failure {
        ControllerCommandFailure::DeadlineExceeded => (ErrorCode::DeadlineExceeded, expired),
        ControllerCommandFailure::InvalidRequest => (ErrorCode::InvalidArgument, invalid_request),
        ControllerCommandFailure::Rejected => (ErrorCode::PermissionDenied, rejected),
        ControllerCommandFailure::ControllerUnavailable => (ErrorCode::Unavailable, unavailable),
    };
    ConnectError::new(code, message)
}

fn controller_command_send_error<T>(error: mpsc::TrySendError<T>) -> ConnectError {
    match error {
        mpsc::TrySendError::Full(_) => ConnectError::new(
            ErrorCode::ResourceExhausted,
            "controller command capacity is exhausted",
        ),
        mpsc::TrySendError::Disconnected(_) => {
            ConnectError::new(ErrorCode::Unavailable, "controller worker is unavailable")
        }
    }
}

impl OperationService for CapabilityService {
    async fn get_operation<'a>(
        &'a self,
        context: RequestContext,
        request: ServiceRequest<'_, GetOperationRequest>,
    ) -> ServiceResult<impl Encodable<GetOperationResponse> + Send + use<'a>> {
        Response::ok(
            self.operation(&context, request.view().operation_id, request.bytes())
                .await?,
        )
    }

    async fn cancel_operation<'a>(
        &'a self,
        context: RequestContext,
        request: ServiceRequest<'_, CancelOperationRequest>,
    ) -> ServiceResult<impl Encodable<CancelOperationResponse> + Send + use<'a>> {
        let admitted = self
            .admit_public_command(
                &context,
                PublicApiAuditMethodV1::CancelOperation,
                request.bytes(),
            )
            .await?;

        Response::ok(CancelOperationResponse {
            operation: Some(admitted.operation).into(),
            ..Default::default()
        })
    }

    async fn watch(
        &self,
        context: RequestContext,
        request: ServiceRequest<'_, WatchRequest>,
    ) -> ServiceResult<ResponseStream<impl Encodable<Event> + Send + use<>>> {
        self.watch_response(&context, request).await
    }

    async fn get_node_capabilities<'a>(
        &'a self,
        _context: RequestContext,
        request: ServiceRequest<'_, GetNodeCapabilitiesRequest>,
    ) -> ServiceResult<impl Encodable<GetNodeCapabilitiesResponse> + Send + use<'a>> {
        Response::ok(self.node_capabilities(request.view())?)
    }
}

fn public_capability_id(context: &RequestContext) -> Result<CapabilityId, ConnectError> {
    let mut values = context.headers().get_all(PUBLIC_CAPABILITY_HEADER).iter();
    let value = values.next().ok_or_else(|| {
        ConnectError::new(
            ErrorCode::Unauthenticated,
            "public operation lookup requires a capability identity",
        )
    })?;
    if values.next().is_some() {
        return Err(ConnectError::new(
            ErrorCode::Unauthenticated,
            "public operation lookup requires exactly one capability identity",
        ));
    }
    let value = value.to_str().map_err(|_| {
        ConnectError::new(
            ErrorCode::Unauthenticated,
            "public capability identity is not valid text",
        )
    })?;
    let capability_id: CapabilityId = value.parse().map_err(|_| {
        ConnectError::new(
            ErrorCode::Unauthenticated,
            "public capability identity is not canonical",
        )
    })?;
    if capability_id.as_bytes() == &[0; 16] {
        return Err(ConnectError::new(
            ErrorCode::Unauthenticated,
            "public capability identity must be nonzero",
        ));
    }

    Ok(capability_id)
}

fn public_capability_handle(context: &RequestContext) -> Result<[u8; 32], ConnectError> {
    let mut values = context
        .headers()
        .get_all(PUBLIC_CAPABILITY_HANDLE_HEADER)
        .iter();
    let value = values.next().ok_or_else(|| {
        ConnectError::new(
            ErrorCode::Unauthenticated,
            "public request requires a capability handle",
        )
    })?;
    if values.next().is_some() {
        return Err(ConnectError::new(
            ErrorCode::Unauthenticated,
            "public request requires exactly one capability handle",
        ));
    }
    let value = value.to_str().map_err(|_| {
        ConnectError::new(
            ErrorCode::Unauthenticated,
            "public capability handle is not valid text",
        )
    })?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ConnectError::new(
            ErrorCode::Unauthenticated,
            "public capability handle is not canonical",
        ));
    }
    let mut handle = [0; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let digit = |byte| match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => 0,
        };
        handle[index] = (digit(pair[0]) << 4) | digit(pair[1]);
    }
    if handle == [0; 32] {
        return Err(ConnectError::new(
            ErrorCode::Unauthenticated,
            "public capability handle must be nonzero",
        ));
    }
    Ok(handle)
}

#[cfg(test)]
fn mutation_unavailable() -> ConnectError {
    ConnectError::new(ErrorCode::Unimplemented, UNAVAILABLE_REASON)
}

#[cfg(test)]
mod tests;
