//! Structurally checked public request DATA and bounded client proposals.
//!
//! The closed request union retains each generated protobuf request unchanged.
//! Construction checks shape, fences, features, framing, and client bounds; it
//! does not authenticate a peer, adopt provenance, admit an operation, or grant
//! effects. A public-client context is opaque input to an injected transport,
//! never Controller authorization evidence. The Controller retains its sealed
//! authority in a separate upper envelope and uses the same DATA validator.

use aos_proto::aos::sandbox::v1 as wire;

use super::limits::{MAXIMUM_CLI_EVENTS, MAXIMUM_CLI_PAGES, MAXIMUM_CLI_WAIT_NANOSECONDS};
use super::proto_json::StructuredOutputSchemaV1;

mod routes;
mod transport;
mod tree;
mod validation;

pub use transport::{
    DormantDeferredSandboxRequestV1, DormantPlanCreateHandlerV1, DormantPublicApiClientV1,
    DormantPublicApiWireTransportV1, DormantSandboxCommandExecutorV1, DormantSandboxTransportV1,
    DormantValidatedRequestSinkV1, dormant_sandbox_exit_code,
};
pub use tree::DormantSandboxTreePageConsumerV1;
pub use validation::validate_operator_recovery_request_v1;

/// Maximum opaque authenticated client context handed to a public API transport.
pub const MAXIMUM_PUBLIC_API_AUTHORIZATION_BYTES: usize = 64 * 1024;

/// Carries an opaque authorization context obtained by an authenticated client.
///
/// The bytes are interpreted and verified only by the injected public API
/// transport. They are not a bearer capability constructor and are never used
/// as controller-side authorization evidence.
#[derive(Clone, Eq, PartialEq)]
pub struct DormantPublicApiAuthorizationV1(Vec<u8>);

impl DormantPublicApiAuthorizationV1 {
    /// Constructs a bounded, nonempty transport authorization context.
    ///
    /// # Errors
    ///
    /// Returns [`DormantSandboxRoutingErrorV1::InvalidRequest`] for empty or
    /// oversized context bytes.
    pub fn new(context: Vec<u8>) -> Result<Self, DormantSandboxRoutingErrorV1> {
        if context.is_empty() || context.len() > MAXIMUM_PUBLIC_API_AUTHORIZATION_BYTES {
            Err(DormantSandboxRoutingErrorV1::InvalidRequest)
        } else {
            Ok(Self(context))
        }
    }

    /// Returns the opaque context to the explicitly injected client transport.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for DormantPublicApiAuthorizationV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DormantPublicApiAuthorizationV1")
            .field("redacted_bytes", &self.0.len())
            .finish_non_exhaustive()
    }
}

/// Selects stable output framing before a transport is chosen.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DormantSandboxOutputV1 {
    /// Selects human-readable output.
    Human,
    /// Selects one ProtoJSON document.
    Json,
    /// Selects line-delimited ProtoJSON.
    JsonLines,
}

/// Bounds all local pagination, event retention, and operation polling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DormantClientStatePlanV1 {
    maximum_pages: u16,
    maximum_events: u32,
    wait_timeout_nanos: Option<u64>,
}

impl DormantClientStatePlanV1 {
    /// Constructs a fail-closed local state plan.
    ///
    /// # Errors
    ///
    /// Returns [`DormantSandboxRoutingErrorV1::InvalidRequest`] when a bound is
    /// zero or exceeds the compiled CLI ceiling.
    pub const fn new(
        maximum_pages: u16,
        maximum_events: u32,
        wait_timeout_nanos: Option<u64>,
    ) -> Result<Self, DormantSandboxRoutingErrorV1> {
        if maximum_pages == 0
            || maximum_pages > MAXIMUM_CLI_PAGES
            || maximum_events == 0
            || maximum_events > MAXIMUM_CLI_EVENTS
            || matches!(wait_timeout_nanos, Some(0))
            || matches!(wait_timeout_nanos, Some(value) if value > MAXIMUM_CLI_WAIT_NANOSECONDS)
        {
            Err(DormantSandboxRoutingErrorV1::InvalidRequest)
        } else {
            Ok(Self {
                maximum_pages,
                maximum_events,
                wait_timeout_nanos,
            })
        }
    }

    /// Returns `None` for return-operation behavior or the bounded wait duration.
    #[must_use]
    pub const fn wait_timeout_nanos(self) -> Option<u64> {
        self.wait_timeout_nanos
    }

    /// Returns the maximum number of continuation pages this invocation may consume.
    #[must_use]
    pub const fn maximum_pages(self) -> u16 {
        self.maximum_pages
    }

    /// Returns the maximum number of watch events this invocation may retain.
    #[must_use]
    pub const fn maximum_events(self) -> u32 {
        self.maximum_events
    }
}

/// Retains the complete command family as a closed protobuf request union.
#[derive(Clone, Debug, PartialEq)]
pub enum DormantSandboxRequestKindV1 {
    /// Purely plans sandbox creation without a mutation context.
    PlanCreate(wire::PlanCreateSandboxRequest),
    /// Creates a sandbox.
    Create(wire::CreateSandboxRequest),
    /// Gets a sandbox.
    GetSandbox(wire::GetSandboxRequest),
    /// Gets an execution.
    GetExecution(wire::GetExecutionRequest),
    /// Gets a filesystem view.
    GetView(wire::GetViewRequest),
    /// Gets an attachment.
    GetAttachment(wire::GetAttachmentRequest),
    /// Gets a snapshot.
    GetSnapshot(wire::GetSnapshotRequest),
    /// Gets an operation.
    GetOperation(wire::GetOperationRequest),
    /// Lists project sandboxes.
    ListSandboxes(wire::ListSandboxesRequest),
    /// Lists sandbox executions.
    ListExecutions(wire::ListExecutionsRequest),
    /// Lists snapshots.
    ListSnapshots(wire::ListSnapshotsRequest),
    /// Lists bounded descendants for tree rendering.
    Tree(wire::ListDescendantsRequest),
    /// Lists immediate children.
    Children(wire::ListChildrenRequest),
    /// Lists bounded ancestors.
    Ancestors(wire::ListAncestorsRequest),
    /// Plans a policy update.
    PlanPolicy(wire::PlanSandboxPolicyRequest),
    /// Applies a policy update.
    UpdatePolicy(wire::UpdateSandboxPolicyRequest),
    /// Starts a sandbox.
    Start(wire::SandboxLifecycleRequest),
    /// Stops a sandbox.
    Stop(wire::SandboxLifecycleRequest),
    /// Suspends a sandbox.
    Suspend(wire::SandboxLifecycleRequest),
    /// Resumes a sandbox.
    Resume(wire::SandboxLifecycleRequest),
    /// Creates an execution.
    Exec(wire::CreateExecutionRequest),
    /// Attaches, resizes, or signals an execution.
    ExecutionControl(wire::ExecutionControlRequest),
    /// Cancels an execution.
    CancelExec(wire::CancelExecutionRequest),
    /// Cancels a long-running operation.
    CancelOperation(wire::CancelOperationRequest),
    /// Creates a snapshot.
    Snapshot(wire::CreateSnapshotRequest),
    /// Deletes a snapshot.
    DeleteSnapshot(wire::DeleteSnapshotRequest),
    /// Restores a snapshot.
    Restore(wire::RestoreSnapshotRequest),
    /// Forks a snapshot.
    Fork(wire::ForkSnapshotRequest),
    /// Deletes a sandbox.
    Delete(wire::DeleteSandboxRequest),
    /// Watches events.
    Events(wire::WatchRequest),
    /// Creates a filesystem view.
    ViewCreate(wire::CreateViewRequest),
    /// Attaches a filesystem view.
    ViewAttach(wire::AttachViewRequest),
    /// Replaces a filesystem-view attachment.
    ViewReplace(wire::ReplaceAttachmentRequest),
    /// Detaches a filesystem view.
    ViewDetach(wire::DetachViewRequest),
    /// Releases a filesystem view.
    ViewRelease(wire::ReleaseViewRequest),
    /// Lists filesystem views.
    ViewList(wire::ListViewsRequest),
    /// Reads cache status.
    CacheStatus(wire::GetCacheStatusRequest),
    /// Pins a cache object.
    CachePin(wire::PinCacheObjectRequest),
    /// Unpins a cache object.
    CacheUnpin(wire::UnpinCacheObjectRequest),
    /// Shows the public feature registry.
    CapabilitiesPublicApi(wire::GetPublicFeatureRegistryRequest),
    /// Shows logical node capabilities.
    CapabilitiesNode(wire::GetNodeCapabilitiesRequest),
    /// Attenuates a capability.
    CapabilityAttenuate(wire::AttenuateCapabilityRequest),
    /// Inspects a capability.
    CapabilityInspect(wire::InspectCapabilityRequest),
    /// Renews a capability.
    CapabilityRenew(wire::RenewCapabilityRequest),
    /// Revokes a capability.
    CapabilityRevoke(wire::RevokeCapabilityRequest),
    /// Proposes an operator recovery action.
    OperatorRecover(wire::OperatorRecoveryRequest),
    /// Generates completion source for one closed shell selection.
    Completions(DormantCompletionShellV1),
}

/// Selects a shell for dormant completion-source generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DormantCompletionShellV1 {
    /// Bash completion syntax.
    Bash,
    /// Fish completion syntax.
    Fish,
    /// Zsh completion syntax.
    Zsh,
}

/// Identifies one exact generated public API method path and cardinality.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DormantPublicApiRouteV1 {
    path: &'static str,
    server_streaming: bool,
}

impl DormantPublicApiRouteV1 {
    /// Returns the exact fully-qualified ConnectRPC procedure path.
    #[must_use]
    pub const fn path(self) -> &'static str {
        self.path
    }

    /// Reports whether this route returns a server stream.
    #[must_use]
    pub const fn is_server_streaming(self) -> bool {
        self.server_streaming
    }
}

/// Reports malformed typed requests or a supplied transport rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DormantSandboxRoutingErrorV1 {
    /// One semantic request invariant is absent or malformed.
    #[error("sandbox command request is invalid")]
    InvalidRequest,
    /// A mutation proposal reached the transport boundary without client context.
    #[error("sandbox command requires authenticated mutation authorization")]
    AuthorizationRequired,
    /// A supplied dormant transport rejected the typed request.
    #[error("sandbox command transport rejected the request")]
    TransportRejected,
}

/// Retains one structurally checked request without authenticated provenance.
#[derive(Clone, Debug, PartialEq)]
pub struct PublicSandboxRequestDataV1 {
    kind: DormantSandboxRequestKindV1,
    command: Option<wire::SandboxCommandRequest>,
    output: DormantSandboxOutputV1,
    client_state: DormantClientStatePlanV1,
}

impl PublicSandboxRequestDataV1 {
    /// Checks untrusted request DATA without adopting or authorizing it.
    ///
    /// # Errors
    ///
    /// Returns the established routing error when request, feature, fence,
    /// execution, framing, or client-state invariants fail.
    pub fn new(
        kind: DormantSandboxRequestKindV1,
        output: DormantSandboxOutputV1,
        client_state: DormantClientStatePlanV1,
    ) -> Result<Self, DormantSandboxRoutingErrorV1> {
        let request = Self {
            command: kind.to_command_proto(),
            kind,
            output,
            client_state,
        };
        request.validate()?;
        Ok(request)
    }

    /// Returns the exact typed request variant.
    #[must_use]
    pub const fn kind(&self) -> &DormantSandboxRequestKindV1 {
        &self.kind
    }

    /// Returns the method-preserving protobuf oneof for transport handoff.
    #[must_use]
    pub const fn command(&self) -> Option<&wire::SandboxCommandRequest> {
        self.command.as_ref()
    }

    /// Returns stable output framing.
    #[must_use]
    pub const fn output(&self) -> DormantSandboxOutputV1 {
        self.output
    }

    /// Returns the checked local-state and polling bounds.
    #[must_use]
    pub const fn client_state(&self) -> DormantClientStatePlanV1 {
        self.client_state
    }

    /// Returns the exact renderer schema after applying wait-vs-operation policy.
    #[must_use]
    pub const fn response_schema(&self) -> StructuredOutputSchemaV1 {
        if self.client_state.wait_timeout_nanos.is_some() {
            use DormantSandboxRequestKindV1 as K;
            use StructuredOutputSchemaV1 as S;
            match &self.kind {
                K::Create(_)
                | K::UpdatePolicy(_)
                | K::Start(_)
                | K::Stop(_)
                | K::Suspend(_)
                | K::Resume(_)
                | K::Restore(_)
                | K::Fork(_)
                | K::Delete(_) => return S::Sandbox,
                K::Exec(_) => return S::Execution,
                K::Snapshot(_) | K::DeleteSnapshot(_) => return S::Snapshot,
                K::ViewCreate(_) | K::ViewRelease(_) => return S::FilesystemView,
                K::ViewAttach(_) | K::ViewReplace(_) | K::ViewDetach(_) => return S::Attachment,
                K::CapabilityRenew(_) | K::CapabilityRevoke(_) => return S::Capability,
                _ => {}
            }
        }
        self.kind.response_schema(self.output)
    }
}

/// Retains an untrusted public proposal and its optional opaque client context.
///
/// Even a proposal with context requires independent server authentication and
/// admission. This type has no adopted-authority variant or constructor.
#[derive(Clone, Debug, PartialEq)]
pub struct DormantPublicApiRequestV1 {
    data: PublicSandboxRequestDataV1,
    authorization: Option<DormantPublicApiAuthorizationV1>,
}

impl DormantPublicApiRequestV1 {
    /// Constructs and fully validates a request whose variant determines the method.
    ///
    /// # Errors
    ///
    /// Returns [`DormantSandboxRoutingErrorV1::AuthorizationRequired`] before
    /// shape validation for a mutation without public-client context. Returns
    /// [`DormantSandboxRoutingErrorV1::InvalidRequest`] when any exact request,
    /// feature, fence, execution, or client-state invariant fails.
    pub fn from_parsed_command(
        kind: DormantSandboxRequestKindV1,
        output: DormantSandboxOutputV1,
        client_state: DormantClientStatePlanV1,
    ) -> Result<Self, DormantSandboxRoutingErrorV1> {
        if kind.requires_authorization() {
            return Err(DormantSandboxRoutingErrorV1::AuthorizationRequired);
        }
        Self::new_validated(kind, output, client_state, None)
    }

    /// Constructs a parsed request with an explicit public-client authorization context.
    ///
    /// The context remains opaque until the injected transport authenticates it.
    /// This constructor does not create controller-side authorization evidence.
    ///
    /// # Errors
    ///
    /// Returns [`DormantSandboxRoutingErrorV1::InvalidRequest`] when request or
    /// client-state validation fails.
    pub fn from_parsed_command_with_authorization(
        kind: DormantSandboxRequestKindV1,
        output: DormantSandboxOutputV1,
        client_state: DormantClientStatePlanV1,
        authorization: DormantPublicApiAuthorizationV1,
    ) -> Result<Self, DormantSandboxRoutingErrorV1> {
        Self::new_validated(kind, output, client_state, Some(authorization))
    }

    fn new_validated(
        kind: DormantSandboxRequestKindV1,
        output: DormantSandboxOutputV1,
        client_state: DormantClientStatePlanV1,
        authorization: Option<DormantPublicApiAuthorizationV1>,
    ) -> Result<Self, DormantSandboxRoutingErrorV1> {
        let data = PublicSandboxRequestDataV1::new(kind, output, client_state)?;
        Ok(Self {
            data,
            authorization,
        })
    }

    /// Returns the exact typed untrusted request variant.
    #[must_use]
    pub const fn kind(&self) -> &DormantSandboxRequestKindV1 {
        self.data.kind()
    }

    /// Returns the method-preserving protobuf oneof for transport handoff.
    #[must_use]
    pub const fn command(&self) -> Option<&wire::SandboxCommandRequest> {
        self.data.command()
    }

    /// Returns opaque context only to an explicitly injected public API transport.
    #[must_use]
    pub const fn public_api_authorization(&self) -> Option<&DormantPublicApiAuthorizationV1> {
        self.authorization.as_ref()
    }

    const fn has_authorization(&self) -> bool {
        self.authorization.is_some()
    }

    /// Returns stable output framing.
    #[must_use]
    pub const fn output(&self) -> DormantSandboxOutputV1 {
        self.data.output()
    }

    /// Returns the checked local-state and polling bounds.
    #[must_use]
    pub const fn client_state(&self) -> DormantClientStatePlanV1 {
        self.data.client_state()
    }

    /// Returns the exact renderer schema after applying wait-vs-operation policy.
    #[must_use]
    pub const fn response_schema(&self) -> StructuredOutputSchemaV1 {
        self.data.response_schema()
    }

    /// Rechecks structural DATA without authenticating or adopting it.
    ///
    /// # Errors
    ///
    /// Returns the established routing error when a request invariant fails.
    pub fn validate(&self) -> Result<(), DormantSandboxRoutingErrorV1> {
        self.data.validate()
    }
}

#[cfg(test)]
mod tests;
