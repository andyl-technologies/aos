//! Dormant typed routing boundary for the complete `aos sandbox` command family.
//!
//! Every route retains its established protobuf request type. The concrete
//! non-effect sink validates and returns that typed request as deferred work;
//! this module opens no socket, registers no controller route, and dispatches
//! no effect.

use aos_proto::aos::sandbox::v1 as wire;

use super::execution::MAXIMUM_ENDPOINT_PROOF_BYTES;
use super::grammar::{MAXIMUM_CLI_EVENTS, MAXIMUM_CLI_PAGES, MAXIMUM_CLI_WAIT_NANOSECONDS};
use super::grammar::{
    MAXIMUM_EXEC_ARGUMENT_BYTES, MAXIMUM_EXEC_ARGUMENT_VECTOR_BYTES, MAXIMUM_EXEC_ARGUMENTS,
};
use super::proto_json::StructuredOutputSchemaV1;
use super::provenance::AuthorizedResolvedMutationV1;
use super::requests::{ResolvedLifecycleActionV1, ResolvedPublicMutationProtoV1};

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

/// Consumes request-bound descendant pages under the CLI's fixed page budget.
pub struct DormantSandboxTreePageConsumerV1 {
    next_request: Option<wire::ListDescendantsRequest>,
    remaining_pages: u16,
}

impl DormantSandboxTreePageConsumerV1 {
    /// Constructs a consumer for one exact initial or resumed tree request.
    ///
    /// # Errors
    ///
    /// Returns [`DormantSandboxRoutingErrorV1::InvalidRequest`] when the root,
    /// page bounds, or server-token/preorder-state pairing is invalid.
    pub fn new(
        request: wire::ListDescendantsRequest,
        client_state: DormantClientStatePlanV1,
    ) -> Result<Self, DormantSandboxRoutingErrorV1> {
        if !valid_tree_request_v1(&request) {
            return Err(DormantSandboxRoutingErrorV1::InvalidRequest);
        }
        Ok(Self {
            next_request: Some(request),
            remaining_pages: client_state.maximum_pages,
        })
    }

    /// Checks and consumes one response against the exact outstanding request.
    ///
    /// A nonterminal response installs the next request with both the original
    /// opaque server token and its exact authenticated preorder state.
    ///
    /// # Errors
    ///
    /// Returns [`DormantSandboxRoutingErrorV1::InvalidRequest`] after the page
    /// budget is exhausted or when the response violates its request binding.
    pub fn consume(
        &mut self,
        response: wire::ListDescendantsResponse,
    ) -> Result<super::proto_json::CheckedSandboxTreeV1, DormantSandboxRoutingErrorV1> {
        if self.remaining_pages == 0 {
            return Err(DormantSandboxRoutingErrorV1::InvalidRequest);
        }
        let request = self
            .next_request
            .as_ref()
            .ok_or(DormantSandboxRoutingErrorV1::InvalidRequest)?;
        let checked = super::proto_json::CheckedSandboxTreeV1::from_response(request, response)
            .map_err(|_| DormantSandboxRoutingErrorV1::InvalidRequest)?;
        let continuation = checked.continuation().cloned();
        let next_request = continuation.map(|continuation| wire::ListDescendantsRequest {
            sandbox_id: request.sandbox_id.clone(),
            maximum_depth: request.maximum_depth,
            page_size: request.page_size,
            page_token: continuation.server_page_token().to_vec(),
            expected_preorder_before: continuation.preorder_before().clone().into(),
            ..Default::default()
        });

        self.remaining_pages -= 1;
        self.next_request = next_request;
        Ok(checked)
    }

    /// Returns the exact next request, including continuation state, when present.
    #[must_use]
    pub const fn next_request(&self) -> Option<&wire::ListDescendantsRequest> {
        self.next_request.as_ref()
    }

    /// Returns the remaining number of responses this consumer will accept.
    #[must_use]
    pub const fn remaining_pages(&self) -> u16 {
        self.remaining_pages
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
    /// Applies an authorized operator recovery action.
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

/// Stores one fully typed parser-produced in-process request.
#[derive(Clone, Debug, PartialEq)]
pub struct DormantSandboxRequestV1 {
    kind: DormantSandboxRequestKindV1,
    command: Option<wire::SandboxCommandRequest>,
    output: DormantSandboxOutputV1,
    client_state: DormantClientStatePlanV1,
    authorization: Option<DormantRequestAuthorizationV1>,
}

#[derive(Clone, Debug, PartialEq)]
enum DormantRequestAuthorizationV1 {
    Controller(AuthorizedResolvedMutationV1),
    PublicApi(DormantPublicApiAuthorizationV1),
}

impl DormantSandboxRequestV1 {
    /// Constructs an effect route only from exact authenticated mutation authority.
    ///
    /// # Errors
    ///
    /// Returns [`DormantSandboxRoutingErrorV1::InvalidRequest`] if the resolved
    /// protobuf projection or renderer/client plan is inconsistent.
    pub(crate) fn from_authorized_mutation(
        authorized: AuthorizedResolvedMutationV1,
        output: DormantSandboxOutputV1,
        client_state: DormantClientStatePlanV1,
    ) -> Result<Self, DormantSandboxRoutingErrorV1> {
        let kind = match authorized.mutation().to_proto() {
            ResolvedPublicMutationProtoV1::CreateSandbox(v) => {
                DormantSandboxRequestKindV1::Create(v)
            }
            ResolvedPublicMutationProtoV1::UpdatePolicy(v) => {
                DormantSandboxRequestKindV1::UpdatePolicy(v)
            }
            ResolvedPublicMutationProtoV1::Lifecycle { action, request } => match action {
                ResolvedLifecycleActionV1::Start
                | ResolvedLifecycleActionV1::ReconstructHibernated => {
                    DormantSandboxRequestKindV1::Start(request)
                }
                ResolvedLifecycleActionV1::Stop => DormantSandboxRequestKindV1::Stop(request),
                ResolvedLifecycleActionV1::Suspend => DormantSandboxRequestKindV1::Suspend(request),
                ResolvedLifecycleActionV1::ResumeFrozen => {
                    DormantSandboxRequestKindV1::Resume(request)
                }
            },
            ResolvedPublicMutationProtoV1::DeleteSandbox(v) => {
                DormantSandboxRequestKindV1::Delete(v)
            }
            ResolvedPublicMutationProtoV1::CreateExecution(v) => {
                DormantSandboxRequestKindV1::Exec(v)
            }
            ResolvedPublicMutationProtoV1::ExecutionControl(v) => {
                DormantSandboxRequestKindV1::ExecutionControl(v)
            }
            ResolvedPublicMutationProtoV1::CancelExecution(v) => {
                DormantSandboxRequestKindV1::CancelExec(v)
            }
            ResolvedPublicMutationProtoV1::CancelOperation(v) => {
                DormantSandboxRequestKindV1::CancelOperation(v)
            }
            ResolvedPublicMutationProtoV1::CreateView(v) => {
                DormantSandboxRequestKindV1::ViewCreate(v)
            }
            ResolvedPublicMutationProtoV1::AttachView(v) => {
                DormantSandboxRequestKindV1::ViewAttach(v)
            }
            ResolvedPublicMutationProtoV1::ReplaceAttachment(v) => {
                DormantSandboxRequestKindV1::ViewReplace(v)
            }
            ResolvedPublicMutationProtoV1::DetachView(v) => {
                DormantSandboxRequestKindV1::ViewDetach(v)
            }
            ResolvedPublicMutationProtoV1::ReleaseView(v) => {
                DormantSandboxRequestKindV1::ViewRelease(v)
            }
            ResolvedPublicMutationProtoV1::CreateSnapshot(v) => {
                DormantSandboxRequestKindV1::Snapshot(v)
            }
            ResolvedPublicMutationProtoV1::RestoreSnapshot(v) => {
                DormantSandboxRequestKindV1::Restore(v)
            }
            ResolvedPublicMutationProtoV1::DeleteSnapshot(v) => {
                DormantSandboxRequestKindV1::DeleteSnapshot(v)
            }
            ResolvedPublicMutationProtoV1::ForkSnapshot(v) => DormantSandboxRequestKindV1::Fork(v),
            ResolvedPublicMutationProtoV1::CachePin(v) => DormantSandboxRequestKindV1::CachePin(v),
            ResolvedPublicMutationProtoV1::CacheUnpin(v) => {
                DormantSandboxRequestKindV1::CacheUnpin(v)
            }
            ResolvedPublicMutationProtoV1::Capability(value) => match value {
                super::requests::ResolvedCapabilityProtoV1::Attenuate(v) => {
                    DormantSandboxRequestKindV1::CapabilityAttenuate(v)
                }
                super::requests::ResolvedCapabilityProtoV1::Inspect(v) => {
                    DormantSandboxRequestKindV1::CapabilityInspect(v)
                }
                super::requests::ResolvedCapabilityProtoV1::Renew(v) => {
                    DormantSandboxRequestKindV1::CapabilityRenew(v)
                }
                super::requests::ResolvedCapabilityProtoV1::Revoke(v) => {
                    DormantSandboxRequestKindV1::CapabilityRevoke(v)
                }
            },
        };
        Self::new_validated(
            kind,
            output,
            client_state,
            Some(DormantRequestAuthorizationV1::Controller(authorized)),
        )
    }

    /// Constructs and fully validates a request whose variant determines the method.
    ///
    /// # Errors
    ///
    /// Returns [`DormantSandboxRoutingErrorV1::InvalidRequest`] when any exact
    /// request, feature, fence, execution, or client-state invariant fails.
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
        Self::new_validated(
            kind,
            output,
            client_state,
            Some(DormantRequestAuthorizationV1::PublicApi(authorization)),
        )
    }

    fn new_validated(
        kind: DormantSandboxRequestKindV1,
        output: DormantSandboxOutputV1,
        client_state: DormantClientStatePlanV1,
        authorization: Option<DormantRequestAuthorizationV1>,
    ) -> Result<Self, DormantSandboxRoutingErrorV1> {
        let request = Self {
            command: kind.to_command_proto(),
            kind,
            output,
            client_state,
            authorization,
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

    /// Returns retained authority only to a future in-crate effect transport.
    #[must_use]
    pub(crate) const fn authorization(&self) -> Option<&AuthorizedResolvedMutationV1> {
        match &self.authorization {
            Some(DormantRequestAuthorizationV1::Controller(authorization)) => Some(authorization),
            Some(DormantRequestAuthorizationV1::PublicApi(_)) | None => None,
        }
    }

    /// Returns opaque authorization only to an explicitly injected public API transport.
    #[must_use]
    pub const fn public_api_authorization(&self) -> Option<&DormantPublicApiAuthorizationV1> {
        match &self.authorization {
            Some(DormantRequestAuthorizationV1::PublicApi(authorization)) => Some(authorization),
            Some(DormantRequestAuthorizationV1::Controller(_)) | None => None,
        }
    }

    const fn has_authorization(&self) -> bool {
        self.authorization.is_some()
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

    /// Validates invariant-bearing scalar fields before any transport can see the request.
    ///
    /// # Errors
    ///
    /// Returns [`DormantSandboxRoutingErrorV1::InvalidRequest`] for missing
    /// identities, mutation fences, descriptors, commands, or recovery actions.
    pub fn validate(&self) -> Result<(), DormantSandboxRoutingErrorV1> {
        use DormantSandboxRequestKindV1 as K;

        let valid = match &self.kind {
            K::PlanCreate(r) => {
                nonempty(&r.project_id)
                    && nonempty(&r.expected_project_resource_version)
                    && descriptor_present(r.specification.as_option())
                    && descriptor_present(r.requested_policy.as_option())
                    && valid_features(&r.required_features)
                    && (r.parent_sandbox_id.is_empty()
                        == r.expected_parent_resource_version.is_empty())
            }
            K::Create(r) => {
                nonempty(&r.project_id)
                    && nonempty(&r.expected_project_resource_version)
                    && descriptor_present(r.specification.as_option())
                    && descriptor_present(r.requested_policy.as_option())
                    && nonempty(&r.idempotency_key)
                    && r.operation_timeout.as_option().is_some_and(|timeout| {
                        (1..=MAXIMUM_CLI_WAIT_NANOSECONDS).contains(&timeout.nanoseconds)
                    })
                    && valid_features(&r.required_features)
                    && (r.parent_sandbox_id.is_empty()
                        == r.expected_parent_resource_version.is_empty())
            }
            K::GetSandbox(r) => nonempty(&r.sandbox_id),
            K::GetExecution(r) => nonempty(&r.execution_id),
            K::GetView(r) => nonempty(&r.view_id),
            K::GetAttachment(r) => nonempty(&r.attachment_id),
            K::GetSnapshot(r) => nonempty(&r.snapshot_id),
            K::GetOperation(r) => nonempty(&r.operation_id),
            K::ListSandboxes(r) => {
                nonempty(&r.project_id)
                    && valid_page_size(r.page_size)
                    && valid_optional_opaque(&r.page_token)
            }
            K::ListExecutions(r) => {
                nonempty(&r.sandbox_id)
                    && valid_page_size(r.page_size)
                    && valid_optional_opaque(&r.page_token)
            }
            K::ListSnapshots(r) => {
                (nonempty(&r.project_id) || nonempty(&r.sandbox_id))
                    && valid_page_size(r.page_size)
                    && valid_optional_opaque(&r.page_token)
            }
            K::Tree(r) => valid_tree_request_v1(r),
            K::Children(r) => {
                nonempty(&r.parent_sandbox_id)
                    && valid_page_size(r.page_size)
                    && valid_optional_opaque(&r.page_token)
            }
            K::Ancestors(r) => {
                nonempty(&r.sandbox_id)
                    && (1..=1_024).contains(&r.bounded_depth)
                    && valid_page_size(r.page_size)
                    && valid_optional_opaque(&r.page_token)
            }
            K::PlanPolicy(r) => {
                nonempty(&r.sandbox_id)
                    && nonempty(&r.expected_resource_version)
                    && descriptor_present(r.requested_policy.as_option())
            }
            K::UpdatePolicy(r) => {
                nonempty(&r.sandbox_id)
                    && descriptor_present(r.requested_policy.as_option())
                    && nonempty(&r.expected_plan_digest)
                    && mutation_resource_only(r.mutation.as_option())
            }
            K::Start(r) => {
                nonempty(&r.sandbox_id) && mutation_resource_only(r.mutation.as_option())
            }
            K::Stop(r) | K::Suspend(r) | K::Resume(r) => {
                nonempty(&r.sandbox_id) && mutation_with_incarnation(r.mutation.as_option())
            }
            K::Exec(r) => {
                nonempty(&r.sandbox_id)
                    && r.command.as_option().is_some_and(valid_command)
                    && nonempty(&r.client_public_key)
                    && nonempty(&r.proof_of_possession)
                    && mutation_with_incarnation(r.mutation.as_option())
                    && r.mutation.as_option().is_some_and(|mutation| {
                        crate::controller_query::contains_semantic_features_v1(
                            &mutation.required_features,
                            &[crate::controller_query::EXECUTION_CREATE_HOLDER_PROOF_FEATURE_V1],
                        )
                    })
                    && r.command.as_option().is_some_and(|command| {
                        execution_required_features_present(
                            command,
                            &r.mutation
                                .as_option()
                                .map_or(&[][..], |mutation| mutation.required_features.as_slice()),
                        )
                    })
            }
            K::ExecutionControl(r) => {
                // The guest-agent resize effect carries each dimension as u16.
                nonempty(&r.execution_id)
                    && mutation_with_incarnation(r.mutation.as_option())
                    && match r.action.to_i32() {
                        1 => {
                            r.terminal_rows == 0
                                && r.terminal_columns == 0
                                && r.signal.to_i32() == 0
                                && (1..=MAXIMUM_ENDPOINT_PROOF_BYTES)
                                    .contains(&r.client_public_key.len())
                                && (1..=MAXIMUM_ENDPOINT_PROOF_BYTES)
                                    .contains(&r.proof_of_possession.len())
                                && r.mutation.as_option().is_some_and(|mutation| {
                                    crate::controller_query::contains_semantic_features_v1(
                                        &mutation.required_features,
                                        &[crate::controller_query::EXECUTION_ATTACH_HOLDER_PROOF_FEATURE_V1],
                                    )
                                })
                        }
                        2 => {
                            (1..=u32::from(u16::MAX)).contains(&r.terminal_rows)
                                && (1..=u32::from(u16::MAX)).contains(&r.terminal_columns)
                                && r.signal.to_i32() == 0
                                && r.client_public_key.is_empty()
                                && r.proof_of_possession.is_empty()
                        }
                        3 => {
                            r.terminal_rows == 0
                                && r.terminal_columns == 0
                                && (1..=7).contains(&r.signal.to_i32())
                                && r.client_public_key.is_empty()
                                && r.proof_of_possession.is_empty()
                        }
                        _ => false,
                    }
            }
            K::CancelExec(r) => {
                nonempty(&r.execution_id) && mutation_with_incarnation(r.mutation.as_option())
            }
            K::CancelOperation(r) => {
                nonempty(&r.operation_id) && mutation_resource_only(r.mutation.as_option())
            }
            K::Snapshot(r) => {
                nonempty(&r.sandbox_id)
                    && (1..=2).contains(&r.requested_availability.to_i32())
                    && mutation_with_incarnation(r.mutation.as_option())
            }
            K::DeleteSnapshot(r) => {
                nonempty(&r.snapshot_id) && mutation_resource_only(r.mutation.as_option())
            }
            K::Restore(r) => {
                nonempty(&r.snapshot_id)
                    && nonempty(&r.target_sandbox_id)
                    && descriptor_present(r.requested_policy.as_option())
                    && mutation_resource_only(r.mutation.as_option())
            }
            K::Fork(r) => {
                nonempty(&r.snapshot_id)
                    && nonempty(&r.target_project_id)
                    && nonempty(&r.expected_project_resource_version)
                    && descriptor_present(r.requested_policy.as_option())
                    && nonempty(&r.idempotency_key)
                    && r.operation_timeout.as_option().is_some_and(|timeout| {
                        (1..=MAXIMUM_CLI_WAIT_NANOSECONDS).contains(&timeout.nanoseconds)
                    })
                    && valid_features(&r.required_features)
                    && crate::controller_query::contains_semantic_features_v1(
                        &r.required_features,
                        &[crate::controller_query::SNAPSHOT_PROJECT_VERSION_FENCE_FEATURE_V1],
                    )
                    && (r.parent_sandbox_id.is_empty()
                        == r.expected_parent_resource_version.is_empty())
            }
            K::Delete(r) => {
                nonempty(&r.sandbox_id)
                    && nonempty(&r.expected_plan_digest)
                    && mutation_resource_only(r.mutation.as_option())
                    && (!r.force
                        || r.mutation.as_option().is_some_and(|mutation| {
                            crate::controller_query::contains_semantic_features_v1(
                                &mutation.required_features,
                                &[crate::controller_query::FORCE_DELETE_FEATURE_V1],
                            )
                        }))
            }
            K::Events(r) => {
                nonempty(&r.project_id)
                    && !r.resource_types.is_empty()
                    && r.resource_types.len() <= 64
                    && valid_features(&r.observation_features)
                    && r.resume_after.as_option().is_none_or(|cursor| {
                        nonempty(&cursor.opaque_cursor)
                            && cursor.opaque_cursor.len()
                                <= super::grammar::MAXIMUM_CLI_OPAQUE_BYTES
                    })
            }
            K::ViewCreate(r) => {
                nonempty(&r.project_id)
                    && descriptor_present(r.revision.as_option())
                    && nonempty(&r.expected_project_resource_version)
                    && nonempty(&r.idempotency_key)
                    && r.operation_timeout.as_option().is_some_and(|timeout| {
                        (1..=MAXIMUM_CLI_WAIT_NANOSECONDS).contains(&timeout.nanoseconds)
                    })
                    && valid_features(&r.required_features)
            }
            K::ViewAttach(r) => {
                nonempty(&r.sandbox_id)
                    && nonempty(&r.view_id)
                    && descriptor_present(r.view_revision.as_option())
                    && nonempty(&r.destination_slot_id)
                    && (1..=5).contains(&r.mutation_mode.to_i32())
                    && mutation_with_incarnation(r.mutation.as_option())
                    && (!r.noexec
                        || r.mutation.as_option().is_some_and(|mutation| {
                            crate::controller_query::contains_semantic_features_v1(
                                &mutation.required_features,
                                &[crate::controller_query::ATTACHMENT_NOEXEC_FEATURE_V1],
                            )
                        }))
            }
            K::ViewReplace(r) => {
                nonempty(&r.attachment_id)
                    && nonempty(&r.new_view_id)
                    && descriptor_present(r.new_view_revision.as_option())
                    && mutation_resource_only(r.mutation.as_option())
            }
            K::ViewDetach(r) => {
                nonempty(&r.attachment_id) && mutation_resource_only(r.mutation.as_option())
            }
            K::ViewRelease(r) => {
                nonempty(&r.view_id) && mutation_resource_only(r.mutation.as_option())
            }
            K::ViewList(r) => {
                nonempty(&r.project_id)
                    && valid_page_size(r.page_size)
                    && valid_optional_opaque(&r.page_token)
            }
            K::CacheStatus(r) => nonempty(&r.project_id) != nonempty(&r.sandbox_id),
            K::CachePin(r) => {
                descriptor_present(r.object.as_option())
                    && valid_cache_consumer(&r.view_id, &r.attachment_id)
                    && mutation_resource_only(r.mutation.as_option())
                    && r.mutation.as_option().is_some_and(|mutation| {
                        crate::controller_query::contains_semantic_features_v1(
                            &mutation.required_features,
                            &[crate::controller_query::CACHE_CONSUMER_PIN_FEATURE_V1],
                        )
                    })
            }
            K::CacheUnpin(r) => {
                descriptor_present(r.object.as_option())
                    && valid_cache_consumer(&r.view_id, &r.attachment_id)
                    && mutation_resource_only(r.mutation.as_option())
                    && r.mutation.as_option().is_some_and(|mutation| {
                        crate::controller_query::contains_semantic_features_v1(
                            &mutation.required_features,
                            &[crate::controller_query::CACHE_CONSUMER_PIN_FEATURE_V1],
                        )
                    })
            }
            K::CapabilitiesPublicApi(_) => true,
            K::CapabilitiesNode(r) => nonempty(&r.node_id),
            K::CapabilityAttenuate(r) => {
                r.parent_capability_handle.len() == 32
                    && nonempty(&r.attenuation)
                    && r.holder_channel_binding.len() == 32
                    && nonempty(&r.idempotency_key)
                    && nonempty(&r.expected_parent_resource_version)
            }
            K::CapabilityInspect(r) => r.capability_handle.len() == 32,
            K::CapabilityRenew(r) => {
                r.capability_handle.len() == 32
                    && r.requested_expiry.as_option().is_some_and(|timestamp| {
                        (-62_135_596_800..=253_402_300_799).contains(&timestamp.seconds)
                            && timestamp.nanoseconds < 1_000_000_000
                    })
                    && mutation_resource_only(r.mutation.as_option())
            }
            K::CapabilityRevoke(r) => {
                nonempty(&r.capability_id) && mutation_resource_only(r.mutation.as_option())
            }
            K::OperatorRecover(r) => {
                super::observation_adapter::OperatorRecoveryRequestV1::try_from(r.clone()).is_ok()
            }
            K::Completions(_) => self.output == DormantSandboxOutputV1::Human,
        };

        let framing_is_valid =
            self.output != DormantSandboxOutputV1::JsonLines || self.kind.supports_json_lines();
        if valid && framing_is_valid {
            Ok(())
        } else {
            Err(DormantSandboxRoutingErrorV1::InvalidRequest)
        }
    }
}

impl DormantSandboxRequestKindV1 {
    fn requires_authorization(&self) -> bool {
        !matches!(
            self,
            Self::PlanCreate(_)
                | Self::GetSandbox(_)
                | Self::GetExecution(_)
                | Self::GetView(_)
                | Self::GetAttachment(_)
                | Self::GetSnapshot(_)
                | Self::GetOperation(_)
                | Self::ListSandboxes(_)
                | Self::ListExecutions(_)
                | Self::ListSnapshots(_)
                | Self::Tree(_)
                | Self::Children(_)
                | Self::Ancestors(_)
                | Self::PlanPolicy(_)
                | Self::Events(_)
                | Self::ViewList(_)
                | Self::CacheStatus(_)
                | Self::CapabilitiesPublicApi(_)
                | Self::CapabilitiesNode(_)
                | Self::CapabilityInspect(_)
                | Self::Completions(_)
        )
    }

    fn to_command_proto(&self) -> Option<wire::SandboxCommandRequest> {
        use wire::sandbox_command_request::Request as R;
        let request = match self {
            Self::PlanCreate(v) => R::PlanCreate(v.clone().into()),
            Self::Create(v) => R::Create(v.clone().into()),
            Self::GetSandbox(v) => R::GetSandbox(v.clone().into()),
            Self::GetExecution(v) => R::GetExecution(v.clone().into()),
            Self::GetView(v) => R::GetView(v.clone().into()),
            Self::GetAttachment(v) => R::GetAttachment(v.clone().into()),
            Self::GetSnapshot(v) => R::GetSnapshot(v.clone().into()),
            Self::GetOperation(v) => R::GetOperation(v.clone().into()),
            Self::ListSandboxes(v) => R::ListSandboxes(v.clone().into()),
            Self::ListExecutions(v) => R::ListExecutions(v.clone().into()),
            Self::ListSnapshots(v) => R::ListSnapshots(v.clone().into()),
            Self::Tree(v) => R::ListDescendants(v.clone().into()),
            Self::Children(v) => R::ListChildren(v.clone().into()),
            Self::Ancestors(v) => R::ListAncestors(v.clone().into()),
            Self::PlanPolicy(v) => R::PlanPolicy(v.clone().into()),
            Self::UpdatePolicy(v) => R::UpdatePolicy(v.clone().into()),
            Self::Start(v) => R::Start(v.clone().into()),
            Self::Stop(v) => R::Stop(v.clone().into()),
            Self::Suspend(v) => R::Suspend(v.clone().into()),
            Self::Resume(v) => R::Resume(v.clone().into()),
            Self::Exec(v) => R::CreateExecution(v.clone().into()),
            Self::ExecutionControl(v) => R::ExecutionControl(v.clone().into()),
            Self::CancelExec(v) => R::CancelExecution(v.clone().into()),
            Self::CancelOperation(v) => R::CancelOperation(v.clone().into()),
            Self::Snapshot(v) => R::CreateSnapshot(v.clone().into()),
            Self::DeleteSnapshot(v) => R::DeleteSnapshot(v.clone().into()),
            Self::Restore(v) => R::RestoreSnapshot(v.clone().into()),
            Self::Fork(v) => R::ForkSnapshot(v.clone().into()),
            Self::Delete(v) => R::DeleteSandbox(v.clone().into()),
            Self::Events(v) => R::Watch(v.clone().into()),
            Self::ViewCreate(v) => R::CreateView(v.clone().into()),
            Self::ViewAttach(v) => R::AttachView(v.clone().into()),
            Self::ViewReplace(v) => R::ReplaceAttachment(v.clone().into()),
            Self::ViewDetach(v) => R::DetachView(v.clone().into()),
            Self::ViewRelease(v) => R::ReleaseView(v.clone().into()),
            Self::ViewList(v) => R::ListViews(v.clone().into()),
            Self::CacheStatus(v) => R::CacheStatus(v.clone().into()),
            Self::CachePin(v) => R::CachePin(v.clone().into()),
            Self::CacheUnpin(v) => R::CacheUnpin(v.clone().into()),
            Self::CapabilitiesPublicApi(v) => R::PublicFeatures(v.clone().into()),
            Self::CapabilitiesNode(v) => R::NodeCapabilities(v.clone().into()),
            Self::CapabilityAttenuate(v) => R::AttenuateCapability(v.clone().into()),
            Self::CapabilityInspect(v) => R::InspectCapability(v.clone().into()),
            Self::CapabilityRenew(v) => R::RenewCapability(v.clone().into()),
            Self::CapabilityRevoke(v) => R::RevokeCapability(v.clone().into()),
            Self::OperatorRecover(v) => R::OperatorRecovery(v.clone().into()),
            Self::Completions(_) => return None,
        };
        Some(wire::SandboxCommandRequest {
            request: Some(request),
            ..Default::default()
        })
    }

    /// Reports whether this route can emit independently framed result records.
    #[must_use]
    pub const fn supports_json_lines(&self) -> bool {
        matches!(
            self,
            Self::ListSandboxes(_)
                | Self::ListExecutions(_)
                | Self::ListSnapshots(_)
                | Self::Tree(_)
                | Self::Children(_)
                | Self::Ancestors(_)
                | Self::Events(_)
                | Self::ViewList(_)
        )
    }

    /// Returns the exact established response schema selected by this route.
    #[must_use]
    pub const fn response_schema(
        &self,
        output: DormantSandboxOutputV1,
    ) -> StructuredOutputSchemaV1 {
        use StructuredOutputSchemaV1 as S;
        match self {
            Self::PlanCreate(_) | Self::PlanPolicy(_) => S::PolicyPlan,
            Self::Create(_)
            | Self::Start(_)
            | Self::Stop(_)
            | Self::Suspend(_)
            | Self::Resume(_)
            | Self::UpdatePolicy(_)
            | Self::Restore(_)
            | Self::Fork(_)
            | Self::Delete(_) => S::Operation,
            Self::GetSandbox(_) => S::Sandbox,
            Self::GetExecution(_) | Self::Exec(_) => S::Execution,
            Self::GetView(_) | Self::ViewCreate(_) | Self::ViewRelease(_) => S::FilesystemView,
            Self::GetAttachment(_)
            | Self::ViewAttach(_)
            | Self::ViewReplace(_)
            | Self::ViewDetach(_) => S::Attachment,
            Self::GetSnapshot(_) | Self::Snapshot(_) | Self::DeleteSnapshot(_) => S::Snapshot,
            Self::GetOperation(_)
            | Self::CancelExec(_)
            | Self::CancelOperation(_)
            | Self::CachePin(_)
            | Self::CacheUnpin(_) => S::Operation,
            Self::ListSandboxes(_) => {
                if matches!(output, DormantSandboxOutputV1::JsonLines) {
                    S::Sandbox
                } else {
                    S::SandboxList
                }
            }
            Self::ListExecutions(_) => {
                if matches!(output, DormantSandboxOutputV1::JsonLines) {
                    S::Execution
                } else {
                    S::ExecutionList
                }
            }
            Self::ListSnapshots(_) => {
                if matches!(output, DormantSandboxOutputV1::JsonLines) {
                    S::Snapshot
                } else {
                    S::SnapshotList
                }
            }
            Self::Tree(_) => S::SandboxTree,
            Self::Children(_) => {
                if matches!(output, DormantSandboxOutputV1::JsonLines) {
                    S::Sandbox
                } else {
                    S::ChildrenList
                }
            }
            Self::Ancestors(_) => {
                if matches!(output, DormantSandboxOutputV1::JsonLines) {
                    S::Sandbox
                } else {
                    S::AncestorsList
                }
            }
            Self::ExecutionControl(_) => S::Operation,
            Self::Events(_) => S::Event,
            Self::ViewList(_) => {
                if matches!(output, DormantSandboxOutputV1::JsonLines) {
                    S::FilesystemView
                } else {
                    S::ViewList
                }
            }
            Self::CacheStatus(_) => S::CacheStatus,
            Self::CapabilitiesPublicApi(_) => S::PublicFeatureRegistry,
            Self::CapabilitiesNode(_) => S::NodeCapabilities,
            Self::CapabilityAttenuate(_)
            | Self::CapabilityInspect(_)
            | Self::CapabilityRenew(_)
            | Self::CapabilityRevoke(_) => S::Capability,
            Self::OperatorRecover(_) => S::Operation,
            Self::Completions(_) => S::CompletionScript,
        }
    }

    /// Returns the closed stable route label used by deferred rendering.
    #[must_use]
    pub const fn route_name(&self) -> &'static str {
        match self {
            Self::PlanCreate(_) => "create-plan",
            Self::Create(_) => "create",
            Self::GetSandbox(_)
            | Self::GetExecution(_)
            | Self::GetView(_)
            | Self::GetAttachment(_)
            | Self::GetSnapshot(_)
            | Self::GetOperation(_) => "get",
            Self::ListSandboxes(_) | Self::ListExecutions(_) | Self::ListSnapshots(_) => "list",
            Self::Tree(_) => "tree",
            Self::Children(_) => "children",
            Self::Ancestors(_) => "ancestors",
            Self::PlanPolicy(_) => "plan-policy",
            Self::UpdatePolicy(_) => "update-policy",
            Self::Start(_) => "start",
            Self::Stop(_) => "stop",
            Self::Suspend(_) => "suspend",
            Self::Resume(_) => "resume",
            Self::Exec(_) => "exec",
            Self::ExecutionControl(_) => "execution-control",
            Self::CancelExec(_) => "cancel-exec",
            Self::CancelOperation(_) => "cancel-operation",
            Self::Snapshot(_) => "snapshot",
            Self::DeleteSnapshot(_) => "snapshot-delete",
            Self::Restore(_) => "restore",
            Self::Fork(_) => "fork",
            Self::Delete(_) => "delete",
            Self::Events(_) => "events",
            Self::ViewCreate(_) => "view-create",
            Self::ViewAttach(_) => "view-attach",
            Self::ViewReplace(_) => "view-replace",
            Self::ViewDetach(_) => "view-detach",
            Self::ViewRelease(_) => "view-release",
            Self::ViewList(_) => "view-list",
            Self::CacheStatus(_) => "cache-status",
            Self::CachePin(_) => "cache-pin",
            Self::CacheUnpin(_) => "cache-unpin",
            Self::CapabilitiesPublicApi(_) => "capabilities-public-api",
            Self::CapabilitiesNode(_) => "capabilities-node",
            Self::CapabilityAttenuate(_) => "capability-attenuate",
            Self::CapabilityInspect(_) => "capability-inspect",
            Self::CapabilityRenew(_) => "capability-renew",
            Self::CapabilityRevoke(_) => "capability-revoke",
            Self::OperatorRecover(_) => "operator-recover",
            Self::Completions(_) => "completions",
        }
    }

    /// Returns the exact public ConnectRPC path for this request variant.
    #[must_use]
    pub const fn public_api_route(&self) -> Option<DormantPublicApiRouteV1> {
        use DormantSandboxRequestKindV1 as K;

        let (path, server_streaming) = match self {
            K::PlanCreate(_) => ("/aos.sandbox.v1.SandboxService/PlanCreate", false),
            K::Create(_) => ("/aos.sandbox.v1.SandboxService/CreateSandbox", false),
            K::GetSandbox(_) => ("/aos.sandbox.v1.SandboxService/GetSandbox", false),
            K::ListSandboxes(_) => ("/aos.sandbox.v1.SandboxService/ListSandboxes", false),
            K::Children(_) => ("/aos.sandbox.v1.SandboxService/ListChildren", false),
            K::Ancestors(_) => ("/aos.sandbox.v1.SandboxService/ListAncestors", false),
            K::Tree(_) => ("/aos.sandbox.v1.SandboxService/ListDescendants", false),
            K::PlanPolicy(_) => ("/aos.sandbox.v1.SandboxService/PlanPolicy", false),
            K::UpdatePolicy(_) => ("/aos.sandbox.v1.SandboxService/UpdatePolicy", false),
            K::Start(_) => ("/aos.sandbox.v1.SandboxService/Start", false),
            K::Stop(_) => ("/aos.sandbox.v1.SandboxService/Stop", false),
            K::Suspend(_) => ("/aos.sandbox.v1.SandboxService/Suspend", false),
            K::Resume(_) => ("/aos.sandbox.v1.SandboxService/Resume", false),
            K::Delete(_) => ("/aos.sandbox.v1.SandboxService/DeleteSandbox", false),
            K::Exec(_) => ("/aos.sandbox.v1.ExecutionService/CreateExecution", false),
            K::GetExecution(_) => ("/aos.sandbox.v1.ExecutionService/GetExecution", false),
            K::ListExecutions(_) => ("/aos.sandbox.v1.ExecutionService/ListExecutions", false),
            K::ExecutionControl(_) => ("/aos.sandbox.v1.ExecutionService/ControlExecution", false),
            K::CancelExec(_) => ("/aos.sandbox.v1.ExecutionService/CancelExecution", false),
            K::ViewCreate(_) => ("/aos.sandbox.v1.FilesystemViewService/CreateView", false),
            K::GetView(_) => ("/aos.sandbox.v1.FilesystemViewService/GetView", false),
            K::GetAttachment(_) => ("/aos.sandbox.v1.FilesystemViewService/GetAttachment", false),
            K::ViewList(_) => ("/aos.sandbox.v1.FilesystemViewService/ListViews", false),
            K::ViewAttach(_) => ("/aos.sandbox.v1.FilesystemViewService/AttachView", false),
            K::ViewReplace(_) => (
                "/aos.sandbox.v1.FilesystemViewService/ReplaceAttachment",
                false,
            ),
            K::ViewDetach(_) => ("/aos.sandbox.v1.FilesystemViewService/DetachView", false),
            K::ViewRelease(_) => ("/aos.sandbox.v1.FilesystemViewService/ReleaseView", false),
            K::Snapshot(_) => ("/aos.sandbox.v1.SnapshotService/CreateSnapshot", false),
            K::GetSnapshot(_) => ("/aos.sandbox.v1.SnapshotService/GetSnapshot", false),
            K::ListSnapshots(_) => ("/aos.sandbox.v1.SnapshotService/ListSnapshots", false),
            K::Restore(_) => ("/aos.sandbox.v1.SnapshotService/RestoreSnapshot", false),
            K::Fork(_) => ("/aos.sandbox.v1.SnapshotService/ForkSnapshot", false),
            K::DeleteSnapshot(_) => ("/aos.sandbox.v1.SnapshotService/DeleteSnapshot", false),
            K::CapabilityAttenuate(_) => ("/aos.sandbox.v1.CapabilityService/Attenuate", false),
            K::CapabilityInspect(_) => ("/aos.sandbox.v1.CapabilityService/Inspect", false),
            K::CapabilityRenew(_) => ("/aos.sandbox.v1.CapabilityService/Renew", false),
            K::CapabilityRevoke(_) => ("/aos.sandbox.v1.CapabilityService/Revoke", false),
            K::GetOperation(_) => ("/aos.sandbox.v1.OperationService/GetOperation", false),
            K::CancelOperation(_) => ("/aos.sandbox.v1.OperationService/CancelOperation", false),
            K::Events(_) => ("/aos.sandbox.v1.OperationService/Watch", true),
            K::CacheStatus(_) => ("/aos.sandbox.v1.CacheService/GetStatus", false),
            K::CachePin(_) => ("/aos.sandbox.v1.CacheService/PinObject", false),
            K::CacheUnpin(_) => ("/aos.sandbox.v1.CacheService/UnpinObject", false),
            K::CapabilitiesPublicApi(_) => (
                "/aos.sandbox.v1.DiscoveryService/GetPublicFeatureRegistry",
                false,
            ),
            K::CapabilitiesNode(_) => (
                "/aos.sandbox.v1.DiscoveryService/GetNodeCapabilities",
                false,
            ),
            K::OperatorRecover(_) => ("/aos.sandbox.v1.OperatorService/Recover", false),
            K::Completions(_) => return None,
        };
        Some(DormantPublicApiRouteV1 {
            path,
            server_streaming,
        })
    }
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

fn nonempty(value: &[u8]) -> bool {
    !value.is_empty()
}

fn valid_cache_consumer(view_id: &[u8], attachment_id: &[u8]) -> bool {
    let valid_identity = |value: &[u8]| value.len() == 16 && value.iter().any(|byte| *byte != 0);
    valid_identity(view_id) && (attachment_id.is_empty() || valid_identity(attachment_id))
}

fn descriptor_present(value: Option<&wire::ObjectDescriptor>) -> bool {
    value.is_some_and(|descriptor| {
        !descriptor.media_type.is_empty()
            && descriptor.sha256.len() == 32
            && descriptor.sha256.iter().any(|byte| *byte != 0)
            && descriptor.encoded_size > 0
    })
}

fn mutation_shape(value: Option<&wire::MutationContext>) -> bool {
    value.is_some_and(|mutation| {
        !mutation.idempotency_key.is_empty()
            && mutation.idempotency_key.len() <= super::grammar::MAXIMUM_IDEMPOTENCY_KEY_BYTES
            && !mutation.expected_resource_version.is_empty()
            && mutation.expected_resource_version.len() <= super::grammar::MAXIMUM_CLI_OPAQUE_BYTES
            && mutation
                .operation_timeout
                .as_option()
                .is_some_and(|timeout| {
                    (1..=MAXIMUM_CLI_WAIT_NANOSECONDS).contains(&timeout.nanoseconds)
                })
            && valid_features(&mutation.required_features)
    })
}

fn mutation_resource_only(value: Option<&wire::MutationContext>) -> bool {
    mutation_shape(value)
        && value.is_some_and(|mutation| mutation.expected_incarnation_id.is_empty())
}

fn mutation_with_incarnation(value: Option<&wire::MutationContext>) -> bool {
    mutation_shape(value)
        && value.is_some_and(|mutation| {
            mutation.expected_incarnation_id.len() == 16
                && mutation
                    .expected_incarnation_id
                    .iter()
                    .any(|byte| *byte != 0)
        })
}

fn valid_page_size(value: u32) -> bool {
    (1..=1_024).contains(&value)
}

fn valid_tree_request_v1(request: &wire::ListDescendantsRequest) -> bool {
    let continuation_is_valid = match (
        request.page_token.is_empty(),
        request.expected_preorder_before.as_option(),
    ) {
        (true, None) => true,
        (false, Some(state)) => {
            state.emitted_nodes > 0
                && state
                    .open_path
                    .first()
                    .is_some_and(|root| root == &request.sandbox_id)
                && super::proto_json::validate_sandbox_tree_preorder_state_v1(state).is_ok()
        }
        _ => false,
    };
    nonempty(&request.sandbox_id)
        && request.sandbox_id.len() == 16
        && (1..=1_024).contains(&request.maximum_depth)
        && valid_page_size(request.page_size)
        && valid_optional_opaque(&request.page_token)
        && continuation_is_valid
}

fn valid_optional_opaque(value: &[u8]) -> bool {
    value.is_empty() || value.len() <= super::grammar::MAXIMUM_CLI_OPAQUE_BYTES
}

fn valid_command(command: &wire::Command) -> bool {
    let direct = command
        .arguments
        .first()
        .is_some_and(|program| !program.is_empty())
        && command.sandbox_shell.is_empty();
    let shell = command.arguments.is_empty()
        && !command.sandbox_shell.is_empty()
        && command.sandbox_shell.len() <= MAXIMUM_EXEC_ARGUMENT_BYTES
        && !command.sandbox_shell.contains(&0);
    // The runtime execution effect encodes PTY geometry as two u16 values.
    let io_shape_is_valid = match command.io_mode.to_i32() {
        1 => {
            !command.allocate_terminal
                && command.terminal_rows == 0
                && command.terminal_columns == 0
                && command.detached_capture_bytes == 0
                && command.maximum_stdout_bytes.is_none()
                && command.maximum_stderr_bytes.is_none()
        }
        2 => {
            command.allocate_terminal
                && (1..=u32::from(u16::MAX)).contains(&command.terminal_rows)
                && (1..=u32::from(u16::MAX)).contains(&command.terminal_columns)
                && command.detached_capture_bytes == 0
                && command.maximum_stdout_bytes.is_none()
                && command.maximum_stderr_bytes.is_none()
        }
        3 => {
            !command.allocate_terminal
                && command.terminal_rows == 0
                && command.terminal_columns == 0
                && crate::controller_query::portable_resource::checked_detached_capture_bytes(
                    command,
                )
                .is_some()
        }
        _ => false,
    };
    let argument_bytes = command.arguments.iter().map(Vec::len).sum::<usize>();
    (direct || shell)
        && command.arguments.len() <= MAXIMUM_EXEC_ARGUMENTS
        && command
            .arguments
            .iter()
            .all(|argument| argument.len() <= MAXIMUM_EXEC_ARGUMENT_BYTES && !argument.contains(&0))
        && argument_bytes <= MAXIMUM_EXEC_ARGUMENT_VECTOR_BYTES
        && command
            .execution_timeout
            .as_option()
            .is_some_and(|timeout| {
                (1..=MAXIMUM_CLI_WAIT_NANOSECONDS).contains(&timeout.nanoseconds)
            })
        && io_shape_is_valid
        && valid_features(&command.stream_features)
        && valid_environment(&command.environment)
        && valid_relative_path(&command.working_directory)
}

/// Checks that execution semantics are required at both mutation and stream scope.
pub(crate) fn execution_required_features_present(
    command: &wire::Command,
    required_features: &[wire::Feature],
) -> bool {
    let program_feature = if command.sandbox_shell.is_empty() {
        None
    } else {
        Some(crate::controller_query::EXECUTION_SANDBOX_SHELL_FEATURE_V1)
    };
    let io_feature = match command.io_mode.to_i32() {
        1 => crate::controller_query::EXECUTION_STREAM_FEATURE_V1,
        2 => crate::controller_query::EXECUTION_PTY_FEATURE_V1,
        3 => crate::controller_query::EXECUTION_DETACHED_CAPTURE_FEATURE_V1,
        _ => return false,
    };
    let mut required = vec![
        crate::controller_query::EXECUTION_TIMEOUT_FEATURE_V1,
        io_feature,
    ];
    let mut stream_required = vec![io_feature];
    required.extend(program_feature);
    if command.io_mode.to_i32() == 3 {
        let ceiling_feature =
            crate::controller_query::EXECUTION_DETACHED_CAPTURE_STREAM_CEILINGS_FEATURE_V1;
        required.push(ceiling_feature);
        stream_required.push(ceiling_feature);
    }
    crate::controller_query::contains_semantic_features_v1(required_features, &required)
        && crate::controller_query::contains_semantic_features_v1(
            &command.stream_features,
            &stream_required,
        )
}

fn valid_features(features: &[wire::Feature]) -> bool {
    crate::controller_query::portable::CheckedFeatureSetV1::try_from(features.to_vec()).is_ok()
}

fn valid_environment(environment: &[wire::EnvironmentVariable]) -> bool {
    let total_bytes = environment.iter().try_fold(0_usize, |total, variable| {
        total
            .checked_add(variable.name.len())?
            .checked_add(variable.value.len())
    });
    environment.len() <= super::execution::MAXIMUM_EXEC_ENVIRONMENT
        && total_bytes
            .is_some_and(|bytes| bytes <= super::execution::MAXIMUM_EXEC_ENVIRONMENT_BYTES)
        && environment.iter().all(|variable| {
            !variable.name.is_empty()
                && variable.name.len() <= super::execution::MAXIMUM_EXEC_ENVIRONMENT_NAME_BYTES
                && variable.value.len() <= super::execution::MAXIMUM_EXEC_ENVIRONMENT_VALUE_BYTES
                && variable.name.len() + 1 + variable.value.len() + 1
                    <= aos_sandbox_core::MAX_EXECUTION_STRING_BYTES
                && !variable.value.contains(&0)
                && variable.name.bytes().enumerate().all(|(index, byte)| {
                    byte == b'_'
                        || byte.is_ascii_alphabetic()
                        || (index > 0 && byte.is_ascii_digit())
                })
        })
        && environment
            .windows(2)
            .all(|pair| pair[0].name < pair[1].name)
}

fn valid_relative_path(path: &[u8]) -> bool {
    path.is_empty()
        || (!path.starts_with(b"/")
            && !path.contains(&0)
            && path
                .split(|byte| *byte == b'/')
                .all(|component| !component.is_empty() && component != b"." && component != b".."))
}

/// Reports malformed typed requests or a supplied transport rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DormantSandboxRoutingErrorV1 {
    /// One semantic request invariant is absent or malformed.
    #[error("sandbox command request is invalid")]
    InvalidRequest,
    /// An effect route reached the transport boundary without sealed authority.
    #[error("sandbox command requires authenticated mutation authorization")]
    AuthorizationRequired,
    /// A supplied dormant transport rejected the typed request.
    #[error("sandbox command transport rejected the request")]
    TransportRejected,
}

/// Preserves a fully validated request as non-effect deferred work.
#[derive(Clone, Debug, PartialEq)]
pub struct DormantDeferredSandboxRequestV1 {
    request: DormantSandboxRequestV1,
}

impl DormantDeferredSandboxRequestV1 {
    /// Returns the exact validated request retained by the non-effect sink.
    #[must_use]
    pub const fn request(&self) -> &DormantSandboxRequestV1 {
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
        request: DormantSandboxRequestV1,
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
        request: DormantSandboxRequestV1,
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
        request: DormantSandboxRequestV1,
    ) -> Result<Self::Output, DormantSandboxRoutingErrorV1> {
        request.validate()?;
        if request.kind.requires_authorization() && request.public_api_authorization().is_none() {
            return Err(DormantSandboxRoutingErrorV1::AuthorizationRequired);
        }
        let route = request
            .kind
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
        request: DormantSandboxRequestV1,
    ) -> Result<T::Output, DormantSandboxRoutingErrorV1> {
        request.validate()?;
        if request.kind.requires_authorization() && !request.has_authorization() {
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
        request: DormantSandboxRequestV1,
    ) -> Result<Self::Output, DormantSandboxRoutingErrorV1> {
        request.validate()?;
        if request.kind.requires_authorization() && !request.has_authorization() {
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
        let request = DormantSandboxRequestV1::from_parsed_command(
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
