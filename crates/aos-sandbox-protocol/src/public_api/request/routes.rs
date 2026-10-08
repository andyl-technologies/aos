//! Closed method projections, output schemas, and public RPC route metadata.

use aos_proto::aos::sandbox::v1 as wire;

use super::{DormantPublicApiRouteV1, DormantSandboxOutputV1, DormantSandboxRequestKindV1};
use crate::public_api::proto_json::StructuredOutputSchemaV1;

impl DormantSandboxRequestKindV1 {
    pub(super) fn requires_authorization(&self) -> bool {
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

    pub(super) fn to_command_proto(&self) -> Option<wire::SandboxCommandRequest> {
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
