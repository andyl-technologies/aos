//! Closed public RPC methods shared by request DATA and native authorization.
//!
//! Serde names retain the exact public service paths. Selecting a method does
//! not authenticate its body or admit an operation.

use serde::{Deserialize, Serialize};

/// Selects one closed public read or mutation RPC method.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum PublicApiAuditMethodV1 {
    /// Plans sandbox creation without admitting a mutation.
    #[serde(rename = "/aos.sandbox.v1.SandboxService/PlanCreate")]
    PlanCreate,
    /// Reads one sandbox resource.
    #[serde(rename = "/aos.sandbox.v1.SandboxService/GetSandbox")]
    GetSandbox,
    /// Lists sandboxes in one project.
    #[serde(rename = "/aos.sandbox.v1.SandboxService/ListSandboxes")]
    ListSandboxes,
    /// Lists the immediate children of one sandbox.
    #[serde(rename = "/aos.sandbox.v1.SandboxService/ListChildren")]
    ListChildren,
    /// Lists the bounded ancestors of one sandbox.
    #[serde(rename = "/aos.sandbox.v1.SandboxService/ListAncestors")]
    ListAncestors,
    /// Lists a bounded sandbox subtree.
    #[serde(rename = "/aos.sandbox.v1.SandboxService/ListDescendants")]
    ListDescendants,
    /// Plans one sandbox policy replacement.
    #[serde(rename = "/aos.sandbox.v1.SandboxService/PlanPolicy")]
    PlanPolicy,
    /// Reads one execution resource.
    #[serde(rename = "/aos.sandbox.v1.ExecutionService/GetExecution")]
    GetExecution,
    /// Lists executions for one sandbox.
    #[serde(rename = "/aos.sandbox.v1.ExecutionService/ListExecutions")]
    ListExecutions,
    /// Reads one filesystem-view resource.
    #[serde(rename = "/aos.sandbox.v1.FilesystemViewService/GetView")]
    GetView,
    /// Reads one filesystem-view attachment.
    #[serde(rename = "/aos.sandbox.v1.FilesystemViewService/GetAttachment")]
    GetAttachment,
    /// Lists filesystem views in one project.
    #[serde(rename = "/aos.sandbox.v1.FilesystemViewService/ListViews")]
    ListViews,
    /// Reads one snapshot resource.
    #[serde(rename = "/aos.sandbox.v1.SnapshotService/GetSnapshot")]
    GetSnapshot,
    /// Lists snapshots in an authorized scope.
    #[serde(rename = "/aos.sandbox.v1.SnapshotService/ListSnapshots")]
    ListSnapshots,
    /// Inspects one capability through its protected handle.
    #[serde(rename = "/aos.sandbox.v1.CapabilityService/Inspect")]
    InspectCapability,
    /// Reads cache status for one authorized scope.
    #[serde(rename = "/aos.sandbox.v1.CacheService/GetStatus")]
    GetCacheStatus,
    /// Reads one durable operation resource.
    #[serde(rename = "/aos.sandbox.v1.OperationService/GetOperation")]
    GetOperation,
    /// Streams authorized project events.
    #[serde(rename = "/aos.sandbox.v1.OperationService/Watch")]
    Watch,
    /// Creates one sandbox.
    #[serde(rename = "/aos.sandbox.v1.SandboxService/CreateSandbox")]
    CreateSandbox,
    /// Updates one sandbox policy.
    #[serde(rename = "/aos.sandbox.v1.SandboxService/UpdatePolicy")]
    UpdatePolicy,
    /// Starts one sandbox.
    #[serde(rename = "/aos.sandbox.v1.SandboxService/Start")]
    StartSandbox,
    /// Stops one sandbox.
    #[serde(rename = "/aos.sandbox.v1.SandboxService/Stop")]
    StopSandbox,
    /// Suspends one sandbox.
    #[serde(rename = "/aos.sandbox.v1.SandboxService/Suspend")]
    SuspendSandbox,
    /// Resumes one sandbox.
    #[serde(rename = "/aos.sandbox.v1.SandboxService/Resume")]
    ResumeSandbox,
    /// Deletes one sandbox.
    #[serde(rename = "/aos.sandbox.v1.SandboxService/DeleteSandbox")]
    DeleteSandbox,
    /// Creates one command execution.
    #[serde(rename = "/aos.sandbox.v1.ExecutionService/CreateExecution")]
    CreateExecution,
    /// Controls one command execution.
    #[serde(rename = "/aos.sandbox.v1.ExecutionService/ControlExecution")]
    ControlExecution,
    /// Cancels one command execution.
    #[serde(rename = "/aos.sandbox.v1.ExecutionService/CancelExecution")]
    CancelExecution,
    /// Creates one filesystem view.
    #[serde(rename = "/aos.sandbox.v1.FilesystemViewService/CreateView")]
    CreateView,
    /// Attaches one filesystem view.
    #[serde(rename = "/aos.sandbox.v1.FilesystemViewService/AttachView")]
    AttachView,
    /// Replaces one filesystem-view attachment.
    #[serde(rename = "/aos.sandbox.v1.FilesystemViewService/ReplaceAttachment")]
    ReplaceAttachment,
    /// Detaches one filesystem view.
    #[serde(rename = "/aos.sandbox.v1.FilesystemViewService/DetachView")]
    DetachView,
    /// Releases one filesystem view.
    #[serde(rename = "/aos.sandbox.v1.FilesystemViewService/ReleaseView")]
    ReleaseView,
    /// Creates one snapshot.
    #[serde(rename = "/aos.sandbox.v1.SnapshotService/CreateSnapshot")]
    CreateSnapshot,
    /// Restores one snapshot.
    #[serde(rename = "/aos.sandbox.v1.SnapshotService/RestoreSnapshot")]
    RestoreSnapshot,
    /// Forks one snapshot.
    #[serde(rename = "/aos.sandbox.v1.SnapshotService/ForkSnapshot")]
    ForkSnapshot,
    /// Deletes one snapshot.
    #[serde(rename = "/aos.sandbox.v1.SnapshotService/DeleteSnapshot")]
    DeleteSnapshot,
    /// Attenuates one capability.
    #[serde(rename = "/aos.sandbox.v1.CapabilityService/Attenuate")]
    AttenuateCapability,
    /// Renews one capability.
    #[serde(rename = "/aos.sandbox.v1.CapabilityService/Renew")]
    RenewCapability,
    /// Revokes one capability.
    #[serde(rename = "/aos.sandbox.v1.CapabilityService/Revoke")]
    RevokeCapability,
    /// Cancels one accepted operation before its semantic commit point.
    #[serde(rename = "/aos.sandbox.v1.OperationService/CancelOperation")]
    CancelOperation,
    /// Pins one cache object.
    #[serde(rename = "/aos.sandbox.v1.CacheService/PinObject")]
    PinCacheObject,
    /// Unpins one cache object.
    #[serde(rename = "/aos.sandbox.v1.CacheService/UnpinObject")]
    UnpinCacheObject,
    /// Performs one explicitly requested operator recovery action.
    #[serde(rename = "/aos.sandbox.v1.OperatorService/Recover")]
    OperatorRecover,
}

