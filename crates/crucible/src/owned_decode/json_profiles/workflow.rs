//! Owns the closed workflow JSON DTOs and their diagnostic label roster.
//!
//! Validation and runtime effects stay in the consuming service. Field names,
//! borrowing and Serde type names retain the existing wire contract.

use serde::Deserialize;
use serde::de::IgnoredAny;

mod executor;

pub use executor::{
    CampaignExecution, CampaignExecutionGrant, CampaignExecutionPlanner,
    CampaignExecutionPlanningBudget, CampaignExecutionRetention, CampaignExecutionSearch,
    ExecutorAssignmentLimits, ExecutorCapacity, ExecutorDeployment, ExecutorEndpoint, ExecutorHost,
    ExecutorHostArchitecture, ExecutorHostOperationalCapacity, ExecutorOperationBudget,
    ExecutorOperationBudgets,
};

/// Deserializes the closed ServiceServer wire object.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceServer {
    /// Declares the connection workers.
    pub connection_workers: usize,
    /// Declares the pending connections.
    pub pending_connections: usize,
    /// Declares the maximum requests per connection.
    pub maximum_requests_per_connection: usize,
    /// Declares the accept poll millis.
    pub accept_poll_millis: u64,
    /// Declares the read timeout millis.
    pub read_timeout_millis: u64,
    /// Declares the write timeout millis.
    pub write_timeout_millis: u64,
}

/// Deserializes the closed ServiceMode wire object.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ServiceMode {
    /// Selects the read write representation.
    ReadWrite,
    /// Selects the read only representation.
    ReadOnly,
}

/// Deserializes the closed WorkflowProjection wire object.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkflowProjection<'input> {
    /// Declares the schema.
    #[serde(borrow)]
    pub schema: &'input str,
    /// Declares the family.
    #[serde(borrow)]
    pub family: &'input str,
    /// Declares the native count.
    pub native_count: u64,
    /// Declares the hot fork.
    pub hot_fork: Option<IgnoredAny>,
    /// Declares the world memory mib.
    pub world_memory_mib: u64,
    /// Declares the execution quanta.
    pub execution_quanta: u64,
    /// Declares the service profile.
    #[serde(borrow)]
    pub service_profile: ServiceProfile<'input>,
    /// Declares the guest assets.
    pub guest_assets: GuestAssets,
    /// Declares the emulator executable artifact.
    #[serde(rename = "qemu")]
    pub executable: IgnoredAny,
    /// Declares the plugin.
    pub plugin: IgnoredAny,
    /// Declares the rows.
    pub rows: IgnoredAny,
}

/// Deserializes the closed ServiceProfile wire object.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceProfile<'input> {
    /// Declares the operator.
    #[serde(borrow)]
    pub operator: ServiceOperator<'input>,
    /// Declares the catalog.
    pub catalog: ResourceVector,
    /// Declares the catalog maximum inodes.
    pub catalog_maximum_inodes: u64,
    /// Declares the native.
    pub native: ResourceVector,
    /// Declares the aggregate.
    pub aggregate: Aggregate,
    /// Declares the preparation seconds.
    pub preparation_seconds: u64,
    /// Declares the invocation seconds.
    pub invocation_seconds: u64,
}

/// Deserializes the closed ServiceOperator wire object.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceOperator<'input> {
    /// Specifies the required deployment of the distinct executor service.
    #[serde(borrow)]
    pub executor: ExecutorDeployment<'input>,
    /// Declares the campaign server.
    pub campaign_server: ServiceServer,
    /// Declares the campaign mode.
    pub campaign_mode: ServiceMode,
    /// Declares the component authorities.
    #[serde(borrow)]
    pub component_authorities: InstalledInput<'input>,
    /// Declares the sqlite bootstrap bytes.
    pub sqlite_bootstrap_bytes: u64,
    /// Declares the sqlite heap bytes.
    pub sqlite_heap_bytes: u64,
    /// Declares the sqlite connections.
    pub sqlite_connections: usize,
    /// Declares the actor main stack bytes.
    pub actor_main_stack_bytes: u64,
    /// Declares the sqlite bootstrap proof.
    #[serde(borrow)]
    pub sqlite_bootstrap_proof: InstalledInput<'input>,
    /// Declares the campaign policy.
    #[serde(borrow)]
    pub campaign_policy: InstalledInput<'input>,
    /// Declares the campaign policy projection.
    #[serde(borrow)]
    pub campaign_policy_projection: InstalledInput<'input>,
    /// Declares the registry.
    pub registry: ResourceVector,
    /// Declares the registry project id.
    pub registry_project_id: u32,
    /// Declares the catalog project id.
    pub catalog_project_id: u32,
    /// Declares the registry maximum inodes.
    pub registry_maximum_inodes: u64,
}

/// Deserializes the closed InstalledInput wire object.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledInput<'input> {
    /// Declares the path.
    #[serde(borrow)]
    pub path: &'input str,
    /// Declares the blake3.
    #[serde(borrow)]
    pub blake3: &'input str,
}

/// Deserializes the closed ResourceVector wire object.
#[derive(Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceVector {
    /// Declares the resident peak bytes.
    pub resident_peak_bytes: u64,
    /// Declares the backing peak bytes.
    pub backing_peak_bytes: u64,
    /// Declares the metadata bytes.
    pub metadata_bytes: u64,
    /// Declares the staging bytes.
    pub staging_bytes: u64,
    /// Declares the paging io slots.
    pub paging_io_slots: u64,
    /// Declares the cpu slots.
    pub cpu_slots: u64,
    /// Declares the task slots.
    pub task_slots: u64,
    /// Declares the file descriptors.
    pub file_descriptors: u64,
}

/// Deserializes the closed Aggregate wire object.
#[derive(PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Aggregate {
    /// Declares the native slots.
    pub native_slots: u64,
    /// Declares the cpu slots.
    pub cpu_slots: u64,
    /// Declares the resident bytes.
    pub resident_bytes: u64,
    /// Declares the backing bytes.
    pub backing_bytes: u64,
    /// Declares the metadata bytes.
    pub metadata_bytes: u64,
    /// Declares the staging bytes.
    pub staging_bytes: u64,
    /// Declares the task slots.
    pub task_slots: u64,
    /// Declares the file descriptors.
    pub file_descriptors: u64,
    /// Declares the paging io slots.
    pub paging_io_slots: u64,
    /// Declares the dirty units.
    pub dirty_units: u64,
}

/// Deserializes the closed GuestAssets wire object.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GuestAssets {
    /// Declares the architecture.
    pub architecture: String,
    /// Declares the boot mode.
    pub boot_mode: String,
    /// Declares the kernel.
    pub kernel: GuestArtifact,
    /// Declares the root image.
    pub root_image: GuestArtifact,
    /// Declares the initrd.
    pub initrd: Option<GuestArtifact>,
    /// Declares the root image format.
    #[serde(rename = "rootImageFormat")]
    pub _root_image_format: RootImageFormat,
    /// Declares the kernel cmdline.
    pub kernel_cmdline: String,
}

/// Deserializes the closed GuestArtifact wire object.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GuestArtifact {
    /// Declares the path.
    pub path: String,
    /// Declares the bytes.
    pub bytes: u64,
    /// Declares the blake3.
    pub blake3: String,
}

/// Deserializes the closed RootImageFormat wire object.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RootImageFormat {
    /// Selects the raw representation.
    Raw,
    /// Selects the qcow2 representation.
    Qcow2,
}

impl<'input> super::sealed::Sealed for WorkflowProjection<'input> {}

impl<'input> super::ClosedJsonProfile<'input> for WorkflowProjection<'input> {
    const DIAGNOSTIC_LABELS: &'static [&'static str] = &[
        "struct ServiceServer",
        "connectionWorkers",
        "pendingConnections",
        "maximumRequestsPerConnection",
        "acceptPollMillis",
        "readTimeoutMillis",
        "writeTimeoutMillis",
        "enum ServiceMode",
        "readWrite",
        "readOnly",
        "struct WorkflowProjection",
        "schema",
        "family",
        "nativeCount",
        "hotFork",
        "worldMemoryMib",
        "executionQuanta",
        "serviceProfile",
        "guestAssets",
        "qemu",
        "plugin",
        "rows",
        "struct ServiceProfile",
        "operator",
        "catalog",
        "catalogMaximumInodes",
        "native",
        "aggregate",
        "preparationSeconds",
        "invocationSeconds",
        "struct ServiceOperator",
        "executor",
        "campaignServer",
        "campaignMode",
        "componentAuthorities",
        "sqliteBootstrapBytes",
        "sqliteHeapBytes",
        "sqliteConnections",
        "actorMainStackBytes",
        "sqliteBootstrapProof",
        "campaignPolicy",
        "campaignPolicyProjection",
        "registry",
        "registryProjectId",
        "catalogProjectId",
        "registryMaximumInodes",
        "struct InstalledInput",
        "path",
        "blake3",
        "struct ResourceVector",
        "residentPeakBytes",
        "backingPeakBytes",
        "metadataBytes",
        "stagingBytes",
        "pagingIoSlots",
        "cpuSlots",
        "taskSlots",
        "fileDescriptors",
        "struct Aggregate",
        "nativeSlots",
        "cpuSlots",
        "residentBytes",
        "backingBytes",
        "metadataBytes",
        "stagingBytes",
        "taskSlots",
        "fileDescriptors",
        "pagingIoSlots",
        "dirtyUnits",
        "struct GuestAssets",
        "architecture",
        "bootMode",
        "kernel",
        "rootImage",
        "initrd",
        "rootImageFormat",
        "kernelCmdline",
        "struct GuestArtifact",
        "path",
        "bytes",
        "blake3",
        "struct CampaignExecution",
        "enum CampaignExecutionPlanner",
        "enum CampaignExecutionSearch",
        "struct CampaignExecutionPlanningBudget",
        "enum CampaignExecutionRetention",
        "struct CampaignExecutionGrant",
        "campaignExecution",
        "planner",
        "planningBudget",
        "plannerScanLimit",
        "executorScanLimit",
        "retention",
        "grant",
        "search",
        "exhaustive",
        "treeSearch",
        "beam",
        "breadthFirst",
        "depthFirst",
        "priority",
        "seed",
        "branchRequests",
        "proposals",
        "inputObjects",
        "inputBytes",
        "fuel",
        "attempts",
        "discard",
        "retainOnFailure",
        "retainAlways",
        "an array of length 32",
        "struct ExecutorDeployment",
        "struct ExecutorEndpoint",
        "struct ExecutorCapacity",
        "struct ExecutorHostOperationalCapacity",
        "enum ExecutorHostArchitecture",
        "struct ExecutorHost",
        "struct ExecutorAssignmentLimits",
        "struct ExecutorOperationBudgets",
        "struct ExecutorOperationBudget",
        "endpoint",
        "server",
        "ledgerDirectory",
        "maximumCheckpointBytes",
        "daemonEpoch",
        "storeNamespace",
        "capacity",
        "hostOperationalCapacity",
        "workerCount",
        "hostArchitecture",
        "qemuProfile",
        "host",
        "assignmentResources",
        "assignmentLimits",
        "hostOperationBudgets",
        "path",
        "ownerUserId",
        "ownerGroupId",
        "socketMode",
        "maximumConcurrentExecutions",
        "maximumVcpus",
        "maximumResidentBytes",
        "maximumDiskBytes",
        "maximumExecutionQuanta",
        "maximumPagingIoSlots",
        "maximumTaskSlots",
        "maximumFileDescriptors",
        "maximumMetadataBytes",
        "maximumStagingBytes",
        "cgroupRoot",
        "runRoot",
        "attemptNamespace",
        "firstProjectId",
        "projectIdCount",
        "childUserId",
        "childGroupId",
        "maximumTasks",
        "maximumFileDescriptors",
        "maximumNodeHostServiceTasks",
        "maximumNodeHostServiceFileDescriptors",
        "maximumNodeHostServiceResidentBytes",
        "watcherServiceResidentBytes",
        "maximumInodes",
        "finishTimeoutMillis",
        "maximumLockedBytes",
        "maximumVcpus",
        "maximumResidentBytes",
        "maximumDiskBytes",
        "maximumExecutionQuanta",
        "setup",
        "quantum",
        "pageIn",
        "writeback",
        "fingerprintInitialization",
        "fingerprintUpdate",
        "quiescence",
        "checkpointCapture",
        "checkpointPublication",
        "restore",
        "forkRearm",
        "transfer",
        "preparation",
        "cleanup",
        "pollMillis",
        "progressMillis",
        "totalMillis",
        "x86_64",
        "an array of length 16",
        "u8",
        "enum RootImageFormat",
        "raw",
        "qcow2",
    ];
}
