//! Fully typed parser grammar for the dormant RFC-0021 sandbox surface.

use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{Result, bail};
use aos_proto::aos::sandbox::v1 as wire;
use aos_sandbox::cli_model::{
    DormantClientStatePlanV1, DormantCompletionShellV1, DormantPublicApiAuthorizationV1,
    DormantSandboxRequestKindV1, DormantSandboxRequestV1, DormantSandboxTreeContinuationV1,
};
use clap::{Args, Subcommand, ValueEnum};

#[derive(Clone)]
struct HexValue(Vec<u8>);

impl HexValue {
    fn clone(&self) -> Vec<u8> {
        self.0.clone()
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn iter(&self) -> std::slice::Iter<'_, u8> {
        self.0.iter()
    }
}

#[derive(Args)]
pub struct SandboxArgs {
    /// Emit one JSON document per response record.
    #[arg(long, conflicts_with = "json")]
    pub json_lines: bool,

    /// Use the registered-client public endpoint instead of root diagnostics.
    #[arg(
        long,
        requires_all = ["public_server_name", "public_credentials"]
    )]
    pub public_api: bool,

    /// Verify the public endpoint against this DNS name or IP address.
    #[arg(long, requires = "public_api", value_name = "NAME")]
    pub public_server_name: Option<String>,

    /// Load the protected public-client credential bundle from this directory.
    #[arg(long, requires = "public_api", value_name = "DIRECTORY")]
    pub public_credentials: Option<PathBuf>,

    #[command(subcommand)]
    pub command: SandboxSubcommand,
}

#[derive(Subcommand)]
pub enum SandboxSubcommand {
    Create(CreateArgs),
    Get(GetArgs),
    List(ListArgs),
    Tree(TreeArgs),
    Children(ChildrenArgs),
    Ancestors(AncestorsArgs),
    PlanPolicy(PlanPolicyArgs),
    UpdatePolicy(UpdatePolicyArgs),
    Start(LifecycleArgs),
    Stop(LifecycleArgs),
    Suspend(LifecycleArgs),
    Resume(LifecycleArgs),
    Exec(ExecArgs),
    AttachExec(ExecutionIdArgs),
    ResizeExec(ResizeExecArgs),
    SignalExec(SignalExecArgs),
    CancelExec(CancelExecArgs),
    CancelOperation(CancelOperationArgs),
    Snapshot(SnapshotArgs),
    DeleteSnapshot(DeleteSnapshotArgs),
    Restore(RestoreArgs),
    Fork(ForkArgs),
    Delete(DeleteArgs),
    Events(EventsArgs),
    View {
        #[command(subcommand)]
        command: ViewSubcommand,
    },
    Cache {
        #[command(subcommand)]
        command: CacheSubcommand,
    },
    Capabilities {
        #[command(subcommand)]
        command: CapabilitiesSubcommand,
    },
    Capability {
        #[command(subcommand)]
        command: CapabilitySubcommand,
    },
    Completions(CompletionArgs),
    OperatorRecover(OperatorRecoveryArgs),
}

#[derive(Subcommand)]
pub enum ViewSubcommand {
    Create(CreateViewArgs),
    Attach(AttachViewArgs),
    Replace(ReplaceViewArgs),
    Detach(AttachmentMutationArgs),
    Release(ViewMutationArgs),
    List(ProjectPageArgs),
}

#[derive(Subcommand)]
pub enum CacheSubcommand {
    Status(CacheStatusArgs),
    Pin(CacheMutationArgs),
    Unpin(CacheMutationArgs),
}

#[derive(Subcommand)]
pub enum CapabilitiesSubcommand {
    PublicApi,
    Node(NodeArgs),
}

#[derive(Subcommand)]
pub enum CapabilitySubcommand {
    Attenuate(AttenuateArgs),
    Inspect(HandleArgs),
    Renew(RenewArgs),
    Revoke(RevokeArgs),
}

#[derive(Clone)]
struct DescriptorValue(wire::ObjectDescriptor);

impl FromStr for DescriptorValue {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut fields = value.splitn(3, ':');
        let media_type = fields.next().unwrap_or_default();
        let digest = fields.next().ok_or("expected MEDIA_TYPE:SHA256:SIZE")?;
        let encoded_size = fields
            .next()
            .ok_or("expected MEDIA_TYPE:SHA256:SIZE")?
            .parse::<u64>()
            .map_err(|_| "descriptor size is invalid")?;
        let sha256 = fixed_hex(digest, 32)?;
        if media_type.is_empty() || encoded_size == 0 {
            return Err("descriptor media type and size must be nonzero".into());
        }
        Ok(Self(wire::ObjectDescriptor {
            media_type: media_type.to_owned(),
            sha256: sha256.clone(),
            encoded_size,
            ..Default::default()
        }))
    }
}

#[derive(Clone)]
struct FeatureValue(wire::Feature);

impl FromStr for FeatureValue {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (namespace, version) = value
            .rsplit_once('@')
            .ok_or("expected NAMESPACE@MAJOR.MINOR")?;
        let (major, minor) = version
            .split_once('.')
            .ok_or("expected NAMESPACE@MAJOR.MINOR")?;
        if namespace.is_empty() {
            return Err("feature namespace is empty".into());
        }
        Ok(Self(wire::Feature {
            namespace: namespace.to_owned(),
            major: major.parse().map_err(|_| "feature major is invalid")?,
            minor: minor.parse().map_err(|_| "feature minor is invalid")?,
            ..Default::default()
        }))
    }
}

#[derive(Args)]
pub struct MutationArgs {
    #[arg(long, value_parser = nonempty_hex)]
    expected_resource_version: HexValue,
    #[arg(long, value_parser = identity_hex)]
    expected_incarnation: Option<HexValue>,
    #[arg(long, value_parser = nonempty_hex)]
    idempotency_key: HexValue,
    #[arg(long)]
    operation_timeout_ns: u64,
    #[arg(long = "require-feature")]
    required_features: Vec<FeatureValue>,
    /// Waits locally for at most this duration; omission returns the operation.
    #[arg(long)]
    wait_timeout_ns: Option<u64>,
}

impl MutationArgs {
    fn proto(&self) -> wire::MutationContext {
        self.proto_with_semantic_features(&[])
    }

    fn proto_with_semantic_features(&self, required: &[&str]) -> wire::MutationContext {
        wire::MutationContext {
            idempotency_key: self.idempotency_key.clone(),
            expected_resource_version: self.expected_resource_version.clone(),
            expected_incarnation_id: optional_bytes(&self.expected_incarnation),
            operation_timeout: duration(self.operation_timeout_ns).into(),
            required_features: features_with_semantics(&self.required_features, required),
            ..Default::default()
        }
    }

    fn wait_timeout_ns(&self) -> Option<u64> {
        self.wait_timeout_ns
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum GetResourceValue {
    Sandbox,
    Execution,
    View,
    Attachment,
    Snapshot,
    Operation,
}

#[derive(Args)]
pub struct GetArgs {
    #[arg(long, value_enum)]
    resource: GetResourceValue,
    #[arg(value_parser = identity_hex)]
    resource_id: HexValue,
}

#[derive(Clone, Copy, ValueEnum)]
enum ListResourceValue {
    Sandbox,
    Execution,
    Snapshot,
}

#[derive(Args)]
pub struct ListArgs {
    #[arg(long, value_enum)]
    resource: ListResourceValue,
    #[arg(long, value_parser = identity_hex)]
    project_id: Option<HexValue>,
    #[arg(long, value_parser = identity_hex)]
    sandbox_id: Option<HexValue>,
    #[arg(long, default_value_t = 100)]
    page_size: u32,
    #[arg(long, value_parser = nonempty_hex)]
    page_token: Option<HexValue>,
    #[arg(long, default_value_t = 4_096)]
    maximum_pages: u16,
}

#[derive(Args)]
pub struct ExecutionIdArgs {
    #[arg(value_parser = identity_hex)]
    execution_id: HexValue,
    #[arg(long, value_parser = nonempty_hex)]
    client_public_key: HexValue,
    #[arg(long, value_parser = nonempty_hex)]
    proof_of_possession: HexValue,
    #[command(flatten)]
    mutation: MutationArgs,
}

#[derive(Args)]
pub struct ProjectPageArgs {
    #[arg(long, value_parser = identity_hex)]
    project_id: HexValue,
    #[arg(long, default_value_t = 100)]
    page_size: u32,
    #[arg(long, value_parser = nonempty_hex)]
    page_token: Option<HexValue>,
    #[arg(long, default_value_t = 4_096)]
    maximum_pages: u16,
}

#[derive(Args)]
pub struct TreeArgs {
    #[arg(value_parser = identity_hex)]
    sandbox_id: HexValue,
    #[arg(long)]
    maximum_depth: u32,
    #[arg(long, default_value_t = 100)]
    page_size: u32,
    /// Resume from a CLI token carrying the authenticated server cursor and preorder state.
    #[arg(long, value_parser = nonempty_hex)]
    page_token: Option<HexValue>,
    #[arg(long, default_value_t = 4_096)]
    maximum_pages: u16,
}

#[derive(Args)]
pub struct ChildrenArgs {
    #[arg(value_parser = identity_hex)]
    parent_sandbox_id: HexValue,
    #[arg(long, default_value_t = 100)]
    page_size: u32,
    #[arg(long, value_parser = nonempty_hex)]
    page_token: Option<HexValue>,
    #[arg(long, default_value_t = 4_096)]
    maximum_pages: u16,
}

#[derive(Args)]
pub struct AncestorsArgs {
    #[arg(value_parser = identity_hex)]
    sandbox_id: HexValue,
    #[arg(long)]
    bounded_depth: u32,
    #[arg(long, default_value_t = 100)]
    page_size: u32,
    #[arg(long, value_parser = nonempty_hex)]
    page_token: Option<HexValue>,
    #[arg(long, default_value_t = 4_096)]
    maximum_pages: u16,
}

#[derive(Args)]
pub struct CreateArgs {
    /// Resolves and validates creation without submitting a mutation.
    #[arg(long)]
    dry_run: bool,
    #[arg(long, value_parser = identity_hex)]
    project_id: HexValue,
    #[arg(long, value_parser = identity_hex, requires = "expected_parent_resource_version")]
    parent_sandbox_id: Option<HexValue>,
    #[arg(long, value_parser = nonempty_hex, requires = "parent_sandbox_id")]
    expected_parent_resource_version: Option<HexValue>,
    #[arg(long, value_parser = nonempty_hex)]
    expected_project_resource_version: HexValue,
    #[arg(long)]
    specification: DescriptorValue,
    #[arg(long)]
    requested_policy: DescriptorValue,
    #[arg(long, value_parser = nonempty_hex)]
    idempotency_key: Option<HexValue>,
    #[arg(long)]
    operation_timeout_ns: Option<u64>,
    #[arg(long)]
    wait_timeout_ns: Option<u64>,
    #[arg(long = "require-feature")]
    required_features: Vec<FeatureValue>,
}

#[derive(Args)]
pub struct PlanPolicyArgs {
    #[arg(value_parser = identity_hex)]
    sandbox_id: HexValue,
    #[arg(long, value_parser = nonempty_hex)]
    expected_resource_version: HexValue,
    #[arg(long)]
    requested_policy: DescriptorValue,
}

#[derive(Args)]
pub struct UpdatePolicyArgs {
    #[arg(value_parser = identity_hex)]
    sandbox_id: HexValue,
    #[arg(long)]
    requested_policy: DescriptorValue,
    #[arg(long, value_parser = digest_hex)]
    expected_plan_digest: HexValue,
    #[command(flatten)]
    mutation: MutationArgs,
}

#[derive(Args)]
pub struct LifecycleArgs {
    #[arg(value_parser = identity_hex)]
    sandbox_id: HexValue,
    #[command(flatten)]
    mutation: MutationArgs,
}

#[derive(Clone, Copy, ValueEnum)]
enum IoMode {
    Stream,
    Pty,
    Detached,
}

#[derive(Args)]
pub struct ExecArgs {
    #[arg(value_parser = identity_hex)]
    sandbox_id: HexValue,
    #[command(flatten)]
    mutation: MutationArgs,
    #[arg(long)]
    shell: Option<String>,
    #[arg(long = "env", value_parser = environment)]
    environment: Vec<(String, Vec<u8>)>,
    #[arg(long)]
    working_directory: Option<String>,
    #[arg(long)]
    execution_timeout_ns: u64,
    #[arg(long, value_enum)]
    io: IoMode,
    #[arg(long, requires = "io")]
    terminal_rows: Option<u32>,
    #[arg(long, requires = "io")]
    terminal_columns: Option<u32>,
    #[arg(long, requires = "io")]
    detached_capture_bytes: Option<u64>,
    #[arg(long, requires = "io")]
    maximum_stdout_bytes: Option<u64>,
    #[arg(long, requires = "io")]
    maximum_stderr_bytes: Option<u64>,
    #[arg(long = "stream-feature")]
    stream_features: Vec<FeatureValue>,
    #[arg(long, value_parser = nonempty_hex)]
    client_public_key: HexValue,
    #[arg(long, value_parser = nonempty_hex)]
    proof_of_possession: HexValue,
    #[arg(num_args = 1.., trailing_var_arg = true, conflicts_with = "shell")]
    program: Vec<String>,
}

#[derive(Args)]
pub struct ResizeExecArgs {
    #[arg(value_parser = identity_hex)]
    execution_id: HexValue,
    #[arg(long)]
    rows: u32,
    #[arg(long)]
    columns: u32,
    #[command(flatten)]
    mutation: MutationArgs,
}

#[derive(Clone, Copy, ValueEnum)]
enum SignalValue {
    Hangup,
    Interrupt,
    Quit,
    Terminate,
    Kill,
    User1,
    User2,
}

#[derive(Args)]
pub struct SignalExecArgs {
    #[arg(value_parser = identity_hex)]
    execution_id: HexValue,
    #[arg(long, value_enum)]
    signal: SignalValue,
    #[command(flatten)]
    mutation: MutationArgs,
}

#[derive(Args)]
pub struct CancelExecArgs {
    #[arg(value_parser = identity_hex)]
    execution_id: HexValue,
    #[command(flatten)]
    mutation: MutationArgs,
}

#[derive(Args)]
pub struct CancelOperationArgs {
    #[arg(value_parser = identity_hex)]
    operation_id: HexValue,
    #[command(flatten)]
    mutation: MutationArgs,
}

#[derive(Clone, Copy, ValueEnum)]
enum SnapshotAvailabilityValue {
    SelfContained,
    ExternalDependencies,
}

#[derive(Args)]
pub struct SnapshotArgs {
    #[arg(value_parser = identity_hex)]
    sandbox_id: HexValue,
    #[arg(long, value_enum)]
    availability: SnapshotAvailabilityValue,
    #[command(flatten)]
    mutation: MutationArgs,
}

#[derive(Args)]
pub struct DeleteSnapshotArgs {
    #[arg(value_parser = identity_hex)]
    snapshot_id: HexValue,
    #[command(flatten)]
    mutation: MutationArgs,
}

#[derive(Args)]
pub struct RestoreArgs {
    #[arg(value_parser = identity_hex)]
    snapshot_id: HexValue,
    #[arg(long, value_parser = identity_hex)]
    target_sandbox_id: HexValue,
    #[arg(long)]
    requested_policy: DescriptorValue,
    #[command(flatten)]
    mutation: MutationArgs,
}

#[derive(Args)]
pub struct ForkArgs {
    #[arg(value_parser = identity_hex)]
    snapshot_id: HexValue,
    #[arg(long, value_parser = identity_hex)]
    target_project_id: HexValue,
    #[arg(long, value_parser = nonempty_hex)]
    expected_project_resource_version: HexValue,
    #[arg(long, value_parser = identity_hex, requires = "expected_parent_resource_version")]
    parent_sandbox_id: Option<HexValue>,
    #[arg(long, value_parser = nonempty_hex, requires = "parent_sandbox_id")]
    expected_parent_resource_version: Option<HexValue>,
    #[arg(long)]
    requested_policy: DescriptorValue,
    #[arg(long, value_parser = nonempty_hex)]
    idempotency_key: HexValue,
    #[arg(long)]
    operation_timeout_ns: u64,
    #[arg(long)]
    wait_timeout_ns: Option<u64>,
    #[arg(long = "require-feature")]
    required_features: Vec<FeatureValue>,
}

#[derive(Args)]
pub struct DeleteArgs {
    #[arg(value_parser = identity_hex)]
    sandbox_id: HexValue,
    #[arg(long)]
    cascade: bool,
    #[arg(long)]
    force: bool,
    #[arg(long, value_parser = digest_hex)]
    expected_plan_digest: HexValue,
    #[command(flatten)]
    mutation: MutationArgs,
}

#[derive(Args)]
pub struct EventsArgs {
    #[arg(long, value_parser = identity_hex)]
    project_id: HexValue,
    #[arg(long = "resource-type", required = true)]
    resource_types: Vec<String>,
    #[arg(long, value_parser = identity_hex)]
    resource_id: Option<HexValue>,
    #[arg(long, value_parser = nonempty_hex)]
    resume_after: Option<HexValue>,
    #[arg(long = "observation-feature")]
    observation_features: Vec<FeatureValue>,
    #[arg(long)]
    audit_only: bool,
    #[arg(long, default_value_t = 65_536)]
    maximum_events: u32,
}

#[derive(Args)]
pub struct CreateViewArgs {
    #[arg(long, value_parser = identity_hex)]
    project_id: HexValue,
    #[arg(long)]
    revision: DescriptorValue,
    #[arg(long, value_parser = nonempty_hex)]
    expected_project_resource_version: HexValue,
    #[arg(long, value_parser = nonempty_hex)]
    idempotency_key: HexValue,
    #[arg(long)]
    operation_timeout_ns: u64,
    #[arg(long)]
    wait_timeout_ns: Option<u64>,
    #[arg(long = "require-feature")]
    required_features: Vec<FeatureValue>,
}

#[derive(Clone, Copy, ValueEnum)]
enum ViewModeValue {
    ReadOnly,
    ReadWrite,
    PrivateCow,
    AppendOnly,
    Service,
}

#[derive(Args)]
pub struct AttachViewArgs {
    #[arg(long, value_parser = identity_hex)]
    sandbox_id: HexValue,
    #[arg(long, value_parser = identity_hex)]
    view_id: HexValue,
    #[arg(long)]
    view_revision: DescriptorValue,
    #[arg(long, value_parser = identity_hex)]
    destination_slot_id: HexValue,
    #[arg(long, value_enum)]
    mode: ViewModeValue,
    #[arg(long)]
    noexec: bool,
    #[command(flatten)]
    mutation: MutationArgs,
}

#[derive(Args)]
pub struct ReplaceViewArgs {
    #[arg(long, value_parser = identity_hex)]
    attachment_id: HexValue,
    #[arg(long, value_parser = identity_hex)]
    new_view_id: HexValue,
    #[arg(long)]
    new_view_revision: DescriptorValue,
    #[command(flatten)]
    mutation: MutationArgs,
}

#[derive(Args)]
pub struct AttachmentMutationArgs {
    #[arg(value_parser = identity_hex)]
    attachment_id: HexValue,
    #[command(flatten)]
    mutation: MutationArgs,
}

#[derive(Args)]
pub struct ViewMutationArgs {
    #[arg(value_parser = identity_hex)]
    view_id: HexValue,
    #[command(flatten)]
    mutation: MutationArgs,
}

#[derive(Args)]
pub struct CacheStatusArgs {
    #[arg(long, value_parser = identity_hex)]
    project_id: Option<HexValue>,
    #[arg(long, value_parser = identity_hex)]
    sandbox_id: Option<HexValue>,
}

#[derive(Args)]
pub struct CacheMutationArgs {
    #[arg(long)]
    object: DescriptorValue,
    /// Identify the view holding this cache dependency.
    #[arg(long, value_parser = identity_hex)]
    view_id: HexValue,
    /// Identify the attachment when the dependency has an attached consumer.
    #[arg(long, value_parser = identity_hex)]
    attachment_id: Option<HexValue>,
    #[command(flatten)]
    mutation: MutationArgs,
}

#[derive(Args)]
pub struct NodeArgs {
    #[arg(value_parser = identity_hex)]
    node_id: HexValue,
}

#[derive(Args)]
pub struct AttenuateArgs {
    #[arg(long, value_parser = nonempty_hex)]
    parent_capability_handle: HexValue,
    #[arg(long, value_parser = nonempty_hex)]
    attenuation: HexValue,
    #[arg(long, value_parser = digest_hex)]
    holder_channel_binding: HexValue,
    #[arg(long, value_parser = nonempty_hex)]
    expected_parent_resource_version: HexValue,
    #[arg(long, value_parser = nonempty_hex)]
    idempotency_key: HexValue,
}

#[derive(Args)]
pub struct HandleArgs {
    #[arg(value_parser = nonempty_hex)]
    capability_handle: HexValue,
}

#[derive(Args)]
pub struct RenewArgs {
    #[arg(long, value_parser = nonempty_hex)]
    capability_handle: HexValue,
    #[arg(long)]
    expiry_seconds: i64,
    #[arg(long, default_value_t = 0)]
    expiry_nanoseconds: u32,
    #[command(flatten)]
    mutation: MutationArgs,
}

#[derive(Args)]
pub struct RevokeArgs {
    #[arg(value_parser = identity_hex)]
    capability_id: HexValue,
    #[command(flatten)]
    mutation: MutationArgs,
}

#[derive(Clone, Copy, ValueEnum)]
enum CompletionShellValue {
    Bash,
    Fish,
    Zsh,
}

#[derive(Args)]
pub struct CompletionArgs {
    #[arg(value_enum)]
    shell: CompletionShellValue,
}

#[derive(Clone, Copy, ValueEnum)]
enum RecoveryActionValue {
    Retry,
    Abandon,
    Reconcile,
    Repair,
}

#[derive(Args)]
pub struct OperatorRecoveryArgs {
    #[arg(long, value_parser = identity_hex)]
    resource_id: HexValue,
    #[arg(long, value_parser = nonempty_hex)]
    expected_resource_version: HexValue,
    #[arg(long, value_enum)]
    action: RecoveryActionValue,
    #[arg(long, value_parser = nonempty_hex)]
    idempotency_key: HexValue,
    #[arg(long)]
    evidence: DescriptorValue,
    /// Waits locally for at most this duration; omission returns the operation.
    #[arg(long)]
    wait_timeout_ns: Option<u64>,
}

impl SandboxSubcommand {
    fn request(&self) -> Result<DormantSandboxRequestKindV1> {
        use DormantSandboxRequestKindV1 as K;

        Ok(match self {
            Self::Create(a) if a.dry_run => {
                if a.idempotency_key.is_some()
                    || a.operation_timeout_ns.is_some()
                    || a.wait_timeout_ns.is_some()
                {
                    bail!("--dry-run rejects idempotency, operation-timeout, and wait options");
                }
                K::PlanCreate(wire::PlanCreateSandboxRequest {
                    project_id: a.project_id.clone(),
                    parent_sandbox_id: optional_bytes(&a.parent_sandbox_id),
                    expected_parent_resource_version: optional_bytes(
                        &a.expected_parent_resource_version,
                    ),
                    expected_project_resource_version: a.expected_project_resource_version.clone(),
                    specification: a.specification.0.clone().into(),
                    requested_policy: a.requested_policy.0.clone().into(),
                    required_features: features(&a.required_features),
                    ..Default::default()
                })
            }
            Self::Create(a) => K::Create(wire::CreateSandboxRequest {
                project_id: a.project_id.clone(),
                parent_sandbox_id: optional_bytes(&a.parent_sandbox_id),
                expected_parent_resource_version: optional_bytes(
                    &a.expected_parent_resource_version,
                ),
                expected_project_resource_version: a.expected_project_resource_version.clone(),
                specification: a.specification.0.clone().into(),
                requested_policy: a.requested_policy.0.clone().into(),
                idempotency_key: required_value(&a.idempotency_key, "idempotency-key")?,
                operation_timeout: duration(required_scalar(
                    a.operation_timeout_ns,
                    "operation-timeout-ns",
                )?)
                .into(),
                required_features: features(&a.required_features),
                ..Default::default()
            }),
            Self::Get(a) => match a.resource {
                GetResourceValue::Sandbox => K::GetSandbox(wire::GetSandboxRequest {
                    sandbox_id: a.resource_id.clone(),
                    ..Default::default()
                }),
                GetResourceValue::Execution => K::GetExecution(wire::GetExecutionRequest {
                    execution_id: a.resource_id.clone(),
                    ..Default::default()
                }),
                GetResourceValue::View => K::GetView(wire::GetViewRequest {
                    view_id: a.resource_id.clone(),
                    ..Default::default()
                }),
                GetResourceValue::Attachment => K::GetAttachment(wire::GetAttachmentRequest {
                    attachment_id: a.resource_id.clone(),
                    ..Default::default()
                }),
                GetResourceValue::Snapshot => K::GetSnapshot(wire::GetSnapshotRequest {
                    snapshot_id: a.resource_id.clone(),
                    ..Default::default()
                }),
                GetResourceValue::Operation => K::GetOperation(wire::GetOperationRequest {
                    operation_id: a.resource_id.clone(),
                    ..Default::default()
                }),
            },
            Self::List(a) => match a.resource {
                ListResourceValue::Sandbox => K::ListSandboxes(wire::ListSandboxesRequest {
                    project_id: required_id(&a.project_id, "project")?,
                    page_size: a.page_size,
                    page_token: optional_bytes(&a.page_token),
                    ..Default::default()
                }),
                ListResourceValue::Execution => K::ListExecutions(wire::ListExecutionsRequest {
                    sandbox_id: required_id(&a.sandbox_id, "sandbox")?,
                    page_size: a.page_size,
                    page_token: optional_bytes(&a.page_token),
                    ..Default::default()
                }),
                ListResourceValue::Snapshot => K::ListSnapshots(wire::ListSnapshotsRequest {
                    project_id: optional_bytes(&a.project_id),
                    sandbox_id: optional_bytes(&a.sandbox_id),
                    page_size: a.page_size,
                    page_token: optional_bytes(&a.page_token),
                    ..Default::default()
                }),
            },
            Self::Tree(a) => K::Tree(tree_request(a)?),
            Self::Children(a) => K::Children(wire::ListChildrenRequest {
                parent_sandbox_id: a.parent_sandbox_id.clone(),
                page_size: a.page_size,
                page_token: optional_bytes(&a.page_token),
                ..Default::default()
            }),
            Self::Ancestors(a) => K::Ancestors(wire::ListAncestorsRequest {
                sandbox_id: a.sandbox_id.clone(),
                bounded_depth: a.bounded_depth,
                page_size: a.page_size,
                page_token: optional_bytes(&a.page_token),
                ..Default::default()
            }),
            Self::PlanPolicy(a) => K::PlanPolicy(wire::PlanSandboxPolicyRequest {
                sandbox_id: a.sandbox_id.clone(),
                expected_resource_version: a.expected_resource_version.clone(),
                requested_policy: a.requested_policy.0.clone().into(),
                ..Default::default()
            }),
            Self::UpdatePolicy(a) => K::UpdatePolicy(wire::UpdateSandboxPolicyRequest {
                sandbox_id: a.sandbox_id.clone(),
                requested_policy: a.requested_policy.0.clone().into(),
                expected_plan_digest: a.expected_plan_digest.clone(),
                mutation: a.mutation.proto().into(),
                ..Default::default()
            }),
            Self::Start(a) => K::Start(lifecycle(a)),
            Self::Stop(a) => K::Stop(lifecycle(a)),
            Self::Suspend(a) => K::Suspend(lifecycle(a)),
            Self::Resume(a) => K::Resume(lifecycle(a)),
            Self::Exec(a) => K::Exec(exec(a)?),
            Self::AttachExec(a) => K::ExecutionControl(execution_control(a, 1)),
            Self::ResizeExec(a) => K::ExecutionControl(wire::ExecutionControlRequest {
                execution_id: a.execution_id.clone(),
                action: 2.into(),
                terminal_rows: a.rows,
                terminal_columns: a.columns,
                mutation: a.mutation.proto().into(),
                ..Default::default()
            }),
            Self::SignalExec(a) => K::ExecutionControl(wire::ExecutionControlRequest {
                execution_id: a.execution_id.clone(),
                action: 3.into(),
                signal: signal(a.signal).into(),
                mutation: a.mutation.proto().into(),
                ..Default::default()
            }),
            Self::CancelExec(a) => K::CancelExec(wire::CancelExecutionRequest {
                execution_id: a.execution_id.clone(),
                mutation: a.mutation.proto().into(),
                ..Default::default()
            }),
            Self::CancelOperation(a) => K::CancelOperation(wire::CancelOperationRequest {
                operation_id: a.operation_id.clone(),
                mutation: a.mutation.proto().into(),
                ..Default::default()
            }),
            Self::Snapshot(a) => K::Snapshot(wire::CreateSnapshotRequest {
                sandbox_id: a.sandbox_id.clone(),
                requested_availability: (match a.availability {
                    SnapshotAvailabilityValue::SelfContained => 1,
                    SnapshotAvailabilityValue::ExternalDependencies => 2,
                })
                .into(),
                mutation: a.mutation.proto().into(),
                ..Default::default()
            }),
            Self::DeleteSnapshot(a) => K::DeleteSnapshot(wire::DeleteSnapshotRequest {
                snapshot_id: a.snapshot_id.clone(),
                mutation: a.mutation.proto().into(),
                ..Default::default()
            }),
            Self::Restore(a) => K::Restore(wire::RestoreSnapshotRequest {
                snapshot_id: a.snapshot_id.clone(),
                target_sandbox_id: a.target_sandbox_id.clone(),
                requested_policy: a.requested_policy.0.clone().into(),
                mutation: a.mutation.proto().into(),
                ..Default::default()
            }),
            Self::Fork(a) => K::Fork(wire::ForkSnapshotRequest {
                snapshot_id: a.snapshot_id.clone(),
                target_project_id: a.target_project_id.clone(),
                parent_sandbox_id: optional_bytes(&a.parent_sandbox_id),
                expected_parent_resource_version: optional_bytes(
                    &a.expected_parent_resource_version,
                ),
                requested_policy: a.requested_policy.0.clone().into(),
                idempotency_key: a.idempotency_key.clone(),
                required_features: features_with_semantics(
                    &a.required_features,
                    &[aos_sandbox::controller_query::SNAPSHOT_PROJECT_VERSION_FENCE_FEATURE_V1],
                ),
                expected_project_resource_version: a.expected_project_resource_version.clone(),
                operation_timeout: duration(a.operation_timeout_ns).into(),
                ..Default::default()
            }),
            Self::Delete(a) => K::Delete(wire::DeleteSandboxRequest {
                sandbox_id: a.sandbox_id.clone(),
                cascade: a.cascade,
                expected_plan_digest: a.expected_plan_digest.clone(),
                mutation: a
                    .mutation
                    .proto_with_semantic_features(if a.force {
                        &[aos_sandbox::controller_query::FORCE_DELETE_FEATURE_V1]
                    } else {
                        &[]
                    })
                    .into(),
                force: a.force,
                ..Default::default()
            }),
            Self::Events(a) => K::Events(wire::WatchRequest {
                project_id: a.project_id.clone(),
                resource_types: a.resource_types.clone(),
                resource_id: optional_bytes(&a.resource_id),
                resume_after: a
                    .resume_after
                    .as_ref()
                    .map(|cursor| wire::WatchCursor {
                        opaque_cursor: cursor.clone(),
                        ..Default::default()
                    })
                    .into(),
                observation_features: features(&a.observation_features),
                audit_only: a.audit_only,
                ..Default::default()
            }),
            Self::View { command } => command.request(),
            Self::Cache { command } => command.request(),
            Self::Capabilities { command } => command.request(),
            Self::Capability { command } => command.request(),
            Self::Completions(a) => K::Completions(match a.shell {
                CompletionShellValue::Bash => DormantCompletionShellV1::Bash,
                CompletionShellValue::Fish => DormantCompletionShellV1::Fish,
                CompletionShellValue::Zsh => DormantCompletionShellV1::Zsh,
            }),
            Self::OperatorRecover(a) => K::OperatorRecover(wire::OperatorRecoveryRequest {
                resource_id: a.resource_id.clone(),
                expected_resource_version: a.expected_resource_version.clone(),
                action: (match a.action {
                    RecoveryActionValue::Retry => 1,
                    RecoveryActionValue::Abandon => 2,
                    RecoveryActionValue::Reconcile => 3,
                    RecoveryActionValue::Repair => 4,
                })
                .into(),
                idempotency_key: a.idempotency_key.clone(),
                evidence: a.evidence.0.clone().into(),
                ..Default::default()
            }),
        })
    }

    fn wait_timeout_ns(&self) -> Option<u64> {
        match self {
            Self::Create(a) if !a.dry_run => a.wait_timeout_ns,
            Self::UpdatePolicy(a) => a.mutation.wait_timeout_ns(),
            Self::Start(a) | Self::Stop(a) | Self::Suspend(a) | Self::Resume(a) => {
                a.mutation.wait_timeout_ns()
            }
            Self::Exec(a) => a.mutation.wait_timeout_ns(),
            Self::AttachExec(a) => a.mutation.wait_timeout_ns(),
            Self::ResizeExec(a) => a.mutation.wait_timeout_ns(),
            Self::SignalExec(a) => a.mutation.wait_timeout_ns(),
            Self::CancelExec(a) => a.mutation.wait_timeout_ns(),
            Self::CancelOperation(a) => a.mutation.wait_timeout_ns(),
            Self::Snapshot(a) => a.mutation.wait_timeout_ns(),
            Self::DeleteSnapshot(a) => a.mutation.wait_timeout_ns(),
            Self::Restore(a) => a.mutation.wait_timeout_ns(),
            Self::Fork(a) => a.wait_timeout_ns,
            Self::Delete(a) => a.mutation.wait_timeout_ns(),
            Self::View { command } => command.wait_timeout_ns(),
            Self::Cache { command } => command.wait_timeout_ns(),
            Self::Capability { command } => command.wait_timeout_ns(),
            Self::OperatorRecover(a) => a.wait_timeout_ns,
            _ => None,
        }
    }

    fn client_bounds(&self) -> (u16, u32) {
        match self {
            Self::List(a) => (a.maximum_pages, 1),
            Self::Tree(a) => (a.maximum_pages, 1),
            Self::Children(a) => (a.maximum_pages, 1),
            Self::Ancestors(a) => (a.maximum_pages, 1),
            Self::Events(a) => (1, a.maximum_events),
            Self::View {
                command: ViewSubcommand::List(a),
            } => (a.maximum_pages, 1),
            _ => (1, 1),
        }
    }
}

impl ViewSubcommand {
    fn wait_timeout_ns(&self) -> Option<u64> {
        match self {
            Self::Attach(a) => a.mutation.wait_timeout_ns(),
            Self::Replace(a) => a.mutation.wait_timeout_ns(),
            Self::Detach(a) => a.mutation.wait_timeout_ns(),
            Self::Release(a) => a.mutation.wait_timeout_ns(),
            Self::Create(a) => a.wait_timeout_ns,
            Self::List(_) => None,
        }
    }
}

impl CacheSubcommand {
    fn wait_timeout_ns(&self) -> Option<u64> {
        match self {
            Self::Pin(a) | Self::Unpin(a) => a.mutation.wait_timeout_ns(),
            Self::Status(_) => None,
        }
    }
}

impl CapabilitySubcommand {
    fn wait_timeout_ns(&self) -> Option<u64> {
        match self {
            Self::Renew(a) => a.mutation.wait_timeout_ns(),
            Self::Revoke(a) => a.mutation.wait_timeout_ns(),
            Self::Attenuate(_) | Self::Inspect(_) => None,
        }
    }
}

impl ViewSubcommand {
    fn request(&self) -> DormantSandboxRequestKindV1 {
        use DormantSandboxRequestKindV1 as K;
        match self {
            Self::Create(a) => K::ViewCreate(wire::CreateViewRequest {
                project_id: a.project_id.clone(),
                revision: a.revision.0.clone().into(),
                expected_project_resource_version: a.expected_project_resource_version.clone(),
                idempotency_key: a.idempotency_key.clone(),
                required_features: features(&a.required_features),
                operation_timeout: duration(a.operation_timeout_ns).into(),
                ..Default::default()
            }),
            Self::Attach(a) => K::ViewAttach(wire::AttachViewRequest {
                sandbox_id: a.sandbox_id.clone(),
                view_id: a.view_id.clone(),
                view_revision: a.view_revision.0.clone().into(),
                destination_slot_id: a.destination_slot_id.clone(),
                mutation_mode: (match a.mode {
                    ViewModeValue::ReadOnly => 1,
                    ViewModeValue::ReadWrite => 2,
                    ViewModeValue::PrivateCow => 3,
                    ViewModeValue::AppendOnly => 4,
                    ViewModeValue::Service => 5,
                })
                .into(),
                mutation: a
                    .mutation
                    .proto_with_semantic_features(if a.noexec {
                        &[aos_sandbox::controller_query::ATTACHMENT_NOEXEC_FEATURE_V1]
                    } else {
                        &[]
                    })
                    .into(),
                noexec: a.noexec,
                ..Default::default()
            }),
            Self::Replace(a) => K::ViewReplace(wire::ReplaceAttachmentRequest {
                attachment_id: a.attachment_id.clone(),
                new_view_id: a.new_view_id.clone(),
                new_view_revision: a.new_view_revision.0.clone().into(),
                mutation: a.mutation.proto().into(),
                ..Default::default()
            }),
            Self::Detach(a) => K::ViewDetach(wire::DetachViewRequest {
                attachment_id: a.attachment_id.clone(),
                mutation: a.mutation.proto().into(),
                ..Default::default()
            }),
            Self::Release(a) => K::ViewRelease(wire::ReleaseViewRequest {
                view_id: a.view_id.clone(),
                mutation: a.mutation.proto().into(),
                ..Default::default()
            }),
            Self::List(a) => K::ViewList(wire::ListViewsRequest {
                project_id: a.project_id.clone(),
                page_size: a.page_size,
                page_token: optional_bytes(&a.page_token),
                ..Default::default()
            }),
        }
    }
}

impl CacheSubcommand {
    fn request(&self) -> DormantSandboxRequestKindV1 {
        use DormantSandboxRequestKindV1 as K;
        match self {
            Self::Status(a) => K::CacheStatus(wire::GetCacheStatusRequest {
                project_id: optional_bytes(&a.project_id),
                sandbox_id: optional_bytes(&a.sandbox_id),
                ..Default::default()
            }),
            Self::Pin(a) => K::CachePin(wire::PinCacheObjectRequest {
                object: a.object.0.clone().into(),
                mutation: a
                    .mutation
                    .proto_with_semantic_features(&[
                        aos_sandbox::controller_query::CACHE_CONSUMER_PIN_FEATURE_V1,
                    ])
                    .into(),
                view_id: a.view_id.clone(),
                attachment_id: optional_bytes(&a.attachment_id),
                ..Default::default()
            }),
            Self::Unpin(a) => K::CacheUnpin(wire::UnpinCacheObjectRequest {
                object: a.object.0.clone().into(),
                mutation: a
                    .mutation
                    .proto_with_semantic_features(&[
                        aos_sandbox::controller_query::CACHE_CONSUMER_PIN_FEATURE_V1,
                    ])
                    .into(),
                view_id: a.view_id.clone(),
                attachment_id: optional_bytes(&a.attachment_id),
                ..Default::default()
            }),
        }
    }
}

impl CapabilitiesSubcommand {
    fn request(&self) -> DormantSandboxRequestKindV1 {
        match self {
            Self::PublicApi => DormantSandboxRequestKindV1::CapabilitiesPublicApi(
                wire::GetPublicFeatureRegistryRequest::default(),
            ),
            Self::Node(a) => {
                DormantSandboxRequestKindV1::CapabilitiesNode(wire::GetNodeCapabilitiesRequest {
                    node_id: a.node_id.clone(),
                    ..Default::default()
                })
            }
        }
    }
}

impl CapabilitySubcommand {
    fn request(&self) -> DormantSandboxRequestKindV1 {
        use DormantSandboxRequestKindV1 as K;
        match self {
            Self::Attenuate(a) => K::CapabilityAttenuate(wire::AttenuateCapabilityRequest {
                parent_capability_handle: a.parent_capability_handle.clone(),
                attenuation: a.attenuation.clone(),
                holder_channel_binding: a.holder_channel_binding.clone(),
                idempotency_key: a.idempotency_key.clone(),
                expected_parent_resource_version: a.expected_parent_resource_version.clone(),
                ..Default::default()
            }),
            Self::Inspect(a) => K::CapabilityInspect(wire::InspectCapabilityRequest {
                capability_handle: a.capability_handle.clone(),
                ..Default::default()
            }),
            Self::Renew(a) => K::CapabilityRenew(wire::RenewCapabilityRequest {
                capability_handle: a.capability_handle.clone(),
                requested_expiry: wire::Timestamp {
                    seconds: a.expiry_seconds,
                    nanoseconds: a.expiry_nanoseconds,
                    ..Default::default()
                }
                .into(),
                mutation: a.mutation.proto().into(),
                ..Default::default()
            }),
            Self::Revoke(a) => K::CapabilityRevoke(wire::RevokeCapabilityRequest {
                capability_id: a.capability_id.clone(),
                mutation: a.mutation.proto().into(),
                ..Default::default()
            }),
        }
    }
}

fn required_id(value: &Option<HexValue>, name: &str) -> Result<Vec<u8>> {
    value
        .as_ref()
        .map(HexValue::clone)
        .ok_or_else(|| anyhow::anyhow!("--{name}-id is required for this resource kind"))
}

fn required_value(value: &Option<HexValue>, name: &str) -> Result<Vec<u8>> {
    value
        .as_ref()
        .map(HexValue::clone)
        .ok_or_else(|| anyhow::anyhow!("--{name} is required unless --dry-run is selected"))
}

fn required_scalar(value: Option<u64>, name: &str) -> Result<u64> {
    value.ok_or_else(|| anyhow::anyhow!("--{name} is required unless --dry-run is selected"))
}

fn optional_bytes(value: &Option<HexValue>) -> Vec<u8> {
    value.as_ref().map_or_else(Vec::new, HexValue::clone)
}

fn tree_request(args: &TreeArgs) -> Result<wire::ListDescendantsRequest> {
    let root: [u8; 16] = args
        .sandbox_id
        .0
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("tree root is invalid"))?;
    let continuation = args
        .page_token
        .as_ref()
        .map(|token| {
            DormantSandboxTreeContinuationV1::decode_cli_token(
                &token.0,
                root,
                args.maximum_depth,
                args.page_size,
            )
        })
        .transpose()?;

    Ok(wire::ListDescendantsRequest {
        sandbox_id: args.sandbox_id.clone(),
        maximum_depth: args.maximum_depth,
        page_size: args.page_size,
        page_token: continuation
            .as_ref()
            .map_or_else(Vec::new, |value| value.server_page_token().to_vec()),
        expected_preorder_before: continuation
            .map(|value| value.preorder_before().clone())
            .into(),
        ..Default::default()
    })
}

fn lifecycle(a: &LifecycleArgs) -> wire::SandboxLifecycleRequest {
    wire::SandboxLifecycleRequest {
        sandbox_id: a.sandbox_id.clone(),
        mutation: a.mutation.proto().into(),
        ..Default::default()
    }
}

fn execution_control(a: &ExecutionIdArgs, action: i32) -> wire::ExecutionControlRequest {
    wire::ExecutionControlRequest {
        execution_id: a.execution_id.clone(),
        action: action.into(),
        client_public_key: a.client_public_key.clone(),
        proof_of_possession: a.proof_of_possession.clone(),
        mutation: a
            .mutation
            .proto_with_semantic_features(&[
                aos_sandbox::controller_query::EXECUTION_ATTACH_HOLDER_PROOF_FEATURE_V1,
            ])
            .into(),
        ..Default::default()
    }
}

fn exec(a: &ExecArgs) -> Result<wire::CreateExecutionRequest> {
    let (arguments, sandbox_shell) = match (&a.shell, &a.program) {
        (Some(shell), program) if program.is_empty() => (Vec::new(), shell.as_bytes().to_vec()),
        (None, program) if !program.is_empty() => (
            program
                .iter()
                .map(|argument| argument.as_bytes().to_vec())
                .collect(),
            Vec::new(),
        ),
        _ => bail!("select exactly one direct program or --shell"),
    };
    let (
        io_mode,
        allocate_terminal,
        terminal_rows,
        terminal_columns,
        capture,
        maximum_stdout_bytes,
        maximum_stderr_bytes,
        io_feature,
    ) = match a.io {
        IoMode::Stream => {
            if a.terminal_rows.is_some()
                || a.terminal_columns.is_some()
                || a.detached_capture_bytes.is_some()
                || a.maximum_stdout_bytes.is_some()
                || a.maximum_stderr_bytes.is_some()
            {
                bail!("stream I/O rejects PTY dimensions and detached capture limits");
            }
            (
                1,
                false,
                0,
                0,
                0,
                None,
                None,
                aos_sandbox::controller_query::EXECUTION_STREAM_FEATURE_V1,
            )
        }
        IoMode::Pty => {
            if a.detached_capture_bytes.is_some()
                || a.maximum_stdout_bytes.is_some()
                || a.maximum_stderr_bytes.is_some()
            {
                bail!("PTY I/O rejects detached capture limits");
            }
            let rows = a
                .terminal_rows
                .ok_or_else(|| anyhow::anyhow!("PTY rows are required"))?;
            let columns = a
                .terminal_columns
                .ok_or_else(|| anyhow::anyhow!("PTY columns are required"))?;
            if rows == 0 || columns == 0 {
                bail!("PTY dimensions must be nonzero");
            }
            (
                2,
                true,
                rows,
                columns,
                0,
                None,
                None,
                aos_sandbox::controller_query::EXECUTION_PTY_FEATURE_V1,
            )
        }
        IoMode::Detached => {
            if a.terminal_rows.is_some() || a.terminal_columns.is_some() {
                bail!("detached I/O rejects PTY dimensions");
            }
            let capture = a
                .detached_capture_bytes
                .ok_or_else(|| anyhow::anyhow!("detached capture limit is required"))?;
            if capture == 0 {
                bail!("detached capture limit must be nonzero");
            }
            let stdout = a
                .maximum_stdout_bytes
                .ok_or_else(|| anyhow::anyhow!("detached maximum stdout bytes are required"))?;
            let stderr = a
                .maximum_stderr_bytes
                .ok_or_else(|| anyhow::anyhow!("detached maximum stderr bytes are required"))?;
            if stdout.checked_add(stderr) != Some(capture) {
                bail!("detached stdout and stderr ceilings must sum to the capture limit");
            }
            (
                3,
                false,
                0,
                0,
                capture,
                Some(stdout),
                Some(stderr),
                aos_sandbox::controller_query::EXECUTION_DETACHED_CAPTURE_FEATURE_V1,
            )
        }
    };
    let mut environment = a
        .environment
        .iter()
        .map(|(name, value)| wire::EnvironmentVariable {
            name: name.clone(),
            value: value.clone(),
            ..Default::default()
        })
        .collect::<Vec<_>>();
    environment.sort_by(|left, right| left.name.cmp(&right.name));
    if environment
        .windows(2)
        .any(|pair| pair[0].name == pair[1].name)
    {
        bail!("execution environment names must be unique");
    }
    let mut semantic_features = vec![
        aos_sandbox::controller_query::EXECUTION_CREATE_HOLDER_PROOF_FEATURE_V1,
        aos_sandbox::controller_query::EXECUTION_TIMEOUT_FEATURE_V1,
        io_feature,
    ];
    if !sandbox_shell.is_empty() {
        semantic_features.push(aos_sandbox::controller_query::EXECUTION_SANDBOX_SHELL_FEATURE_V1);
    }
    let mut stream_semantic_features = vec![io_feature];
    if io_mode == 3 {
        let ceiling_feature =
            aos_sandbox::controller_query::EXECUTION_DETACHED_CAPTURE_STREAM_CEILINGS_FEATURE_V1;
        semantic_features.push(ceiling_feature);
        stream_semantic_features.push(ceiling_feature);
    }

    Ok(wire::CreateExecutionRequest {
        sandbox_id: a.sandbox_id.clone(),
        command: wire::Command {
            arguments,
            environment,
            working_directory: a
                .working_directory
                .as_ref()
                .map_or_else(Vec::new, |path| path.as_bytes().to_vec()),
            allocate_terminal,
            sandbox_shell,
            execution_timeout: duration(a.execution_timeout_ns).into(),
            io_mode: io_mode.into(),
            terminal_rows,
            terminal_columns,
            detached_capture_bytes: capture,
            maximum_stdout_bytes,
            maximum_stderr_bytes,
            stream_features: features_with_semantics(&a.stream_features, &stream_semantic_features),
            ..Default::default()
        }
        .into(),
        client_public_key: a.client_public_key.clone(),
        proof_of_possession: a.proof_of_possession.clone(),
        mutation: a
            .mutation
            .proto_with_semantic_features(&semantic_features)
            .into(),
        ..Default::default()
    })
}

fn duration(nanoseconds: u64) -> wire::Duration {
    wire::Duration {
        nanoseconds,
        ..Default::default()
    }
}

fn features(values: &[FeatureValue]) -> Vec<wire::Feature> {
    features_with_semantics(values, &[])
}

fn features_with_semantics(values: &[FeatureValue], required: &[&str]) -> Vec<wire::Feature> {
    let mut features = values
        .iter()
        .map(|value| value.0.clone())
        .collect::<Vec<_>>();
    features.extend(required.iter().map(|namespace| wire::Feature {
        namespace: (*namespace).to_owned(),
        major: 1,
        minor: 0,
        ..Default::default()
    }));
    features.sort_by(|left, right| {
        (&left.namespace, left.major, left.minor).cmp(&(&right.namespace, right.major, right.minor))
    });
    features.dedup_by(|left, right| {
        (&left.namespace, left.major, left.minor) == (&right.namespace, right.major, right.minor)
    });
    features
}

fn signal(value: SignalValue) -> i32 {
    match value {
        SignalValue::Hangup => 1,
        SignalValue::Interrupt => 2,
        SignalValue::Quit => 3,
        SignalValue::Terminate => 4,
        SignalValue::Kill => 5,
        SignalValue::User1 => 6,
        SignalValue::User2 => 7,
    }
}

fn identity_hex(value: &str) -> Result<HexValue, String> {
    fixed_hex(value, 16)
}

fn digest_hex(value: &str) -> Result<HexValue, String> {
    fixed_hex(value, 32)
}

fn nonempty_hex(value: &str) -> Result<HexValue, String> {
    let decoded = hex::decode(value).map_err(|_| "value must be hexadecimal")?;
    if decoded.is_empty() || decoded.len() > 4 * 1024 {
        Err("value must contain 1..=4096 decoded bytes".into())
    } else {
        Ok(HexValue(decoded))
    }
}

fn fixed_hex(value: &str, length: usize) -> Result<HexValue, String> {
    let decoded = nonempty_hex(value)?;
    if decoded.len() != length || decoded.iter().all(|byte| *byte == 0) {
        Err(format!(
            "value must be a nonzero {length}-byte hexadecimal value"
        ))
    } else {
        Ok(decoded)
    }
}

fn environment(value: &str) -> Result<(String, Vec<u8>), String> {
    let (name, value) = value.split_once('=').ok_or("expected NAME=VALUE")?;
    if name.is_empty()
        || !name.bytes().enumerate().all(|(index, byte)| {
            byte == b'_' || byte.is_ascii_alphabetic() || (index > 0 && byte.is_ascii_digit())
        })
    {
        return Err("environment name is invalid".into());
    }
    Ok((name.to_owned(), value.as_bytes().to_vec()))
}

/// Constructs a routed request after selecting its output contract.
///
/// # Errors
///
/// Returns an error when cross-field semantics such as execution I/O or a
/// resource-specific list scope are incomplete.
pub fn routed_request(
    args: &SandboxArgs,
    output: aos_sandbox::cli_model::DormantSandboxOutputV1,
) -> Result<DormantSandboxRequestV1> {
    let (maximum_pages, maximum_events) = args.command.client_bounds();
    let client_state = DormantClientStatePlanV1::new(
        maximum_pages,
        maximum_events,
        args.command.wait_timeout_ns(),
    )?;
    Ok(DormantSandboxRequestV1::from_parsed_command(
        args.command.request()?,
        output,
        client_state,
    )?)
}

/// Constructs a routed request with explicit opaque public-transport authorization.
///
/// # Errors
///
/// Returns an error when cross-field semantics or local client bounds are invalid.
pub fn routed_request_with_authorization(
    args: &SandboxArgs,
    output: aos_sandbox::cli_model::DormantSandboxOutputV1,
    authorization: DormantPublicApiAuthorizationV1,
) -> Result<DormantSandboxRequestV1> {
    let (maximum_pages, maximum_events) = args.command.client_bounds();
    let client_state = DormantClientStatePlanV1::new(
        maximum_pages,
        maximum_events,
        args.command.wait_timeout_ns(),
    )?;
    Ok(
        DormantSandboxRequestV1::from_parsed_command_with_authorization(
            args.command.request()?,
            output,
            client_state,
            authorization,
        )?,
    )
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::cli::{Cli, Commands};
    use clap::{CommandFactory as _, Parser as _};

    #[test]
    fn rfc_primary_command_family_is_exposed() {
        let command = Cli::command();
        let sandbox = command
            .get_subcommands()
            .find(|subcommand| subcommand.get_name() == "sandbox")
            .unwrap();
        let names: Vec<_> = sandbox
            .get_subcommands()
            .map(clap::Command::get_name)
            .collect();

        for required in [
            "create",
            "get",
            "list",
            "tree",
            "children",
            "start",
            "stop",
            "suspend",
            "resume",
            "exec",
            "attach-exec",
            "cancel-exec",
            "snapshot",
            "restore",
            "fork",
            "delete",
            "events",
            "view",
            "cache",
        ] {
            assert!(names.contains(&required), "missing aos sandbox {required}");
        }

        for (group, required) in [
            (
                "view",
                &["create", "attach", "replace", "detach", "list"][..],
            ),
            ("cache", &["status", "pin", "unpin"][..]),
        ] {
            let nested = sandbox
                .get_subcommands()
                .find(|subcommand| subcommand.get_name() == group)
                .unwrap();
            let nested_names: Vec<_> = nested
                .get_subcommands()
                .map(clap::Command::get_name)
                .collect();
            for &name in required {
                assert!(
                    nested_names.contains(&name),
                    "missing aos sandbox {group} {name}"
                );
            }
        }
    }

    #[test]
    fn public_transport_options_are_complete_or_rejected() {
        let parsed = Cli::try_parse_from([
            "aos",
            "sandbox",
            "--public-api",
            "--public-server-name",
            "sandbox-controller.example",
            "--public-credentials",
            "/private/sandbox-client",
            "capabilities",
            "public-api",
        ])
        .unwrap();
        let Commands::Sandbox(arguments) = parsed.command else {
            panic!("sandbox command was not preserved");
        };
        assert!(arguments.public_api);
        assert_eq!(
            arguments.public_server_name.as_deref(),
            Some("sandbox-controller.example")
        );
        assert_eq!(
            arguments.public_credentials.as_deref(),
            Some(Path::new("/private/sandbox-client"))
        );

        assert!(
            Cli::try_parse_from([
                "aos",
                "sandbox",
                "--public-api",
                "capabilities",
                "public-api",
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "aos",
                "sandbox",
                "--public-server-name",
                "sandbox-controller.example",
                "capabilities",
                "public-api",
            ])
            .is_err()
        );
    }
}
