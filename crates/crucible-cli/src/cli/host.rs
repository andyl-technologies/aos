//! Thin authenticated host RAM and supervision CLI controls.
//!
//! Every mutation names an exact operational incarnation, expected revision,
//! and retry key. The CLI retrieves the existing policy before changing selected
//! fields and delegates admission, durable idempotency, and convergence to the
//! executor. These commands emit no guest or session commands.

use super::*;

#[path = "host/rendering.rs"]
mod rendering;
use crucible_api::host_operational::{
    HostOperationClass, HostOperationalDisposition, HostOperationalRequest,
    HostOperationalResponse, HostOperationalTarget, HostOuterCapOwner, HostOuterCapTarget,
    HostRamMode, HostRamTarget,
};
use rendering::{hex_bytes, response_json};

#[derive(Args, Debug, PartialEq, Eq)]
pub(super) struct HostArgs {
    #[command(flatten)]
    target: HostTargetArgs,
    #[command(subcommand)]
    command: HostCommand,
}

#[derive(Args, Debug, PartialEq, Eq)]
struct HostTargetArgs {
    /// Daemon incarnation from the executor's operational receipt.
    #[arg(long, value_name = "HEX64")]
    daemon_epoch: String,
    /// Execution identity, or retained-template owner identity.
    #[arg(long, value_name = "HEX64")]
    owner: String,
    /// Authenticated node identity, or retained-template identity.
    #[arg(long, value_name = "HEX64")]
    node: Option<String>,
    /// Exact current process/controller generation.
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    owner_generation: Option<u64>,
    /// Exact current RAM mapping ownership generation.
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    arena_generation: Option<u64>,
    /// Select the retained shared source owner instead of a private node.
    #[arg(long)]
    retained_template: bool,
}

#[derive(Subcommand, Debug, PartialEq, Eq)]
enum HostCommand {
    /// Discover current RAM arenas and their exact ownership generations.
    Targets(HostTargetsArgs),
    /// Observe accepted policy, physical convergence, resources, and deadlines.
    Status,
    /// Inspect independently qualified backend behavior and compulsory floors.
    Capabilities,
    /// Change selected RAM placement fields on the running arena.
    Set(HostRamSetArgs),
    /// Change one live operation class's polling and completion allowances.
    Latency(HostLatencyArgs),
    /// Amend a separate outer allowance measured from its original host start.
    AmendOuterCap(HostOuterCapArgs),
    /// Retry identical canonical request bytes after a lost response.
    Retry(HostRetryArgs),
}

#[derive(Args, Debug, PartialEq, Eq)]
struct HostTargetsArgs {
    /// Maximum targets in this live observation page.
    #[arg(long, default_value_t = 32, value_parser = clap::value_parser!(u8).range(1..=32))]
    limit: u8,
    /// Exclusive continuation target as the JSON returned in the previous page.
    #[arg(long, value_name = "JSON")]
    after: Option<String>,
}

#[derive(Args, Debug, PartialEq, Eq)]
struct HostUpdateIdentity {
    /// Expected accepted policy revision for this new request.
    #[arg(long)]
    expected_revision: u64,
    /// Durable retry key; reuse only when retrying identical request bytes.
    #[arg(long, value_name = "HEX64")]
    idempotency_key: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum HostMode {
    /// Maintain a best-effort resident page cache.
    Managed,
    /// Minimize safely evictable residency with complete disk preservation.
    DiskOriented,
    /// Establish and maintain the qualified full-RAM residency guarantee.
    ResidentRequired,
}

#[derive(Args, Debug, PartialEq, Eq)]
#[command(group(ArgGroup::new("change").required(true).multiple(true).args([
    "mode", "resident_target_bytes", "eviction_preference", "writeback_bytes_per_second",
    "maximum_paging_io_in_flight", "prefetch_on_increase", "reservation_amendment"
])))]
struct HostRamSetArgs {
    #[command(flatten)]
    identity: HostUpdateIdentity,
    /// Requested host placement mode, subject to backend qualification.
    #[arg(long, value_enum)]
    mode: Option<HostMode>,
    /// Desired resident guest-page bytes; zero requests minimum safe residency.
    #[arg(long)]
    resident_target_bytes: Option<u64>,
    /// Cold-page eviction preference from zero through one hundred.
    #[arg(long, value_parser = clap::value_parser!(u8).range(0..=100))]
    eviction_preference: Option<u8>,
    /// Positive maximum background preservation throughput.
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    writeback_bytes_per_second: Option<u64>,
    /// Positive maximum concurrent paging operations.
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..))]
    maximum_paging_io_in_flight: Option<u32>,
    /// Enable or disable bounded prefetch after an admitted target increase.
    #[arg(long, action = ArgAction::Set)]
    prefetch_on_increase: Option<bool>,
    /// Bounded JSON resource amendment with prior revision and transition peak.
    #[arg(long, value_name = "PATH")]
    reservation_amendment: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum HostClass {
    Setup,
    Quantum,
    PageIn,
    Writeback,
    FingerprintInitialization,
    FingerprintUpdate,
    Quiescence,
    CheckpointCapture,
    CheckpointPublication,
    Restore,
    ForkRearm,
    Transfer,
    Preparation,
    Cleanup,
}

impl HostClass {
    fn operation(self) -> HostOperationClass {
        match self {
            Self::Setup => HostOperationClass::Setup,
            Self::Quantum => HostOperationClass::Quantum,
            Self::PageIn => HostOperationClass::PageIn,
            Self::Writeback => HostOperationClass::Writeback,
            Self::FingerprintInitialization => HostOperationClass::FingerprintInitialization,
            Self::FingerprintUpdate => HostOperationClass::FingerprintUpdate,
            Self::Quiescence => HostOperationClass::Quiescence,
            Self::CheckpointCapture => HostOperationClass::CheckpointCapture,
            Self::CheckpointPublication => HostOperationClass::CheckpointPublication,
            Self::Restore => HostOperationClass::Restore,
            Self::ForkRearm => HostOperationClass::ForkRearm,
            Self::Transfer => HostOperationClass::Transfer,
            Self::Preparation => HostOperationClass::Preparation,
            Self::Cleanup => HostOperationClass::Cleanup,
        }
    }
}

#[derive(Args, Debug, PartialEq, Eq)]
#[command(group(ArgGroup::new("change").required(true).multiple(true).args([
    "poll_interval_ms", "progress_timeout_ms", "total_timeout_ms"
])))]
struct HostLatencyArgs {
    #[command(flatten)]
    identity: HostUpdateIdentity,
    /// Operation whose live allowance is amended without resetting its start.
    #[arg(value_enum)]
    class: HostClass,
    /// Positive host polling slice; expiration yields to control processing.
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    poll_interval_ms: Option<u64>,
    /// Lack-of-progress allowance in milliseconds; zero removes this allowance.
    #[arg(long)]
    progress_timeout_ms: Option<u64>,
    /// Original-entry total allowance in milliseconds; zero removes it.
    #[arg(long)]
    total_timeout_ms: Option<u64>,
}

#[derive(Args, Debug, PartialEq, Eq)]
#[command(group(ArgGroup::new("allowance").required(true).args(["allowance_ms", "unlimited"])))]
struct HostOuterCapArgs {
    /// Existing original-start cap identity from the operational status receipt.
    #[arg(long, value_name = "HEX64")]
    cap_id: String,
    /// Select the independent service-owner namespace instead of an execution.
    #[arg(long)]
    service_owner: bool,
    /// Expected outer-cap revision; independent of RAM policy revision.
    #[arg(long)]
    expected_revision: u64,
    /// Durable retry identity for this exact original-start amendment.
    #[arg(long, value_name = "HEX64")]
    idempotency_key: String,
    /// Positive total allowance from the cap owner's original start.
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    allowance_ms: Option<u64>,
    /// Explicitly remove this outer cap, subject to finite infrastructure budgets.
    #[arg(long)]
    unlimited: bool,
}

#[derive(Args, Debug, PartialEq, Eq)]
struct HostRetryArgs {
    /// Exact lowercase request hex emitted before the original mutation.
    #[arg(long, value_name = "HEX", value_parser = parse_request_hex)]
    canonical_request: CanonicalHostRequest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CanonicalHostRequest(Vec<u8>);

fn parse_request_hex(text: &str) -> Result<CanonicalHostRequest, String> {
    if text.len() > crucible_api::host_operational::HOST_OPERATIONAL_MAX_BYTES * 2
        || !text.len().is_multiple_of(2)
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("canonical request must be bounded lowercase hexadecimal bytes".into());
    }
    let mut bytes = Vec::with_capacity(text.len() / 2);
    for pair in text.as_bytes().as_chunks::<2>().0 {
        let digit = |byte| {
            if byte <= b'9' {
                byte - b'0'
            } else {
                byte - b'a' + 10
            }
        };
        bytes.push((digit(pair[0]) << 4) | digit(pair[1]));
    }
    crucible_api::host_operational::codec::validate_request(&bytes)
        .map_err(|error| error.to_string())?;
    Ok(CanonicalHostRequest(bytes))
}

pub(super) fn run_host_invocation(cli: &Cli, args: &HostArgs) -> Result<(), CliError> {
    let daemon = cli
        .daemon
        .as_deref()
        .ok_or_else(|| usage_error("host controls require --daemon"))?;
    if cli.trusted_unauthenticated_daemon
        || cli.daemon_ca.is_none()
        || cli.daemon_cert.is_none()
        || cli.daemon_key.is_none()
    {
        return Err(usage_error(
            "host controls require authenticated --daemon-ca/--daemon-cert/--daemon-key",
        ));
    }
    let plan = plan_backend_selection(cli)?
        .ok_or_else(|| usage_error("host control daemon route is missing"))?;
    let client = remote_rpc_client(daemon, &plan)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(CliError::Io)?;
    let response = runtime.block_on(execute(&client, &args.target, &args.command))?;
    let rejected = match response.value() {
        HostOperationalResponse::PolicyUpdate { disposition, .. }
        | HostOperationalResponse::OuterCapAmendment { disposition, .. } => !matches!(
            disposition,
            HostOperationalDisposition::Accepted | HostOperationalDisposition::Replayed,
        ),
        _ => false,
    };
    // Preserve the complete returned acceptance and observed convergence. A
    // successful RPC alone never implies that desired pages have already moved.
    let value = response_json(response.value());
    let output = if matches!(cli.format, Some(OutputFormat::Jsonl)) {
        serde_json::to_string(&value)
    } else {
        serde_json::to_string_pretty(&value)
    }
    .map_err(|error| backend_error(error.to_string()))?;
    println!("{output}");
    if rejected {
        return Err(backend_error(
            "host operational request was refused; see returned disposition",
        ));
    }
    Ok(())
}

async fn execute(
    client: &RpcControlClient,
    target_args: &HostTargetArgs,
    command: &HostCommand,
) -> Result<crucible_api::AdmittedOutput<HostOperationalResponse>, CliError> {
    if let HostCommand::Targets(args) = command {
        let after = args.after.as_deref().map(parse_target_cursor).transpose()?;
        return send_request(
            client,
            HostOperationalRequest::ListTargets {
                target: crucible_api::host_operational::HostRamOwnerTarget {
                    daemon_epoch: hex_identity(&target_args.daemon_epoch)?,
                    owner_id: hex_identity(&target_args.owner)?,
                },
                after,
                limit: args.limit,
            },
        )
        .await;
    }
    if let HostCommand::AmendOuterCap(args) = command {
        let owner = hex_identity(&target_args.owner)?;
        return send_request(
            client,
            HostOperationalRequest::AmendOuterCap {
                target: HostOuterCapTarget {
                    daemon_epoch: hex_identity(&target_args.daemon_epoch)?,
                    owner: if args.service_owner {
                        HostOuterCapOwner::Service(owner)
                    } else {
                        HostOuterCapOwner::Execution(owner)
                    },
                    owner_generation: owner_generation(target_args)?,
                    cap_id: hex_identity(&args.cap_id)?,
                },
                expected_cap_revision: args.expected_revision,
                idempotency_key: hex_identity(&args.idempotency_key)?,
                allowance: args.allowance_ms.map(Duration::from_millis),
            },
        )
        .await;
    }
    if let HostCommand::Retry(args) = command {
        let request =
            crucible_api::host_operational::codec::decode_request(&args.canonical_request.0)
                .map_err(|error| usage_error(error.to_string()))?;
        let exact_target = match request.target() {
            HostOperationalTarget::Owner(_) => false,
            HostOperationalTarget::Ram(expected) => expected == target(target_args)?,
            HostOperationalTarget::OuterCap(expected) => {
                let owner = match expected.owner {
                    HostOuterCapOwner::Execution(owner) | HostOuterCapOwner::Service(owner) => {
                        owner
                    }
                };
                expected.daemon_epoch == hex_identity(&target_args.daemon_epoch)?
                    && owner == hex_identity(&target_args.owner)?
                    && expected.owner_generation == owner_generation(target_args)?
            }
        };
        if !exact_target || !request.is_mutating() {
            return Err(usage_error(
                "retry bytes must bind the selected owner and an operational mutation",
            ));
        }
        let (request, _request_custody) = request.into_parts();
        return send_request(client, request).await;
    }
    let target = target(target_args)?;
    let request = match command {
        HostCommand::Status => HostOperationalRequest::Status { target },
        HostCommand::Capabilities => HostOperationalRequest::Capabilities { target },
        HostCommand::Retry(_) | HostCommand::AmendOuterCap(_) | HostCommand::Targets(_) => {
            return Err(backend_error("host owner routing is inconsistent"));
        }
        HostCommand::Set(_) | HostCommand::Latency(_) => {
            let status = client
                .host_operational(HostOperationalRequest::Status { target })
                .await
                .map_err(control_client_error)?;
            let HostOperationalResponse::Status(status) = status.value() else {
                return Err(backend_error(
                    "host controller returned inconsistent policy status",
                ));
            };
            let mut policy = status.requested_policy;
            let identity = match command {
                HostCommand::Set(args) => {
                    if let Some(mode) = args.mode {
                        policy.mode = match mode {
                            HostMode::Managed => HostRamMode::Managed,
                            HostMode::DiskOriented => HostRamMode::DiskOriented,
                            HostMode::ResidentRequired => HostRamMode::ResidentRequired,
                        };
                    }
                    if let Some(value) = args.resident_target_bytes {
                        policy.resident_target_bytes = value;
                    }
                    if let Some(value) = args.eviction_preference {
                        policy.eviction_preference = value;
                    }
                    if let Some(value) = args.writeback_bytes_per_second {
                        policy.writeback_bytes_per_second = value;
                    }
                    if let Some(value) = args.maximum_paging_io_in_flight {
                        policy.maximum_paging_io_in_flight = value;
                    }
                    if let Some(value) = args.prefetch_on_increase {
                        policy.prefetch_on_increase = value;
                    }
                    &args.identity
                }
                HostCommand::Latency(args) => {
                    let budget = &mut policy.latency.classes[args.class.operation() as usize];
                    if let Some(value) = args.poll_interval_ms {
                        budget.poll_interval = Duration::from_millis(value);
                    }
                    if let Some(value) = args.progress_timeout_ms {
                        budget.progress_timeout = optional_allowance(value);
                    }
                    if let Some(value) = args.total_timeout_ms {
                        budget.total_timeout = optional_allowance(value);
                    }
                    &args.identity
                }
                _ => return Err(backend_error("host policy command routing is inconsistent")),
            };
            if status.policy_revision != identity.expected_revision {
                return Err(usage_error(
                    "host policy revision changed; retry a lost response with the original canonical request, or observe status and submit a new key",
                ));
            }
            HostOperationalRequest::UpdatePolicy {
                target,
                expected_policy_revision: identity.expected_revision,
                idempotency_key: hex_identity(&identity.idempotency_key)?,
                policy: Box::new(policy),
                reservation_amendment: match command {
                    HostCommand::Set(args) => args
                        .reservation_amendment
                        .as_deref()
                        .map(read_reservation_amendment)
                        .transpose()?,
                    _ => None,
                },
            }
        }
    };
    send_request(client, request).await
}

async fn send_request(
    client: &RpcControlClient,
    request: HostOperationalRequest,
) -> Result<crucible_api::AdmittedOutput<HostOperationalResponse>, CliError> {
    if request.is_mutating() {
        let bytes = crucible_api::host_operational::codec::encode_request(&request)
            .map_err(|error| usage_error(error.to_string()))?;
        let text = hex_bytes(&bytes);
        eprintln!("crucible: host request retry bytes: {text}");
    }
    client
        .host_operational(request)
        .await
        .map_err(control_client_error)
}

fn optional_allowance(millis: u64) -> Option<Duration> {
    if millis == 0 {
        None
    } else {
        Some(Duration::from_millis(millis))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResourceDocument {
    resident_peak_bytes: u64,
    backing_peak_bytes: u64,
    metadata_bytes: u64,
    staging_bytes: u64,
    paging_io_slots: u64,
    cpu_slots: u64,
    task_slots: u64,
    file_descriptors: u64,
}

impl ResourceDocument {
    fn vector(self) -> crucible_api::host_operational::HostResourceVector {
        crucible_api::host_operational::HostResourceVector {
            resident_peak_bytes: self.resident_peak_bytes,
            backing_peak_bytes: self.backing_peak_bytes,
            metadata_bytes: self.metadata_bytes,
            staging_bytes: self.staging_bytes,
            paging_io_slots: self.paging_io_slots,
            cpu_slots: self.cpu_slots,
            task_slots: self.task_slots,
            file_descriptors: self.file_descriptors,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReservationDocument {
    expected_reservation_revision: u64,
    requested: ResourceDocument,
    transition_peak: ResourceDocument,
}

fn read_reservation_amendment(
    path: &Path,
) -> Result<crucible_api::host_operational::HostReservationAmendment, CliError> {
    let file = fs::File::open(path).map_err(CliError::Io)?;
    let mut bytes = Vec::new();
    file.take(crucible_api::host_operational::HOST_OPERATIONAL_MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(CliError::Io)?;
    if bytes.len() > crucible_api::host_operational::HOST_OPERATIONAL_MAX_BYTES {
        return Err(usage_error("host reservation amendment exceeds size limit"));
    }
    let document: ReservationDocument = serde_json::from_slice(&bytes)
        .map_err(|error| usage_error(format!("invalid host reservation amendment: {error}")))?;
    Ok(crucible_api::host_operational::HostReservationAmendment {
        expected_reservation_revision: document.expected_reservation_revision,
        requested: document.requested.vector(),
        transition_peak: document.transition_peak.vector(),
    })
}

fn target(args: &HostTargetArgs) -> Result<HostRamTarget, CliError> {
    Ok(HostRamTarget {
        daemon_epoch: hex_identity(&args.daemon_epoch)?,
        owner_id: hex_identity(&args.owner)?,
        node_id: hex_identity(
            args.node
                .as_deref()
                .ok_or_else(|| usage_error("RAM controls require --node"))?,
        )?,
        owner_generation: owner_generation(args)?,
        arena_generation: args
            .arena_generation
            .ok_or_else(|| usage_error("RAM controls require --arena-generation"))?,
        retained_template: args.retained_template,
    })
}

fn owner_generation(args: &HostTargetArgs) -> Result<u64, CliError> {
    args.owner_generation
        .ok_or_else(|| usage_error("this host control requires --owner-generation"))
}

fn parse_target_cursor(text: &str) -> Result<HostRamTarget, CliError> {
    if text.len() > crucible_api::host_operational::HOST_OPERATIONAL_MAX_BYTES {
        return Err(usage_error("host target cursor exceeds size limit"));
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Cursor {
        daemon_epoch: String,
        owner: String,
        node: String,
        owner_generation: u64,
        arena_generation: u64,
        retained_template: bool,
    }
    let cursor: Cursor = serde_json::from_str(text)
        .map_err(|error| usage_error(format!("invalid host target cursor: {error}")))?;
    if cursor.owner_generation == 0 || cursor.arena_generation == 0 {
        return Err(usage_error(
            "host target cursor generations must be nonzero",
        ));
    }
    Ok(HostRamTarget {
        daemon_epoch: hex_identity(&cursor.daemon_epoch)?,
        owner_id: hex_identity(&cursor.owner)?,
        node_id: hex_identity(&cursor.node)?,
        owner_generation: cursor.owner_generation,
        arena_generation: cursor.arena_generation,
        retained_template: cursor.retained_template,
    })
}

fn hex_identity(text: &str) -> Result<[u8; 32], CliError> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(usage_error(
            "host operational identities must be 64 lowercase hexadecimal digits",
        ));
    }
    let mut bytes = [0; 32];
    for (index, pair) in text.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let digit = |byte| {
            if byte <= b'9' {
                byte - b'0'
            } else {
                byte - b'a' + 10
            }
        };
        bytes[index] = (digit(pair[0]) << 4) | digit(pair[1]);
    }
    Ok(bytes)
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- parser fixtures panic only when authored invocation assumptions fail.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn target_discovery_requires_only_authenticated_owner_namespace() {
        let invocation = vec![
            String::from("crucible"),
            String::from("host"),
            String::from("--daemon-epoch"),
            "11".repeat(32),
            String::from("--owner"),
            "22".repeat(32),
            String::from("targets"),
        ];
        let parsed = Cli::try_parse_from(invocation).unwrap();
        let Commands::Host(args) = parsed.command else {
            panic!("expected host command");
        };
        assert_eq!(args.target.owner_generation, None);
        assert!(matches!(
            args.command,
            HostCommand::Targets(HostTargetsArgs {
                limit: 32,
                after: None
            })
        ));
        assert!(target(&args.target).is_err());
    }

    fn invocation(arguments: &[&str]) -> Vec<String> {
        let mut values = vec!["crucible".into(), "host".into()];
        for (flag, value) in [
            ("--daemon-epoch", "11".repeat(32)),
            ("--owner", "22".repeat(32)),
            ("--node", "33".repeat(32)),
        ] {
            values.push(flag.into());
            values.push(value);
        }
        values.extend([
            "--owner-generation".into(),
            "7".into(),
            "--arena-generation".into(),
            "9".into(),
        ]);
        values.extend(arguments.iter().map(|argument| (*argument).into()));
        values
    }

    #[test]
    fn host_policy_parser_requires_a_real_change_and_durable_retry_key() {
        let key = "44".repeat(32);
        assert!(
            Cli::try_parse_from(invocation(&[
                "set",
                "--expected-revision",
                "2",
                "--idempotency-key",
                &key
            ]))
            .is_err()
        );
        let parsed = Cli::try_parse_from(invocation(&[
            "set",
            "--expected-revision",
            "2",
            "--idempotency-key",
            &key,
            "--resident-target-bytes",
            "0",
            "--eviction-preference",
            "100",
        ]))
        .unwrap();
        assert!(matches!(parsed.command, Commands::Host(_)));
        assert!(plan_cli_invocation(&parsed).proves_t_cli_2());
    }

    #[test]
    fn host_latency_and_outer_cap_are_separate_explicit_amendments() {
        let key = "44".repeat(32);
        assert!(
            Cli::try_parse_from(invocation(&[
                "latency",
                "quantum",
                "--expected-revision",
                "2",
                "--idempotency-key",
                &key,
                "--total-timeout-ms",
                "0"
            ]))
            .is_ok()
        );
        assert!(
            Cli::try_parse_from(invocation(&[
                "amend-outer-cap",
                "--expected-revision",
                "8",
                "--idempotency-key",
                &key
            ]))
            .is_err()
        );
        assert!(
            Cli::try_parse_from(invocation(&[
                "amend-outer-cap",
                "--expected-revision",
                "8",
                "--idempotency-key",
                &key,
                "--cap-id",
                &key,
                "--unlimited"
            ]))
            .is_ok()
        );
    }

    #[test]
    fn host_target_rejects_noncanonical_and_stale_zero_generation_inputs() {
        assert!(hex_identity(&"AA".repeat(32)).is_err());
        let mut values = invocation(&["status"]);
        let generation = values
            .iter()
            .position(|value| value == "--owner-generation")
            .unwrap()
            + 1;
        values[generation] = "0".into();
        assert!(Cli::try_parse_from(values).is_err());
    }

    #[test]
    fn host_retry_reuses_complete_original_request_instead_of_current_policy() {
        let _scope = crucible_core::test_support::fixture_decode_scope(32 * 1024 * 1024)
            .unwrap_or_else(|error| panic!("finite host retry component authority: {error}"));
        let request = HostOperationalRequest::AmendOuterCap {
            target: HostOuterCapTarget {
                daemon_epoch: [0x11; 32],
                owner: HostOuterCapOwner::Execution([0x22; 32]),
                owner_generation: 7,
                cap_id: [0x77; 32],
            },
            expected_cap_revision: 8,
            idempotency_key: [0x44; 32],
            allowance: None,
        };
        let bytes = crucible_api::host_operational::codec::encode_request(&request).unwrap();
        let hex = hex_bytes(&bytes);
        let parsed =
            Cli::try_parse_from(invocation(&["retry", "--canonical-request", &hex])).unwrap();
        let Commands::Host(args) = parsed.command else {
            panic!("fixture");
        };
        let HostCommand::Retry(args) = args.command else {
            panic!("fixture");
        };

        assert_eq!(&args.canonical_request.0, bytes.value());
        assert_eq!(
            crucible_api::host_operational::codec::decode_request(&args.canonical_request.0)
                .unwrap(),
            request
        );
        assert!(
            parse_request_hex(
                &"ff".repeat(crucible_api::host_operational::HOST_OPERATIONAL_MAX_BYTES + 1)
            )
            .is_err()
        );
    }
}
