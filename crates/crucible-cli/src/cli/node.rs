//! Thin installed-node compilation, observation, and retained-status commands.
//!
//! The local daemon owns installation policy, graph admission, observed dispatch,
//! and native cleanup. These commands transport authored bytes and render original
//! durable state without implementing scheduling or claiming deterministic replay.

#[path = "node_debug.rs"]
mod debug;

#[path = "node_debug_preserving.rs"]
mod debug_preserving;

#[path = "node_cache_reuse.rs"]
mod cache_reuse;
#[path = "node_capability.rs"]
mod capability;
#[path = "node_conditional_replay.rs"]
mod conditional_replay;
#[path = "node_root.rs"]
mod root;

#[path = "node_host_state.rs"]
mod host_state;
#[path = "node_terminal_state.rs"]
mod terminal_state;

#[path = "node_native_state.rs"]
mod native_state;

#[path = "node_kvm.rs"]
mod kvm;

use clap::{Args, Subcommand};
use crucible_campaign::observed_node_attempt::{ObservedAttemptOutcome, ObservedAttemptState};
use crucible_daemon::node_control::{
    NodeControlCommand, NodeControlDaemon, NodeControlRequest, NodeControlResult, NodeDaemonPolicy,
    decode_node_selections, decode_node_state, request_node_control,
};
use serde_json::json;
use std::{
    fs::File,
    io::{Read, Write},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use super::{Cli, CliError, usage_error};

#[derive(Args, Debug, PartialEq, Eq)]
pub(super) struct NodeArgs {
    #[command(subcommand)]
    command: NodeCommand,
}

#[derive(Subcommand, Debug, PartialEq, Eq)]
enum NodeCommand {
    #[command(flatten)]
    Debug(debug::NodeDebugCommand),
    #[command(flatten)]
    PreservingDebug(debug_preserving::NodePreservingDebugCommand),
    #[command(flatten)]
    Root(root::NodeRootCommand),
    #[command(flatten)]
    Capability(capability::NodeCapabilityCommand),
    #[command(flatten)]
    CacheReuse(cache_reuse::NodeCacheReuseCommand),
    #[command(flatten)]
    TerminalState(terminal_state::NodeTerminalCommand),
    #[command(flatten)]
    ConditionalReplay(conditional_replay::NodeConditionalReplayCommand),
    #[command(flatten)]
    ExactState(host_state::NodeHostStateCommand),
    #[command(flatten)]
    NativeState(native_state::NodeNativeStateCommand),
    #[command(flatten)]
    Kvm(kvm::NodeKvmCommand),
    /// Host the private installed-node observation daemon.
    Serve {
        /// Load the operator's independently authenticated installation policy JSON.
        #[arg(long)]
        policy: PathBuf,
        /// Own the private signed source archive for explicit conditional replay.
        #[arg(long)]
        transcript_archive: Option<PathBuf>,
    },
    /// Compile a complete scenario using the owning daemon's installed identities.
    Compile {
        /// Connect to the private same-UID node daemon socket.
        #[arg(long)]
        socket: PathBuf,
        /// Read the closed installed-profile selection JSON array.
        #[arg(long)]
        selections: PathBuf,
        /// Write a new canonical scenario file.
        #[arg(long)]
        output: PathBuf,
    },
    /// Reserve one original observed execution without promising deterministic replay.
    Observe {
        /// Connect to the private same-UID node daemon socket.
        #[arg(long)]
        socket: PathBuf,
        /// Select a durable observation ledger name.
        #[arg(long)]
        ledger: String,
        /// Preserve an independent execution nonce, 32 lowercase hexadecimal digits.
        #[arg(long)]
        execution: String,
        /// Read the original installed-profile selection JSON array.
        #[arg(long)]
        selections: PathBuf,
        /// Read the canonical scenario previously compiled by this daemon edition.
        #[arg(long)]
        scenario: PathBuf,
        /// Read the explicit bounded node-run configuration JSON.
        #[arg(long)]
        configuration: PathBuf,
    },
    /// Read original durable execution status without native launch or replay.
    Status {
        /// Connect to the private same-UID node daemon socket.
        #[arg(long)]
        socket: PathBuf,
        /// Select the original independent execution nonce.
        #[arg(long)]
        execution: String,
    },
}

pub(super) fn run_node_invocation(cli: &Cli, args: &NodeArgs) -> Result<(), CliError> {
    if cli.daemon.is_some()
        || cli.campaign_deployment.is_some()
        || cli.qemu.is_some()
        || cli.plugin.is_some()
        || cli.seed.is_some()
        || cli.store.is_some()
        || cli.trace.is_some()
        || cli.backend != super::Backend::Auto
        || cli
            .format
            .is_some_and(|format| !format.is_machine_readable())
    {
        return Err(usage_error(
            "node commands use their explicit installed policy/socket and execution nonce",
        ));
    }
    match &args.command {
        NodeCommand::Debug(command) => debug::run(command),
        NodeCommand::PreservingDebug(command) => debug_preserving::run(command),
        NodeCommand::Root(command) => root::run(command),
        NodeCommand::Capability(command) => capability::run(command),
        NodeCommand::CacheReuse(command) => cache_reuse::run(command),
        NodeCommand::TerminalState(command) => terminal_state::run(command),
        NodeCommand::ConditionalReplay(command) => conditional_replay::run(command),
        NodeCommand::ExactState(command) => host_state::run(command),
        NodeCommand::NativeState(command) => native_state::run(command),
        NodeCommand::Kvm(command) => kvm::run(command),
        NodeCommand::Serve {
            policy,
            transcript_archive,
        } => serve(policy, transcript_archive.as_deref()),
        NodeCommand::Compile {
            socket,
            selections,
            output,
        } => {
            let selections = decode_node_selections(&bounded_file(selections, 64 * 1024)?)
                .map_err(node_error)?;
            let request = NodeControlRequest::new(
                "operator/compile",
                NodeControlCommand::Compile { selections },
            )
            .map_err(node_error)?;
            let reply = request_node_control(socket, &request).map_err(node_error)?;
            let NodeControlResult::Compiled { scenario } = reply.result else {
                return Err(node_error(
                    "daemon refused compilation or returned another result",
                ));
            };
            let mut file = File::options()
                .write(true)
                .create_new(true)
                .open(output)
                .map_err(CliError::Io)?;
            file.write_all(scenario.as_slice()).map_err(CliError::Io)?;
            file.sync_all().map_err(CliError::Io)
        }
        NodeCommand::Observe {
            socket,
            ledger,
            execution,
            selections,
            scenario,
            configuration,
        } => {
            let selections = decode_node_selections(&bounded_file(selections, 64 * 1024)?)
                .map_err(node_error)?;
            let command = NodeControlCommand::observe(
                ledger.clone(),
                execution.clone(),
                selections,
                bounded_file(scenario, 8 * 1024 * 1024)?,
                bounded_file(configuration, 4096)?,
            );
            let request =
                NodeControlRequest::new("operator/observe", command).map_err(node_error)?;
            let reply = request_node_control(socket, &request).map_err(node_error)?;
            print_state(&decode_node_state(&reply).map_err(node_error)?)
        }
        NodeCommand::Status { socket, execution } => {
            let request = NodeControlRequest::new(
                "operator/status",
                NodeControlCommand::Status {
                    execution: execution.clone(),
                },
            )
            .map_err(node_error)?;
            let reply = request_node_control(socket, &request).map_err(node_error)?;
            print_state(&decode_node_state(&reply).map_err(node_error)?)
        }
    }
}

fn serve(
    policy: &std::path::Path,
    transcript_archive: Option<&std::path::Path>,
) -> Result<(), CliError> {
    let policy =
        NodeDaemonPolicy::from_json(&bounded_file(policy, 64 * 1024)?).map_err(node_error)?;
    let stopping = Arc::new(AtomicBool::new(false));
    let signal_stopping = stopping.clone();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(CliError::Io)?;
    // Install both termination handlers before publishing an endpoint: callers
    // may request shutdown as soon as its socket becomes visible.
    let (mut interrupt, mut terminate) = runtime
        .block_on(async {
            Ok::<_, std::io::Error>((
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?,
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?,
            ))
        })
        .map_err(CliError::Io)?;
    let mut daemon = if let Some(path) = transcript_archive {
        NodeControlDaemon::start_with_conditional_directory(policy, path.to_owned())
            .map_err(node_error)?
    } else {
        NodeControlDaemon::start(policy).map_err(node_error)?
    };
    // The signal thread changes only operational admission state; model execution
    // and cleanup remain on the existing owning actor and durable original ledger.
    let signal = std::thread::Builder::new()
        .name("crucible-node-signal".into())
        .spawn(move || {
            runtime.block_on(async {
                tokio::select! {
                    biased;
                    _ = interrupt.recv() => {},
                    _ = terminate.recv() => {},
                }
                signal_stopping.store(true, Ordering::Release);
            })
        })
        .map_err(CliError::Io)?;
    let result = daemon.serve(&stopping).map_err(node_error);
    if signal.is_finished() {
        signal
            .join()
            .map_err(|_| node_error("node daemon signal handler failed"))?;
    }
    result
}

fn print_state(state: &ObservedAttemptState) -> Result<(), CliError> {
    let request = state.request();
    let mut value = json!({
        "format":"crucible.node-observed-status", "version":1,
        "execution":hex::encode(request.execution().as_bytes()),
        "plan":request.plan_digest().to_string(),
        "capabilities":request.capabilities().digest().to_string(),
        "inputs":request.inputs().to_string(),
        "repeatable":request.capabilities().roster().is_repeatable(),
    });
    if request.conditional_scope().is_some() {
        value["materialization"] = json!("conditional_transcript_replay");
    }
    match state {
        ObservedAttemptState::Reserved(_) => {
            value["status"] = json!("reserved");
        }
        ObservedAttemptState::Quarantined { reason, .. } => {
            value["status"] = json!("quarantined");
            value["reason"] = json!(reason);
        }
        ObservedAttemptState::Completed(result) => {
            value["status"] = json!("completed");
            value["result"] = json!(result.id().map_err(node_error)?.content_id().to_string());
            value["incoming"] = json!(result.incoming().to_string());
            value["outgoing"] = json!(result.outgoing().to_string());
            value["evidence"] = json!(result.evidence().to_string());
            value["outcome"] = json!(match result.outcome() {
                ObservedAttemptOutcome::Completed => "completed",
                ObservedAttemptOutcome::Failed => "failed",
                ObservedAttemptOutcome::BudgetExhausted => "budget_exhausted",
                ObservedAttemptOutcome::Cancelled => "cancelled",
            });
        }
    }
    println!("{}", serde_json::to_string(&value).map_err(node_error)?);
    Ok(())
}

fn bounded_file(path: &std::path::Path, maximum: usize) -> Result<Vec<u8>, CliError> {
    let file = File::open(path).map_err(CliError::Io)?;
    let mut bytes = Vec::new();
    file.take((maximum + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(CliError::Io)?;
    if bytes.len() > maximum {
        return Err(usage_error("node input file exceeds finite byte ceiling"));
    }
    Ok(bytes)
}

fn node_error(error: impl std::fmt::Display) -> CliError {
    super::backend_error(format!("node control: {error}"))
}
