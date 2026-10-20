//! Transports installed closed-native preservation requests to the owning daemon.
//!
//! These commands carry portable choices and signed source identities. Native
//! qualification, original operation recovery and cleanup remain actor-owned.

use std::path::PathBuf;

use clap::{Subcommand, ValueEnum};
use crucible_daemon::{
    node_control::{NodeControlRequest, NodeControlResult, request_node_control},
    node_observed_executor::{
        InstalledGem5Isa, NativeCapturePoint, NativeWorldOutcome, NativeWorldRecord,
        NativeWorldRequest,
    },
};

use super::{CliError, bounded_file, node_error};

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(super) enum NativeIsa {
    X86_64,
    Aarch64,
}

impl NativeIsa {
    fn installed(self) -> InstalledGem5Isa {
        match self {
            Self::X86_64 => InstalledGem5Isa::X86_64,
            Self::Aarch64 => InstalledGem5Isa::Aarch64,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(super) enum CapturePoint {
    Pending,
    HeldPublication,
}

impl CapturePoint {
    fn native(self) -> NativeCapturePoint {
        match self {
            Self::Pending => NativeCapturePoint::Pending,
            Self::HeldPublication => NativeCapturePoint::HeldPublication,
        }
    }
}

#[derive(Debug, Eq, PartialEq, Subcommand)]
pub(super) enum NodeNativeStateCommand {
    /// Capture the installed Clock and gem5 world at an original custody boundary.
    #[command(name = "native-capture")]
    Capture {
        /// Connect to the private same-UID node daemon socket.
        #[arg(long)]
        socket: PathBuf,
        /// Preserve an independent operation nonce, 32 lowercase hex digits.
        #[arg(long)]
        execution: String,
        /// Select the installed freestanding known-checksum guest architecture.
        #[arg(long, value_enum)]
        isa: NativeIsa,
        /// Capture a pending grant or completed output before publication and ACK.
        #[arg(long, value_enum)]
        point: CapturePoint,
    },
    /// Restore a signed native world with freshly qualified owner routes.
    #[command(name = "native-restore")]
    Restore {
        /// Connect to the private same-UID node daemon socket.
        #[arg(long)]
        socket: PathBuf,
        /// Preserve a new independent restoration nonce, 32 lowercase hex digits.
        #[arg(long)]
        execution: String,
        /// Require the original installed guest architecture.
        #[arg(long, value_enum)]
        isa: NativeIsa,
        /// Read a completed original native-state record from this private realm.
        #[arg(long)]
        source: PathBuf,
        /// Complete and acknowledge the retained original grant exactly once.
        #[arg(long)]
        complete_original: bool,
    },
    /// Read the original native-world reservation or result without dispatch.
    #[command(name = "native-status")]
    Status {
        /// Connect to the private same-UID node daemon socket.
        #[arg(long)]
        socket: PathBuf,
        /// Select the original independent operation nonce.
        #[arg(long)]
        execution: String,
    },
}

pub(super) fn run(command: &NodeNativeStateCommand) -> Result<(), CliError> {
    let (socket, request) = match command {
        NodeNativeStateCommand::Capture {
            socket,
            execution,
            isa,
            point,
        } => (
            socket,
            NativeWorldRequest::Capture {
                execution: execution.clone(),
                isa: isa.installed(),
                point: point.native(),
            },
        ),
        NodeNativeStateCommand::Restore {
            socket,
            execution,
            isa,
            source,
            complete_original,
        } => {
            let original = NativeWorldRecord::from_json(&bounded_file(source, 16 * 1024 * 1024)?)
                .map_err(node_error)?;
            let NativeWorldOutcome::Completed { artifact, .. } = original.state else {
                return Err(node_error(
                    "native restore requires a completed original capture record",
                ));
            };
            (
                socket,
                NativeWorldRequest::Restore {
                    execution: execution.clone(),
                    isa: isa.installed(),
                    source: artifact,
                    complete_original: *complete_original,
                },
            )
        }
        NodeNativeStateCommand::Status { socket, execution } => (
            socket,
            NativeWorldRequest::Status {
                execution: execution.clone(),
            },
        ),
    };
    let request =
        NodeControlRequest::native_state("operator/native-state", request).map_err(node_error)?;
    let reply = request_node_control(socket, &request).map_err(node_error)?;
    let NodeControlResult::NativeState { record } = reply.result else {
        return Err(node_error(
            "daemon refused native-state operation or returned another result",
        ));
    };
    let encoded = serde_json::to_string(record.as_ref()).map_err(node_error)?;
    println!("{encoded}");
    Ok(())
}
