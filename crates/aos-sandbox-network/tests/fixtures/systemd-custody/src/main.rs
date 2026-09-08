//! Drives the real systemd Network namespace descriptor-store boundary.
//!
//! This binary is built only by the fleet qualification. It deliberately is
//! not an `aos-netd` binary target and is never installed by the production
//! package. The serving mode inherits production `aos-netd.service` sandboxing;
//! the client mode runs in the privileged fleet controller and creates no
//! authority inside that service.

mod activation;
mod control;
mod fake_manager;
mod manager_probe;
mod state;

use std::ffi::OsString;
use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context as _, Result, bail};
use aos_sandbox_linux::pidfd::{NamespaceFd, NamespaceIdentity, NamespaceKind};
use aos_sandbox_network::{
    FixedBpfObservationReader, MAXIMUM_RETAINED_NETWORK_NAMESPACES, NetworkNamespaceStoreOutcome,
    SystemdNetworkNamespaceStore, adopt_systemd_activation, validate_activation_replay,
};

use self::activation::take_systemd_activation;
use self::control::{ControlCommand, ControlListener, send_control_command};
use self::state::{CustodyState, PinRoot};

const CONTROL_SOCKET: &str = "/var/lib/aos/sandbox-network/custody-fixture.sock";
const STATE_FILE: &str = "/var/lib/aos/sandbox-network/custody-fixture.state";
const HOST_IDENTITY_FILE: &str = "/var/lib/aos/sandbox-network/trusted-host-netns";
const PIN_ROOT: &str = "/run/aos/sandbox-pins/netns";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("aos-netd custody fixture: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    match arguments.next().as_deref() {
        Some(mode) if mode == "serve" => serve(arguments),
        Some(mode) if mode == "send" => send(arguments),
        Some(mode) if mode == "fake-manager" => fake_manager(arguments),
        Some(mode) if mode == "artifact-custody" => artifact_custody(arguments),
        _ => bail!(
            "usage: aos-netd-custody-fixture serve CAPACITY | send COMMAND [FD_PATH ...] | fake-manager ADDRESS MODE READY_PATH | artifact-custody HELPER GATE_OBJECT"
        ),
    }
}

fn artifact_custody(mut arguments: impl Iterator<Item = OsString>) -> Result<()> {
    let helper = arguments
        .next()
        .context("artifact-custody requires HELPER")?;
    let gate_object = arguments
        .next()
        .context("artifact-custody requires GATE_OBJECT")?;
    if arguments.next().is_some() {
        bail!("artifact-custody accepts exactly two paths");
    }

    FixedBpfObservationReader::new(helper.into(), gate_object.into())
        .context("construct fixed BPF observer with retained artifact custody")?;
    println!("ARTIFACT_CUSTODY_OK");
    Ok(())
}

fn serve(mut arguments: impl Iterator<Item = OsString>) -> Result<()> {
    let capacity = parse_capacity(arguments.next())?;
    if arguments.next().is_some() {
        bail!("serve accepts exactly one capacity argument");
    }

    // Take ownership before opening state or starting the systemd D-Bus worker.
    let raw_activation = take_systemd_activation()?;
    let host_identity = state::read_identity(Path::new(HOST_IDENTITY_FILE))?;
    let activation = adopt_systemd_activation(
        raw_activation.listener,
        &raw_activation.names,
        raw_activation.retained,
        capacity,
        host_identity,
    )
    .context("adopt systemd activation")?;
    let custody_state = CustodyState::load(Path::new(STATE_FILE))?;
    let pins = PinRoot::new(Path::new(PIN_ROOT));
    custody_state.validate_pins(&pins, host_identity)?;
    let requirements = custody_state.requirements()?;
    validate_activation_replay(&activation, &requirements)
        .context("validate exact protected activation replay")?;
    let store = SystemdNetworkNamespaceStore::from_environment(&activation)
        .context("connect to the real systemd descriptor store")?;
    let listener = ControlListener::bind(Path::new(CONTROL_SOCKET))?;

    serve_commands(listener, store, custody_state, pins, host_identity)
}

fn serve_commands(
    listener: ControlListener,
    store: SystemdNetworkNamespaceStore,
    mut custody_state: CustodyState,
    pins: PinRoot<'_>,
    host_identity: NamespaceIdentity,
) -> Result<()> {
    loop {
        let connection = listener.accept()?;
        let command = match connection.receive() {
            Ok(command) => command,
            Err(error) => {
                connection.respond(format!("ERROR {error:#}").as_bytes())?;
                continue;
            }
        };
        match handle_command(command, &store, &mut custody_state, &pins, host_identity) {
            Ok(response) => connection.respond(response.as_bytes())?,
            Err(failure) => {
                connection.respond(format!("ERROR {:#}", failure.error).as_bytes())?;
                if failure.fatal {
                    return Err(failure.error);
                }
            }
        }
    }
}

struct CommandFailure {
    error: anyhow::Error,
    fatal: bool,
}

impl CommandFailure {
    fn recoverable(error: impl Into<anyhow::Error>) -> Self {
        Self {
            error: error.into(),
            fatal: false,
        }
    }

    fn fatal(error: impl Into<anyhow::Error>) -> Self {
        Self {
            error: error.into(),
            fatal: true,
        }
    }
}

fn handle_command(
    command: ControlCommand,
    store: &SystemdNetworkNamespaceStore,
    custody_state: &mut CustodyState,
    pins: &PinRoot<'_>,
    host_identity: NamespaceIdentity,
) -> Result<String, CommandFailure> {
    match command {
        ControlCommand::Ping => Ok("PONG".to_owned()),
        ControlCommand::Store { name, descriptor } => {
            let namespace = NamespaceFd::from_owned(descriptor, NamespaceKind::Network)
                .context("control descriptor is not a Network namespace")
                .map_err(CommandFailure::recoverable)?;
            let identity = namespace.identity();
            if identity == host_identity {
                return match store.store(&name, &namespace) {
                    Err(error) => Err(CommandFailure::recoverable(error)),
                    Ok(_) => Err(CommandFailure::fatal(anyhow::anyhow!(
                        "custody adapter accepted the trusted host namespace"
                    ))),
                };
            }

            custody_state
                .validate_pin(pins, &name, identity, host_identity)
                .map_err(CommandFailure::recoverable)?;
            let outcome = store
                .store(&name, &namespace)
                .map_err(CommandFailure::recoverable)?;
            custody_state
                .record(&name, identity)
                .map_err(CommandFailure::fatal)?;
            Ok(outcome_text(outcome).to_owned())
        }
        ControlCommand::Remove { name } => {
            let outcome = store.remove(&name).map_err(CommandFailure::recoverable)?;
            custody_state.remove(&name).map_err(CommandFailure::fatal)?;
            Ok(outcome_text(outcome).to_owned())
        }
        ControlCommand::CapacityProbe {
            first_name,
            first_descriptor,
            second_name,
            second_descriptor,
        } => {
            let first = NamespaceFd::from_owned(first_descriptor, NamespaceKind::Network)
                .context("first capacity descriptor is not a Network namespace")
                .map_err(CommandFailure::recoverable)?;
            let second = NamespaceFd::from_owned(second_descriptor, NamespaceKind::Network)
                .context("second capacity descriptor is not a Network namespace")
                .map_err(CommandFailure::recoverable)?;
            if first.identity() == second.identity() {
                return Err(CommandFailure::recoverable(anyhow::anyhow!(
                    "capacity descriptors name the same namespace"
                )));
            }
            custody_state
                .validate_pin(pins, &first_name, first.identity(), host_identity)
                .map_err(CommandFailure::recoverable)?;
            custody_state
                .validate_pin(pins, &second_name, second.identity(), host_identity)
                .map_err(CommandFailure::recoverable)?;
            manager_probe::force_capacity_rejection(
                &first_name,
                first.as_fd(),
                &second_name,
                second.as_fd(),
            )
            .map_err(CommandFailure::recoverable)?;
            Ok("CAPACITY_PROBED".to_owned())
        }
    }
}

fn send(mut arguments: impl Iterator<Item = OsString>) -> Result<()> {
    let command = arguments
        .next()
        .context("send requires a command payload")?
        .into_string()
        .map_err(|_| anyhow::anyhow!("command is not Unicode"))?;
    let descriptor_paths = arguments.map(std::path::PathBuf::from).collect::<Vec<_>>();
    let response = send_control_command(Path::new(CONTROL_SOCKET), &command, &descriptor_paths)?;
    println!("{response}");
    Ok(())
}

fn fake_manager(mut arguments: impl Iterator<Item = OsString>) -> Result<()> {
    let address = unicode_argument(arguments.next(), "fake-manager address")?;
    let mode = unicode_argument(arguments.next(), "fake-manager mode")?;
    let ready_path = arguments
        .next()
        .context("fake-manager ready path is absent")?;
    if arguments.next().is_some() {
        bail!("fake-manager accepts exactly three arguments");
    }
    self::fake_manager::serve(&address, &mode, Path::new(&ready_path))
}

fn unicode_argument(value: Option<OsString>, field: &'static str) -> Result<String> {
    value
        .with_context(|| format!("{field} is absent"))?
        .into_string()
        .map_err(|_| anyhow::anyhow!("{field} is not Unicode"))
}

fn parse_capacity(value: Option<OsString>) -> Result<usize> {
    let value = value
        .context("serve capacity is absent")?
        .into_string()
        .map_err(|_| anyhow::anyhow!("serve capacity is not Unicode"))?;
    let capacity = value
        .parse::<usize>()
        .context("serve capacity is not a decimal usize")?;
    if capacity == 0 || capacity > MAXIMUM_RETAINED_NETWORK_NAMESPACES {
        bail!("serve capacity is outside the hard custody bound");
    }
    Ok(capacity)
}

const fn outcome_text(outcome: NetworkNamespaceStoreOutcome) -> &'static str {
    match outcome {
        NetworkNamespaceStoreOutcome::Stored => "STORED",
        NetworkNamespaceStoreOutcome::Replay => "REPLAY",
        NetworkNamespaceStoreOutcome::Removed => "REMOVED",
        NetworkNamespaceStoreOutcome::Absent => "ABSENT",
    }
}
