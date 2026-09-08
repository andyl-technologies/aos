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
mod observer_qualification;
mod state;

use std::ffi::OsString;
use std::fs::File;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context as _, Result, bail, ensure};
use aos_sandbox_linux::netlink::network_namespace_id;
use aos_sandbox_linux::pidfd::{NamespaceFd, NamespaceIdentity, NamespaceKind};
use aos_sandbox_network::{
    FixedBpfObservationReader, FixedNftablesObservationReader, FixedRtnetlinkObservationReader,
    MAXIMUM_RETAINED_NETWORK_NAMESPACES, NetworkFlowDirectionV1, NetworkNamespaceStoreOutcome,
    NetworkPortRangeV1, NetworkTransportProtocolV1, ObservedFlowV1, ObservedInterfaceV1,
    ObservedIpAddressV1, ObservedNetworkNamespaceV1, ObservedNftAntiSpoofRuleV1,
    ObservedNftBaseChainV1, ObservedNftVerdictV1, SystemdNetworkNamespaceStore,
    adopt_systemd_activation, validate_activation_replay,
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
        Some(mode) if mode == "nft-observe" => nft_observe(arguments),
        Some(mode) if mode == "netnsid" => netnsid(arguments),
        Some(mode) if mode == "observer-plan" => observer_qualification::plan(arguments),
        Some(mode) if mode == "observer-run" => observer_qualification::run(arguments),
        Some(mode) if mode == "observer-kernel-run" => {
            observer_qualification::run_kernel(arguments)
        }
        _ => bail!(
            "usage: aos-netd-custody-fixture serve CAPACITY | send COMMAND [FD_PATH ...] | fake-manager ADDRESS MODE READY_PATH | artifact-custody HELPER GATE_OBJECT | nft-observe IP NFT LOADER GATE_OBJECT IFINDEX LOCAL_ADDRESS LOCAL_ADDRESS | netnsid PEER_NAMESPACE | observer-plan MODE STATE_ROOT GATE_OBJECT | observer-run MODE STATE_ROOT NAMESPACE IP GATE_OBJECT | observer-kernel-run MODE STATE_ROOT NAMESPACE IP NFT ENFORCEMENT_LOADER BPF_OBSERVER GATE_OBJECT"
        ),
    }
}

fn nft_observe(mut arguments: impl Iterator<Item = OsString>) -> Result<()> {
    let ip = arguments.next().context("nft-observe requires IP")?;
    let nft = arguments.next().context("nft-observe requires NFT")?;
    let loader = arguments.next().context("nft-observe requires LOADER")?;
    let gate_object = PathBuf::from(
        arguments
            .next()
            .context("nft-observe requires GATE_OBJECT")?,
    );
    let expected_ifindex = unicode_argument(arguments.next(), "nft-observe interface index")?
        .parse::<u32>()
        .context("parse nft-observe interface index")?;
    let mut expected_addresses = [
        observed_address(arguments.next(), "first nft-observe local address")?,
        observed_address(arguments.next(), "second nft-observe local address")?,
    ];
    if arguments.next().is_some() {
        bail!("nft-observe accepts exactly seven arguments");
    }
    expected_addresses.sort_unstable();

    let rtnetlink = FixedRtnetlinkObservationReader::new(ip.into())
        .context("construct fixed rtnetlink observer with retained artifact custody")?;
    let nftables = FixedNftablesObservationReader::new(nft.into(), loader.into())
        .context("construct fixed nftables observer with retained artifact custody")?;
    let first_links = rtnetlink
        .observe_sandbox()
        .context("read first rtnetlink snapshot")?;
    let first = nftables
        .observe(&first_links.links)
        .context("read first nftables snapshot")?;
    let second_links = rtnetlink
        .observe_sandbox()
        .context("read second rtnetlink snapshot")?;
    let second = nftables
        .observe(&second_links.links)
        .context("read second nftables snapshot")?;
    ensure!(
        first_links == second_links && first == second,
        "rtnetlink or nftables changed between complete snapshots"
    );
    ensure!(
        first.installed_artifact_digest == first.loader_artifact_digest,
        "nftables loader provenance differs from retained artifact"
    );
    ensure!(
        first.loader_policy_digest == observer_qualification::managed_policy_digest(&gate_object)?,
        "nftables policy provenance differs from the fixture plan"
    );
    ensure!(
        first.anti_spoof_rules.len() == 4 && first.flows.len() == 6,
        "nftables normalized rule inventory is incomplete"
    );
    let expected_chains = vec![
        ObservedNftBaseChainV1 {
            name: "ingress".to_owned(),
            hook: "input".to_owned(),
            chain_type: "filter".to_owned(),
            priority: 0,
            policy_drop: true,
        },
        ObservedNftBaseChainV1 {
            name: "egress".to_owned(),
            hook: "output".to_owned(),
            chain_type: "filter".to_owned(),
            priority: 0,
            policy_drop: true,
        },
    ];
    ensure!(
        first.default_drop && first.base_chains == expected_chains,
        "nftables base-chain contract differs from the fixture plan"
    );
    let interface = ObservedInterfaceV1 {
        namespace: ObservedNetworkNamespaceV1::Sandbox,
        ifindex: expected_ifindex,
    };
    let expected_anti_spoof = vec![
        ObservedNftAntiSpoofRuleV1 {
            direction: NetworkFlowDirectionV1::Ingress,
            interface,
            local_addresses: vec![expected_addresses[0]],
            inverted_match: true,
            position: 0,
            verdict: ObservedNftVerdictV1::Drop,
        },
        ObservedNftAntiSpoofRuleV1 {
            direction: NetworkFlowDirectionV1::Egress,
            interface,
            local_addresses: vec![expected_addresses[0]],
            inverted_match: true,
            position: 0,
            verdict: ObservedNftVerdictV1::Drop,
        },
        ObservedNftAntiSpoofRuleV1 {
            direction: NetworkFlowDirectionV1::Ingress,
            interface,
            local_addresses: vec![expected_addresses[1]],
            inverted_match: true,
            position: 1,
            verdict: ObservedNftVerdictV1::Drop,
        },
        ObservedNftAntiSpoofRuleV1 {
            direction: NetworkFlowDirectionV1::Egress,
            interface,
            local_addresses: vec![expected_addresses[1]],
            inverted_match: true,
            position: 1,
            verdict: ObservedNftVerdictV1::Drop,
        },
    ];
    ensure!(
        first.anti_spoof_rules == expected_anti_spoof,
        "nftables anti-spoof set differs from the managed namespace plan"
    );
    let endpoint_id = aos_sandbox_core::NetworkEndpointId::from_bytes([81; 16]);
    let expected_flows = vec![
        ObservedFlowV1 {
            endpoint_id,
            direction: NetworkFlowDirectionV1::Ingress,
            protocol: NetworkTransportProtocolV1::Tcp,
            remote_prefix: aos_sandbox_network::NetworkIpPrefixV1::ipv6(
                [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                128,
            )?,
            ports: Some(NetworkPortRangeV1::new(8443, 8443)?),
            position: 2,
            verdict: ObservedNftVerdictV1::Accept,
        },
        ObservedFlowV1 {
            endpoint_id,
            direction: NetworkFlowDirectionV1::Ingress,
            protocol: NetworkTransportProtocolV1::Udp,
            remote_prefix: aos_sandbox_network::NetworkIpPrefixV1::ipv4([198, 51, 100, 7], 32)?,
            ports: Some(NetworkPortRangeV1::new(53, 54)?),
            position: 3,
            verdict: ObservedNftVerdictV1::Accept,
        },
        ObservedFlowV1 {
            endpoint_id,
            direction: NetworkFlowDirectionV1::Ingress,
            protocol: NetworkTransportProtocolV1::IcmpV6,
            remote_prefix: aos_sandbox_network::NetworkIpPrefixV1::ipv6(
                [0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                64,
            )?,
            ports: None,
            position: 4,
            verdict: ObservedNftVerdictV1::Accept,
        },
        ObservedFlowV1 {
            endpoint_id,
            direction: NetworkFlowDirectionV1::Egress,
            protocol: NetworkTransportProtocolV1::Tcp,
            remote_prefix: aos_sandbox_network::NetworkIpPrefixV1::ipv4([10, 80, 0, 0], 16)?,
            ports: Some(NetworkPortRangeV1::new(443, 443)?),
            position: 2,
            verdict: ObservedNftVerdictV1::Accept,
        },
        ObservedFlowV1 {
            endpoint_id,
            direction: NetworkFlowDirectionV1::Egress,
            protocol: NetworkTransportProtocolV1::Udp,
            remote_prefix: aos_sandbox_network::NetworkIpPrefixV1::ipv6(
                [0x20, 0x01, 0x0d, 0xb8, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                64,
            )?,
            ports: Some(NetworkPortRangeV1::new(1000, 1005)?),
            position: 3,
            verdict: ObservedNftVerdictV1::Accept,
        },
        ObservedFlowV1 {
            endpoint_id,
            direction: NetworkFlowDirectionV1::Egress,
            protocol: NetworkTransportProtocolV1::IcmpV4,
            remote_prefix: aos_sandbox_network::NetworkIpPrefixV1::ipv4([203, 0, 113, 0], 24)?,
            ports: None,
            position: 4,
            verdict: ObservedNftVerdictV1::Accept,
        },
    ];
    ensure!(
        first.flows == expected_flows,
        "nftables endpoint flow differs from the fixture plan"
    );

    println!("NFT_OBSERVER_OK");
    Ok(())
}

fn observed_address(argument: Option<OsString>, name: &'static str) -> Result<ObservedIpAddressV1> {
    let address = unicode_argument(argument, name)?
        .parse::<IpAddr>()
        .with_context(|| format!("parse {name}"))?;

    Ok(match address {
        IpAddr::V4(address) => ObservedIpAddressV1::Ipv4(address.octets()),
        IpAddr::V6(address) => ObservedIpAddressV1::Ipv6(address.octets()),
    })
}

fn netnsid(mut arguments: impl Iterator<Item = OsString>) -> Result<()> {
    let peer_path = arguments
        .next()
        .context("netnsid requires PEER_NAMESPACE")?;
    if arguments.next().is_some() {
        bail!("netnsid accepts exactly one peer namespace path");
    }

    let peer_file = File::open(&peer_path).context("open fixture peer namespace")?;
    let peer = NamespaceFd::from_owned(peer_file.into(), NamespaceKind::Network)
        .context("type fixture peer namespace")?;
    let current = NamespaceFd::current_network().context("retain current fixture namespace")?;
    let namespace_id = network_namespace_id(&peer).context("query fixture peer namespace ID")?;
    let current_identity = current.identity();
    let peer_identity = peer.identity();

    println!(
        "NETNSID {namespace_id} CURRENT {} {} PEER {} {}",
        current_identity.device, current_identity.inode, peer_identity.device, peer_identity.inode
    );
    Ok(())
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
