//! Durable loopback endpoint brokers and closed kernel ownership proofs.

mod state_authority;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

use aos_ability_model::builtin::{NETWORK_ENDPOINT_OBSERVATION_SCHEMA, NETWORK_ENDPOINT_OUTPUT};
use aos_ability_model::{LocalKey, ResourceId, RevisionId};
use aos_ability_runtime::adapter::RuntimeControl;
use serde::{Deserialize, Serialize};

pub(super) use self::state_authority::scan_endpoint_ledger as scan_endpoint_ledger_for_storage;
use self::state_authority::{
    authenticate_stored_binding, endpoint_details, endpoint_record, expected_listener_argument,
    require_requested, scan_endpoint_ledger, validate_broker_set_shape, write_endpoint_state,
};
use super::super::native_resource_map::NativeResourceQualification;
use super::platform::NativePlatformTools;
use super::storage::StorageBinding;
use super::{
    ENDPOINT_ROOT, EndpointInput, EndpointValue, HostState, NativeDependencyBinding,
    NativeHostRecord, NativeHostRequest, ability_value, decode_input, invalid, new_state,
    read_state_optional, record, remove_atomic_temporary_root, remove_regular_optional,
    require_current_state, require_matching_state, resource_key, store_error, write_state,
};

const BROKER_POLL: Duration = Duration::from_millis(5);
const SOCKET_ROOT: &str = "/run/aos-ability-postgresql";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum EndpointPhase {
    Preparing,
    Allocated,
    Releasing,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct BrokerSpec {
    family: BrokerFamily,
    slot: u8,
    principal: String,
    uid: u32,
    gid: u32,
    server_port: u16,
    public_port: u16,
    backend_path: String,
    executable: String,
    listener_argument: String,
    backend_argument: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum BrokerFamily {
    Ipv4,
    Ipv6,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct BrokerSet {
    ipv4: BrokerSpec,
    ipv6: BrokerSpec,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct BrokerIdentity {
    pid: u32,
    process_group: u32,
    start_time: u64,
    socket_inode: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BrokerProcess {
    pid: u32,
    process_group: u32,
    start_time: u64,
    state: char,
}

struct PortReservations {
    port: u16,
    _ipv4: OwnedFd,
    _ipv6: OwnedFd,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct EndpointStateDetails {
    phase: EndpointPhase,
    port_locked: bool,
    requested: EndpointInput,
    endpoint: Option<EndpointValue>,
    storage: StorageBinding,
    brokers: BrokerSet,
    ipv4_identity: Option<BrokerIdentity>,
    ipv6_identity: Option<BrokerIdentity>,
}

pub(super) fn execute_endpoint(
    request: &NativeHostRequest,
    runtime: &dyn RuntimeControl,
) -> Result<NativeHostRecord, io::Error> {
    let input: EndpointInput = decode_input(&request.durable.inputs, "network endpoint")?;
    match request.durable.method.as_str() {
        "materialize" => materialize(request, &input, runtime),
        "observe" => observe(request, &input),
        "release" => release(request, &input, runtime),
        _ => Err(invalid("unsupported endpoint method")),
    }
}

fn materialize(
    request: &NativeHostRequest,
    input: &EndpointInput,
    runtime: &dyn RuntimeControl,
) -> Result<NativeHostRecord, io::Error> {
    let reservations = scan_endpoint_ledger()?;
    let binding = request
        .durable
        .storage_binding
        .as_ref()
        .ok_or_else(|| invalid("endpoint broker has no PostgreSQL slot association"))?;
    let mut state = match read_state_optional(&request.resource.state_path)? {
        Some(state) => {
            require_matching_state(request, &state)?;
            let details = endpoint_details(&state)?;
            require_requested(input, &details.requested)?;
            if details.storage != *binding {
                return Err(invalid("endpoint storage association changed"));
            }
            authenticate_stored_binding(&details)?;
            let endpoint = details
                .endpoint
                .as_ref()
                .ok_or_else(|| invalid("endpoint intent has no reserved public value"))?;
            let brokers = broker_set(&request.durable.platform, endpoint.port, binding)?;
            if details.brokers != brokers {
                return Err(invalid("endpoint broker specification changed"));
            }
            details
        }
        None => {
            let reservation = reserve_public_port(input.port, &reservations)?;
            let public_port = reservation.port;
            let endpoint = EndpointValue {
                address: "127.0.0.1".to_string(),
                port: public_port,
                transport: "tcp".to_string(),
            };
            let details = EndpointStateDetails {
                phase: EndpointPhase::Preparing,
                port_locked: false,
                requested: input.clone(),
                endpoint: Some(endpoint),
                storage: binding.clone(),
                brokers: broker_set(&request.durable.platform, public_port, binding)?,
                ipv4_identity: None,
                ipv6_identity: None,
            };
            write_endpoint_state(request, &details)?;
            drop(reservation);
            details
        }
    };

    let may_reselect_dynamic_port = !state.port_locked;
    if state.phase != EndpointPhase::Preparing {
        state.phase = EndpointPhase::Preparing;
        write_endpoint_state(request, &state)?;
    }

    let mut launch_attempts = 0_u8;
    let (endpoint, ipv4_identity, ipv6_identity) = loop {
        let ipv4_result = ensure_broker(&request.durable.platform, &state.brokers.ipv4, runtime);
        let result = match ipv4_result {
            Ok((endpoint, identity)) => {
                if state.ipv4_identity.as_ref() != Some(&identity) {
                    state.ipv4_identity = Some(identity.clone());
                    write_endpoint_state(request, &state)?;
                }
                ensure_broker(&request.durable.platform, &state.brokers.ipv6, runtime)
                    .map(|(ipv6_endpoint, ipv6)| (endpoint, identity, ipv6_endpoint, ipv6))
            }
            Err(error) => Err(error),
        };
        match result {
            Ok((endpoint, ipv4, ipv6_endpoint, ipv6)) => {
                if endpoint != ipv6_endpoint {
                    return Err(invalid("endpoint broker families publish different values"));
                }
                if state.ipv6_identity.as_ref() != Some(&ipv6) {
                    state.ipv6_identity = Some(ipv6.clone());
                    write_endpoint_state(request, &state)?;
                }
                break (endpoint, ipv4, ipv6);
            }
            Err(error)
                if error.kind() == io::ErrorKind::AddrInUse
                    && input.port == 0
                    && may_reselect_dynamic_port
                    && launch_attempts < 8 =>
            {
                launch_attempts += 1;
                terminate_broker_optional(
                    &state.brokers.ipv4,
                    state.ipv4_identity.as_ref(),
                    runtime,
                )?;
                terminate_broker_optional(
                    &state.brokers.ipv6,
                    state.ipv6_identity.as_ref(),
                    runtime,
                )?;
                let current = scan_endpoint_ledger()?
                    .into_iter()
                    .filter(|(resource, _)| resource != &request.durable.resource)
                    .collect::<Vec<_>>();
                let reservation = reserve_public_port(0, &current)?;
                let public_port = reservation.port;
                state.endpoint = Some(EndpointValue {
                    address: "127.0.0.1".to_string(),
                    port: public_port,
                    transport: "tcp".to_string(),
                });
                state.brokers = broker_set(&request.durable.platform, public_port, binding)?;
                state.ipv4_identity = None;
                state.ipv6_identity = None;
                write_endpoint_state(request, &state)?;
                drop(reservation);
            }
            Err(error) => return Err(error),
        }
    };
    state.phase = EndpointPhase::Allocated;
    state.port_locked = true;
    state.endpoint = Some(endpoint.clone());
    state.ipv4_identity = Some(ipv4_identity);
    state.ipv6_identity = Some(ipv6_identity);
    write_endpoint_state(request, &state)?;
    authenticate_settled_broker(&state)?;
    endpoint_record(
        request,
        Some(endpoint),
        true,
        Some(request.durable.revision),
    )
}

fn observe(
    request: &NativeHostRequest,
    input: &EndpointInput,
) -> Result<NativeHostRecord, io::Error> {
    scan_endpoint_ledger()?;
    let state = require_current_state(request)?;
    let details = endpoint_details(&state)?;
    require_requested(input, &details.requested)?;
    let binding = request
        .durable
        .storage_binding
        .as_ref()
        .ok_or_else(|| invalid("endpoint observation has no PostgreSQL slot association"))?;
    let endpoint = details
        .endpoint
        .as_ref()
        .ok_or_else(|| invalid("endpoint marker has no public value"))?;
    if details.storage != *binding {
        return Err(invalid("endpoint observation storage association changed"));
    }
    authenticate_stored_binding(&details)?;
    if details.brokers != broker_set(&request.durable.platform, endpoint.port, binding)? {
        return Err(invalid("endpoint broker specification changed"));
    }
    let (endpoint, _, _) = authenticate_settled_broker(&details)?;
    endpoint_record(request, Some(endpoint), true, Some(state.revision))
}

fn release(
    request: &NativeHostRequest,
    input: &EndpointInput,
    runtime: &dyn RuntimeControl,
) -> Result<NativeHostRecord, io::Error> {
    scan_endpoint_ledger()?;
    let Some(state) = read_state_optional(&request.resource.state_path)? else {
        let binding = request
            .durable
            .storage_binding
            .as_ref()
            .ok_or_else(|| invalid("endpoint release has no PostgreSQL slot association"))?;
        if orphan_broker_residue(binding, input)? {
            return Err(invalid(
                "endpoint broker exists without an ownership marker",
            ));
        }
        remove_atomic_temporary_root(&request.resource.state_path, 0o600)?;
        return endpoint_record(request, None, false, None);
    };
    require_matching_state(request, &state)?;
    let mut details = endpoint_details(&state)?;
    if details.phase != EndpointPhase::Releasing {
        if !matches!(
            details.phase,
            EndpointPhase::Preparing | EndpointPhase::Allocated
        ) {
            return Err(invalid("endpoint marker has an invalid release phase"));
        }
        details.phase = EndpointPhase::Releasing;
        write_endpoint_state(request, &details)?;
    }
    authenticate_stored_binding(&details)?;
    terminate_broker_optional(
        &details.brokers.ipv4,
        details.ipv4_identity.as_ref(),
        runtime,
    )?;
    terminate_broker_optional(
        &details.brokers.ipv6,
        details.ipv6_identity.as_ref(),
        runtime,
    )?;
    let endpoint = details
        .endpoint
        .as_ref()
        .ok_or_else(|| invalid("endpoint release marker has no public value"))?;
    let other_reservations = scan_endpoint_ledger()?
        .into_iter()
        .filter(|(resource, _)| resource != &request.durable.resource)
        .collect::<Vec<_>>();
    let _reservation = reserve_public_port(endpoint.port, &other_reservations)?;
    if !find_exact_processes(&details.brokers.ipv4)?.is_empty()
        || !find_exact_processes(&details.brokers.ipv6)?.is_empty()
    {
        return Err(invalid(
            "endpoint broker remained after authenticated termination",
        ));
    }
    remove_regular_optional(&request.resource.state_path, 0)?;
    endpoint_record(request, None, false, None)
}

fn orphan_broker_residue(
    binding: &StorageBinding,
    input: &EndpointInput,
) -> Result<bool, io::Error> {
    let expected_backend = format!(
        "UNIX-CONNECT:{SOCKET_ROOT}/{:02}/.s.PGSQL.{}",
        binding.slot,
        20_000_u16
            .checked_add(u16::from(binding.slot))
            .ok_or_else(|| invalid("endpoint broker internal port overflowed"))?
    );
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let argv = match fs::read(format!("/proc/{pid}/cmdline")) {
            Ok(argv) => argv,
            Err(error) if process_disappeared(&error) => continue,
            Err(error) => return Err(error),
        };
        let arguments = argv
            .split(|byte| *byte == 0)
            .filter(|argument| !argument.is_empty())
            .collect::<Vec<_>>();
        if !arguments
            .iter()
            .any(|argument| *argument == expected_backend.as_bytes())
        {
            continue;
        }
        let listener_arguments = arguments
            .iter()
            .filter_map(|argument| std::str::from_utf8(argument).ok())
            .filter(|argument| {
                argument.starts_with("TCP4-LISTEN:") || argument.starts_with("TCP6-LISTEN:")
            })
            .collect::<Vec<_>>();
        let [listener] = listener_arguments.as_slice() else {
            return Err(invalid(
                "endpoint broker residue has ambiguous listener authority",
            ));
        };
        let listener = std::str::from_utf8(listener.as_bytes())
            .map_err(|_| invalid("endpoint broker residue has a non-UTF-8 listener"))?;
        let family = if listener.starts_with("TCP4-LISTEN:") {
            BrokerFamily::Ipv4
        } else if listener.starts_with("TCP6-LISTEN:") {
            BrokerFamily::Ipv6
        } else {
            return Err(invalid("endpoint broker residue has a foreign listener"));
        };
        let port = listener
            .split_once(':')
            .and_then(|(_, suffix)| suffix.split_once(','))
            .and_then(|(port, _)| port.parse::<u16>().ok())
            .filter(|port| *port > 0)
            .ok_or_else(|| invalid("endpoint broker residue has an invalid port"))?;
        if listener != expected_listener_argument(family, port)
            || input.port != 0 && input.port != port
        {
            return Err(invalid("endpoint broker residue has foreign authority"));
        }
        return Ok(true);
    }
    Ok(false)
}

pub(super) fn endpoint_health(state: &HostState) -> Result<bool, io::Error> {
    authenticate_settled_broker(&endpoint_details(state)?).map(|_| true)
}

pub(super) fn endpoint_from_state(state: &HostState) -> Result<EndpointValue, io::Error> {
    authenticate_settled_broker(&endpoint_details(state)?).map(|(endpoint, _, _)| endpoint)
}

pub(super) fn authenticate_endpoint(
    binding: &NativeDependencyBinding,
    expected: &EndpointValue,
) -> Result<(), io::Error> {
    let endpoint_output = LocalKey::new(NETWORK_ENDPOINT_OUTPUT).map_err(store_error)?;
    if binding.input != "endpoint"
        || binding.interface
            != aos_ability_model::builtin::network_endpoint_interface_key().map_err(store_error)?
        || !matches!(binding.method.as_str(), "materialize" | "observe")
        || binding.output != endpoint_output
    {
        return Err(invalid(
            "endpoint producer authority has a foreign contract shape",
        ));
    }
    scan_endpoint_ledger()?;
    let marker =
        Path::new(ENDPOINT_ROOT).join(format!("{}.json", resource_key(&binding.resource)?));
    let state = read_state_optional(&marker)?
        .ok_or_else(|| invalid("endpoint dependency has no ownership marker"))?;
    if state.resource != binding.resource
        || state.revision != binding.revision
        || state.qualification != binding.qualification
        || endpoint_from_state(&state)? != *expected
    {
        return Err(invalid(
            "endpoint dependency differs from its producer authority",
        ));
    }
    Ok(())
}

pub(super) fn authenticate_endpoint_storage_binding(
    resource: &ResourceId,
    binding: &StorageBinding,
) -> Result<(), io::Error> {
    let marker = Path::new(ENDPOINT_ROOT).join(format!("{}.json", resource_key(resource)?));
    let Some(state) = read_state_optional(&marker)? else {
        return Ok(());
    };
    if state.resource != *resource {
        return Err(invalid(
            "endpoint association marker names another resource",
        ));
    }
    let details = endpoint_details(&state)?;
    validate_broker_set_shape(&details.brokers)?;
    if details.storage != *binding {
        return Err(invalid(
            "endpoint ownership ledger disagrees with its storage binding",
        ));
    }
    authenticate_stored_binding(&details)?;
    Ok(())
}

fn broker_set(
    platform: &NativePlatformTools,
    public_port: u16,
    binding: &StorageBinding,
) -> Result<BrokerSet, io::Error> {
    Ok(BrokerSet {
        ipv4: broker_spec(platform, BrokerFamily::Ipv4, public_port, binding)?,
        ipv6: broker_spec(platform, BrokerFamily::Ipv6, public_port, binding)?,
    })
}

fn broker_spec(
    platform: &NativePlatformTools,
    family: BrokerFamily,
    public_port: u16,
    binding: &StorageBinding,
) -> Result<BrokerSpec, io::Error> {
    let server_port = 20_000_u16
        .checked_add(u16::from(binding.slot))
        .ok_or_else(|| invalid("endpoint broker internal port overflowed"))?;
    let backend_path = format!("{SOCKET_ROOT}/{:02}/.s.PGSQL.{server_port}", binding.slot);
    Ok(BrokerSpec {
        family,
        slot: binding.slot,
        principal: super::postgresql_broker_principal(binding.slot)?,
        uid: super::postgresql_broker_uid(binding.slot)?,
        gid: super::postgresql_probe_gid(binding.slot)?,
        server_port,
        public_port,
        backend_argument: format!("UNIX-CONNECT:{backend_path}"),
        backend_path,
        executable: platform.broker_executable().to_string(),
        listener_argument: expected_listener_argument(family, public_port),
    })
}

fn ensure_broker(
    platform: &NativePlatformTools,
    spec: &BrokerSpec,
    runtime: &dyn RuntimeControl,
) -> Result<(EndpointValue, BrokerIdentity), io::Error> {
    let exact_processes = find_exact_processes(spec)?;
    let candidates = process_leaders(&exact_processes);
    if candidates.len() > 1 {
        return Err(invalid("endpoint marker has multiple matching brokers"));
    }
    if candidates.is_empty() && !exact_processes.is_empty() {
        terminate_exact_processes(spec, exact_processes, runtime)?;
    }
    if let Some(process) = candidates.into_iter().next() {
        if process.state == 'Z' {
            reap_child(process.pid);
            if exact_broker_process(process.pid, spec)?.is_some() {
                return Err(invalid("endpoint broker zombie could not be reaped"));
            }
        } else {
            return wait_for_broker(process, spec, runtime);
        }
    }
    if runtime.is_cancelled() {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "endpoint broker launch was cancelled",
        ));
    }

    if platform.broker_executable() != spec.executable {
        return Err(invalid("endpoint broker platform authority changed"));
    }
    let mut command = platform.broker_command(spec.uid, spec.gid);
    command
        .arg(&spec.listener_argument)
        .arg(&spec.backend_argument)
        .process_group(0)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = command.spawn()?;
    let pid = child.id();
    let Some(process_group) = i32::try_from(pid)
        .ok()
        .and_then(rustix::process::Pid::from_raw)
    else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(invalid("endpoint broker has no valid process group"));
    };
    let leader =
        match rustix::process::pidfd_open(process_group, rustix::process::PidfdFlags::empty()) {
            Ok(leader) => leader,
            Err(error) => {
                cleanup_spawned_broker(&mut child, process_group, None);
                return Err(error.into());
            }
        };
    let deadline = match deadline(runtime) {
        Ok(deadline) => deadline,
        Err(error) => {
            cleanup_spawned_broker(&mut child, process_group, Some(&leader));
            return Err(error);
        }
    };
    loop {
        if runtime.is_cancelled() || Instant::now() >= deadline {
            cleanup_spawned_broker(&mut child, process_group, Some(&leader));
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "endpoint broker launch exhausted its runtime budget",
            ));
        }
        let exited = match broker_launcher_exited(&leader) {
            Ok(exited) => exited,
            Err(error) => {
                cleanup_spawned_broker(&mut child, process_group, Some(&leader));
                return Err(error);
            }
        };
        if exited {
            let kind = match broker_port_is_available(spec) {
                Ok(false) => io::ErrorKind::AddrInUse,
                _ => io::ErrorKind::Other,
            };
            cleanup_spawned_broker(&mut child, process_group, Some(&leader));
            return Err(io::Error::new(
                kind,
                "endpoint broker exited before ownership proof",
            ));
        }
        let exact_process = match exact_broker_process(pid, spec) {
            Ok(process) => process,
            Err(error) => {
                cleanup_spawned_broker(&mut child, process_group, Some(&leader));
                return Err(error);
            }
        };
        match exact_process {
            Some(process) => match broker_identity(process, spec) {
                Ok(result) => return Ok(result),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    std::thread::sleep(BROKER_POLL);
                }
                Err(error) => {
                    cleanup_spawned_broker(&mut child, process_group, Some(&leader));
                    return Err(error);
                }
            },
            None => {
                std::thread::sleep(BROKER_POLL);
            }
        }
    }
}

fn broker_launcher_exited(leader: &OwnedFd) -> Result<bool, io::Error> {
    Ok(rustix::process::waitid(
        rustix::process::WaitId::PidFd(leader.as_fd()),
        rustix::process::WaitIdOptions::NOHANG
            | rustix::process::WaitIdOptions::EXITED
            | rustix::process::WaitIdOptions::NOWAIT,
    )?
    .is_some())
}

fn cleanup_spawned_broker(
    child: &mut std::process::Child,
    process_group: rustix::process::Pid,
    leader: Option<&OwnedFd>,
) {
    let _ = rustix::process::kill_process_group(process_group, rustix::process::Signal::KILL);
    if let Some(leader) = leader {
        let _ = rustix::process::pidfd_send_signal(leader, rustix::process::Signal::KILL);
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn wait_for_broker(
    process: BrokerProcess,
    spec: &BrokerSpec,
    runtime: &dyn RuntimeControl,
) -> Result<(EndpointValue, BrokerIdentity), io::Error> {
    let deadline = deadline(runtime)?;
    loop {
        let Some(current) = exact_broker_process(process.pid, spec)? else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "endpoint broker disappeared during recovery",
            ));
        };
        if current.process_group != process.process_group
            || current.start_time != process.start_time
        {
            return Err(invalid(
                "endpoint broker incarnation changed during recovery",
            ));
        }
        match broker_identity(current, spec) {
            Ok(result) => return Ok(result),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        if runtime.is_cancelled() || Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "endpoint broker recovery exhausted its runtime budget",
            ));
        }
        std::thread::sleep(BROKER_POLL);
    }
}

fn authenticate_settled_broker(
    details: &EndpointStateDetails,
) -> Result<(EndpointValue, BrokerIdentity, BrokerIdentity), io::Error> {
    if details.phase != EndpointPhase::Allocated {
        return Err(invalid("endpoint broker is not settled"));
    }
    let expected = details
        .endpoint
        .as_ref()
        .ok_or_else(|| invalid("settled endpoint has no public value"))?;
    let recorded_ipv4 = details
        .ipv4_identity
        .as_ref()
        .ok_or_else(|| invalid("settled endpoint has no IPv4 broker identity"))?;
    let recorded_ipv6 = details
        .ipv6_identity
        .as_ref()
        .ok_or_else(|| invalid("settled endpoint has no IPv6 broker identity"))?;
    let (endpoint, actual_ipv4) = authenticate_one_broker(&details.brokers.ipv4, recorded_ipv4)?;
    let (ipv6_endpoint, actual_ipv6) =
        authenticate_one_broker(&details.brokers.ipv6, recorded_ipv6)?;
    if endpoint != *expected || ipv6_endpoint != *expected {
        return Err(invalid("endpoint broker identity changed"));
    }
    Ok((endpoint, actual_ipv4, actual_ipv6))
}

fn authenticate_one_broker(
    spec: &BrokerSpec,
    recorded: &BrokerIdentity,
) -> Result<(EndpointValue, BrokerIdentity), io::Error> {
    let candidates = find_exact_brokers(spec)?;
    if candidates.len() != 1 || candidates[0].pid != recorded.pid {
        return Err(invalid(
            "settled endpoint does not have exactly one broker incarnation",
        ));
    }
    let (endpoint, actual) = broker_identity(candidates[0].clone(), spec)?;
    if &actual != recorded {
        return Err(invalid("endpoint broker incarnation changed"));
    }
    Ok((endpoint, actual))
}

fn find_exact_brokers(spec: &BrokerSpec) -> Result<Vec<BrokerProcess>, io::Error> {
    let processes = find_exact_processes(spec)?;
    let leaders = process_leaders(&processes);
    if processes.iter().any(|process| {
        process.process_group != process.pid
            && !leaders
                .iter()
                .any(|leader| leader.pid == process.process_group)
    }) {
        return Err(invalid("endpoint broker has an orphaned connection worker"));
    }
    Ok(leaders)
}

fn process_leaders(processes: &[BrokerProcess]) -> Vec<BrokerProcess> {
    processes
        .iter()
        .filter(|process| process.process_group == process.pid)
        .cloned()
        .collect()
}

fn find_exact_processes(spec: &BrokerSpec) -> Result<Vec<BrokerProcess>, io::Error> {
    let mut processes = Vec::new();
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        if let Some(process) = exact_broker_process(pid, spec)? {
            processes.push(process);
        }
    }
    Ok(processes)
}

fn exact_broker_process(pid: u32, spec: &BrokerSpec) -> Result<Option<BrokerProcess>, io::Error> {
    let executable = match fs::canonicalize(format!("/proc/{pid}/exe")) {
        Ok(executable) => executable,
        Err(error) if process_disappeared(&error) => return Ok(None),
        Err(error) => return Err(error),
    };
    if executable != Path::new(&spec.executable) {
        return Ok(None);
    }
    let argv = match fs::read(format!("/proc/{pid}/cmdline")) {
        Ok(argv) => argv,
        Err(error) if process_disappeared(&error) => return Ok(None),
        Err(error) => return Err(error),
    };
    let arguments = argv
        .split(|byte| *byte == 0)
        .filter(|argument| !argument.is_empty())
        .collect::<Vec<_>>();
    if arguments.len() != 3
        || arguments[0] != spec.executable.as_bytes()
        || arguments[1] != spec.listener_argument.as_bytes()
        || arguments[2] != spec.backend_argument.as_bytes()
    {
        return Ok(None);
    }
    let status = match fs::read_to_string(format!("/proc/{pid}/status")) {
        Ok(status) => status,
        Err(error) if process_disappeared(&error) => return Ok(None),
        Err(error) => return Err(error),
    };
    require_process_ids(&status, spec.uid, spec.gid)?;
    let stat = match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => stat,
        Err(error) if process_disappeared(&error) => return Ok(None),
        Err(error) => return Err(error),
    };
    let (state, process_group, start_time) = process_stat(&stat)?;
    Ok(Some(BrokerProcess {
        pid,
        process_group,
        start_time,
        state,
    }))
}

fn broker_identity(
    process: BrokerProcess,
    spec: &BrokerSpec,
) -> Result<(EndpointValue, BrokerIdentity), io::Error> {
    if process.state == 'Z' {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "endpoint broker exited before listener proof",
        ));
    }
    let socket_inode = listener_for_process(process.pid, spec.family, spec.public_port)?;
    Ok((
        EndpointValue {
            address: "127.0.0.1".to_string(),
            port: spec.public_port,
            transport: "tcp".to_string(),
        },
        BrokerIdentity {
            pid: process.pid,
            process_group: process.process_group,
            start_time: process.start_time,
            socket_inode,
        },
    ))
}

fn listener_for_process(
    pid: u32,
    family: BrokerFamily,
    public_port: u16,
) -> Result<u64, io::Error> {
    let mut sockets = BTreeSet::new();
    for entry in fs::read_dir(format!("/proc/{pid}/fd"))? {
        let entry = entry?;
        let target = match fs::read_link(entry.path()) {
            Ok(target) => target,
            Err(error) if process_disappeared(&error) => continue,
            Err(error) => return Err(error),
        };
        if let Some(inode) = target
            .to_str()
            .and_then(|target| target.strip_prefix("socket:["))
            .and_then(|target| target.strip_suffix(']'))
            .and_then(|target| target.parse::<u64>().ok())
        {
            sockets.insert(inode);
        }
    }
    let mut listeners = Vec::new();
    let (table_path, wildcard) = match family {
        BrokerFamily::Ipv4 => ("/proc/net/tcp", "00000000"),
        BrokerFamily::Ipv6 => ("/proc/net/tcp6", "00000000000000000000000000000000"),
    };
    let table = fs::read_to_string(table_path)?;
    for line in table.lines().skip(1) {
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.len() <= 9 || fields[3] != "0A" {
            continue;
        }
        let Some((address, port)) = fields[1].split_once(':') else {
            continue;
        };
        let Ok(port) = u16::from_str_radix(port, 16) else {
            continue;
        };
        let Ok(inode) = fields[9].parse::<u64>() else {
            continue;
        };
        if address == wildcard && public_port == port && sockets.contains(&inode) {
            listeners.push(inode);
        }
    }
    match listeners.as_slice() {
        [listener] => Ok(*listener),
        [] => Err(io::Error::new(
            io::ErrorKind::NotFound,
            "endpoint broker listener is not ready",
        )),
        _ => Err(invalid("endpoint broker owns multiple public listeners")),
    }
}

fn process_stat(stat: &str) -> Result<(char, u32, u64), io::Error> {
    let close = stat
        .rfind(')')
        .ok_or_else(|| invalid("endpoint broker process stat is malformed"))?;
    let fields = stat[close + 1..]
        .split_ascii_whitespace()
        .collect::<Vec<_>>();
    let state = fields
        .first()
        .and_then(|value| value.chars().next())
        .ok_or_else(|| invalid("endpoint broker process state is malformed"))?;
    let process_group = fields
        .get(2)
        .and_then(|value| value.parse::<u32>().ok())
        .ok_or_else(|| invalid("endpoint broker process group is malformed"))?;
    let start_time = fields
        .get(19)
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| invalid("endpoint broker start time is malformed"))?;
    Ok((state, process_group, start_time))
}

fn require_process_ids(status: &str, uid: u32, gid: u32) -> Result<(), io::Error> {
    let expected = format!("{uid}\t{uid}\t{uid}\t{uid}");
    let expected_group = format!("{gid}\t{gid}\t{gid}\t{gid}");
    let zero_capabilities = ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"]
        .iter()
        .all(|label| {
            status.lines().any(|line| {
                line.strip_prefix(label)
                    .is_some_and(|value| value.trim() == "0000000000000000")
            })
        });
    let no_new_privileges = status.lines().any(|line| {
        line.strip_prefix("NoNewPrivs:")
            .is_some_and(|value| value.trim() == "1")
    });
    let no_supplementary_groups = status.lines().any(|line| {
        line.strip_prefix("Groups:")
            .is_some_and(|value| value.split_ascii_whitespace().next().is_none())
    });
    if !status
        .lines()
        .any(|line| line.strip_prefix("Uid:\t") == Some(expected.as_str()))
        || !status
            .lines()
            .any(|line| line.strip_prefix("Gid:\t") == Some(expected_group.as_str()))
        || !zero_capabilities
        || !no_new_privileges
        || !no_supplementary_groups
    {
        return Err(invalid("endpoint broker has another process identity"));
    }
    Ok(())
}

fn terminate_broker_optional(
    spec: &BrokerSpec,
    recorded: Option<&BrokerIdentity>,
    runtime: &dyn RuntimeControl,
) -> Result<(), io::Error> {
    let processes = find_exact_processes(spec)?;
    if let Some(identity) = recorded {
        return terminate_broker(spec, identity, runtime);
    }
    if processes.is_empty() {
        return Ok(());
    }
    terminate_exact_processes(spec, processes, runtime)
}

fn terminate_exact_processes(
    spec: &BrokerSpec,
    processes: Vec<BrokerProcess>,
    runtime: &dyn RuntimeControl,
) -> Result<(), io::Error> {
    let leaders = processes
        .iter()
        .filter(|process| process.pid == process.process_group)
        .collect::<Vec<_>>();
    match leaders.as_slice() {
        [leader] => terminate_broker(
            spec,
            &BrokerIdentity {
                pid: leader.pid,
                process_group: leader.process_group,
                start_time: leader.start_time,
                socket_inode: 0,
            },
            runtime,
        ),
        [] => terminate_captured_processes(spec, processes, runtime),
        _ => Err(invalid("endpoint marker has multiple exact broker leaders")),
    }
}

fn terminate_broker(
    spec: &BrokerSpec,
    identity: &BrokerIdentity,
    runtime: &dyn RuntimeControl,
) -> Result<(), io::Error> {
    let Some(leader) = exact_broker_process(identity.pid, spec)? else {
        let residue = find_exact_processes(spec)?
            .into_iter()
            .filter(|process| process.process_group == identity.process_group)
            .collect::<Vec<_>>();
        return terminate_captured_processes(spec, residue, runtime);
    };
    if leader.pid != leader.process_group
        || leader.process_group != identity.process_group
        || leader.start_time != identity.start_time
    {
        return Err(invalid(
            "endpoint broker incarnation changed before release",
        ));
    }
    if let Ok(socket_inode) = listener_for_process(leader.pid, spec.family, spec.public_port)
        && identity.socket_inode != 0
        && socket_inode != identity.socket_inode
    {
        return Err(invalid("endpoint broker socket incarnation changed"));
    }

    let leader_capture = capture_exact_process(spec, &leader)?;
    signal_captured(&leader_capture, rustix::process::Signal::STOP)?;
    let deadline = deadline(runtime)?;
    loop {
        let Some((state, process_group, start_time)) = process_stat_optional(identity.pid)? else {
            break;
        };
        if process_group != identity.process_group || start_time != identity.start_time {
            return Err(invalid("endpoint broker changed while awaiting SIGSTOP"));
        }
        if matches!(state, 'T' | 't' | 'Z') {
            break;
        }
        if runtime.is_cancelled() || Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "endpoint broker did not stop before worker capture",
            ));
        }
        std::thread::sleep(BROKER_POLL);
    }

    let processes = find_exact_processes(spec)?;
    if processes
        .iter()
        .any(|process| process.process_group != identity.process_group)
    {
        return Err(invalid("endpoint broker has a foreign exact process group"));
    }
    let mut captures = Vec::with_capacity(processes.len());
    for process in processes {
        if process.pid == leader_capture.process.pid {
            continue;
        }
        captures.push(capture_exact_process(spec, &process)?);
    }
    captures.push(leader_capture);
    terminate_captures(captures, runtime)
}

struct CapturedBrokerProcess {
    process: BrokerProcess,
    pidfd: OwnedFd,
}

fn capture_exact_process(
    spec: &BrokerSpec,
    process: &BrokerProcess,
) -> Result<CapturedBrokerProcess, io::Error> {
    let pid = i32::try_from(process.pid)
        .ok()
        .and_then(rustix::process::Pid::from_raw)
        .ok_or_else(|| invalid("endpoint broker PID is outside the supported range"))?;
    let pidfd = match rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()) {
        Ok(pidfd) => pidfd,
        Err(rustix::io::Errno::SRCH) => {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "endpoint broker exited during pidfd capture",
            ));
        }
        Err(error) => return Err(error.into()),
    };
    let Some(current) = exact_broker_process(process.pid, spec)? else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "endpoint broker exited during pidfd capture",
        ));
    };
    if current.process_group != process.process_group || current.start_time != process.start_time {
        return Err(invalid(
            "endpoint broker incarnation changed after opening its pidfd",
        ));
    }
    Ok(CapturedBrokerProcess {
        process: current,
        pidfd,
    })
}

fn signal_captured(
    captured: &CapturedBrokerProcess,
    signal: rustix::process::Signal,
) -> Result<(), io::Error> {
    match rustix::process::pidfd_send_signal(&captured.pidfd, signal) {
        Ok(()) | Err(rustix::io::Errno::SRCH) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn terminate_captured_processes(
    spec: &BrokerSpec,
    processes: Vec<BrokerProcess>,
    runtime: &dyn RuntimeControl,
) -> Result<(), io::Error> {
    let mut captures = Vec::with_capacity(processes.len());
    for process in processes {
        captures.push(capture_exact_process(spec, &process)?);
    }
    terminate_captures(captures, runtime)
}

fn terminate_captures(
    captures: Vec<CapturedBrokerProcess>,
    runtime: &dyn RuntimeControl,
) -> Result<(), io::Error> {
    for capture in &captures {
        signal_captured(capture, rustix::process::Signal::KILL)?;
    }
    let deadline = deadline(runtime)?;
    loop {
        for capture in &captures {
            reap_child(capture.process.pid);
        }
        let any_alive = captures.iter().try_fold(false, |alive, capture| {
            let current = process_stat_optional(capture.process.pid)?;
            Ok::<_, io::Error>(
                alive
                    || current.as_ref().is_some_and(|(_, _, start_time)| {
                        *start_time == capture.process.start_time
                    }),
            )
        })?;
        if !any_alive {
            return Ok(());
        }
        if runtime.is_cancelled() || Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "endpoint broker captures exhausted their termination budget",
            ));
        }
        std::thread::sleep(BROKER_POLL);
    }
}

fn reap_child(pid: u32) {
    let Some(pid) = i32::try_from(pid)
        .ok()
        .and_then(rustix::process::Pid::from_raw)
    else {
        return;
    };
    let _ = rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::NOHANG);
}

fn process_stat_optional(pid: u32) -> Result<Option<(char, u32, u64)>, io::Error> {
    match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => process_stat(&stat).map(Some),
        Err(error) if process_disappeared(&error) => Ok(None),
        Err(error) => Err(error),
    }
}

fn process_disappeared(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::InvalidInput
    )
}

fn deadline(runtime: &dyn RuntimeControl) -> Result<Instant, io::Error> {
    let budget = runtime
        .attempt_remaining_millis()
        .min(runtime.recovery_remaining_millis());
    if budget == 0 {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "endpoint broker has no runtime budget",
        ));
    }
    Instant::now()
        .checked_add(Duration::from_millis(budget))
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "endpoint deadline overflowed"))
}

fn reserve_public_port(
    requested_port: u16,
    reservations: &[(ResourceId, EndpointValue)],
) -> Result<PortReservations, io::Error> {
    for _ in 0..64 {
        let ipv4 = rustix::net::socket_with(
            rustix::net::AddressFamily::INET,
            rustix::net::SocketType::STREAM,
            rustix::net::SocketFlags::CLOEXEC,
            None,
        )?;
        rustix::net::bind(
            &ipv4,
            &SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, requested_port),
        )?;
        let public_port = SocketAddrV4::try_from(rustix::net::getsockname(&ipv4)?)
            .map_err(|_| invalid("IPv4 reservation returned another address family"))?
            .port();
        if reservations
            .iter()
            .any(|(_, endpoint)| endpoint.port == public_port)
        {
            if requested_port == 0 {
                continue;
            }
            return Err(invalid(
                "endpoint port is already reserved by the ownership ledger",
            ));
        }

        let ipv6 = rustix::net::socket_with(
            rustix::net::AddressFamily::INET6,
            rustix::net::SocketType::STREAM,
            rustix::net::SocketFlags::CLOEXEC,
            None,
        )?;
        rustix::net::sockopt::set_ipv6_v6only(&ipv6, true)?;
        match rustix::net::bind(
            &ipv6,
            &SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, public_port, 0, 0),
        ) {
            Ok(()) => {
                return Ok(PortReservations {
                    port: public_port,
                    _ipv4: ipv4,
                    _ipv6: ipv6,
                });
            }
            Err(error) if requested_port == 0 && error == rustix::io::Errno::ADDRINUSE => {}
            Err(error) => return Err(error.into()),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AddrInUse,
        "no dual-family endpoint port is available",
    ))
}

fn broker_port_is_available(spec: &BrokerSpec) -> Result<bool, io::Error> {
    let family = match spec.family {
        BrokerFamily::Ipv4 => rustix::net::AddressFamily::INET,
        BrokerFamily::Ipv6 => rustix::net::AddressFamily::INET6,
    };
    let socket = rustix::net::socket_with(
        family,
        rustix::net::SocketType::STREAM,
        rustix::net::SocketFlags::CLOEXEC,
        None,
    )?;
    let result = match spec.family {
        BrokerFamily::Ipv4 => rustix::net::bind(
            &socket,
            &SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, spec.public_port),
        ),
        BrokerFamily::Ipv6 => {
            rustix::net::sockopt::set_ipv6_v6only(&socket, true)?;
            rustix::net::bind(
                &socket,
                &SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, spec.public_port, 0, 0),
            )
        }
    };
    match result {
        Ok(()) => Ok(true),
        Err(rustix::io::Errno::ADDRINUSE) => Ok(false),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dual_family_reservation_excludes_competing_wildcard_binds() {
        let reservation = reserve_public_port(0, &[]).expect("reserve both address families");

        let ipv4 = rustix::net::socket(
            rustix::net::AddressFamily::INET,
            rustix::net::SocketType::STREAM,
            None,
        )
        .expect("create competing IPv4 socket");
        let ipv4_error = rustix::net::bind(
            &ipv4,
            &SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, reservation.port),
        )
        .expect_err("IPv4 wildcard must remain reserved");
        assert_eq!(ipv4_error, rustix::io::Errno::ADDRINUSE);

        let ipv6 = rustix::net::socket(
            rustix::net::AddressFamily::INET6,
            rustix::net::SocketType::STREAM,
            None,
        )
        .expect("create competing IPv6 socket");
        rustix::net::sockopt::set_ipv6_v6only(&ipv6, true).expect("force IPv6-only mode");
        let ipv6_error = rustix::net::bind(
            &ipv6,
            &SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, reservation.port, 0, 0),
        )
        .expect_err("IPv6 wildcard must remain reserved");
        assert_eq!(ipv6_error, rustix::io::Errno::ADDRINUSE);
    }

    #[test]
    fn broker_arguments_pin_ranges_and_aggregate_worker_bound() {
        assert_eq!(
            expected_listener_argument(BrokerFamily::Ipv4, 54321),
            "TCP4-LISTEN:54321,bind=0.0.0.0,reuseaddr,fork,range=127.0.0.0/8,max-children=32"
        );
        assert_eq!(
            expected_listener_argument(BrokerFamily::Ipv6, 54321),
            "TCP6-LISTEN:54321,bind=[::],ipv6only=1,reuseaddr,fork,range=[::1]/128,max-children=32"
        );
    }

    #[test]
    fn process_stat_extracts_state_group_and_start_ticks() {
        let stat = "42 (endpoint broker) S 1 42 42 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 987654";
        assert_eq!(
            process_stat(stat).expect("parse proc stat"),
            ('S', 42, 987654)
        );
    }

    #[test]
    fn broker_confinement_requires_empty_supplementary_groups() {
        let status = "Uid:\t7100\t7100\t7100\t7100\nGid:\t71\t71\t71\t71\nGroups:\t\nNoNewPrivs:\t1\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\n";
        require_process_ids(status, 7100, 71).expect("accept confined broker");

        let elevated = status.replace("Groups:\t\n", "Groups:\t71\n");
        assert!(require_process_ids(&elevated, 7100, 71).is_err());
    }
}
