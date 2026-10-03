//! Admits and rechecks only the Gateway's original fixed PID1 launch.
//!
//! Selectors in argv are immutable-unit DATA, never authority. The same pidfd,
//! cgroup anchor, executable, fragment and invocation survive every readback.
//! The sole existing Systemd, immutable-image, SELinux and credential engines
//! do the physical work. A retained procfs reader supplies advisory node-memory
//! admission, not a reservation or a hard all-node network-memory bound.

use std::fs::File;
use std::io::Read as _;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::fs::FileExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use aos_sandbox_linux::cgroup::{CgroupV2Root, RetainedCgroupAnchor};
use aos_sandbox_linux::guest_confinement::require_subject;
use aos_sandbox_linux::inherited_fd::duplicate_initial_activation_table;
use aos_sandbox_linux::pidfd::{PidFd, PidFdInfo};
use aos_sandbox_linux::selinux_policy::VerifiedLiveSelinuxPolicy;
use aos_systemd::{OwnedValue, SystemdClient, Value};
use rustix::fs::{CWD, Mode, OFlags, openat};
use rustix::net::{
    AddressFamily, Protocol, SocketFlags, SocketType, bind, getsockname, ipv6_v6only, listen,
    set_ipv6_v6only, socket_acceptconn, socket_cookie, socket_domain, socket_type, socket_with,
};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use crate::immutable_image::RetainedImmutableFileV1;
use crate::systemd_property_data;

use super::GitGatewayServiceErrorV1 as Error;

mod node_memory;

use node_memory::RetainedNodeMemoryObservationV1;

const RESIDENCY_PROFILE: &str = "service-memcg-observed-node-memory-v1";
const UNIT: &str = "aos-sandbox-git-gateway.service";
const USER: &str = "aos-git-gateway";
const CONTEXT: &str = "system_u:system_r:aos_sandbox_git_gateway_t";
const CGROUP: &str = "/system.slice/aos-sandbox-git-gateway.service";
const CREDENTIAL_DIRECTORY: &str = "/run/credentials/aos-sandbox-git-gateway.service";
pub(super) const MEMORY_MAX_BYTES: u64 = 1024 * 1024 * 1024;
const TASKS_MAX: u64 = 8;
const NOFILE_MAX: u64 = 128;
const LISTEN_BACKLOG: i32 = 2;
const READBACK_TIMEOUT: Duration = Duration::from_secs(5);
const MAXIMUM_EXECUTABLE_BYTES: u64 = 128 * 1024 * 1024;
const CREDENTIAL_NAMES: [&str; 4] = [
    "public-api-server-cert",
    "public-api-server-key",
    "public-api-client-ca",
    "public-api-principals",
];

const SERVICE_PROPERTIES: &[&str] = &[
    "ControlGroup", "Type", "Restart", "User", "Group", "DynamicUser",
    "SupplementaryGroups", "SELinuxContext", "CapabilityBoundingSet",
    "AmbientCapabilities", "NoNewPrivileges", "MemoryMax", "MemorySwapMax",
    "TasksMax", "LimitNOFILE", "LimitNOFILESoft", "CPUQuotaPerSecUSec",
    "CPUQuotaPeriodUSec", "ExecStart", "ExecStartPre", "ExecStartPost",
    "OpenFile", "ExtraFileDescriptorNames", "FileDescriptorStoreMax",
    "NFileDescriptorStore", "LoadCredential", "LoadCredentialEncrypted",
    "SetCredential", "SetCredentialEncrypted", "ImportCredential",
    "PrivateNetwork", "ProtectControlGroups", "ProtectSystem", "DevicePolicy",
    "RestrictNamespaces", "MemoryDenyWriteExecute", "UMask",
    "ReadWritePaths", "BindPaths", "StateDirectory", "RuntimeDirectory",
    "RestrictAddressFamilies", "PrivateDevices", "PrivateTmp", "ProtectHome",
    "ProtectProc", "ProtectKernelTunables", "ProtectKernelModules", "ProtectKernelLogs",
    "RestrictRealtime", "RestrictSUIDSGID", "LockPersonality", "LimitCORE", "LimitCORESoft",
    "ExecCondition", "ImportCredentialEx", "RootDirectory", "RootImage",
];
const UNIT_PROPERTIES: &[&str] = &["FragmentPath", "DropInPaths", "Transient", "InvocationID"];

struct SelectionV1 {
    arguments: [String; 7],
    endpoint: SocketAddr,
    uid: u32,
    gid: u32,
    minimum_observed_node_available_bytes: u64,
    delegation: Option<[String; 3]>,
}

impl SelectionV1 {
    fn from_environment() -> Result<Self, Error> {
        let mut arguments = std::env::args_os();
        let mut next = || {
            arguments
                .next()
                .and_then(|value| value.into_string().ok())
                .filter(|value| !value.is_empty() && value.len() <= 1024 && value.is_ascii())
                .ok_or(Error::Configuration)
        };
        let selected = [next()?, next()?, next()?, next()?, next()?, next()?, next()?];
        let mut selection = Self::decode(selected)?;
        if let Some(flag) = arguments.next() {
            let flag = flag.into_string().map_err(|_| Error::Configuration)?;
            let uid = arguments.next().and_then(|value| value.into_string().ok()).ok_or(Error::Configuration)?;
            let gid = arguments.next().and_then(|value| value.into_string().ok()).ok_or(Error::Configuration)?;
            if flag != "--read-scope-inspection" || arguments.next().is_some() {
                return Err(Error::Configuration);
            }
            let ids = [uid.parse::<u32>().map_err(|_| Error::Configuration)?,
                gid.parse::<u32>().map_err(|_| Error::Configuration)?];
            if ids.iter().any(|id| *id == 0 || *id >= 65536)
                || ids[0].to_string() != uid || ids[1].to_string() != gid
                || ids[0] == selection.uid || ids[1] == selection.gid
            { return Err(Error::Configuration); }
            selection.delegation = Some([flag, uid, gid]);
        }
        Ok(selection)
    }

    fn decode(arguments: [String; 7]) -> Result<Self, Error> {
        let endpoint = arguments[1].parse::<SocketAddr>().map_err(|_| Error::Configuration)?;
        let uid = arguments[2].parse::<u32>().map_err(|_| Error::Configuration)?;
        let gid = arguments[3].parse::<u32>().map_err(|_| Error::Configuration)?;
        let minimum_observed_node_available_bytes = arguments[6]
            .parse::<u64>()
            .map_err(|_| Error::Configuration)?;
        if endpoint.port() < 1024 || uid == 0 || gid == 0
            || !arguments[0].starts_with("/nix/store/")
            || !arguments[0].ends_with("/bin/aos-sandbox-git-gateway")
            || arguments[1] != endpoint.to_string()
            || arguments[2] != uid.to_string() || arguments[3] != gid.to_string()
            || !arguments[4].starts_with("/nix/store/")
            || !arguments[4].ends_with("/policy.33")
            || arguments[5] != RESIDENCY_PROFILE
            || arguments[6] != minimum_observed_node_available_bytes.to_string()
            || minimum_observed_node_available_bytes < MEMORY_MAX_BYTES
        {
            return Err(Error::Configuration);
        }
        Ok(Self {
            arguments,
            endpoint,
            uid,
            gid,
            minimum_observed_node_available_bytes,
            delegation: None,
        })
    }

    fn executable(&self) -> &Path {
        Path::new(&self.arguments[0])
    }

    fn policy_path(&self) -> &str {
        &self.arguments[4]
    }

    fn command_arguments(&self) -> std::borrow::Cow<'_, [String]> {
        match &self.delegation {
            None => std::borrow::Cow::Borrowed(&self.arguments),
            Some(additional) => std::borrow::Cow::Owned(
                self.arguments.iter().chain(additional).cloned().collect(),
            ),
        }
    }
}

/// Owns the physical launch readback before any runtime or credential open.
pub(super) struct GatewayStartupV1 {
    selection: SelectionV1,
    process: PidFd,
    _root: CgroupV2Root,
    cgroup: RetainedCgroupAnchor,
    executable: RetainedImmutableFileV1,
    node_memory: RetainedNodeMemoryObservationV1,
}

impl GatewayStartupV1 {
    pub(super) fn capture() -> Result<Self, Error> {
        // Direct bind has no inherited activation roles. LISTEN_* is not PID1
        // proof, and an empty declaration cannot hide a foreign descriptor.
        if ["LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"]
            .iter().any(|name| std::env::var_os(name).is_some())
        {
            return Err(Error::InheritedDescriptors);
        }
        duplicate_initial_activation_table(0).map_err(|_| Error::InheritedDescriptors)?;
        let selection = SelectionV1::from_environment()?;
        if std::env::var_os("CREDENTIALS_DIRECTORY")
            != Some(CREDENTIAL_DIRECTORY.into())
        {
            return Err(Error::Credentials);
        }

        let pid = NonZeroU32::new(std::process::id()).ok_or(Error::KernelEnvelope)?;
        let process = PidFd::open(pid).map_err(|_| Error::KernelEnvelope)?;
        let root = CgroupV2Root::from_owned(
            openat(CWD, "/sys/fs/cgroup", OFlags::PATH | OFlags::DIRECTORY
                | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty())
                .map_err(|_| Error::KernelEnvelope)?,
        ).map_err(|_| Error::KernelEnvelope)?;
        let cgroup = root.resolve(Path::new(CGROUP.trim_start_matches('/')))
            .map_err(|_| Error::KernelEnvelope)?;
        require_kernel_envelope(&selection, &process, &cgroup)?;
        require_subject(CONTEXT).map_err(|_| Error::Mac)?;

        let executable = RetainedImmutableFileV1::open_with_profile(
            selection.executable().to_owned(), None, MAXIMUM_EXECUTABLE_BYTES, true,
        ).map_err(|_| Error::Image)?;
        executable.require_executed(pid.get()).map_err(|_| Error::Image)?;
        require_kernel_envelope(&selection, &process, &cgroup)?;
        let node_memory = RetainedNodeMemoryObservationV1::capture()?;

        Ok(Self {
            selection,
            process,
            _root: root,
            cgroup,
            executable,
            node_memory,
        })
    }

    pub(super) async fn admit(self) -> Result<GatewayAdmissionV1, Error> {
        let manager = tokio::time::timeout(READBACK_TIMEOUT, SystemdClient::connect())
            .await.map_err(|_| Error::Service)?
            .map_err(|_| Error::Service)?;
        let original = observe(&manager, &self.selection).await?;
        let fragment = RetainedImmutableFileV1::observe_fragment(original.fragment.clone())
            .map_err(|_| Error::Image)?;
        let policy = VerifiedLiveSelinuxPolicy::verify(self.selection.policy_path())
            .map_err(|_| Error::Mac)?;

        let admitted = GatewayAdmissionV1 {
            startup: self,
            manager,
            original,
            fragment,
            policy,
            failure: Mutex::new(None),
        };
        admitted.recheck_original().await?;
        Ok(admitted)
    }
}

/// Keeps private launch custody, never a caller-constructible authority token.
pub(in crate::git) struct GatewayAdmissionV1 {
    startup: GatewayStartupV1,
    manager: SystemdClient,
    original: ServiceObservationV1,
    fragment: RetainedImmutableFileV1,
    policy: VerifiedLiveSelinuxPolicy,
    failure: Mutex<Option<Error>>,
}

impl GatewayAdmissionV1 {
    pub(super) async fn bind_listener(&self) -> Result<GatewayListenerV1, Error> {
        let mut failure = self.failure.lock().await;
        begin_gate(&mut failure)?;

        // Genuine service controls and the original advisory reader are joined
        // before socket(), bind(), listen() or acceptance. The observation does
        // not hold node capacity across this bookend and the next effect.
        let result = async {
            self.recheck_original().await?;
            let listener = GatewayListenerV1::bind(self.startup.selection.endpoint)?;
            self.recheck_original().await?;
            listener.recheck()?;
            Ok(listener)
        }.await;
        finish_gate(&mut failure, result)
    }

    pub(in crate::git) async fn recheck(&self) -> Result<(), Error> {
        let mut failure = self.failure.lock().await;
        // Cancellation/unwind while any fallible observation is in flight
        // leaves admission latched. The mutex serializes both fixed drivers.
        begin_gate(&mut failure)?;
        let result = self.recheck_original().await;
        finish_gate(&mut failure, result)
    }

    pub(in crate::git) fn original_invocation(&self) -> [u8; 16] {
        self.original.invocation
    }

    pub(in crate::git) fn delegation_controller_ids(&self) -> Option<(u32, u32)> {
        let selected = self.startup.selection.delegation.as_ref()?;
        Some((selected[1].parse().ok()?, selected[2].parse().ok()?))
    }

    async fn recheck_original(&self) -> Result<(), Error> {
        let retained = &self.startup;
        require_kernel_envelope(&retained.selection, &retained.process, &retained.cgroup)?;
        retained.node_memory.require_current(
            retained.selection.minimum_observed_node_available_bytes,
        )?;
        require_subject(CONTEXT).map_err(|_| Error::Mac)?;
        retained.executable.revalidate().map_err(|_| Error::Image)?;
        retained.executable.require_executed(std::process::id()).map_err(|_| Error::Image)?;
        self.fragment.revalidate().map_err(|_| Error::Image)?;
        self.policy.revalidate(retained.selection.policy_path()).map_err(|_| Error::Mac)?;
        let current = observe(&self.manager, &retained.selection).await?;
        if current != self.original {
            return Err(Error::Service);
        }
        if std::env::var_os("CREDENTIALS_DIRECTORY") != Some(CREDENTIAL_DIRECTORY.into()) {
            return Err(Error::Credentials);
        }

        self.fragment.revalidate().map_err(|_| Error::Image)?;
        retained.executable.revalidate().map_err(|_| Error::Image)?;
        retained.executable.require_executed(std::process::id()).map_err(|_| Error::Image)?;
        require_subject(CONTEXT).map_err(|_| Error::Mac)?;
        require_kernel_envelope(&retained.selection, &retained.process, &retained.cgroup)?;
        retained.node_memory.require_current(
            retained.selection.minimum_observed_node_available_bytes,
        )
    }
}

// Both serialized callers reject the first failure before reading any sample.
fn begin_gate(failure: &mut Option<Error>) -> Result<(), Error> {
    if let Some(cause) = *failure {
        return Err(cause);
    }
    *failure = Some(Error::Interrupted);
    Ok(())
}

// Called only by an armed original gate after its closed-entry check. It
// cannot reopen a previously failed owner or construct admission from DATA.
fn finish_gate<T>(failure: &mut Option<Error>, result: Result<T, Error>) -> Result<T, Error> {
    match result {
        Ok(value) => {
            *failure = None;
            Ok(value)
        }
        Err(cause) => {
            *failure = Some(cause);
            Err(cause)
        }
    }
}

#[derive(Eq, PartialEq)]
struct ServiceObservationV1 {
    fragment: PathBuf,
    invocation: [u8; 16],
}

async fn observe(manager: &SystemdClient, selection: &SelectionV1) -> Result<ServiceObservationV1, Error> {
    let (service, unit) = tokio::time::timeout(
        READBACK_TIMEOUT,
        manager.observe_pid1_service_startup_properties(
            UNIT, std::process::id(), SERVICE_PROPERTIES, UNIT_PROPERTIES,
        ),
    ).await.map_err(|_| Error::Service)?.map_err(|_| Error::Service)?;
    decode_delivery(&service, &unit, selection, std::process::id())
}

fn decode_delivery(
    service: &[OwnedValue],
    unit: &[OwnedValue],
    selection: &SelectionV1,
    pid: u32,
) -> Result<ServiceObservationV1, Error> {
    require_service_delivery(service, selection, pid)?;

    let [fragment, drop_ins, transient, invocation] = unit else {
        return Err(Error::Service);
    };
    let path = <&str>::try_from(fragment).map_err(|_| Error::Service)?;
    if path.len() > 1024 || !path.ends_with(&format!("/{UNIT}"))
        || !empty_array(drop_ins) || bool::try_from(transient).ok() != Some(false)
    {
        return Err(Error::Service);
    }
    let Value::Array(invocation) = &**invocation else {
        return Err(Error::Service);
    };
    let id = systemd_property_data::nonzero_invocation_bytes(invocation.inner())
        .ok_or(Error::Service)?;

    let fragment = std::fs::canonicalize(path).map_err(|_| Error::Image)?;
    if !fragment.starts_with("/nix/store") || !fragment.ends_with(UNIT) {
        return Err(Error::Image);
    }
    Ok(ServiceObservationV1 {
        fragment,
        invocation: id,
    })
}

fn require_service_delivery(
    service: &[OwnedValue],
    selection: &SelectionV1,
    pid: u32,
) -> Result<(), Error> {
    let [
        cgroup, kind, restart, user, group, dynamic, supplementary, context,
        bounding, ambient, nnp, memory, swap, tasks, nofile, nofile_soft,
        cpu, cpu_period, start, pre, post, open_files, extras, store_max, stored,
        credentials, encrypted, inline, inline_encrypted, imported,
        private_network, protect_cgroups, protect_system, devices, namespaces,
        deny_wx, umask,
        write_paths, bind_paths, state_directories, runtime_directories,
        address_families, private_devices, private_tmp, protect_home,
        protect_proc, protect_tunables, protect_modules, protect_logs,
        realtime, suid, personality, core, core_soft,
        conditions, imported_ex, root_directory, root_image,
    ] = service else {
        return Err(Error::Service);
    };
    if <&str>::try_from(cgroup).ok() != Some(CGROUP)
        || <&str>::try_from(kind).ok() != Some("exec")
        || <&str>::try_from(restart).ok() != Some("no")
        || <&str>::try_from(user).ok() != Some(USER)
        || <&str>::try_from(group).ok() != Some(USER)
        || bool::try_from(dynamic).ok() != Some(false)
        || !empty_array(supplementary) || !exact_context(context)
        || u64::try_from(bounding).ok() != Some(0)
        || u64::try_from(ambient).ok() != Some(0)
        || bool::try_from(nnp).ok() != Some(true)
        || u64::try_from(memory).ok() != Some(MEMORY_MAX_BYTES)
        || u64::try_from(swap).ok() != Some(0)
        || u64::try_from(tasks).ok() != Some(TASKS_MAX)
        || u64::try_from(nofile).ok() != Some(NOFILE_MAX)
        || u64::try_from(nofile_soft).ok() != Some(NOFILE_MAX)
        || u64::try_from(cpu).ok() != Some(1_000_000)
        || u64::try_from(cpu_period).ok() != Some(100_000)
        || !exact_command(start, &selection.command_arguments(), pid)
        || !empty_array(pre) || !empty_array(post)
        || !empty_array(open_files) || !empty_array(extras)
        || u32::try_from(store_max).ok() != Some(0)
        || u32::try_from(stored).ok() != Some(0)
        || !exact_credentials(credentials)
        || !empty_array(encrypted) || !empty_array(inline)
        || !empty_array(inline_encrypted) || !empty_array(imported)
        || bool::try_from(private_network).ok() != Some(false)
        || bool::try_from(protect_cgroups).ok() != Some(true)
        || <&str>::try_from(protect_system).ok() != Some("strict")
        || <&str>::try_from(devices).ok() != Some("closed")
        || u64::try_from(namespaces).ok() != Some(0)
        || bool::try_from(deny_wx).ok() != Some(true)
        || u32::try_from(umask).ok() != Some(0o077)
        || !empty_array(write_paths) || !empty_array(bind_paths)
        || !empty_array(state_directories) || !empty_array(runtime_directories)
        || !exact_address_families(address_families)
        || bool::try_from(private_devices).ok() != Some(true)
        || bool::try_from(private_tmp).ok() != Some(true)
        || <&str>::try_from(protect_home).ok() != Some("yes")
        || <&str>::try_from(protect_proc).ok() != Some(
            if selection.delegation.is_some() { "default" } else { "invisible" },
        )
        || bool::try_from(protect_tunables).ok() != Some(true)
        || bool::try_from(protect_modules).ok() != Some(true)
        || bool::try_from(protect_logs).ok() != Some(true)
        || bool::try_from(realtime).ok() != Some(true)
        || bool::try_from(suid).ok() != Some(true)
        || bool::try_from(personality).ok() != Some(true)
        || u64::try_from(core).ok() != Some(0)
        || u64::try_from(core_soft).ok() != Some(0)
        || !empty_array(conditions) || !empty_array(imported_ex)
        || <&str>::try_from(root_directory).ok() != Some("")
        || <&str>::try_from(root_image).ok() != Some("")
    {
        return Err(Error::Service);
    }

    Ok(())
}

fn empty_array(value: &OwnedValue) -> bool {
    matches!(&**value, Value::Array(values) if values.is_empty())
}

fn exact_context(value: &OwnedValue) -> bool {
    systemd_property_data::explicit_context(value) == Some(CONTEXT)
}

fn exact_address_families(value: &OwnedValue) -> bool {
    let Value::Structure(value) = &**value else {
        return false;
    };
    let [Value::Bool(true), Value::Array(families)] = value.fields() else {
        return false;
    };
    let expected = ["AF_UNIX", "AF_INET", "AF_INET6"];
    let mut found = [false; 3];
    for family in families.inner() {
        let Value::Str(family) = family else {
            return false;
        };
        let Some(index) = expected.iter().position(|value| *value == family.as_str()) else {
            return false;
        };
        if found[index] {
            return false;
        }
        found[index] = true;
    }
    found == [true; 3]
}

fn exact_command(value: &OwnedValue, arguments: &[String], pid: u32) -> bool {
    let Some(command) = systemd_property_data::single_exec_start(value) else {
        return false;
    };

    command.path == arguments[0] && command.pid == pid && command.argv.len() == arguments.len()
        && command.argv.iter().zip(arguments).all(|(value, expected)| {
            matches!(value, Value::Str(value) if value.as_str() == expected)
        })
}

fn exact_credentials(value: &OwnedValue) -> bool {
    let Value::Array(entries) = &**value else {
        return false;
    };
    if entries.len() != CREDENTIAL_NAMES.len() {
        return false;
    }
    let mut found = [false; 4];
    for entry in entries.inner() {
        let Value::Structure(entry) = entry else {
            return false;
        };
        let [Value::Str(name), Value::Str(source)] = entry.fields() else {
            return false;
        };
        let Some(index) = CREDENTIAL_NAMES.iter().position(|expected| *expected == name.as_str()) else {
            return false;
        };
        let Some(source) = source.as_str().strip_prefix("/run/credentials/@system/") else {
            return false;
        };
        if found[index] || source.is_empty() || source.len() > 255
            || !source.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
        {
            return false;
        }
        found[index] = true;
    }
    found == [true; 4]
}

fn require_kernel_envelope(
    selection: &SelectionV1,
    process: &PidFd,
    cgroup: &RetainedCgroupAnchor,
) -> Result<(), Error> {
    require_identity(cgroup.verify_exact_membership(process).map_err(|_| Error::KernelEnvelope)?, selection)?;
    let limit = rustix::process::getrlimit(rustix::process::Resource::Nofile);
    if limit.current != Some(NOFILE_MAX) || limit.maximum != Some(NOFILE_MAX) {
        return Err(Error::KernelEnvelope);
    }
    for (name, expected) in [
        ("memory.max", "1073741824\n"),
        ("memory.swap.max", "0\n"),
        ("pids.max", "8\n"),
        ("cpu.max", "100000 100000\n"),
    ] {
        let actual = read_limit(cgroup, name)?;
        if actual != expected {
            return Err(Error::KernelEnvelope);
        }
    }
    require_process_status(selection.gid)?;
    require_identity(cgroup.verify_exact_membership(process).map_err(|_| Error::KernelEnvelope)?, selection)
}

fn require_identity(info: PidFdInfo, selection: &SelectionV1) -> Result<(), Error> {
    let credentials = info.credentials().ok_or(Error::KernelEnvelope)?;
    if info.pid() != std::process::id() || info.thread_group_id() != std::process::id()
        || info.parent_pid() != 1
        || [credentials.real_user_id(), credentials.effective_user_id(),
            credentials.saved_user_id(), credentials.filesystem_user_id()] != [selection.uid; 4]
        || [credentials.real_group_id(), credentials.effective_group_id(),
            credentials.saved_group_id(), credentials.filesystem_group_id()] != [selection.gid; 4]
    {
        return Err(Error::KernelEnvelope);
    }
    Ok(())
}

fn read_limit(cgroup: &RetainedCgroupAnchor, name: &str) -> Result<String, Error> {
    let file = File::from(openat(
        cgroup.as_fd(), name, OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    ).map_err(|_| Error::KernelEnvelope)?);
    let mut bytes = [0; 65];
    let length = file.read_at(&mut bytes, 0).map_err(|_| Error::KernelEnvelope)?;
    if length == 0 || length == bytes.len() {
        return Err(Error::KernelEnvelope);
    }
    String::from_utf8(bytes[..length].to_vec()).map_err(|_| Error::KernelEnvelope)
}

fn require_process_status(gid: u32) -> Result<(), Error> {
    let file = File::from(openat(
        CWD, "/proc/thread-self/status",
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    ).map_err(|_| Error::KernelEnvelope)?);
    let mut file = file;
    let mut bytes = [0; 16 * 1024 + 1];
    let mut length = 0;
    loop {
        if length == bytes.len() {
            return Err(Error::KernelEnvelope);
        }
        let read = file.read(&mut bytes[length..]).map_err(|_| Error::KernelEnvelope)?;
        if read == 0 {
            break;
        }
        length += read;
    }
    let status = std::str::from_utf8(&bytes[..length]).map_err(|_| Error::KernelEnvelope)?;
    require_status_data(status, gid)
}

fn require_status_data(status: &str, gid: u32) -> Result<(), Error> {
    let mut seen = [false; 7];
    for line in status.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let index = match name {
            "CapEff" => 0,
            "CapBnd" => 1,
            "CapAmb" => 2,
            "CapPrm" => 3,
            "CapInh" => 4,
            "NoNewPrivs" => 5,
            "Groups" => 6,
            _ => continue,
        };
        if seen[index] {
            return Err(Error::KernelEnvelope);
        }
        seen[index] = true;
        let accepted = match index {
            0..=4 => u64::from_str_radix(value.trim(), 16).ok() == Some(0),
            5 => value.trim() == "1",
            _ => value.split_whitespace().all(|group| group.parse::<u32>().ok() == Some(gid)),
        };
        if !accepted {
            return Err(Error::KernelEnvelope);
        }
    }
    if seen != [true; 7] {
        return Err(Error::KernelEnvelope);
    }
    Ok(())
}

/// Retains the same real listening socket, independent of any peer owner.
pub(super) struct GatewayListenerV1 {
    listener: TcpListener,
    pin: OwnedFd,
    endpoint: SocketAddr,
    cookie: u64,
}

impl GatewayListenerV1 {
    fn bind(endpoint: SocketAddr) -> Result<Self, Error> {
        let domain = if endpoint.is_ipv4() { AddressFamily::INET } else { AddressFamily::INET6 };
        let socket = socket_with(
            domain, SocketType::STREAM, SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            Some(Protocol::TCP),
        ).map_err(|_| Error::Listener)?;
        if endpoint.is_ipv6() {
            // One selected family, not an implicit IPv4-mapped second ingress.
            set_ipv6_v6only(&socket, true).map_err(|_| Error::Listener)?;
        }
        // No reuse-address, alternate endpoint or DNS fallback is selected.
        bind(&socket, &endpoint).map_err(|_| Error::Listener)?;
        listen(&socket, LISTEN_BACKLOG).map_err(|_| Error::Listener)?;
        let cookie = socket_cookie(&socket).map_err(|_| Error::Listener)?;
        if cookie == 0 {
            return Err(Error::Listener);
        }
        let pin = rustix::io::fcntl_dupfd_cloexec(&socket, 64).map_err(|_| Error::Listener)?;
        let listener = TcpListener::from_std(std::net::TcpListener::from(socket))
            .map_err(|_| Error::Listener)?;
        let admitted = Self {
            listener,
            pin,
            endpoint,
            cookie,
        };
        admitted.recheck()?;
        Ok(admitted)
    }

    pub(super) fn listener(&self) -> &TcpListener {
        &self.listener
    }

    pub(super) fn recheck(&self) -> Result<(), Error> {
        let domain = if self.endpoint.is_ipv4() { AddressFamily::INET } else { AddressFamily::INET6 };
        for fd in [self.pin.as_fd(), self.listener.as_fd()] {
            if socket_type(fd).map_err(|_| Error::Listener)? != SocketType::STREAM
                || socket_domain(fd).map_err(|_| Error::Listener)? != domain
                || !socket_acceptconn(fd).map_err(|_| Error::Listener)?
                || socket_cookie(fd).map_err(|_| Error::Listener)? != self.cookie
                || self.endpoint.is_ipv6() && !ipv6_v6only(fd).map_err(|_| Error::Listener)?
                || SocketAddr::try_from(getsockname(fd).map_err(|_| Error::Listener)?)
                    .map_err(|_| Error::Listener)? != self.endpoint
            {
                return Err(Error::Listener);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value(value: impl Into<Value<'static>>) -> OwnedValue {
        OwnedValue::try_from(value.into()).unwrap()
    }

    // Pure PID1 property DATA exercises the private comparison engine only.
    // It cannot construct admission, an immutable file, pidfd or live listener.
    fn service_data(selection: &SelectionV1, pid: u32) -> Vec<OwnedValue> {
        SERVICE_PROPERTIES.iter().map(|name| match *name {
            "ControlGroup" => value(CGROUP),
            "Type" => value("exec"),
            "Restart" => value("no"),
            "User" | "Group" => value(USER),
            "SELinuxContext" => value((false, CONTEXT)),
            "ProtectSystem" => value("strict"),
            "DevicePolicy" => value("closed"),
            "ProtectHome" => value("yes"),
            "ProtectProc" => value("invisible"),
            "RootDirectory" | "RootImage" => value(""),
            "MemoryMax" => OwnedValue::from(MEMORY_MAX_BYTES),
            "MemorySwapMax" | "CapabilityBoundingSet" | "AmbientCapabilities"
            | "RestrictNamespaces" | "LimitCORE" | "LimitCORESoft" => OwnedValue::from(0_u64),
            "TasksMax" => OwnedValue::from(TASKS_MAX),
            "LimitNOFILE" | "LimitNOFILESoft" => OwnedValue::from(NOFILE_MAX),
            "CPUQuotaPerSecUSec" => OwnedValue::from(1_000_000_u64),
            "CPUQuotaPeriodUSec" => OwnedValue::from(100_000_u64),
            "UMask" => OwnedValue::from(0o077_u32),
            "FileDescriptorStoreMax" | "NFileDescriptorStore" => OwnedValue::from(0_u32),
            "DynamicUser" | "PrivateNetwork" => OwnedValue::from(false),
            "NoNewPrivileges" | "ProtectControlGroups" | "MemoryDenyWriteExecute"
            | "PrivateDevices" | "PrivateTmp" | "ProtectKernelTunables"
            | "ProtectKernelModules" | "ProtectKernelLogs" | "RestrictRealtime"
            | "RestrictSUIDSGID" | "LockPersonality" => OwnedValue::from(true),
            "ExecStart" => value(vec![(
                selection.arguments[0].clone(), selection.arguments.to_vec(), false,
                0_u64, 0_u64, 0_u64, 0_u64, pid, 0_i32, 0_i32,
            )]),
            "LoadCredential" => value(CREDENTIAL_NAMES.iter().map(|name| {
                (name.to_string(), format!("/run/credentials/@system/{name}"))
            }).collect::<Vec<_>>()),
            "RestrictAddressFamilies" => value((true, vec!["AF_UNIX", "AF_INET", "AF_INET6"])),
            "SupplementaryGroups" | "ExecStartPre" | "ExecStartPost" | "OpenFile"
            | "ExtraFileDescriptorNames" | "LoadCredentialEncrypted" | "SetCredential"
            | "SetCredentialEncrypted" | "ImportCredential" | "ReadWritePaths"
            | "BindPaths" | "StateDirectory" | "RuntimeDirectory" | "ExecCondition"
            | "ImportCredentialEx" => value(Vec::<String>::new()),
            unknown => panic!("fixture has no selected property: {unknown}"),
        }).collect()
    }

    #[test]
    fn closed_service_data_requires_exact_selected_launch_and_hard_limits() {
        let selected = selection("127.0.0.1:8443").unwrap();
        let data = service_data(&selected, 7);
        assert!(require_service_delivery(&data, &selected, 7).is_ok());

        for (name, replacement) in [
            ("MemoryMax", OwnedValue::from(u64::MAX)),
            ("MemorySwapMax", OwnedValue::from(1_u64)),
            ("TasksMax", OwnedValue::from(9_u64)),
            ("LimitNOFILESoft", OwnedValue::from(129_u64)),
            ("CPUQuotaPerSecUSec", OwnedValue::from(2_000_000_u64)),
            ("CapabilityBoundingSet", OwnedValue::from(1_u64)),
            ("NoNewPrivileges", OwnedValue::from(false)),
            ("RestrictNamespaces", OwnedValue::from(1_u64)),
            ("User", value("aos-sandboxd")),
            ("PrivateNetwork", OwnedValue::from(true)),
        ] {
            let mut changed = service_data(&selected, 7);
            let index = SERVICE_PROPERTIES.iter().position(|actual| *actual == name).unwrap();
            changed[index] = replacement;
            assert_eq!(require_service_delivery(&changed, &selected, 7), Err(Error::Service), "{name}");
        }
        assert_eq!(require_service_delivery(&data, &selected, 8), Err(Error::Service));
    }

    #[test]
    fn credential_delivery_refuses_duplicates_foreign_sources_and_extra_routes() {
        let selected = selection("127.0.0.1:8443").unwrap();
        for entries in [
            vec![("public-api-server-cert".to_owned(), "/run/credentials/@system/cert".to_owned()); 4],
            CREDENTIAL_NAMES.iter().map(|name| {
                (name.to_string(), format!("/unselected/{name}"))
            }).collect(),
        ] {
            assert!(!exact_credentials(&value(entries)));
        }

        let mut changed = service_data(&selected, 7);
        let index = SERVICE_PROPERTIES.iter().position(|name| *name == "ImportCredential").unwrap();
        changed[index] = value(vec!["*"]);
        assert_eq!(require_service_delivery(&changed, &selected, 7), Err(Error::Service));
    }

    #[test]
    fn service_data_refuses_writable_paths_and_family_widening() {
        let selected = selection("127.0.0.1:8443").unwrap();
        for name in ["ReadWritePaths", "StateDirectory", "SupplementaryGroups", "ExecCondition"] {
            let mut changed = service_data(&selected, 7);
            let index = SERVICE_PROPERTIES.iter().position(|actual| *actual == name).unwrap();
            changed[index] = value(vec!["foreign"]);
            assert_eq!(require_service_delivery(&changed, &selected, 7), Err(Error::Service), "{name}");
        }

        assert!(!exact_address_families(&value((false, vec!["AF_UNIX", "AF_INET", "AF_INET6"]))));
        assert!(!exact_address_families(&value((true, vec!["AF_UNIX", "AF_INET", "AF_INET6", "AF_PACKET"]))));
        assert!(!exact_address_families(&value((true, vec!["AF_UNIX", "AF_INET", "AF_INET"]))));
    }

    fn selection(endpoint: &str) -> Result<SelectionV1, Error> {
        SelectionV1::decode([
            "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-aos-sandboxd-1/bin/aos-sandbox-git-gateway".into(),
            endpoint.into(), "980".into(), "980".into(),
            "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-aos-selinux-kernel-policy-readback-1/policy.33".into(),
            RESIDENCY_PROFILE.into(), MEMORY_MAX_BYTES.to_string(),
        ])
    }

    #[test]
    fn direct_endpoint_rejects_dns_zero_privileged_and_noncanonical_forms() {
        for endpoint in ["localhost:8443", "127.0.0.1:0", "127.0.0.1:443", "127.0.0.1:08443"] {
            assert!(selection(endpoint).is_err(), "{endpoint}");
        }
        assert!(selection("127.0.0.1:8443").is_ok());
        assert!(selection("[::1]:8443").is_ok());
    }

    #[test]
    fn fixed_role_rejects_root_identity_and_sibling_executable() {
        let mut selected = selection("127.0.0.1:8443").unwrap().arguments;
        selected[2] = "0".into();
        assert!(SelectionV1::decode(selected.clone()).is_err());
        selected[2] = "980".into();
        selected[0] = selected[0].replace("aos-sandbox-git-gateway", "aos-sandboxd");
        assert!(SelectionV1::decode(selected).is_err());
    }

    #[test]
    fn status_refuses_effective_capability_and_foreign_group() {
        let status = concat!(
            "CapEff:\t0000000000000000\nCapBnd:\t0000000000000000\n",
            "CapAmb:\t0000000000000000\nCapPrm:\t0000000000000000\n",
            "CapInh:\t0000000000000000\nNoNewPrivs:\t1\nGroups:\t980\n",
        );
        assert!(require_status_data(status, 980).is_ok());
        assert!(require_status_data(&status.replace("Groups:\t980", "Groups:\t980 981"), 980).is_err());
        let effective = status.replace("CapEff:\t0000000000000000", "CapEff:\t0000000000000001");
        let permitted = status.replace("CapPrm:\t0000000000000000", "CapPrm:\t0000000000000001");
        assert!(require_status_data(&effective, 980).is_err());
        assert!(require_status_data(&permitted, 980).is_err());
        assert!(require_status_data(&status.replace("NoNewPrivs:\t1", "NoNewPrivs:\t0"), 980).is_err());
    }

    #[test]
    fn status_refuses_missing_or_duplicate_selected_fields() {
        let status = "CapEff: 0\nCapBnd: 0\nCapAmb: 0\nCapPrm: 0\nCapInh: 0\nNoNewPrivs: 1\nGroups:\n";
        assert!(require_status_data(status, 980).is_ok());
        assert!(require_status_data(&status.replace("CapAmb: 0\n", ""), 980).is_err());
        assert!(require_status_data(&format!("{status}CapEff: 0\n"), 980).is_err());
    }

    #[test]
    fn armed_readback_records_its_result_without_constructing_an_owner() {
        let mut failed = Some(Error::Interrupted);
        let result: Result<(), Error> = Err(Error::NodeMemoryPressure);

        assert_eq!(finish_gate(&mut failed, result), result);
        assert_eq!(failed, Some(Error::NodeMemoryPressure));

        // Only an already-armed original caller reaches this success branch.
        let mut successful = Some(Error::Interrupted);
        assert_eq!(finish_gate(&mut successful, Ok(())), Ok(()));
        assert_eq!(successful, None);
    }

    #[test]
    fn observed_node_profile_requires_canonical_explicit_minimum() {
        let original = selection("127.0.0.1:8443").unwrap().arguments;
        for (index, replacement) in [
            (5, ""),
            (5, "hard-isolated-residency"),
            (5, "all-kernel-network-memory"),
            (6, ""),
            (6, "0"),
            (6, "1073741823"),
            (6, "01073741824"),
            (6, "+1073741824"),
            (6, "18446744073709551616"),
        ] {
            let mut changed = original.clone();
            changed[index] = replacement.into();

            assert!(SelectionV1::decode(changed).is_err(), "{replacement}");
        }

        let selected = SelectionV1::decode(original).unwrap();
        assert_eq!(
            selected.minimum_observed_node_available_bytes,
            MEMORY_MAX_BYTES,
        );
    }

    #[test]
    fn original_pid1_command_binds_profile_and_threshold() {
        let original = selection("127.0.0.1:8443").unwrap();
        let data = service_data(&original, 7);

        for index in [5, 6] {
            let mut changed = original.arguments.clone();
            changed[index] = if index == 5 {
                "foreign-profile".into()
            } else {
                (MEMORY_MAX_BYTES + 1).to_string()
            };
            let start = SERVICE_PROPERTIES
                .iter()
                .position(|name| *name == "ExecStart")
                .unwrap();

            assert!(!exact_command(&data[start], &changed, 7));
        }
    }

    #[test]
    fn failed_or_interrupted_gate_cannot_read_a_favorable_sample() {
        for cause in [
            Error::NodeMemoryObservation,
            Error::NodeMemoryPressure,
            Error::Interrupted,
        ] {
            let mut first_failure = Some(cause);

            assert_eq!(begin_gate(&mut first_failure), Err(cause));
            assert_eq!(first_failure, Some(cause));
        }

        let mut open = None;
        assert_eq!(begin_gate(&mut open), Ok(()));
        assert_eq!(open, Some(Error::Interrupted));
    }
}
