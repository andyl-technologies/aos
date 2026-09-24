//! Fixed shifted-userns target and privileged phase-0 pidfs inspector.
//!
//! PID 1 runs `target` under `PrivateUsers=managed`. A distinct fixed inspector
//! with only CAP_SYS_PTRACE pins that service through PID 1, its exact cgroup,
//! and pidfs, verifies the target's kernel hardening, then signs one
//! boot/package-bound AOSHPB02 observation. The
//! result does not attest nspawn's payload seccomp filter or enable launch.

use std::env;
use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::num::NonZeroU32;
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use aos_sandbox_host::phase0_probe::{Phase0ProbeObservationV2, SignedPhase0ProbeRecordV2};
use aos_sandbox_host::phase0_probe::{
    verified_packaged_hostd_digest, verified_packaged_inspector_digest,
};
use aos_sandbox_host::plan::{VerifiedLiveSelinuxPolicyV1, verified_packaged_nspawn_digest};
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::cgroup::CgroupV2Root;
use aos_sandbox_linux::pidfd::{NamespaceKind, PidFd};
use aos_systemd::{OwnedValue, SystemdClient};
use ed25519_dalek::SigningKey;
use rustix::fs::{Mode, OFlags, open};
use zeroize::Zeroizing;

const TARGET_SERVICE: &str = "aos-sandbox-host-phase0-target.service";
const RESULT_DIRECTORY: &str = "/var/lib/aos/sandbox-host-phase0";
const RESULT_FILE: &str = "probe-v2";
const SIGNING_SEED_CREDENTIAL: &str = "phase0-probe-signing-seed-v1";
const PUBLIC_KEY_CREDENTIAL: &str = "phase0-probe-public-key-v1";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("aos-sandbox-host-phase0-probe: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut arguments = env::args();
    let _program = arguments.next();
    match (
        arguments.next().as_deref(),
        arguments.next(),
        arguments.next(),
        arguments.next(),
    ) {
        (Some("target"), None, None, None) => {
            std::thread::sleep(Duration::from_secs(60));
            Ok(())
        }
        (Some("inspect"), Some(nspawn_path), Some(hostd_path), Some(selinux_policy)) => {
            if !rustix::process::getuid().is_root() || !rustix::process::geteuid().is_root() {
                return Err("inspector requires root identity".to_owned());
            }
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| error.to_string())?;
            runtime.block_on(inspect(&nspawn_path, &hostd_path, &selinux_policy))
        }
        _ => Err("expected fixed target or inspect mode".to_owned()),
    }
}

async fn inspect(nspawn_path: &str, hostd_path: &str, selinux_policy: &str) -> Result<(), String> {
    let boot_id = KernelBootId::current()
        .map(KernelBootId::into_bytes)
        .map_err(|error| error.to_string())?;
    let nspawn_sha256 =
        verified_packaged_nspawn_digest(nspawn_path).map_err(|error| error.to_string())?;
    let hostd_sha256 =
        verified_packaged_hostd_digest(Path::new(hostd_path)).map_err(|error| error.to_string())?;
    let inspector_path = env::current_exe().map_err(|error| error.to_string())?;
    let inspector_sha256 =
        verified_packaged_inspector_digest(&inspector_path).map_err(|error| error.to_string())?;
    let selinux_policy_sha256 = VerifiedLiveSelinuxPolicyV1::verify(selinux_policy)
        .map(VerifiedLiveSelinuxPolicyV1::digest)
        .map_err(|error| error.to_string())?;
    let client = SystemdClient::connect()
        .await
        .map_err(|error| error.to_string())?;
    let service = client
        .observe_service_control_group(TARGET_SERVICE)
        .await
        .map_err(|error| error.to_string())?;
    let properties = client
        .observe_pid1_service_properties(
            TARGET_SERVICE,
            service.main_pid.get(),
            &[
                "NoNewPrivileges",
                "PrivateNetwork",
                "PrivateDevices",
                "ProtectSystem",
            ],
        )
        .await
        .map_err(|error| error.to_string())?;
    verify_target_unit_hardening(&properties)?;

    let target = PidFd::open(service.main_pid).map_err(|error| error.to_string())?;
    let target_before = target.info().map_err(|error| error.to_string())?;
    if target_before.pid() != service.main_pid.get()
        || target_before.thread_group_id() != service.main_pid.get()
        || target_before.parent_pid() != 1
    {
        return Err("fixed shifted target is not PID 1's main process".to_owned());
    }
    let cgroup =
        CgroupV2Root::from_owned(open_cgroup_root()?).map_err(|error| error.to_string())?;
    let relative_cgroup = service
        .control_group
        .strip_prefix('/')
        .ok_or_else(|| "target cgroup is not absolute".to_owned())?;
    let anchor = cgroup
        .resolve(Path::new(relative_cgroup))
        .map_err(|error| error.to_string())?;
    let membership = anchor
        .verify_exact_membership(&target)
        .map_err(|error| error.to_string())?;
    let cgroup_id = membership
        .cgroup_id()
        .ok_or_else(|| "target cgroup ID is absent".to_owned())?;

    let own_pid = u32::try_from(rustix::process::getpid().as_raw_nonzero().get())
        .map_err(|_| "inspector PID is invalid".to_owned())?;
    let own_pid = NonZeroU32::new(own_pid).ok_or_else(|| "inspector PID is zero".to_owned())?;
    let own_user = PidFd::open(own_pid)
        .and_then(|process| process.namespace(NamespaceKind::User))
        .map_err(|error| error.to_string())?;
    let user = target
        .namespace(NamespaceKind::User)
        .map_err(|error| error.to_string())?;
    let mount = target
        .namespace(NamespaceKind::Mount)
        .map_err(|error| error.to_string())?;
    let network = target
        .namespace(NamespaceKind::Network)
        .map_err(|error| error.to_string())?;
    let pid = target
        .namespace(NamespaceKind::Pid)
        .map_err(|error| error.to_string())?;
    if user.identity() == own_user.identity() {
        return Err("target is not in a shifted user namespace".to_owned());
    }
    let (host_uid_start, uid_count) = read_id_map(service.main_pid, "uid_map")?;
    let (host_gid_start, gid_count) = read_id_map(service.main_pid, "gid_map")?;
    if uid_count != gid_count || uid_count < 65_536 {
        return Err("shifted target identity range is too small".to_owned());
    }
    verify_target_status(&read_target_status(service.main_pid)?)?;

    let target_after = target.info().map_err(|error| error.to_string())?;
    verify_target_status(&read_target_status(service.main_pid)?)?;
    if target_before != target_after
        || anchor
            .verify_exact_membership(&target)
            .map_err(|error| error.to_string())?
            != membership
        || !target.is_alive().map_err(|error| error.to_string())?
        || client
            .observe_service_control_group(TARGET_SERVICE)
            .await
            .map_err(|error| error.to_string())?
            != service
    {
        return Err("shifted target changed during pidfs inspection".to_owned());
    }

    let observation = Phase0ProbeObservationV2 {
        boot_id,
        nspawn_sha256,
        hostd_sha256,
        inspector_sha256,
        selinux_policy_sha256,
        target_pid: service.main_pid.get(),
        host_uid_start,
        host_gid_start,
        mapping_count: uid_count,
        cgroup_id,
        user: user.identity(),
        mount: mount.identity(),
        network: network.identity(),
        pid: pid.identity(),
    };
    let key = load_signing_key()?;
    let report =
        SignedPhase0ProbeRecordV2::sign(observation, &key).map_err(|error| error.to_string())?;
    publish_report(&report.encode())
}

fn open_cgroup_root() -> Result<OwnedFd, String> {
    open(
        "/sys/fs/cgroup",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| error.to_string())
}

fn read_id_map(pid: NonZeroU32, name: &str) -> Result<(u32, u32), String> {
    let path = format!("/proc/{pid}/{name}");
    let descriptor = open(
        &path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| error.to_string())?;
    let mut bytes = Vec::new();
    File::from(descriptor)
        .take(129)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > 128 {
        return Err("shifted identity map is oversized".to_owned());
    }
    parse_shifted_id_map(&bytes)
}

fn read_target_status(pid: NonZeroU32) -> Result<String, String> {
    let path = format!("/proc/{pid}/status");
    let descriptor = open(
        &path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| error.to_string())?;
    let mut bytes = Vec::new();
    File::from(descriptor)
        .take(16 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > 16 * 1024 {
        return Err("shifted target status is oversized".to_owned());
    }
    String::from_utf8(bytes).map_err(|_| "shifted target status is not text".to_owned())
}

fn verify_target_status(status: &str) -> Result<(), String> {
    let field = |name: &str| -> Option<&str> {
        let mut values = status.lines().filter_map(|line| {
            let (key, value) = line.split_once(':')?;
            (key == name).then(|| value.trim())
        });
        let value = values.next()?;
        values.next().is_none().then_some(value)
    };
    for name in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
        if field(name) != Some("0000000000000000") {
            return Err(format!("shifted target {name} is not zero"));
        }
    }
    if field("NoNewPrivs") != Some("1") || field("Seccomp") != Some("2") {
        return Err("shifted target lacks NNP or seccomp enforcement".to_owned());
    }
    if !field("Seccomp_filters")
        .and_then(|count| count.parse::<u32>().ok())
        .is_some_and(|count| count > 0)
    {
        return Err("shifted target has no installed seccomp filter".to_owned());
    }
    Ok(())
}

fn verify_target_unit_hardening(values: &[OwnedValue]) -> Result<(), String> {
    let [
        no_new_privileges,
        private_network,
        private_devices,
        protect_system,
    ] = values
    else {
        return Err("shifted target unit readback is incomplete".to_owned());
    };
    for property in [no_new_privileges, private_network, private_devices] {
        if !bool::try_from(property).map_err(|error| error.to_string())? {
            return Err("shifted target unit hardening differs from fixed policy".to_owned());
        }
    }
    if <&str>::try_from(protect_system).map_err(|error| error.to_string())? != "strict" {
        return Err("shifted target filesystem policy is not strict".to_owned());
    }
    Ok(())
}

fn parse_shifted_id_map(bytes: &[u8]) -> Result<(u32, u32), String> {
    let value =
        std::str::from_utf8(bytes).map_err(|_| "shifted identity map is not text".to_owned())?;
    let mut fields = value.split_whitespace();
    let inner = fields.next().and_then(|value| value.parse::<u32>().ok());
    let outer = fields.next().and_then(|value| value.parse::<u32>().ok());
    let count = fields.next().and_then(|value| value.parse::<u32>().ok());
    if inner != Some(0) || fields.next().is_some() || outer == Some(0) || count == Some(0) {
        return Err("shifted identity map is not one nonidentity range".to_owned());
    }
    let outer = outer.ok_or_else(|| "shifted identity map has no outer start".to_owned())?;
    let count = count.ok_or_else(|| "shifted identity map has no count".to_owned())?;
    outer
        .checked_add(count - 1)
        .ok_or_else(|| "shifted identity map overflows".to_owned())?;
    Ok((outer, count))
}

fn load_signing_key() -> Result<SigningKey, String> {
    let directory = env::var_os("CREDENTIALS_DIRECTORY")
        .ok_or_else(|| "phase-0 inspector credentials are absent".to_owned())?;
    let seed = Zeroizing::new(read_credential(
        Path::new(&directory).join(SIGNING_SEED_CREDENTIAL),
        32,
    )?);
    let public = read_credential(Path::new(&directory).join(PUBLIC_KEY_CREDENTIAL), 32)?;
    let mut secret = Zeroizing::new([0u8; 32]);
    secret.copy_from_slice(&seed);
    let key = SigningKey::from_bytes(&secret);
    if key.verifying_key().to_bytes() != public.as_slice() {
        return Err("phase-0 inspector signing key differs from independent public pin".to_owned());
    }
    Ok(key)
}

fn read_credential(path: impl AsRef<Path>, size: usize) -> Result<Vec<u8>, String> {
    let descriptor = open(
        path.as_ref(),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| error.to_string())?;
    let mut file = File::from(descriptor);
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o077 != 0
        || metadata.len() != size as u64
    {
        return Err("phase-0 credential has invalid protected metadata".to_owned());
    }
    let mut bytes = vec![0; size];
    file.read_exact(&mut bytes)
        .map_err(|error| error.to_string())?;
    let mut extra = [0];
    if file.read(&mut extra).map_err(|error| error.to_string())? != 0 {
        return Err("phase-0 credential has trailing bytes".to_owned());
    }
    Ok(bytes)
}

fn publish_report(bytes: &[u8]) -> Result<(), String> {
    let root = Path::new(RESULT_DIRECTORY);
    let metadata = root.symlink_metadata().map_err(|error| error.to_string())?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
        return Err("phase-0 result directory is not protected".to_owned());
    }
    let next = root.join("probe-v2.next");
    let final_path = root.join(RESULT_FILE);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&next)
        .map_err(|error| error.to_string())?;
    file.write_all(bytes).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())?;
    std::fs::rename(&next, final_path).map_err(|error| error.to_string())?;
    File::open(root)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::{parse_shifted_id_map, verify_target_status};

    #[test]
    fn shifted_map_requires_one_nonidentity_nonoverflowing_range() {
        assert_eq!(
            parse_shifted_id_map(b"0 524288 65536\n").unwrap(),
            (524_288, 65_536)
        );
        for invalid in [
            b"0 0 65536\n".as_slice(),
            b"1 524288 65536\n",
            b"0 524288 65536\n1 600000 1\n",
            b"0 4294967290 65536\n",
            b"0 524288 0\n",
        ] {
            assert!(parse_shifted_id_map(invalid).is_err());
        }
    }

    #[test]
    fn shifted_target_status_requires_zero_caps_nnp_and_an_installed_filter() {
        let valid = "CapInh:\t0000000000000000\n\
CapPrm:\t0000000000000000\n\
CapEff:\t0000000000000000\n\
CapBnd:\t0000000000000000\n\
CapAmb:\t0000000000000000\n\
NoNewPrivs:\t1\n\
Seccomp:\t2\n\
Seccomp_filters:\t1\n";
        assert!(verify_target_status(valid).is_ok());
        for changed in [
            valid.replace("CapBnd:\t0000000000000000", "CapBnd:\t0000000000000001"),
            valid.replace("NoNewPrivs:\t1", "NoNewPrivs:\t0"),
            valid.replace("Seccomp:\t2", "Seccomp:\t0"),
            valid.replace("Seccomp_filters:\t1", "Seccomp_filters:\t0"),
            format!("{valid}Seccomp_filters:\t1\n"),
        ] {
            assert!(verify_target_status(&changed).is_err());
        }
    }
}
