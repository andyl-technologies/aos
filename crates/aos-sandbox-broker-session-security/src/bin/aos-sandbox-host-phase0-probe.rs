//! Fixed shifted-userns target and privileged phase-0 pidfs inspector.
//!
//! PID 1 runs `target` under `PrivateUsers=managed`. A distinct fixed inspector
//! with only CAP_SYS_PTRACE pins that service through PID 1, its exact cgroup,
//! and pidfs, then signs one boot/package-bound AOSHPB01 observation. The
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

use aos_sandbox_host::phase0_probe::verified_packaged_hostd_digest;
use aos_sandbox_host::phase0_probe::{Phase0ProbeObservationV1, SignedPhase0ProbeRecordV1};
use aos_sandbox_host::plan::VerifiedLiveSelinuxPolicyV1;
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::cgroup::CgroupV2Root;
use aos_sandbox_linux::pidfd::{NamespaceKind, PidFd};
use aos_systemd::SystemdClient;
use ed25519_dalek::SigningKey;
use rustix::fs::{FileType, Mode, OFlags, fstat, open};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

const TARGET_SERVICE: &str = "aos-sandbox-host-phase0-target.service";
const RESULT_DIRECTORY: &str = "/var/lib/aos/sandbox-host-phase0";
const RESULT_FILE: &str = "probe-v1";
const SIGNING_SEED_CREDENTIAL: &str = "phase0-probe-signing-seed-v1";
const PUBLIC_KEY_CREDENTIAL: &str = "phase0-probe-public-key-v1";
const MAXIMUM_NSPAWN_BYTES: u64 = 256 * 1024 * 1024;

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
    let nspawn_sha256 = hash_packaged_nspawn(nspawn_path)?;
    let hostd_sha256 =
        verified_packaged_hostd_digest(Path::new(hostd_path)).map_err(|error| error.to_string())?;
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
    client
        .observe_pid1_service_properties(TARGET_SERVICE, service.main_pid.get(), &[])
        .await
        .map_err(|error| error.to_string())?;

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

    let target_after = target.info().map_err(|error| error.to_string())?;
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

    let observation = Phase0ProbeObservationV1 {
        boot_id,
        nspawn_sha256,
        hostd_sha256,
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
        SignedPhase0ProbeRecordV1::sign(observation, &key).map_err(|error| error.to_string())?;
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

fn hash_packaged_nspawn(path: &str) -> Result<[u8; 32], String> {
    if !path.starts_with("/nix/store/") || !path.ends_with("/bin/systemd-nspawn") {
        return Err("nspawn is not the fixed packaged executable".to_owned());
    }
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| error.to_string())?;
    let stat = fstat(&descriptor).map_err(|error| error.to_string())?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != 0
        || stat.st_mode & 0o022 != 0
        || stat.st_mode & 0o111 == 0
        || stat.st_size <= 0
        || u64::try_from(stat.st_size).unwrap_or(u64::MAX) > MAXIMUM_NSPAWN_BYTES
    {
        return Err("nspawn package has invalid protected metadata".to_owned());
    }
    let mut file = File::from(descriptor);
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let amount = file.read(&mut buffer).map_err(|error| error.to_string())?;
        if amount == 0 {
            break;
        }
        total = total
            .checked_add(amount as u64)
            .ok_or_else(|| "nspawn package is oversized".to_owned())?;
        if total > MAXIMUM_NSPAWN_BYTES {
            return Err("nspawn package is oversized".to_owned());
        }
        digest.update(&buffer[..amount]);
    }
    if total != stat.st_size as u64
        || file.metadata().map_err(|error| error.to_string())?.len() != stat.st_size as u64
    {
        return Err("nspawn package changed during measurement".to_owned());
    }
    Ok(digest.finalize().into())
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
    let next = root.join("probe-v1.next");
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
    use super::parse_shifted_id_map;

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
}
