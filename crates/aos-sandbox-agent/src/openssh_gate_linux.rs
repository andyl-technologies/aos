//! Fixed Linux installation and physical readback for one OpenSSH attach gate.
//!
//! The runner owns the sshd child it launched. Each signed observation rereads
//! protected configuration and keys, confirms the original config inode,
//! checks the executable behind procfs, and finds the child's listening socket.

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Read as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use ed25519_dalek::SigningKey;
use sha2::{Digest as _, Sha256};
use ssh_key::{Algorithm, PrivateKey, PublicKey};

use crate::openssh_gate::{
    OpenSshGateBindingV1, OpenSshGateClaimV1, OpenSshGatePhysicalStateV1, OpenSshGateReadbackV1,
    sign_openssh_gate_readback_v1,
};

const SSHD_PATH: &str = "/usr/sbin/sshd";
const CONFIG_PATH: &str = "/etc/aos/sandbox-attach/sshd_config";
const CA_PATH: &str = "/etc/aos/sandbox-attach/trusted_user_ca.pub";
const HOST_KEY_PATH: &str = "/etc/aos/sandbox-attach/host_key";
const HOST_PUBLIC_KEY_PATH: &str = "/etc/aos/sandbox-attach/host_key.pub";
const GATE_PATH: &str = "/usr/libexec/aos-sandbox-exec-gate";
const CLAIM_PATH: &str = "/etc/aos/sandbox-attach/gate-record.json";
const O_CLOEXEC: i32 = 0o2_000_000;
const O_NOFOLLOW: i32 = 0o400_000;
const MAXIMUM_EXECUTABLE_BYTES: u64 = 128 * 1_048_576;

/// Owns the live daemon launched for an exact installed attach gate.
pub struct RunningOpenSshGateV1 {
    child: Child,
    binding: OpenSshGateBindingV1,
    config_device: u64,
    config_inode: u64,
}

impl RunningOpenSshGateV1 {
    /// Returns the owned daemon identity for a protected guest claim.
    ///
    /// # Errors
    ///
    /// Returns an error if the daemon exited or its procfs identity vanished.
    pub fn daemon_identity(&mut self) -> Result<(u32, u64), OpenSshGatePhysicalErrorV1> {
        if self.child.try_wait()?.is_some() {
            return Err(OpenSshGatePhysicalErrorV1::DaemonUnavailable);
        }
        let pid = self.child.id();
        Ok((pid, process_start_ticks(pid)?))
    }

    /// Verifies installed files and launches the fixed guest sshd executable.
    ///
    /// # Errors
    ///
    /// Returns an error if any installed file, CA, host key, gate executable,
    /// or exact configuration is absent or unsafe, or if sshd cannot launch.
    pub fn start(binding: OpenSshGateBindingV1) -> Result<Self, OpenSshGatePhysicalErrorV1> {
        binding
            .validate()
            .map_err(|_| OpenSshGatePhysicalErrorV1::InvalidBinding)?;
        let config = check_installed_files(&binding)?;
        let executable_path = fs::canonicalize(SSHD_PATH)?;
        let executable = read_protected_file(&executable_path, MAXIMUM_EXECUTABLE_BYTES, true)?;
        if executable.bytes.is_empty() {
            return Err(OpenSshGatePhysicalErrorV1::InvalidInstallation);
        }

        let child = Command::new(SSHD_PATH)
            .args(["-D", "-e", "-f", CONFIG_PATH])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        Ok(Self {
            child,
            binding,
            config_device: config.device,
            config_inode: config.inode,
        })
    }

    /// Reads the live daemon and protected files, then signs the exact result.
    ///
    /// # Errors
    ///
    /// Returns an error if the daemon exited, the config was replaced, file
    /// trust changed, the listener disappeared, or signing data is invalid.
    pub fn signed_readback(
        &mut self,
        challenge: [u8; 32],
        route_digest: [u8; 32],
        channel_binding: [u8; 32],
        key: &SigningKey,
    ) -> Result<Vec<u8>, OpenSshGatePhysicalErrorV1> {
        if self.child.try_wait()?.is_some() {
            return Err(OpenSshGatePhysicalErrorV1::DaemonUnavailable);
        }
        let config = check_installed_files(&self.binding)?;
        if config.device != self.config_device || config.inode != self.config_inode {
            return Err(OpenSshGatePhysicalErrorV1::InvalidInstallation);
        }
        let pid = self.child.id();
        let start_ticks = process_start_ticks(pid)?;
        let claim = load_openssh_gate_claim_v1()?;
        if claim.binding != self.binding
            || claim.route_digest != route_digest
            || claim.sshd_pid != pid
            || claim.sshd_start_ticks != start_ticks
        {
            return Err(OpenSshGatePhysicalErrorV1::InvalidInstallation);
        }
        let executable_path = PathBuf::from(format!("/proc/{pid}/exe"));
        if fs::read_link(&executable_path)? != fs::canonicalize(SSHD_PATH)? {
            return Err(OpenSshGatePhysicalErrorV1::DaemonUnavailable);
        }
        let executable = read_protected_file(
            &fs::canonicalize(&executable_path)?,
            MAXIMUM_EXECUTABLE_BYTES,
            true,
        )?;
        let gate = read_protected_file(
            &fs::canonicalize(GATE_PATH)?,
            MAXIMUM_EXECUTABLE_BYTES,
            true,
        )?;
        let host_key = read_protected_file(Path::new(HOST_KEY_PATH), 16 * 1024, false)?;
        if host_key.mode & 0o077 != 0 {
            return Err(OpenSshGatePhysicalErrorV1::InvalidInstallation);
        }
        if !owns_listening_socket(pid, self.binding.port)? {
            return Err(OpenSshGatePhysicalErrorV1::DaemonUnavailable);
        }

        let physical = OpenSshGatePhysicalStateV1 {
            sshd_pid: pid,
            sshd_start_ticks: start_ticks,
            sshd_executable_digest: digest(&executable.bytes),
            gate_executable_digest: digest(&gate.bytes),
            host_private_key_digest: digest(&host_key.bytes),
        };
        let readback = OpenSshGateReadbackV1 {
            challenge,
            route_digest,
            channel_binding,
            binding: self.binding.clone(),
            physical,
        };
        sign_openssh_gate_readback_v1(&readback, key)
            .map_err(|_| OpenSshGatePhysicalErrorV1::InvalidBinding)
    }
}

impl Drop for RunningOpenSshGateV1 {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Builds the only accepted sshd configuration for one attach route.
///
/// # Errors
///
/// Returns an error for invalid bounded route fields.
pub fn expected_openssh_gate_config_v1(
    binding: &OpenSshGateBindingV1,
) -> Result<Vec<u8>, OpenSshGatePhysicalErrorV1> {
    binding
        .validate()
        .map_err(|_| OpenSshGatePhysicalErrorV1::InvalidBinding)?;
    if !binding.user.bytes().enumerate().all(|(index, byte)| {
        byte.is_ascii_alphanumeric() || byte == b'_' || (index != 0 && byte == b'-')
    }) {
        return Err(OpenSshGatePhysicalErrorV1::InvalidBinding);
    }
    let command = format!(
        "{GATE_PATH} --operation-id {} --execution-id {} --incarnation-id {} --assignment-epoch {} --principal-id {} --audit-id {}",
        hex_id(&binding.attach_operation_id),
        hex_id(&binding.execution_id),
        hex_id(&binding.incarnation_id),
        binding.assignment_epoch,
        hex_id(&binding.principal_id),
        hex_id(&binding.audit_id),
    );
    Ok(format!(
        "Port {}\nHostKey {HOST_KEY_PATH}\nHostKeyAlgorithms ssh-ed25519\nPubkeyAuthentication yes\nPubkeyAcceptedAlgorithms ssh-ed25519-cert-v01@openssh.com\nTrustedUserCAKeys {CA_PATH}\nAuthenticationMethods publickey\nAuthorizedKeysFile none\nAuthorizedKeysCommand none\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nHostbasedAuthentication no\nPermitRootLogin no\nAllowUsers {}\nForceCommand {command}\nDisableForwarding yes\nPermitTTY yes\nPermitUserEnvironment no\nPermitUserRC no\nUsePAM no\nStrictModes yes\nLogLevel VERBOSE\n",
        binding.port, binding.user,
    )
    .into_bytes())
}

/// Loads the public root-installed claim for the unprivileged forced command.
///
/// The guest process owner must independently check the claim against its
/// root-only process ledger before returning an I/O descriptor.
///
/// # Errors
///
/// Returns an error if the claim or public CA/config files are changed,
/// noncanonical, stale, or not protected by root-owned directories.
pub fn load_openssh_gate_claim_v1() -> Result<OpenSshGateClaimV1, OpenSshGatePhysicalErrorV1> {
    let file = read_protected_file(Path::new(CLAIM_PATH), 4096, false)?;
    let claim: OpenSshGateClaimV1 = serde_json::from_slice(&file.bytes)
        .map_err(|_| OpenSshGatePhysicalErrorV1::InvalidInstallation)?;
    claim
        .validate()
        .map_err(|_| OpenSshGatePhysicalErrorV1::InvalidInstallation)?;
    if serde_json::to_vec(&claim).map_err(|_| OpenSshGatePhysicalErrorV1::InvalidInstallation)?
        != file.bytes
    {
        return Err(OpenSshGatePhysicalErrorV1::InvalidInstallation);
    }
    let config = read_protected_file(Path::new(CONFIG_PATH), 4096, false)?;
    let ca = read_protected_file(Path::new(CA_PATH), 256, false)?;
    let host_public = read_protected_file(Path::new(HOST_PUBLIC_KEY_PATH), 256, false)?;
    if config.bytes != expected_openssh_gate_config_v1(&claim.binding)?
        || digest(&config.bytes) != claim.binding.gate_config_digest
        || ca.bytes != format!("{}\n", claim.binding.trusted_user_ca_public_key).as_bytes()
        || host_public.bytes != format!("{}\n", claim.binding.host_public_key).as_bytes()
        || process_start_ticks(claim.process_pid)? != claim.process_start_ticks
        || process_start_ticks(claim.sshd_pid)? != claim.sshd_start_ticks
    {
        return Err(OpenSshGatePhysicalErrorV1::InvalidInstallation);
    }
    Ok(claim)
}

struct ProtectedFile {
    bytes: Vec<u8>,
    device: u64,
    inode: u64,
    mode: u32,
}

fn check_installed_files(
    binding: &OpenSshGateBindingV1,
) -> Result<ProtectedFile, OpenSshGatePhysicalErrorV1> {
    let config = read_protected_file(Path::new(CONFIG_PATH), 4096, false)?;
    if digest(&config.bytes) != binding.gate_config_digest
        || config.bytes != expected_openssh_gate_config_v1(binding)?
    {
        return Err(OpenSshGatePhysicalErrorV1::InvalidInstallation);
    }
    let ca = read_protected_file(Path::new(CA_PATH), 256, false)?;
    let host_public = read_protected_file(Path::new(HOST_PUBLIC_KEY_PATH), 256, false)?;
    let host_private = read_protected_file(Path::new(HOST_KEY_PATH), 16 * 1024, false)?;
    if host_private.mode & 0o077 != 0 {
        return Err(OpenSshGatePhysicalErrorV1::InvalidInstallation);
    }
    if ca.bytes != format!("{}\n", binding.trusted_user_ca_public_key).as_bytes()
        || host_public.bytes != format!("{}\n", binding.host_public_key).as_bytes()
    {
        return Err(OpenSshGatePhysicalErrorV1::InvalidInstallation);
    }
    let private = PrivateKey::from_openssh(&host_private.bytes)
        .map_err(|_| OpenSshGatePhysicalErrorV1::InvalidInstallation)?;
    let public = PublicKey::from_openssh(&binding.host_public_key)
        .map_err(|_| OpenSshGatePhysicalErrorV1::InvalidInstallation)?;
    let ca_public = PublicKey::from_openssh(&binding.trusted_user_ca_public_key)
        .map_err(|_| OpenSshGatePhysicalErrorV1::InvalidInstallation)?;
    if private.is_encrypted()
        || private.algorithm() != Algorithm::Ed25519
        || private.public_key().key_data() != public.key_data()
        || ca_public.algorithm() != Algorithm::Ed25519
    {
        return Err(OpenSshGatePhysicalErrorV1::InvalidInstallation);
    }
    read_protected_file(
        &fs::canonicalize(GATE_PATH)?,
        MAXIMUM_EXECUTABLE_BYTES,
        true,
    )?;
    Ok(config)
}

fn read_protected_file(
    path: &Path,
    maximum_bytes: u64,
    executable: bool,
) -> Result<ProtectedFile, OpenSshGatePhysicalErrorV1> {
    check_protected_ancestors(path)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW | O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.len() == 0
        || metadata.len() > maximum_bytes
        || (executable && metadata.mode() & 0o111 == 0)
    {
        return Err(OpenSshGatePhysicalErrorV1::InvalidInstallation);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len() {
        return Err(OpenSshGatePhysicalErrorV1::InvalidInstallation);
    }
    Ok(ProtectedFile {
        bytes,
        device: metadata.dev(),
        inode: metadata.ino(),
        mode: metadata.mode(),
    })
}

fn check_protected_ancestors(path: &Path) -> Result<(), OpenSshGatePhysicalErrorV1> {
    for parent in path.ancestors().skip(1) {
        let metadata = fs::symlink_metadata(parent)?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(OpenSshGatePhysicalErrorV1::InvalidInstallation);
        }
    }
    Ok(())
}

fn process_start_ticks(pid: u32) -> Result<u64, OpenSshGatePhysicalErrorV1> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let fields = stat
        .rsplit_once(')')
        .ok_or(OpenSshGatePhysicalErrorV1::DaemonUnavailable)?
        .1;
    let mut fields = fields.split_whitespace();
    if matches!(fields.next(), None | Some("Z" | "X")) {
        return Err(OpenSshGatePhysicalErrorV1::DaemonUnavailable);
    }
    let start = fields
        .nth(18)
        .ok_or(OpenSshGatePhysicalErrorV1::DaemonUnavailable)?;
    start
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or(OpenSshGatePhysicalErrorV1::DaemonUnavailable)
}

fn owns_listening_socket(pid: u32, port: u16) -> Result<bool, OpenSshGatePhysicalErrorV1> {
    let mut inodes = BTreeSet::new();
    for entry in fs::read_dir(format!("/proc/{pid}/fd"))? {
        let target = fs::read_link(entry?.path())?;
        let text = target.to_string_lossy();
        if let Some(inode) = text
            .strip_prefix("socket:[")
            .and_then(|rest| rest.strip_suffix(']'))
        {
            inodes.insert(inode.to_owned());
        }
    }
    for table in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let contents = fs::read_to_string(table)?;
        for row in contents.lines().skip(1) {
            let fields: Vec<_> = row.split_whitespace().collect();
            if fields.len() < 10 || fields[3] != "0A" || !inodes.contains(fields[9]) {
                continue;
            }
            let Some((_, hex_port)) = fields[1].rsplit_once(':') else {
                continue;
            };
            if u16::from_str_radix(hex_port, 16).ok() == Some(port) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn hex_id(bytes: &[u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(32);
    for byte in bytes {
        result.push(char::from(HEX[usize::from(byte >> 4)]));
        result.push(char::from(HEX[usize::from(byte & 15)]));
    }
    result
}

/// Reports invalid installed files or a missing live daemon.
#[derive(Debug, thiserror::Error)]
pub enum OpenSshGatePhysicalErrorV1 {
    /// The supplied route cannot be an exact forced-command gate.
    #[error("OpenSSH attach gate binding is invalid")]
    InvalidBinding,
    /// The installed files disagree with the admitted route or lack root trust.
    #[error("OpenSSH attach gate installation is invalid")]
    InvalidInstallation,
    /// The owned sshd process or its listener is unavailable.
    #[error("OpenSSH attach gate daemon is unavailable")]
    DaemonUnavailable,
    /// The Linux file or process readback failed.
    #[error("OpenSSH attach gate physical readback failed: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::{OpenSshGateBindingV1, expected_openssh_gate_config_v1};

    #[test]
    fn fixed_config_forces_exact_certificate_command_and_denies_forwarding() {
        let binding = OpenSshGateBindingV1 {
            attach_operation_id: [1; 16],
            execution_id: [2; 16],
            incarnation_id: [3; 16],
            assignment_epoch: 4,
            principal_id: [5; 16],
            audit_id: [6; 16],
            user: "aos_exec".to_owned(),
            port: 2222,
            host_public_key: "ssh-ed25519 AAAA".to_owned(),
            trusted_user_ca_public_key: "ssh-ed25519 BBBB".to_owned(),
            expires_at: 2_000_000_000,
            gate_config_digest: [7; 32],
        };
        let config = String::from_utf8(expected_openssh_gate_config_v1(&binding).unwrap()).unwrap();
        assert!(config.contains("TrustedUserCAKeys /etc/aos/sandbox-attach/trusted_user_ca.pub\n"));
        assert!(config.contains("DisableForwarding yes\n"));
        assert!(config.contains("--assignment-epoch 4 --principal-id"));
        assert!(config.contains("ForceCommand /usr/libexec/aos-sandbox-exec-gate"));
    }
}
