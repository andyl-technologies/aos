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
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use aos_sandbox_core::public_attach_route::{
    PUBLIC_ATTACH_CERTIFICATE_TYPE_V1, PUBLIC_ATTACH_GATE_PATH_V1, public_attach_force_command_v1,
    valid_public_attach_user_v1,
};
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
const GATE_PATH: &str = PUBLIC_ATTACH_GATE_PATH_V1;
const SSHD_SESSION_PATH: &str = "/usr/libexec/sshd-session";
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
    gate_device: u64,
    gate_inode: u64,
    gate_digest: [u8; 32],
    monitor_installation: Option<MonitorInstallationV2>,
}

#[derive(Clone)]
struct MeasuredExecutable {
    device: u64,
    inode: u64,
    digest: [u8; 32],
}

impl MeasuredExecutable {
    fn opened(file: &ProtectedFile) -> Self {
        Self {
            device: file.device,
            inode: file.inode,
            digest: digest(&file.bytes),
        }
    }

    fn require_file(&self, path: &Path) -> Result<(), OpenSshGatePhysicalErrorV1> {
        let file = read_protected_file(path, MAXIMUM_EXECUTABLE_BYTES, true)?;
        if file.device != self.device
            || file.inode != self.inode
            || digest(&file.bytes) != self.digest
        {
            return Err(OpenSshGatePhysicalErrorV1::InvalidInstallation);
        }
        Ok(())
    }
}

#[derive(Clone)]
struct MonitorInstallationV2 {
    listener: Arc<aos_sandbox_linux::pidfd::PidFd>,
    configuration_device: u64,
    configuration_inode: u64,
    session_executable: MeasuredExecutable,
    listener_executable: MeasuredExecutable,
    gate_executable: MeasuredExecutable,
}

/// Retains a live owner-created monitor installation, not persisted SSH proof.
///
/// Only the daemon owner creates this anchor from files opened before launch.
/// It cannot authorize I/O or survive a Guest restart by loading a claim.
#[derive(Clone)]
pub struct OpenSshMonitorRuntimeV2 {
    installation: MonitorInstallationV2,
    claim: OpenSshGateClaimV1,
}

impl OpenSshMonitorRuntimeV2 {
    /// Returns the original protected gate/runtime joined to the live owner.
    #[must_use]
    pub const fn claim(&self) -> &OpenSshGateClaimV1 {
        &self.claim
    }

    /// Rechecks the retained listener and accepted physical installation.
    ///
    /// # Errors
    /// Rejects a dead/reused listener, changed claim/config/trust/image or
    /// absent owned listening socket. This observation is not a held I/O cut.
    pub fn require_current(&self) -> Result<(), OpenSshGatePhysicalErrorV1> {
        if load_openssh_gate_claim_v1()? != self.claim {
            return Err(OpenSshGatePhysicalErrorV1::InvalidInstallation);
        }
        self.require_original_session_installation_v4()
    }

    // Original-session terminal data remains readable after leader exit or
    // certificate expiry. This private physical validator does not authorize a
    // control, recover a session, reserve I/O or weaken require_current().
    fn require_original_session_installation_v4(&self) -> Result<(), OpenSshGatePhysicalErrorV1> {
        let installed = check_installed_files(&self.claim.binding)?;
        if installed.configuration.device != self.installation.configuration_device
            || installed.configuration.inode != self.installation.configuration_inode
        {
            return Err(OpenSshGatePhysicalErrorV1::InvalidInstallation);
        }
        let listener = self
            .installation
            .listener
            .process_identity()
            .map_err(|_| OpenSshGatePhysicalErrorV1::DaemonUnavailable)?;
        let credentials = self
            .installation
            .listener
            .info()
            .map_err(|_| OpenSshGatePhysicalErrorV1::DaemonUnavailable)?
            .credentials()
            .ok_or(OpenSshGatePhysicalErrorV1::InvalidInstallation)?;
        if listener.pid() != self.claim.sshd_pid
            || listener.start_time_ticks() != self.claim.sshd_start_ticks
            || load_installed_gate_claim()? != self.claim
            || !owns_listening_socket(listener.pid(), self.claim.binding.port)?
            || credentials.real_user_id() != 0
            || credentials.effective_user_id() != 0
            || credentials.saved_user_id() != 0
            || credentials.filesystem_user_id() != 0
        {
            return Err(OpenSshGatePhysicalErrorV1::InvalidInstallation);
        }
        self.installation
            .listener_executable
            .require_file(&canonicalize_physical_path(SSHD_PATH)?)?;
        self.installation
            .listener_executable
            .require_file(&canonicalize_physical_path(format!(
                "/proc/{}/exe",
                listener.pid()
            ))?)?;
        self.installation
            .session_executable
            .require_file(&canonicalize_physical_path(SSHD_SESSION_PATH)?)?;
        self.installation
            .gate_executable
            .require_file(&canonicalize_physical_path(GATE_PATH)?)?;
        Ok(())
    }

    /// Checks one pinned root monitor against the accepted helper and listener.
    ///
    /// # Errors
    /// Rejects non-root credentials, foreign runtime ancestry, image mutation,
    /// dead monitors or PID reuse. No callback-nominated PID is accepted.
    pub fn require_monitor(
        &self,
        monitor: &aos_sandbox_linux::pidfd::PidFd,
    ) -> Result<(), OpenSshGatePhysicalErrorV1> {
        self.require_current()?;
        self.require_original_monitor_identity(monitor)
    }

    /// Checks a retained original root monitor for nonauthorizing terminal data.
    ///
    /// This requires the original owner-created installation and pinned live
    /// monitor. It does not establish fresh attach/control permission, reread
    /// custody from a persisted claim, or allow another descriptor transfer.
    ///
    /// # Errors
    /// Rejects changed claim/config/trust/image, dead listener/monitor, foreign
    /// ancestry or non-root credentials. Original route expiry is not renewed.
    pub fn require_original_terminal_monitor_v4(
        &self,
        monitor: &aos_sandbox_linux::pidfd::PidFd,
    ) -> Result<(), OpenSshGatePhysicalErrorV1> {
        self.require_original_session_installation_v4()?;
        self.require_original_monitor_identity(monitor)
    }

    /// Checks physical original monitor custody for an unexpired owner control.
    ///
    /// Original leader coordinates remain historical. The Guest must separately
    /// retain and validate the actual active execution subtree under its barrier;
    /// this physical observation cannot replace current policy or authorize I/O.
    ///
    /// # Errors
    /// Rejects expiry, physical substitution, dead/foreign monitors or PID reuse.
    pub fn require_original_control_monitor_v5(
        &self,
        monitor: &aos_sandbox_linux::pidfd::PidFd,
    ) -> Result<(), OpenSshGatePhysicalErrorV1> {
        require_original_control_expiry_v5(&self.claim)?;
        self.require_original_session_installation_v4()?;
        self.require_original_monitor_identity(monitor)
    }

    fn require_original_monitor_identity(
        &self,
        monitor: &aos_sandbox_linux::pidfd::PidFd,
    ) -> Result<(), OpenSshGatePhysicalErrorV1> {
        let identity = monitor
            .process_identity()
            .map_err(|_| OpenSshGatePhysicalErrorV1::DaemonUnavailable)?;
        let credentials = monitor
            .info()
            .map_err(|_| OpenSshGatePhysicalErrorV1::DaemonUnavailable)?
            .credentials()
            .ok_or(OpenSshGatePhysicalErrorV1::InvalidInstallation)?;
        if identity.parent_pid() != self.claim.sshd_pid
            || credentials.real_user_id() != 0
            || credentials.effective_user_id() != 0
            || credentials.saved_user_id() != 0
            || credentials.filesystem_user_id() != 0
        {
            return Err(OpenSshGatePhysicalErrorV1::InvalidInstallation);
        }
        self.installation
            .session_executable
            .require_file(&canonicalize_physical_path(format!(
                "/proc/{}/exe",
                identity.pid()
            ))?)?;
        if !monitor
            .is_alive()
            .map_err(|_| OpenSshGatePhysicalErrorV1::DaemonUnavailable)?
        {
            return Err(OpenSshGatePhysicalErrorV1::DaemonUnavailable);
        }
        Ok(())
    }

    /// Checks the monitor's pinned post-auth child and accepted login credentials.
    ///
    /// # Errors
    /// Rejects foreign/dead/reused children, wrong credentials or helper images.
    /// This does not establish continuous child memory/descriptor confinement.
    pub fn require_child(
        &self,
        child: &aos_sandbox_linux::pidfd::PidFd,
        monitor_pid: u32,
        uid: u32,
        gid: u32,
    ) -> Result<(), OpenSshGatePhysicalErrorV1> {
        self.require_confined_child_v3(child, monitor_pid, uid, gid)?;
        let identity = child
            .process_identity()
            .map_err(|_| OpenSshGatePhysicalErrorV1::DaemonUnavailable)?;
        self.installation
            .session_executable
            .require_file(&canonicalize_physical_path(format!(
                "/proc/{}/exe",
                identity.pid()
            ))?)?;
        Ok(())
    }

    /// Checks kernel identity for a measured monitor's no-exec confined fork.
    ///
    /// This does not open a nondumpable child's procfs image: that would require
    /// expanding the Guest's ptrace capability ceiling. Only the separately
    /// retained v3 measured producer can establish image inheritance and
    /// irreversible confinement before this check is useful.
    ///
    /// # Errors
    /// Rejects wrong/dead/reused children, ancestry or login credentials.
    pub fn require_confined_child_v3(
        &self,
        child: &aos_sandbox_linux::pidfd::PidFd,
        parent_pid: u32,
        uid: u32,
        gid: u32,
    ) -> Result<(), OpenSshGatePhysicalErrorV1> {
        let identity = child
            .process_identity()
            .map_err(|_| OpenSshGatePhysicalErrorV1::DaemonUnavailable)?;
        let credentials = child
            .info()
            .map_err(|_| OpenSshGatePhysicalErrorV1::DaemonUnavailable)?
            .credentials()
            .ok_or(OpenSshGatePhysicalErrorV1::InvalidInstallation)?;
        if uid == 0
            || identity.parent_pid() != parent_pid
            || credentials.real_user_id() != uid
            || credentials.effective_user_id() != uid
            || credentials.saved_user_id() != uid
            || credentials.filesystem_user_id() != uid
            || credentials.real_group_id() != gid
            || credentials.effective_group_id() != gid
            || credentials.saved_group_id() != gid
            || credentials.filesystem_group_id() != gid
        {
            return Err(OpenSshGatePhysicalErrorV1::InvalidInstallation);
        }
        if !child
            .is_alive()
            .map_err(|_| OpenSshGatePhysicalErrorV1::DaemonUnavailable)?
        {
            return Err(OpenSshGatePhysicalErrorV1::DaemonUnavailable);
        }
        Ok(())
    }
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
        Self::start_profile(binding, false, Stdio::null())
    }

    /// Starts the fixed binding-only root-monitor prerequisite.
    ///
    /// Original configuration and certificate bytes remain unchanged. The
    /// explicit launch option does not enable ticket-bound descriptor transfer.
    ///
    /// # Errors
    /// Rejects unsafe/missing files, failed pidfd custody or daemon launch.
    pub fn start_with_monitor_v2(
        binding: OpenSshGateBindingV1,
    ) -> Result<Self, OpenSshGatePhysicalErrorV1> {
        Self::start_profile(binding, true, Stdio::null())
    }

    /// Retains ephemeral qualification stderr through the actual launch checks.
    ///
    /// # Errors
    /// Returns the original installation, custody, or daemon-launch error.
    #[cfg(test)]
    pub(crate) fn start_for_qualification(
        binding: OpenSshGateBindingV1,
        monitor: bool,
        diagnostic: fs::File,
    ) -> Result<Self, OpenSshGatePhysicalErrorV1> {
        Self::start_profile(binding, monitor, Stdio::from(diagnostic))
    }

    /// Samples exit status from the qualification's original owned daemon.
    ///
    /// # Errors
    /// Returns an error if the original child status cannot be read.
    #[cfg(test)]
    pub(crate) fn qualification_exit_status(
        &mut self,
    ) -> std::io::Result<Option<std::process::ExitStatus>> {
        self.child.try_wait()
    }

    fn start_profile(
        binding: OpenSshGateBindingV1,
        monitor: bool,
        stderr: Stdio,
    ) -> Result<Self, OpenSshGatePhysicalErrorV1> {
        binding
            .validate()
            .map_err(|_| OpenSshGatePhysicalErrorV1::InvalidBinding)?;
        let installed = check_installed_files(&binding)?;
        let executable_path = canonicalize_physical_path(SSHD_PATH)?;
        let executable = read_protected_file(&executable_path, MAXIMUM_EXECUTABLE_BYTES, true)?;
        if executable.bytes.is_empty() {
            return Err(OpenSshGatePhysicalErrorV1::InvalidInstallation);
        }

        // Pin the exact callback opened during installation, then recheck it
        // immediately before launch. A later physical readback must still
        // match this identity before the guest can report certificate readiness.
        let gate_digest = digest(&installed.gate_executable.bytes);
        let gate = read_protected_file(
            &canonicalize_physical_path(GATE_PATH)?,
            MAXIMUM_EXECUTABLE_BYTES,
            true,
        )?;
        if gate.device != installed.gate_executable.device
            || gate.inode != installed.gate_executable.inode
            || digest(&gate.bytes) != gate_digest
        {
            return Err(OpenSshGatePhysicalErrorV1::InvalidInstallation);
        }

        let session_executable = if monitor {
            Some(read_protected_file(
                &canonicalize_physical_path(SSHD_SESSION_PATH)?,
                MAXIMUM_EXECUTABLE_BYTES,
                true,
            )?)
        } else {
            None
        };
        let mut command = Command::new(SSHD_PATH);
        command.args(["-D", "-e", "-f", CONFIG_PATH]);
        if monitor {
            command.arg("-oAosAttachMonitorV2=yes");
            command.arg("-oSshdSessionPath=/usr/libexec/sshd-session");
            MeasuredExecutable::opened(
                session_executable
                    .as_ref()
                    .ok_or(OpenSshGatePhysicalErrorV1::InvalidInstallation)?,
            )
            .require_file(&canonicalize_physical_path(SSHD_SESSION_PATH)?)?;
        }
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(stderr)
            .spawn()?;
        let monitor_installation = match session_executable
            .map(|session| {
                let pid = std::num::NonZeroU32::new(child.id())
                    .ok_or(OpenSshGatePhysicalErrorV1::DaemonUnavailable)?;
                let listener = aos_sandbox_linux::pidfd::PidFd::open(pid)
                    .map_err(|_| OpenSshGatePhysicalErrorV1::DaemonUnavailable)?;
                Ok::<_, OpenSshGatePhysicalErrorV1>(MonitorInstallationV2 {
                    listener: Arc::new(listener),
                    configuration_device: installed.configuration.device,
                    configuration_inode: installed.configuration.inode,
                    session_executable: MeasuredExecutable::opened(&session),
                    listener_executable: MeasuredExecutable::opened(&executable),
                    gate_executable: MeasuredExecutable::opened(&installed.gate_executable),
                })
            })
            .transpose()
        {
            Ok(installation) => installation,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        };
        Ok(Self {
            child,
            binding,
            config_device: installed.configuration.device,
            config_inode: installed.configuration.inode,
            gate_device: installed.gate_executable.device,
            gate_inode: installed.gate_executable.inode,
            gate_digest,
            monitor_installation,
        })
    }

    /// Retains the accepted start-time installation after a fresh owner readback.
    ///
    /// # Errors
    /// Rejects a legacy launch, changed claim/binding/image, or dead listener.
    pub fn monitor_runtime_v2(
        &mut self,
        claim: &OpenSshGateClaimV1,
    ) -> Result<OpenSshMonitorRuntimeV2, OpenSshGatePhysicalErrorV1> {
        if claim.binding != self.binding
            || self.daemon_identity()? != (claim.sshd_pid, claim.sshd_start_ticks)
        {
            return Err(OpenSshGatePhysicalErrorV1::InvalidInstallation);
        }
        let runtime = OpenSshMonitorRuntimeV2 {
            installation: self
                .monitor_installation
                .clone()
                .ok_or(OpenSshGatePhysicalErrorV1::InvalidInstallation)?,
            claim: claim.clone(),
        };
        runtime.require_current()?;
        Ok(runtime)
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
        let readback = self.physical_readback(challenge, route_digest, channel_binding)?;
        sign_openssh_gate_readback_v1(&readback, key)
            .map_err(|_| OpenSshGatePhysicalErrorV1::InvalidBinding)
    }

    /// Measures the installed gate without granting its owner signing-key custody.
    ///
    /// The protected agent entry signs this value only after matching its
    /// authenticated session and provisioned runtime. The owned sshd child,
    /// protected claim, files, and listener are checked anew on every call.
    ///
    /// # Errors
    ///
    /// Returns an error when the owned daemon or exact installation changed.
    pub fn physical_readback(
        &mut self,
        challenge: [u8; 32],
        route_digest: [u8; 32],
        channel_binding: [u8; 32],
    ) -> Result<OpenSshGateReadbackV1, OpenSshGatePhysicalErrorV1> {
        let claim = load_openssh_gate_claim_v1()?;
        self.physical_readback_from_installed_claim(challenge, route_digest, channel_binding, claim)
    }

    /// Measures the original installation for a separately held active-tree control.
    ///
    /// # Errors
    /// Rejects expired or substituted installation, trust, listener or executable.
    /// It does not check or authorize an execution; the Guest owner holds that cut.
    pub fn original_control_physical_readback_v5(
        &mut self,
        challenge: [u8; 32],
        route_digest: [u8; 32],
        channel_binding: [u8; 32],
    ) -> Result<OpenSshGateReadbackV1, OpenSshGatePhysicalErrorV1> {
        let claim = load_unexpired_openssh_attach_profile_v5()?;
        self.physical_readback_from_installed_claim(challenge, route_digest, channel_binding, claim)
    }

    fn physical_readback_from_installed_claim(
        &mut self,
        challenge: [u8; 32],
        route_digest: [u8; 32],
        channel_binding: [u8; 32],
        claim: OpenSshGateClaimV1,
    ) -> Result<OpenSshGateReadbackV1, OpenSshGatePhysicalErrorV1> {
        if self.child.try_wait()?.is_some() {
            return Err(OpenSshGatePhysicalErrorV1::DaemonUnavailable);
        }
        let installed = check_installed_files(&self.binding)?;
        if let Some(monitor) = &self.monitor_installation {
            monitor
                .session_executable
                .require_file(&canonicalize_physical_path(SSHD_SESSION_PATH)?)?;
        }
        if installed.configuration.device != self.config_device
            || installed.configuration.inode != self.config_inode
        {
            return Err(OpenSshGatePhysicalErrorV1::InvalidInstallation);
        }
        let pid = self.child.id();
        let start_ticks = process_start_ticks(pid)?;
        if claim.binding != self.binding
            || claim.route_digest != route_digest
            || claim.sshd_pid != pid
            || claim.sshd_start_ticks != start_ticks
        {
            return Err(OpenSshGatePhysicalErrorV1::InvalidInstallation);
        }
        let executable_path = PathBuf::from(format!("/proc/{pid}/exe"));
        if fs::read_link(&executable_path).inspect_err(|_error| {
            #[cfg(test)]
            qualification_io_failure("read_link", &executable_path, _error);
        })? != canonicalize_physical_path(SSHD_PATH)?
        {
            return Err(OpenSshGatePhysicalErrorV1::DaemonUnavailable);
        }
        let executable = read_protected_file(
            &canonicalize_physical_path(&executable_path)?,
            MAXIMUM_EXECUTABLE_BYTES,
            true,
        )?;
        // Sample the callback again after claim and process observation. The
        // measured bytes must still be the original installation-opened file.
        let gate = read_protected_file(
            &canonicalize_physical_path(GATE_PATH)?,
            MAXIMUM_EXECUTABLE_BYTES,
            true,
        )?;
        let gate_digest = digest(&gate.bytes);
        if gate.device != self.gate_device
            || gate.inode != self.gate_inode
            || gate_digest != self.gate_digest
        {
            return Err(OpenSshGatePhysicalErrorV1::InvalidInstallation);
        }
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
            gate_executable_digest: gate_digest,
            host_private_key_digest: digest(&host_key.bytes),
        };
        let readback = OpenSshGateReadbackV1 {
            challenge,
            route_digest,
            channel_binding,
            binding: self.binding.clone(),
            physical,
        };
        Ok(readback)
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
    if !valid_public_attach_user_v1(&binding.user) {
        return Err(OpenSshGatePhysicalErrorV1::InvalidBinding);
    }
    let command = public_attach_force_command_v1(
        &binding.attach_operation_id,
        &binding.execution_id,
        &binding.incarnation_id,
        binding.assignment_epoch,
        &binding.principal_id,
        &binding.audit_id,
    );
    Ok(format!(
        "Port {}\nHostKey {HOST_KEY_PATH}\nHostKeyAlgorithms ssh-ed25519\nPubkeyAuthentication yes\nPubkeyAcceptedAlgorithms {PUBLIC_ATTACH_CERTIFICATE_TYPE_V1}\nTrustedUserCAKeys {CA_PATH}\nAuthenticationMethods publickey\nAuthorizedPrincipalsFile none\nAuthorizedPrincipalsCommand {GATE_PATH} --authorized-principals %t %k\nAuthorizedPrincipalsCommandUser {}\nAuthorizedKeysFile none\nAuthorizedKeysCommand none\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nHostbasedAuthentication no\nPermitRootLogin no\nAllowUsers {}\nForceCommand {command}\nDisableForwarding yes\nPermitTTY yes\nPermitUserEnvironment no\nPermitUserRC no\nUsePAM no\nStrictModes yes\nLogLevel VERBOSE\n",
        binding.port, binding.user, binding.user,
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
    let claim = load_unexpired_openssh_attach_profile_v5()?;
    if process_start_ticks(claim.process_pid)? != claim.process_start_ticks {
        return Err(OpenSshGatePhysicalErrorV1::InvalidInstallation);
    }
    Ok(claim)
}

/// Reads the protected original unexpired certificate profile without execution authority.
///
/// The original leader coordinates are historical data here, not a current
/// process witness. The certificate-profile callback uses this reader without
/// a leader check; strict provisioning separately verifies that leader. The
/// existing trusted root monitor must independently join the actual holder
/// signature and private child to the Guest's active original
/// execution subtree, while Controller and Host retain their current cuts.
/// This metadata check is not a live monitor witness and cannot issue a
/// ticket, bind custody, reserve or release I/O.
///
/// # Errors
/// Rejects malformed or substituted protected claim/config/trust, an expired
/// original route or a changed recorded listener identity. No expiry is renewed.
pub fn load_unexpired_openssh_attach_profile_v5()
-> Result<OpenSshGateClaimV1, OpenSshGatePhysicalErrorV1> {
    let claim = load_installed_gate_claim()?;
    require_original_control_expiry_v5(&claim)?;
    Ok(claim)
}

fn require_original_control_expiry_v5(
    claim: &OpenSshGateClaimV1,
) -> Result<(), OpenSshGatePhysicalErrorV1> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| OpenSshGatePhysicalErrorV1::InvalidInstallation)?
        .as_secs();
    if i64::try_from(now).map_or(true, |now| claim.binding.expires_at <= now) {
        return Err(OpenSshGatePhysicalErrorV1::InvalidInstallation);
    }
    Ok(())
}

fn load_installed_gate_claim() -> Result<OpenSshGateClaimV1, OpenSshGatePhysicalErrorV1> {
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

struct InstalledGateFiles {
    configuration: ProtectedFile,
    gate_executable: ProtectedFile,
}

fn check_installed_files(
    binding: &OpenSshGateBindingV1,
) -> Result<InstalledGateFiles, OpenSshGatePhysicalErrorV1> {
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
    let gate_executable = read_protected_file(
        &canonicalize_physical_path(GATE_PATH)?,
        MAXIMUM_EXECUTABLE_BYTES,
        true,
    )?;
    Ok(InstalledGateFiles {
        configuration: config,
        gate_executable,
    })
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
        .open(path)
        .inspect_err(|_error| {
            #[cfg(test)]
            qualification_io_failure("protected open", path, _error);
        })?;
    let metadata = file.metadata().inspect_err(|_error| {
        #[cfg(test)]
        qualification_io_failure("opened-file metadata", path, _error);
    })?;
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
    file.read_to_end(&mut bytes).inspect_err(|_error| {
        #[cfg(test)]
        qualification_io_failure("protected read_to_end", path, _error);
    })?;
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

/// Reads the actual immutable v2 ticket claim without claiming SSH custody.
///
/// # Errors
/// Rejects missing, writable, foreign, symlinked, oversized, or malformed data.
pub fn load_original_ticket_claim_v2() -> Result<Vec<u8>, OpenSshGatePhysicalErrorV1> {
    let file = read_protected_file(
        Path::new(crate::openssh_ticket::OPENSSH_TICKET_CLAIM_PATH_V2),
        aos_sandbox_core::public_attach_ticket::PUBLIC_ATTACH_TICKET_MAXIMUM_BYTES_V2 as u64,
        false,
    )?;
    aos_sandbox_core::public_attach_ticket::PublicAttachTicketBindingV2::decode(&file.bytes)
        .map_err(|_| OpenSshGatePhysicalErrorV1::InvalidInstallation)?;
    Ok(file.bytes)
}

fn check_protected_ancestors(path: &Path) -> Result<(), OpenSshGatePhysicalErrorV1> {
    for parent in path.ancestors().skip(1) {
        let metadata = fs::symlink_metadata(parent).inspect_err(|_error| {
            #[cfg(test)]
            qualification_io_failure("protected ancestor metadata", parent, _error);
        })?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(OpenSshGatePhysicalErrorV1::InvalidInstallation);
        }
    }
    Ok(())
}

fn process_start_ticks(pid: u32) -> Result<u64, OpenSshGatePhysicalErrorV1> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).inspect_err(|_error| {
        #[cfg(test)]
        qualification_io_failure(
            "process stat read",
            Path::new(&format!("/proc/{pid}/stat")),
            _error,
        );
    })?;
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
    for entry in fs::read_dir(format!("/proc/{pid}/fd")).inspect_err(|_error| {
        #[cfg(test)]
        qualification_io_failure(
            "descriptor directory open",
            Path::new(&format!("/proc/{pid}/fd")),
            _error,
        );
    })? {
        let entry = entry.inspect_err(|_error| {
            #[cfg(test)]
            qualification_io_failure(
                "descriptor directory entry",
                Path::new(&format!("/proc/{pid}/fd")),
                _error,
            );
        })?;
        let target = fs::read_link(entry.path()).inspect_err(|_error| {
            #[cfg(test)]
            qualification_io_failure("descriptor read_link", &entry.path(), _error);
        })?;
        let text = target.to_string_lossy();
        if let Some(inode) = text
            .strip_prefix("socket:[")
            .and_then(|rest| rest.strip_suffix(']'))
        {
            inodes.insert(inode.to_owned());
        }
    }
    for table in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let contents = fs::read_to_string(table).inspect_err(|_error| {
            #[cfg(test)]
            qualification_io_failure("TCP table read", Path::new(table), _error);
        })?;
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

// One filesystem call resolves the same physical name; test-only context
// observes an error without replacing it or authorizing the resolved path.
fn canonicalize_physical_path(path: impl AsRef<Path>) -> std::io::Result<PathBuf> {
    let path = path.as_ref();
    fs::canonicalize(path).inspect_err(|_error| {
        #[cfg(test)]
        qualification_io_failure("canonicalize", path, _error);
    })
}

// Diagnostic output exists only in library-test qualification. inspect_err
// preserves the original Io(error); no content or authorization is reflected.
#[cfg(test)]
fn qualification_io_failure(operation: &str, path: &Path, error: &std::io::Error) {
    eprintln!(
        "OpenSSH qualification-only physical readback {operation} failed at {}: {error}",
        path.display(),
    );
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
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
    fn canonical_path_diagnostics_preserve_resolved_path_and_original_error() {
        let directory = tempfile::tempdir().unwrap();
        let expected = std::fs::canonicalize(directory.path()).unwrap();

        let resolved = super::canonicalize_physical_path(directory.path()).unwrap();
        let error = super::canonicalize_physical_path(directory.path().join("absent")).unwrap_err();

        assert_eq!(resolved, expected);
        assert_eq!(error.raw_os_error(), Some(2));
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn qualification_context_preserves_original_os_error() {
        let error = Err::<(), _>(std::io::Error::from_raw_os_error(2))
            .inspect_err(|error| {
                super::qualification_io_failure(
                    "descriptor read_link",
                    std::path::Path::new("/proc/qualification/fd/7"),
                    error,
                );
            })
            .unwrap_err();

        let super::OpenSshGatePhysicalErrorV1::Io(error) =
            super::OpenSshGatePhysicalErrorV1::from(error)
        else {
            panic!("qualification changed the physical error class");
        };
        assert_eq!(error.raw_os_error(), Some(2));
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
    }

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
        assert!(config.contains("AuthorizedPrincipalsFile none\n"));
        assert!(config.contains("AuthorizedPrincipalsCommand /usr/libexec/aos-sandbox-exec-gate --authorized-principals %t %k\n"));
        assert!(config.contains("AuthorizedPrincipalsCommandUser aos_exec\n"));
        assert!(config.contains("AuthorizedKeysFile none\nAuthorizedKeysCommand none\n"));
        assert!(config.contains("PermitUserEnvironment no\nPermitUserRC no\n"));
    }
}
