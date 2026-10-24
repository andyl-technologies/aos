//! Root-owned OpenSSH claim installation and live physical observation.
//!
//! The authenticated Host request names a route, while the protected guest
//! ledger supplies every process fact. A live owned sshd and exact installed
//! trust files are required before the agent signs any readback.

use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;
use std::time::{Duration, Instant};

use crate::openssh_gate_linux::{OpenSshGatePhysicalErrorV1, SelectedRunningOpenSshGateV1};
use aos_sandbox_guest_protocol::AgentRuntimeBindingV1;
use aos_sandbox_guest_protocol::openssh_gate::{
    OpenSshGateClaimV1, OpenSshGateObserveRequestV1, OpenSshGateReadbackV1,
    expected_openssh_gate_config_v1,
};
use aos_sandbox_model::ObjectDigest;
use sha2::{Digest as _, Sha256};

use crate::GuestProcessEffectErrorV1;
use crate::ledger::{Ledger, ProcessRecord, runtime_identity};
use crate::process::check_deadline;

const DIRECTORY: &str = "/etc/aos/sandbox-attach";
const CONFIG: &str = "/etc/aos/sandbox-attach/sshd_config";
const CLAIM: &str = "/etc/aos/sandbox-attach/gate-record.json";
const NSS_POLICY: &str = "/etc/nsswitch.conf";
const LOGIN_DATABASE: &str = "/etc/passwd";
const MAXIMUM_LOGIN_FILE_BYTES: u64 = aos_sandbox_guest_protocol::openssh_receiving::OPENSSH_LOGIN_FILE_BYTES_V1 as u64;
const O_CLOEXEC: i32 = 0o2_000_000;
const O_NOFOLLOW: i32 = 0o400_000;

mod startup;
pub(super) use startup::GuestOpenSshInstallOriginalV1;

pub(super) struct GuestOpenSshGate {
    daemon: SelectedRunningOpenSshGateV1,
    claim: OpenSshGateClaimV1,
}

impl GuestOpenSshGate {
    /// Polls retirement of only the same owner-created SSH daemon.
    pub(super) fn poll_original_retirement_v1(&mut self, ledger: &Ledger) -> Result<bool, GuestProcessEffectErrorV1> {
        self.daemon.poll_retirement(ledger)
    }

    pub(super) fn bind_ticket_v2(
        &mut self,
        request: &OpenSshGateObserveRequestV1,
        ticket_bytes: &[u8],
        runtime: &AgentRuntimeBindingV1,
        channel: ObjectDigest,
        ledger: &Ledger,
        deadline: Instant,
    ) -> Result<(OpenSshGateReadbackV1, [u8; 32]), GuestProcessEffectErrorV1> {
        let ticket = aos_sandbox_model::public_attach_ticket::PublicAttachTicketBindingV2::decode(
            ticket_bytes,
        )
        .map_err(|_| GuestProcessEffectErrorV1::InvalidRequest)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| GuestProcessEffectErrorV1::InvalidRequest)?
            .as_secs();
        aos_sandbox_guest_protocol::openssh_ticket::validate_ticket_profile_v2(&self.claim, &ticket, now)
            .map_err(|_| GuestProcessEffectErrorV1::InvalidRequest)?;
        // Admission and physical process state precede immutable installation.
        // A partial create is never repaired: cold replay must reject it.
        self.observe(request, runtime, channel, ledger, deadline)?;
        install_original_ticket_v2(ticket_bytes)?;
        let readback = self.observe(request, runtime, channel, ledger, deadline)?;
        let installed = crate::openssh_gate_linux::load_original_ticket_claim_v2()
            .map_err(|_| GuestProcessEffectErrorV1::LedgerConflict)?;
        if installed != ticket_bytes {
            return Err(GuestProcessEffectErrorV1::LedgerConflict);
        }
        Ok((
            readback,
            aos_sandbox_guest_protocol::openssh_ticket::ticket_digest_v2(&installed),
        ))
    }

    pub(super) fn execution(&self) -> [u8; 16] {
        self.claim.binding.execution_id
    }

    pub(super) fn install_retaining_once(
        request: &OpenSshGateObserveRequestV1,
        runtime: &AgentRuntimeBindingV1,
        ledger: &Ledger,
        deadline: Instant,
        startup_deadline: Option<u64>,
        topology: &aos_sandbox_linux::guest_cgroup::GuestRuntimeTopologyOriginalV1,
        payload: &aos_sandbox_linux::guest_cgroup::GuestPayloadCgroupCustodyV1,
        execution_root: &aos_sandbox_linux::cgroup::RetainedCgroupAnchor,
        original: &mut GuestOpenSshInstallOriginalV1,
    ) -> Result<Self, GuestProcessEffectErrorV1> {
        if original.entered { return Err(GuestProcessEffectErrorV1::AmbiguousEffect); }
        original.entered = true;
        original.execution = Some(request.binding.execution_id);
        let result = Self::install_retaining_inner(request, runtime, ledger, deadline, startup_deadline,
            topology, payload, execution_root, original);
        let positive = result.is_ok();
        original.body = Some(result);
        if !positive {
            ledger.request_ssh_retirement_v1(request.binding.execution_id);
            return Err(GuestProcessEffectErrorV1::AmbiguousEffect);
        }
        Ok(Self {
            daemon: original.daemon.take().ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?,
            claim: original.claim.take().ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?,
        })
    }

    fn install_retaining_inner(
        request: &OpenSshGateObserveRequestV1,
        runtime: &AgentRuntimeBindingV1,
        ledger: &Ledger,
        deadline: Instant,
        startup_deadline: Option<u64>,
        topology: &aos_sandbox_linux::guest_cgroup::GuestRuntimeTopologyOriginalV1,
        payload: &aos_sandbox_linux::guest_cgroup::GuestPayloadCgroupCustodyV1,
        execution_root: &aos_sandbox_linux::cgroup::RetainedCgroupAnchor,
        original: &mut GuestOpenSshInstallOriginalV1,
    ) -> Result<(), GuestProcessEffectErrorV1> {
        check_deadline(deadline)?;
        let process = ledger.read_process_bytes(request.binding.execution_id)?;
        verify_admitted_process_with_login(&process, request, runtime, ledger, &mut |user| {
            let nss_policy = original.daemon_start.read_static_login_v1(Path::new(NSS_POLICY), MAXIMUM_LOGIN_FILE_BYTES)?;
            let database = original.daemon_start.read_static_login_v1(Path::new(LOGIN_DATABASE), MAXIMUM_LOGIN_FILE_BYTES)?;
            static_login_identity_contents(user, &nss_policy, &database)
        })?;

        let config = expected_openssh_gate_config_v1(&request.binding)
            .map_err(|_| GuestProcessEffectErrorV1::InvalidRequest)?;
        if <[u8; 32]>::from(Sha256::digest(&config)) != request.binding.gate_config_digest {
            return Err(GuestProcessEffectErrorV1::InvalidRequest);
        }
        let startup_deadline = startup_deadline.ok_or(OpenSshGatePhysicalErrorV1::ListenerReceiptRequired)?;
        original.current.bind_original_cutoff_v1(startup_deadline, &process)?;
        let mut current = || original.current.require_next(ledger, &process, request.binding.expires_at, deadline);
        original.config.install_once(CONFIG, &config, 0o644, &mut current)?;
        check_deadline(deadline)?;

        // start() authenticates the guest-local private host key, public key,
        // CA, fixed config, and installed gate executable before launching.
        original.daemon = Some(original.selected.start_once(
            request.binding.clone(), &process, ledger, topology, payload, execution_root,
            startup_deadline, &mut original.daemon_start, &mut current,
        )?);
        let (sshd_pid, sshd_start_ticks) = original.daemon.as_ref()
            .ok_or(GuestProcessEffectErrorV1::AmbiguousEffect)?.coordinates();
        let claim = OpenSshGateClaimV1 {
            binding: request.binding.clone(),
            route_digest: request.route_digest,
            runtime_identity: process.runtime,
            process_pid: process.pid,
            process_start_ticks: process.start_ticks,
            sshd_pid,
            sshd_start_ticks,
            pty: process.pty,
        };
        claim
            .validate()
            .map_err(|_| GuestProcessEffectErrorV1::InvalidRequest)?;
        let bytes =
            serde_json::to_vec(&claim).map_err(|_| GuestProcessEffectErrorV1::LedgerConflict)?;
        check_deadline(deadline)?;
        original.record.install_once(CLAIM, &bytes, 0o644, &mut current)?;
        current()?;
        original.claim = Some(claim);
        Ok(())
    }

    pub(super) fn monitor_runtime_v2(
        &mut self,
    ) -> Result<crate::openssh_gate_linux::OpenSshMonitorRuntimeV2, GuestProcessEffectErrorV1> {
        self.daemon.monitor_runtime(&self.claim)
            .map_err(|_| GuestProcessEffectErrorV1::InvalidRequest)
    }

    pub(super) fn observe(
        &mut self,
        request: &OpenSshGateObserveRequestV1,
        runtime: &AgentRuntimeBindingV1,
        channel: ObjectDigest,
        ledger: &Ledger,
        deadline: Instant,
    ) -> Result<OpenSshGateReadbackV1, GuestProcessEffectErrorV1> {
        check_deadline(deadline)?;
        self.daemon.require_selected_readback_ready_v1()?;
        if self.claim.binding != request.binding || self.claim.route_digest != request.route_digest
        {
            return Err(GuestProcessEffectErrorV1::InvalidRequest);
        }
        let process = ledger.read_process_bytes(request.binding.execution_id)?;
        verify_admitted_process(&process, request, runtime, ledger)?;
        if self.claim.runtime_identity != process.runtime
            || self.claim.process_pid != process.pid
            || self.claim.process_start_ticks != process.start_ticks
            || self.claim.pty != process.pty
        {
            return Err(GuestProcessEffectErrorV1::LedgerConflict);
        }
        loop {
            check_deadline(deadline)?;
            match self.daemon.physical_readback(
                &self.claim,
                request.challenge,
                request.route_digest,
                *channel.as_bytes(),
            ) {
                Ok(readback) => {
                    check_deadline(deadline)?;
                    return Ok(readback);
                }
                Err(OpenSshGatePhysicalErrorV1::DaemonUnavailable) => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => {
                    return Err(GuestProcessEffectErrorV1::Unavailable(
                        "OpenSSH gate readback failed",
                    ));
                }
            }
        }
    }

    /// Observes physical installation while retaining the active original tree.
    /// Historical leader coordinates do not assert current leader credentials.
    ///
    /// # Errors
    /// Rejects changed original scope/runtime/installation, absent active tree,
    /// expiry, invalid fixed login identity or a missed deadline.
    pub(super) fn observe_active_original_tree_v5(
        &mut self,
        request: &OpenSshGateObserveRequestV1,
        runtime: &AgentRuntimeBindingV1,
        channel: ObjectDigest,
        ledger: &Ledger,
        deadline: Instant,
    ) -> Result<OpenSshGateReadbackV1, GuestProcessEffectErrorV1> {
        check_deadline(deadline)?;
        self.daemon.require_selected_readback_ready_v1()?;
        let process = ledger.read_process_bytes(request.binding.execution_id)?;
        let bridge_request =
            aos_sandbox_guest_protocol::openssh_gate::decode_openssh_gate_bridge_request_v1(
                &self
                    .claim
                    .encode_bridge_request()
                    .map_err(|_| GuestProcessEffectErrorV1::InvalidRequest)?,
            )
            .map_err(|_| GuestProcessEffectErrorV1::InvalidRequest)?;
        if self.claim.binding != request.binding
            || self.claim.route_digest != request.route_digest
            || process.runtime != runtime_identity(runtime)
            || !crate::bridge::request_matches(&bridge_request, &self.claim, &process)
        {
            return Err(GuestProcessEffectErrorV1::InvalidRequest);
        }
        ledger.require_active_original_tree_v5(&process)?;
        static_login_identity(&request.binding.user)?;
        let readback = self
            .daemon
            .physical_readback(
                &self.claim,
                request.challenge,
                request.route_digest,
                *channel.as_bytes(),
            )
            .map_err(|_| GuestProcessEffectErrorV1::InvalidRequest)?;
        check_deadline(deadline)?;
        ledger.require_active_original_tree_v5(&process)?;
        Ok(readback)
    }
}

fn verify_admitted_process(
    process: &ProcessRecord,
    request: &OpenSshGateObserveRequestV1,
    runtime: &AgentRuntimeBindingV1,
    ledger: &Ledger,
) -> Result<(), GuestProcessEffectErrorV1> {
    verify_admitted_process_with_login(process, request, runtime, ledger, &mut static_login_identity)
}

fn verify_admitted_process_with_login(
    process: &ProcessRecord,
    request: &OpenSshGateObserveRequestV1,
    runtime: &AgentRuntimeBindingV1,
    ledger: &Ledger,
    login: &mut dyn FnMut(&str) -> Result<(u32, u32), GuestProcessEffectErrorV1>,
) -> Result<(), GuestProcessEffectErrorV1> {
    let binding = &request.binding;
    if process.execution != binding.execution_id
        || process.incarnation != binding.incarnation_id
        || process.assignment_epoch != binding.assignment_epoch
        || process.principal != binding.principal_id
        || process.audit != binding.audit_id
        || process.runtime != runtime_identity(runtime)
        || process.canceled
        || process.terminal.is_some()
        || !ledger.require_live_process(process)?
    {
        return Err(GuestProcessEffectErrorV1::InvalidRequest);
    }
    login(&binding.user)?;
    Ok(())
}

pub(super) fn static_login_identity(user: &str) -> Result<(u32, u32), GuestProcessEffectErrorV1> {
    let nss_policy = read_protected_static_file(NSS_POLICY)?;
    let database = read_protected_static_file(LOGIN_DATABASE)?;
    static_login_identity_contents(user, &nss_policy, &database)
}

fn static_login_identity_contents(
    user: &str,
    nss_policy: &str,
    database: &str,
) -> Result<(u32, u32), GuestProcessEffectErrorV1> {
    // The fixed SSH account is a transport identity, never the admitted
    // execution credentials. Its actual nonzero UID/GID must agree with the
    // privileged authenticated monitor witness; original process identity is
    // independently joined through the original Authorize row and held tree.

    let mut found_policy = false;
    for line in nss_policy.lines() {
        let policy = line.split('#').next().unwrap_or("").trim();
        if policy.is_empty() {
            continue;
        }
        let Some((database, sources)) = policy.split_once(':') else {
            return Err(GuestProcessEffectErrorV1::InvalidRequest);
        };
        if database.trim() == "passwd" {
            if found_policy || !sources.split_whitespace().eq(["files"]) {
                return Err(GuestProcessEffectErrorV1::InvalidRequest);
            }
            found_policy = true;
        }
    }
    if !found_policy {
        return Err(GuestProcessEffectErrorV1::InvalidRequest);
    }

    let mut found_user = None;
    for line in database.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<_> = line.split(':').collect();
        if fields.len() != 7 || fields[0].is_empty() {
            return Err(GuestProcessEffectErrorV1::InvalidRequest);
        }
        if fields[0] == user {
            let uid = fields[2]
                .parse::<u32>()
                .map_err(|_| GuestProcessEffectErrorV1::InvalidRequest)?;
            let gid = fields[3]
                .parse::<u32>()
                .map_err(|_| GuestProcessEffectErrorV1::InvalidRequest)?;
            if found_user.is_some() || uid == 0 {
                return Err(GuestProcessEffectErrorV1::InvalidRequest);
            }
            found_user = Some((uid, gid));
        }
    }
    found_user.ok_or(GuestProcessEffectErrorV1::InvalidRequest)
}

fn read_protected_static_file(path: &str) -> Result<String, GuestProcessEffectErrorV1> {
    let root = fs::symlink_metadata("/")?;
    let etc = fs::symlink_metadata("/etc")?;
    if !root.is_dir()
        || root.uid() != 0
        || root.mode() & 0o022 != 0
        || !etc.is_dir()
        || etc.uid() != 0
        || etc.mode() & 0o022 != 0
    {
        return Err(GuestProcessEffectErrorV1::UnprotectedLedger);
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(O_CLOEXEC | O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.len() == 0
        || metadata.len() > MAXIMUM_LOGIN_FILE_BYTES
    {
        return Err(GuestProcessEffectErrorV1::UnprotectedLedger);
    }
    let mut bytes = Vec::new();
    file.take(MAXIMUM_LOGIN_FILE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len() || bytes.contains(&0) {
        return Err(GuestProcessEffectErrorV1::InvalidRequest);
    }
    String::from_utf8(bytes).map_err(|_| GuestProcessEffectErrorV1::InvalidRequest)
}

#[cfg(test)]
mod tests {
    //! Static transport accounts stay distinct from original execution credentials.
    use super::static_login_identity_contents;

    #[test]
    fn static_files_policy_requires_exact_account_uid() {
        let passwd =
            "root:x:0:0:root:/root:/bin/sh\naos_exec:x:1001:1001::/home/aos_exec:/bin/sh\n";
        assert!(
            static_login_identity_contents("aos_exec", "passwd: files\n", passwd).unwrap()
                == (1001, 1001)
        );
        assert!(
            static_login_identity_contents(
                "aos_exec",
                "passwd: files\n",
                "aos_exec:x:0:1001::/:/bin/false\n"
            )
            .is_err()
        );
        assert!(static_login_identity_contents("missing", "passwd: files\n", passwd).is_err());
        assert!(static_login_identity_contents("root", "passwd: files\n", passwd).is_err());
        assert!(
            static_login_identity_contents(
                "aos_exec",
                "passwd: files\n",
                "aos_exec:x:0:0::/:/bin/false\n"
            )
            .is_err()
        );
    }

    #[test]
    fn dynamic_or_ambiguous_nss_policy_is_denied() {
        let passwd = "aos_exec:x:1001:1001::/home/aos_exec:/bin/sh\n";
        for policy in [
            "passwd: files systemd\n",
            "passwd: compat\n",
            "passwd: files\npasswd: files\n",
            "group: files\n",
        ] {
            assert!(static_login_identity_contents("aos_exec", policy, passwd).is_err());
        }
        assert!(
            static_login_identity_contents(
                "aos_exec",
                "passwd: files\n",
                &format!("{passwd}{passwd}")
            )
            .is_err()
        );
    }

    #[test]
    fn nonroot_transport_login_does_not_replace_root_execution_identity() {
        let identity = static_login_identity_contents(
            "aos_exec",
            "passwd: files\n",
            "aos_exec:x:1001:1002::/:/bin/false\n",
        )
        .unwrap();
        let original_execution_uid = 0;

        assert_eq!(identity, (1001, 1002));
        assert_ne!(identity.0, original_execution_uid);
        assert!(
            static_login_identity_contents(
                "aos_exec",
                "passwd: files\n",
                "aos_exec:x:0:1002::/:/bin/false\n",
            )
            .is_err()
        );
    }
}

fn install_original_ticket_v2(bytes: &[u8]) -> Result<(), GuestProcessEffectErrorV1> {
    let path = aos_sandbox_guest_protocol::openssh_ticket::OPENSSH_TICKET_CLAIM_PATH_V2;
    // Reuse the protected reader on replay; equal bytes are the only success.
    // No rename/replacement path exists for a post-issuance sidecar.
    match fs::symlink_metadata(path) {
        Ok(_) => {
            let previous = crate::openssh_gate_linux::load_original_ticket_claim_v2()
                .map_err(|_| GuestProcessEffectErrorV1::UnprotectedLedger)?;
            return if previous == bytes {
                Ok(())
            } else {
                Err(GuestProcessEffectErrorV1::LedgerConflict)
            };
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    for directory in ["/etc", "/etc/aos", DIRECTORY] {
        let metadata = fs::symlink_metadata(directory)?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(GuestProcessEffectErrorV1::UnprotectedLedger);
        }
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .custom_flags(O_CLOEXEC | O_NOFOLLOW)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    File::open(DIRECTORY)?.sync_all()?;
    Ok(())
}
