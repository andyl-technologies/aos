//! Root-owned OpenSSH claim installation and live physical observation.
//!
//! The authenticated Host request names a route, while the protected guest
//! ledger supplies every process fact. A live owned sshd and exact installed
//! trust files are required before the agent signs any readback.

use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;
use std::time::{Duration, Instant};

use aos_sandbox_agent::AgentRuntimeBindingV1;
use aos_sandbox_agent::openssh_gate::{
    OpenSshGateClaimV1, OpenSshGateObserveRequestV1, OpenSshGateReadbackV1,
};
use aos_sandbox_agent::openssh_gate_linux::{
    OpenSshGatePhysicalErrorV1, RunningOpenSshGateV1, expected_openssh_gate_config_v1,
};
use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use crate::GuestProcessEffectErrorV1;
use crate::ledger::{Ledger, ProcessRecord, runtime_identity};
use crate::process::{check_deadline, process_matches};

const DIRECTORY: &str = "/etc/aos/sandbox-attach";
const CONFIG: &str = "/etc/aos/sandbox-attach/sshd_config";
const CLAIM: &str = "/etc/aos/sandbox-attach/gate-record.json";
const O_CLOEXEC: i32 = 0o2_000_000;
const O_NOFOLLOW: i32 = 0o400_000;

pub(super) struct GuestOpenSshGate {
    daemon: RunningOpenSshGateV1,
    claim: OpenSshGateClaimV1,
}

impl GuestOpenSshGate {
    pub(super) fn execution(&self) -> [u8; 16] {
        self.claim.binding.execution_id
    }

    pub(super) fn install(
        request: &OpenSshGateObserveRequestV1,
        runtime: &AgentRuntimeBindingV1,
        ledger: &Ledger,
        deadline: Instant,
    ) -> Result<Self, GuestProcessEffectErrorV1> {
        check_deadline(deadline)?;
        let process = ledger.read_process_bytes(request.binding.execution_id)?;
        verify_admitted_process(&process, request, runtime)?;

        let config = expected_openssh_gate_config_v1(&request.binding)
            .map_err(|_| GuestProcessEffectErrorV1::InvalidRequest)?;
        if <[u8; 32]>::from(Sha256::digest(&config)) != request.binding.gate_config_digest {
            return Err(GuestProcessEffectErrorV1::InvalidRequest);
        }
        install_protected_file(CONFIG, &config, 0o644)?;
        check_deadline(deadline)?;

        // start() authenticates the guest-local private host key, public key,
        // CA, fixed config, and installed gate executable before launching.
        let mut daemon = RunningOpenSshGateV1::start(request.binding.clone())
            .map_err(|_| GuestProcessEffectErrorV1::Unavailable("OpenSSH gate unavailable"))?;
        let (sshd_pid, sshd_start_ticks) = daemon
            .daemon_identity()
            .map_err(|_| GuestProcessEffectErrorV1::Unavailable("OpenSSH gate unavailable"))?;
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
        install_protected_file(CLAIM, &bytes, 0o644)?;

        Ok(Self { daemon, claim })
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
        if self.claim.binding != request.binding || self.claim.route_digest != request.route_digest
        {
            return Err(GuestProcessEffectErrorV1::InvalidRequest);
        }
        let process = ledger.read_process_bytes(request.binding.execution_id)?;
        verify_admitted_process(&process, request, runtime)?;
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
}

fn verify_admitted_process(
    process: &ProcessRecord,
    request: &OpenSshGateObserveRequestV1,
    runtime: &AgentRuntimeBindingV1,
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
        || !process_matches(process)?
    {
        return Err(GuestProcessEffectErrorV1::InvalidRequest);
    }
    Ok(())
}

fn install_protected_file(
    target: &str,
    bytes: &[u8],
    mode: u32,
) -> Result<(), GuestProcessEffectErrorV1> {
    for directory in ["/etc", "/etc/aos", DIRECTORY] {
        let metadata = fs::symlink_metadata(directory)?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(GuestProcessEffectErrorV1::UnprotectedLedger);
        }
    }
    let target = Path::new(target);
    match fs::symlink_metadata(target) {
        Ok(metadata)
            if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 =>
        {
            return Err(GuestProcessEffectErrorV1::UnprotectedLedger);
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let temporary = target.with_extension("next");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(O_CLOEXEC | O_NOFOLLOW)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(mode))?;
    fs::rename(&temporary, target)?;
    File::open(DIRECTORY)?.sync_all()?;
    Ok(())
}
