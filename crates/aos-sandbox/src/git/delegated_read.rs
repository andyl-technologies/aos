//! Owns the fixed Gateway-to-Controller Git read-scope inspection exchange.
//!
//! The sole codec carries historical TLS/request DATA between two currently
//! checked existing service owners. It never creates a `PublicApiPeer`, a
//! reservation, an export or an effect permission. Even evaluated scope ends
//! in an empty HTTP 503 until those independent producers are installed.
//!
//! ```text
//! AOSGDI01 request[512] -> AOSGDR01 result[256] -> AOSGDA01 local receipt[64]
//! version:u16be=1, length:u32be, sequence:u64be=1, reserved bytes=0
//! SCM_RIGHTS: none; original BOOTTIME cut: at most ten seconds, never renewed
//! ```

use std::fmt;
use std::future::poll_fn;
use std::path::Path;
use std::time::Duration;

use aos_sandbox_core::{ChannelBinding, PrincipalId, ProjectId, ResourceId, RawPairedClockSample};
use aos_sandbox_linux::cgroup::{CgroupV2Root, RetainedCgroupAnchor};
use aos_sandbox_linux::pidfd::{PidFd, PidFdProcObservationsV1, PidFdProcessIdentity};
use aos_sandbox_linux::seqpacket::{
    KernelAuthorizedRecordSubject, ReceivedRecord, RecordBindingError, RecordSubjectListener,
    RetainedSeqpacketAdmissionErrorV1, RetainedSeqpacketReceiveErrorV1, SeqpacketError,
    SeqpacketSocket,
};
use aos_systemd::{OwnedValue, SystemdClient, Value};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use rustix::fs::{CWD, Mode, OFlags, openat};
use sha2::{Digest as _, Sha256};
use tokio::io::unix::AsyncFd;
use zeroize::Zeroizing;

use crate::cli_model::authorization_adapter::{
    CliAuthorizationAdapterError, CurrentCapabilityDecisionV1, RetainedAuthorizationTimeFloorV1,
};
use crate::controller::ControllerProtectedClockV1;
use crate::immutable_image::RetainedImmutableFileV1;
use crate::public_api_session::{PublicApiSessionAcceptor, PublicApiSessionError};

const ENDPOINT: &str = "/run/aos/git-upload-delegation/control.sock";
const DIRECTORY: &str = "/run/aos/git-upload-delegation";
const MAXIMUM_LIFETIME: u64 = 10_000_000_000;
const REQUEST_BYTES: usize = 512;
const RESULT_BYTES: usize = 256;
const RECEIPT_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum GitReadKindV1 {
    Discovery = 1,
    Upload = 2,
}

/// Selects only an empty negative HTTP result; never a Git terminal receipt.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum NegativeGitResponseV1 {
    Unauthorized,
    Forbidden,
    Unavailable,
}

impl NegativeGitResponseV1 {
    pub(super) const fn status(self) -> u16 {
        match self {
            Self::Unauthorized => 401,
            Self::Forbidden => 403,
            Self::Unavailable => 503,
        }
    }
}

/// Keeps the decoded original Basic bytes and its actual decoder outcome.
/// No header value or password appears in diagnostics.
pub(super) struct BasicHolderV1 {
    decoded: Zeroizing<[u8; 68]>,
    decode: Option<Result<usize, base64::DecodeSliceError>>,
    handle: Option<[u8; 32]>,
    missing: bool,
}

impl BasicHolderV1 {
    pub(super) fn capture(headers: &http::HeaderMap) -> Self {
        let mut retained = Self {
            decoded: Zeroizing::new([0; 68]), decode: None, handle: None, missing: false,
        };
        let mut values = headers.get_all(http::header::AUTHORIZATION).iter();
        let Some(value) = values.next() else {
            retained.missing = true;
            return retained;
        };
        if values.next().is_some() {
            return retained;
        }
        let Some(encoded) = value.as_bytes().strip_prefix(b"Basic ") else {
            return retained;
        };
        if encoded.len() != 92 {
            return retained;
        }
        retained.decode = Some(STANDARD.decode_slice(encoded, &mut *retained.decoded));
        if !matches!(retained.decode, Some(Ok(68))) || &retained.decoded[..4] != b"aos:" {
            return retained;
        }
        // Re-encoding with the SAME engine excludes alternate padding/alphabet.
        let mut canonical = [0; 92];
        if STANDARD.encode_slice(&*retained.decoded, &mut canonical).ok() != Some(92)
            || canonical != encoded
        {
            return retained;
        }
        let mut handle = [0; 32];
        for (index, byte) in handle.iter_mut().enumerate() {
            let Some(high) = hex(retained.decoded[4 + index * 2]) else { return retained; };
            let Some(low) = hex(retained.decoded[5 + index * 2]) else { return retained; };
            *byte = high << 4 | low;
        }
        if handle != [0; 32] {
            retained.handle = Some(handle);
        }
        retained
    }

    pub(super) fn handle(&self) -> Option<[u8; 32]> {
        self.handle
    }

    pub(super) fn negative(&self) -> NegativeGitResponseV1 {
        if self.missing { NegativeGitResponseV1::Unauthorized } else { NegativeGitResponseV1::Forbidden }
    }
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

/// Reports a redacted failure while its actual originals remain in the owner.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("original Git read inspection is unavailable")]
pub struct GitReadInspectionUnavailableV1;

enum CauseV1 {
    Linux(aos_sandbox_linux::Error),
    Transport(SeqpacketError),
    Io(std::io::Error),
    Native(rustix::io::Errno),
    Session(PublicApiSessionError),
    Image(crate::immutable_image::ImmutableImageErrorV1),
    Clock(crate::ProtectedOwnershipClockError),
    Pair(aos_sandbox_core::OwnershipLeaseVerificationError),
    Timeout(tokio::time::error::Elapsed),
    Gateway(super::gateway_service::GitGatewayServiceErrorV1),
    Closed,
}

impl fmt::Debug for CauseV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GitReadInspectionCauseV1 { .. }")
    }
}

impl CauseV1 {
    fn native(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Linux(cause) => Some(cause),
            Self::Transport(cause) => Some(cause),
            Self::Io(cause) => Some(cause),
            Self::Native(cause) => Some(cause),
            Self::Session(cause) => Some(cause),
            Self::Image(cause) => Some(cause),
            Self::Clock(cause) => Some(cause),
            Self::Pair(cause) => Some(cause),
            Self::Timeout(cause) => Some(cause),
            Self::Gateway(cause) => Some(cause),
            Self::Closed => None,
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum PhaseV1 { Fresh, Checking, Ready, Ended, Completed }

#[derive(Clone, Copy)]
enum RoleV1 { Gateway, Controller }

impl RoleV1 {
    const fn unit(self) -> &'static str {
        match self {
            Self::Gateway => "aos-sandbox-git-gateway.service",
            Self::Controller => "aos-sandboxd.service",
        }
    }

    const fn user(self) -> &'static str {
        match self { Self::Gateway => "aos-git-gateway", Self::Controller => "aos-sandboxd" }
    }

    const fn context(self) -> &'static [u8] {
        match self {
            Self::Gateway => b"system_u:system_r:aos_sandbox_git_gateway_t",
            Self::Controller => b"system_u:system_r:aos_sandbox_controller_t",
        }
    }

    const fn cgroup(self) -> &'static str {
        match self {
            Self::Gateway => "system.slice/aos-sandbox-git-gateway.service",
            Self::Controller => "aos-control.slice/aos-sandboxd.service",
        }
    }
}

#[derive(Clone, Copy)]
struct RoleIdsV1 { uid: u32, gid: u32 }

struct ServiceDataV1 {
    invocation: [u8; 16],
    fragment: std::path::PathBuf,
}

struct RoleObservationV1 {
    role: RoleV1,
    ids: RoleIdsV1,
    proc: Option<PidFdProcObservationsV1>,
    identity: Option<PidFdProcessIdentity>,
    delivery: Option<Result<(Vec<OwnedValue>, Vec<OwnedValue>), aos_systemd::Error>>,
    original: Option<ServiceDataV1>,
    fragment: Option<RetainedImmutableFileV1>,
    root: Option<CgroupV2Root>,
    cgroup: Option<RetainedCgroupAnchor>,
}

impl RoleObservationV1 {
    fn new(role: RoleV1, ids: RoleIdsV1) -> Self {
        Self { role, ids, proc: None, identity: None, delivery: None,
            original: None, fragment: None, root: None, cgroup: None }
    }

    async fn check(&mut self, manager: &SystemdClient, process: &PidFd) -> Result<(), CauseV1> {
        let info = process.info().map_err(CauseV1::Linux)?;
        require_ids(info, self.ids)?;
        if self.proc.is_none() {
            self.proc = Some(process.prepare_proc_observations_v1());
            let proc = self.proc.as_mut().ok_or(CauseV1::Closed)?;
            self.identity = Some(proc.capture_stat(process).map_err(CauseV1::Linux)?);
            let context = proc.capture_context(process).map_err(CauseV1::Linux)?;
            require_context(context, self.role.context())?;
        } else {
            let proc = self.proc.as_mut().ok_or(CauseV1::Closed)?;
            if Some(proc.observe_identity(process).map_err(CauseV1::Linux)?) != self.identity {
                return Err(CauseV1::Closed);
            }
            require_context(proc.observe_context(process).map_err(CauseV1::Linux)?, self.role.context())?;
        }
        let identity = self.identity.ok_or(CauseV1::Closed)?;
        if identity.pid() != info.pid() || identity.thread_group_id() != info.pid() {
            return Err(CauseV1::Closed);
        }
        if self.root.is_none() {
            let fd = openat(CWD, "/sys/fs/cgroup", OFlags::PATH | OFlags::DIRECTORY
                | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty()).map_err(CauseV1::Native)?;
            self.root = Some(CgroupV2Root::from_owned(fd).map_err(CauseV1::Linux)?);
            self.cgroup = Some(self.root.as_ref().ok_or(CauseV1::Closed)?
                .resolve(Path::new(self.role.cgroup())).map_err(CauseV1::Linux)?);
        }
        self.cgroup.as_ref().ok_or(CauseV1::Closed)?
            .verify_exact_membership(process).map_err(CauseV1::Linux)?;

        self.delivery = Some(manager.observe_pid1_service_startup_properties(
            self.role.unit(), info.pid(),
            &["User", "Group", "ControlGroup", "NoNewPrivileges", "CapabilityBoundingSet",
                "AmbientCapabilities", "ProtectProc", "SELinuxContext"],
            &["FragmentPath", "DropInPaths", "Transient", "InvocationID"],
        ).await);
        let (service, unit) = self.delivery.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(CauseV1::Closed)?;
        let current = decode_service(self.role, service, unit)?;
        if let Some(original) = &self.original {
            if original.invocation != current.invocation || original.fragment != current.fragment {
                return Err(CauseV1::Closed);
            }
        } else {
            self.original = Some(current);
            self.fragment = Some(RetainedImmutableFileV1::observe_fragment(
                self.original.as_ref().ok_or(CauseV1::Closed)?.fragment.clone(),
            ).map_err(CauseV1::Image)?);
        }
        self.fragment.as_ref().ok_or(CauseV1::Closed)?.revalidate().map_err(CauseV1::Image)?;
        self.cgroup.as_ref().ok_or(CauseV1::Closed)?
            .verify_exact_membership(process).map_err(CauseV1::Linux)?;
        require_ids(process.info().map_err(CauseV1::Linux)?, self.ids)
    }
}

fn require_ids(info: aos_sandbox_linux::pidfd::PidFdInfo, ids: RoleIdsV1) -> Result<(), CauseV1> {
    let credentials = info.credentials().ok_or(CauseV1::Closed)?;
    if ids.uid == 0 || ids.gid == 0 || info.pid() != info.thread_group_id()
        || [credentials.real_user_id(), credentials.effective_user_id(),
            credentials.saved_user_id(), credentials.filesystem_user_id()] != [ids.uid; 4]
        || [credentials.real_group_id(), credentials.effective_group_id(),
            credentials.saved_group_id(), credentials.filesystem_group_id()] != [ids.gid; 4]
    { return Err(CauseV1::Closed); }
    Ok(())
}

fn require_context(bytes: &[u8], expected: &[u8]) -> Result<(), CauseV1> {
    let bytes = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    if bytes == expected || bytes.strip_suffix(b":s0") == Some(expected) { Ok(()) }
    else { Err(CauseV1::Closed) }
}

fn decode_service(role: RoleV1, service: &[OwnedValue], unit: &[OwnedValue]) -> Result<ServiceDataV1, CauseV1> {
    let [user, group, cgroup, nnp, bounding, ambient, proc, context] = service else {
        return Err(CauseV1::Closed);
    };
    let Value::Structure(context) = &**context else { return Err(CauseV1::Closed); };
    let [Value::Bool(false), Value::Str(context)] = context.fields() else { return Err(CauseV1::Closed); };
    if <&str>::try_from(user).ok() != Some(role.user()) || <&str>::try_from(group).ok() != Some(role.user())
        || <&str>::try_from(cgroup).ok() != Some(format!("/{}", role.cgroup()).as_str())
        || bool::try_from(nnp).ok() != Some(true) || u64::try_from(bounding).ok() != Some(0)
        || u64::try_from(ambient).ok() != Some(0) || <&str>::try_from(proc).ok() != Some("default")
        || context.as_str().as_bytes() != role.context()
    { return Err(CauseV1::Closed); }
    let [fragment, drops, transient, invocation] = unit else { return Err(CauseV1::Closed); };
    let Value::Array(drops) = &**drops else { return Err(CauseV1::Closed); };
    let Value::Array(invocation) = &**invocation else { return Err(CauseV1::Closed); };
    let invocation = crate::systemd_property_data::nonzero_invocation_bytes(invocation.inner())
        .ok_or(CauseV1::Closed)?;
    let fragment = <&str>::try_from(fragment).map_err(|_| CauseV1::Closed)?;
    if !drops.is_empty() || bool::try_from(transient).ok() != Some(false)
        || fragment.len() > 1024 || !fragment.ends_with(&format!("/{}", role.unit()))
    { return Err(CauseV1::Closed); }
    let fragment = std::fs::canonicalize(fragment).map_err(CauseV1::Io)?;
    if !fragment.starts_with("/nix/store") { return Err(CauseV1::Closed); }
    Ok(ServiceDataV1 { invocation, fragment })
}

#[derive(Default)]
struct RecordSlotV1 {
    received: Option<Result<ReceivedRecord, RetainedSeqpacketReceiveErrorV1>>,
    binding_failure: Option<(RecordBindingError, ReceivedRecord)>,
    payload: Option<Vec<u8>>,
    subject: Option<KernelAuthorizedRecordSubject>,
    observed: Option<RoleObservationV1>,
}

/// Holds one original channel and fixed record slots, without self-borrows.
struct ChannelV1 {
    socket: Option<Result<SeqpacketSocket, RetainedSeqpacketAdmissionErrorV1>>,
    manager: Option<Result<SystemdClient, aos_systemd::Error>>,
    clock: Option<ControllerProtectedClockV1>,
    first_clock: Option<RawPairedClockSample>,
    latest_clock: Option<RawPairedClockSample>,
    deadline: Option<u64>,
    connection: RoleObservationV1,
    first: RecordSlotV1,
    second: RecordSlotV1,
    send: Option<Result<(), SeqpacketError>>,
    failure: Option<CauseV1>,
    postcheck_debt: Option<CauseV1>,
    shutdown: Option<Result<(), rustix::io::Errno>>,
    phase: PhaseV1,
}

impl ChannelV1 {
    fn new(role: RoleV1, ids: RoleIdsV1) -> Self {
        Self {
            socket: None, manager: None, clock: None, first_clock: None,
            latest_clock: None, deadline: None, connection: RoleObservationV1::new(role, ids),
            first: RecordSlotV1::default(), second: RecordSlotV1::default(),
            send: None, failure: None, postcheck_debt: None, shutdown: None, phase: PhaseV1::Fresh,
        }
    }

    fn initialize_clock(&mut self, deadline: Option<u64>) -> Result<(), CauseV1> {
        self.clock = Some(ControllerProtectedClockV1::open_fixed().map_err(CauseV1::Clock)?);
        let sample = self.clock.as_mut().ok_or(CauseV1::Closed)?.sample().map_err(CauseV1::Clock)?;
        self.first_clock = Some(sample);
        self.latest_clock = Some(sample);
        let maximum = sample.boottime_nanoseconds().checked_add(MAXIMUM_LIFETIME).ok_or(CauseV1::Closed)?;
        self.deadline = Some(deadline.map_or(maximum, |deadline| deadline.min(maximum)));
        self.check_clock()
    }

    fn check_clock(&mut self) -> Result<(), CauseV1> {
        let sample = self.clock.as_mut().ok_or(CauseV1::Closed)?.sample().map_err(CauseV1::Clock)?;
        self.latest_clock = Some(sample);
        self.first_clock.ok_or(CauseV1::Closed)?.validate_later_sample(sample).map_err(CauseV1::Pair)?;
        if sample.boottime_nanoseconds() >= self.deadline.ok_or(CauseV1::Closed)? {
            return Err(CauseV1::Closed);
        }
        Ok(())
    }

    fn remaining(&mut self) -> Result<Duration, CauseV1> {
        self.check_clock()?;
        let sample = self.latest_clock.ok_or(CauseV1::Closed)?;
        Ok(Duration::from_nanos(self.deadline.ok_or(CauseV1::Closed)? - sample.boottime_nanoseconds()))
    }

    async fn check_role(&mut self) -> Result<(), CauseV1> {
        let remaining = self.remaining()?;
        if self.manager.is_none() {
            self.manager = Some(tokio::time::timeout(remaining, SystemdClient::connect()).await
                .map_err(CauseV1::Timeout)?);
        }
        if !matches!(self.manager, Some(Ok(_))) { return Err(CauseV1::Closed); }
        // Connecting can consume the original budget. Its whole Result is
        // resident before taking a fresh remaining-cut loan for the next await.
        let remaining = self.remaining()?;
        let manager = self.manager.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CauseV1::Closed)?;
        let socket = self.socket.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CauseV1::Closed)?;
        let peer = socket.peer();
        if peer.credentials().uid() != self.connection.ids.uid
            || peer.credentials().gid() != self.connection.ids.gid
        { return Err(CauseV1::Closed); }
        tokio::time::timeout(remaining, self.connection.check(manager, peer.pidfd())).await
            .map_err(CauseV1::Timeout)??;
        self.check_clock()
    }

    async fn receive(&mut self, second: bool, width: usize) -> Result<(), CauseV1> {
        let remaining = self.remaining()?;
        {
            let socket = self.socket.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CauseV1::Closed)?;
            let readiness = AsyncFd::new(socket.as_fd().map_err(CauseV1::Transport)?).map_err(CauseV1::Io)?;
            let mut ready = tokio::time::timeout(remaining, readiness.readable()).await
                .map_err(CauseV1::Timeout)?.map_err(CauseV1::Io)?;
            ready.clear_ready();
        }
        let slot = if second { &mut self.second } else { &mut self.first };
        if slot.received.is_some() || slot.payload.is_some() || slot.binding_failure.is_some() {
            return Err(CauseV1::Closed);
        }
        let socket = self.socket.as_mut().and_then(|result| result.as_mut().ok()).ok_or(CauseV1::Closed)?;
        slot.received = Some(socket.receive_retaining(width));
        // The WHOLE receive result/partial error is now resident before clock,
        // length, parser, record-subject or origin observations.
        let postcheck = self.check_clock();
        let slot = if second { &mut self.second } else { &mut self.first };
        if !matches!(slot.received, Some(Ok(_))) {
            if let Err(cause) = postcheck { self.postcheck_debt.get_or_insert(cause); }
            return Err(CauseV1::Closed);
        }
        postcheck?;
        let socket = self.socket.as_mut().and_then(|result| result.as_mut().ok()).ok_or(CauseV1::Closed)?;

        // The sole consuming lower binder owns its argument through the call.
        // Abort on provider unwind before a temporary owning return can drop;
        // no callback, extraction or custody take/reinsert continuation exists.
        let mut crossing = OriginalMoveFenceV1(true);
        let Some(Ok(record)) = slot.received.take() else { return Err(CauseV1::Closed); };
        match socket.bind_received_retaining(record) {
            Ok(bound) => {
                let (payload, subject, _peer) = bound.into_parts();
                slot.payload = Some(payload);
                slot.subject = Some(subject);
            }
            Err(original) => slot.binding_failure = Some(original),
        }
        crossing.0 = false;
        if slot.binding_failure.is_some() { return Err(CauseV1::Closed); }
        if slot.payload.as_ref().map(Vec::len) != Some(width) { return Err(CauseV1::Closed); }
        self.check_record_role(second).await?;
        self.check_clock()
    }

    async fn check_record_role(&mut self, second: bool) -> Result<(), CauseV1> {
        let remaining = self.remaining()?;
        let manager = self.manager.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CauseV1::Closed)?;
        let slot = if second { &mut self.second } else { &mut self.first };
        let subject = slot.subject.as_ref().ok_or(CauseV1::Closed)?;
        let ids = self.connection.ids;
        if subject.credentials().uid() != ids.uid || subject.credentials().gid() != ids.gid {
            return Err(CauseV1::Closed);
        }
        if slot.observed.is_none() {
            slot.observed = Some(RoleObservationV1::new(self.connection.role, ids));
        }
        let observed = slot.observed.as_mut().ok_or(CauseV1::Closed)?;
        tokio::time::timeout(remaining, observed.check(manager, subject.pidfd())).await
            .map_err(CauseV1::Timeout)??;
        // Independent fixed service bookends, not SO_PEERPIDFD==SCM_PIDFD as
        // a general kernel claim. Both must be this direct service invocation.
        if observed.original.as_ref().map(|value| value.invocation)
            != self.connection.original.as_ref().map(|value| value.invocation)
        { return Err(CauseV1::Closed); }
        self.check_clock()
    }

    async fn send(&mut self, bytes: &[u8]) -> Result<(), CauseV1> {
        let remaining = self.remaining()?;
        {
            let socket = self.socket.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CauseV1::Closed)?;
            let readiness = AsyncFd::new(socket.as_fd().map_err(CauseV1::Transport)?).map_err(CauseV1::Io)?;
            let mut ready = tokio::time::timeout(remaining, readiness.writable()).await
                .map_err(CauseV1::Timeout)?.map_err(CauseV1::Io)?;
            ready.clear_ready();
        }
        let socket = self.socket.as_mut().and_then(|result| result.as_mut().ok()).ok_or(CauseV1::Closed)?;
        self.send = Some(socket.send(bytes));
        if !matches!(self.send, Some(Ok(()))) { return Err(CauseV1::Closed); }
        self.check_clock()
    }

    fn finish(&mut self, result: Result<(), CauseV1>, phase: PhaseV1) -> Result<(), GitReadInspectionUnavailableV1> {
        match result {
            Ok(()) => { self.phase = phase; Ok(()) }
            Err(cause) => {
                self.failure.get_or_insert(cause);
                self.end();
                Err(GitReadInspectionUnavailableV1)
            }
        }
    }

    fn end(&mut self) {
        self.phase = PhaseV1::Ended;
        if self.shutdown.is_none() {
            if let Some(Ok(socket)) = &self.socket {
                if let Ok(fd) = socket.as_fd() {
                    self.shutdown = Some(rustix::net::shutdown(fd, rustix::net::Shutdown::Both));
                }
            }
        }
    }

    fn has_shutdown_debt(&self) -> bool {
        matches!(self.shutdown, Some(Err(_)))
            || self.socket.as_ref().and_then(|result| result.as_ref().err())
                .is_some_and(|cause| cause.shutdown_failure().is_some())
            || [&self.first, &self.second].iter().any(|slot| {
                slot.received.as_ref().and_then(|result| result.as_ref().err())
                    .is_some_and(|cause| cause.shutdown_failure().is_some())
            })
    }

    // A coarse closed marker does not replace a nested owning lower error.
    // All returned native Results are still resident and only borrowed here.
    fn native_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(cause) = self.failure.as_ref().and_then(CauseV1::native) {
            return Some(cause);
        }
        if let Some(cause) = self.socket.as_ref().and_then(|result| result.as_ref().err()) {
            return Some(cause);
        }
        if let Some(cause) = self.manager.as_ref().and_then(|result| result.as_ref().err()) {
            return Some(cause);
        }
        if let Some(cause) = self.connection.delivery.as_ref().and_then(|result| result.as_ref().err()) {
            return Some(cause);
        }
        for slot in [&self.first, &self.second] {
            if let Some(cause) = slot.received.as_ref().and_then(|result| result.as_ref().err()) {
                return Some(cause);
            }
            if let Some((cause, _)) = &slot.binding_failure { return Some(cause); }
            if let Some(cause) = slot.observed.as_ref().and_then(|owner| owner.delivery.as_ref())
                .and_then(|result| result.as_ref().err())
            { return Some(cause); }
        }
        self.send.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &(dyn std::error::Error + 'static))
    }
}

impl Drop for ChannelV1 {
    fn drop(&mut self) { self.end(); }
}

struct OriginalMoveFenceV1(bool);

impl Drop for OriginalMoveFenceV1 {
    fn drop(&mut self) {
        if self.0 { std::process::abort(); }
    }
}

struct ChannelOperationV1<'a> { channel: &'a mut ChannelV1, armed: bool }

impl ChannelOperationV1<'_> {
    fn finish(&mut self, result: Result<(), CauseV1>, phase: PhaseV1) -> Result<(), GitReadInspectionUnavailableV1> {
        let returned = self.channel.finish(result, phase);
        self.armed = false;
        returned
    }
}

impl Drop for ChannelOperationV1<'_> {
    fn drop(&mut self) {
        if self.armed { self.channel.end(); }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct ReadFactsV1 {
    pub(crate) principal: PrincipalId,
    pub(crate) project: ProjectId,
    pub(crate) resource: ResourceId,
    pub(crate) binding: ChannelBinding,
    pub(crate) holder: [u8; 32],
    fingerprint: [u8; 32],
    client_ca: [u8; 32],
    registrations: [u8; 32],
}

fn array<const N: usize>(bytes: &[u8], at: usize) -> Result<[u8; N], CauseV1> {
    bytes.get(at..at + N).and_then(|bytes| bytes.try_into().ok()).ok_or(CauseV1::Closed)
}

fn header(bytes: &[u8], magic: &[u8; 8], width: usize) -> Result<(), CauseV1> {
    if bytes.len() != width || bytes.get(..8) != Some(magic)
        || array::<2>(bytes, 8)? != 1_u16.to_be_bytes()
        || u32::from_be_bytes(array(bytes, 12)?) as usize != width
        || array::<8>(bytes, 16)? != 1_u64.to_be_bytes()
    { return Err(CauseV1::Closed); }
    Ok(())
}

fn new_header<const N: usize>(magic: &[u8; 8]) -> [u8; N] {
    let mut bytes = [0; N];
    bytes[..8].copy_from_slice(magic);
    bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
    bytes[12..16].copy_from_slice(&(N as u32).to_be_bytes());
    bytes[16..24].copy_from_slice(&1_u64.to_be_bytes());
    bytes
}

fn request_commitment(kind: u8, project: [u8; 16], resource: [u8; 16], length: u32, body: [u8; 32]) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"aos.sandbox.git.delegated-read-request.v1\0")
        .chain_update([kind])
        .chain_update(project)
        .chain_update(resource)
        .chain_update(length.to_be_bytes())
        .chain_update(body)
        .finalize().into()
}

fn decode_request(bytes: &[u8], channel: &mut ChannelV1) -> Result<ReadFactsV1, CauseV1> {
    header(bytes, b"AOSGDI01", REQUEST_BYTES)?;
    if !matches!(bytes[10], 1 | 2) || bytes[11] != 0 || bytes[424..].iter().any(|byte| *byte != 0) {
        return Err(CauseV1::Closed);
    }
    channel.check_clock()?;
    let now = channel.latest_clock.ok_or(CauseV1::Closed)?;
    let deadline = u64::from_be_bytes(array(bytes, 40)?);
    if array::<16>(bytes, 24)? != now.host_boot_id()
        || deadline <= now.boottime_nanoseconds()
        || deadline - now.boottime_nanoseconds() > MAXIMUM_LIFETIME
        || deadline > u64::from_be_bytes(array(bytes, 412)?)
        || array::<16>(bytes, 384)? != channel.connection.original.as_ref().ok_or(CauseV1::Closed)?.invocation
        || u64::from_be_bytes(array(bytes, 400)?) == 0 || u32::from_be_bytes(array(bytes, 408)?) == 0
        || u32::from_be_bytes(array(bytes, 420)?) as usize > super::http_owner::MAXIMUM_BODY_BYTES
        || (bytes[10] == 1 && u32::from_be_bytes(array(bytes, 420)?) != 0)
    { return Err(CauseV1::Closed); }
    channel.deadline = Some(channel.deadline.ok_or(CauseV1::Closed)?.min(deadline));
    let facts = ReadFactsV1 {
        principal: PrincipalId::from_bytes(array(bytes, 48)?),
        project: ProjectId::from_bytes(array(bytes, 64)?),
        resource: ResourceId::from_bytes(array(bytes, 80)?),
        binding: ChannelBinding::new(array(bytes, 128)?),
        holder: array(bytes, 288)?, fingerprint: array(bytes, 96)?,
        client_ca: array(bytes, 320)?, registrations: array(bytes, 352)?,
    };
    if array::<32>(bytes, 224)? != request_commitment(
        bytes[10], array(bytes, 64)?, array(bytes, 80)?,
        u32::from_be_bytes(array(bytes, 420)?), array(bytes, 256)?,
    ) {
        return Err(CauseV1::Closed);
    }
    if facts.principal.as_bytes() == &[0; 16] || facts.project.as_bytes() == &[0; 16]
        || facts.resource.as_bytes() == &[0; 16] || facts.holder == [0; 32]
        || [facts.fingerprint, facts.client_ca, facts.registrations,
            array(bytes, 160)?, array(bytes, 192)?, array(bytes, 224)?, array(bytes, 256)?]
            .iter().any(|value| *value == [0; 32])
    { return Err(CauseV1::Closed); }
    Ok(facts)
}

/// Retains the fixed direct listener and every returned bind failure.
/// No activation descriptor, alternate path, repair or unlink is accepted.
pub struct GitReadListenerAttemptV1 {
    listener: Option<Result<RecordSubjectListener, SeqpacketError>>,
    directory: Option<std::fs::File>,
    directory_identity: Option<(u64, u64)>,
    ids: Option<RoleIdsV1>,
    controller_ids: Option<RoleIdsV1>,
    failure: Option<CauseV1>,
    phase: PhaseV1,
}

impl GitReadListenerAttemptV1 {
    /// Creates empty destination slots without opening a descriptor.
    pub const fn new() -> Self {
        Self { listener: None, directory: None, directory_identity: None,
            ids: None, controller_ids: None, failure: None, phase: PhaseV1::Fresh }
    }

    /// Binds only the selected existing Controller's fixed direct endpoint.
    ///
    /// Numeric inputs are configuration DATA. Actual process IDs, subject,
    /// directory, listener and later original peer bookends independently hold.
    /// Lower open/bind pre-return custody remains outside this contract.
    ///
    /// # Errors
    /// Retains original returned ownership and typed native/bind failures.
    pub fn bind_controller_once(
        &mut self,
        controller_uid: u32,
        controller_gid: u32,
        gateway_uid: u32,
        gateway_gid: u32,
    ) -> Result<(), GitReadInspectionUnavailableV1> {
        if self.phase != PhaseV1::Fresh { self.phase = PhaseV1::Ended; return Err(GitReadInspectionUnavailableV1); }
        self.phase = PhaseV1::Checking;
        let result = (|| {
            if controller_uid == 0 || controller_gid == 0 || gateway_uid == 0 || gateway_gid == 0
                || controller_uid == gateway_uid || controller_gid == gateway_gid
                || rustix::process::getuid().as_raw() != controller_uid
                || rustix::process::geteuid().as_raw() != controller_uid
                || rustix::process::getgid().as_raw() != controller_gid
                || rustix::process::getegid().as_raw() != controller_gid
            { return Err(CauseV1::Closed); }
            aos_sandbox_linux::guest_confinement::require_subject(
                "system_u:system_r:aos_sandbox_controller_t",
            ).map_err(CauseV1::Linux)?;
            self.ids = Some(RoleIdsV1 { uid: gateway_uid, gid: gateway_gid });
            self.controller_ids = Some(RoleIdsV1 { uid: controller_uid, gid: controller_gid });
            self.directory = Some(std::fs::File::from(openat(CWD, DIRECTORY,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty()).map_err(CauseV1::Native)?));
            let directory = self.directory.as_ref().ok_or(CauseV1::Closed)?;
            let stat = rustix::fs::fstat(directory).map_err(CauseV1::Native)?;
            if stat.st_uid != controller_uid || stat.st_gid != controller_gid || stat.st_mode & 0o7777 != 0o755 {
                return Err(CauseV1::Closed);
            }
            self.directory_identity = Some((stat.st_dev, stat.st_ino));
            require_runtime_label(directory)?;
            self.listener = Some(RecordSubjectListener::bind(Path::new(ENDPOINT), 2));
            let listener = self.listener.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CauseV1::Closed)?;
            listener.require_local_filesystem_path(Path::new(ENDPOINT)).map_err(CauseV1::Transport)?;
            rustix::fs::chmod(ENDPOINT, Mode::from_raw_mode(0o666)).map_err(CauseV1::Native)?;
            self.check_path(controller_uid, controller_gid)
        })();
        match result {
            Ok(()) => { self.phase = PhaseV1::Ready; Ok(()) }
            Err(cause) => { self.failure.get_or_insert(cause); self.phase = PhaseV1::Ended; Err(GitReadInspectionUnavailableV1) }
        }
    }

    fn check_path(&self, uid: u32, gid: u32) -> Result<(), CauseV1> {
        let directory = self.directory.as_ref().ok_or(CauseV1::Closed)?;
        let held = rustix::fs::fstat(directory).map_err(CauseV1::Native)?;
        let named = rustix::fs::statat(CWD, DIRECTORY, rustix::fs::AtFlags::SYMLINK_NOFOLLOW).map_err(CauseV1::Native)?;
        if self.directory_identity != Some((held.st_dev, held.st_ino))
            || (held.st_dev, held.st_ino) != (named.st_dev, named.st_ino)
            || held.st_uid != uid || held.st_gid != gid || held.st_mode & 0o7777 != 0o755
        { return Err(CauseV1::Closed); }
        require_runtime_label(directory)?;
        let socket = rustix::fs::statat(CWD, ENDPOINT, rustix::fs::AtFlags::SYMLINK_NOFOLLOW).map_err(CauseV1::Native)?;
        if rustix::fs::FileType::from_raw_mode(socket.st_mode) != rustix::fs::FileType::Socket
            || socket.st_uid != uid || socket.st_gid != gid || socket.st_mode & 0o7777 != 0o666
        { return Err(CauseV1::Closed); }
        let listener = self.listener.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CauseV1::Closed)?;
        listener.validate_current().map_err(CauseV1::Transport)?;
        listener.require_local_filesystem_path(Path::new(ENDPOINT)).map_err(CauseV1::Transport)
    }

    /// Parks a whole actual accept outcome directly in one empty fixed candidate.
    ///
    /// # Errors
    /// Permanently fences failed or interrupted acceptance; never reaccepts it.
    pub fn accept_original<'a>(
        &'a mut self,
        destination: &'a mut Option<GitReadRequestOwnerV1>,
    ) -> impl std::future::Future<Output = Result<(), GitReadInspectionUnavailableV1>> + 'a {
        let armed = self.phase == PhaseV1::Ready && destination.is_none();
        if armed { self.phase = PhaseV1::Checking; }
        async move {
            let mut operation = ListenerOperationV1 { listener: self, armed };
            if !armed { return Err(GitReadInspectionUnavailableV1); }
            let result = async {
                let ids = operation.listener.ids.ok_or(CauseV1::Closed)?;
                let controller = operation.listener.controller_ids.ok_or(CauseV1::Closed)?;
                operation.listener.check_path(controller.uid, controller.gid)?;
                let listener = operation.listener.listener.as_ref()
                    .and_then(|result| result.as_ref().ok()).ok_or(CauseV1::Closed)?;
                {
                    let readiness = AsyncFd::new(listener.as_fd()).map_err(CauseV1::Io)?;
                    let mut ready = readiness.readable().await.map_err(CauseV1::Io)?;
                    ready.clear_ready();
                }
                operation.listener.check_path(controller.uid, controller.gid)?;
                // Empty construction and slot parking precede the actual accept.
                *destination = Some(GitReadRequestOwnerV1::new(ids));
                let candidate = destination.as_mut().ok_or(CauseV1::Closed)?;
                let listener = operation.listener.listener.as_mut()
                    .and_then(|result| result.as_mut().ok()).ok_or(CauseV1::Closed)?;
                candidate.channel.socket = Some(listener.accept_retaining());
                if !matches!(candidate.channel.socket, Some(Ok(_))) { return Err(CauseV1::Closed); }
                candidate.channel.initialize_clock(None)?;
                operation.listener.check_path(controller.uid, controller.gid)?;
                Ok(())
            }.await;
            match result {
                Ok(()) => { operation.listener.phase = PhaseV1::Ready; operation.armed = false; Ok(()) }
                Err(cause) => {
                    operation.listener.failure.get_or_insert(cause);
                    operation.listener.phase = PhaseV1::Ended;
                    if let Some(candidate) = destination { candidate.channel.end(); }
                    operation.armed = false;
                    Err(GitReadInspectionUnavailableV1)
                }
            }
        }
    }
}

impl Default for GitReadListenerAttemptV1 {
    fn default() -> Self { Self::new() }
}

struct ListenerOperationV1<'a> { listener: &'a mut GitReadListenerAttemptV1, armed: bool }

impl Drop for ListenerOperationV1<'_> {
    fn drop(&mut self) {
        if self.armed { self.listener.phase = PhaseV1::Ended; }
    }
}

fn require_runtime_label(file: &std::fs::File) -> Result<(), CauseV1> {
    let mut bytes = [0; 256];
    let count = rustix::fs::fgetxattr(file, "security.selinux", &mut bytes[..]).map_err(CauseV1::Native)?;
    let actual = bytes[..count].strip_suffix(&[0]).unwrap_or(&bytes[..count]);
    if actual != b"system_u:object_r:aos_git_read_delegate_runtime_t:s0" { return Err(CauseV1::Closed); }
    Ok(())
}

/// Owns one genuine accepted request, its original subjects and Journal crossing.
/// Construction is private to the fixed direct listener; no supplied FD/peer,
/// parsed field tuple or positive authority constructor exists.
pub struct GitReadRequestOwnerV1 {
    channel: ChannelV1,
    facts: Option<ReadFactsV1>,
    pub(crate) crossing: RetainedAuthorizationTimeFloorV1,
    pub(crate) decision: Option<Result<CurrentCapabilityDecisionV1, CliAuthorizationAdapterError>>,
    result: Option<[u8; RESULT_BYTES]>,
    evaluation_attempted: bool,
    pub(crate) lookup_failure: Option<crate::publisher_authority::PublisherAuthorityError>,
}

impl GitReadRequestOwnerV1 {
    fn new(ids: RoleIdsV1) -> Self {
        Self { channel: ChannelV1::new(RoleV1::Gateway, ids), facts: None,
            crossing: RetainedAuthorizationTimeFloorV1::default(), decision: None,
            result: None, evaluation_attempted: false, lookup_failure: None }
    }

    /// Receives once into the original fixed slots before parsing or admission.
    ///
    /// # Errors
    /// Keeps first typed cause, raw subjects/bytes and separate shutdown debt.
    pub fn receive_original(&mut self) -> impl std::future::Future<Output = Result<(), GitReadInspectionUnavailableV1>> + '_ {
        let armed = self.channel.phase == PhaseV1::Fresh && self.facts.is_none();
        if armed { self.channel.phase = PhaseV1::Checking; }
        let Self { channel, facts, .. } = self;
        let mut operation = ChannelOperationV1 { channel, armed };
        async move {
            if !armed { operation.channel.end(); return Err(GitReadInspectionUnavailableV1); }
            let returned = async {
                operation.channel.check_role().await?;
                operation.channel.receive(false, REQUEST_BYTES).await?;
                let slot = &mut operation.channel.first;
                let bytes = slot.payload.as_ref().ok_or(CauseV1::Closed)?;
                // Fixed-size stack DATA does not replace the resident original.
                let bytes: [u8; REQUEST_BYTES] = bytes.as_slice().try_into().map_err(|_| CauseV1::Closed)?;
                *facts = Some(decode_request(&bytes, operation.channel)?);
                operation.channel.check_role().await?;
                Ok(())
            }.await;
            operation.finish(returned, PhaseV1::Ready)
        }
    }

    /// Rechecks original fixed roles and the nonrenewable cut.
    ///
    /// # Errors
    /// Permanently fences failure or interrupted revalidation, retaining owners.
    pub fn recheck(&mut self) -> impl std::future::Future<Output = Result<(), GitReadInspectionUnavailableV1>> + '_ {
        let previous = self.channel.phase;
        let armed = matches!(previous, PhaseV1::Ready | PhaseV1::Completed);
        if armed { self.channel.phase = PhaseV1::Checking; }
        let mut operation = ChannelOperationV1 { channel: &mut self.channel, armed };
        async move {
            if !armed { operation.channel.end(); return Err(GitReadInspectionUnavailableV1); }
            let result = async {
                operation.channel.check_role().await?;
                operation.channel.check_record_role(false).await?;
                Ok(())
            }.await;
            operation.finish(result, previous)
        }
    }

    /// Borrows route DATA only after genuine original receipt admission.
    ///
    /// # Errors
    /// Refuses a failed or incomplete original. Returned IDs grant no rights.
    pub fn route(&self) -> Result<(ProjectId, ResourceId), GitReadInspectionUnavailableV1> {
        if !matches!(self.channel.phase, PhaseV1::Ready | PhaseV1::Completed) { return Err(GitReadInspectionUnavailableV1); }
        self.facts.map(|facts| (facts.project, facts.resource)).ok_or(GitReadInspectionUnavailableV1)
    }

    pub(crate) fn begin_evaluation(&mut self, acceptor: &PublicApiSessionAcceptor) -> Result<ReadFactsV1, CliAuthorizationAdapterError> {
        if self.channel.phase != PhaseV1::Ready || self.evaluation_attempted {
            return Err(CliAuthorizationAdapterError::ProtectedAuthorizationRejected);
        }
        self.evaluation_attempted = true;
        let facts = self.facts.ok_or(CliAuthorizationAdapterError::ProtectedAuthorizationRejected)?;
        acceptor.check_git_delegated_registration(facts.fingerprint, facts.principal, facts.project,
            facts.binding, facts.client_ca, facts.registrations)
            .map_err(|cause| {
                self.channel.failure.get_or_insert(CauseV1::Session(cause));
                CliAuthorizationAdapterError::ProtectedAuthorizationRejected
            })?;
        self.channel.check_clock().map_err(|cause| {
            self.channel.failure.get_or_insert(cause);
            CliAuthorizationAdapterError::ProtectedAuthorizationRejected
        })?;
        Ok(facts)
    }

    pub(crate) fn evaluate_current(
        &mut self,
        journal: &mut crate::Journal,
        capability: aos_sandbox_core::CapabilityId,
        facts: ReadFactsV1,
    ) {
        let Some(clock) = self.channel.clock.as_mut() else {
            self.decision = Some(Err(CliAuthorizationAdapterError::ProtectedAuthorizationRejected));
            return;
        };
        self.decision = Some(crate::cli_model::authorization_adapter::evaluate_current_protected_capability_retained(
            journal, crate::publisher_authority::PublisherAuthorityLimits::default(),
            crate::publisher_policy::PublisherPolicyLimits::default(), capability,
            facts.project, facts.principal, facts.binding, clock,
            aos_sandbox_core::ResourceKind::GitObjectDatabase, aos_sandbox_core::Operation::ContentRead,
            &aos_sandbox_core::Selector::Resource { resource: facts.resource }, &mut self.crossing,
        ));
    }

    /// Rechecks the same loaded registration originals, never recapturing TLS.
    ///
    /// # Errors
    /// Retains the actual registration cause and fences this original.
    pub fn recheck_registration(&mut self, acceptor: &PublicApiSessionAcceptor) -> Result<(), GitReadInspectionUnavailableV1> {
        let Some(facts) = self.facts else { self.channel.end(); return Err(GitReadInspectionUnavailableV1); };
        if !matches!(self.channel.phase, PhaseV1::Ready | PhaseV1::Completed) {
            self.channel.end(); return Err(GitReadInspectionUnavailableV1);
        }
        let result = acceptor.check_git_delegated_registration(facts.fingerprint, facts.principal,
            facts.project, facts.binding, facts.client_ca, facts.registrations).map_err(CauseV1::Session);
        self.channel.finish(result, self.channel.phase)
    }

    /// Sends only historical inspection DATA, then receives a local receipt.
    /// No result means reservation/effect permission or a remote Drain receipt.
    ///
    /// # Errors
    /// Keeps failed whole records, typed causes and debt; cannot retry the flight.
    pub fn complete_local_inspection(&mut self) -> impl std::future::Future<Output = Result<(), GitReadInspectionUnavailableV1>> + '_ {
        let armed = self.channel.phase == PhaseV1::Ready && self.result.is_none() && self.evaluation_attempted;
        if armed { self.channel.phase = PhaseV1::Checking; }
        let handle_rejected = self.handle_rejected();
        let Self { channel, result, decision, crossing, facts, .. } = self;
        let mut operation = ChannelOperationV1 { channel, armed };
        async move {
            if !armed { operation.channel.end(); return Err(GitReadInspectionUnavailableV1); }
            let returned = async {
                operation.channel.check_role().await?;
                let request = operation.channel.first.payload.as_ref().ok_or(CauseV1::Closed)?;
                let original = facts.ok_or(CauseV1::Closed)?;
                let mut bytes = new_header::<RESULT_BYTES>(b"AOSGDR01");
                bytes[10] = 1;
                bytes[11] = match decision {
                    Some(Ok(_)) if crossing.clean_readback() && operation.channel.failure.is_none() => 1,
                    Some(Err(_)) if (crossing.clean_readback() || handle_rejected)
                        && operation.channel.failure.is_none() => 2,
                    _ => 3,
                };
                bytes[24..40].copy_from_slice(&operation.channel.first_clock.ok_or(CauseV1::Closed)?.host_boot_id());
                bytes[40..48].copy_from_slice(&operation.channel.deadline.ok_or(CauseV1::Closed)?.to_be_bytes());
                bytes[48..80].copy_from_slice(&Sha256::digest(request));
                bytes[80..96].copy_from_slice(original.principal.as_bytes());
                bytes[96..112].copy_from_slice(original.project.as_bytes());
                bytes[112..128].copy_from_slice(original.resource.as_bytes());
                if bytes[11] == 1 {
                    let decision = decision.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CauseV1::Closed)?;
                    let coordinates = decision.original_coordinates(array(request, 160)?);
                    bytes[128..136].copy_from_slice(&coordinates.policy_generation.to_be_bytes());
                    bytes[136..144].copy_from_slice(&coordinates.revocation_generation.to_be_bytes());
                    bytes[144..152].copy_from_slice(&coordinates.controller_generation.to_be_bytes());
                    bytes[152..184].copy_from_slice(&coordinates.policy_digest);
                    bytes[184..192].copy_from_slice(&decision.authorized_wall_seconds().to_be_bytes());
                }
                *result = Some(bytes);
                operation.channel.send(result.as_ref().ok_or(CauseV1::Closed)?).await?;
                operation.channel.receive(true, RECEIPT_BYTES).await?;
                let receipt = operation.channel.second.payload.as_ref().ok_or(CauseV1::Closed)?;
                header(receipt, b"AOSGDA01", RECEIPT_BYTES)?;
                if receipt[10] != 1 || receipt[11] != 0 || receipt[56..].iter().any(|byte| *byte != 0)
                    || array::<32>(receipt, 24)? != <[u8; 32]>::from(Sha256::digest(bytes))
                { return Err(CauseV1::Closed); }
                operation.channel.check_role().await?;
                operation.channel.check_record_role(false).await?;
                operation.channel.check_record_role(true).await?;
                Ok(())
            }.await;
            operation.finish(returned, PhaseV1::Completed)
        }
    }

    /// Reports separate local shutdown debt without claiming any owner Drain.
    pub fn shutdown_debt_observed(&self) -> bool { self.channel.has_shutdown_debt() }

    /// Borrows an actual resident failure without taking any custody or IO.
    /// Coarse inherited evaluator/readback refusals need not have a native cause.
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(cause) = self.lookup_failure.as_ref() { return Some(cause); }
        if let Some(cause) = self.crossing.failure() { return Some(cause); }
        self.channel.native_failure()
    }

    /// Reports whether a crossing/native refusal must remain terminal-resident.
    /// A negative grant result after a clean floor readback is not an effect.
    pub fn terminal_failure_observed(&self) -> bool {
        self.channel.failure.is_some() || self.channel.phase == PhaseV1::Ended
            || self.channel.postcheck_debt.is_some()
            || self.channel.has_shutdown_debt()
            || (self.evaluation_attempted && !self.crossing.clean_readback() && !self.handle_rejected())
    }

    fn handle_rejected(&self) -> bool {
        use crate::publisher_authority::PublisherAuthorityError as Error;
        matches!(self.lookup_failure, Some(Error::UnknownCapability | Error::Revoked
            | Error::InvalidHandle | Error::HandleHolderMismatch))
    }

    /// Ends a completed local exchange before deliberate original destruction.
    ///
    /// # Errors
    /// Refuses crossing failures or real shutdown debt; absence is not Drain.
    pub fn retire_completed_local(&mut self) -> Result<(), GitReadInspectionUnavailableV1> {
        if self.channel.phase != PhaseV1::Completed || self.terminal_failure_observed() {
            self.channel.end(); return Err(GitReadInspectionUnavailableV1);
        }
        self.channel.end();
        if self.channel.has_shutdown_debt() { return Err(GitReadInspectionUnavailableV1); }
        self.channel.phase = PhaseV1::Completed;
        Ok(())
    }
}

/// Keeps the original local client in the same funded Gateway resident.
pub(super) struct GitDelegatedClientV1 {
    channel: ChannelV1,
    request: Option<[u8; REQUEST_BYTES]>,
    receipt: Option<[u8; RECEIPT_BYTES]>,
}

impl GitDelegatedClientV1 {
    pub(super) fn new(controller_uid: u32, controller_gid: u32) -> Self {
        Self { channel: ChannelV1::new(RoleV1::Controller,
            RoleIdsV1 { uid: controller_uid, gid: controller_gid }), request: None, receipt: None }
    }

    pub(super) fn inspect<'a>(
        &'a mut self,
        ready: &'a mut super::http_owner::GitHttpRequestV1<'_>,
        admission: &'a super::gateway_service::startup::GatewayAdmissionV1,
    ) -> impl std::future::Future<Output = Result<NegativeGitResponseV1, GitReadInspectionUnavailableV1>> + 'a {
        let armed = self.channel.phase == PhaseV1::Fresh && self.request.is_none();
        if armed { self.channel.phase = PhaseV1::Checking; }
        let Self { channel, request, receipt } = self;
        let mut operation = ChannelOperationV1 { channel, armed };
        async move {
            if !armed { operation.channel.end(); return Err(GitReadInspectionUnavailableV1); }
            let result = async {
                operation.channel.initialize_clock(Some(ready.original_deadline_boottime()))?;
                ready.recheck().await.map_err(|_| CauseV1::Closed)?;
                let remaining = operation.channel.remaining()?;
                tokio::time::timeout(remaining, admission.recheck()).await
                    .map_err(CauseV1::Timeout)?.map_err(CauseV1::Gateway)?;
                operation.channel.check_clock()?;
                let (kind, basic) = ready.delegated_input().ok_or(CauseV1::Closed)?;
                let holder = basic.handle().ok_or(CauseV1::Closed)?;
                let peer = ready.peer();
                let trust = peer.original_trust_coordinates().map_err(CauseV1::Session)?;
                let sample = operation.channel.first_clock.ok_or(CauseV1::Closed)?;
                let mut bytes = new_header::<REQUEST_BYTES>(b"AOSGDI01");
                bytes[10] = kind as u8;
                bytes[24..40].copy_from_slice(&sample.host_boot_id());
                bytes[40..48].copy_from_slice(&operation.channel.deadline.ok_or(CauseV1::Closed)?.to_be_bytes());
                bytes[48..64].copy_from_slice(peer.principal().as_bytes());
                bytes[64..80].copy_from_slice(peer.project().as_bytes());
                bytes[80..96].copy_from_slice(ready.request().endpoint().repository().as_bytes());
                bytes[96..128].copy_from_slice(&trust[3]);
                bytes[128..160].copy_from_slice(peer.key_binding().as_bytes());
                bytes[160..192].copy_from_slice(&peer.session_binding());
                bytes[192..224].copy_from_slice(ready.binding().as_bytes());
                let body_digest = Sha256::digest(ready.body()).into();
                bytes[224..256].copy_from_slice(&request_commitment(
                    kind as u8, *peer.project().as_bytes(),
                    *ready.request().endpoint().repository().as_bytes(),
                    ready.body().len() as u32, body_digest,
                ));
                bytes[256..288].copy_from_slice(&body_digest);
                bytes[288..320].copy_from_slice(&holder);
                bytes[320..352].copy_from_slice(&trust[1]);
                bytes[352..384].copy_from_slice(&trust[2]);
                bytes[384..400].copy_from_slice(&admission.original_invocation());
                bytes[400..408].copy_from_slice(&ready.original_socket_cookie().get().to_be_bytes());
                bytes[408..412].copy_from_slice(&ready.original_stream_id().to_be_bytes());
                bytes[412..420].copy_from_slice(&peer.deadline_boottime_nanoseconds().map_err(CauseV1::Session)?.to_be_bytes());
                bytes[420..424].copy_from_slice(&(ready.body().len() as u32).to_be_bytes());
                *request = Some(bytes);
                operation.channel.socket = Some(SeqpacketSocket::connect_retaining(Path::new(ENDPOINT)));
                let socket = operation.channel.socket.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CauseV1::Closed)?;
                socket.peer().require_peer_filesystem_path(socket.as_fd().map_err(CauseV1::Transport)?, Path::new(ENDPOINT))
                    .map_err(CauseV1::Transport)?;

                let exchanged = async {
                    operation.channel.check_role().await?;
                    operation.channel.send(request.as_ref().ok_or(CauseV1::Closed)?).await?;
                    operation.channel.receive(false, RESULT_BYTES).await?;
                    let bytes = operation.channel.first.payload.as_ref().ok_or(CauseV1::Closed)?;
                    header(bytes, b"AOSGDR01", RESULT_BYTES)?;
                    let original = request.as_ref().ok_or(CauseV1::Closed)?;
                    if bytes[10] != 1 || !matches!(bytes[11], 1 | 2 | 3)
                        || bytes[192..].iter().any(|byte| *byte != 0)
                        || bytes[24..48] != original[24..48]
                        || array::<32>(bytes, 48)? != <[u8; 32]>::from(Sha256::digest(original))
                        || bytes[80..128] != original[48..96]
                        || (bytes[11] != 1 && bytes[128..192].iter().any(|byte| *byte != 0))
                    { return Err(CauseV1::Closed); }
                    let status = if bytes[11] == 2 { NegativeGitResponseV1::Forbidden } else { NegativeGitResponseV1::Unavailable };
                    let mut received = new_header::<RECEIPT_BYTES>(b"AOSGDA01");
                    received[10] = 1;
                    received[24..56].copy_from_slice(&Sha256::digest(bytes));
                    *receipt = Some(received);
                    operation.channel.send(receipt.as_ref().ok_or(CauseV1::Closed)?).await?;
                    operation.channel.check_role().await?;
                    operation.channel.check_record_role(false).await?;
                    Ok(status)
                };
                tokio::pin!(exchanged);
                let status = tokio::select! {
                    result = &mut exchanged => result?,
                    _failed = poll_fn(|context| ready.poll_while_child_parked(context)) => return Err(CauseV1::Closed),
                };
                drop(exchanged);
                ready.recheck().await.map_err(|_| CauseV1::Closed)?;
                let remaining = operation.channel.remaining()?;
                tokio::time::timeout(remaining, admission.recheck()).await
                    .map_err(CauseV1::Timeout)?.map_err(CauseV1::Gateway)?;
                operation.channel.check_clock()?;
                Ok::<_, CauseV1>(status)
            }.await;
            match result {
                Ok(status) => {
                    operation.finish(Ok(()), PhaseV1::Completed)?;
                    operation.channel.end();
                    if operation.channel.has_shutdown_debt() { return Err(GitReadInspectionUnavailableV1); }
                    operation.channel.phase = PhaseV1::Completed;
                    Ok(status)
                }
                Err(cause) => {
                    operation.finish(Err(cause), PhaseV1::Ended)?;
                    Err(GitReadInspectionUnavailableV1)
                }
            }
        }
    }

    pub(super) fn shutdown_debt_observed(&self) -> bool { self.channel.has_shutdown_debt() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_basic_handle_is_lookup_data_and_redacted() {
        let mut headers = http::HeaderMap::new();
        let bytes = format!("aos:{}", "01".repeat(32));
        headers.insert(http::header::AUTHORIZATION,
            format!("Basic {}", STANDARD.encode(bytes)).parse().unwrap());
        let retained = BasicHolderV1::capture(&headers);
        assert_eq!(retained.handle(), Some([1; 32]));
    }

    #[test]
    fn duplicate_uppercase_zero_and_wrong_user_refuse() {
        for value in [format!("aos:{}", "AA".repeat(32)),
            format!("aos:{}", "00".repeat(32)), format!("bob:{}", "01".repeat(32))]
        {
            let mut headers = http::HeaderMap::new();
            let value: http::HeaderValue = format!("Basic {}", STANDARD.encode(value)).parse().unwrap();
            headers.insert(http::header::AUTHORIZATION, value.clone());
            assert!(BasicHolderV1::capture(&headers).handle().is_none());
            headers.append(http::header::AUTHORIZATION, value);
            assert!(BasicHolderV1::capture(&headers).handle().is_none());
        }
    }

    #[test]
    fn wire_widths_headers_and_negative_statuses_are_closed() {
        for (bytes, magic, width) in [
            (new_header::<REQUEST_BYTES>(b"AOSGDI01").to_vec(), b"AOSGDI01", REQUEST_BYTES),
            (new_header::<RESULT_BYTES>(b"AOSGDR01").to_vec(), b"AOSGDR01", RESULT_BYTES),
            (new_header::<RECEIPT_BYTES>(b"AOSGDA01").to_vec(), b"AOSGDA01", RECEIPT_BYTES),
        ] {
            assert!(header(&bytes, magic, width).is_ok());
            assert!(header(&bytes[..width - 1], magic, width).is_err());
        }
        assert_eq!([NegativeGitResponseV1::Unauthorized.status(), NegativeGitResponseV1::Forbidden.status(),
            NegativeGitResponseV1::Unavailable.status()], [401, 403, 503]);
    }
}
