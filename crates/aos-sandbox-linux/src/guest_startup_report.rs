//! Retains the fixed Guest startup report and its original Host carrier.
//!
//! Both report kinds use the existing FD8 descriptor-report engine. The normal
//! component kind supplements the ordinary Agent and PID1 topology; it does
//! not select the canary Agent, authorize execution or prove systemd exec.
//! Only the actual post-exec systemd report can establish that last fact.
//!
//! ```text
//! Challenge (200): AOSHCR01|AOSNHR01, version:u16=1, kind:u16=0,
//! length:u32=200, channel-or-canary-nonce[32], request-or-job-digest[32],
//! Guardian[32], sandbox[16], incarnation[16], epoch:u64, generation:u64,
//! reserved[16], Host-boot[16], original-BOOTTIME-D:u64.
//! Report (176): same first160 bytes, phase-count:u32, errno:i32, sequence:u64.
//! ```

use sha2::{Digest as _, Sha256};
use std::fs::{File, OpenOptions};
use std::os::fd::{AsFd as _, BorrowedFd};
use std::os::unix::fs::OpenOptionsExt as _;
use std::process::{Child, Command};

use crate::inherited_fd::GuestCanaryReportOriginalV1;
use crate::pidfd::HostCanaryLocalChildOriginalsV1;
use crate::seqpacket::{
    GuestAncestorHostChannelV1, GuestAncestorHostRecordV1, RetainedSeqpacketReceiveErrorV1,
    SeqpacketError,
};

const O_CLOEXEC: i32 = 0o2_000_000;

/// Identifies one fixed report wire family as nonauthorizing comparison DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostStartupReportKindV1 {
    /// Preserves the original isolated canary startup and challenge bytes.
    Canary,
    /// Supplements normal PID1 topology and the ordinary Agent effect owner.
    Component,
}

/// Reports a pure challenge comparison refusal without a native observation.
#[derive(Debug, thiserror::Error)]
pub enum HostStartupReportChallengeErrorV1 {
    /// The fixed framing, sealed tuple or channel binding differs.
    #[error("startup report challenge differs from the original launch")]
    Mismatch,
    /// The supplied absolute BOOTTIME endpoint is zero.
    #[error("startup report challenge has no original deadline")]
    Deadline,
}

fn challenge_kind(
    bytes: &[u8],
) -> Result<HostStartupReportKindV1, HostStartupReportChallengeErrorV1> {
    use HostStartupReportChallengeErrorV1::Mismatch;
    if bytes.len() != CANARY_CHALLENGE_BYTES
        || bytes[8..12] != [0, 1, 0, 0]
        || bytes[12..16] != (CANARY_CHALLENGE_BYTES as u32).to_be_bytes()
        || bytes[160..176] != [0; 16]
        || bytes[16..48] == [0; 32]
        || bytes[48..80] == [0; 32]
        || bytes[80..112] == [0; 32]
        || bytes[176..192] == [0; 16]
    {
        return Err(Mismatch);
    }
    match &bytes[..8] {
        b"AOSHCR01" => Ok(HostStartupReportKindV1::Canary),
        b"AOSNHR01" => Ok(HostStartupReportKindV1::Component),
        _ => Err(Mismatch),
    }
}

/// Compares a fixed report challenge with the same sealed Agent launch tuple.
///
/// Component reports bind the actual normal channel directly. Canary reports
/// retain the original domain-separated derivation. Returned kind/deadline
/// DATA grants no Host, process, financial or effect authority.
///
/// # Errors
/// Refuses malformed framing, another sealed runtime/channel or a zero D.
pub fn require_host_startup_report_challenge_v1(
    bytes: &[u8],
    runtime: &[u8; 104],
    channel: [u8; 32],
) -> Result<(HostStartupReportKindV1, u64), HostStartupReportChallengeErrorV1> {
    use HostStartupReportChallengeErrorV1::{Deadline, Mismatch};
    let kind = challenge_kind(bytes)?;
    if bytes[112..144] != runtime[..32]
        || bytes[144..152] != runtime[32..40]
        || bytes[152..160] != runtime[72..80]
    {
        return Err(Mismatch);
    }
    let expected = match kind {
        HostStartupReportKindV1::Canary => {
            let mut binding = Sha256::new();
            binding.update(b"aos.sandbox.host.canary-agent-channel.v1\0");
            binding.update(&bytes[48..80]);
            binding.update(&bytes[80..112]);
            binding.update(&bytes[176..192]);
            binding.update(&bytes[16..48]);
            <[u8; 32]>::from(binding.finalize())
        }
        HostStartupReportKindV1::Component => bytes[16..48].try_into().map_err(|_| Mismatch)?,
    };
    if expected != channel {
        return Err(Mismatch);
    }
    let deadline = u64::from_be_bytes(bytes[192..200].try_into().map_err(|_| Mismatch)?);
    if deadline == 0 {
        return Err(Deadline);
    }
    Ok((kind, deadline))
}

const CANARY_CHALLENGE_BYTES: usize = 200;
const CANARY_HEADER_BYTES: usize = 176;
const CANARY_WAIT_NANOSECONDS: u64 = 30_000_000_000;
const CANARY_OWN_PATHS: [&str; 11] = [
    "/",
    "/proc/thread-self/ns/user",
    "/proc/thread-self/ns/mnt",
    "/proc/thread-self/ns/net",
    "/proc/thread-self/ns/pid",
    "/proc/thread-self/stat",
    "/proc/thread-self/status",
    "/proc/thread-self/attr/current",
    "/proc/thread-self/uid_map",
    "/proc/thread-self/gid_map",
    "/proc/thread-self/exe",
];

/// Retains the actual fixed report channel and every reached startup original.
///
/// All fields remain resident through the one Agent spawn and immediate PID1
/// exec. Failure/unwind terminates before disposal; this is no drain proof.
pub struct GuestStartupReportOriginalV1 {
    original: GuestCanaryReportOriginalV1,
    socket: GuestAncestorHostChannelV1,
    agent: GuestAncestorHostChannelV1,
    challenge: Option<GuestAncestorHostRecordV1>,
    provisioning_duplicate: Option<crate::Result<std::os::fd::OwnedFd>>,
    provisioning: crate::immutable_file::SealedMemfdReadOriginalV2,
    provisioning_refusal: Option<crate::immutable_file::SealedMemfdReadClosedV2>,
    receive_failure: Option<RetainedSeqpacketReceiveErrorV1>,
    originals: [Option<File>; 11],
    spawned_agent: Option<Child>,
    child_originals: HostCanaryLocalChildOriginalsV1,
    header: [u8; CANARY_HEADER_BYTES],
    deadline: u64,
    selected: bool,
    capture_entered: bool,
    kind: Option<HostStartupReportKindV1>,
    bound: bool,
    attempted: bool,
    armed: bool,
    first_failure: Option<Box<dyn std::error::Error>>,
}

impl GuestStartupReportOriginalV1 {
    /// Creates inert report destinations without touching the descriptor table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            original: GuestCanaryReportOriginalV1::new(),
            socket: GuestAncestorHostChannelV1::new(),
            agent: GuestAncestorHostChannelV1::new(),
            challenge: None,
            provisioning_duplicate: None,
            provisioning: crate::immutable_file::SealedMemfdReadOriginalV2::new(),
            provisioning_refusal: None,
            receive_failure: None,
            originals: std::array::from_fn(|_| None),
            spawned_agent: None,
            child_originals: HostCanaryLocalChildOriginalsV1::new(),
            header: [0; CANARY_HEADER_BYTES],
            deadline: 0,
            selected: false,
            capture_entered: false,
            kind: None,
            bound: false,
            attempted: false,
            armed: false,
            first_failure: None,
        }
    }

    /// Captures fixed FD8 and its same-Host challenge before kind selection.
    ///
    /// # Errors
    /// Retains actual slot/channel/receive failure and refuses malformed kinds.
    pub fn capture_original(&mut self) -> Result<bool, Box<dyn std::error::Error>> {
        if self.capture_entered {
            self.first_failure
                .get_or_insert_with(|| "Guest report capture repeated".into());
            return Err("Guest report capture is closed".into());
        }
        self.capture_entered = true;
        let result = self.capture_inner();
        if let Err(cause) = result {
            self.first_failure = Some(cause);
            return Err("Guest report capture failed; original cause remains resident".into());
        }
        Ok(self.selected)
    }

    fn capture_inner(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.armed = true;
        self.selected = self
            .original
            .capture_original()
            .map_err(|_| "Guest canary report capture failed; original cause remains resident")?;
        if !self.selected {
            self.armed = false;
        } else {
            self.agent
                .capture_agent_original()
                .map_err(|_| "Guest original Agent channel failed; cause remains resident")?;
            self.socket
                .capture_report_original(&self.original)
                .map_err(|_| "Guest original report channel failed; cause remains resident")?;
            self.socket.require_same_host_original(&mut self.agent)?;
            self.receive_challenge_original()?;
            // Capture only the same fixed sealed launch before the framed
            // kind can select either startup path. Its callback below returns
            // pure DATA; no key, descriptor or mapping can escape it.
            self.provisioning_duplicate =
                Some(crate::inherited_fd::duplicate_inherited_descriptor(4));
            let descriptor = match self.provisioning_duplicate.take() {
                Some(Ok(descriptor)) => descriptor,
                failed => {
                    self.provisioning_duplicate = failed;
                    return Err("Guest report provisioning duplicate failed".into());
                }
            };
            if let Err(cause) = self.provisioning.prepare_once(descriptor, 258, 258) {
                self.provisioning_refusal = Some(cause);
                return Err("Guest report provisioning mapping failed".into());
            }
        }
        Ok(())
    }

    /// Returns only the kind framed on the actual original Host channel.
    ///
    /// The sealed runtime/channel comparison must precede startup effects.
    #[must_use]
    pub fn kind_data_v1(&self) -> Option<HostStartupReportKindV1> {
        self.kind
    }

    /// Borrows the same fully sealed launch only within its original mapping.
    ///
    /// # Errors
    /// Refuses an absent/failed capture or an already retired positive mapping.
    pub fn with_launch_bytes_v1<R>(
        &self,
        use_bytes: impl for<'a> FnOnce(&'a [u8]) -> R,
    ) -> Result<R, crate::immutable_file::SealedMemfdReadClosedV2> {
        self.provisioning
            .with_bytes(|bytes, _identity| use_bytes(bytes))
    }

    /// Joins the actual received challenge to the sealed Agent launch tuple.
    ///
    /// # Errors
    /// Retains kind/runtime/channel/deadline mismatch and refuses reentry.
    pub fn bind_launch_once_v1(
        &mut self,
        runtime: &[u8; 104],
        channel: [u8; 32],
    ) -> Result<(), Box<dyn std::error::Error>> {
        if self.bound || !self.selected || self.first_failure.is_some() {
            self.first_failure
                .get_or_insert_with(|| "Guest report binding repeated or absent".into());
            return Err("Guest report binding is closed".into());
        }
        let result = (|| {
            let same_original = self.provisioning.with_bytes(|bytes, _identity| {
                bytes[8..112] == *runtime && bytes[112..144] == channel
            })?;
            if !same_original {
                return Err("Guest report tuple differs from its actual sealed original".into());
            }
            let record = self.challenge.as_ref().ok_or("Guest challenge is absent")?;
            let (kind, deadline) =
                require_host_startup_report_challenge_v1(record.payload(), runtime, channel)?;
            if Some(kind) != self.kind || deadline != self.deadline {
                return Err("Guest report kind changed".into());
            }
            self.socket.require_record_original(record)?;
            self.socket.require_same_host_original(&mut self.agent)?;
            self.require_before(deadline)?;
            self.provisioning.retire_positive_mapping_v2()?;
            self.bound = true;
            Ok(())
        })();
        if let Err(cause) = result {
            self.first_failure = Some(cause);
            return Err("Guest report binding failed; original cause remains resident".into());
        }
        Ok(())
    }

    /// Reports the same PID1 originals after complete sealed launch binding.
    ///
    /// # Errors
    /// Retains native opens/send failures and rejects repeated or unbound entry.
    pub fn report_original(
        &mut self,
        runtime: &[u8; 104],
        channel: [u8; 32],
    ) -> Result<(), Box<dyn std::error::Error>> {
        if !self.selected || !self.bound || self.attempted || self.first_failure.is_some() {
            return Err("Guest canary report observation is closed".into());
        }
        self.attempted = true;
        match self.report_inner(runtime, channel) {
            Ok(()) => Ok(()),
            Err(cause) => {
                self.first_failure = Some(cause);
                Err("Guest canary report failed; original cause remains resident".into())
            }
        }
    }

    fn report_inner(
        &mut self,
        runtime: &[u8; 104],
        channel: [u8; 32],
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.socket.require_same_host_original(&mut self.agent)?;

        let record = self
            .challenge
            .as_ref()
            .ok_or("Guest report challenge is absent")?;
        let (kind, deadline) =
            require_host_startup_report_challenge_v1(record.payload(), runtime, channel)?;
        if Some(kind) != self.kind || deadline != self.deadline {
            return Err("Guest startup report binding changed".into());
        }
        self.socket.require_record_original(record)?;
        self.require_before(self.deadline)?;
        self.header
            .copy_from_slice(&record.payload()[..CANARY_HEADER_BYTES]);

        for (slot, path) in CANARY_OWN_PATHS.iter().enumerate() {
            self.originals[slot] = Some(
                OpenOptions::new()
                    .read(true)
                    .custom_flags(O_CLOEXEC)
                    .open(path)?,
            );
            self.require_before(self.deadline)?;
        }
        self.send_originals(3, 0, 0..5)?;
        self.send_originals(4, 1, 5..10)?;
        self.send_originals(5, 2, 10..11)?;
        Ok(())
    }

    fn receive_challenge_original(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let first_deadline = crate::seqpacket::bounded::boottime()?
            .checked_add(CANARY_WAIT_NANOSECONDS)
            .ok_or("Guest canary challenge deadline overflowed")?;
        loop {
            self.require_before(first_deadline)?;
            let received = self.socket.receive_startup_report_retaining_v1();
            match received {
                Ok(record) => {
                    self.challenge = Some(record);
                    break;
                }
                Err(error)
                    if error.is_nonconsuming_would_block()
                        || error.is_nonconsuming_interrupted() =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
                Err(error) => {
                    self.receive_failure = Some(error);
                    return Err(
                        "Guest canary challenge receive failed; originals remain resident".into(),
                    );
                }
            }
        }
        self.require_before(first_deadline)?;
        let record = self
            .challenge
            .as_ref()
            .ok_or("Guest canary challenge is absent")?;
        self.socket.require_record_original(record)?;
        self.socket.require_same_host_original(&mut self.agent)?;
        self.kind = Some(challenge_kind(record.payload())?);
        self.deadline = u64::from_be_bytes(
            record.payload()[192..200]
                .try_into()
                .map_err(|_| HostStartupReportChallengeErrorV1::Mismatch)?,
        );
        if self.deadline == 0 {
            return Err(HostStartupReportChallengeErrorV1::Deadline.into());
        }
        self.require_before(self.deadline)?;
        Ok(())
    }

    fn send_originals(
        &mut self,
        kind: u16,
        sequence: u64,
        slots: std::ops::Range<usize>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.header[10..12].copy_from_slice(&kind.to_be_bytes());
        self.header[12..16].copy_from_slice(&(CANARY_HEADER_BYTES as u32).to_be_bytes());
        self.header[168..176].copy_from_slice(&sequence.to_be_bytes());
        let count = slots.len();
        let first = self.originals[slots.start]
            .as_ref()
            .ok_or("Guest canary original descriptor is absent")?
            .as_fd();
        let mut descriptors: [BorrowedFd<'_>; 5] = [first; 5];
        for (target, slot) in slots.enumerate() {
            descriptors[target] = self.originals[slot]
                .as_ref()
                .ok_or("Guest canary original descriptor is absent")?
                .as_fd();
        }
        loop {
            self.require_before(self.deadline)?;
            match self
                .socket
                .send_with_descriptors(&self.header, &descriptors[..count])
            {
                Ok(()) => return self.require_before(self.deadline),
                Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
                Err(cause) => return Err(cause.into()),
            }
        }
    }

    /// Spawns only the old selected canary Agent and reports that actual Child.
    ///
    /// # Errors
    /// Retains failed spawn/readback/send and rejects another report kind.
    pub fn spawn_agent_original(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.kind != Some(HostStartupReportKindV1::Canary)
            || !self.selected
            || !self.attempted
            || self.spawned_agent.is_some()
            || self.first_failure.is_some()
        {
            return Err("Guest original Agent spawn is closed".into());
        }
        match self.spawn_agent_inner() {
            Ok(()) => Ok(()),
            Err(cause) => {
                self.first_failure = Some(cause);
                Err("Guest original Agent observation failed; cause remains resident".into())
            }
        }
    }

    fn spawn_agent_inner(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.require_before(self.deadline)?;
        self.socket.require_same_host_original(&mut self.agent)?;
        let mut command = Command::new("/usr/libexec/aos-sandbox-guest-agent");
        command.env_clear();
        command.stdin(std::process::Stdio::null());
        command.stdout(std::process::Stdio::null());
        command.stderr(std::process::Stdio::null());
        command.arg("--host-canary-readiness-v1");
        self.spawned_agent = Some(command.spawn()?);
        self.child_originals.capture_original(
            self.spawned_agent
                .as_ref()
                .ok_or("actual Agent child is absent")?,
        )?;
        self.report_captured_agent_original()
    }

    /// Reports the actual already-retained normal Agent without spawning one.
    ///
    /// The caller retains the same Child and normal topology owner throughout.
    ///
    /// # Errors
    /// Retains native failure and rejects unbound, canary or repeated entry.
    pub fn report_component_agent_once_v1(
        &mut self,
        child: &Child,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if self.kind != Some(HostStartupReportKindV1::Component)
            || !self.bound
            || !self.attempted
            || self.first_failure.is_some()
        {
            return Err("normal Agent report is closed".into());
        }
        let result = (|| {
            self.require_before(self.deadline)?;
            self.socket.require_same_host_original(&mut self.agent)?;
            self.child_originals.capture_original(child)?;
            self.report_captured_agent_original()
        })();
        if let Err(cause) = result {
            self.first_failure = Some(cause);
            return Err("normal Agent report failed; original cause remains resident".into());
        }
        Ok(())
    }

    fn report_captured_agent_original(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.require_before(self.deadline)?;

        for stage in 0..2 {
            loop {
                self.require_before(self.deadline)?;
                let result = if stage == 0 {
                    self.socket
                        .send_host_canary_child_first_v1(&mut self.child_originals, &self.header)
                } else {
                    self.socket
                        .send_host_canary_child_second_v1(&mut self.child_originals, &self.header)
                };
                match result {
                    Ok(()) => break,
                    Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                        std::thread::sleep(std::time::Duration::from_millis(2));
                    }
                    Err(cause) => return Err(cause.into()),
                }
            }
            self.require_before(self.deadline)?;
        }
        self.socket.require_same_host_original(&mut self.agent)?;
        self.child_originals.recheck_original()?;
        self.require_before(self.deadline)
    }

    fn require_before(&self, deadline: u64) -> Result<(), Box<dyn std::error::Error>> {
        if crate::seqpacket::bounded::boottime()? >= deadline {
            return Err("Guest canary original deadline expired".into());
        }
        Ok(())
    }

    /// Makes only the same bound FD8 inheritable for immediate systemd exec.
    ///
    /// # Errors
    /// Retains expired deadline or actual descriptor-disposition failure.
    pub fn prepare_systemd_exec(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if !self.bound || !self.attempted || self.first_failure.is_some() {
            return Err("Guest report exec disposition is closed".into());
        }
        self.require_before(self.deadline)?;
        self.original
            .prepare_systemd_exec()
            .map_err(|_| "Guest canary exec disposition failed; original cause remains resident")?;
        // Successful exec retains original FD8. If exec fails or unwinds this
        // still-armed owner terminates rather than silently dropping prefixes.
        Ok(())
    }

    /// Prices the real fixed report source before its first native operation.
    ///
    /// This supplements the normal Guest topology/Agent source. It includes
    /// the report's retained Rust models, the existing C seccomp export's two
    /// 98,504-byte arrays, fixed post-exec report storage, and native peaks.
    /// It grants no report role, launch, process or account.
    #[must_use]
    pub fn receiving_obligations_v1() -> Option<(usize, usize, usize)> {
        let receive = GuestAncestorHostChannelV1::startup_report_receive_obligations_v1()?;
        let child = HostCanaryLocalChildOriginalsV1::receiving_obligations_v1()?;
        let error = std::mem::size_of::<crate::Error>()
            .checked_add(std::mem::size_of::<SeqpacketError>())?
            .checked_add(std::mem::size_of::<std::io::Error>())?
            .checked_mul(2)?;
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(receive.0)?
            .checked_add(child.0)?
            .checked_add(
                crate::immutable_file::SealedMemfdReadOriginalV2::receiving_memory_bytes_v2()?,
            )?
            .checked_add(4096 + 2 * (CANARY_CHALLENGE_BYTES + 1))?
            .checked_add(2 * 98_504 + 2 * 4096)?
            .checked_add(error)?;
        // FD8 original+capture, report channel+Host pidfd, Agent channel+Host
        // pidfd remain throughout. Receive failure stops before mapping/opens;
        // later phases add the challenge pin, eleven PID1 files and actual
        // child readback. At Agent birth the CLOEXEC report table still has
        // a real child copy until exec; it cannot be treated as already gone.
        // Existing normal spawn/null/error-pipe source is separately joined.
        let before_child = 6_usize.checked_add(1 + 11)?;
        let files = 6_usize
            .checked_add(receive.1.max(2).max(1 + 11 + child.1))?
            .max(before_child.checked_mul(2)?);
        Some((bytes, files, 11 + child.2 + 1))
    }
}

impl Default for GuestStartupReportOriginalV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for GuestStartupReportOriginalV1 {
    fn drop(&mut self) {
        if self.armed {
            std::process::abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn component() -> ([u8; 200], [u8; 104], [u8; 32]) {
        let mut bytes = [0; 200];
        bytes[..8].copy_from_slice(b"AOSNHR01");
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[12..16].copy_from_slice(&200_u32.to_be_bytes());
        bytes[16..48].fill(1);
        bytes[48..80].fill(2);
        bytes[80..112].fill(3);
        bytes[112..144].fill(4);
        bytes[144..152].copy_from_slice(&5_u64.to_be_bytes());
        bytes[152..160].copy_from_slice(&6_u64.to_be_bytes());
        bytes[176..192].fill(7);
        bytes[192..200].copy_from_slice(&8_u64.to_be_bytes());
        let mut runtime = [0; 104];
        runtime[..32].fill(4);
        runtime[32..40].copy_from_slice(&5_u64.to_be_bytes());
        runtime[72..80].copy_from_slice(&6_u64.to_be_bytes());
        (bytes, runtime, [1; 32])
    }

    #[test]
    fn component_uses_the_original_normal_channel_and_supplied_deadline() {
        let (bytes, runtime, channel) = component();

        assert_eq!(
            require_host_startup_report_challenge_v1(&bytes, &runtime, channel).unwrap(),
            (HostStartupReportKindV1::Component, 8)
        );
        assert!(require_host_startup_report_challenge_v1(&bytes, &runtime, [9; 32]).is_err());
    }

    #[test]
    fn changing_the_report_family_cannot_adopt_the_other_channel_law() {
        let (mut bytes, runtime, normal_channel) = component();
        bytes[..8].copy_from_slice(b"AOSHCR01");

        assert!(
            require_host_startup_report_challenge_v1(&bytes, &runtime, normal_channel).is_err()
        );
        let mut binding = Sha256::new();
        binding.update(b"aos.sandbox.host.canary-agent-channel.v1\0");
        binding.update(&bytes[48..80]);
        binding.update(&bytes[80..112]);
        binding.update(&bytes[176..192]);
        binding.update(&bytes[16..48]);
        let canary_channel = binding.finalize().into();
        assert_eq!(
            require_host_startup_report_challenge_v1(&bytes, &runtime, canary_channel).unwrap(),
            (HostStartupReportKindV1::Canary, 8)
        );
    }

    #[test]
    fn malformed_role_runtime_reservation_and_deadline_remain_closed() {
        let (bytes, runtime, channel) = component();
        for offset in [0, 8, 10, 12, 16, 48, 80, 112, 144, 152, 160, 168] {
            let mut changed = bytes;
            changed[offset] ^= 0x80;
            // Digest/Guardian fields are Host comparisons; this local codec
            // only requires them nonzero. Zero their complete plane instead.
            if matches!(offset, 48 | 80) {
                changed[offset..offset + 32].fill(0);
            }
            assert!(
                require_host_startup_report_challenge_v1(&changed, &runtime, channel).is_err(),
                "offset {offset}"
            );
        }
        let mut changed = bytes;
        changed[192..200].fill(0);
        assert!(matches!(
            require_host_startup_report_challenge_v1(&changed, &runtime, channel),
            Err(HostStartupReportChallengeErrorV1::Deadline)
        ));
        assert!(
            require_host_startup_report_challenge_v1(&bytes[..199], &runtime, channel).is_err()
        );
    }
}
