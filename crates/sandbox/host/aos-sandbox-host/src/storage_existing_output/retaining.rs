//! Keeps the actual fixed Storage client, query and split held-output flight.
//!
//! A hold spans genuine Host-owned turns. This mechanical owner contains no
//! Controller/Host claim, authorizer, payer or physical-dataset constructor.

use std::error::Error;
use std::fs::Metadata;
use std::mem::size_of;
use std::os::fd::OwnedFd;
use rand::TryRngCore as _;

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::cgroup::{RuntimeScopeMembershipOriginalV1, StorageOutputClientCgroupOriginalV2};
use aos_sandbox_linux::seqpacket::{ConnectionPeerIdentity, RecordBindingError,
    RetainedSeqpacketAdmissionErrorV1};
use aos_sandbox_linux::seqpacket::descriptor_subject::{ReceivedDescriptorRecord, DescriptorSubjectSocket};
use aos_sandbox_protocol::storage_existing_output::ExistingOutputProtocolErrorV1;
use aos_sandbox_protocol::storage_held_output_session::HeldOutputSessionProtocolErrorV1;
use crate::storage_root_export::{StorageClientTransportErrorV2, send_request_retaining_v2,
    receive_reply_retaining_v2};
use super::*;

const ROUTE_SAMPLES: usize = 24;
const MEMBERSHIP_SAMPLES: usize = 8;
const ACTIVE_SAMPLES: usize = 1;

#[derive(Debug, thiserror::Error)]
pub(super) enum NativeCauseV2 {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Linux(#[from] aos_sandbox_linux::Error),
    #[error(transparent)]
    Transport(#[from] StorageClientTransportErrorV2),
    #[error(transparent)]
    Binding(#[from] RecordBindingError),
    #[error(transparent)]
    Existing(#[from] ExistingOutputProtocolErrorV1),
    #[error(transparent)]
    Held(#[from] HeldOutputSessionProtocolErrorV1),
    #[error(transparent)]
    Capture(#[from] aos_sandbox_protocol::storage_capture_session::CaptureSessionProtocolErrorV2),
    #[error(transparent)]
    Kernel(#[from] rustix::io::Errno),
    #[error(transparent)]
    Entropy(#[from] rand::rand_core::OsError),
    #[error(transparent)]
    Host(#[from] HostError),
}

impl NativeCauseV2 {
    fn as_error(&self) -> &(dyn Error + 'static) {
        match self {
            Self::Io(cause) => cause,
            Self::Linux(cause) => cause,
            Self::Transport(cause) => cause,
            Self::Binding(cause) => cause,
            Self::Existing(cause) => cause,
            Self::Held(cause) => cause,
            Self::Capture(cause) => cause,
            Self::Kernel(cause) => cause,
            Self::Entropy(cause) => cause,
            Self::Host(cause) => cause,
        }
    }
}

pub(super) struct NativeOriginalV2 {
    causes: Vec<NativeCauseV2>,
    metadata: Vec<std::io::Result<Metadata>>,
    membership: Vec<RuntimeScopeMembershipOriginalV1>,
    active: Vec<RuntimeScopeMembershipOriginalV1>,
    pub(super) request: Option<ExistingOutputRequestV1>,
    pub(super) begin: Option<HeldOutputBeginV1>,
    pub(super) terminal: Option<HeldOutputTerminalV1>,
}

impl NativeOriginalV2 {
    pub(super) fn new() -> Self {
        Self {
            causes: Vec::with_capacity(2),
            metadata: Vec::with_capacity(ROUTE_SAMPLES),
            membership: Vec::with_capacity(MEMBERSHIP_SAMPLES),
            active: Vec::with_capacity(ACTIVE_SAMPLES),
            request: None,
            begin: None,
            terminal: None,
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.causes.first().map(NativeCauseV2::as_error)
            .or_else(|| self.metadata.iter().find_map(|slot| slot.as_ref().err().map(|cause| cause as _)))
            .or_else(|| self.membership.iter().find_map(|slot| slot.failure().map(|cause| cause as _)))
            .or_else(|| self.active.iter().find_map(|slot| slot.failure().map(|cause| cause as _)))
    }

    pub(super) fn positive_files_disposed_v5(&self) -> bool {
        self.failure().is_none()
            && self.membership.iter().all(|sample| sample.native_disposal_v4().is_some())
            && self.active.iter().all(RuntimeScopeMembershipOriginalV1::active_file_is_disposed_v5)
    }

}

pub(super) type NativeDestinationV2<'a> = Option<&'a mut NativeOriginalV2>;

pub(super) struct OpenOriginalV2 {
    socket: Option<DescriptorSubjectSocket>,
    admission: Option<RetainedSeqpacketAdmissionErrorV1>,
    native: NativeOriginalV2,
}

impl OpenOriginalV2 {
    pub(super) fn new() -> Self { Self { socket: None, admission: None, native: NativeOriginalV2::new() } }
    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.admission.as_ref().map(|cause| cause as _).or_else(|| self.native.failure())
    }

    pub(super) fn positive_files_disposed_v5(&self) -> bool {
        self.admission.is_none() && self.native.positive_files_disposed_v5()
    }
}

pub(super) struct ReplyOriginalV2 {
    packet: Option<ReceivedDescriptorRecord>,
    subject: Option<KernelAuthorizedRecordSubject>,
    bytes: Option<Vec<u8>>,
    descriptors: Option<Vec<OwnedFd>>,
    native: NativeOriginalV2,
}

impl ReplyOriginalV2 {
    pub(super) fn new() -> Self { Self { packet: None, subject: None, bytes: None, descriptors: None, native: NativeOriginalV2::new() } }
    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> { self.native.failure() }

    pub(super) fn positive_files_disposed_v5(&self) -> bool {
        self.native.positive_files_disposed_v5()
    }
}

pub(super) struct QueryOriginalV2 {
    open: OpenOriginalV2,
    native: NativeOriginalV2,
    reply: ReplyOriginalV2,
}

impl QueryOriginalV2 {
    pub(super) fn new() -> Self { Self { open: OpenOriginalV2::new(), native: NativeOriginalV2::new(), reply: ReplyOriginalV2::new() } }
    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.open.failure().or_else(|| self.native.failure()).or_else(|| self.reply.failure())
    }

    fn retire_completed_query_v5(&mut self) -> Result<()> {
        if self.failure().is_some() || self.open.admission.is_some()
            || self.reply.packet.is_some()
            || self.reply.descriptors.as_ref().is_some_and(|rights| !rights.is_empty())
            || !self.open.native.positive_files_disposed_v5()
            || !self.native.positive_files_disposed_v5()
            || !self.reply.native.positive_files_disposed_v5()
        { return Err(refused()); }
        // This actual Query's copied row is complete. Hold opens a distinct
        // channel only after these same socket/subject originals physically drop.
        drop(self.reply.subject.take());
        drop(self.open.socket.take());
        Ok(())
    }
}

pub(super) fn query_destinations(original: Option<&mut QueryOriginalV2>)
    -> (Option<&mut OpenOriginalV2>, NativeDestinationV2<'_>, Option<&mut ReplyOriginalV2>) {
    match original {
        Some(original) => (Some(&mut original.open), Some(&mut original.native), Some(&mut original.reply)),
        None => (None, None, None),
    }
}

pub(super) fn open_destinations(original: Option<&mut OpenOriginalV2>)
    -> (Option<&mut Option<DescriptorSubjectSocket>>, Option<&mut Option<RetainedSeqpacketAdmissionErrorV1>>, NativeDestinationV2<'_>) {
    match original {
        Some(original) => (Some(&mut original.socket), Some(&mut original.admission), Some(&mut original.native)),
        None => (None, None, None),
    }
}

pub(super) fn reply_destinations(original: Option<&mut ReplyOriginalV2>)
    -> (Option<&mut Option<ReceivedDescriptorRecord>>, Option<&mut Option<KernelAuthorizedRecordSubject>>,
        Option<&mut Option<Vec<u8>>>, Option<&mut Option<Vec<OwnedFd>>>, NativeDestinationV2<'_>) {
    match original {
        Some(original) => (Some(&mut original.packet), Some(&mut original.subject), Some(&mut original.bytes), Some(&mut original.descriptors), Some(&mut original.native)),
        None => (None, None, None, None, None),
    }
}

pub(super) struct ValueGuardV2<'a, T> {
    value: Option<T>,
    destination: Option<&'a mut Option<T>>,
}

impl<'a, T> ValueGuardV2<'a, T> {
    pub(super) fn new(value: T, destination: Option<&'a mut Option<T>>) -> Self { Self { value: Some(value), destination } }
    pub(super) fn get(&self) -> Result<&T> { self.value.as_ref().ok_or_else(refused) }
    pub(super) fn get_mut(&mut self) -> Result<&mut T> { self.value.as_mut().ok_or_else(refused) }
    pub(super) fn take(mut self) -> Result<T> { self.value.take().ok_or_else(refused) }
}

impl<T> Drop for ValueGuardV2<'_, T> {
    fn drop(&mut self) {
        if let Some(destination) = self.destination.as_deref_mut() {
            if self.value.is_some() {
                if destination.is_some() { std::process::abort(); }
                *destination = self.value.take();
            }
        }
    }
}

pub(super) type SocketGuardV2<'a> = ValueGuardV2<'a, DescriptorSubjectSocket>;

pub(super) struct StorageReplyGuardV2<'a> {
    pub(super) subject: ValueGuardV2<'a, KernelAuthorizedRecordSubject>,
    pub(super) bytes: ValueGuardV2<'a, Vec<u8>>,
    pub(super) descriptors: ValueGuardV2<'a, Vec<OwnedFd>>,
    pub(super) storage: PidFdInfo,
}

impl StorageReplyGuardV2<'_> {
    pub(super) fn bytes(&self) -> Result<&[u8]> { self.bytes.get().map(Vec::as_slice) }
    pub(super) fn retire_ordinary_subject(&mut self) {
        if self.subject.destination.is_none() { drop(self.subject.value.take()); }
    }
    pub(super) fn into_parts(self) -> Result<(Vec<u8>, PidFdInfo, KernelAuthorizedRecordSubject)> {
        if !self.descriptors.get()?.is_empty() {
            return Err(refused());
        }
        Ok((self.bytes.take()?, self.storage, self.subject.take()?))
    }
}

pub(super) struct HeldClientStateV2 {
    // Actual ordinary local drop order: record subject, payload, then socket.
    pub(super) proof_subject: KernelAuthorizedRecordSubject,
    pub(super) proof_bytes: Vec<u8>,
    pub(super) socket: DescriptorSubjectSocket,
    pub(super) route: SocketRouteIdentity,
    pub(super) manager: PidFdInfo,
    pub(super) begin: HeldOutputBeginV1,
    pub(super) proof: HeldOutputProofV1,
    pub(super) storage: PidFdInfo,
}

/// Owns one fixed query and hold across the actual Host operation's turns.
pub(crate) struct StorageExistingOutputOriginalV2 {
    cgroups: StorageOutputClientCgroupOriginalV2,
    client: Option<StorageExistingOutputClientV1>,
    client_result: Option<Result<()>>,
    query: QueryOriginalV2,
    query_result: Option<Result<ExistingOutputObservationV1>>,
    query_disposal: Option<Result<()>>,
    hold: QueryOriginalV2,
    held: Option<HeldClientStateV2>,
    hold_result: Option<Result<()>>,
    settlement: ReplyOriginalV2,
    settlement_native: NativeOriginalV2,
    settlement_result: Option<Result<()>>,
    abort: ReplyOriginalV2,
    abort_native: NativeOriginalV2,
    abort_result: Option<Result<()>>,
    terminal_complete: bool,
}

impl StorageExistingOutputOriginalV2 {
    /// Creates only precharged destinations; this performs no native IO.
    pub(crate) fn new() -> Self {
        Self {
            cgroups: StorageOutputClientCgroupOriginalV2::new(),
            client: None,
            client_result: None,
            query: QueryOriginalV2::new(),
            query_result: None,
            query_disposal: None,
            hold: QueryOriginalV2::new(),
            held: None,
            hold_result: None,
            settlement: ReplyOriginalV2::new(),
            settlement_native: NativeOriginalV2::new(),
            settlement_result: None,
            abort: ReplyOriginalV2::new(),
            abort_native: NativeOriginalV2::new(),
            abort_result: None,
            terminal_complete: false,
        }
    }

    /// Captures fixed native client anchors from the genuine catalog's held root.
    ///
    /// # Errors
    /// Retains the actual first root/anchor/probe error or refuses repeated entry.
    pub(crate) fn capture_client_once(&mut self, root: &CgroupV2Root) -> Result<()> {
        if self.client_result.is_some() { return Err(refused()); }
        self.client_result = Some((|| {
            self.client = Some(capture_fixed_client_v2(root, &mut self.cgroups)?);
            Ok(())
        })());
        unit(&self.client_result)
    }

    pub(super) fn completed_client_v2(&self) -> Result<&StorageExistingOutputClientV1> {
        unit(&self.client_result)?;
        self.client.as_ref().ok_or_else(refused)
    }

    /// Queries the exact supplied row and split after the caller's full precharge.
    ///
    /// # Errors
    /// Retains the original socket, responder, protocol or exact-row refusal.
    pub(crate) fn query_once(
        &mut self,
        execution: [u8;16],
        create: [u8;16],
        assignment: [u8;32],
        expected: ExpectedExistingOutputV1,
        cutoff: u64,
    ) -> Result<()> {
        if self.query_result.is_some() || !matches!(self.client_result, Some(Ok(()))) {
            return Err(refused());
        }
        self.query_result = Some((|| {
            let client = self.client.as_ref().ok_or_else(refused)?;
            let observation = client.query_exchange_with_disposition(execution, create, expected.record_digest(), Some(cutoff), Some(&mut self.query))?;
            expected.verify(assignment, &observation.response)?;
            Ok(observation)
        })());
        if !matches!(self.query_result, Some(Ok(_))) { return Err(refused()); }
        self.query_disposal = Some(self.query.retire_completed_query_v5());
        unit(&self.query_disposal)
    }

    /// Begins a V1 hold against this same owner's actual queried row and head.
    ///
    /// # Errors
    /// Refuses missing query, repeated entry or the original native/protocol error.
    pub(crate) fn begin_hold_once(&mut self, cutoff: u64) -> Result<()> {
        if self.hold_result.is_some() || !matches!(self.query_result, Some(Ok(_)))
            || !matches!(self.query_disposal, Some(Ok(())))
            || !self.cgroups.positive_prefix_is_disposed_v5() {
            return Err(refused());
        }
        self.hold_result = Some((|| {
            let client = self.client.as_ref().ok_or_else(refused)?;
            let expected = self.query_result.as_ref().and_then(|slot| slot.as_ref().ok()).ok_or_else(refused)?.response;
            self.held = Some(client.begin_held_observed(expected, Some(cutoff), Some(&mut self.hold))?);
            Ok(())
        })());
        unit(&self.hold_result)
    }

    /// Borrows the actual held proof while neither terminal path has entered.
    ///
    /// # Errors
    /// Refuses an absent hold or a terminal path already entered.
    pub(crate) fn held_proof_v2(&self) -> Result<&HeldOutputProofV1> {
        if self.settlement_result.is_some() || self.abort_result.is_some() {
            return Err(refused());
        }
        self.held.as_ref().map(|held| &held.proof).ok_or_else(refused)
    }

    /// Returns the original verified hold's absolute kernel boottime cutoff.
    ///
    /// This copied DATA cannot extend or renew the hold. The caller must check
    /// its actual retained clock against this cutoff before each live use.
    ///
    /// # Errors
    /// Refuses an absent hold or a terminal path already entered.
    pub(crate) fn held_cutoff_v2(&self) -> Result<u64> {
        self.held_proof_v2()?;
        self.held.as_ref().map(|held| held.begin.deadline_boottime_nanoseconds)
            .ok_or_else(refused)
    }

    /// Sends the existing V1 settlement and independently attempts its exact Ack.
    ///
    /// # Errors
    /// Retains the first native/protocol error and every later owed Ack prefix.
    pub(crate) fn settle_once(&mut self, digest: [u8;32], cutoff: u64) -> Result<()> {
        if self.settlement_result.is_some() || self.abort_result.is_some() || digest == [0;32] {
            return Err(refused());
        }
        self.settlement_result = Some(self.client.as_ref().ok_or_else(refused)?.terminal_observed(
            self.held.as_mut().ok_or_else(refused)?, HeldOutputTerminalModeV1::Settle, digest,
            cutoff, Some(&mut self.settlement_native), Some(&mut self.settlement),
        ));
        if matches!(self.settlement_result, Some(Ok(()))) { self.terminal_complete = true; }
        unit(&self.settlement_result)
    }

    /// Attempts the existing V1 Abort and Ack on the same held channel once.
    ///
    /// # Errors
    /// Retains original terminal/Ack failures; no valid proof can be fabricated
    /// for an incomplete begin, and an already entered settlement cannot abort.
    pub(crate) fn abort_once(&mut self, cutoff: u64) -> Result<()> {
        if self.abort_result.is_some() || self.settlement_result.is_some() {
            return Err(refused());
        }
        // Without a verified begin/proof pair no legal V1 terminal can be made.
        // Keep the failed channel/prefix; no synthetic acknowledgement is issued.
        self.abort_result = Some(match (self.client.as_ref(), self.held.as_mut()) {
            (Some(client), Some(held)) => client.terminal_observed(held, HeldOutputTerminalModeV1::Abort,
                [0;32], cutoff, Some(&mut self.abort_native), Some(&mut self.abort)),
            _ => Err(refused()),
        });
        if matches!(self.abort_result, Some(Ok(()))) { self.terminal_complete = true; }
        unit(&self.abort_result)
    }

    /// Borrows the earliest resident native/protocol or original boundary cause.
    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.cgroups.failure().map(|cause| cause as _).or_else(|| error(&self.client_result))
            .or_else(|| self.query.failure()).or_else(|| error(&self.query_result))
            .or_else(|| error(&self.query_disposal))
            .or_else(|| self.hold.failure()).or_else(|| error(&self.hold_result))
            .or_else(|| self.settlement_native.failure()).or_else(|| self.settlement.failure())
            .or_else(|| error(&self.settlement_result)).or_else(|| self.abort_native.failure())
            .or_else(|| self.abort.failure()).or_else(|| error(&self.abort_result))
    }

    // Both actual client anchors, original socket+peer and held record subject.
    // The successful constructor/open/native scopes have already physically
    // retired their temporary files before any Guest can enter.
    pub(super) fn held_native_files_v6() -> Option<usize> {
        let (_, raw) = DescriptorSubjectSocket::retaining_raw_admission_obligations_v2()?;
        let (_, connect) = aos_sandbox_linux::seqpacket::SeqpacketSocket::retained_connect_obligations_v1();
        2_usize.checked_add(raw.max(connect))?.checked_add(1)
    }

    pub(crate) fn held_terminal_files_v6() -> Option<u64> {
        let (_, receive) = DescriptorSubjectSocket::storage_zero_rights_reply_obligations_v6(ACK_BYTES)?;
        u64::try_from(Self::held_native_files_v6()?.checked_add(receive)?).ok()
    }

    /// Supplies this complete finite client reservoir before any allocation or IO.
    ///
    /// This is representation DATA, not funding, an output grant or proof of fit.
    pub(crate) fn preparation_demand_v2() -> Option<ResourceVector> {
        let (cgroup_bytes, cgroup_files, cgroup_names) = StorageOutputClientCgroupOriginalV2::receiving_demand_v2()?;
        let (membership_bytes, membership_files, membership_names) = RuntimeScopeMembershipOriginalV1::exact_receiving_demand_v1()?;
        let (active_bytes, active_files, active_names) = RuntimeScopeMembershipOriginalV1::active_receiving_demand_v1()?;
        let (receive_bytes, receive_files) = DescriptorSubjectSocket::storage_zero_rights_reply_obligations_v6(
            RESPONSE_BYTES.max(PROOF_BYTES).max(ACK_BYTES),
        )?;
        let (connect_bytes, connect_files) = aos_sandbox_linux::seqpacket::SeqpacketSocket::retained_connect_obligations_v1();
        let (raw_admission_bytes, raw_admission_files) = DescriptorSubjectSocket::retaining_raw_admission_obligations_v2()?;
        // Ten native-result containers allocate their bounded Vec backing in
        // new(): Open/body/reply for query and begin, plus terminal/reply for
        // settlement and abort. Their reached probes are a narrower finite
        // roster: five exact memberships per query/begin, three per terminal,
        // and one active check per connection. Both terminal byte reservoirs
        // remain funded; no failed-probe cleanup credit is assumed.
        let native_containers = 10usize;
        let exact_probes = 16usize;
        let active_probes = 2usize;
        let receives = 4usize;
        let vectors = 2usize.checked_mul(size_of::<NativeCauseV2>())?
            .checked_add(ROUTE_SAMPLES.checked_mul(size_of::<std::io::Result<Metadata>>())?)?
            .checked_add(MEMBERSHIP_SAMPLES.checked_mul(size_of::<RuntimeScopeMembershipOriginalV1>())?)?
            .checked_add(ACTIVE_SAMPLES.checked_mul(size_of::<RuntimeScopeMembershipOriginalV1>())?)?;
        let bytes = size_of::<Self>().checked_mul(3)?.checked_add(cgroup_bytes)?
            .checked_add(vectors.checked_mul(native_containers)?)?
            .checked_add(membership_bytes.checked_mul(exact_probes)?)?
            .checked_add(active_bytes.checked_mul(active_probes)?)?
            .checked_add(receive_bytes.checked_mul(receives)?)?
            .checked_add(connect_bytes.checked_mul(2)?)?
            .checked_add(raw_admission_bytes.checked_mul(2)?)?.checked_add(16 * 4096)?;
        // Positive exact/active leaves close at their completed local scope.
        // A failed leaf returns before another entry. Query's actual socket and
        // subject additionally drop before Hold can open its distinct channel.
        // Both client anchors and the held socket/subject remain resident.
        let anchor_files = 2_usize;
        let connection_peak = connect_files.max(raw_admission_files);
        let acquisition = anchor_files.checked_add(connection_peak)?.checked_add(receive_files)?;
        let terminal = usize::try_from(Self::held_terminal_files_v6()?).ok()?;
        let files = cgroup_files.max(acquisition).max(terminal);
        let names = cgroup_names.checked_add(4)?
            .checked_add(membership_names.checked_mul(exact_probes)?)?
            .checked_add(active_names.checked_mul(active_probes)?)?;
        let traffic = aos_sandbox_protocol::storage_existing_output::REQUEST_BYTES.checked_add(RESPONSE_BYTES)?
            .checked_add(aos_sandbox_protocol::storage_held_output_session::BEGIN_BYTES)?.checked_add(PROOF_BYTES)?
            .checked_add(aos_sandbox_protocol::storage_held_output_session::TERMINAL_BYTES.checked_mul(2)?)?
            .checked_add(ACK_BYTES.checked_mul(2)?)?;
        Some(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?)
            .with(D::OpenFiles, u64::try_from(files).ok()?).with(D::MetadataEntries, u64::try_from(names).ok()?)
            .with(D::NetworkBytes, u64::try_from(traffic).ok()?).with(D::OutputBytes, u64::try_from(traffic).ok()?))
    }
}

impl Drop for StorageExistingOutputOriginalV2 {
    fn drop(&mut self) {
        if self.held.is_some() && !self.terminal_complete {
            std::process::abort();
        }
    }
}

fn unit(result: &Option<Result<()>>) -> Result<()> {
    if matches!(result, Some(Ok(()))) { Ok(()) } else { Err(refused()) }
}
fn error<T>(slot: &Option<Result<T>>) -> Option<&(dyn Error + 'static)> { slot.as_ref()?.as_ref().err().map(|cause| cause as _) }
fn refused() -> HostError { query_error("retained original refused") }

pub(super) fn capture_fixed_client_v2(
    root: &CgroupV2Root,
    cgroups: &mut StorageOutputClientCgroupOriginalV2,
) -> Result<StorageExistingOutputClientV1> {
    cgroups.capture_once(root).map_err(|_| refused())?;
    let (storage_cgroup, manager_cgroup) = cgroups.take_pair_retiring_positive_prefix_v5().ok_or_else(refused)?;
    Ok(StorageExistingOutputClientV1 { storage_cgroup, manager_cgroup })
}

pub(super) fn capture<T, E: Into<NativeCauseV2> + std::fmt::Display>(result: std::result::Result<T,E>, native: &mut NativeDestinationV2<'_>) -> Result<T> {
    match result {
        Ok(value) => Ok(value),
        Err(cause) => match native.as_deref_mut() {
            Some(original) => {
                if original.causes.len() >= 2 { std::process::abort(); }
                original.causes.push(cause.into());
                Err(refused())
            }
            None => Err(query_error(cause)),
        },
    }
}

pub(super) fn membership_observed(anchor: &RetainedCgroupAnchor, process: &aos_sandbox_linux::pidfd::PidFd,
    native: &mut NativeDestinationV2<'_>) -> Result<PidFdInfo> {
    let Some(original) = native.as_deref_mut() else { return anchor.verify_exact_membership(process).map_err(query_error); };
    if original.membership.len() >= MEMBERSHIP_SAMPLES { return Err(refused()); }
    original.membership.push(RuntimeScopeMembershipOriginalV1::new());
    let observed = original.membership.last_mut().ok_or_else(refused)?;
    observed.capture_once(anchor, process, None).map_err(|_| refused())?;
    let info = observed.completed_info().ok_or_else(refused)?;
    // The exact sampler has completed its own before/after membership, final
    // pidfd identity and liveness checks. Only copied DATA escapes this scope.
    if observed.retire_completed_files_once_v4().is_none() { return Err(refused()); }
    Ok(info)
}

pub(super) fn active_observed(anchor: &RetainedCgroupAnchor, native: &mut NativeDestinationV2<'_>) -> Result<()> {
    let Some(original) = native.as_deref_mut() else { return anchor.validate_current().map_err(query_error); };
    if original.active.len() >= ACTIVE_SAMPLES { return Err(refused()); }
    original.active.push(RuntimeScopeMembershipOriginalV1::new());
    let observed = original.active.last_mut().ok_or_else(refused)?;
    observed.capture_active_once(anchor).map_err(|_| refused())?;
    if !observed.retire_active_file_once_v5() { return Err(refused()); }
    Ok(())
}

pub(super) fn peer_alive_observed(peer: &ConnectionPeerIdentity, native: &mut NativeDestinationV2<'_>) -> Result<bool> {
    capture(peer.is_alive(), native)
}

pub(super) fn alive_observed(subject: &KernelAuthorizedRecordSubject, native: &mut NativeDestinationV2<'_>, _suppressed: bool) -> Result<bool> {
    capture(subject.is_alive(), native)
}

pub(super) fn connect_observed<'a>(destination: Option<&'a mut Option<DescriptorSubjectSocket>>,
    admission: Option<&mut Option<RetainedSeqpacketAdmissionErrorV1>>, native: &mut NativeDestinationV2<'_>) -> Result<SocketGuardV2<'a>> {
    connect_observed_with_raw_v3(destination, admission, native, false)
}

pub(super) fn connect_observed_with_raw_v3<'a>(
    destination: Option<&'a mut Option<DescriptorSubjectSocket>>,
    admission: Option<&mut Option<RetainedSeqpacketAdmissionErrorV1>>,
    native: &mut NativeDestinationV2<'_>,
    retain_raw_peer: bool,
) -> Result<SocketGuardV2<'a>> {
    connect_observed_with_mode_v6(destination, admission, native, retain_raw_peer, false)
}

// Logical replies cannot carry descriptors. Physical Capture shares this
// connector but keeps rights enabled until its real pipe delivery is verified.
pub(super) fn connect_observed_with_mode_v6<'a>(
    destination: Option<&'a mut Option<DescriptorSubjectSocket>>,
    admission: Option<&mut Option<RetainedSeqpacketAdmissionErrorV1>>,
    native: &mut NativeDestinationV2<'_>,
    retain_raw_peer: bool,
    descriptor_free: bool,
) -> Result<SocketGuardV2<'a>> {
    let socket = if native.is_some() {
        let admitted = if descriptor_free {
            DescriptorSubjectSocket::connect_zero_rights_retaining_v6(Path::new(QUERY_SOCKET))
        } else if retain_raw_peer {
            DescriptorSubjectSocket::connect_retaining_raw_v2(Path::new(QUERY_SOCKET))
        } else {
            DescriptorSubjectSocket::connect_retaining(Path::new(QUERY_SOCKET))
        };
        match admitted {
            Ok(socket) => socket,
            Err(cause) => { if let Some(slot) = admission { *slot = Some(cause); } return Err(refused()); }
        }
    } else { DescriptorSubjectSocket::connect(Path::new(QUERY_SOCKET)).map_err(query_error)? };
    Ok(ValueGuardV2::new(socket, destination))
}

pub(super) fn send_observed(socket: &mut DescriptorSubjectSocket, bytes: &[u8], deadline: u64,
    native: &mut NativeDestinationV2<'_>) -> Result<()> {
    if native.is_some() { capture(send_request_retaining_v2(socket, bytes, deadline), native) }
    else { send_request(socket, bytes, deadline) }
}

pub(super) fn receive_observed<'a>(socket: &mut DescriptorSubjectSocket, deadline: u64, maximum: usize,
    destination: Option<&'a mut Option<ReceivedDescriptorRecord>>, native: &mut NativeDestinationV2<'_>) -> Result<ValueGuardV2<'a, ReceivedDescriptorRecord>> {
    let record = if native.is_some() { capture(receive_reply_retaining_v2(socket, deadline, maximum), native)? }
        else { receive_reply(socket, deadline, maximum, 0)? };
    Ok(ValueGuardV2::new(record, destination))
}

pub(super) fn receive_capture_pipes_observed<'a>(
    socket: &mut DescriptorSubjectSocket,
    deadline: u64,
    maximum: usize,
    destination: Option<&'a mut Option<ReceivedDescriptorRecord>>,
    native: &mut NativeDestinationV2<'_>,
) -> Result<ValueGuardV2<'a, ReceivedDescriptorRecord>> {
    let record = capture(
        crate::storage_root_export::receive_capture_pipes_retaining_v2(socket, deadline, maximum),
        native,
    )?;
    Ok(ValueGuardV2::new(record, destination))
}

pub(super) fn validate_origin_observed(socket: &mut DescriptorSubjectSocket, packet: &ReceivedDescriptorRecord,
    native: &mut NativeDestinationV2<'_>) -> Result<()> {
    if native.is_some() { capture(socket.validate_received_origin_retaining(packet), native) }
    else { socket.validate_received_origin(packet).map_err(query_error) }
}

pub(super) fn clock_observed(native: &mut NativeDestinationV2<'_>) -> Result<u64> {
    if native.is_some() { capture(crate::storage_root_export::boottime_v2(), native) }
    else { boottime() }
}

pub(super) fn fresh_challenge_observed(
    cutoff: Option<u64>, native: &mut NativeDestinationV2<'_>,
) -> Result<([u8;32], u64)> {
    let mut nonce = [0;32];
    capture(OsRng.try_fill_bytes(&mut nonce), native)?;
    let now = clock_observed(native)?;
    let mut deadline = now.checked_add(QUERY_DEADLINE_NANOSECONDS)
        .ok_or_else(|| query_error("deadline overflow"))?;
    if let Some(cutoff) = cutoff {
        deadline = deadline.min(cutoff);
        if now >= deadline { return Err(query_error("original cutoff elapsed")); }
    }
    Ok((nonce, deadline))
}

pub(super) enum RouteMetadataV2<'a> { Local(Metadata), Original(&'a Metadata) }
impl std::ops::Deref for RouteMetadataV2<'_> {
    type Target = Metadata;
    fn deref(&self) -> &Metadata { match self { Self::Local(value) => value, Self::Original(value) => value } }
}

pub(super) fn route_metadata_observed<'a>(path: &str, native: &'a mut NativeDestinationV2<'_>) -> Result<RouteMetadataV2<'a>> {
    let Some(original) = native.as_deref_mut() else { return fs::symlink_metadata(path).map(RouteMetadataV2::Local).map_err(query_error); };
    if original.metadata.len() >= ROUTE_SAMPLES { return Err(refused()); }
    original.metadata.push(fs::symlink_metadata(path));
    match original.metadata.last() {
        Some(Ok(metadata)) => Ok(RouteMetadataV2::Original(metadata)),
        _ => Err(refused()),
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd as _;
    use super::*;

    #[test]
    fn independent_later_refusal_does_not_replace_the_actual_native_error() {
        let mut original = NativeOriginalV2::new();
        let refused: std::io::Result<()> = Err(std::io::Error::from_raw_os_error(9));
        assert!(capture(refused, &mut Some(&mut original)).is_err());
        let first = std::ptr::from_ref(original.failure().unwrap());

        let later: std::io::Result<()> = Err(std::io::Error::from_raw_os_error(13));
        assert!(capture(later, &mut Some(&mut original)).is_err());

        assert_eq!(original.causes.len(), 2);
        assert!(!original.positive_files_disposed_v5());
        assert!(std::ptr::eq(first, std::ptr::from_ref(original.failure().unwrap())));
        assert_eq!(original.failure().unwrap().downcast_ref::<std::io::Error>()
            .unwrap().raw_os_error(), Some(9));
    }

    #[test]
    fn abandoned_local_guard_parks_the_same_original_description() {
        let file = tempfile::tempfile().unwrap();
        let descriptor = file.as_raw_fd();
        let mut destination = None;

        {
            let guarded = ValueGuardV2::new(file, Some(&mut destination));
            assert_eq!(guarded.get().unwrap().as_raw_fd(), descriptor);
        }

        assert_eq!(destination.as_ref().unwrap().as_raw_fd(), descriptor);
        assert!(destination.as_ref().unwrap().metadata().is_ok());
    }
}
