//! Keeps the actual single-use Host scope exchange across native refusal.
//!
//! These inert destinations admit no work or authority. The existing trusted
//! caller pays their complete native/representation requirement first; the
//! same protocol, assignment and signature engines still construct live scope.

use std::os::fd::OwnedFd;
use aos_sandbox_linux::seqpacket::{RetainedSeqpacketAdmissionErrorV1, RetainedSeqpacketReceiveErrorV1};
use aos_sandbox_linux::seqpacket::descriptor_subject::{DescriptorSubjectSocket, ReceivedDescriptorRecord};
use aos_sandbox_linux::pidfd::RuntimeScopeReceivedPidFdOriginalV1;
use aos_sandbox_linux::cgroup::{CgroupV2Root, RuntimeScopeCgroupOriginalV1};
use super::*;

/// Keeps the original socket admission and configured Host input on failure.
///
/// This is native DATA custody. Its successful client alone proves no current
/// assignment, authorization, Source identity or Controller financial admission.
#[doc(hidden)]
pub struct RuntimeScopeOpeningOriginalV1 {
    pub(super) expected: Option<HostServiceIdentity>,
    pub(super) socket: Option<Result<DescriptorSubjectSocket, RetainedSeqpacketAdmissionErrorV1>>,
    pub(super) validation: Option<Result<(), RuntimeScopeError>>,
    pub(super) attempted: bool,
    pub(super) active: aos_sandbox_linux::cgroup::RuntimeScopeMembershipOriginalV1,
}

impl RuntimeScopeOpeningOriginalV1 {
    /// Creates empty native destinations without opening a socket.
    #[must_use]
    pub fn new() -> Self {
        Self {
            expected: None,
            socket: None,
            validation: None,
            attempted: false,
            active: aos_sandbox_linux::cgroup::RuntimeScopeMembershipOriginalV1::new(),
        }
    }

    /// Borrows the first actual original Host/cgroup/socket admission refusal.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.active.failure().map(|cause| cause as _)
            .or_else(|| self.validation.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.socket.as_ref()?.as_ref().err().map(|cause| cause as _))
    }
}

/// Retains the exchange records, descriptor roles and membership probe prefixes.
///
/// No constructor adopts a scope or accepts a semantic-success flag. Only the
/// existing actual exchange engine fills these destinations.
#[doc(hidden)]
pub struct RuntimeScopeObserveOriginalV1 {
    pub(super) client: Option<RuntimeScopeClient>,
    pub(super) hello_receive: Option<RetainedSeqpacketReceiveErrorV1>,
    pub(super) hello: Option<ReceivedDescriptorRecord>,
    pub(super) hello_bytes: Option<Vec<u8>>,
    pub(super) expected_host: Option<HostServiceIdentity>,
    pub(super) hello_subject: Option<KernelAuthorizedRecordSubject>,
    pub(super) host: Option<HostExecution>,
    pub(super) response_receive: Option<RetainedSeqpacketReceiveErrorV1>,
    pub(super) response: Option<ReceivedDescriptorRecord>,
    pub(super) response_bytes: Option<Vec<u8>>,
    pub(super) response_subject: Option<KernelAuthorizedRecordSubject>,
    pub(super) descriptors: Option<Vec<OwnedFd>>,
    pub(super) payload_raw: Option<OwnedFd>,
    pub(super) cgroup_raw: Option<OwnedFd>,
    pub(super) payload_admission: RuntimeScopeReceivedPidFdOriginalV1,
    pub(super) payload: Option<PidFd>,
    pub(super) cgroup_admission: RuntimeScopeCgroupOriginalV1,
    pub(super) cgroup_root: Option<CgroupV2Root>,
    pub(super) anchor: Option<RetainedCgroupAnchor>,
    pub(super) observed: Option<ObservedPayloadScope>,
    pub(super) attempted: bool,
    pub(super) error: Option<RuntimeScopeError>,
    pub(super) membership: RuntimeScopeMembershipWindowV1,
}

impl RuntimeScopeObserveOriginalV1 {
    /// Creates empty native destinations without receiving or observing anything.
    #[must_use]
    pub fn new() -> Self {
        Self {
            client: None,
            hello_receive: None,
            hello: None,
            hello_bytes: None,
            expected_host: None,
            hello_subject: None,
            host: None,
            response_receive: None,
            response: None,
            response_bytes: None,
            response_subject: None,
            descriptors: None,
            payload_raw: None,
            cgroup_raw: None,
            payload_admission: RuntimeScopeReceivedPidFdOriginalV1::new(),
            payload: None,
            cgroup_admission: RuntimeScopeCgroupOriginalV1::new(),
            cgroup_root: None,
            anchor: None,
            observed: None,
            attempted: false,
            error: None,
            membership: RuntimeScopeMembershipWindowV1::new(),
        }
    }

    /// Borrows the actual first selected native receive or typed-pin refusal.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.membership.failure()
            .or_else(|| self.hello_receive.as_ref().map(|cause| cause as _))
            .or_else(|| self.response_receive.as_ref().map(|cause| cause as _))
            .or_else(|| self.payload_admission.failure().map(|cause| cause as _))
            .or_else(|| self.cgroup_admission.failure().map(|cause| cause as _))
            .or_else(|| self.error.as_ref().map(|cause| cause as _))
    }
}

// On a selected failure, each lexical value moves into its distinct actual
// caller destination before its old scope can release native custody. Ordinary
// None keeps the same value at the same lexical destruction frontier.
pub(super) struct HeldValueV1<'destination, T> {
    value: Option<T>,
    destination: Option<&'destination mut Option<T>>,
}

impl<'destination, T> HeldValueV1<'destination, T> {
    pub(super) fn new(value: T, destination: Option<&'destination mut Option<T>>) -> Self {
        Self { value: Some(value), destination }
    }

    pub(super) fn keep_selected(value: T, destination: Option<&'destination mut Option<T>>) -> Self {
        if destination.is_some() {
            Self::new(value, destination)
        } else {
            drop(value);
            Self { value: None, destination: None }
        }
    }

    pub(super) fn get(&self) -> Result<&T, RuntimeScopeError> {
        self.value.as_ref().ok_or(RuntimeScopeError::Descriptor)
    }

    pub(super) fn get_mut(&mut self) -> Result<&mut T, RuntimeScopeError> {
        self.value.as_mut().ok_or(RuntimeScopeError::Descriptor)
    }

    pub(super) fn take(mut self) -> Result<T, RuntimeScopeError> {
        self.value.take().ok_or(RuntimeScopeError::Descriptor)
    }
}

impl<T> Drop for HeldValueV1<'_, T> {
    fn drop(&mut self) {
        if let Some(destination) = self.destination.as_deref_mut() {
            if self.value.is_some() {
                // Every private destination is vacant on the once-only entry.
                // An unexpected occupied destination must preserve both values.
                if destination.is_some() {
                    std::process::abort();
                }
                *destination = self.value.take();
            }
        }
    }
}

// Split the once-only owner into disjoint native destinations before guards borrow it.
pub(super) struct ObserveDestinationsV1<'a> {
    pub(super) selected: bool,
    pub(super) membership: Option<&'a mut RuntimeScopeMembershipWindowV1>,
    pub(super) client: Option<&'a mut Option<RuntimeScopeClient>>,
    pub(super) hello_receive: Option<&'a mut Option<RetainedSeqpacketReceiveErrorV1>>,
    pub(super) hello: Option<&'a mut Option<ReceivedDescriptorRecord>>,
    pub(super) hello_bytes: Option<&'a mut Option<Vec<u8>>>,
    pub(super) expected_host: Option<&'a mut Option<HostServiceIdentity>>,
    pub(super) hello_subject: Option<&'a mut Option<KernelAuthorizedRecordSubject>>,
    pub(super) host: Option<&'a mut Option<HostExecution>>,
    pub(super) response_receive: Option<&'a mut Option<RetainedSeqpacketReceiveErrorV1>>,
    pub(super) response: Option<&'a mut Option<ReceivedDescriptorRecord>>,
    pub(super) response_bytes: Option<&'a mut Option<Vec<u8>>>,
    pub(super) response_subject: Option<&'a mut Option<KernelAuthorizedRecordSubject>>,
    pub(super) descriptors: Option<&'a mut Option<Vec<OwnedFd>>>,
    pub(super) payload_raw: Option<&'a mut Option<OwnedFd>>,
    pub(super) cgroup_raw: Option<&'a mut Option<OwnedFd>>,
    pub(super) payload_admission: Option<&'a mut RuntimeScopeReceivedPidFdOriginalV1>,
    pub(super) payload: Option<&'a mut Option<PidFd>>,
    pub(super) cgroup_admission: Option<&'a mut RuntimeScopeCgroupOriginalV1>,
    pub(super) cgroup_root: Option<&'a mut Option<CgroupV2Root>>,
    pub(super) anchor: Option<&'a mut Option<RetainedCgroupAnchor>>,
    pub(super) observed: Option<&'a mut Option<ObservedPayloadScope>>,
}

impl<'a> ObserveDestinationsV1<'a> {
    pub(super) fn new(original: Option<&'a mut RuntimeScopeObserveOriginalV1>) -> Self {
        match original {
            Some(original) => Self {
                selected: true,
                membership: Some(&mut original.membership),
                client: Some(&mut original.client),
                hello_receive: Some(&mut original.hello_receive),
                hello: Some(&mut original.hello),
                hello_bytes: Some(&mut original.hello_bytes),
                expected_host: Some(&mut original.expected_host),
                hello_subject: Some(&mut original.hello_subject),
                host: Some(&mut original.host),
                response_receive: Some(&mut original.response_receive),
                response: Some(&mut original.response),
                response_bytes: Some(&mut original.response_bytes),
                response_subject: Some(&mut original.response_subject),
                descriptors: Some(&mut original.descriptors),
                payload_raw: Some(&mut original.payload_raw),
                cgroup_raw: Some(&mut original.cgroup_raw),
                payload_admission: Some(&mut original.payload_admission),
                payload: Some(&mut original.payload),
                cgroup_admission: Some(&mut original.cgroup_admission),
                cgroup_root: Some(&mut original.cgroup_root),
                anchor: Some(&mut original.anchor),
                observed: Some(&mut original.observed),
            },
            None => Self {
                selected: false,
                membership: None,
                client: None,
                hello_receive: None,
                hello: None,
                hello_bytes: None,
                expected_host: None,
                hello_subject: None,
                host: None,
                response_receive: None,
                response: None,
                response_bytes: None,
                response_subject: None,
                descriptors: None,
                payload_raw: None,
                cgroup_raw: None,
                payload_admission: None,
                payload: None,
                cgroup_admission: None,
                cgroup_root: None,
                anchor: None,
                observed: None,
            },
        }
    }
}

/// Retains the actual current-selection result and native exchange on refusal.
///
/// This empty destination grants no assignment or endpoint. Its existing
/// protected acquisition engine alone constructs the completed live scope.
#[doc(hidden)]
pub struct RuntimeScopeAcquireOriginalV1 {
    pub(super) client: Option<RuntimeScopeClient>,
    pub(super) observation: RuntimeScopeObserveOriginalV1,
    pub(super) current: Option<CurrentRuntimeScope>,
    pub(super) error: Option<CurrentRuntimeScopeError>,
    pub(super) membership: RuntimeScopeMembershipWindowV1,
    pub(super) attempted: bool,
}

impl RuntimeScopeAcquireOriginalV1 {
    /// Creates empty destinations without reading credentials or opening anything.
    #[must_use]
    pub fn new() -> Self {
        Self {
            client: None,
            observation: RuntimeScopeObserveOriginalV1::new(),
            current: None,
            error: None,
            attempted: false,
            membership: RuntimeScopeMembershipWindowV1::new(),
        }
    }

    /// Returns fixed native exchange byte/FD/name demand, without journal models.
    ///
    /// The trusted caller separately prepays current journal replay, signed
    /// artifacts and credentials. This DATA cannot admit an exchange or scope.
    #[must_use]
    pub fn fixed_native_receiving_demand_v1() -> Option<aos_sandbox_core::ResourceVector> {
        use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
        use aos_sandbox_linux::seqpacket::SeqpacketSocket;
        let (connect_bytes, connect_files) = SeqpacketSocket::retained_connect_obligations_v1();
        let (hello_bytes, hello_files) = DescriptorSubjectSocket::runtime_scope_receive_obligations_v1(
            aos_sandbox_protocol::MAXIMUM_HANDSHAKE_BYTES,
        )?;
        let (response_bytes, response_files) = DescriptorSubjectSocket::runtime_scope_receive_obligations_v1(
            RESPONSE_BYTES as usize,
        )?;
        let (pin_bytes, pin_files) = RuntimeScopeReceivedPidFdOriginalV1::receiving_demand_v1()?;
        let (cgroup_bytes, cgroup_files, names) = RuntimeScopeCgroupOriginalV1::receiving_demand_v1()?;
        // Actual owners plus their constructor/return/move carriers; the two
        // receive suppliers include their captured and malformed-prefix storage.
        let bytes = std::mem::size_of::<Self>().checked_mul(3)?
            .checked_add(std::mem::size_of::<RuntimeScopeOpeningOriginalV1>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<ObservedPayloadScope>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<CurrentRuntimeScope>().checked_mul(3)?)?
            .checked_add(connect_bytes)?.checked_add(hello_bytes)?.checked_add(response_bytes)?
            .checked_add(pin_bytes)?.checked_add(cgroup_bytes)?
            .checked_add(aos_sandbox_protocol::payload_scope::MAXIMUM_PAYLOAD_SCOPE_BODY_BYTES.checked_mul(3)?)?
            .checked_add(RESPONSE_BYTES as usize)?
            // The existing outer codec bounds the complete authorized packet;
            // five lanes cover copied quartet/body, encoded packet, decode and
            // retained artifact/raw message overlaps. Typed replay/signature
            // model geometry is still paid separately by the genuine caller.
            .checked_add(aos_sandbox_protocol::MAXIMUM_REQUEST_BYTES.checked_mul(5)?)?;
        use aos_sandbox_linux::cgroup::RuntimeScopeMembershipOriginalV1 as Membership;
        let (payload_bytes, payload_files, payload_names) = Membership::receiving_demand_v1()?;
        let (host_bytes, host_files, host_names) = Membership::exact_receiving_demand_v1()?;
        let (active_bytes, active_files, active_names) = Membership::active_receiving_demand_v1()?;
        // The actual exchange reaches nine Host exact flights, three payload
        // exact-or-descendant flights and one opening active-file probe.
        let membership_bytes = payload_bytes.checked_mul(3)?
            .checked_add(host_bytes.checked_mul(9)?)?.checked_add(active_bytes)?;
        let membership_files = payload_files.checked_mul(3)?
            .checked_add(host_files.checked_mul(9)?)?.checked_add(active_files)?;
        let membership_names = payload_names.checked_mul(3)?
            .checked_add(host_names.checked_mul(9)?)?.checked_add(active_names)?;
        let bytes = bytes.checked_add(membership_bytes)?;
        let files = connect_files.checked_add(hello_files)?.checked_add(response_files)?
            .checked_add(pin_files)?.checked_add(cgroup_files)?.checked_add(1)?
            .checked_add(membership_files)?;
        let output = aos_sandbox_protocol::MAXIMUM_HANDSHAKE_BYTES
            .checked_add(aos_sandbox_protocol::MAXIMUM_REQUEST_BYTES)?;
        let traffic = output.checked_add(aos_sandbox_protocol::MAXIMUM_HANDSHAKE_BYTES)?
            .checked_add(RESPONSE_BYTES as usize)?;
        Some(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?)
            .with(D::OpenFiles, u64::try_from(files).ok()?)
            .with(D::MetadataEntries, u64::try_from(names.checked_add(membership_names)?).ok()?)
            .with(D::NetworkBytes, u64::try_from(traffic).ok()?)
            .with(D::OutputBytes, u64::try_from(output).ok()?))
    }

    pub(crate) fn retain_unentered_client_v1(&mut self, client: RuntimeScopeClient) {
        if self.client.is_some() || self.attempted {
            std::process::abort();
        }
        self.client = Some(client);
        self.attempted = true;
    }

    /// Borrows the first actual exchange, selection, signature or currentness refusal.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.observation.failure()
            .or_else(|| self.membership.failure())
            .or_else(|| self.error.as_ref().map(|cause| cause as _))
    }
}

// A fixed one-exchange destination count. Host construction/pre-send/response
// use five flights; payload construction plus the paired final Host/payload
// recheck use four more. The current-selection final recheck uses three in its
// own window. Unused headers are bytes, never metadata-entry charges.
pub(super) struct RuntimeScopeMembershipWindowV1 {
    samples: [aos_sandbox_linux::cgroup::RuntimeScopeMembershipOriginalV1; 12],
    next: usize,
}

impl RuntimeScopeMembershipWindowV1 {
    pub(super) fn new() -> Self {
        Self {
            samples: std::array::from_fn(|_| {
                aos_sandbox_linux::cgroup::RuntimeScopeMembershipOriginalV1::new()
            }),
            next: 0,
        }
    }

    pub(super) fn observe(
        &mut self, anchor: &RetainedCgroupAnchor, process: &PidFd, hint: Option<&Path>,
    ) -> Result<PidFdInfo, RuntimeScopeError> {
        let sample = self.samples.get_mut(self.next).ok_or(RuntimeScopeError::RetainedNative)?;
        self.next += 1;
        sample.capture_once(anchor, process, hint).map_err(|_| RuntimeScopeError::RetainedNative)?;
        sample.completed_info().ok_or(RuntimeScopeError::RetainedNative)
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.samples[..self.next].iter().find_map(|sample| sample.failure().map(|cause| cause as _))
    }
}
