//! Applies the original Network worker horizon to fixed native record shapes.
//!
//! The shapes and cutoff are transport DATA. The caller still supplies genuine
//! dispatch authority, payment, native identities and all enclosing posts. No
//! constructor here creates any of those permissions or extends a deadline.

use super::descriptor_subject::{
    DescriptorSubjectSocket, MAXIMUM_PACKET_BYTES, ReceivedDescriptorRecord,
};
use super::receive_custody::SubjectProfileV1;
use super::{RetainedSeqpacketReceiveErrorV1, uapi};
use aos_linux_descriptors::Error;
use aos_linux_descriptors::Result;
use std::os::fd::BorrowedFd;

/// Names one existing Network READY or result record and its exact rights table.
#[derive(Clone, Copy, Debug)]
pub enum NetworkWorkerRecordKindV4 {
    /// Preparation READY:32 fixed bytes plus at most512 cgroup bytes, one right.
    PreparationReady,
    /// Observation READY:16 fixed bytes plus at most512 cgroup bytes, no rights.
    ObservationReady,
    /// Preparation's existing128-byte result without rights.
    PreparationResult,
    /// Observation's existing212-byte result without rights.
    ObservationResult,
    /// Preparation's128-byte result or its closed160-byte V2 negative.
    PreparationTerminalV2,
    /// Observation's212-byte result or its closed160-byte V2 negative.
    ObservationTerminalV2,
    /// Preparation READY with one namespace right, or its zero-right negative.
    PreparationReadyOrNegativeV2,
    /// Observation READY or its negative, each without transferred rights.
    ObservationReadyOrNegativeV2,
    /// First bounded P frame: actual63 host right or actual9 target+host rights.
    PreparationRequestFirstV2,
    /// A bounded continuation P frame, without another namespace right.
    PreparationRequestContinuationV2,
    /// H03 bootstrap's fixed 528-byte comparison header, without rights.
    ObservationHandoffHeaderV3,
    /// The original observation namespace request, with host and target rights.
    ObservationNamespaceRequestV2,
    /// The worker's exact ten-byte terminal acknowledgment, without rights.
    AcknowledgmentV2,
}

impl NetworkWorkerRecordKindV4 {
    /// Returns the existing maximum payload for this closed transport shape.
    #[must_use]
    pub const fn maximum_payload_bytes_v4(self) -> usize {
        match self {
            Self::PreparationReady => 32 + 512,
            Self::ObservationReady => 16 + 512,
            Self::PreparationResult => 128,
            Self::ObservationResult => 212,
            Self::PreparationTerminalV2 => 160,
            Self::ObservationTerminalV2 => 212,
            Self::PreparationReadyOrNegativeV2 => 32 + 512,
            Self::ObservationReadyOrNegativeV2 => 16 + 512,
            Self::PreparationRequestFirstV2 => 64 * 1024,
            Self::PreparationRequestContinuationV2 => 64 * 1024,
            Self::ObservationHandoffHeaderV3 => 528,
            Self::ObservationNamespaceRequestV2 => 184 + 512 * 1024,
            Self::AcknowledgmentV2 => 10,
        }
    }

    fn descriptors_v4(self) -> usize {
        match self {
            Self::PreparationReady | Self::PreparationReadyOrNegativeV2 => 1,
            Self::PreparationRequestFirstV2 => 2,
            Self::ObservationNamespaceRequestV2 => 2,
            _ => 0,
        }
    }
}

/// Carries unchanged original BOOTTIME and optional absolute WALL ceilings.
///
/// This deny-only mechanical horizon grants no worker, currentness or effect
/// permission. Baseline values must come from the caller's actual retained
/// native clock original; separately paid paired effects remain mandatory.
#[derive(Clone, Copy, Debug)]
pub struct NetworkWorkerNativeCutoffV4 {
    baseline_boot: u64,
    baseline_wall: i64,
    original_deadline: u64,
    wall_expiry: Option<i64>,
}

// The returned Linux error owns these actual negative native scalar samples.
// Successful pure samples have no later consumer and may leave this frame.
#[derive(Debug)]
struct NetworkWorkerCutoffFailureV4 {
    _boot: rustix::time::Timespec,
    _wall: rustix::time::Timespec,
    _original: NetworkWorkerNativeCutoffV4,
}

impl std::fmt::Display for NetworkWorkerCutoffFailureV4 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Network worker original cutoff expired or clock regressed")
    }
}

impl std::error::Error for NetworkWorkerCutoffFailureV4 {}

impl NetworkWorkerNativeCutoffV4 {
    /// Stores actual baseline values and the existing narrowed source ceilings.
    #[must_use]
    pub const fn new(
        baseline_boot: u64,
        baseline_wall: i64,
        original_deadline: u64,
        wall_expiry: Option<i64>,
    ) -> Self {
        Self {
            baseline_boot,
            baseline_wall,
            original_deadline,
            wall_expiry,
        }
    }

    /// Returns the unchanged original BOOTTIME ceiling as transport DATA.
    #[must_use]
    pub const fn original_deadline_v4(self) -> u64 {
        self.original_deadline
    }

    /// Prices the actual scalar pair, first-cause payload and error controls.
    #[must_use]
    pub fn receiving_bytes_v4() -> Option<usize> {
        std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(std::mem::size_of::<NetworkWorkerCutoffFailureV4>())?
            .checked_add(std::mem::size_of::<std::io::Error>())?
            .checked_add(4 * std::mem::size_of::<usize>())
    }

    pub(super) fn check_v4(self) -> Result<()> {
        self.observe_native_v4().map(|_| ())
    }

    /// Returns a deny-checked native BOOTTIME scalar under the unchanged caps.
    ///
    /// This observation grants no currentness, effect or cleanup permission.
    /// Its caller must retain an error and its typed rejected pair on failure.
    ///
    /// # Errors
    /// Owns the actual rejected scalar pair for expiry or clock regression.
    pub fn observe_native_v4(self) -> Result<u64> {
        let boot = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
        let wall = rustix::time::clock_gettime(rustix::time::ClockId::Realtime);
        let now = u64::try_from(boot.tv_sec)
            .ok()
            .and_then(|seconds| seconds.checked_mul(1_000_000_000))
            .zip(
                u64::try_from(boot.tv_nsec)
                    .ok()
                    .filter(|nanos| *nanos < 1_000_000_000),
            )
            .and_then(|(seconds, nanos)| seconds.checked_add(nanos));
        if now.is_none_or(|now| now < self.baseline_boot || now >= self.original_deadline)
            || wall.tv_sec < self.baseline_wall
            || !(0..1_000_000_000).contains(&wall.tv_nsec)
            || self.wall_expiry.is_some_and(|expiry| wall.tv_sec >= expiry)
        {
            return Err(Error::Syscall {
                operation: "Network worker original native horizon",
                source: std::io::Error::other(NetworkWorkerCutoffFailureV4 {
                    _boot: boot,
                    _wall: wall,
                    _original: self,
                }),
            });
        }
        now.ok_or_else(|| {
            Error::invalid(
                "Network worker original horizon",
                "validated scalar missing",
            )
        })
    }
}

impl DescriptorSubjectSocket {
    /// Receives an unentered owed O six-right slot or the parent's early ACK.
    ///
    /// The actor accepts only the original full H03/six-right record or exact
    /// ACK10/zero-right record after owed Source/origin checks. This dedicated
    /// profile preserves the six-right control ceiling and grants no public
    /// credential, read, effect or renewed deadline permission.
    ///
    /// # Errors
    /// Retains the same original native prefix, subject, rights and endpoint.
    pub fn receive_owed_network_observer_handoff_or_ack_retaining_v3(
        &mut self,
        exact_bytes: usize,
    ) -> std::result::Result<ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1> {
        if !(528..=MAXIMUM_PACKET_BYTES).contains(&exact_bytes) {
            return Err(RetainedSeqpacketReceiveErrorV1::before_receive(super::SeqpacketError::InvalidMaximum));
        }
        self.receive_profile_with_cutoff_v4(exact_bytes,
            SubjectProfileV1::Descriptors { expected: 6, allow_empty: true },
            uapi::ReceiveControlProfileV1::NetworkObserverPublicHandoff6, None)
    }

    /// Receives an unentered owed O namespace pair or the parent's early ACK.
    ///
    /// Only the previously admitted exact O request with two rights or exact
    /// ACK10 with none may pass the actual Source-bound consumer. All returned
    /// carriers remain resident through negative handback; none is adopted.
    ///
    /// # Errors
    /// Retains the original native prefix and refuses an unbounded allocation.
    pub fn receive_owed_network_observer_namespace_or_ack_retaining_v3(
        &mut self,
        exact_bytes: usize,
    ) -> std::result::Result<ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1> {
        if !(184..=184 + 512 * 1024).contains(&exact_bytes) {
            return Err(RetainedSeqpacketReceiveErrorV1::before_receive(super::SeqpacketError::InvalidMaximum));
        }
        self.receive_profile_with_cutoff_v4(exact_bytes,
            SubjectProfileV1::Descriptors { expected: 2, allow_empty: true },
            uapi::ReceiveControlProfileV1::WorkerObserver, None)
    }

    /// Receives one unentered owed P frame or the parent's early zero-right ACK.
    ///
    /// First-frame native roles remain only one or two; the zero-right branch
    /// is exclusively canonical ACK DATA at the actor. Continuations carry no
    /// rights. The consumer authenticates actual Source and bounded P2 progress
    /// and never retries an entered native failure or creates effect authority.
    ///
    /// # Errors
    /// Retains every original native operand and actual descriptor sequence.
    pub fn receive_owed_network_preparation_frame_or_ack_retaining_v3(
        &mut self,
        first: bool,
    ) -> std::result::Result<ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1> {
        let profile = if first { SubjectProfileV1::NetworkPreparationOwedFirstOrAckV3 }
            else { SubjectProfileV1::Descriptors { expected: 0, allow_empty: false } };
        self.receive_profile_with_cutoff_v4(64 * 1024, profile,
            uapi::ReceiveControlProfileV1::WorkerObserver, None)
    }

    /// Receives one prepaid bootstrap P frame before signed D is available.
    ///
    /// The first frame admits only the existing one-or-two-right role shape;
    /// a continuation admits none. The actual child must retain Source/native
    /// posts, authenticate the first record and validate its bounded header
    /// before allocating the aggregate. This performs no poll, retry, deadline
    /// construction, Source adoption or effect admission.
    ///
    /// # Errors
    /// Retains the same native receive prefix, endpoint and ancillary failure.
    pub fn receive_network_preparation_bootstrap_frame_retaining_v3(
        &mut self,
        first: bool,
    ) -> std::result::Result<ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1> {
        let profile = if first {
            SubjectProfileV1::NetworkPreparationFirstV2
        } else {
            SubjectProfileV1::Descriptors { expected: 0, allow_empty: false }
        };
        self.receive_profile_with_cutoff_v4(
            64 * 1024,
            profile,
            uapi::ReceiveControlProfileV1::WorkerObserver,
            None,
        )
    }

    /// Receives one already-owed ten-byte ACK without renewing effect D.
    ///
    /// The actual worker prepays this one nonblocking receive before its
    /// terminal send. Native Source/channel affinity and exact V2 ACK bytes
    /// remain independent caller obligations. Missing ACK retains uncertainty;
    /// it grants no new read, helper, effect or Source permission.
    ///
    /// # Errors
    /// Retains the original endpoint, subject, ancillary and native failure.
    pub fn receive_owed_network_worker_acknowledgment_retaining_v3(
        &mut self,
    ) -> std::result::Result<ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1> {
        self.receive_profile_with_cutoff_v4(
            10,
            SubjectProfileV1::Descriptors { expected: 0, allow_empty: false },
            uapi::ReceiveControlProfileV1::WorkerObserver,
            None,
        )
    }

    /// Receives the fixed H03 header before learning the signed effect horizon.
    ///
    /// The caller prepays this one nonblocking receive on the actual issued
    /// Source-bound channel. Native peer/record affinity precedes acceptance
    /// of its comparison DATA. The header grants no D or read permission.
    ///
    /// # Errors
    /// Retains the actual endpoint, native prefix, subject and ancillary error.
    pub fn receive_network_observer_handoff_header_retaining_v3(
        &mut self,
    ) -> std::result::Result<ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1> {
        self.receive_profile_with_cutoff_v4(
            528,
            SubjectProfileV1::Descriptors {
                expected: 0,
                allow_empty: false,
            },
            uapi::ReceiveControlProfileV1::WorkerObserver,
            None,
        )
    }

    /// Receives exactly the H03 width checked from the native-bound header.
    ///
    /// This is the dedicated six-right bootstrap profile on the same native
    /// engine. No fabricated cutoff precedes signed admission. The caller
    /// compares the complete fixed prefix, authenticates all six originals
    /// and requires the original signed D before any positive read operation.
    ///
    /// # Errors
    /// Retains the endpoint and reached native prefix for malformed transport,
    /// rights, process subject, or an invalid allocation bound.
    pub fn receive_network_observer_bootstrap_handoff_retaining_v3(
        &mut self,
        exact_bytes: usize,
    ) -> std::result::Result<ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1> {
        if !(528..=MAXIMUM_PACKET_BYTES).contains(&exact_bytes) {
            return Err(RetainedSeqpacketReceiveErrorV1::before_receive(
                super::SeqpacketError::InvalidMaximum,
            ));
        }
        self.receive_profile_with_cutoff_v4(
            exact_bytes,
            SubjectProfileV1::NetworkObserverPublicHandoff6,
            uapi::ReceiveControlProfileV1::NetworkObserverPublicHandoff6,
            None,
        )
    }

    /// Sends a closed child READY, result or negative on the existing engine.
    ///
    /// A bootstrap READY and an already-owed negative may omit the deny-only
    /// native cutoff. The actual child Source, original cause and independent
    /// posts remain with the caller; this transport creates no effect grant.
    ///
    /// # Errors
    /// Returns the original native receipt and optional rejected clock for
    /// transport failure; refuses another kind or an inexact rights table.
    pub fn send_network_worker_child_record_retaining_v3(
        &mut self,
        kind: NetworkWorkerRecordKindV4,
        payload: &[u8],
        descriptors: &[BorrowedFd<'_>],
        cutoff: Option<NetworkWorkerNativeCutoffV4>,
    ) -> (
        std::result::Result<
            super::descriptor_subject::DescriptorWorkerNativeSendAttemptV1,
            super::SeqpacketError,
        >,
        Option<Error>,
    ) {
        let valid_width = match kind {
            NetworkWorkerRecordKindV4::PreparationReady => (32..=32 + 512).contains(&payload.len()),
            NetworkWorkerRecordKindV4::ObservationReady => (16..=16 + 512).contains(&payload.len()),
            NetworkWorkerRecordKindV4::PreparationResult => payload.len() == 128,
            NetworkWorkerRecordKindV4::ObservationResult => payload.len() == 212,
            NetworkWorkerRecordKindV4::PreparationTerminalV2 => payload.len() == 160,
            NetworkWorkerRecordKindV4::ObservationTerminalV2 => matches!(payload.len(), 160 | 212),
            _ => false,
        };
        if !valid_width || descriptors.len() != kind.descriptors_v4() {
            return (Err(super::SeqpacketError::InvalidMaximum), None);
        }
        let mut gate = || cutoff.map_or(Ok(()), NetworkWorkerNativeCutoffV4::check_v4);
        self.send_worker_record_with_gate_v4(payload, descriptors, Some(&mut gate))
    }

    /// Prices the same child sender, native receipt and retained clock failure.
    #[must_use]
    pub fn network_worker_child_send_obligations_v3() -> Option<usize> {
        super::descriptor_subject::DescriptorWorkerNativeSendAttemptV1::requested_bytes_v1()?
            .checked_add(NetworkWorkerNativeCutoffV4::receiving_bytes_v4()?)
    }

    /// Receives the exact admitted observation request with host/target rights.
    ///
    /// The width comes from the already authenticated handoff's ninth section.
    /// The unchanged original cutoff guards both native preview and consume;
    /// the caller still requires exact byte equality with that admitted section.
    ///
    /// # Errors
    /// Retains the actual endpoint, native prefix and ancillary/clock failure.
    pub fn receive_network_observer_namespace_request_retaining_v3(
        &mut self,
        exact_bytes: usize,
        cutoff: NetworkWorkerNativeCutoffV4,
    ) -> std::result::Result<ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1> {
        if !(184..=184 + 512 * 1024).contains(&exact_bytes) {
            return Err(RetainedSeqpacketReceiveErrorV1::before_receive(
                super::SeqpacketError::InvalidMaximum,
            ));
        }
        self.receive_profile_with_cutoff_v4(
            exact_bytes,
            SubjectProfileV1::Descriptors {
                expected: 2,
                allow_empty: false,
            },
            uapi::ReceiveControlProfileV1::WorkerObserver,
            Some(cutoff),
        )
    }

    /// Prices the actual admitted namespace-request width on the same engine.
    #[must_use]
    pub fn network_observer_namespace_request_receive_obligations_v3(
        exact_bytes: usize,
    ) -> Option<(usize, usize)> {
        if !(184..=184 + 512 * 1024).contains(&exact_bytes) {
            return None;
        }
        let control = uapi::ReceiveControlProfileV1::WorkerObserver;
        let (bytes, files) = Self::worker_observer_receive_obligations_v1();
        let old_raw = super::SeqpacketSocket::requested_receive_bytes(4096, control, 2);
        let raw = super::SeqpacketSocket::requested_receive_bytes(exact_bytes, control, 2);
        Some((
            bytes
                .checked_sub(old_raw)?
                .checked_add(raw)?
                .checked_add(NetworkWorkerNativeCutoffV4::receiving_bytes_v4()?)?,
            files,
        ))
    }

    /// Receives one issued worker's READY-or-negative record without a new D.
    ///
    /// The caller retains the actual issued child pins and pays this one
    /// nonblocking receive before entry. READY supplies no effect permission;
    /// a positive continuation still requires the unchanged Source and D.
    /// Negative ACK and actual dead/Empty disposition remain independently owed.
    ///
    /// # Errors
    /// Refuses another shape, transport, inexact rights or process admission,
    /// retaining the original endpoint and reached native receive prefix.
    pub fn receive_owed_network_worker_ready_or_negative_retaining_v2(
        &mut self,
        kind: NetworkWorkerRecordKindV4,
    ) -> std::result::Result<ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1> {
        if !matches!(
            kind,
            NetworkWorkerRecordKindV4::PreparationReadyOrNegativeV2
                | NetworkWorkerRecordKindV4::ObservationReadyOrNegativeV2
        ) {
            return Err(RetainedSeqpacketReceiveErrorV1::before_receive(
                super::SeqpacketError::InvalidMaximum,
            ));
        }
        self.receive_profile_with_cutoff_v4(
            kind.maximum_payload_bytes_v4(),
            SubjectProfileV1::Descriptors {
                expected: kind.descriptors_v4(),
                allow_empty: matches!(
                    kind,
                    NetworkWorkerRecordKindV4::PreparationReadyOrNegativeV2
                ),
            },
            uapi::ReceiveControlProfileV1::WorkerObserver,
            None,
        )
    }

    /// Receives an already-issued worker's owed terminal comparison record.
    ///
    /// This performs one nonblocking strict receive on the retained endpoint.
    /// It deliberately admits only the closed V2 terminal shapes, without a
    /// fresh positive effect clock. The caller retains original D, native child
    /// custody, first cause, ACK and death/Empty obligations. A late positive
    /// payload supplies no effect success or renewed Source permission.
    ///
    /// # Errors
    /// Refuses another record shape, transport, ancillary or native subject
    /// failure while retaining the actual endpoint and reached receive prefix.
    pub fn receive_owed_network_worker_terminal_retaining_v2(
        &mut self,
        kind: NetworkWorkerRecordKindV4,
    ) -> std::result::Result<ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1> {
        if !matches!(
            kind,
            NetworkWorkerRecordKindV4::PreparationTerminalV2
                | NetworkWorkerRecordKindV4::ObservationTerminalV2
        ) {
            return Err(RetainedSeqpacketReceiveErrorV1::before_receive(
                super::SeqpacketError::InvalidMaximum,
            ));
        }
        self.receive_profile_with_cutoff_v4(
            kind.maximum_payload_bytes_v4(),
            SubjectProfileV1::Descriptors {
                expected: 0,
                allow_empty: false,
            },
            uapi::ReceiveControlProfileV1::WorkerObserver,
            None,
        )
    }

    /// Receives the closed six-public-credential observer handoff.
    ///
    /// The caller prepays the exact compiled packet ceiling before entry. The
    /// same retained preview/consume engine requires exactly six ordered rights
    /// plus one authenticated process subject under the unchanged cutoff.
    /// Public credential roles and canonical AOSNOH03 bytes remain separate
    /// domain checks; this native carrier supplies no Source or read authority.
    ///
    /// # Errors
    /// Retains the original endpoint, raw rights, subject and native failure for
    /// invalid geometry, transport, ancillary, clock or process admission.
    pub fn receive_network_observer_handoff_retaining_v2(
        &mut self,
        maximum_bytes: usize,
        cutoff: NetworkWorkerNativeCutoffV4,
    ) -> std::result::Result<ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1> {
        if !(528..=MAXIMUM_PACKET_BYTES).contains(&maximum_bytes) {
            return Err(RetainedSeqpacketReceiveErrorV1::before_receive(
                super::SeqpacketError::InvalidMaximum,
            ));
        }
        self.receive_profile_with_cutoff_v4(
            maximum_bytes,
            SubjectProfileV1::NetworkObserverPublicHandoff6,
            uapi::ReceiveControlProfileV1::NetworkObserverPublicHandoff6,
            Some(cutoff),
        )
    }

    /// Prices the dedicated six-right receiver for its actual compiled bound.
    ///
    /// The packet ceiling comes from the canonical handoff supplier. It is not
    /// a native FD cap, Source invoice or permission to adopt public credentials.
    ///
    /// # Errors
    /// Returns no quote when the header cannot fit or size arithmetic overflows.
    #[must_use]
    pub fn network_observer_handoff_receive_obligations_v2(
        maximum_bytes: usize,
    ) -> Option<(usize, usize)> {
        if !(528..=MAXIMUM_PACKET_BYTES).contains(&maximum_bytes) {
            return None;
        }
        let old_control = uapi::ReceiveControlProfileV1::WorkerObserver;
        let control = uapi::ReceiveControlProfileV1::NetworkObserverPublicHandoff6;
        let (old, _) = Self::worker_observer_receive_obligations_v1();
        let old_raw = super::SeqpacketSocket::requested_receive_bytes(4096, old_control, 2);
        let raw = super::SeqpacketSocket::requested_receive_bytes(maximum_bytes, control, 2);
        let bytes = old
            .checked_sub(old_raw)?
            .checked_add(raw)?
            .checked_add(NetworkWorkerNativeCutoffV4::receiving_bytes_v4()?)?;
        // A positive preview retains six rights and its subject pin while the
        // consumed sample may have installed every raw control-buffer cell.
        let files = control.maximum_descriptor_slots().checked_add(6 + 1)?;
        Some((bytes, files))
    }

    /// Receives one closed Network record on the same strict retained engine.
    ///
    /// The original BOOTTIME/WALL horizon is checked immediately before BOTH
    /// native preview and consume. A refusal after preview retains that actual
    /// packet/ancillary prefix and fences the same original endpoint.
    ///
    /// # Errors
    /// Owns the original cutoff, native, ancillary or exact-table failure.
    pub fn receive_network_worker_retaining_v4(
        &mut self,
        kind: NetworkWorkerRecordKindV4,
        cutoff: NetworkWorkerNativeCutoffV4,
    ) -> std::result::Result<ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1> {
        let profile = match kind {
            NetworkWorkerRecordKindV4::PreparationRequestFirstV2 => {
                SubjectProfileV1::NetworkPreparationFirstV2
            }
            _ => SubjectProfileV1::Descriptors {
                expected: kind.descriptors_v4(),
                allow_empty: matches!(
                    kind,
                    NetworkWorkerRecordKindV4::PreparationReadyOrNegativeV2
                ),
            },
        };
        self.receive_profile_with_cutoff_v4(
            kind.maximum_payload_bytes_v4(),
            profile,
            uapi::ReceiveControlProfileV1::WorkerObserver,
            Some(cutoff),
        )
    }

    /// Returns compiled raw/retained receive bytes and simultaneous native FDs.
    ///
    /// Only real native objects are counted. No Rust fields become namespace
    /// entries; the surrounding genuine owner pays its actual names separately.
    #[must_use]
    pub fn network_worker_receive_obligations_v4(
        kind: NetworkWorkerRecordKindV4,
    ) -> Option<(usize, usize)> {
        let control = uapi::ReceiveControlProfileV1::WorkerObserver;
        let (old, files) = Self::worker_observer_receive_obligations_v1();
        let old_raw = super::SeqpacketSocket::requested_receive_bytes(4096, control, 2);
        let raw = super::SeqpacketSocket::requested_receive_bytes(
            kind.maximum_payload_bytes_v4(),
            control,
            2,
        );
        Some((
            old.checked_sub(old_raw)?
                .checked_add(raw)?
                .checked_add(NetworkWorkerNativeCutoffV4::receiving_bytes_v4()?)?,
            files,
        ))
    }
}

#[cfg(test)]
mod clock_custody_tests {
    use super::*;

    #[test]
    fn v2_terminal_shapes_cover_negatives_without_widening_v1_records_or_rights() {
        assert_eq!(
            NetworkWorkerRecordKindV4::PreparationResult.maximum_payload_bytes_v4(),
            128
        );
        assert_eq!(
            NetworkWorkerRecordKindV4::ObservationResult.maximum_payload_bytes_v4(),
            212
        );
        assert_eq!(
            NetworkWorkerRecordKindV4::PreparationTerminalV2.maximum_payload_bytes_v4(),
            160
        );
        assert_eq!(
            NetworkWorkerRecordKindV4::ObservationTerminalV2.maximum_payload_bytes_v4(),
            212
        );
        for kind in [
            NetworkWorkerRecordKindV4::PreparationResult,
            NetworkWorkerRecordKindV4::ObservationResult,
            NetworkWorkerRecordKindV4::PreparationTerminalV2,
            NetworkWorkerRecordKindV4::ObservationTerminalV2,
        ] {
            assert_eq!(kind.descriptors_v4(), 0);
        }
        assert_eq!(
            NetworkWorkerRecordKindV4::ObservationHandoffHeaderV3.maximum_payload_bytes_v4(),
            528
        );
        assert_eq!(
            NetworkWorkerRecordKindV4::ObservationHandoffHeaderV3.descriptors_v4(),
            0
        );
        assert_eq!(
            NetworkWorkerRecordKindV4::ObservationNamespaceRequestV2.descriptors_v4(),
            2
        );
        assert_eq!(
            NetworkWorkerRecordKindV4::AcknowledgmentV2.maximum_payload_bytes_v4(),
            10
        );
        assert_eq!(
            NetworkWorkerRecordKindV4::AcknowledgmentV2.descriptors_v4(),
            0
        );
        assert!(
            DescriptorSubjectSocket::network_observer_namespace_request_receive_obligations_v3(183)
                .is_none()
        );
        assert!(
            DescriptorSubjectSocket::network_observer_namespace_request_receive_obligations_v3(
                184 + 512 * 1024 + 1
            )
            .is_none()
        );
    }

    #[test]
    fn expired_actual_pair_stays_owned_by_the_returned_native_error() {
        let boot = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
        let wall = rustix::time::clock_gettime(rustix::time::ClockId::Realtime);
        let baseline = u64::try_from(boot.tv_sec).unwrap() * 1_000_000_000
            + u64::try_from(boot.tv_nsec).unwrap();
        let cutoff = NetworkWorkerNativeCutoffV4::new(
            baseline,
            wall.tv_sec,
            baseline + 5_000_000_000,
            Some(wall.tv_sec),
        );

        let error = cutoff.check_v4().unwrap_err();

        let Error::Syscall { source, .. } = &error else {
            panic!("actual typed clock payload missing")
        };
        let original = source
            .get_ref()
            .unwrap()
            .downcast_ref::<NetworkWorkerCutoffFailureV4>()
            .unwrap();
        assert!(original._wall.tv_sec >= wall.tv_sec);
        assert_eq!(
            original._original.original_deadline,
            cutoff.original_deadline
        );
        assert_eq!(original._original.wall_expiry, Some(wall.tv_sec));
        let first = original as *const NetworkWorkerCutoffFailureV4;
        assert_eq!(
            first,
            source
                .get_ref()
                .unwrap()
                .downcast_ref::<NetworkWorkerCutoffFailureV4>()
                .unwrap() as *const NetworkWorkerCutoffFailureV4
        );
    }
}
