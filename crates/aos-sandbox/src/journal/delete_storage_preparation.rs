//! Shares Delete26/7/9/62 native mechanics without creating a caller or worker lease.
//!
//! The real Root/Source/C17 loan alone calls these crate-private mechanics after
//! exact historical comparison and complete prepayment. The same existing
//! currentness and captured append kernels keep every entered native prefix;
//! no Journal, socket, writer or Controller interval is reopened here.

use super::broker_session_receiving::StorageSessionGeometryRefusalV1;
use super::inventory_native::InventoryAppendWindowOriginalV2;
use super::native_interval::captured::{CapturedAppendOwnerV1, DeleteSessionAppendWindowV1};
use super::*;
use aos_proto::aos::sandbox::local::v1::{Audience, BrokerMethod};
use crate::ResourceReservationErrorV1;
use aos_sandbox_broker_session_protocol::{
    BrokerSessionProtocolV1, VerifiedBrokerSessionTranscriptV1,
};
use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::seqpacket::{
    RecordBindingError, SeqpacketSocket, StorageSeqpacketSessionOriginV1,
};
use std::error::Error;

type Closed = ResourceReservationErrorV1;

#[derive(Clone, Copy)]
enum First {
    Binding,
    Before,
    Association,
    Socket,
    After,
    Extent,
    Encoded,
    Future,
    Geometry,
    Installation,
    Retirement,
    Reentry,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Purpose {
    Preparation26,
    Apply7,
    Network9,
    Mount62,
}

impl Purpose {
    fn method(self) -> BrokerMethod {
        match self {
            Self::Preparation26 => BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG,
            Self::Apply7 => BrokerMethod::BROKER_METHOD_STORAGE_APPLY,
            Self::Network9 => BrokerMethod::BROKER_METHOD_NETWORK_APPLY,
            Self::Mount62 => BrokerMethod::BROKER_METHOD_MOUNT_APPLY_ATTACHMENT_ANCHOR_V1,
        }
    }

    fn protocol(self) -> BrokerSessionProtocolV1 {
        match self {
            Self::Preparation26 | Self::Apply7 => BrokerSessionProtocolV1::Storage,
            Self::Network9 => BrokerSessionProtocolV1::Network,
            Self::Mount62 => BrokerSessionProtocolV1::Mount,
        }
    }

    fn directory(self) -> &'static str {
        let role = match self {
            Self::Preparation26 | Self::Apply7 => crate::ControllerInitialBrokerSessionRoleV1::Storage,
            Self::Network9 => crate::ControllerInitialBrokerSessionRoleV1::Network,
            Self::Mount62 => crate::ControllerInitialBrokerSessionRoleV1::Mount,
        };
        super::storage_captured_open::controller_session_directory_data_v1(role)
    }
}

enum Predecessor {
    Inventory((u64, u64, u64, u64)),
    Preparation([u8; 64]),
}

pub(crate) struct DeleteStorageSessionNativeOriginalV3 {
    purpose: Purpose,
    predecessor_native: Option<Result<[u8; 64], JournalError>>,
    predecessor_witness: aos_sandbox_journal::protected_storage::WriterWitnessOriginalsV1<JournalError>,
    link: Option<StorageNativeOpeningOwnerLinkV1>,
    binding: Option<([u8; 32], [u8; 32])>,
    recipe: Option<Result<(), JournalError>>,
    uid: Option<u32>,
    before: ProtectedJournalCurrentnessOriginalsV1,
    before_result: Option<Result<(), JournalError>>,
    association: Option<Result<(), JournalError>>,
    socket: Option<Result<StorageSeqpacketSessionOriginV1, RecordBindingError>>,
    socket_native: Option<Result<u64, aos_sandbox_linux::Error>>,
    after: ProtectedJournalCurrentnessOriginalsV1,
    after_result: Option<Result<(), JournalError>>,
    metadata: Option<std::io::Result<std::fs::Metadata>>,
    extent: Option<Result<ProtectedJournalPreopenReplayExtentV1, JournalError>>,
    encoded: Option<Result<u64, StorageSessionGeometryRefusalV1>>,
    future: Option<Result<ProtectedJournalPreopenReplayExtentV1, JournalError>>,
    geometry: Option<Result<ResourceVector, JournalError>>,
    window: InventoryAppendWindowOriginalV2,
    first: Option<First>,
    entered: bool,
    reentry: Option<JournalError>,
}

impl DeleteStorageSessionNativeOriginalV3 {
    pub(crate) fn preparation_v3() -> Self {
        Self::new(Purpose::Preparation26)
    }

    pub(crate) fn apply_v3() -> Self {
        Self::new(Purpose::Apply7)
    }

    pub(crate) fn network_v4() -> Self {
        Self::new(Purpose::Network9)
    }

    pub(crate) fn mount_v4() -> Self {
        Self::new(Purpose::Mount62)
    }

    fn new(purpose: Purpose) -> Self {
        Self {
            purpose,
            predecessor_native: None,
            predecessor_witness: aos_sandbox_journal::protected_storage::WriterWitnessOriginalsV1::new(),
            link: None,
            binding: None,
            recipe: None,
            uid: None,
            before: ProtectedJournalCurrentnessOriginalsV1::new(),
            before_result: None,
            association: None,
            socket: None,
            socket_native: None,
            after: ProtectedJournalCurrentnessOriginalsV1::new(),
            after_result: None,
            metadata: None,
            extent: None,
            encoded: None,
            future: None,
            geometry: None,
            window: Default::default(),
            first: None,
            entered: false,
            reentry: None,
        }
    }

    pub(crate) fn capture_receiving_demand_v3() -> Result<ResourceVector, JournalError> {
        Self::capture_receiving_for_purpose_v4(Purpose::Preparation26)
    }

    pub(crate) fn network_capture_receiving_demand_v4() -> Result<ResourceVector, JournalError> {
        Self::capture_receiving_for_purpose_v4(Purpose::Network9)
    }

    pub(crate) fn mount_capture_receiving_demand_v4() -> Result<ResourceVector, JournalError> {
        Self::capture_receiving_for_purpose_v4(Purpose::Mount62)
    }

    fn capture_receiving_for_purpose_v4(purpose: Purpose) -> Result<ResourceVector, JournalError> {
        let names = ProtectedJournalCurrentnessOriginalsV1::fixed_demand_v1(
            Path::new(purpose.directory()),
            "session.journal",
        )?;
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(2)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(JournalError::JournalTooLarge)?;
        let witness = aos_sandbox_journal::protected_storage::WriterWitnessOriginalsV1::<
            JournalError,
        >::receiving_footprint_v1()
        .ok_or(JournalError::JournalTooLarge)?;
        let witness_bytes =
            u64::try_from(witness.memory_bytes).map_err(|_| JournalError::JournalTooLarge)?;
        let bytes = bytes
            .checked_add(witness_bytes)
            .ok_or(JournalError::JournalTooLarge)?;
        names
            .checked_add(names)
            .and_then(|demand| demand.checked_add(names))
            .and_then(|demand| demand.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes)))
            .map_err(JournalError::ReceivingAccounting)
    }

    pub(crate) fn capture_inventory_once_v3(
        &mut self,
        journal: &Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        expected_native: (u64, u64, u64, u64),
    ) -> Result<(), Closed> {
        self.capture_engine_v3(journal, socket, transcript, Predecessor::Inventory(expected_native))
    }

    pub(crate) fn capture_preparation_once_v3(
        &mut self,
        journal: &Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        expected_native: [u8; 64],
    ) -> Result<(), Closed> {
        self.capture_engine_v3(journal, socket, transcript, Predecessor::Preparation(expected_native))
    }

    fn capture_engine_v3(
        &mut self,
        journal: &Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        predecessor: Predecessor,
    ) -> Result<(), Closed> {
        if self.entered {
            self.reentry.get_or_insert(JournalError::ProtectedBoundary);
            self.first.get_or_insert(First::Reentry);
            return Err(Closed::Conflict);
        }
        self.entered = true;
        self.recipe = Some((|| {
            if !matches!((self.purpose, &predecessor),
                (Purpose::Preparation26, Predecessor::Inventory(_))
                    | (Purpose::Network9, Predecessor::Inventory(_))
                    | (Purpose::Mount62, Predecessor::Inventory(_))
                    | (Purpose::Apply7, Predecessor::Preparation(_)))
                || transcript.protocol() != self.purpose.protocol()
                || transcript.audience() != Audience::AUDIENCE_NODE_CONTROLLER
                || !transcript.negotiated_methods().contains(&self.purpose.method())
                || journal.configured_limits() != super::broker_session_receiving::protected_session_journal_limits_v1()
                || !matches!(&journal.native, super::native_backing::JournalNativeBackingV1::Ordinary(_))
            { return Err(JournalError::ProtectedBoundary); }
            Ok(())
        })());
        if !matches!(self.recipe, Some(Ok(()))) {
            self.first = Some(First::Binding);
            return Err(Closed::Conflict);
        }
        self.uid = Some(rustix::process::geteuid().as_raw());
        self.before_result = Some(match &predecessor {
            Predecessor::Inventory(_) => journal.validate_held_owned_at_for_uid_retaining(
                self.purpose.directory(),
                "session.journal",
                self.uid.ok_or(Closed::Conflict)?,
                &mut self.before,
            ),
            Predecessor::Preparation(_) => {
                // The actual completed26 lender already fixes the same held
                // root/link/socket. Observe its current full native position
                // using the existing names/witness kernel before any7 append.
                self.predecessor_native = Some(journal.observe_session_completion_position_retaining_v2(
                    &mut self.before,
                    &mut self.predecessor_witness,
                ));
                if matches!(self.predecessor_native, Some(Ok(_))) {
                    Ok(())
                } else {
                    Err(JournalError::ProtectedBoundary)
                }
            }
        });
        if !matches!(self.before_result, Some(Ok(()))) {
            self.first.get_or_insert(First::Before);
        }
        if self.first.is_none() {
            // The genuine upper loan already joined its completed predecessor
            // to the actual Root/C contract. Compare that owner's native cut
            // to this exact held file before either receipt append; the shared
            // engine never reconstructs a predecessor from a head tuple.
            self.association = Some(match predecessor {
                Predecessor::Inventory(expected_native) => require_inventory_native_boundary_v3(
                    super::inventory_native::completed_boundary_data_v2(journal, &self.before),
                    expected_native,
                ),
                Predecessor::Preparation(expected_native) => require_preparation_native_boundary_v3(
                    self.predecessor_native.as_ref().and_then(|result| result.as_ref().ok()),
                    &expected_native,
                ),
            });
            if !matches!(self.association, Some(Ok(()))) {
                self.first.get_or_insert(First::Association);
            }
        }
        if self.first.is_none() {
            self.link = Some(journal.held_session_owner_link_v1());
            self.binding = Some((
                transcript.session_binding(),
                transcript.protected_context_digest(),
            ));
            self.socket =
                Some(socket.capture_storage_session_origin_retaining_v4(&mut self.socket_native));
            if !matches!(self.socket, Some(Ok(_))) {
                self.first.get_or_insert(First::Socket);
            }
        }
        // Entering the names-before owns this independent post, including a
        // failed before or cookie. The original first cause remains selected.
        self.after_result = Some(journal.observe_held_names_post_retaining_v1(&mut self.after));
        if !matches!(self.after_result, Some(Ok(()))) {
            self.first.get_or_insert(First::After);
        }
        if self.first.is_none() {
            Ok(())
        } else {
            Err(Closed::Conflict)
        }
    }

    pub(crate) fn require_completed_capture_v3(&self) -> Result<(), Closed> {
        if self.first.is_none()
            && self.link.is_some()
            && self.binding.is_some()
            && matches!(self.before_result, Some(Ok(())))
            && matches!(self.association, Some(Ok(())))
            && matches!(self.socket, Some(Ok(_)))
            && matches!(self.socket_native, Some(Ok(_)))
            && matches!(self.after_result, Some(Ok(())))
        {
            Ok(())
        } else {
            Err(Closed::Conflict)
        }
    }

    pub(crate) fn require_journal_v3(&self, journal: &Journal) -> Result<(), Closed> {
        if self
            .link
            .as_ref()
            .is_some_and(|link| link.matches_journal_v1(journal))
        {
            Ok(())
        } else {
            Err(Closed::Conflict)
        }
    }

    pub(crate) fn require_session_v3(
        &self,
        journal: &Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), Closed> {
        // Owed observations compare actual retained identity without a healthy
        // C/Root gate. The caller separately retains the whole primary failure.
        self.require_journal_v3(journal)?;
        if self.binding
            != Some((
                transcript.session_binding(),
                transcript.protected_context_digest(),
            ))
            || transcript.protocol() != self.purpose.protocol()
        {
            return Err(Closed::Conflict);
        }
        self.socket
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(Closed::Conflict)?
            .require_same_socket_data_v4(socket)
            .map_err(|_| Closed::Conflict)
    }

    pub(crate) fn prepare_append_demand_v3(
        &mut self,
        journal: &Journal,
        request_bytes: usize,
    ) -> Result<ResourceVector, JournalError> {
        if self.first.is_some()
            || self.extent.is_some()
            || self.require_journal_v3(journal).is_err()
        {
            self.reentry.get_or_insert(JournalError::ProtectedBoundary);
            self.first.get_or_insert(First::Reentry);
            return Err(JournalError::ProtectedBoundary);
        }
        self.extent = Some(journal.held_session_receiving_extent_v1(&mut self.metadata));
        let Some(Ok(extent)) = self.extent.as_ref() else {
            self.first = Some(First::Extent);
            return Err(JournalError::ProtectedBoundary);
        };
        self.encoded = Some(
            match self.purpose {
                Purpose::Preparation26 => super::broker_session_receiving::delete_storage_preparation_append_encoded_bound_v3(
                    extent, request_bytes,
                ),
                Purpose::Apply7 => super::broker_session_receiving::delete_storage_apply_append_encoded_bound_v3(
                    extent, request_bytes,
                ),
                Purpose::Network9 => super::broker_session_receiving::delete_network_apply_append_encoded_bound_v4(
                    extent, request_bytes,
                ),
                Purpose::Mount62 => super::broker_session_receiving::delete_mount_reap_append_encoded_bound_v4(
                    extent, request_bytes,
                ),
            },
        );
        let Some(Ok(encoded)) = self.encoded.as_ref() else {
            self.first = Some(First::Encoded);
            return Err(JournalError::ProtectedBoundary);
        };
        self.future = Some((|| {
            let future = extent
                .native_bytes
                .checked_add(*encoded)
                .ok_or(JournalError::JournalTooLarge)?;
            super::protected_journal_preopen_replay_extent_for_prefix_v1(extent.limits, future)
        })());
        let Some(Ok(future)) = self.future.as_ref() else {
            self.first = Some(First::Future);
            return Err(JournalError::ProtectedBoundary);
        };
        self.geometry = Some((|| {
            let native_replay = future.dominant_native_receiving_demand_v1()?;
            let semantic_replay = future.dominant_semantic_receiving_demand_v1()?;
            let mut native = CapturedAppendOwnerV1::append_demand_for_fixed_v1(
                self.purpose.directory(),
                "session.journal",
                *encoded,
            )?
            .checked_add(native_replay)
            .and_then(|demand| demand.checked_add(semantic_replay))
            .map_err(JournalError::ReceivingAccounting)?;
            let bytes = DeleteSessionAppendWindowV1::construction_bytes_v1()
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or(JournalError::JournalTooLarge)?;
            native = native
                .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
                .map_err(JournalError::ReceivingAccounting)?;
            if !journal.has_captured_append_custody_v1() {
                native = native
                    .checked_add(
                        CapturedAppendOwnerV1::construction_demand_v1()
                            .ok_or(JournalError::JournalTooLarge)?,
                    )
                    .map_err(JournalError::ReceivingAccounting)?;
            }
            // The common request/outcome invoice pays the actual stored log
            // bytes and model replay. This term is the reached native sink,
            // transaction replay, names and retained helper custody only.
            Ok(native)
        })());
        match self.geometry.as_ref() {
            Some(Ok(demand)) => Ok(*demand),
            _ => {
                self.first = Some(First::Geometry);
                Err(JournalError::ProtectedBoundary)
            }
        }
    }

    pub(crate) fn install_prepaid_append_once_v3(
        &mut self,
        journal: &mut Journal,
    ) -> Result<(), JournalError> {
        if self.first.is_some()
            || !matches!(self.geometry, Some(Ok(_)))
            || self.require_journal_v3(journal).is_err()
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let encoded = self
            .encoded
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(JournalError::ProtectedBoundary)?;
        let result = self.window.install_prepaid_once_v2(
            journal,
            self.purpose.directory(),
            self.uid.ok_or(JournalError::ProtectedBoundary)?,
            encoded,
        );
        if result.is_err() {
            self.first.get_or_insert(First::Installation);
        }
        result
    }

    pub(crate) fn close_append_window_v3(&self) {
        self.window.close_if_owed_v2();
    }

    pub(crate) fn retire_prepaid_append_once_v3(
        &mut self,
        journal: &mut Journal,
    ) -> Result<(), JournalError> {
        if self.first.is_some() || self.require_journal_v3(journal).is_err() {
            return Err(JournalError::ProtectedBoundary);
        }
        match self.window.prepare_retirement_v2(journal) {
            Ok(disposal) => {
                disposal.complete_after_upper_disposal();
                Ok(())
            }
            Err(cause) => {
                self.first.get_or_insert(First::Retirement);
                Err(cause)
            }
        }
    }

    pub(crate) fn failure_v3(&self) -> Option<&(dyn Error + 'static)> {
        fn cause<T, E: Error + 'static>(
            slot: &Option<Result<T, E>>,
        ) -> Option<&(dyn Error + 'static)> {
            slot.as_ref()?.as_ref().err().map(|cause| cause as _)
        }
        match self.first? {
            First::Binding => cause(&self.recipe),
            First::Before => self.before.failure()
                .or_else(|| self.predecessor_witness.failure().map(|cause| cause as _))
                .or_else(|| cause(&self.predecessor_native))
                .or_else(|| cause(&self.before_result)),
            First::Association => cause(&self.association),
            First::Socket => cause(&self.socket_native).or_else(|| cause(&self.socket)),
            First::After => self.after.failure().or_else(|| cause(&self.after_result)),
            First::Extent => cause(&self.metadata).or_else(|| cause(&self.extent)),
            First::Encoded => cause(&self.encoded),
            First::Future => cause(&self.future),
            First::Geometry => cause(&self.geometry),
            First::Installation | First::Retirement => self.window.failure(),
            First::Reentry => self.reentry.as_ref().map(|cause| cause as _),
        }
    }
}


// The actual names-before sampler alone supplies the first argument. The second
// is comparison DATA from the genuine Root/Source/C17 loan, never a native grant.
fn require_inventory_native_boundary_v3(
    observed: Option<(u64, u64, u64, u64)>,
    expected: (u64, u64, u64, u64),
) -> Result<(), JournalError> {
    if observed == Some(expected) {
        Ok(())
    } else {
        Err(JournalError::StaleAuthoritySnapshot)
    }
}

fn require_preparation_native_boundary_v3(
    observed: Option<&[u8; 64]>,
    expected: &[u8; 64],
) -> Result<(), JournalError> {
    if observed == Some(expected) {
        Ok(())
    } else {
        Err(JournalError::StaleAuthoritySnapshot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preparation_boundary_requires_the_entire_actual_native_position() {
        let expected = [19; 64];
        assert!(require_preparation_native_boundary_v3(Some(&expected), &expected).is_ok());
        assert!(require_preparation_native_boundary_v3(None, &expected).is_err());

        for index in 0..expected.len() {
            let mut foreign = expected;
            foreign[index] ^= 1;
            assert!(require_preparation_native_boundary_v3(Some(&foreign), &expected).is_err());
        }
    }

    #[test]
    fn inventory_boundary_requires_every_actual_native_coordinate() {
        let expected = (11, 12, 13, 14);
        assert!(require_inventory_native_boundary_v3(Some(expected), expected).is_ok());
        assert!(require_inventory_native_boundary_v3(None, expected).is_err());
        for observed in [(10, 12, 13, 14), (11, 10, 13, 14),
            (11, 12, 10, 14), (11, 12, 13, 10)] {
            assert!(require_inventory_native_boundary_v3(Some(observed), expected).is_err());
        }
    }
}
