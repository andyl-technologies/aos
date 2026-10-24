//! Seals the two genuine native Session members behind one upper flight driver.

use super::*;

pub(super) enum Predecessor<'held> {
    Inventory {
        request: [u8; 32],
        outcome: [u8; 32],
        native: (u64, u64, u64, u64),
        protected: (u64, [u8; 32]),
    },
    Preparation(&'held DeleteStoragePreparationIoOriginalV3),
}

pub(super) enum CaptureData {
    Inventory { native: (u64, u64, u64, u64), protected: (u64, [u8; 32]) },
    Preparation([u8; 64]),
}

// Exactly these two actual native owners implement this private interface. It
// erases neither the completed26 borrow nor any native/protected-row checks.
pub(super) trait Native {
    const METHOD: aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod;
    fn capture_receiving_demand_v3() -> Result<ResourceVector, JournalError>;
    fn failure_v3(&self) -> Option<&(dyn Error + 'static)>;
    fn completed_native_v3(&self) -> Result<&[u8; 64], Closed>;
    fn retained_demand_v3(&self, turn: u64) -> Result<ResourceVector, Closed>;
    fn require_session_v3(&self, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1) -> Result<(), Closed>;
    fn require_journal_v3(&self, journal: &Journal) -> Result<(), Closed>;
    fn prepare_append_demand_v3(&mut self, journal: &Journal, bound: usize)
        -> Result<ResourceVector, JournalError>;
    fn install_prepaid_append_once_v3(&mut self, journal: &mut Journal) -> Result<(), JournalError>;
    fn close_append_window_v3(&self);
    fn retire_prepaid_append_once_v3(&mut self, journal: &mut Journal) -> Result<(), JournalError>;
    fn capture_v3(&mut self, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1, predecessor: &Predecessor<'_>,
        outcome: &AuthenticatedBrokerMethodOutcomeV1, data: CaptureData) -> Result<(), JournalError>;
}

macro_rules! native_methods {
    ($native:ty) => {
        fn capture_receiving_demand_v3() -> Result<ResourceVector, JournalError> {
            <$native>::capture_receiving_demand_v3()
        }

        fn failure_v3(&self) -> Option<&(dyn Error + 'static)> {
            <$native>::failure_v3(self)
        }

        fn completed_native_v3(&self) -> Result<&[u8; 64], Closed> {
            <$native>::completed_native_v3(self)
        }

        fn retained_demand_v3(&self, turn: u64) -> Result<ResourceVector, Closed> {
            <$native>::retained_demand_v3(self, turn)
        }

        fn require_session_v3(&self, journal: &Journal, socket: &SeqpacketSocket,
            transcript: &VerifiedBrokerSessionTranscriptV1) -> Result<(), Closed> {
            <$native>::require_session_v3(self, journal, socket, transcript)
        }

        fn require_journal_v3(&self, journal: &Journal) -> Result<(), Closed> {
            <$native>::require_journal_v3(self, journal)
        }

        fn prepare_append_demand_v3(&mut self, journal: &Journal, bound: usize)
            -> Result<ResourceVector, JournalError> {
            <$native>::prepare_append_demand_v3(self, journal, bound)
        }

        fn install_prepaid_append_once_v3(&mut self, journal: &mut Journal) -> Result<(), JournalError> {
            <$native>::install_prepaid_append_once_v3(self, journal)
        }

        fn close_append_window_v3(&self) {
            <$native>::close_append_window_v3(self)
        }

        fn retire_prepaid_append_once_v3(&mut self, journal: &mut Journal) -> Result<(), JournalError> {
            <$native>::retire_prepaid_append_once_v3(self, journal)
        }
    };
}

impl Native for DeleteStoragePreparationIoOriginalV3 {
    const METHOD: aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod =
        aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG;

    native_methods!(DeleteStoragePreparationIoOriginalV3);

    fn capture_v3(&mut self, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1, predecessor: &Predecessor<'_>,
        outcome: &AuthenticatedBrokerMethodOutcomeV1, data: CaptureData) -> Result<(), JournalError> {
        let actual = require_inventory_capture_v4(transcript, predecessor, outcome, data,
            aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES)?;
        self.capture_session_once_v3(journal, socket, transcript, actual)
            .map_err(|_| JournalError::ProtectedBoundary)
    }
}

fn require_inventory_capture_v4(
    transcript: &VerifiedBrokerSessionTranscriptV1, predecessor: &Predecessor<'_>,
    outcome: &AuthenticatedBrokerMethodOutcomeV1, data: CaptureData,
    method: aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod,
) -> Result<(u64, u64, u64, u64), JournalError> {
    use sha2::{Digest as _, Sha256};
    let (Predecessor::Inventory { request, outcome: expected, native, protected },
        CaptureData::Inventory { native: actual, protected: actual_protected }) = (predecessor, data)
    else { return Err(JournalError::ProtectedBoundary); };
    if outcome.method() != method
        || *request != <[u8; 32]>::from(Sha256::digest(outcome.request().canonical_packet()))
        || *expected != <[u8; 32]>::from(Sha256::digest(outcome.canonical_packet()))
        || *native != actual || *protected != actual_protected
        || outcome.request().session_binding() != transcript.session_binding() {
        return Err(JournalError::StaleAuthoritySnapshot);
    }
    Ok(actual)
}

impl Native for DeleteNetworkApplyIoOriginalV4 {
    const METHOD: aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod =
        aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_NETWORK_APPLY;

    native_methods!(DeleteNetworkApplyIoOriginalV4);

    fn capture_v3(&mut self, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1, predecessor: &Predecessor<'_>,
        outcome: &AuthenticatedBrokerMethodOutcomeV1, data: CaptureData) -> Result<(), JournalError> {
        let actual = require_inventory_capture_v4(transcript, predecessor, outcome, data,
            aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES)?;
        self.capture_session_once_v3(journal, socket, transcript, actual)
            .map_err(|_| JournalError::ProtectedBoundary)
    }
}

impl Native for DeleteMountReapIoOriginalV4 {
    const METHOD: aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod =
        aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_MOUNT_APPLY_ATTACHMENT_ANCHOR_V1;

    native_methods!(DeleteMountReapIoOriginalV4);

    fn capture_v3(&mut self, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1, predecessor: &Predecessor<'_>,
        outcome: &AuthenticatedBrokerMethodOutcomeV1, data: CaptureData) -> Result<(), JournalError> {
        let actual = require_inventory_capture_v4(transcript, predecessor, outcome, data,
            aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_DESTINATION_SLOTS)?;
        self.capture_session_once_v3(journal, socket, transcript, actual)
            .map_err(|_| JournalError::ProtectedBoundary)
    }
}

impl Native for DeleteStorageApplyIoOriginalV3 {
    const METHOD: aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod =
        aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_STORAGE_APPLY;

    native_methods!(DeleteStorageApplyIoOriginalV3);

    fn capture_v3(&mut self, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1, predecessor: &Predecessor<'_>,
        outcome: &AuthenticatedBrokerMethodOutcomeV1, data: CaptureData) -> Result<(), JournalError> {
        let (Predecessor::Preparation(preparation), CaptureData::Preparation(native)) = (predecessor, data)
        else { return Err(JournalError::ProtectedBoundary); };
        if preparation.completed_native_v3().map_err(|_| JournalError::ProtectedBoundary)? != &native {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        // The native owner itself joins every64 coordinate, exact actual26
        // request/outcome identity and the same live Journal/socket/transcript.
        self.capture_session_once_v3(journal, socket, transcript, preparation, outcome)
            .map_err(|_| JournalError::ProtectedBoundary)
    }
}
