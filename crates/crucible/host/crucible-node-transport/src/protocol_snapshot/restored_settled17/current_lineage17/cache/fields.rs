//! Owns only concrete signed lineage DTOs, never historical native capabilities.

use super::super::super::current_capture17_borrowed::{
    BorrowedCaptureRegistration17, BorrowedCurrentCapture17,
};
use super::*;
use crate::bodies::{BeginRequest, CaptureArguments, ObserveRequest};
use crate::reference_packet::service::{
    complete_restore::{
        activation::{upload::*, *},
        restoration_observe::*,
    },
    restored_settled_capture::{upload::*, *},
    restored_settled_confirmation::*,
};
use crucible_node_format::ActivationManifest;
use serde_json::Map;

pub(crate) struct BootLineage17Fields {
    pub(crate) host_registration: LineageSlot17<Value>,
    pub(crate) ack_original: LineageSlot17<Option<Envelope>>,
    pub(crate) ack_context: LineageSlot17<Option<CurrentDto17<PacketCanonicalAckAdmissionContext>>>,
    pub(crate) ack_proof: LineageSlot17<Option<CurrentDto17<PacketCanonicalAckAdmissionProof>>>,
    pub(crate) normalized_0: LineageSlot17<Option<Value>>,
    pub(crate) normalized_1: LineageSlot17<Option<Value>>,
    pub(crate) normalized_2: LineageSlot17<Option<Value>>,
    pub(crate) normalized_3: LineageSlot17<Option<Value>>,
}

impl Default for BootLineage17Fields {
    fn default() -> Self {
        Self {
            host_registration: Default::default(),
            ack_original: Default::default(),
            ack_context: Default::default(),
            ack_proof: Default::default(),
            normalized_0: Default::default(),
            normalized_1: Default::default(),
            normalized_2: Default::default(),
            normalized_3: Default::default(),
        }
    }
}

impl BootLineage17Fields {
    pub(super) fn preflight<'rows>(
        loan: &BorrowedCurrentBootLineage17<'_, 'rows>,
        ledger: &mut Ledger<'rows, '_, '_>,
    ) -> Result<(), ProviderError> {
        loan.data
            .host_registration
            .preflight_target17_data(ledger)?;
        loan.ack_original.preflight_target17_data(ledger)?;
        loan.ack_context.preflight_target17_data(ledger)?;
        loan.ack_proof.preflight_target17_data(ledger)?;
        loan.normalized[0].preflight_target17_data(ledger)?;
        loan.normalized[1].preflight_target17_data(ledger)?;
        loan.normalized[2].preflight_target17_data(ledger)?;
        loan.normalized[3].preflight_target17_data(ledger)?;
        Ok(())
    }

    pub(super) fn read<'rows>(
        &mut self,
        loan: &BorrowedCurrentBootLineage17<'_, 'rows>,
        ledger: &mut Ledger<'rows, '_, '_>,
    ) -> Result<(), ProviderError> {
        self.host_registration
            .read(&loan.data.host_registration, ledger)?;
        self.ack_original.read(&loan.ack_original, ledger)?;
        self.ack_context.read(&loan.ack_context, ledger)?;
        self.ack_proof.read(&loan.ack_proof, ledger)?;
        self.normalized_0.read(&loan.normalized[0], ledger)?;
        self.normalized_1.read(&loan.normalized[1], ledger)?;
        self.normalized_2.read(&loan.normalized[2], ledger)?;
        self.normalized_3.read(&loan.normalized[3], ledger)?;
        Ok(())
    }

    pub(super) fn observe(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        self.host_registration.observe(observer)?;
        self.ack_original.observe(observer)?;
        self.ack_context.observe(observer)?;
        self.ack_proof.observe(observer)?;
        self.normalized_0.observe(observer)?;
        self.normalized_1.observe(observer)?;
        self.normalized_2.observe(observer)?;
        self.normalized_3.observe(observer)?;
        Ok(())
    }
}

pub(crate) struct PrepareLineage17Fields {
    pub(crate) original: LineageSlot17<Option<Envelope>>,
    pub(crate) request: LineageSlot17<Option<CurrentDto17<PacketCompleteRestorePrepareRequest>>>,
    pub(crate) context: LineageSlot17<Option<CurrentDto17<PacketCompleteRestorePrepareContext>>>,
    pub(crate) proof: LineageSlot17<Option<CurrentDto17<PacketCompleteRestoreTransferProof>>>,
}

impl Default for PrepareLineage17Fields {
    fn default() -> Self {
        Self {
            original: Default::default(),
            request: Default::default(),
            context: Default::default(),
            proof: Default::default(),
        }
    }
}

impl PrepareLineage17Fields {
    pub(super) fn preflight<'rows>(
        loan: &BorrowedCurrentPrepareLineage17<'_, 'rows>,
        ledger: &mut Ledger<'rows, '_, '_>,
    ) -> Result<(), ProviderError> {
        loan.original.preflight_target17_data(ledger)?;
        loan.request.preflight_target17_data(ledger)?;
        loan.context.preflight_target17_data(ledger)?;
        loan.proof.preflight_target17_data(ledger)?;
        Ok(())
    }

    pub(super) fn read<'rows>(
        &mut self,
        loan: &BorrowedCurrentPrepareLineage17<'_, 'rows>,
        ledger: &mut Ledger<'rows, '_, '_>,
    ) -> Result<(), ProviderError> {
        self.original.read(&loan.original, ledger)?;
        self.request.read(&loan.request, ledger)?;
        self.context.read(&loan.context, ledger)?;
        self.proof.read(&loan.proof, ledger)?;
        Ok(())
    }

    pub(super) fn observe(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        self.original.observe(observer)?;
        self.request.observe(observer)?;
        self.context.observe(observer)?;
        self.proof.observe(observer)?;
        Ok(())
    }
}

pub(crate) struct CommitLineage17Fields {
    pub(crate) controller_pid: LineageSlot17<U64>,
    pub(crate) controller_uid: LineageSlot17<U64>,
    pub(crate) controller_executable: LineageSlot17<ContentRef>,

    pub(crate) original: LineageSlot17<Option<Envelope>>,
    pub(crate) request: LineageSlot17<Option<CurrentDto17<PacketCompleteRestoreCommitRequest>>>,
    pub(crate) context: LineageSlot17<Option<CurrentDto17<PacketCompleteRestoreCommitContext>>>,
    pub(crate) proof: LineageSlot17<Option<CurrentDto17<PacketCompleteRestoreTransferProof>>>,
    pub(crate) hold: LineageSlot17<Option<CurrentDto17<PacketNativeRestoredCommitHold>>>,
}

impl Default for CommitLineage17Fields {
    fn default() -> Self {
        Self {
            controller_pid: Default::default(),
            controller_uid: Default::default(),
            controller_executable: Default::default(),

            original: Default::default(),
            request: Default::default(),
            context: Default::default(),
            proof: Default::default(),
            hold: Default::default(),
        }
    }
}

impl CommitLineage17Fields {
    pub(super) fn preflight<'rows>(
        loan: &BorrowedCurrentCommitLineage17<'_, 'rows>,
        ledger: &mut Ledger<'rows, '_, '_>,
    ) -> Result<(), ProviderError> {
        let launch = loan.launch.as_ref().ok_or_else(invalid)?;
        launch.controller_pid.preflight_target17_data(ledger)?;
        launch.controller_uid.preflight_target17_data(ledger)?;
        launch
            .controller_executable
            .preflight_target17_data(ledger)?;
        loan.original.preflight_target17_data(ledger)?;
        loan.request.preflight_target17_data(ledger)?;
        loan.context.preflight_target17_data(ledger)?;
        loan.proof.preflight_target17_data(ledger)?;
        loan.gate_data.preflight_target17_data(ledger)?;
        Ok(())
    }

    pub(super) fn read<'rows>(
        &mut self,
        loan: &BorrowedCurrentCommitLineage17<'_, 'rows>,
        ledger: &mut Ledger<'rows, '_, '_>,
    ) -> Result<(), ProviderError> {
        let launch = loan.launch.as_ref().ok_or_else(invalid)?;
        self.controller_pid.read(&launch.controller_pid, ledger)?;
        self.controller_uid.read(&launch.controller_uid, ledger)?;
        self.controller_executable
            .read(&launch.controller_executable, ledger)?;
        self.original.read(&loan.original, ledger)?;
        self.request.read(&loan.request, ledger)?;
        self.context.read(&loan.context, ledger)?;
        self.proof.read(&loan.proof, ledger)?;
        self.hold.read(&loan.gate_data, ledger)?;
        Ok(())
    }

    pub(super) fn observe(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        self.controller_pid.observe(observer)?;
        self.controller_uid.observe(observer)?;
        self.controller_executable.observe(observer)?;
        self.original.observe(observer)?;
        self.request.observe(observer)?;
        self.context.observe(observer)?;
        self.proof.observe(observer)?;
        self.hold.observe(observer)?;
        Ok(())
    }
}

pub(crate) struct CaptureLineage17Fields {
    pub(crate) original: LineageSlot17<Option<Envelope>>,
    pub(crate) arguments: LineageSlot17<Option<CurrentDto17<CaptureArguments>>>,
    pub(crate) capture: LineageSlot17<Option<CurrentDto17<PacketRestoredSettledCaptureArtifact>>>,
    pub(crate) capture_context:
        LineageSlot17<Option<CurrentDto17<PacketRestoredSettledCaptureContext>>>,
    pub(crate) upload:
        LineageSlot17<Option<CurrentDto17<PacketRestoredSettledCaptureUploadArtifact>>>,
    pub(crate) upload_context:
        LineageSlot17<Option<CurrentDto17<PacketRestoredSettledCaptureUploadContext>>>,
    pub(crate) continuation:
        LineageSlot17<Option<CurrentDto17<PacketRestoredSettledCaptureUploadContinuation>>>,
    pub(crate) confirmation:
        LineageSlot17<Option<CurrentDto17<PacketRestoredSettledAfterConfirmationRequest>>>,
    pub(crate) terminal: LineageSlot17<Option<Envelope>>,
    pub(crate) prepared_reply: LineageSlot17<Option<Map<String, Value>>>,
    pub(crate) confirmation_receipt: LineageSlot17<Option<Value>>,
}

impl Default for CaptureLineage17Fields {
    fn default() -> Self {
        Self {
            original: Default::default(),
            arguments: Default::default(),
            capture: Default::default(),
            capture_context: Default::default(),
            upload: Default::default(),
            upload_context: Default::default(),
            continuation: Default::default(),
            confirmation: Default::default(),
            terminal: Default::default(),
            prepared_reply: Default::default(),
            confirmation_receipt: Default::default(),
        }
    }
}

impl CaptureLineage17Fields {
    pub(super) fn preflight<'rows>(
        loan: &BorrowedCurrentCapture17<'_, 'rows>,
        ledger: &mut Ledger<'rows, '_, '_>,
    ) -> Result<(), ProviderError> {
        loan.original.preflight_target17_data(ledger)?;
        loan.arguments.preflight_target17_data(ledger)?;
        loan.capture.preflight_target17_data(ledger)?;
        loan.capture_context.preflight_target17_data(ledger)?;
        loan.upload.preflight_target17_data(ledger)?;
        loan.upload_context.preflight_target17_data(ledger)?;
        loan.continuation.preflight_target17_data(ledger)?;
        loan.confirmation.preflight_target17_data(ledger)?;
        loan.terminal.preflight_target17_data(ledger)?;
        loan.prepared_reply.preflight_target17_data(ledger)?;
        loan.confirmation_receipt.preflight_target17_data(ledger)?;
        Ok(())
    }

    pub(super) fn read<'rows>(
        &mut self,
        loan: &BorrowedCurrentCapture17<'_, 'rows>,
        ledger: &mut Ledger<'rows, '_, '_>,
    ) -> Result<(), ProviderError> {
        self.original.read(&loan.original, ledger)?;
        self.arguments.read(&loan.arguments, ledger)?;
        self.capture.read(&loan.capture, ledger)?;
        self.capture_context.read(&loan.capture_context, ledger)?;
        self.upload.read(&loan.upload, ledger)?;
        self.upload_context.read(&loan.upload_context, ledger)?;
        self.continuation.read(&loan.continuation, ledger)?;
        self.confirmation.read(&loan.confirmation, ledger)?;
        self.terminal.read(&loan.terminal, ledger)?;
        self.prepared_reply.read(&loan.prepared_reply, ledger)?;
        self.confirmation_receipt
            .read(&loan.confirmation_receipt, ledger)?;
        Ok(())
    }

    pub(super) fn observe(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        self.original.observe(observer)?;
        self.arguments.observe(observer)?;
        self.capture.observe(observer)?;
        self.capture_context.observe(observer)?;
        self.upload.observe(observer)?;
        self.upload_context.observe(observer)?;
        self.continuation.observe(observer)?;
        self.confirmation.observe(observer)?;
        self.terminal.observe(observer)?;
        self.prepared_reply.observe(observer)?;
        self.confirmation_receipt.observe(observer)?;
        Ok(())
    }
}

pub(crate) struct RegistrationLineage17Fields {
    pub(crate) request: LineageSlot17<Envelope>,
    pub(crate) arguments: LineageSlot17<CurrentDto17<CaptureArguments>>,
    pub(crate) begin: LineageSlot17<CurrentDto17<BeginRequest>>,
}

impl Default for RegistrationLineage17Fields {
    fn default() -> Self {
        Self {
            request: Default::default(),
            arguments: Default::default(),
            begin: Default::default(),
        }
    }
}

impl RegistrationLineage17Fields {
    pub(super) fn preflight<'rows>(
        loan: &BorrowedCaptureRegistration17<'_, 'rows>,
        ledger: &mut Ledger<'rows, '_, '_>,
    ) -> Result<(), ProviderError> {
        loan.request.preflight_target17_data(ledger)?;
        loan.arguments.preflight_target17_data(ledger)?;
        loan.begin.preflight_target17_data(ledger)?;
        Ok(())
    }

    pub(super) fn read<'rows>(
        &mut self,
        loan: &BorrowedCaptureRegistration17<'_, 'rows>,
        ledger: &mut Ledger<'rows, '_, '_>,
    ) -> Result<(), ProviderError> {
        self.request.read(&loan.request, ledger)?;
        self.arguments.read(&loan.arguments, ledger)?;
        self.begin.read(&loan.begin, ledger)?;
        Ok(())
    }

    pub(super) fn observe(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        self.request.observe(observer)?;
        self.arguments.observe(observer)?;
        self.begin.observe(observer)?;
        Ok(())
    }
}
