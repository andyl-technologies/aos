//! Reads the entire current Commit owner and all retained failed partials.

use super::{
    current_contracts::*,
    current_launch::CurrentLaunch17,
    current_pending::CurrentPendingControl17,
    current_shared::{CurrentShared17, read_reference17, read_shared17},
};
use crate::ProviderError;
use crate::connection::settled17::{HistoricalReversedByteBank17, read_byte_bank_parts17};
use crate::envelope::Envelope;
use crate::protocol_snapshot::{
    PreparedArchivedNativeProtocolMapping,
    owned11::typed::{Fields, HistoricalType, Ledger, invalid, plain_string, unsigned},
};
use crate::reference_packet::continuation_models::settled_reader::prepared::{
    CurrentPreparedModel17Data, read_current_prepared_model17_data,
};
use crate::reference_packet::control::{
    PacketCompleteRestorePhysicalHold, PacketSettledControlRecord17Data,
};
use crate::reference_packet::service::{
    ack_emitter::NativeAckBoot,
    complete_restore::{transfer::*, *},
};
use crate::retained_metadata::aliases::MetadataSharedKind;
use crucible_node_contract::ContentRef;
use serde_json::Value;
use std::{
    cell::RefCell,
    mem::{align_of, size_of},
};

pub(crate) struct CurrentPrepared17(
    pub(crate) CurrentPreparedModel17Data<PacketSettledControlRecord17Data>,
);
impl HistoricalType for CurrentPrepared17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        read_current_prepared_model17_data::<PacketSettledControlRecord17Data>(input, ledger, build)
            .map(|value| value.map(Self))
    }
}

pub(crate) struct CurrentCommit17 {
    pub(crate) creator: u32,
    pub(crate) original: Option<Envelope>,
    pub(crate) launch: Option<CurrentLaunch17>,
    pub(crate) mapping_group: usize,
    pub(crate) host_authority: Option<Value>,
    pub(crate) kernel_binding: Option<Value>,
    pub(crate) policy_binding: Option<Value>,
    pub(crate) request: Option<PacketCompleteRestoreCommitRequest>,
    pub(crate) proof: Option<PacketCompleteRestoreTransferProof>,
    pub(crate) context: Option<PacketCompleteRestoreCommitContext>,
    pub(crate) capture_request: Option<Envelope>,
    pub(crate) pending_control: Option<CurrentPendingControl17>,
    pub(crate) prepared_model: Option<CurrentPrepared17>,
    pub(crate) physical_hold_group: Option<usize>,
    pub(crate) gate_evidence: Option<(ContentRef, Vec<u8>)>,
    pub(crate) gate_data: Option<PacketNativeRestoredCommitHold>,
    pub(crate) receipt_body: Vec<u8>,
    pub(crate) receipt_result: Option<crate::bodies::PrepareRestoreResult>,
    pub(crate) receipt_started: bool,
    pub(crate) completed_response: Option<ContentRef>,
    pub(crate) response_body: Vec<u8>,
    pub(crate) requested_model_bytes: usize,
    pub(crate) verified: bool,
    pub(crate) installation_started: bool,
}
impl CurrentCommit17 {
    pub(crate) fn read_shared_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<CurrentShared17<Self>>, ProviderError> {
        read_shared17::<Self>(
            input,
            ledger,
            build,
            MetadataSharedKind::NativeRestoreCommitAttempt,
            NativeAckBoot::current_commit_shared_layout17_data(),
        )
    }
}
impl HistoricalType for CurrentCommit17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        role(
            fields.named("schema")?,
            "source-private.native-current-restore-commit/17",
        )?;
        let creator =
            <Plain17<u32> as CurrentField17>::read(fields.named("creator")?, ledger, build)?;
        role(
            fields.named("thread_role")?,
            "same-original-native-thread-history-only",
        )?;
        let original = <Plain17<Option<Envelope>> as CurrentField17>::read(
            fields.named("original")?,
            ledger,
            build,
        )?;
        let launch = ledger.read::<Option<CurrentLaunch17>>(fields.named("launch")?, build)?;
        role(
            fields.named("mapping_role")?,
            "native-archived-protocol-mapping",
        )?;
        let mapping_group = read_reference17(
            ledger,
            MetadataSharedKind::ArchivedMapping,
            (
                size_of::<RefCell<PreparedArchivedNativeProtocolMapping>>(),
                align_of::<RefCell<PreparedArchivedNativeProtocolMapping>>(),
            ),
        )?;
        let host_authority = <Plain17<Option<Value>> as CurrentField17>::read(
            fields.named("host_authority")?,
            ledger,
            build,
        )?;
        let kernel_binding = <Plain17<Option<Value>> as CurrentField17>::read(
            fields.named("kernel_binding")?,
            ledger,
            build,
        )?;
        let policy_binding = <Plain17<Option<Value>> as CurrentField17>::read(
            fields.named("policy_binding")?,
            ledger,
            build,
        )?;
        let request =
            <Optional17<CurrentDto17<PacketCompleteRestoreCommitRequest>> as CurrentField17>::read(
                fields.named("request")?,
                ledger,
                build,
            )?;
        let proof =
            <Optional17<CurrentDto17<PacketCompleteRestoreTransferProof>> as CurrentField17>::read(
                fields.named("proof")?,
                ledger,
                build,
            )?;
        let context =
            <Optional17<CurrentDto17<PacketCompleteRestoreCommitContext>> as CurrentField17>::read(
                fields.named("context")?,
                ledger,
                build,
            )?;
        let capture_request = <Plain17<Option<Envelope>> as CurrentField17>::read(
            fields.named("capture_request")?,
            ledger,
            build,
        )?;
        let pending_control = ledger
            .read::<Option<CurrentPendingControl17>>(fields.named("pending_control")?, build)?;
        let prepared_model =
            ledger.read::<Option<CurrentPrepared17>>(fields.named("prepared_model")?, build)?;
        let raw = fields.named("physical_hold_role")?;
        let physical_hold_group = if raw == b"null" {
            None
        } else {
            role(raw, "native-complete-restore-physical-hold")?;
            Some(read_reference17(
                ledger,
                MetadataSharedKind::NativeRestoredPhysicalHold,
                (
                    size_of::<PacketCompleteRestorePhysicalHold>(),
                    align_of::<PacketCompleteRestorePhysicalHold>(),
                ),
            )?)
        };
        let gate_evidence = read_gate_evidence17(fields.named("gate_evidence")?, ledger, build)?;
        let gate_data =
            <Optional17<CurrentDto17<PacketNativeRestoredCommitHold>> as CurrentField17>::read(
                fields.named("gate_data")?,
                ledger,
                build,
            )?;
        let receipt_body = ledger
            .read::<HistoricalReversedByteBank17>(fields.named("receipt_body")?, build)?
            .map(|bank| bank.0);
        let receipt_result = <Optional17<CurrentDto17<crate::bodies::PrepareRestoreResult>> as CurrentField17>::read(fields.named("receipt_result")?, ledger, build)?;
        let receipt_started = <Plain17<bool> as CurrentField17>::read(
            fields.named("receipt_started")?,
            ledger,
            build,
        )?;
        let completed_response = <Plain17<Option<ContentRef>> as CurrentField17>::read(
            fields.named("completed_response")?,
            ledger,
            build,
        )?;
        let response_body = ledger
            .read::<HistoricalReversedByteBank17>(fields.named("response_body")?, build)?
            .map(|bank| bank.0);
        let requested_model_bytes = <Plain17<usize> as CurrentField17>::read(
            fields.named("requested_model_bytes")?,
            ledger,
            build,
        )?;
        let verified =
            <Plain17<bool> as CurrentField17>::read(fields.named("verified")?, ledger, build)?;
        let installation_started = <Plain17<bool> as CurrentField17>::read(
            fields.named("installation_started")?,
            ledger,
            build,
        )?;
        fields.finish()?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            creator: creator.ok_or_else(invalid)?,
            original: original.ok_or_else(invalid)?,
            launch: launch.ok_or_else(invalid)?,
            mapping_group,
            host_authority: host_authority.ok_or_else(invalid)?,
            kernel_binding: kernel_binding.ok_or_else(invalid)?,
            policy_binding: policy_binding.ok_or_else(invalid)?,
            request: request.ok_or_else(invalid)?,
            proof: proof.ok_or_else(invalid)?,
            context: context.ok_or_else(invalid)?,
            capture_request: capture_request.ok_or_else(invalid)?,
            pending_control: pending_control.ok_or_else(invalid)?,
            prepared_model: prepared_model.ok_or_else(invalid)?,
            physical_hold_group,
            gate_evidence: gate_evidence.ok_or_else(invalid)?,
            gate_data: gate_data.ok_or_else(invalid)?,
            receipt_body: receipt_body.ok_or_else(invalid)?,
            receipt_result: receipt_result.ok_or_else(invalid)?,
            receipt_started: receipt_started.ok_or_else(invalid)?,
            completed_response: completed_response.ok_or_else(invalid)?,
            response_body: response_body.ok_or_else(invalid)?,
            requested_model_bytes: requested_model_bytes.ok_or_else(invalid)?,
            verified: verified.ok_or_else(invalid)?,
            installation_started: installation_started.ok_or_else(invalid)?,
        }))
    }
}
fn role(input: &[u8], expected: &str) -> Result<(), ProviderError> {
    if plain_string(input)? != expected {
        return Err(invalid());
    }
    Ok(())
}
fn read_gate_evidence17(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<Option<Option<(ContentRef, Vec<u8>)>>, ProviderError> {
    if input == b"null" {
        return Ok(build.then_some(None));
    }
    let mut fields = Fields::array(input)?;
    let reference = ledger.read::<ContentRef>(fields.next()?.ok_or_else(invalid)?, build)?;
    let raw = fields.next()?.ok_or_else(invalid)?;
    let capacity =
        usize::try_from(unsigned(fields.next()?.ok_or_else(invalid)?)?).map_err(|_| invalid())?;
    fields.finish()?;
    let body = read_byte_bank_parts17(raw, capacity, ledger, build)?;
    if !build {
        return Ok(None);
    }
    Ok(Some(Some((
        reference.ok_or_else(invalid)?,
        body.ok_or_else(invalid)?,
    ))))
}
