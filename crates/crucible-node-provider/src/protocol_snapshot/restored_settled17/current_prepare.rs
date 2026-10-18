//! Retains complete actual current Prepare fields without reconstructing custody.

use super::current_contracts::*;
use super::current_custody::HistoricalRestoreInputCustody17;
use super::current_quotes::{CurrentControlQuote17, CurrentServiceQuote17};
use super::current_shared::{CurrentShared17, read_shared17, shared_row17};
use crate::ProviderError;
use crate::connection::{
    OriginalCompleteRestoreInputCustody, settled17::HistoricalReversedByteBank17,
};
use crate::envelope::Envelope;
use crate::protocol_snapshot::owned11::typed::{
    Fields, HistoricalType, Ledger, invalid, plain_string,
};
use crate::reference_packet::service::ack_emitter::NativeAckBoot;
use crate::reference_packet::service::complete_restore::transfer::*;
use crate::retained_metadata::aliases::MetadataSharedKind;
use crucible_node_contract::Bytes;
use serde_json::Value;
use std::{
    cell::RefCell,
    mem::{align_of, size_of},
};

pub(crate) struct CurrentPrepare17 {
    pub(crate) creator: u32,
    pub(crate) original: Option<Envelope>,
    pub(crate) service_quote: Option<CurrentServiceQuote17>,
    pub(crate) control_quote: Option<CurrentControlQuote17>,
    pub(crate) realize: Option<crate::bodies::RealizeRequest>,
    pub(crate) receipt_started: bool,
    pub(crate) input_segment_issued: bool,
    pub(crate) input_segment_started: bool,
    pub(crate) receipt_result: Option<crate::bodies::PrepareRestoreResult>,
    pub(crate) receipt_body: Vec<u8>,
    pub(crate) request: Option<PacketCompleteRestorePrepareRequest>,
    pub(crate) proof: Option<PacketCompleteRestoreTransferProof>,
    pub(crate) context: Option<PacketCompleteRestorePrepareContext>,
    pub(crate) context_body: Vec<u8>,
    pub(crate) kernel: Option<Value>,
    pub(crate) policy: Option<Value>,
    pub(crate) transfer_token: Option<Bytes>,
    pub(crate) custody: Option<CurrentShared17<HistoricalRestoreInputCustody17>>,
    pub(crate) reactive: bool,
    pub(crate) verified: bool,
}

impl CurrentPrepare17 {
    pub(crate) fn read_shared_with_native_parent_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
        expected_boot_group: usize,
    ) -> Result<Option<CurrentShared17<Self>>, ProviderError> {
        let start = ledger.rows.encoded_position();
        let layout = NativeAckBoot::current_prepare_shared_layout17_data();
        shared_row17(ledger, layout)?;
        let group = ledger.shared_begin(MetadataSharedKind::NativeRestorePrepareAttempt)?;
        let payload =
            Self::read_with_native_parent_data(input, ledger, build, expected_boot_group)?;
        let rows = ledger.rows.encoded_between(start)?;
        ledger.shared_finish(group, layout.0, input, rows)?;
        Ok(payload.map(|payload| CurrentShared17 { group, payload }))
    }

    fn read_with_native_parent_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
        expected_boot_group: usize,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        role(
            fields.named("schema")?,
            "source-private.native-current-restore-prepare/17",
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
        let raw = fields.named("service_quote")?;
        let service_quote = if raw == b"null" {
            Some(None)
        } else {
            CurrentServiceQuote17::read_with_native_parent_data(
                raw,
                ledger,
                build,
                expected_boot_group,
            )?
            .map(Some)
        };
        let control_quote =
            ledger.read::<Option<CurrentControlQuote17>>(fields.named("control_quote")?, build)?;
        let realize = <Plain17<Option<crate::bodies::RealizeRequest>> as CurrentField17>::read(
            fields.named("realize")?,
            ledger,
            build,
        )?;
        let receipt_started = <Plain17<bool> as CurrentField17>::read(
            fields.named("receipt_started")?,
            ledger,
            build,
        )?;
        let input_segment_issued = <Plain17<bool> as CurrentField17>::read(
            fields.named("input_segment_issued")?,
            ledger,
            build,
        )?;
        let input_segment_started = <Plain17<bool> as CurrentField17>::read(
            fields.named("input_segment_started")?,
            ledger,
            build,
        )?;
        let receipt_result = <Optional17<CurrentDto17<crate::bodies::PrepareRestoreResult>> as CurrentField17>::read(fields.named("receipt_result")?, ledger, build)?;
        let receipt_body = ledger
            .read::<HistoricalReversedByteBank17>(fields.named("receipt_body")?, build)?
            .map(|bank| bank.0);
        let request = <Optional17<CurrentDto17<PacketCompleteRestorePrepareRequest>> as CurrentField17>::read(fields.named("request")?, ledger, build)?;
        let proof =
            <Optional17<CurrentDto17<PacketCompleteRestoreTransferProof>> as CurrentField17>::read(
                fields.named("proof")?,
                ledger,
                build,
            )?;
        let context = <Optional17<CurrentDto17<PacketCompleteRestorePrepareContext>> as CurrentField17>::read(fields.named("context")?, ledger, build)?;
        let context_body = ledger
            .read::<HistoricalReversedByteBank17>(fields.named("context_body")?, build)?
            .map(|bank| bank.0);
        let kernel = <Plain17<Option<Value>> as CurrentField17>::read(
            fields.named("kernel")?,
            ledger,
            build,
        )?;
        let policy = <Plain17<Option<Value>> as CurrentField17>::read(
            fields.named("policy")?,
            ledger,
            build,
        )?;
        let transfer_token = <Plain17<Option<Bytes>> as CurrentField17>::read(
            fields.named("transfer_token")?,
            ledger,
            build,
        )?;
        let raw = fields.named("custody")?;
        let custody = if raw == b"null" {
            Some(None)
        } else {
            read_shared17::<HistoricalRestoreInputCustody17>(
                raw,
                ledger,
                build,
                MetadataSharedKind::NativeRestoreInputCustody,
                (
                    size_of::<RefCell<OriginalCompleteRestoreInputCustody>>(),
                    align_of::<RefCell<OriginalCompleteRestoreInputCustody>>(),
                ),
            )?
            .map(Some)
        };
        let reactive =
            <Plain17<bool> as CurrentField17>::read(fields.named("reactive")?, ledger, build)?;
        let verified =
            <Plain17<bool> as CurrentField17>::read(fields.named("verified")?, ledger, build)?;
        role(
            fields.named("owner_role")?,
            "native-complete-restore-prepare",
        )?;
        fields.finish()?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            creator: creator.ok_or_else(invalid)?,
            original: original.ok_or_else(invalid)?,
            service_quote: service_quote.ok_or_else(invalid)?,
            control_quote: control_quote.ok_or_else(invalid)?,
            realize: realize.ok_or_else(invalid)?,
            receipt_started: receipt_started.ok_or_else(invalid)?,
            input_segment_issued: input_segment_issued.ok_or_else(invalid)?,
            input_segment_started: input_segment_started.ok_or_else(invalid)?,
            receipt_result: receipt_result.ok_or_else(invalid)?,
            receipt_body: receipt_body.ok_or_else(invalid)?,
            request: request.ok_or_else(invalid)?,
            proof: proof.ok_or_else(invalid)?,
            context: context.ok_or_else(invalid)?,
            context_body: context_body.ok_or_else(invalid)?,
            kernel: kernel.ok_or_else(invalid)?,
            policy: policy.ok_or_else(invalid)?,
            transfer_token: transfer_token.ok_or_else(invalid)?,
            custody: custody.ok_or_else(invalid)?,
            reactive: reactive.ok_or_else(invalid)?,
            verified: verified.ok_or_else(invalid)?,
        }))
    }
}

fn role(input: &[u8], expected: &str) -> Result<(), ProviderError> {
    if plain_string(input)? != expected {
        return Err(invalid());
    }
    Ok(())
}

impl CurrentPrepare17 {
    /// Returns the exact full custody group without creating an installed token.
    pub(crate) fn custody_group_data(&self) -> Option<usize> {
        self.custody.as_ref().map(|custody| custody.group)
    }
}
