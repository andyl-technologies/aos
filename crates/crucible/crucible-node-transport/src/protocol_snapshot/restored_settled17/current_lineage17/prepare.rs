//! Borrows only needed Prepare lineage while validating every retained field.

use super::super::current_custody::HistoricalRestoreInputCustody17;
use super::*;
use crate::connection::{
    OriginalCompleteRestoreInputCustody, settled17::HistoricalReversedByteBank17,
};

pub(super) fn read_shared<'body, 'rows>(
    input: &'body [u8],
    ledger: &mut Ledger<'rows, '_, '_>,
    boot_group: usize,
) -> Result<BorrowedCurrentPrepareLineage17<'body, 'rows>, ProviderError> {
    let start = ledger.rows.encoded_position();
    let layout = NativeAckBoot::current_prepare_shared_layout17_data();
    shared_row17(ledger, layout)?;
    let group = ledger.shared_begin(MetadataSharedKind::NativeRestorePrepareAttempt)?;
    let mut fields = Fields::object(input)?;
    role(
        fields.named("schema")?,
        "source-private.native-current-restore-prepare/17",
    )?;
    discard::<u32>(fields.named("creator")?, ledger)?;
    role(
        fields.named("thread_role")?,
        "same-original-native-thread-history-only",
    )?;
    let original = loan(fields.named("original")?, ledger)?;
    let service_quote = fields.named("service_quote")?;
    if service_quote != b"null"
        && CurrentServiceQuote17::read_with_native_parent_data(
            service_quote,
            ledger,
            false,
            boot_group,
        )?
        .is_some()
    {
        return Err(invalid());
    }
    discard::<Option<CurrentControlQuote17>>(fields.named("control_quote")?, ledger)?;
    discard::<Option<crate::bodies::RealizeRequest>>(fields.named("realize")?, ledger)?;
    let receipt_started = scalar(fields.named("receipt_started")?, ledger)?;
    let input_segment_issued = scalar(fields.named("input_segment_issued")?, ledger)?;
    let input_segment_started = scalar(fields.named("input_segment_started")?, ledger)?;
    discard::<Option<CurrentDto17<crate::bodies::PrepareRestoreResult>>>(
        fields.named("receipt_result")?,
        ledger,
    )?;
    let receipt_body = loan::<HistoricalReversedByteBank17>(fields.named("receipt_body")?, ledger)?;
    let request = loan(fields.named("request")?, ledger)?;
    let proof = loan(fields.named("proof")?, ledger)?;
    let context = loan(fields.named("context")?, ledger)?;
    discard::<HistoricalReversedByteBank17>(fields.named("context_body")?, ledger)?;
    discard::<Option<Value>>(fields.named("kernel")?, ledger)?;
    discard::<Option<Value>>(fields.named("policy")?, ledger)?;
    discard::<Option<Bytes>>(fields.named("transfer_token")?, ledger)?;
    let custody = fields.named("custody")?;
    let custody_group = if custody == b"null" {
        None
    } else {
        let start = ledger.rows.encoded_position();
        let layout = (
            size_of::<RefCell<OriginalCompleteRestoreInputCustody>>(),
            align_of::<RefCell<OriginalCompleteRestoreInputCustody>>(),
        );
        shared_row17(ledger, layout)?;
        let group = ledger.shared_begin(MetadataSharedKind::NativeRestoreInputCustody)?;
        discard::<HistoricalRestoreInputCustody17>(custody, ledger)?;
        let rows = ledger.rows.encoded_between(start)?;
        ledger.shared_finish(group, layout.0, custody, rows)?;
        Some(group)
    };
    discard::<bool>(fields.named("reactive")?, ledger)?;
    let verified = scalar(fields.named("verified")?, ledger)?;
    role(
        fields.named("owner_role")?,
        "native-complete-restore-prepare",
    )?;
    fields.finish()?;
    let rows = ledger.rows.encoded_between(start)?;
    ledger.shared_finish(group, layout.0, input, rows)?;
    Ok(BorrowedCurrentPrepareLineage17 {
        definition: input,
        group,
        original,
        request,
        proof,
        context,
        receipt_body,
        custody_group,
        verified,
        receipt_started,
        input_segment_issued,
        input_segment_started,
    })
}
