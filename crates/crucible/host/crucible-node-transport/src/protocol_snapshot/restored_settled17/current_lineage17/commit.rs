//! Borrows signed Commit lineage without owning the old installation capsule.

use super::super::{current_commit::CurrentPrepared17, current_pending::CurrentPendingControl17};
use super::*;
use crate::connection::settled17::{HistoricalReversedByteBank17, read_byte_bank_parts17};

pub(super) fn read_shared<'body, 'rows>(
    input: &'body [u8],
    ledger: &mut Ledger<'rows, '_, '_>,
) -> Result<BorrowedCurrentCommitLineage17<'body, 'rows>, ProviderError> {
    let start = ledger.rows.encoded_position();
    let layout = NativeAckBoot::current_commit_shared_layout17_data();
    shared_row17(ledger, layout)?;
    let group = ledger.shared_begin(MetadataSharedKind::NativeRestoreCommitAttempt)?;
    let mut fields = Fields::object(input)?;
    role(
        fields.named("schema")?,
        "source-private.native-current-restore-commit/17",
    )?;
    discard::<u32>(fields.named("creator")?, ledger)?;
    role(
        fields.named("thread_role")?,
        "same-original-native-thread-history-only",
    )?;
    let original = loan(fields.named("original")?, ledger)?;
    let launch = super::controller::read(fields.named("launch")?, ledger)?;
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
    discard::<Option<Value>>(fields.named("host_authority")?, ledger)?;
    discard::<Option<Value>>(fields.named("kernel_binding")?, ledger)?;
    discard::<Option<Value>>(fields.named("policy_binding")?, ledger)?;
    let request = loan(fields.named("request")?, ledger)?;
    let proof = loan(fields.named("proof")?, ledger)?;
    let context = loan(fields.named("context")?, ledger)?;
    discard::<Option<Envelope>>(fields.named("capture_request")?, ledger)?;
    discard::<Option<CurrentPendingControl17>>(fields.named("pending_control")?, ledger)?;
    discard::<Option<CurrentPrepared17>>(fields.named("prepared_model")?, ledger)?;
    let hold = fields.named("physical_hold_role")?;
    let hold_group = if hold == b"null" {
        None
    } else {
        role(hold, "native-complete-restore-physical-hold")?;
        Some(read_reference17(
            ledger,
            MetadataSharedKind::NativeRestoredPhysicalHold,
            (
                size_of::<PacketCompleteRestorePhysicalHold>(),
                align_of::<PacketCompleteRestorePhysicalHold>(),
            ),
        )?)
    };
    let evidence = fields.named("gate_evidence")?;
    if evidence != b"null" {
        let mut evidence = Fields::array(evidence)?;
        discard::<ContentRef>(evidence.next()?.ok_or_else(invalid)?, ledger)?;
        let body = evidence.next()?.ok_or_else(invalid)?;
        let capacity = usize::try_from(unsigned(evidence.next()?.ok_or_else(invalid)?)?)
            .map_err(|_| invalid())?;
        evidence.finish()?;
        if read_byte_bank_parts17(body, capacity, ledger, false)?.is_some() {
            return Err(invalid());
        }
    }
    let gate_data = loan(fields.named("gate_data")?, ledger)?;
    let receipt_body = loan::<HistoricalReversedByteBank17>(fields.named("receipt_body")?, ledger)?;
    discard::<Option<CurrentDto17<crate::bodies::PrepareRestoreResult>>>(
        fields.named("receipt_result")?,
        ledger,
    )?;
    let receipt_started = scalar(fields.named("receipt_started")?, ledger)?;
    let completed_response = loan(fields.named("completed_response")?, ledger)?;
    discard::<HistoricalReversedByteBank17>(fields.named("response_body")?, ledger)?;
    discard::<usize>(fields.named("requested_model_bytes")?, ledger)?;
    let verified = scalar(fields.named("verified")?, ledger)?;
    let installation_started = scalar(fields.named("installation_started")?, ledger)?;
    fields.finish()?;
    let rows = ledger.rows.encoded_between(start)?;
    ledger.shared_finish(group, layout.0, input, rows)?;
    Ok(BorrowedCurrentCommitLineage17 {
        definition: input,
        group,
        mapping_group,
        hold_group,
        launch,
        original,
        request,
        proof,
        context,
        gate_data,
        receipt_body,
        completed_response,
        verified,
        installation_started,
        receipt_started,
    })
}
