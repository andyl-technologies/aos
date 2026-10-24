//! Retains native receiver and contextual operation-pin typed partials.
//!
//! Pin JSON omits its receiver ledger payload. Its parser therefore requires the
//! enclosing receiver's concrete full view and validates that repeated source
//! traversal without allocating a second target ledger for the pin handle.

use super::*;
use crate::protocol_snapshot::owned11::native::blob::{
    HistoricalNativeBlobLedger,
    native17_retained::{NativeBlobKey17ReadAttempt, NativeBlobLedger17ReadAttempt},
};
use crate::protocol_snapshot::owned11::typed::Native17Build;
use crate::retained_metadata::MetadataObserver;

/// Keeps a complete or partial ledger through full-view alias conjunction.
#[derive(Default)]
pub(crate) struct NativeBlobGroup17ReadAttempt {
    started: bool,
    completed: Option<HistoricalNativeBlobLedger>,
    leaf: NativeBlobLedger17ReadAttempt,
    group: Option<usize>,
    payload: usize,
}

/// Reads the full Blob group without a local output that can be lost on error.
///
/// # Errors
/// Refuses the source layout, complete leaf grammar, target storage or aliases.
pub(crate) fn read_native17_blob_group_into_data(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    attempt: &mut NativeBlobGroup17ReadAttempt,
) -> Result<(Option<usize>, usize), ProviderError> {
    if attempt.started {
        return Err(ProviderError::Conflict(
            "native17 Blob group already attempted",
        ));
    }
    attempt.started = true;
    if input == b"null" {
        return Ok((None, 0));
    }
    let (start, layout, group) = begin_group(ledger)?;
    attempt.group = Some(group);
    HistoricalNativeBlobLedger::read_into_data(input, ledger, &mut attempt.leaf)?;
    attempt.payload = attempt.leaf.historical_payload_bytes_data();
    let rows = ledger.rows.encoded_between(start)?;
    ledger.shared_finish(group, layout, input, rows)?;
    attempt.completed =
        Some(HistoricalNativeBlobLedger::take_output_data(&mut attempt.leaf).ok_or_else(invalid)?);
    Ok((Some(group), attempt.payload))
}

/// Preflights the same full group and returns its checked ordinal and map census.
///
/// # Errors
/// Refuses malformed fields, source layouts, target demand or incomplete aliases.
pub(crate) fn preflight_native17_blob_group_fields_data(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
) -> Result<(Option<usize>, usize), ProviderError> {
    if input == b"null" {
        return Ok((None, 0));
    }
    let (start, layout, group) = begin_group(ledger)?;
    let payload = HistoricalNativeBlobLedger::preflight_native17_fields_data(input, ledger)?;
    let rows = ledger.rows.encoded_between(start)?;
    ledger.shared_finish(group, layout, input, rows)?;
    Ok((Some(group), payload))
}

impl NativeBlobGroup17ReadAttempt {
    pub(crate) fn completed_data(&self) -> Option<&HistoricalNativeBlobLedger> {
        self.completed.as_ref()
    }
    pub(crate) fn take_completed_data(&mut self) -> Option<HistoricalNativeBlobLedger> {
        self.completed.take()
    }
    pub(crate) fn observe_attempt_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        if let Some(value) = &self.completed {
            HistoricalNativeBlobLedger::observe_output_data(value, observer)?;
        }
        HistoricalNativeBlobLedger::observe_attempt_data(&self.leaf, observer)
    }
}

fn begin_group(ledger: &mut Ledger<'_, '_, '_>) -> Result<(usize, usize, usize), ProviderError> {
    let start = ledger.rows.encoded_position();
    let layout = crate::blob::original_blob_layouts().state;
    let (alignment, _, _) = crate::blob::original_blob_alignment17_data();
    if ledger.row_aligned(MetadataRecordKind::Shared, 1, alignment)? != layout {
        return Err(invalid());
    }
    let group = ledger.shared_begin(MetadataSharedKind::BlobLedger)?;
    Ok((start, layout, group))
}

/// Keeps receiver identifiers, full ledger partials and its eventual real Rc.
#[derive(Default)]
pub(crate) struct CurrentNativeBlobReceiver17ReadAttempt {
    started: bool,
    completed: Option<HistoricalNativeBlobReceiver17>,
    session: Option<Id>,
    session_attempt: <Id as Native17Build>::Attempt,
    incarnation: Option<Id>,
    incarnation_attempt: <Id as Native17Build>::Attempt,
    state: NativeBlobGroup17ReadAttempt,
}

impl HistoricalType for HistoricalNativeBlobReceiver17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        read_native17_blob_receiver_data(input, ledger, build).map(|result| result.0)
    }
}

/// Reads a native receiver into the supplied permanent outer owner.
///
/// # Errors
/// Refuses malformed fields, shared roots, target storage or alias conjunction.
pub(crate) fn read_native17_blob_receiver_into_data(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    attempt: &mut CurrentNativeBlobReceiver17ReadAttempt,
) -> Result<NativeBlobReceiver17GroupIds, ProviderError> {
    if attempt.started {
        return Err(ProviderError::Conflict(
            "native17 receiver already attempted",
        ));
    }
    attempt.started = true;
    let mut fields = Fields::array(input)?;
    exact(next(&mut fields)?, "source-private.native-blob-receiver/11")?;
    owned::<Id>(
        next(&mut fields)?,
        ledger,
        &mut attempt.session_attempt,
        &mut attempt.session,
    )?;
    owned::<Id>(
        next(&mut fields)?,
        ledger,
        &mut attempt.incarnation_attempt,
        &mut attempt.incarnation,
    )?;
    let limits = read_limits(next(&mut fields)?, ledger)?;
    let (group, payload) =
        read_native17_blob_group_into_data(next(&mut fields)?, ledger, &mut attempt.state)?;
    let ledger_group = group.ok_or_else(invalid)?;
    let supervisor = read_supervisor(next(&mut fields)?, ledger)?;
    fields.finish()?;
    if attempt.session.is_none()
        || attempt.incarnation.is_none()
        || attempt.state.completed_data().is_none()
    {
        return Err(invalid());
    }
    ledger.native17_target_shared_data::<HistoricalNativeBlobLedger>()?;
    let groups = NativeBlobReceiver17GroupIds {
        ledger: ledger_group,
        supervisor,
    };
    // Every fallible check precedes these transfers and the funded real Rc.
    attempt.completed = Some(HistoricalNativeBlobReceiver17 {
        data: HistoricalNativeBlobReceiver {
            session: attempt.session.take().ok_or_else(invalid)?,
            incarnation: attempt.incarnation.take().ok_or_else(invalid)?,
            limits,
            state: Rc::new(attempt.state.take_completed_data().ok_or_else(invalid)?),
            supervisor_group: supervisor,
        },
        historical_payload_bytes: payload,
        groups,
    });
    Ok(groups)
}

impl Native17Build for HistoricalNativeBlobReceiver17 {
    type Attempt = CurrentNativeBlobReceiver17ReadAttempt;
    fn read_into_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        attempt: &mut Self::Attempt,
    ) -> Result<(), ProviderError> {
        read_native17_blob_receiver_into_data(input, ledger, attempt).map(|_| ())
    }
    fn preflight_data(input: &[u8], ledger: &mut Ledger<'_, '_, '_>) -> Result<(), ProviderError> {
        Self::preflight_settled17_fields_data(input, ledger).map(|_| ())
    }
    fn output_data(attempt: &Self::Attempt) -> Option<&Self> {
        attempt.completed.as_ref()
    }
    fn take_output_data(attempt: &mut Self::Attempt) -> Option<Self> {
        attempt.completed.take()
    }
    fn observe_attempt_data(
        attempt: &Self::Attempt,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        if let Some(value) = &attempt.completed {
            Self::observe_output_data(value, observer)?;
        }
        if let Some(value) = &attempt.session {
            Id::observe_output_data(value, observer)?;
        }
        Id::observe_attempt_data(&attempt.session_attempt, observer)?;
        if let Some(value) = &attempt.incarnation {
            Id::observe_output_data(value, observer)?;
        }
        Id::observe_attempt_data(&attempt.incarnation_attempt, observer)?;
        attempt.state.observe_attempt_data(observer)
    }
    fn observe_output_data(
        value: &Self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        Id::observe_output_data(&value.data.session, observer)?;
        Id::observe_output_data(&value.data.incarnation, observer)?;
        observer.shared_original(MetadataSharedKind::BlobLedger, value.data.state.as_ref())?;
        HistoricalNativeBlobLedger::observe_output_data(value.data.state.as_ref(), observer)
    }
}

impl HistoricalNativeBlobReceiver17 {
    /// Preflights every allocating child and returns the same-pass shared groups.
    ///
    /// # Errors
    /// Refuses malformed receiver fields, source rows, target demand or aliases.
    pub(crate) fn preflight_settled17_fields_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
    ) -> Result<NativeBlobReceiver17GroupIds, ProviderError> {
        let mut fields = Fields::array(input)?;
        exact(next(&mut fields)?, "source-private.native-blob-receiver/11")?;
        Id::preflight_data(next(&mut fields)?, ledger)?;
        Id::preflight_data(next(&mut fields)?, ledger)?;
        read_limits(next(&mut fields)?, ledger)?;
        let (group, _) = preflight_native17_blob_group_fields_data(next(&mut fields)?, ledger)?;
        let ledger_group = group.ok_or_else(invalid)?;
        let supervisor = read_supervisor(next(&mut fields)?, ledger)?;
        fields.finish()?;
        ledger.native17_target_shared_data::<HistoricalNativeBlobLedger>()?;
        Ok(NativeBlobReceiver17GroupIds {
            ledger: ledger_group,
            supervisor,
        })
    }
}

fn read_supervisor(input: &[u8], ledger: &mut Ledger<'_, '_, '_>) -> Result<usize, ProviderError> {
    exact(input, "source-private.native-supervisor-owner/11")?;
    let layout = crate::reference_packet::service::original_native_supervisor_layout();
    let alignment = crate::reference_packet::service::original_native_supervisor_alignment17_data();
    if ledger.row_aligned(MetadataRecordKind::Shared, 1, alignment)? != layout {
        return Err(invalid());
    }
    ledger.shared_reference(MetadataSharedKind::NativeSupervisor, layout)
}

fn read_limits(input: &[u8], ledger: &mut Ledger<'_, '_, '_>) -> Result<BlobLimits, ProviderError> {
    let mut fields = Fields::array(input)?;
    let mut values = [0usize; 7];
    for value in &mut values {
        *value = ledger
            .read::<usize>(next(&mut fields)?, true)?
            .ok_or_else(invalid)?;
    }
    fields.finish()?;
    let [
        reserved_bytes,
        content_bytes,
        chunk_bytes,
        transfers_per_origin,
        tombstones_per_origin,
        chunks_per_transfer,
        operation_pins,
    ] = values;
    if chunk_bytes == 0
        || chunk_bytes > 1_048_576
        || !(1..=4096).contains(&transfers_per_origin)
        || !(1..=4096).contains(&tombstones_per_origin)
        || chunks_per_transfer == 0
        || operation_pins == 0
    {
        return Err(invalid());
    }
    Ok(BlobLimits {
        reserved_bytes,
        content_bytes,
        chunk_bytes,
        transfers_per_origin,
        tombstones_per_origin,
        chunks_per_transfer,
        operation_pins,
    })
}

/// Keeps contextual pin fields without claiming the repeated ledger as its owner.
#[derive(Default)]
pub(crate) struct CurrentOperationPin17ReadAttempt {
    started: bool,
    completed: Option<HistoricalOperationPin17>,
    key: NativeBlobKey17ReadAttempt,
    pin: Option<U64>,
    owner: Option<Id>,
    owner_attempt: <Id as Native17Build>::Attempt,
    schema: Option<ContentRef>,
    schema_attempt: <ContentRef as Native17Build>::Attempt,
    settled: Option<bool>,
}

/// Reads all pin fields and the exact full source ledger traversal in one pass.
///
/// # Errors
/// Refuses malformed pin/receiver views, source rows, target demand or aliases.
pub(crate) fn read_native17_operation_pin_into_data(
    input: &[u8],
    receiver_input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    attempt: &mut CurrentOperationPin17ReadAttempt,
) -> Result<usize, ProviderError> {
    if attempt.started {
        return Err(ProviderError::Conflict(
            "native17 contextual pin already attempted",
        ));
    }
    attempt.started = true;
    let mut fields = Fields::object(input)?;
    attempt.key.read_into_data(fields.named("key")?, ledger)?;
    attempt.pin = ledger.read::<U64>(fields.named("pin")?, true)?;
    owned::<Id>(
        fields.named("owner")?,
        ledger,
        &mut attempt.owner_attempt,
        &mut attempt.owner,
    )?;
    owned::<ContentRef>(
        fields.named("schema")?,
        ledger,
        &mut attempt.schema_attempt,
        &mut attempt.schema,
    )?;
    attempt.settled = ledger.read::<bool>(fields.named("settled")?, true)?;
    fields.finish()?;
    let group = repeated_pin_ledger(receiver_input, ledger)?;
    if attempt.key.output_data().is_none() || attempt.owner.is_none() || attempt.schema.is_none() {
        return Err(invalid());
    }
    let pin = attempt.pin.ok_or_else(invalid)?.get();
    let settled = attempt.settled.ok_or_else(invalid)?;
    attempt.completed = Some(HistoricalOperationPin17 {
        key: attempt.key.take_output_data().ok_or_else(invalid)?,
        pin,
        owner: attempt.owner.take().ok_or_else(invalid)?,
        schema: attempt.schema.take().ok_or_else(invalid)?,
        settled,
        ledger_group: group,
    });
    Ok(group)
}

/// Preflights actual pin allocations and validates its repeated ledger view.
///
/// # Errors
/// Refuses malformed pin/receiver fields, target storage or source group joins.
pub(crate) fn preflight_native17_operation_pin_fields_data(
    input: &[u8],
    receiver_input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
) -> Result<usize, ProviderError> {
    let mut fields = Fields::object(input)?;
    NativeBlobKey17ReadAttempt::preflight_data(fields.named("key")?, ledger)?;
    ledger.read::<U64>(fields.named("pin")?, false)?;
    Id::preflight_data(fields.named("owner")?, ledger)?;
    ContentRef::preflight_data(fields.named("schema")?, ledger)?;
    ledger.read::<bool>(fields.named("settled")?, false)?;
    fields.finish()?;
    repeated_pin_ledger(receiver_input, ledger)
}

fn repeated_pin_ledger(
    receiver_input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
) -> Result<usize, ProviderError> {
    let mut receiver = Fields::array(receiver_input)?;
    exact(
        next(&mut receiver)?,
        "source-private.native-blob-receiver/11",
    )?;
    for _ in 0..3 {
        next(&mut receiver)?;
    }
    let payload = next(&mut receiver)?;
    exact(
        next(&mut receiver)?,
        "source-private.native-supervisor-owner/11",
    )?;
    receiver.finish()?;
    let pause = ledger.suspend_native17_targets_data()?;
    let result = preflight_native17_blob_group_fields_data(payload, ledger);
    ledger.resume_native17_targets_data(pause)?;
    result?.0.ok_or_else(invalid)
}

impl CurrentOperationPin17ReadAttempt {
    pub(crate) fn completed_data(&self) -> Option<&HistoricalOperationPin17> {
        self.completed.as_ref()
    }
    pub(crate) fn take_completed_data(&mut self) -> Option<HistoricalOperationPin17> {
        self.completed.take()
    }
    pub(crate) fn observe_attempt_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        if let Some(value) = &self.completed {
            value.observe_retained_data(observer)?;
        }
        self.key.observe_attempt_data(observer)?;
        if let Some(value) = &self.owner {
            Id::observe_output_data(value, observer)?;
        }
        Id::observe_attempt_data(&self.owner_attempt, observer)?;
        if let Some(value) = &self.schema {
            ContentRef::observe_output_data(value, observer)?;
        }
        ContentRef::observe_attempt_data(&self.schema_attempt, observer)
    }
}

impl HistoricalOperationPin17 {
    /// Counts only actual pin-owned fields; its receiver ledger stays separately owned.
    ///
    /// # Errors
    /// Refuses exhausted observer capacity or checked backing/traversal overflow.
    pub(crate) fn observe_retained_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        Id::observe_output_data(&self.key.session, observer)?;
        Id::observe_output_data(&self.key.incarnation, observer)?;
        Id::observe_output_data(&self.key.transfer, observer)?;
        Id::observe_output_data(&self.owner, observer)?;
        ContentRef::observe_output_data(&self.schema, observer)
    }
}

fn owned<T: Native17Build>(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    child: &mut T::Attempt,
    output: &mut Option<T>,
) -> Result<(), ProviderError> {
    T::read_into_data(input, ledger, child)?;
    *output = Some(T::take_output_data(child).ok_or_else(invalid)?);
    Ok(())
}
