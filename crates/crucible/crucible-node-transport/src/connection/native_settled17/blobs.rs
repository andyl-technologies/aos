//! Reads actual receiver/pin leaves and conjoins their full repeated ledger views.

use super::*;
use crate::blob::{BlobLimits, TransferKey};
use crate::envelope::RequestOrigin;
use crate::protocol_snapshot::owned11::native::blob::{
    HistoricalNativeBlobLedger, HistoricalNativeBlobReceiver, HistoricalNativePinPhase,
};
use crucible_node_format::ContentRef;
use std::rc::Rc;

/// Identifies both real shared roots of one historical receiver view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeBlobReceiver17GroupIds {
    pub(crate) ledger: usize,
    pub(crate) supervisor: usize,
}

/// Retains full receiver/ledger DATA without reconstructing a consuming receiver.
pub(crate) struct HistoricalNativeBlobReceiver17 {
    pub(crate) data: HistoricalNativeBlobReceiver,
    pub(crate) historical_payload_bytes: usize,
    groups: NativeBlobReceiver17GroupIds,
}

impl HistoricalNativeBlobReceiver17 {
    /// Returns actual archive-local ledger and supervisor groups.
    pub(crate) const fn group_ids_data(&self) -> NativeBlobReceiver17GroupIds {
        self.groups
    }

    /// Checks complete retained transfer, pin, chunk and nonrefunded-credit DATA.
    ///
    /// # Errors
    /// Refuses inconsistent scopes, bytes, pin populations or custody tombstones.
    pub(crate) fn authenticate_state_data(&self) -> Result<(), ProviderError> {
        self.data.authenticate_state()
    }
}

/// Reads the complete stable receiver leaf using only explicit17 shared groups.
///
/// # Errors
/// Refuses malformed bounds/fields, full-ledger row mismatch or unavailable backing.
pub(crate) fn read_native17_blob_receiver_data(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<
    (
        Option<HistoricalNativeBlobReceiver17>,
        NativeBlobReceiver17GroupIds,
    ),
    ProviderError,
> {
    let mut fields = Fields::array(input)?;
    exact(next(&mut fields)?, "source-private.native-blob-receiver/11")?;
    let session = ledger.read::<Id>(next(&mut fields)?, build)?;
    let incarnation = ledger.read::<Id>(next(&mut fields)?, build)?;
    let mut limits = Fields::array(next(&mut fields)?)?;
    let mut values = [0usize; 7];
    for value in &mut values {
        *value = ledger
            .read::<usize>(next(&mut limits)?, true)?
            .ok_or_else(invalid)?;
    }
    limits.finish()?;
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
    let limits = BlobLimits {
        reserved_bytes,
        content_bytes,
        chunk_bytes,
        transfers_per_origin,
        tombstones_per_origin,
        chunks_per_transfer,
        operation_pins,
    };
    let (state, group, payload) = super::reader::read_blobs(next(&mut fields)?, ledger, build)?;
    let ledger_group = group.ok_or_else(invalid)?;
    exact(
        next(&mut fields)?,
        "source-private.native-supervisor-owner/11",
    )?;
    let layout = crate::reference_packet::service::original_native_supervisor_layout();
    let alignment = crate::reference_packet::service::original_native_supervisor_alignment17_data();
    if ledger.row_aligned(MetadataRecordKind::Shared, 1, alignment)? != layout {
        return Err(invalid());
    }
    let supervisor_group = ledger.shared_reference(MetadataSharedKind::NativeSupervisor, layout)?;
    fields.finish()?;
    let groups = NativeBlobReceiver17GroupIds {
        ledger: ledger_group,
        supervisor: supervisor_group,
    };
    ledger.native17_target_shared_data::<HistoricalNativeBlobLedger>()?;
    if !build {
        return Ok((None, groups));
    }
    Ok((
        Some(HistoricalNativeBlobReceiver17 {
            data: HistoricalNativeBlobReceiver {
                session: session.ok_or_else(invalid)?,
                incarnation: incarnation.ok_or_else(invalid)?,
                limits,
                state: Rc::new(state.ok_or_else(invalid)?),
                supervisor_group,
            },
            historical_payload_bytes: payload,
            groups,
        }),
        groups,
    ))
}

/// Retains every operation-pin wrapper field with its actual receiver group.
pub(crate) struct HistoricalOperationPin17 {
    pub(crate) key: TransferKey,
    pub(crate) pin: u64,
    pub(crate) owner: Id,
    pub(crate) schema: ContentRef,
    pub(crate) settled: bool,
    pub(crate) ledger_group: usize,
}

impl HistoricalOperationPin17 {
    /// Checks the pin against the independently retained exact receiver ledger.
    ///
    /// # Errors
    /// Refuses different ledger/scope, absent pin or inconsistent wrapper state.
    pub(crate) fn authenticate_receiver_data(
        &self,
        receiver: &HistoricalNativeBlobReceiver17,
    ) -> Result<(), ProviderError> {
        if self.ledger_group != receiver.groups.ledger
            || self.key.session != receiver.data.session
            || self.key.incarnation != receiver.data.incarnation
        {
            return Err(invalid());
        }
        let record = receiver
            .data
            .state
            .records
            .get(&self.key)
            .ok_or_else(invalid)?;
        let pin = record.pins.get(&self.pin).ok_or_else(invalid)?;
        if pin.owner != self.owner
            || pin.schema != self.schema
            || record.quarantined
            || !record.verified
            || pin.phase
                != if self.settled {
                    HistoricalNativePinPhase::Settled
                } else {
                    HistoricalNativePinPhase::Held
                }
        {
            return Err(invalid());
        }
        Ok(())
    }
}

/// Reads the pin wrapper and the actual ledger rewalk implied by its real Rc.
///
/// The receiver input supplies the full immutable ledger bytes omitted by the
/// pin serializer. Those bytes are strictly reread against this same group's
/// own capacity rows; the caller retains the receiver before accepting pins.
///
/// # Errors
/// Refuses malformed pin/receiver grammar, mismatched repeated ledger or backing.
pub(crate) fn read_native17_operation_pin_data(
    input: &[u8],
    receiver_input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<(Option<HistoricalOperationPin17>, usize), ProviderError> {
    let mut fields = Fields::object(input)?;
    let mut key = Fields::array(fields.named("key")?)?;
    let origin = match plain_string(next(&mut key)?)? {
        "controller" => RequestOrigin::Controller,
        "provider" => RequestOrigin::Provider,
        _ => return Err(invalid()),
    };
    let session = ledger.read::<Id>(next(&mut key)?, build)?;
    let incarnation = ledger.read::<Id>(next(&mut key)?, build)?;
    let transfer = ledger.read::<Id>(next(&mut key)?, build)?;
    key.finish()?;
    let pin = ledger.read::<U64>(fields.named("pin")?, build)?;
    let owner = ledger.read::<Id>(fields.named("owner")?, build)?;
    let schema = ledger.read::<ContentRef>(fields.named("schema")?, build)?;
    let settled = ledger.read::<bool>(fields.named("settled")?, build)?;
    fields.finish()?;
    let mut receiver = Fields::array(receiver_input)?;
    exact(
        next(&mut receiver)?,
        "source-private.native-blob-receiver/11",
    )?;
    for _ in 0..3 {
        next(&mut receiver)?;
    }
    let raw_ledger = next(&mut receiver)?;
    exact(
        next(&mut receiver)?,
        "source-private.native-supervisor-owner/11",
    )?;
    receiver.finish()?;
    let pause = ledger.suspend_native17_targets_data()?;
    let repeated = super::reader::read_blobs(raw_ledger, ledger, false);
    ledger.resume_native17_targets_data(pause)?;
    let (_, group, _) = repeated?;
    let ledger_group = group.ok_or_else(invalid)?;
    if !build {
        return Ok((None, ledger_group));
    }
    Ok((
        Some(HistoricalOperationPin17 {
            key: TransferKey {
                origin,
                session: session.ok_or_else(invalid)?,
                incarnation: incarnation.ok_or_else(invalid)?,
                transfer: transfer.ok_or_else(invalid)?,
            },
            pin: pin.ok_or_else(invalid)?.get(),
            owner: owner.ok_or_else(invalid)?,
            schema: schema.ok_or_else(invalid)?,
            settled: settled.ok_or_else(invalid)?,
            ledger_group,
        }),
        ledger_group,
    ))
}

mod retained;
pub(crate) use retained::{
    CurrentNativeBlobReceiver17ReadAttempt, CurrentOperationPin17ReadAttempt,
    NativeBlobGroup17ReadAttempt, preflight_native17_blob_group_fields_data,
    preflight_native17_operation_pin_fields_data, read_native17_blob_group_into_data,
    read_native17_blob_receiver_into_data, read_native17_operation_pin_into_data,
};
