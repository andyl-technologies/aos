//! Reconstructs the completed SDK quote with its real historical alias graph.
//!
//! This leaf retains numeric Observe facts and the three original shared handles.
//! It neither recreates an Observe deadline nor authenticates live report currency.

use super::super::{
    state::{next, tag},
    typed::{Fields, HistoricalType, Ledger, historical_struct, invalid},
};
use super::{policy::HistoricalNativePolicy, shared::NativeLedger};
use crate::{
    ProviderError,
    connection::{
        NativeCaptureFutureReceiveQuote, NativeCaptureSdkSnapshotBankQuote,
        NativeCaptureSdkStateData,
    },
    protocol_snapshot::{
        MetadataAliasAllocationFacts, MetadataRecordAllocationFacts, OriginalProtocolStorageFacts,
        ProtocolSnapshotAllocationFacts, ProtocolSnapshotLiteralAllocationFacts,
    },
    retained_metadata::{
        RetainedProtocolMetadataFacts, aliases::MetadataSharedKind, records::MetadataRecordKind,
    },
    transport::DecodedCompactOriginalFrames,
};
use std::rc::Rc;

/// Retains the completed quote's data and shared handles without live currency.
pub struct HistoricalNativeCaptureSdkOwner {
    pub(super) data: NativeCaptureSdkStateData,
    pub(super) retained: RetainedProtocolMetadataFacts,
    pub(super) strong_edges: usize,
    pub(super) unique_roots: usize,
    pub(super) actor_group: usize,
    pub(super) codec_group: usize,
    pub(super) policy: Rc<HistoricalNativePolicy>,
    pub(super) frames: Rc<DecodedCompactOriginalFrames>,
}

impl HistoricalNativeCaptureSdkOwner {
    /// Borrows the exact historical numeric report component without owner rights.
    pub fn sdk_data_view(&self) -> impl serde::Serialize + '_ {
        &self.data
    }

    /// Returns the historical actual retained metadata counts.
    pub const fn retained_metadata_data(&self) -> RetainedProtocolMetadataFacts {
        self.retained
    }

    /// Returns actual strong-edge and unique-root counts from the original walk.
    pub const fn shared_counts_data(&self) -> (usize, usize) {
        (self.strong_edges, self.unique_roots)
    }

    pub(super) fn authenticate_connection(
        &self,
        connection: &super::connection::HistoricalNativeConnection,
    ) -> Result<(), ProviderError> {
        if self.actor_group != connection.actor_group
            || self.codec_group != connection.codec_group
            || !Rc::ptr_eq(&self.policy, &connection.policy)
            || !Rc::ptr_eq(&self.frames, &connection.frames)
        {
            return Err(invalid());
        }
        Ok(())
    }
}

historical_struct!(OriginalProtocolStorageFacts {
    maximum_frame_bytes: usize,
    maximum_history_bytes: usize,
    maximum_frames_per_direction: usize,
    byte_capacity: usize,
    descriptor_capacity: usize,
    descriptor_bytes: usize,
    allocated_bytes: usize,
    retained_bytes: usize,
    incoming_frames: usize,
    outgoing_frames: usize,
    all_io_complete: bool,
});

historical_struct!(ProtocolSnapshotLiteralAllocationFacts {
    maximum_history_bytes: usize,
    maximum_frames_per_direction: usize,
    byte_capacity: usize,
    descriptor_capacity: usize,
    descriptor_bytes: usize,
    retained_bytes: usize,
    allocated_bytes: usize,
});

historical_struct!(ProtocolSnapshotAllocationFacts {
    maximum_encoded_bytes: usize,
    encoded_capacity: usize,
    encoded_length: usize,
    literal: Option<ProtocolSnapshotLiteralAllocationFacts>,
    allocated_bytes: usize,
});

historical_struct!(MetadataRecordAllocationFacts {
    maximum_rows: usize,
    capacity_rows: usize,
    retained_rows: usize,
    allocated_bytes: usize,
});

historical_struct!(MetadataAliasAllocationFacts {
    maximum_rows: usize,
    row_capacity: usize,
    lookup_capacity: usize,
    retained_rows: usize,
    row_bytes: usize,
    lookup_bytes: usize,
});

historical_struct!(NativeCaptureSdkSnapshotBankQuote {
    allocation: ProtocolSnapshotAllocationFacts,
    records: MetadataRecordAllocationFacts,
    aliases: MetadataAliasAllocationFacts,
    required_record_rows: usize,
    required_alias_rows: usize,
    current_encoded_extent: usize,
});

historical_struct!(NativeCaptureFutureReceiveQuote {
    maximum_frame_body_bytes: usize,
    raw_read_requested_bytes: usize,
    raw_dom_requested_bytes: usize,
    typed_validation_requested_bytes: usize,
    correlation_requested_bytes: usize,
    current_incident_copy_requested_bytes: usize,
    original_descriptor_required_bytes: usize,
    original_literal_required_bytes: usize,
    maximum_requested_bytes: usize,
});

historical_struct!(NativeCaptureSdkStateData {
    original_storage: OriginalProtocolStorageFacts,
    before: NativeCaptureSdkSnapshotBankQuote,
    after: NativeCaptureSdkSnapshotBankQuote,
    frame_bank_views: usize,
    maximum_literal_encoding_growth_bytes: usize,
    maximum_descriptor_encoding_growth_bytes: usize,
    future_capture_receive: NativeCaptureFutureReceiveQuote,
});

fn metadata(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
    let mut fields = Fields::array(input)?;
    let string_capacity_bytes = ledger
        .read::<usize>(next(&mut fields)?, true)?
        .ok_or_else(invalid)?;
    let string_banks = ledger
        .read::<usize>(next(&mut fields)?, true)?
        .ok_or_else(invalid)?;
    let vector_capacity_bytes = ledger
        .read::<usize>(next(&mut fields)?, true)?
        .ok_or_else(invalid)?;
    let vector_banks = ledger
        .read::<usize>(next(&mut fields)?, true)?
        .ok_or_else(invalid)?;
    let boxed_value_bytes = ledger
        .read::<usize>(next(&mut fields)?, true)?
        .ok_or_else(invalid)?;
    let shared_value_bytes = ledger
        .read::<usize>(next(&mut fields)?, true)?
        .ok_or_else(invalid)?;
    let shared_backing_views = ledger
        .read::<usize>(next(&mut fields)?, true)?
        .ok_or_else(invalid)?;
    let tree_containers = ledger
        .read::<usize>(next(&mut fields)?, true)?
        .ok_or_else(invalid)?;
    let tree_entries = ledger
        .read::<usize>(next(&mut fields)?, true)?
        .ok_or_else(invalid)?;
    let maximum_tree_key_value_bytes = ledger
        .read::<usize>(next(&mut fields)?, true)?
        .ok_or_else(invalid)?;
    let maximum_tree_entry_alignment = ledger
        .read::<usize>(next(&mut fields)?, true)?
        .ok_or_else(invalid)?;
    let maximum_shared_value_alignment = ledger
        .read::<usize>(next(&mut fields)?, true)?
        .ok_or_else(invalid)?;
    let observed_nodes = ledger
        .read::<usize>(next(&mut fields)?, true)?
        .ok_or_else(invalid)?;
    let capacity_records = ledger
        .read::<usize>(next(&mut fields)?, true)?
        .ok_or_else(invalid)?;
    fields.finish()?;
    Ok(RetainedProtocolMetadataFacts {
        string_capacity_bytes,
        string_banks,
        vector_capacity_bytes,
        vector_banks,
        boxed_value_bytes,
        shared_value_bytes,
        shared_backing_views,
        tree_containers,
        tree_entries,
        maximum_tree_key_value_bytes,
        maximum_tree_entry_alignment,
        maximum_shared_value_alignment,
        observed_nodes,
        capacity_records,
    })
}

pub(super) fn read(
    input: &[u8],
    ledger: &mut NativeLedger<'_, '_, '_, '_, '_>,
    build: bool,
) -> Result<Option<HistoricalNativeCaptureSdkOwner>, ProviderError> {
    let mut fields = Fields::array(input)?;
    tag(
        &mut fields,
        "source-private.native-capture-sdk-completed-owner/12",
    )?;
    let mut numeric = Fields::array(next(&mut fields)?)?;
    tag(
        &mut numeric,
        "source-private.native-capture-sdk-quote-data/12",
    )?;
    // These fields own no heap banks. Parse them in both passes to check the
    // original completed walk's invariant before any historical reconstruction.
    let data = ledger
        .ledger
        .read::<NativeCaptureSdkStateData>(next(&mut numeric)?, true)?
        .ok_or_else(invalid)?;
    let retained = metadata(next(&mut numeric)?, ledger.ledger)?;
    let strong_edges = ledger
        .ledger
        .read::<usize>(next(&mut numeric)?, true)?
        .ok_or_else(invalid)?;
    let unique_roots = ledger
        .ledger
        .read::<usize>(next(&mut numeric)?, true)?
        .ok_or_else(invalid)?;
    tag(&mut numeric, "opaque-original-observe-cut")?;
    numeric.finish()?;
    if retained.shared_backing_views != unique_roots
        || unique_roots == 0
        || strong_edges < unique_roots
        || unique_roots > 64
    {
        return Err(invalid());
    }
    tag(&mut fields, "historical-source-owner")?;
    let layout = std::mem::size_of::<crate::protocol_snapshot::ProtocolCaptureOwner>();
    if ledger.ledger.row(MetadataRecordKind::Shared, 1)? != layout {
        return Err(invalid());
    }
    let actor_group = ledger.ledger.shared(
        MetadataSharedKind::ProtocolOwner,
        layout,
        b"historical-source-owner",
        b"",
    )?;
    let (codec_group, policy) = super::connection::codec(next(&mut fields)?, ledger, build)?;
    let frames = ledger.frames(next(&mut fields)?, build, MetadataSharedKind::FrameBank)?;
    fields.finish()?;
    if !build {
        return Ok(None);
    }
    Ok(Some(HistoricalNativeCaptureSdkOwner {
        data,
        retained,
        strong_edges,
        unique_roots,
        actor_group,
        codec_group,
        policy: policy.ok_or_else(invalid)?,
        frames: frames.ok_or_else(invalid)?,
    }))
}

// The closed owning walk fails to compile if a historical field is added.
super::super::retained_storage::fields!(
    HistoricalNativeCaptureSdkOwner,
    data,
    retained,
    strong_edges,
    unique_roots,
    actor_group,
    codec_group,
    policy,
    frames
);

pub(crate) mod current17;

/// Names actual fixed local and returned headers of this handwritten reader.
///
/// Empty maps and `Option` payloads remain real controls when `build` is false;
/// no tree entries, backing allocations or owning reconstruction are included.
pub(super) fn borrowed_validation_headers_data() -> usize {
    use std::mem::size_of;

    fn header<T>() -> usize {
        size_of::<Option<T>>() + size_of::<Result<Option<T>, ProviderError>>()
    }

    fn field<T: super::super::typed::HistoricalType>() -> usize {
        header::<T>() + T::borrowed_header_counter_scratch_data()
    }

    field::<usize>()
        + field::<usize>()
        + field::<usize>()
        + field::<usize>()
        + field::<usize>()
        + field::<usize>()
        + field::<usize>()
        + field::<usize>()
        + field::<usize>()
        + field::<usize>()
        + field::<usize>()
        + field::<usize>()
        + field::<usize>()
        + field::<usize>()
        + field::<NativeCaptureSdkStateData>()
        + field::<usize>()
        + field::<usize>()
        + header::<HistoricalNativeCaptureSdkOwner>()
        + header::<Rc<HistoricalNativePolicy>>()
        + header::<Rc<DecodedCompactOriginalFrames>>()
        + size_of::<RetainedProtocolMetadataFacts>()
        + size_of::<Result<RetainedProtocolMetadataFacts, ProviderError>>()
}
