//! Conjoins exact native17 shared payload and role edges in one aggregate pass.

use crate::ProviderError;
use crate::protocol_snapshot::owned11::typed::{HistoricalType, Ledger, invalid};
use crate::retained_metadata::{aliases::MetadataSharedKind, records::MetadataRecordKind};

/// Retains an inert decoded payload with its aggregate historical alias group.
pub(crate) struct CurrentShared17<T> {
    pub(crate) group: usize,
    pub(crate) payload: T,
}

/// Consumes the actual conservative native payload row for every shared edge.
pub(crate) fn shared_row17(
    ledger: &mut Ledger<'_, '_, '_>,
    layout: (usize, usize),
) -> Result<(), ProviderError> {
    if ledger.row_aligned(MetadataRecordKind::Shared, 1, layout.1)? != layout.0 {
        return Err(invalid());
    }
    Ok(())
}

/// Reads a full defining payload while retaining exact capacity and alias spans.
pub(crate) fn read_shared17<T: HistoricalType>(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
    kind: MetadataSharedKind,
    layout: (usize, usize),
) -> Result<Option<CurrentShared17<T>>, ProviderError> {
    let start = ledger.rows.encoded_position();
    shared_row17(ledger, layout)?;
    let group = ledger.shared_begin(kind)?;
    let payload = ledger.read::<T>(input, build)?;
    let rows = ledger.rows.encoded_between(start)?;
    ledger.shared_finish(group, layout.0, input, rows)?;
    Ok(payload.map(|payload| CurrentShared17 { group, payload }))
}

/// Reads a role reference only after its full root was completed in this pass.
pub(crate) fn read_reference17(
    ledger: &mut Ledger<'_, '_, '_>,
    kind: MetadataSharedKind,
    layout: (usize, usize),
) -> Result<usize, ProviderError> {
    shared_row17(ledger, layout)?;
    ledger.shared_reference(kind, layout.0)
}

/// Reads a native Rc vector while separately constructing historical payloads.
pub(crate) fn read_shared_vector17<T: HistoricalType>(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
    kind: MetadataSharedKind,
    payload_layout: (usize, usize),
    native_element_layout: (usize, usize),
    explicit_capacity: Option<usize>,
) -> Result<Option<Vec<CurrentShared17<T>>>, ProviderError> {
    use crate::protocol_snapshot::owned11::typed::Fields;
    let capacity = ledger.row_aligned(
        MetadataRecordKind::Vector,
        native_element_layout.0,
        native_element_layout.1,
    )?;
    if explicit_capacity.is_some_and(|expected| expected != capacity)
        || capacity
            .checked_mul(native_element_layout.0)
            .is_none_or(|bytes| bytes > ledger.limits.maximum_owned_backing_bytes)
        || capacity
            .checked_mul(std::mem::size_of::<CurrentShared17<T>>())
            .is_none()
    {
        return Err(invalid());
    }
    ledger.native17_target_vector_data::<CurrentShared17<T>>(capacity)?;
    let mut fields = Fields::array(input)?;
    let mut output = Vec::new();
    if build {
        output.try_reserve_exact(capacity).map_err(|_| invalid())?;
        if output.capacity() != capacity {
            return Err(invalid());
        }
    }
    let mut length = 0usize;
    while let Some(raw) = fields.next()? {
        length = length.checked_add(1).ok_or_else(invalid)?;
        if length > capacity {
            return Err(invalid());
        }
        if let Some(value) = read_shared17::<T>(raw, ledger, build, kind, payload_layout)? {
            output.push(value);
        }
    }
    fields.finish()?;
    Ok(build.then_some(output))
}
