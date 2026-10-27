//! Prices the existing public projection decoder representations as passive DATA.
//!
//! A historical native audit supplies its actual maximum observed row bound;
//! a current native query supplies its actual maximum current row bound. The
//! same protobuf/model recipe creates no owner, decoder permit or paid loan.

/// Prices four existing Sandbox decoder and canonical model representations.
///
/// Returns `None` when scalar conversion, protobuf geometry or checked growth
/// cannot represent the original decoder demand.
#[must_use]
pub fn sandbox_projection_decoding_receiving_bytes_v2(encoded_bytes: usize) -> Option<u64> {
    projection_encoded_model_receiving_bytes_v2(encoded_bytes,
        std::mem::size_of::<aos_sandbox_api::aos::sandbox::v1::Sandbox>())
}

/// Prices the same projection recipe for an actual concrete protobuf model width.
///
/// The width is representation DATA, not a paid header or admission. Returns
/// `None` on conversion, protobuf geometry refusal or checked multiplication.
#[must_use]
pub fn projection_encoded_model_receiving_bytes_v2(encoded_bytes: usize, width: usize) -> Option<u64> {
    let bytes = aos_sandbox_broker_session_protocol::receiving_geometry::protobuf_carriers_v1(
        u64::try_from(encoded_bytes).ok()?, u64::try_from(width).ok()?,
    ).ok()?;
    // accepted_target and the spec producer each own their projected model;
    // its canonical round trip and command clone can coexist with that input.
    bytes.checked_mul(4)
}

/// Prices the existing Execution projection model from supplied current rows.
///
/// Returns `None` on checked decoder or forwarding geometry overflow. Supplied
/// rows convey no native health, role, currentness or paid authority.
#[must_use]
pub fn execution_source_receiving_bytes_v1(
    rows: crate::domain_ledger::readonly::HistoricalLedgerRowsDataV2<'_>,
) -> Option<u64> {
    projection_model_receiving_bytes_v1(rows,
        std::mem::size_of::<aos_sandbox_api::aos::sandbox::v1::Execution>())
}

/// Prices the existing Sandbox projection model from supplied current rows.
///
/// Returns `None` on checked decoder or forwarding geometry overflow. The
/// genuine caller independently retains all native observations and admission.
#[must_use]
pub fn sandbox_source_receiving_bytes_v1(
    rows: crate::domain_ledger::readonly::HistoricalLedgerRowsDataV2<'_>,
) -> Option<u64> {
    projection_model_receiving_bytes_v1(rows,
        std::mem::size_of::<aos_sandbox_api::aos::sandbox::v1::Sandbox>())
}

/// Prices the same Snapshot and FilesystemView decoder and return carriers.
///
/// Returns `None` on checked decoder, forwarding or retained model overflow.
/// The calculation grants neither metadata access nor a native operation loan.
#[must_use]
pub fn metadata_source_receiving_bytes_v2(
    rows: crate::domain_ledger::readonly::HistoricalLedgerRowsDataV2<'_>,
) -> Option<u64> {
    use super::{PROJECTION_KEY_PREFIX, PublicProjectionRecordV1};

    projection_model_receiving_bytes_v1(rows,
        std::mem::size_of::<aos_sandbox_api::aos::sandbox::v1::Snapshot>()
            .max(std::mem::size_of::<aos_sandbox_api::aos::sandbox::v1::FilesystemView>()))?
        .checked_add(u64::try_from(std::mem::size_of::<PublicProjectionRecordV1>()
            .checked_mul(3)?).ok()?)?
        .checked_add(u64::try_from(PROJECTION_KEY_PREFIX.len().checked_add(1 + 16)?
            .checked_mul(3)?).ok()?)
}

fn projection_model_receiving_bytes_v1(
    rows: crate::domain_ledger::readonly::HistoricalLedgerRowsDataV2<'_>,
    width: usize,
) -> Option<u64> {
    let mut maximum = 0usize;
    for (key, value) in rows.records_data_v2(aos_sandbox_model::RecordNamespace::DesiredState) {
        if key.starts_with(super::PROJECTION_KEY_PREFIX) {
            maximum = maximum.max(value.len());
        }
    }
    let decoder = projection_encoded_model_receiving_bytes_v2(maximum, width)?;
    // Both public and private argument/return boundaries carry the actual
    // two-reference row view. This is memory, not a namespace/index entry.
    let controls = std::mem::size_of::<crate::domain_ledger::readonly::HistoricalLedgerRowsDataV2<'_>>()
        .checked_mul(6)?
        .checked_add(std::mem::size_of::<Option<u64>>().checked_mul(6)?)?;
    decoder.checked_add(u64::try_from(controls).ok()?)
}
