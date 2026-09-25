//! Journal adapter for the shared pure `AOSMSA02` codec.

use aos_sandbox::journal::{JournalRecord, RecordNamespace};

pub(super) use aos_sandbox_protocol::mount_source_acquisition_state::format::*;

use super::model::StoredRecordV2;
use crate::{MountError, Result};

pub(super) fn state_error(message: impl Into<String>) -> MountError {
    MountError::State(message.into())
}

pub(super) fn put_record(record: &StoredRecordV2) -> Result<JournalRecord> {
    let (key, value) = encode_mount_source_state_record_v2(record)?;
    Ok(JournalRecord::put(
        RecordNamespace::MountSourceAcquisition,
        key,
        value,
    ))
}

pub(super) fn materialized_record(record: StoredRecordV2) -> Result<Vec<u8>> {
    put_record(&record)?
        .value()
        .map(ToOwned::to_owned)
        .ok_or_else(|| state_error("AOSMSA02 record materialized as a delete"))
}
