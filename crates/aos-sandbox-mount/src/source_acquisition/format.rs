//! Journal adapter for the shared pure `AOSMSA02` codec.

use aos_sandbox::journal::{JournalRecord, RecordNamespace};

pub(super) use aos_sandbox_protocol::mount_source_acquisition_state::format::*;

use super::model::StoredRecordV2;
use crate::{MountError, Result};

pub(super) fn state_error(message: &'static str) -> MountError {
    MountError::State(message.to_owned())
}

pub(super) fn put_record(record: &StoredRecordV2) -> Result<JournalRecord> {
    let (key, value) = encode_mount_source_state_record_v2(record)?;
    Ok(JournalRecord::put(
        RecordNamespace::MountSourceAcquisition,
        key,
        value,
    ))
}
