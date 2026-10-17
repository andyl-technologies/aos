//! Writes every defining sealed startup quote field without a new grant.

use super::*;
use crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes;
use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};

impl PacketNativeRestoredSuffixStartupStorageData {
    pub(crate) fn borrowed_settled_history_data(&self) -> impl Serialize + '_ {
        Sealed(self)
    }
}

struct Sealed<'a>(&'a PacketNativeRestoredSuffixStartupStorageData);
impl Serialize for Sealed<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let PacketNativeRestoredSuffixStartupStorageData {
            model,
            launch_digest,
            launch_bytes,
            frame_bytes,
            originals,
            reservation,
            retained,
            transient,
            scratch,
            requested,
        } = self.0;
        let PacketCompleteRestoreOwnerValidationStorage {
            snapshot_bytes,
            journal_bytes,
            control_bytes,
            model_vector_backing_bytes,
            anchor_bytes,
            capture_comparison_bytes,
            declared_scanner_bytes,
            total_bytes,
        } = model;
        let mut state = serializer.serialize_struct("SealedSuffixStartupHistory", 11)?;
        state.serialize_field("schema", "source-private.native-restored-suffix-sealed/1")?;
        state.serialize_field(
            "model",
            &(
                snapshot_bytes,
                journal_bytes,
                control_bytes,
                model_vector_backing_bytes,
                anchor_bytes,
                capture_comparison_bytes,
                declared_scanner_bytes,
                total_bytes,
            ),
        )?;
        state.serialize_field("launch_digest", &BorrowedCompactBytes::new(launch_digest))?;
        state.serialize_field("launch_bytes", launch_bytes)?;
        state.serialize_field("frame_bytes", frame_bytes)?;
        state.serialize_field("originals", originals)?;
        state.serialize_field("reservation", reservation)?;
        state.serialize_field("retained", retained)?;
        state.serialize_field("transient", transient)?;
        state.serialize_field("scratch", scratch)?;
        state.serialize_field("requested", requested)?;
        state.end()
    }
}

impl PacketNativeRestoredSuffixStartupStorageData {
    pub(crate) fn settled_history_counter_scratch_data() -> usize {
        use std::mem::size_of;
        size_of::<Sealed<'static>>() + size_of::<[&'static usize; 8]>()
    }
}
