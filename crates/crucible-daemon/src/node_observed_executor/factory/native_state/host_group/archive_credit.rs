//! Derives the selected complete-owner archive credit before native birth.
//!
//! The record binds the independently regenerated immutable roster and reserves
//! portable records, the original coordinator, queued payloads and the unchanged
//! native-record residual together. It grants no capture or restoration authority.
//! Its own body is excluded from the length projection and added exactly after
//! encoding, so neither the record nor the complete world has a hash cycle.
//! The two named source references are provenance pins in this closed leaf role;
//! the outer metadata codec independently retains their positive dependencies.
//!
//! ```json
//! {"schema":"crucible.independent-group.archive-credit.v1","owners":4}
//! ```

use std::collections::BTreeSet;

use crucible::node_state::{NativeArchiveLimits, StateLimits};
use crucible_node_contract::{ContentRef, canonical};
use serde::Serialize;

use super::super::super::{NodeObservedError, refused};

const RECORD_BYTES: usize = 16 * 1024 * 1024;
const NATIVE_RECORD_BYTES: usize = 64 * 1024 * 1024;
const QUEUED_PAYLOAD_BYTES: usize = 1024 * 1024;
const TOTAL_STATE_BYTES: usize = 2 * 1024 * 1024 * 1024;

#[derive(Serialize)]
struct Record<'a> {
    schema: &'static str,
    metadata_root: &'a ContentRef,
    selected_scenario: &'a ContentRef,
    owners: usize,
    immutable_objects_without_credit: usize,
    immutable_bytes_without_credit: usize,
    per_record_bytes: usize,
    portable_records_including_index: usize,
    coordinator_bytes: usize,
    queued_payload_bytes: usize,
    native_record_residual_bytes: usize,
    total_record_bytes_without_credit_body: usize,
}

pub(super) struct ArchiveCredit {
    reference: ContentRef,
    body: Vec<u8>,
    total_record_bytes: usize,
}

impl ArchiveCredit {
    pub(super) fn new<'a>(
        root: &ContentRef,
        selected: &ContentRef,
        owners: usize,
        references: impl Iterator<Item = &'a ContentRef>,
    ) -> Result<Self, NodeObservedError> {
        if owners != 4 || root == selected {
            return Err(refused(
                "complete archive credit requires four original owners",
            ));
        }
        let mut unique = BTreeSet::new();
        let mut immutable_bytes = 0usize;
        for reference in references {
            let length = usize::try_from(reference.length.get())
                .map_err(|_| refused("immutable archive length exceeds this host"))?;
            if length > 512 * 1024 * 1024 || unique.len() >= 20_000 {
                return Err(refused(
                    "complete immutable archive geometry exceeds source credit",
                ));
            }
            if unique.insert(reference) {
                immutable_bytes = immutable_bytes
                    .checked_add(length)
                    .ok_or_else(|| refused("complete immutable archive byte overflow"))?;
            }
        }
        let portable_records = owners
            .checked_add(4)
            .ok_or_else(|| refused("portable archive record count overflow"))?;
        let projected = complete_bytes(immutable_bytes, portable_records, 0)?;
        let record = Record {
            schema: "crucible.independent-group.archive-credit.v1",
            metadata_root: root,
            selected_scenario: selected,
            owners,
            immutable_objects_without_credit: unique.len(),
            immutable_bytes_without_credit: immutable_bytes,
            per_record_bytes: RECORD_BYTES,
            portable_records_including_index: portable_records,
            coordinator_bytes: RECORD_BYTES,
            queued_payload_bytes: QUEUED_PAYLOAD_BYTES,
            native_record_residual_bytes: NATIVE_RECORD_BYTES,
            total_record_bytes_without_credit_body: projected,
        };
        let body = canonical::canonical_json(&serde_json::to_value(record)?)?;
        let total_record_bytes = complete_bytes(immutable_bytes, portable_records, body.len())?;
        let reference = canonical::content_ref(&body, "application/json")?;
        if unique.contains(&reference) {
            return Err(refused(
                "archive credit appears in its own source projection",
            ));
        }
        let credit = Self {
            reference,
            body,
            total_record_bytes,
        };
        credit.require_aggregate(TOTAL_STATE_BYTES)?;
        Ok(credit)
    }

    pub(super) fn reference(&self) -> &ContentRef {
        &self.reference
    }

    pub(super) fn body(&self) -> &[u8] {
        &self.body
    }

    pub(super) fn authenticate(
        &self,
        reference: &ContentRef,
        bytes: Option<&[u8]>,
    ) -> Result<(), NodeObservedError> {
        if reference != &self.reference || bytes != Some(self.body.as_slice()) {
            return Err(refused(
                "original source archive credit is missing or differs",
            ));
        }
        reference.verify(self.body())?;
        Ok(())
    }

    pub(super) fn limits(&self) -> NativeArchiveLimits {
        let mut limits = reader_limits();
        limits.native.maximum_total_record_bytes = self.total_record_bytes;
        limits
    }

    pub(super) fn native_record_ceiling(
        &self,
        queued_payload_bytes: usize,
    ) -> Result<usize, NodeObservedError> {
        if queued_payload_bytes > QUEUED_PAYLOAD_BYTES {
            return Err(refused(
                "actual queued payloads exceed original complete source credit",
            ));
        }
        Ok(NATIVE_RECORD_BYTES)
    }

    fn require_aggregate(&self, available: usize) -> Result<(), NodeObservedError> {
        if available < self.total_record_bytes || available > TOTAL_STATE_BYTES {
            return Err(refused("complete source archive aggregate credit differs"));
        }
        Ok(())
    }
}

fn complete_bytes(
    immutable_bytes: usize,
    portable_records: usize,
    credit_body_bytes: usize,
) -> Result<usize, NodeObservedError> {
    let total = portable_records
        .checked_mul(RECORD_BYTES)
        .and_then(|bytes| bytes.checked_add(immutable_bytes))
        .and_then(|bytes| bytes.checked_add(RECORD_BYTES))
        .and_then(|bytes| bytes.checked_add(QUEUED_PAYLOAD_BYTES))
        .and_then(|bytes| bytes.checked_add(NATIVE_RECORD_BYTES))
        .and_then(|bytes| bytes.checked_add(credit_body_bytes))
        .filter(|bytes| *bytes <= TOTAL_STATE_BYTES)
        .ok_or_else(|| refused("complete archive credit exceeds original state interface"))?;
    Ok(total)
}

/// Keeps the original reader and per-object interfaces before source selection.
pub(in crate::node_observed_executor::factory) fn reader_limits() -> NativeArchiveLimits {
    NativeArchiveLimits {
        state: StateLimits {
            maximum_content_bytes: 512 * 1024 * 1024,
            maximum_total_content_bytes: TOTAL_STATE_BYTES,
            maximum_record_bytes: RECORD_BYTES,
            maximum_native_processes: 8192,
            ..StateLimits::default()
        },
        native: crucible::node_contract::NativeCaptureLimits {
            maximum_objects: 20_000,
            maximum_record_bytes: RECORD_BYTES,
            maximum_total_record_bytes: NATIVE_RECORD_BYTES,
            maximum_artifact_bytes: 2 * 1024 * 1024 * 1024,
            maximum_total_artifact_bytes: 8 * 1024 * 1024 * 1024,
        },
    }
}

#[cfg(test)]
#[path = "archive_credit_tests.rs"]
mod tests;
