//! Borrows the same completed conflict archive for private original retirement.
//!
//! The serializer holds its original mutex guard throughout output. It never
//! clones a history, drains a row or converts observer data into release authority.

use std::sync::MutexGuard;

use serde::{Serialize, Serializer, ser::SerializeStruct};

use super::{Archive, OriginalConflictRecorder, refused};
use crate::ProviderError;
use crucible_node_format::Bytes;

pub(crate) struct OriginalConflictHistory<'a> {
    archive: MutexGuard<'a, Archive>,
    private_token: &'a Bytes,
}

impl OriginalConflictRecorder {
    pub(crate) fn private_original_history(
        &self,
    ) -> Result<OriginalConflictHistory<'_>, ProviderError> {
        let archive = self
            .archive
            .lock()
            .map_err(|_| refused("original conflict history poisoned"))?;
        if archive.incomplete
            || archive.bytes.len() > archive.maximum_bytes
            || archive.rows.len() > archive.maximum_transmissions
            || archive.reserved_bytes > archive.maximum_bytes
        {
            return Err(refused("original conflict history remains incomplete"));
        }

        let mut cursor = 0usize;
        for row in &archive.rows {
            if !row.write_completed || !row.conflict_refusal_verified {
                return Err(refused("original conflict send/read remains unresolved"));
            }
            let received = row
                .received
                .ok_or_else(|| refused("original conflict response absent"))?;
            for (start, length) in [
                row.original_request,
                row.original_response,
                (row.request_start, row.request_length),
                received,
            ] {
                if start != cursor || length == 0 {
                    return Err(refused("original conflict history coverage differs"));
                }
                cursor = cursor
                    .checked_add(length)
                    .filter(|end| *end <= archive.bytes.len())
                    .ok_or_else(|| refused("original conflict history range differs"))?;
            }
        }
        if cursor != archive.bytes.len() {
            return Err(refused("original conflict history has unowned bytes"));
        }
        Ok(OriginalConflictHistory {
            archive,
            private_token: &self.private_token,
        })
    }
}

impl Serialize for OriginalConflictHistory<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let original = &self.archive;
        let mut body = serializer.serialize_struct("OriginalConflictHistory", 9)?;
        body.serialize_field("schema", "crucible.private-original-conflict-history.v1")?;
        body.serialize_field("encoding", "canonical-transmitted-and-decoded-envelope-v1")?;
        body.serialize_field("scope", &original.scope)?;
        body.serialize_field("private_token", &self.private_token)?;
        body.serialize_field("rows", &original.rows)?;
        body.serialize_field("bytes", &original.bytes)?;
        body.serialize_field("maximum_transmissions", &original.maximum_transmissions)?;
        body.serialize_field("maximum_bytes", &original.maximum_bytes)?;
        body.serialize_field("reserved_bytes", &original.reserved_bytes)?;
        body.end()
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "Tests intentionally panic on setup or oracle failures."
)]
mod tests {
    use super::*;
    use crate::client::history_credit::Count;
    use crate::client::reference::conflict_transmissions::{OriginalConflictLimits, Scope};
    use crucible_node_format::Id;

    fn recorder() -> OriginalConflictRecorder {
        let (recorder, _) = OriginalConflictRecorder::reserve_scope(
            Scope {
                session: Id::new("archive-session").unwrap(),
                incarnation: Id::new("archive-incarnation").unwrap(),
                connection: Id::new("archive-connection").unwrap(),
            },
            OriginalConflictLimits {
                maximum_transmissions: 3,
                maximum_bytes: 4096,
            },
            &Bytes::new(vec![19; 32]),
        )
        .unwrap();
        recorder
    }

    #[test]
    fn private_conflict_archive_credit_and_sink_failure_preserve_original_storage() {
        let original = recorder();
        let before = original.archive.lock().unwrap().bytes.capacity();

        let history = original.private_original_history().unwrap();
        assert!(serde_json::to_writer(&mut Count::new(1), &history).is_err());
        let mut credit = Count::new(4096);
        serde_json::to_writer(&mut credit, &history).unwrap();
        let expected = serde_json::to_vec(&history).unwrap();
        assert_eq!(credit.used(), expected.len());
        drop(history);

        let history = original.private_original_history().unwrap();
        let mut storage = [0u8; 1];
        let target = storage.as_mut_slice();
        assert!(serde_json::to_writer(target, &history).is_err());
        assert_eq!(serde_json::to_vec(&history).unwrap(), expected);
        drop(history);
        let archive = original.archive.lock().unwrap();
        assert_eq!(archive.bytes.capacity(), before);
        assert!(archive.rows.is_empty());
        assert!(!archive.incomplete);
    }

    #[test]
    fn unresolved_conflict_archive_and_unowned_bytes_never_export() {
        let original = recorder();
        {
            let mut archive = original.archive.lock().unwrap();
            archive.incomplete = true;
        }
        assert!(original.private_original_history().is_err());
        {
            let mut archive = original.archive.lock().unwrap();
            archive.incomplete = false;
            archive.bytes.push(7);
        }
        assert!(original.private_original_history().is_err());
        assert_eq!(original.archive.lock().unwrap().bytes.as_slice(), &[7]);
    }
}
