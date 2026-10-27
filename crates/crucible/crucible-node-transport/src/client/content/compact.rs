//! Borrows complete client byte custody using deterministic original alias edges.
//!
//! This separate source-private format retains one compact payload for each
//! original Rc allocation. Every transfer and object keeps its reference,
//! capacity and lifetime state. Indices describe historical data, not authority.
//!
//! ```json
//! ["source-private.client-content/7", 65536, 8, 4096, 12,
//!  [["transfer-id", {}, ["transfer", 0], 12, true, {}]],
//!  [["object-key", {}, ["transfer", 0], 12, null]]]
//! ```

use super::ClientContent;
use crate::protocol_snapshot::{Sequence, compact_bytes::BorrowedCompactBytes};
use std::rc::Rc;

impl ClientContent {
    /// Borrows every original content owner with compact full-byte alias edges.
    ///
    /// This data-only view neither installs a source nor authenticates Capture.
    /// Original limits, credit, full references and capacities remain present;
    /// equal values in different Rc allocations are separate payload groups.
    pub fn original_compact_protocol_view(&self) -> impl serde::Serialize + '_ {
        let transfers = Sequence(move || {
            self.transfers
                .iter()
                .enumerate()
                .map(move |(index, (id, transfer))| {
                    let first = self
                        .transfers
                        .iter()
                        .take(index)
                        .position(|(_, earlier)| Rc::ptr_eq(&earlier.bytes, &transfer.bytes))
                        .unwrap_or(index);
                    let payload = (first == index)
                        .then(|| BorrowedCompactBytes::new(transfer.bytes.as_slice()));

                    (
                        id,
                        &transfer.reference,
                        ("transfer", first),
                        transfer.bytes.capacity(),
                        transfer.complete,
                        payload,
                    )
                })
        });
        let objects = Sequence(move || {
            self.objects
                .iter()
                .enumerate()
                .map(move |(index, (key, (reference, bytes)))| {
                    let transfer = self
                        .transfers
                        .iter()
                        .position(|(_, transfer)| Rc::ptr_eq(bytes, &transfer.bytes));
                    let (kind, first, payload) = match transfer {
                        Some(first) => ("transfer", first, None),
                        None => {
                            let first = self
                                .objects
                                .iter()
                                .take(index)
                                .position(|(_, (_, earlier))| Rc::ptr_eq(bytes, earlier))
                                .unwrap_or(index);
                            let payload = (first == index)
                                .then(|| BorrowedCompactBytes::new(bytes.as_slice()));
                            ("object", first, payload)
                        }
                    };

                    (key, reference, (kind, first), bytes.capacity(), payload)
                })
        });

        (
            "source-private.client-content/7",
            self.maximum_bytes,
            self.maximum_objects,
            self.maximum_chunk,
            self.reserved,
            transfers,
            objects,
        )
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::client::content::Transfer;
    use crate::protocol_snapshot::compact_bytes::ValidatedCompactBytes;
    use crucible_node_format::{Id, canonical};

    #[test]
    fn compact_original_content_preserves_real_aliases_distinct_equal_buffers_and_spare_capacity() {
        let mut first = Vec::with_capacity(64);
        first.extend_from_slice(b"same");
        let mut second = Vec::with_capacity(96);
        second.extend_from_slice(b"same");
        let first = Rc::new(first);
        let second = Rc::new(second);
        assert!(!Rc::ptr_eq(&first, &second));
        let reference = canonical::content_ref(b"same", "application/octet-stream").unwrap();
        let mut content = ClientContent::new(1024, 8, 256).unwrap();
        content.reserved = 8;
        content.transfers.insert(
            Id::new("first").unwrap(),
            Transfer {
                reference: reference.clone(),
                bytes: first.clone(),
                complete: true,
            },
        );
        content.transfers.insert(
            Id::new("second").unwrap(),
            Transfer {
                reference: reference.clone(),
                bytes: second.clone(),
                complete: true,
            },
        );
        content.objects.insert(
            reference.hash.digest.clone(),
            (reference.clone(), first.clone()),
        );
        let empty = Rc::new(Vec::with_capacity(32));
        let empty_reference = canonical::content_ref(b"", "application/octet-stream").unwrap();
        content.objects.insert(
            empty_reference.hash.digest.clone(),
            (empty_reference, empty.clone()),
        );

        let old = serde_json::to_vec(&content.protocol_view()).unwrap();
        let bytes = serde_json::to_vec(&content.original_compact_protocol_view()).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value[0], "source-private.client-content/7");
        assert_eq!(value[4], 8);
        let transfers = value[5].as_array().unwrap();
        assert_eq!(transfers.len(), 2);
        assert_eq!(transfers[0][2], serde_json::json!(["transfer", 0]));
        assert_eq!(transfers[1][2], serde_json::json!(["transfer", 1]));
        assert_eq!(transfers[0][3], first.capacity());
        assert_eq!(transfers[1][3], second.capacity());
        for row in transfers {
            let encoded = serde_json::to_vec(&row[5]).unwrap();
            let plan = ValidatedCompactBytes::validate(&encoded, encoded.len(), 64).unwrap();
            let mut original = Vec::with_capacity(row[3].as_u64().unwrap() as usize);
            let capacity = original.capacity();
            plan.fill_preowned(&mut original).unwrap();
            assert_eq!(original, b"same");
            assert_eq!(original.capacity(), capacity);
        }
        let objects = value[6].as_array().unwrap();
        let alias = objects
            .iter()
            .find(|row| row[0] == reference.hash.digest)
            .unwrap();
        assert_eq!(alias[2], serde_json::json!(["transfer", 0]));
        assert!(alias[4].is_null());
        let empty_row = objects.iter().find(|row| !row[4].is_null()).unwrap();
        assert_eq!(empty_row[3], empty.capacity());
        let encoded = serde_json::to_vec(&empty_row[4]).unwrap();
        let plan = ValidatedCompactBytes::validate(&encoded, encoded.len(), 0).unwrap();
        let mut original = Vec::with_capacity(empty_row[3].as_u64().unwrap() as usize);
        let pointer = original.as_ptr();
        plan.fill_preowned(&mut original).unwrap();
        assert!(original.is_empty());
        assert_eq!(original.capacity(), 32);
        assert_eq!(original.as_ptr(), pointer);
        assert_eq!(serde_json::to_vec(&content.protocol_view()).unwrap(), old);
    }
}
