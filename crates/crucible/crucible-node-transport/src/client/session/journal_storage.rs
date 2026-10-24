//! Prices both persistent SDK journals under their actual shared byte ceiling.
//!
//! Each entry owns its request, optional response, identity hash and map ID. The
//! session charges complete canonical envelope bytes before retaining them.
//! These DATA quotes change no quota and create no allocation reservation.

use super::*;
use crate::retained_metadata::{
    requested_storage::tree_storage_data,
    serialization_storage::{
        OriginalJsonValueStorageExtentData,
        original_json_value_storage_forest_counter_scratch_data,
        original_json_value_storage_forest_data,
    },
};
use std::mem::{align_of, size_of};

impl ClientCustody {
    /// Bounds new persistent journal backing at the current unchanged ceilings.
    ///
    /// Both endpoint namespaces may fill independently. Their complete requests
    /// and responses share the one canonical-byte quota, including retained
    /// requests whose send fails. Map IDs and request-identity hashes are separate
    /// allocations, priced beside the envelope forest and actual tree layouts.
    /// Current allocations remain independently charged by the owning census.
    ///
    /// This quotes only journal backing. Caller-owned requests, correlation
    /// clones, receiver/serializer work, content transfers and conservative
    /// whole-owner observation growth require independent funding. The caller
    /// admits the fixed counter before this DATA walk; no quota is increased.
    ///
    /// # Errors
    /// Refuses unsupported tree layouts, checked overflow or backing above the
    /// independent supplied restriction. No Source or allocation grant is issued.
    pub fn original_journal_retained_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, ProviderError> {
        let entries = multiply(2, self.maximum_requests)?;
        let documents = multiply(2, entries)?;
        let envelopes = original_json_value_storage_forest_data(self.maximum_bytes, documents)?;
        let trees = tree_storage_data(
            2,
            entries,
            size_of::<Id>() + size_of::<ClientOriginal>(),
            align_of::<(Id, ClientOriginal)>(),
        )?;
        // request_hash validates IDs and constructs these exact hash strings.
        // These duplicate map keys and identity fields are outside the envelope.
        let identity =
            crucible_node_format::MAX_ID_BYTES + "blake3-256".len() + "cnp.request.v1".len() + 64;
        let retained = add(
            envelopes.value_dom_requested_bytes,
            add(trees, multiply(entries, identity)?)?,
        )?;
        if retained > maximum {
            return Err(refused());
        }
        Ok(retained)
    }

    /// Names fixed journal/forest quotes and pinned tree-layout controls.
    pub const fn original_journal_retained_counter_scratch_data() -> usize {
        original_json_value_storage_forest_counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<OriginalJsonValueStorageExtentData>()
            + size_of::<Result<OriginalJsonValueStorageExtentData, ProviderError>>()
            + 16 * size_of::<usize>()
            + size_of::<std::alloc::Layout>()
            + size_of::<[usize; 5]>()
            + size_of::<std::slice::Iter<'static, usize>>()
            + size_of::<Result<usize, ProviderError>>()
    }
}

fn add(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_add(right).ok_or_else(refused)
}

fn multiply(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_mul(right).ok_or_else(refused)
}

fn refused() -> ProviderError {
    ProviderError::ResourceExhausted("original SDK journal storage projection")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::retained_metadata::{
        MetadataObserver,
        records::{MetadataRecordBank, MetadataRecordKind},
    };

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn observed_backing(custody: &ClientCustody) -> Result<usize, ProviderError> {
        let mut records = MetadataRecordBank::reserve(8192)?;
        let mut observer = MetadataObserver::recording(&mut records);
        custody.observe_owned_metadata(&mut observer)?;
        observer.finish();

        records.rows().iter().try_fold(0, |sum, row| {
            let bytes = match row.kind {
                MetadataRecordKind::Tree => {
                    tree_storage_data(1, row.extent, row.element_bytes, row.alignment)?
                }
                MetadataRecordKind::String | MetadataRecordKind::Vector => {
                    multiply(row.extent, row.element_bytes)?
                }
                MetadataRecordKind::Shared | MetadataRecordKind::Boxed => {
                    return Err(refused());
                }
            };
            add(sum, bytes)
        })
    }

    #[test]
    fn both_original_namespaces_and_failed_unsent_requests_fit_without_changing_quota() -> TestResult
    {
        let mut custody = ClientCustody::new(12, ClientContent::new(65_536, 8, 4096)?)?;
        let before = custody.original_journal_retained_storage_data(usize::MAX)?;
        let ceilings = (custody.maximum_requests, custody.maximum_bytes);

        // Construct journal DATA using the same complete canonical byte charge
        // and request hash as exchange. A missing terminal is an unsent/uncertain
        // prefix; these records supply no connection or native execution witness.
        for origin in [RequestOrigin::Controller, RequestOrigin::Provider] {
            for index in 0..12 {
                let mut request = crate::envelope::tests::request();
                let id = Id::new(format!("{}-{index}", "x".repeat(120)))?;
                request.request_id = crate::envelope::Nullable(Some(id.clone()));
                request.body = serde_json::from_value(serde_json::json!({
                    "nested": [{"first": [0, 1, 2]}, {"second": "retained"}],
                    "number": 1e-7,
                }))?;
                let identity = request.request_hash(origin)?;
                let response = if index % 2 == 0 {
                    let mut response = request.clone();
                    response.message = MessageKind::Response;
                    Some(response)
                } else {
                    None
                };
                let bytes = envelope_bytes(&request)?
                    + response
                        .as_ref()
                        .map(envelope_bytes)
                        .transpose()?
                        .unwrap_or(0);
                custody.retain_journal_bytes(bytes)?;
                let journal = match origin {
                    RequestOrigin::Controller => &mut custody.controller,
                    RequestOrigin::Provider => &mut custody.provider,
                };
                journal.insert(
                    id,
                    ClientOriginal {
                        request,
                        identity,
                        response,
                    },
                );
            }
        }

        assert!(observed_backing(&custody)? <= before);
        assert_eq!(
            custody.original_journal_retained_storage_data(before)?,
            before
        );
        assert!(
            custody
                .original_journal_retained_storage_data(before - 1)
                .is_err()
        );
        assert_eq!((custody.maximum_requests, custody.maximum_bytes), ceilings);
        assert!(
            custody
                .content
                .original_completed_objects_data()
                .next()
                .is_none()
        );
        Ok(())
    }
}
