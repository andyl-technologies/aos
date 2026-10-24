//! Compares internal growth bounds with actual content owners and fixed quotas.

use super::*;
use crate::retained_metadata::{
    MetadataObserver,
    records::{MetadataRecordBank, MetadataRecordKind},
    requested_storage::{shared_header_storage_data, tree_storage_data},
};
use crucible_node_format::{Bytes, Extensions, canonical};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn observed_backing(content: &ClientContent) -> Result<usize, ProviderError> {
    let mut records = MetadataRecordBank::reserve(4096)?;
    let mut observer = MetadataObserver::recording(&mut records);
    content.observe_owned_metadata(&mut observer)?;
    observer.finish();

    records.rows().iter().try_fold(0, |total, row| {
        let bytes = match row.kind {
            MetadataRecordKind::Tree => {
                tree_storage_data(1, row.extent, row.element_bytes, row.alignment)?
            }
            MetadataRecordKind::String | MetadataRecordKind::Vector => {
                multiply(row.extent, row.element_bytes)?
            }
            MetadataRecordKind::Shared => {
                add(row.extent, shared_header_storage_data(1, row.alignment)?)?
            }
            MetadataRecordKind::Boxed => return Err(exhausted()),
        };
        add(total, bytes)
    })
}

fn ceilings(content: &ClientContent) -> (usize, usize, usize) {
    (
        content.maximum_bytes,
        content.maximum_objects,
        content.maximum_chunk,
    )
}

#[test]
fn borrowed_installation_and_replayed_partial_transfer_keep_unchanged_bounds() -> TestResult {
    let mut content = ClientContent::new(4096, 8, 5)?;
    let quote = content.original_internal_growth_storage_data(usize::MAX)?;
    let original_ceilings = ceilings(&content);
    let installed = b"independent borrowed installation";
    let installed_ref = canonical::content_ref(installed, "application/json")?;
    let received = b"incoming chunked bytes";
    let received_ref = canonical::content_ref(received, "application/json")?;
    let transfer_id = Id::new("internal-growth-transfer")?;

    content.install_borrowed(std::iter::once((&installed_ref, installed.as_slice())))?;
    content.begin(&BlobBeginRequest {
        transfer_id: transfer_id.clone(),
        content: received_ref.clone(),
        extensions: Extensions::new(),
    })?;
    assert!(observed_backing(&content)? <= quote.retained_requested_bytes_data());
    for (index, bytes) in received.chunks(5).enumerate() {
        let request = BlobChunkRequest {
            transfer_id: transfer_id.clone(),
            offset: U64::new((index * 5) as u64),
            bytes: Bytes::new(bytes.to_vec()),
            extensions: Extensions::new(),
        };
        content.chunk(&request)?;
        content.chunk(&request)?;
        assert!(observed_backing(&content)? <= quote.retained_requested_bytes_data());
    }
    content.finish(&BlobFinishRequest {
        transfer_id,
        extensions: Extensions::new(),
    })?;

    assert_eq!(content.get(&installed_ref)?, installed);
    assert_eq!(content.get(&received_ref)?, received);
    assert_eq!(ceilings(&content), original_ceilings);
    assert_eq!(
        content.original_internal_growth_storage_data(usize::MAX)?,
        quote
    );
    assert!(observed_backing(&content)? <= quote.retained_requested_bytes_data());
    let peak = sum(&[quote.retained, quote.transient, quote.scratch])?;
    assert_eq!(content.original_internal_growth_storage_data(peak)?, quote);
    assert!(
        content
            .original_internal_growth_storage_data(peak - 1)
            .is_err()
    );
    Ok(())
}

#[test]
fn empty_and_incomplete_transfers_still_keep_their_identity_and_shared_owners() -> TestResult {
    let mut content = ClientContent::new(1, 4, 1)?;
    let quote = content.original_internal_growth_storage_data(usize::MAX)?;
    let reference = canonical::content_ref(b"", "application/json")?;

    for index in 0..4 {
        content.begin(&BlobBeginRequest {
            transfer_id: Id::new(format!("empty-transfer-{index}"))?,
            content: reference.clone(),
            extensions: Extensions::new(),
        })?;
    }
    content.finish(&BlobFinishRequest {
        transfer_id: Id::new("empty-transfer-0")?,
        extensions: Extensions::new(),
    })?;

    assert_eq!(content.reserved, 0);
    assert_eq!(content.transfers.len(), 4);
    assert_eq!(content.objects.len(), 1);
    assert!(
        content
            .transfers
            .values()
            .any(|transfer| !transfer.complete)
    );
    assert!(observed_backing(&content)? <= quote.retained_requested_bytes_data());
    assert!(
        content
            .begin(&BlobBeginRequest {
                transfer_id: Id::new("one-transfer-too-many")?,
                content: reference,
                extensions: Extensions::new(),
            })
            .is_err()
    );
    assert_eq!(
        content.original_internal_growth_storage_data(usize::MAX)?,
        quote
    );
    Ok(())
}

#[test]
fn oversized_caller_owned_capacity_remains_an_independent_current_charge() -> TestResult {
    let mut content = ClientContent::new(128, 8, 8)?;
    let quote = content.original_internal_growth_storage_data(usize::MAX)?;
    let mut bytes = Vec::with_capacity(1_048_576);
    bytes.extend_from_slice(b"already owned caller bytes");
    let mut original = canonical::content_ref(&bytes, "application/json")?;
    original.media_type.reserve(1_048_576);
    let lookup = original.clone();
    content.install(original, bytes)?;
    let current = observed_backing(&content)?;

    assert!(current > quote.retained_requested_bytes_data());
    let added = b"new bounded internal allocation";
    let added_ref = canonical::content_ref(added, "application/json")?;
    content.install_borrowed(std::iter::once((&added_ref, added.as_slice())))?;

    assert!(observed_backing(&content)? <= add(current, quote.retained_requested_bytes_data())?);
    assert_eq!(
        content.original_internal_growth_storage_data(usize::MAX)?,
        quote
    );
    assert_eq!(content.get(&lookup)?, b"already owned caller bytes");
    assert_eq!(content.get(&added_ref)?, added);
    Ok(())
}

#[test]
fn checked_overflow_and_an_independent_empty_restriction_refuse_without_growth() -> TestResult {
    let content = ClientContent::new(usize::MAX, 1, 1)?;
    let before = ceilings(&content);
    assert!(
        content
            .original_internal_growth_storage_data(usize::MAX)
            .is_err()
    );
    assert_eq!(ceilings(&content), before);
    assert!(content.transfers.is_empty());
    assert!(content.objects.is_empty());

    let content = ClientContent::new(128, 2, 8)?;
    assert!(content.original_internal_growth_storage_data(0).is_err());
    assert_eq!(content.reserved, 0);
    assert!(content.transfers.is_empty());
    assert!(content.objects.is_empty());
    Ok(())
}
