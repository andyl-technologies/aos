//! Actual wide-batch codec, source ordering, duplicate and refusal controls.
//!
//! The existing portable fixture supplies its unchanged finite account. These
//! controls make no kernel-accounting or native-performance qualification claim.

use super::*;
use crate::ram::codec_ownership::PendingEnvelope;

fn page(index: u64) -> [u8; 64] {
    let mut bytes = [0; 64];
    fill_page(index, &mut bytes);
    bytes
}

fn duplicate_input(input: &crate::ram::PendingPublication) -> crate::ram::PendingPublication {
    let PendingEnvelope::OwnedSmall(envelope) = &input.envelope else {
        panic!("page input retains its actual owned small envelope");
    };
    crate::ram::PendingPublication {
        id: input.id,
        source: input.source.clone(),
        envelope: PendingEnvelope::OwnedSmall(envelope.clone()),
    }
}

#[test]
fn full_pending_batch_keeps_source_order_logarithmic_search_and_first_duplicate() {
    let directory = tempfile::tempdir().unwrap();
    let fixture = Fixture::new(directory.path());
    let retention = fixture.retention();
    let baseline = fixture.quota.0.usage().unwrap();
    let mut boundary = || Ok(());
    let mut work = Work::new(fixture.store.limits, &fixture.original, &mut boundary).unwrap();
    let prepared = fixture.quota.0.usage().unwrap();
    fixture.store.begin_publication_batch(&mut work).unwrap();
    let count = crate::ram::codec::MAX_PUBLICATION_BATCH_OBJECTS;
    let admitted = fixture.quota.0.usage().unwrap();
    let pending = work.pending.as_ref().unwrap();
    assert_eq!(std::mem::size_of_val(&pending.sorted_positions), 2 * count);
    assert!(
        admitted.1 - prepared.1
            >= (count * std::mem::size_of::<crate::ram::PendingPublication>()
                + std::mem::size_of::<crate::ram::PendingBatch>()) as u64
    );
    assert!(pending.is_empty());
    assert_eq!(count, 256);
    let mut expected = Vec::new();
    for index in 0..count {
        expected.push(
            fixture
                .store
                .put_page(&page(index as u64), &retention, &mut work)
                .unwrap()
                .0,
        );
    }
    let pending = work.pending.as_ref().unwrap();
    assert_eq!(pending.len(), count);
    assert_eq!(
        pending.iter().map(|object| object.id).collect::<Vec<_>>(),
        expected
    );
    assert!(
        pending.identity_comparisons.get() < count as u64 * 16,
        "actual lookup/insertion comparisons must remain below the old 32640 distinct-ID scans"
    );
    let comparisons = pending.identity_comparisons.get();
    let positions = pending.sorted_positions;
    let encoded = pending.encoded_bytes;
    let held = fixture.quota.0.usage().unwrap();

    assert_eq!(
        fixture
            .store
            .put_page(&page(0), &retention, &mut work)
            .unwrap()
            .0,
        expected[0]
    );
    let pending = work.pending.as_ref().unwrap();
    assert_eq!(
        pending.len(),
        count,
        "first-entry duplicate cannot flush a full batch"
    );
    assert_eq!(pending.identity_comparisons.get() - comparisons, 1);
    assert_eq!(pending.sorted_positions, positions);
    assert_eq!(pending.encoded_bytes, encoded);
    assert_eq!(fixture.quota.0.usage().unwrap(), held);

    let next = fixture
        .store
        .put_page(&page(count as u64), &retention, &mut work)
        .unwrap()
        .0;
    let pending = work.pending.as_ref().unwrap();
    assert_eq!(
        pending.len(),
        1,
        "the actual full batch published before its replacement input"
    );
    assert_eq!(pending.objects[0].id, next);
    assert_eq!(pending.sorted_positions[0], 0);
    assert_eq!(pending.identity_comparisons.get(), 0);
    fixture.store.flush_publication_batch(&mut work).unwrap();
    drop(work);
    assert_eq!(fixture.quota.0.usage().unwrap(), baseline);
}

#[test]
fn pending_capacity_and_invalid_position_refuse_before_index_or_source_mutation() {
    let directory = tempfile::tempdir().unwrap();
    let fixture = Fixture::new(directory.path());
    let retention = fixture.retention();
    let mut boundary = || Ok(());
    let mut work = Work::new(fixture.store.limits, &fixture.original, &mut boundary).unwrap();
    fixture.store.begin_publication_batch(&mut work).unwrap();
    fixture
        .store
        .put_page(&page(0), &retention, &mut work)
        .unwrap();
    let pending = work.pending.as_mut().unwrap();
    let positions = pending.sorted_positions;
    let encoded = pending.encoded_bytes;
    let input = duplicate_input(&pending.objects[0]);
    let held = fixture.quota.0.usage().unwrap();
    assert!(matches!(
        pending.push_at(2, input),
        Err(RamStoreError::Invalid("RAM publication insertion position"))
    ));
    assert_eq!(pending.len(), 1);
    assert_eq!(pending.sorted_positions, positions);
    assert_eq!(pending.encoded_bytes, encoded);
    assert_eq!(fixture.quota.0.usage().unwrap(), held);

    for index in 1..crate::ram::codec::MAX_PUBLICATION_BATCH_OBJECTS {
        fixture
            .store
            .put_page(&page(index as u64), &retention, &mut work)
            .unwrap();
    }
    let pending = work.pending.as_mut().unwrap();
    let positions = pending.sorted_positions;
    let encoded = pending.encoded_bytes;
    let input = duplicate_input(&pending.objects[0]);
    let held = fixture.quota.0.usage().unwrap();
    assert!(matches!(
        pending.push_at(pending.len(), input),
        Err(RamStoreError::Limit("RAM publication batch capacity"))
    ));
    assert_eq!(
        pending.len(),
        crate::ram::codec::MAX_PUBLICATION_BATCH_OBJECTS
    );
    assert_eq!(pending.sorted_positions, positions);
    assert_eq!(pending.encoded_bytes, encoded);
    assert_eq!(fixture.quota.0.usage().unwrap(), held);
}

#[test]
fn pending_duplicate_still_compares_exact_envelope_and_preserves_retry_state() {
    let directory = tempfile::tempdir().unwrap();
    let fixture = Fixture::new(directory.path());
    let retention = fixture.retention();
    let mut boundary = || Ok(());
    let mut work = Work::new(fixture.store.limits, &fixture.original, &mut boundary).unwrap();
    fixture.store.begin_publication_batch(&mut work).unwrap();
    let id = fixture
        .store
        .put_page(&page(0), &retention, &mut work)
        .unwrap()
        .0;
    let pending = work.pending.as_mut().unwrap();
    let positions = pending.sorted_positions;
    let encoded = pending.encoded_bytes;
    let PendingEnvelope::OwnedSmall(envelope) = &mut pending.objects[0].envelope else {
        panic!("owned small page");
    };
    crate::ram::codec_ownership::SharedEnvelope::get_mut(envelope)
        .unwrap()
        .body_mut()[36] ^= 1;
    let held = fixture.quota.0.usage().unwrap();

    let error = fixture
        .store
        .put_page(&page(0), &retention, &mut work)
        .unwrap_err();
    assert!(
        matches!(error, RamStoreError::Store(StoreError::Corrupt { id: found }) if found == id)
    );
    let pending = work.pending.as_mut().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending.sorted_positions, positions);
    assert_eq!(pending.encoded_bytes, encoded);
    assert_eq!(fixture.quota.0.usage().unwrap(), held);
    let PendingEnvelope::OwnedSmall(envelope) = &mut pending.objects[0].envelope else {
        panic!("owned small page");
    };
    crate::ram::codec_ownership::SharedEnvelope::get_mut(envelope)
        .unwrap()
        .body_mut()[36] ^= 1;
    assert_eq!(
        fixture
            .store
            .put_page(&page(0), &retention, &mut work)
            .unwrap()
            .0,
        id
    );
    assert_eq!(work.pending.as_ref().unwrap().len(), 1);
}

#[test]
fn original_callback_refusal_leaves_pending_index_and_input_custody_unchanged() {
    let directory = tempfile::tempdir().unwrap();
    let fixture = Fixture::new(directory.path());
    let retention = fixture.retention();
    let refuse = std::cell::Cell::new(false);
    let mut boundary = || {
        if refuse.get() {
            Err(RamStoreError::Canceled)
        } else {
            Ok(())
        }
    };
    let mut work = Work::new(fixture.store.limits, &fixture.original, &mut boundary).unwrap();
    fixture.store.begin_publication_batch(&mut work).unwrap();
    fixture
        .store
        .put_page(&page(0), &retention, &mut work)
        .unwrap();
    let pending = work.pending.as_ref().unwrap();
    let positions = pending.sorted_positions;
    let encoded = pending.encoded_bytes;
    let comparisons = pending.identity_comparisons.get();
    let held = fixture.quota.0.usage().unwrap();
    refuse.set(true);

    assert!(matches!(
        fixture.store.put_page(&page(1), &retention, &mut work),
        Err(RamStoreError::Canceled)
    ));
    let pending = work.pending.as_ref().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending.sorted_positions, positions);
    assert_eq!(pending.encoded_bytes, encoded);
    assert_eq!(pending.identity_comparisons.get(), comparisons);
    assert_eq!(fixture.quota.0.usage().unwrap(), held);
}
