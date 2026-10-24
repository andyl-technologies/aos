//! Larger transactions retaining per-source authentication and one durable cut.

use super::*;

fn inputs() -> Vec<(ContentId, BlobHandle, Arc<std::sync::atomic::AtomicUsize>)> {
    (0..256_u64)
        .map(|ordinal| {
            let mut bytes = [0x37; 32];
            bytes[..8].copy_from_slice(&ordinal.to_be_bytes());
            counted_input(&bytes)
        })
        .collect()
}

#[test]
fn full_width_authenticates_in_order_and_commits_one_pack_then_reopens() {
    let fixture = Fixture::new(b"prior object").expect("component fixture");
    let baseline = fixture.quota.resources.usage().expect("same bank");
    let supplied = inputs();
    let objects = supplied
        .iter()
        .map(|(id, source, _)| (*id, source.clone()))
        .collect::<Vec<_>>();
    let before = fixture
        .backend
        .load_index()
        .expect("old index")
        .header
        .generation;
    let receipts = fixture
        .backend
        .put_many_if_absent_with_boundary(&fixture.original, &objects, &mut || Ok(()))
        .expect("256 source transaction");

    assert_eq!(receipts.len(), 256);
    assert!(
        receipts
            .iter()
            .zip(&objects)
            .all(|(receipt, (id, source))| {
                receipt.id == *id
                    && receipt.is_durable()
                    && receipt
                        .placements
                        .iter()
                        .all(|placement| placement.logical_length == source.logical_length())
            })
    );
    assert!(
        supplied
            .iter()
            .all(|(_, _, opens)| opens.load(Ordering::SeqCst) == 1)
    );
    assert_eq!(
        fixture
            .backend
            .load_index()
            .expect("new index")
            .header
            .generation,
        before + 256
    );
    assert_eq!(
        fixture
            .backend
            .accounting()
            .expect("accounting")
            .logical_objects(),
        257
    );
    assert_eq!(fixture.backend.accounting().expect("accounting").packs(), 2);
    drop(receipts);
    assert_eq!(
        fixture.quota.resources.usage().expect("closed loans"),
        baseline
    );

    let reopened = PackedBlobBackend::open(
        "checked-packed",
        fixture._root.path(),
        MIN_TARGET_PACK_BYTES,
    )
    .expect("durable reopened index");
    for (ordinal, (id, _)) in objects.iter().enumerate() {
        let mut expected = [0x37; 32];
        expected[..8].copy_from_slice(&(ordinal as u64).to_be_bytes());
        let source = reopened
            .read_with_boundary(&fixture.original, *id, None, &mut || Ok(()))
            .expect("fresh authenticated placement");
        let body = source
            .read_all_with_boundary(&fixture.original, 32, &mut || Ok(()))
            .expect("full identity and EOF");
        assert_eq!(&*body, &expected);
    }
    assert_eq!(
        fixture.quota.resources.usage().expect("read loans closed"),
        baseline
    );
}

#[test]
fn above_width_refuses_before_opening_any_source_or_publishing() {
    let fixture = Fixture::new(b"prior object").expect("component fixture");
    let (id, source, opens) = counted_input(b"new object");
    let objects = vec![(id, source); 257];
    let before = fs::read(fixture.backend.index_path()).expect("old index");
    let error = fixture
        .backend
        .put_many_if_absent_with_boundary(&fixture.original, &objects, &mut || Ok(()))
        .expect_err("strict transaction bound");
    assert!(matches!(error, StoreError::Quota));
    assert_eq!(opens.load(Ordering::SeqCst), 0);
    assert_eq!(
        fs::read(fixture.backend.index_path()).expect("unchanged index"),
        before
    );
}

// Encode the actual near-overflow root through the production format. This
// is a component counter boundary, not an installed native/runtime history.
fn install_later_group_overflow(fixture: &Fixture) {
    let index = fixture.backend.load_index().expect("current root");
    let mut header = index.header;
    header.generation = u64::MAX - 64;
    let mut bytes = Vec::with_capacity(super::super::super::index_format::PAGE_BYTES);
    header
        .append(fixture.backend.configuration, index.body(), &mut bytes)
        .expect("valid encoded root boundary");
    fs::write(fixture.backend.index_path(), bytes).expect("actual component root");
}

#[test]
fn late_corrupt_source_precedes_future_whole_group_overflow() {
    let fixture = Fixture::new(b"prior object").expect("component fixture");
    install_later_group_overflow(&fixture);
    let supplied = inputs();
    let mut objects = supplied
        .iter()
        .map(|(id, source, _)| (*id, source.clone()))
        .collect::<Vec<_>>();
    let corrupt = objects[200].0;
    objects[200].1 = BlobHandle::from_bytes([0x19; 32]);
    let before = fs::read(fixture.backend.index_path()).expect("old index");
    let baseline = fixture.quota.resources.usage().expect("same bank");
    let error = fixture
        .backend
        .put_many_if_absent_with_boundary(&fixture.original, &objects, &mut || Ok(()))
        .expect_err("full ContentId authentication");
    let StoreError::PackedScope { source } = &error else {
        panic!("own actual failure: {error:?}")
    };
    assert!(matches!(source.work_failure(), Some(StoreError::Corrupt { id }) if *id == corrupt));
    assert_eq!(source.outcome(), PackedPublicationOutcome::default());
    assert!(
        supplied[..200]
            .iter()
            .all(|(_, _, count)| count.load(Ordering::SeqCst) == 1)
    );
    assert!(
        supplied[201..]
            .iter()
            .all(|(_, _, count)| count.load(Ordering::SeqCst) == 0)
    );
    assert_eq!(
        fs::read(fixture.backend.index_path()).expect("old durable root"),
        before
    );
    drop(error);
    assert_eq!(
        fixture.quota.resources.usage().expect("staging closed"),
        baseline
    );
}

#[test]
fn cancellation_after_source_65_has_no_intermediate_durable_index() {
    let fixture = Fixture::new(b"prior object").expect("component fixture");
    let supplied = inputs();
    let objects = supplied
        .iter()
        .map(|(id, source, _)| (*id, source.clone()))
        .collect::<Vec<_>>();
    let before = fs::read(fixture.backend.index_path()).expect("old index");
    let baseline = fixture.quota.resources.usage().expect("same bank");
    let error = fixture
        .backend
        .put_many_if_absent_with_boundary(&fixture.original, &objects, &mut || {
            if supplied[64].2.load(Ordering::SeqCst) != 0 {
                Err(StoreError::Unavailable)
            } else {
                Ok(())
            }
        })
        .expect_err("one-shot original callback");
    let StoreError::PackedScope { source } = &error else {
        panic!("own actual failure: {error:?}")
    };
    assert!(matches!(
        source.first_boundary(),
        Some(StoreError::Unavailable)
    ));
    assert_eq!(source.outcome(), PackedPublicationOutcome::default());
    assert_eq!(
        fs::read(fixture.backend.index_path()).expect("old durable root"),
        before
    );
    drop(error);
    assert_eq!(
        fixture
            .quota
            .resources
            .usage()
            .expect("same loans returned"),
        baseline
    );
}

#[test]
fn denied_transaction_metadata_precedes_source_effects() {
    let fixture = Fixture::new(b"prior object").expect("component fixture");
    let baseline = fixture.quota.resources.usage().expect("same bank");
    let original = fixture.original.child().expect("same issuer child");
    let available = RESIDENT_BYTES - fixture.quota.resources.usage().expect("child control").1;
    let pressure = fixture
        .original
        .reserve_scratch_bytes(available - 1)
        .expect("existing-bank pressure");
    let supplied = inputs();
    let objects = supplied
        .iter()
        .map(|(id, source, _)| (*id, source.clone()))
        .collect::<Vec<_>>();
    let before = fs::read(fixture.backend.index_path()).expect("old index");
    let error = fixture
        .backend
        .put_many_if_absent_with_boundary(&original, &objects, &mut || Ok(()))
        .expect_err("paid transaction metadata");
    assert!(matches!(error, StoreError::DecodeAdmission { .. }));
    assert!(
        supplied
            .iter()
            .all(|(_, _, count)| count.load(Ordering::SeqCst) == 0)
    );
    assert_eq!(
        fs::read(fixture.backend.index_path()).expect("unchanged root"),
        before
    );
    drop((error, original, pressure));
    assert_eq!(
        fixture.quota.resources.usage().expect("same account"),
        baseline
    );
}

#[test]
fn actual_pack_write_refusal_precedes_future_whole_group_overflow() {
    let fixture = Fixture::new(b"prior object").expect("component fixture");
    install_later_group_overflow(&fixture);
    let supplied = inputs();
    let objects = supplied
        .iter()
        .map(|(id, source, _)| (*id, source.clone()))
        .collect::<Vec<_>>();
    let before = fs::read(fixture.backend.index_path()).expect("old root");
    let baseline = fixture.quota.resources.usage().expect("same original");
    let mut observed_write = false;
    let error = fixture
        .backend
        .put_many_if_absent_with_boundary(&fixture.original, &objects, &mut || {
            // Observe the actual private pack candidate after its first native
            // write. Published packs do not have this staging-name prefix.
            for entry in
                fs::read_dir(&fixture.backend.packs).map_err(|source| StoreError::StreamIo {
                    operation: "observe-component-pack-write",
                    source,
                })?
            {
                let entry = entry.map_err(|source| StoreError::StreamIo {
                    operation: "observe-component-pack-write",
                    source,
                })?;
                if entry
                    .file_name()
                    .as_encoded_bytes()
                    .starts_with(b".pack.tmp-")
                    && entry
                        .metadata()
                        .map_err(|source| StoreError::StreamIo {
                            operation: "observe-component-pack-write",
                            source,
                        })?
                        .len()
                        != 0
                {
                    observed_write = true;
                    return Err(StoreError::Unavailable);
                }
            }
            Ok(())
        })
        .expect_err("initiating post-pack-write boundary refusal");
    assert!(observed_write);
    let StoreError::PackedScope { source } = &error else {
        panic!("own actual publication failure: {error:?}");
    };
    assert!(matches!(
        source.first_boundary(),
        Some(StoreError::Unavailable)
    ));
    assert_eq!(source.outcome().durable_objects, 0);
    assert_eq!(
        fs::read(fixture.backend.index_path()).expect("old published root"),
        before
    );
    drop(error);
    assert_eq!(
        fixture
            .quota
            .resources
            .usage()
            .expect("candidate loans retired"),
        baseline
    );
}
