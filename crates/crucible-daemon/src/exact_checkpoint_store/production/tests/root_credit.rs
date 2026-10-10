//! Credited RAM-root decoding and the lifetime of actual delayed readers.

use super::*;

#[test]
fn decoded_ram_root_credit_survives_the_last_delayed_reader_clone() {
    let _original_fixture_scope =
        crate::exact_checkpoint_store::test_support::fixture_decode_scope();

    let directory = tempfile::tempdir().expect("RAM-root credit fixture directory");
    let fixture = crucible_api::build_exact_ram_production_checkpoint_codec_fixture(
        &directory.path().join("source"),
    )
    .expect("authenticated persistent RAM fixture");
    let backend = Arc::new(DirectoryBlobBackend::new(
        "delayed-root-credit",
        directory.path().join("objects"),
    ));
    let retention = crucible_cas::ram::RamRetentionAuthority::new(Arc::new(
        crucible_cas::content_store::MemoryRefBackend::new(),
    ));
    let resources = crate::exact_checkpoint_store::test_support::fixture_ram_root_resources()
        .expect("finite component RAM-root credit");
    let store = ExactCheckpointStore::new(backend.clone(), 1 << 30, retention.clone())
        .expect("admit exact store")
        .with_ram_root_resources(Arc::clone(&resources));
    let prepared = store
        .prepare_production_closure(fixture.closure().clone())
        .expect("prepare complete RAM fixture");
    let checkpoint = store
        .publish_production_closure(&prepared)
        .expect("publish complete RAM fixture")
        .root();

    let uncredited = ExactCheckpointStore::new(backend, 1 << 30, retention.clone())
        .expect("store constructor grants no decode resources");
    assert!(matches!(
        uncredited.load_production_closure(checkpoint),
        Err(ExactCheckpointStoreError::UnsupportedBackend {
            capability: "checkpoint-metadata-resources"
        })
    ));
    let loaded = store
        .load_production_closure(checkpoint)
        .expect("authenticate credited root");
    let full_allowance = crate::exact_checkpoint_store::test_support::FIXTURE_RESIDENT_BYTES;
    assert!(matches!(
        resources.reserve_resources(0, full_allowance),
        Err(StoreError::Quota)
    ));
    drop(loaded);
    let released_metadata = resources
        .reserve_resources(0, full_allowance)
        .expect("last loaded metadata owner releases its complete decode credit");
    drop(released_metadata);

    let loaded = store
        .load_production_closure(checkpoint)
        .expect("authenticate complete returned-source inventory");
    let publication = retention
        .acquire()
        .expect("returned-source retention fence");
    let sources = loaded
        .prepare_paged_ram_sources(1 << 30, &publication, &mut || Ok(()))
        .expect("admit source container and immutable identities");
    assert_eq!(sources.len(), 1);
    let page_original = loaded
        .ram_original()
        .expect("same saved namespace parent")
        .clone();
    let source = sources[0].clone();
    assert!(std::ptr::eq(source.node(), sources[0].node()));
    drop(sources);
    drop(publication);
    drop(loaded);

    assert!(matches!(
        resources.reserve_resources(0, full_allowance),
        Err(StoreError::Quota)
    ));
    crucible_qemu::ram_source::QemuRamBacking::with_page_response(
        &source,
        "machine.ram",
        0,
        &mut || Ok(()),
        &mut |read, _| {
            read.proof()
                .verify(
                    read.bytes(),
                    source.root().record(),
                    source.root().logical_digest(),
                )
                .expect("scoped source proves its authenticated page");
            assert!(matches!(
                resources.reserve_resources(0, full_allowance),
                Err(StoreError::Quota)
            ));
        },
    )
    .expect("source clone retains cold-read and metadata authority");

    // The direct storage API independently retains a completion after
    // the scoped host response and its last source owner close.
    let page_account = page_original.child().expect("same saved operation bank");
    let read = source
        .store()
        .read_page_with_proof(source.root(), "machine.ram", 0, &page_account, &mut || {
            Ok(())
        })
        .expect("same original retains an independent storage completion");
    drop(page_account);
    drop(page_original);
    read.proof()
        .verify(
            read.bytes(),
            source.root().record(),
            source.root().logical_digest(),
        )
        .expect("returned source proves the same authenticated page");
    drop(source);
    assert!(matches!(
        resources.reserve_resources(0, full_allowance),
        Err(StoreError::Quota)
    ));
    drop(read);
    let released_sources = resources
        .reserve_resources(0, full_allowance)
        .expect("last page consumer releases its retained original decode loans");
    drop(released_sources);

    let loaded = store
        .load_production_closure(checkpoint)
        .expect("authenticate independent delayed-reader ownership");
    let publication = retention.acquire().expect("root claim publication fence");
    let lease = publication
        .retain_root(loaded.paged_ram_root_ids()[0])
        .expect("claim actual durable RAM root");
    let (ram_store, root, original) = loaded
        .open_paged_ram(0, lease, &mut || Ok(()))
        .expect("open actual credited delayed reader");
    drop(publication);
    let delayed = root.clone();
    drop(root);
    drop(loaded);
    drop(store);
    drop(prepared);

    assert!(matches!(
        resources.reserve_resources(0, full_allowance),
        Err(StoreError::Quota)
    ));
    let account = original.child().expect("same retained operation bank");
    let read = ram_store
        .read_page_with_proof(&delayed, "machine.ram", 0, &account, &mut || Ok(()))
        .expect("authenticate real cold page after every facade closes");
    assert_eq!(read.bytes().len(), 4096);
    read.proof()
        .verify(read.bytes(), delayed.record(), delayed.logical_digest())
        .expect("page proof retains the exact logical RAM authority");

    drop(delayed);
    assert!(matches!(
        resources.reserve_resources(0, full_allowance),
        Err(StoreError::Quota)
    ));
    drop(read);
    drop(account);
    drop(original);
    let reusable = resources
        .reserve_resources(0, full_allowance)
        .expect("last delayed borrower releases its original decode credit");
    drop(reusable);
}
