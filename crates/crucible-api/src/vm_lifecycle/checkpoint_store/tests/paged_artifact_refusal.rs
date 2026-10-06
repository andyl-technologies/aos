//! Verifies refusal of absent or altered device chunks by the current closure loader.

use super::*;

#[test]
fn paged_loader_rejects_missing_or_corrupt_device_chunks() -> Result<(), Box<dyn std::error::Error>>
{
    let _scope = crucible::test_support::fixture_decode_scope(256 * 1024 * 1024)
        .unwrap_or_else(|error| panic!("finite API component authority: {error}"));

    let store = tempfile::tempdir()?;
    let fixture = build_exact_ram_production_checkpoint_codec_fixture(store.path())?;
    let source = fixture.source();
    let scenario = source.scenario_def();
    let identity = fixture.closure().identity();
    let manifest = decode::decode_manifest_with_limits(
        fixture.closure().manifest(),
        source.plan().fault_signals().resource_limits(),
    )?;
    assert_eq!(manifest.format_version, MANIFEST_VERSION);
    let device = &manifest
        .targets
        .first()
        .ok_or("paged fixture has no target")?
        .exact_ram
        .device;
    let chunk = *device
        .chunks
        .first()
        .ok_or("device artifact has no chunks")?;
    let path = object_path(&object_parent(store.path(), scenario.id()), chunk);
    let original = fs::read(&path)?;
    assert!(!original.is_empty());
    load_exact_checkpoint_set(
        store.path(),
        &scenario,
        source,
        identity,
        Some(&crate::vm_lifecycle::checkpoint_store::test_support::test_ram_catalog_provider()),
    )?;

    // Keep the closure and all declared identities unchanged. The production
    // loader must reject the stored bytes before a restore admission exists.
    for missing in [false, true] {
        if missing {
            fs::remove_file(&path)?;
        } else {
            let mut corrupted = original.clone();
            corrupted[0] ^= 1;
            fs::write(&path, corrupted)?;
            assert_eq!(fs::metadata(&path)?.len(), u64::try_from(original.len())?);
        }

        let result = load_exact_checkpoint_set(
            store.path(),
            &scenario,
            source,
            identity,
            Some(&crate::vm_lifecycle::checkpoint_store::test_support::test_ram_catalog_provider()),
        );
        assert!(
            result.is_err(),
            "paged loader admitted {} device chunk",
            if missing { "absent" } else { "byte-corrupt" }
        );

        fs::write(&path, &original)?;
        load_exact_checkpoint_set(
            store.path(),
            &scenario,
            source,
            identity,
            Some(&crate::vm_lifecycle::checkpoint_store::test_support::test_ram_catalog_provider()),
        )?;
    }
    Ok(())
}

#[test]
fn paged_loader_rejects_corrupt_page_with_retained_root_metadata()
-> Result<(), Box<dyn std::error::Error>> {
    let _scope = crucible::test_support::fixture_decode_scope(256 * 1024 * 1024)
        .unwrap_or_else(|error| panic!("finite API component authority: {error}"));

    let store = tempfile::tempdir()?;
    let fixture = build_exact_ram_production_checkpoint_codec_fixture(store.path())?;
    let scenario = fixture.source().scenario_def();
    let identity = fixture.closure().identity();
    let source = fixture
        .closure()
        .ram_sources()
        .first()
        .ok_or("missing RAM source")?;
    let catalog = paged::PagedRamCatalog::open(
        store.path(),
        scenario.id(),
        fixture.source().plan().fault_signals().resource_limits(),
        Some(&crate::vm_lifecycle::checkpoint_store::test_support::test_ram_catalog_provider()),
    )?;
    let root = source.root().clone();
    assert_eq!(
        catalog
            .store()
            .read_page(&root, "machine.ram", 1, &mut || Ok(()))?,
        vec![0x7f; 4096]
    );
    load_exact_checkpoint_set(
        store.path(),
        &scenario,
        fixture.source(),
        identity,
        Some(&crate::vm_lifecycle::checkpoint_store::test_support::test_ram_catalog_provider()),
    )?;

    let (object, original) = catalog.corrupt_page_object_for_test(&root, "machine.ram", 1)?;
    assert!(
        catalog
            .store()
            .read_page(&root, "machine.ram", 1, &mut || Ok(()))
            .is_err()
    );
    assert!(
        catalog
            .open_root(root.object_id(), root.record(), &mut || Ok(()))
            .is_err()
    );
    assert!(
        load_exact_checkpoint_set(
            store.path(),
            &scenario,
            fixture.source(),
            identity,
            Some(&crate::vm_lifecycle::checkpoint_store::test_support::test_ram_catalog_provider())
        )
        .is_err()
    );
    assert!(fixture.closure().validate_complete().is_err());

    catalog.restore_object_for_test(object, &original)?;
    assert!(
        catalog
            .open_root(object, root.record(), &mut || Ok(()))
            .is_err()
    );
    assert_eq!(
        catalog
            .store()
            .read_page(&root, "machine.ram", 1, &mut || Ok(()))?,
        vec![0x7f; 4096]
    );
    load_exact_checkpoint_set(
        store.path(),
        &scenario,
        fixture.source(),
        identity,
        Some(&crate::vm_lifecycle::checkpoint_store::test_support::test_ram_catalog_provider()),
    )?;
    fixture.closure().validate_complete()?;
    Ok(())
}
