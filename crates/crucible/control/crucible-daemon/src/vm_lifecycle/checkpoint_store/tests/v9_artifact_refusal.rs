//! Verifies refusal of absent or altered device chunks by the v9 closure loader.

use super::*;

#[test]
fn v9_loader_rejects_missing_or_corrupt_device_chunks() -> Result<(), Box<dyn std::error::Error>> {
    let store = tempfile::tempdir()?;
    let fixture = build_exact_ram_production_checkpoint_codec_fixture(store.path())?;
    let source = fixture.source();
    let scenario = source.scenario_def();
    let identity = fixture.closure().identity();
    let manifest = decode::decode_manifest_with_limits(
        fixture.closure().manifest(),
        source.plan().fault_signals().resource_limits(),
    )?;
    assert_eq!(manifest.format_version, 9);
    let device = &manifest
        .targets
        .first()
        .ok_or("v9 fixture has no target")?
        .exact_ram
        .device;
    let chunk = *device
        .chunks
        .first()
        .ok_or("device artifact has no chunks")?;
    let path = object_path(&object_parent(store.path(), scenario.id()), chunk);
    let original = fs::read(&path)?;
    assert!(!original.is_empty());
    load_exact_checkpoint_set(store.path(), &scenario, source, identity)?;

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

        let result = load_exact_checkpoint_set(store.path(), &scenario, source, identity);
        assert!(
            result.is_err(),
            "v9 loader admitted {} device chunk",
            if missing { "absent" } else { "byte-corrupt" }
        );

        fs::write(&path, &original)?;
        load_exact_checkpoint_set(store.path(), &scenario, source, identity)?;
    }
    Ok(())
}
