//! Materialize the packaged Phase 5 fixtures against the selected guest files.

use std::error::Error;
use std::fs::{self, File};
use std::path::{Path, PathBuf};

use crucible::{ContentAddressedBlobRef, ContentHash, ScenarioDefForm, World};

const SEARCH_TEMPLATE: &str =
    include_str!("../../../tests/crucible/fixtures/live-qemu-search.scenario.toml");
const FUZZ_TEMPLATE: &str =
    include_str!("../../../tests/crucible/fixtures/live-qemu-fuzz.family.toml");

#[derive(Clone, Copy)]
struct GuestAssetHashes {
    kernel: ContentHash,
    root_image: ContentHash,
    initrd: ContentHash,
}

impl GuestAssetHashes {
    fn from_files(kernel: &Path, root_image: &Path, initrd: &Path) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            kernel: ContentHash::from_reader(File::open(kernel)?)?,
            root_image: ContentHash::from_reader(File::open(root_image)?)?,
            initrd: ContentHash::from_reader(File::open(initrd)?)?,
        })
    }
}

fn materialize_search(template: &str, hashes: GuestAssetHashes) -> Result<String, Box<dyn Error>> {
    let source = ScenarioDefForm::from_canonical_toml(template)?;
    let mut nodes = source
        .world()
        .vm_nodes()
        .into_iter()
        .cloned()
        .collect::<Vec<_>>();
    if nodes.len() != source.world().nodes().len() || nodes.is_empty() {
        return Err("Phase 5 search fixture must contain only VM nodes".into());
    }

    for node in &mut nodes {
        node.kernel = Some(ContentAddressedBlobRef::from_hash(hashes.kernel));
        node.root_image = Some(ContentAddressedBlobRef::from_hash(hashes.root_image));
        node.initrd = Some(ContentAddressedBlobRef::from_hash(hashes.initrd));
    }

    let world = World::from_nodes_and_links(nodes, source.world().links().to_vec())?;
    let materialized = ScenarioDefForm::from_components_with_measurements_and_app_random_draw_cap(
        &world,
        source.plan(),
        source.properties(),
        source.measurements(),
        source.seed(),
        source.app_random_draw_cap(),
    )?
    .with_selectables(source.selectables().clone())?;
    let canonical = materialized.to_canonical_toml()?;

    // Parsing the output checks its regenerated world and scenario identities.
    let checked = ScenarioDefForm::from_canonical_toml(&canonical)?;
    for node in checked.world().vm_nodes() {
        if node.kernel != Some(ContentAddressedBlobRef::from_hash(hashes.kernel))
            || node.root_image != Some(ContentAddressedBlobRef::from_hash(hashes.root_image))
            || node.initrd != Some(ContentAddressedBlobRef::from_hash(hashes.initrd))
        {
            return Err("materialized search fixture has a mismatched guest asset".into());
        }
    }
    Ok(canonical)
}

fn materialize_fuzz(
    template: &str,
    source: &ScenarioDefForm,
    hashes: GuestAssetHashes,
) -> Result<String, Box<dyn Error>> {
    let node = source
        .world()
        .vm_nodes()
        .into_iter()
        .next()
        .ok_or("Phase 5 search fixture has no VM node")?;
    let pairs = [
        (
            node.kernel.ok_or("search fixture has no kernel")?,
            hashes.kernel,
        ),
        (
            node.root_image.ok_or("search fixture has no root image")?,
            hashes.root_image,
        ),
        (
            node.initrd.ok_or("search fixture has no initrd")?,
            hashes.initrd,
        ),
    ];
    let mut materialized = template.to_owned();

    for (authored, selected) in pairs {
        let old = format!("blake3:{}", authored.hash().to_hex());
        if materialized.matches(&old).count() != 1 {
            return Err(format!("expected one family reference to {old}").into());
        }
        let new = format!("blake3:{}", selected.to_hex());
        materialized = materialized.replace(&old, &new);
    }

    let family: toml::Value = toml::from_str(&materialized)?;
    let node_template = family
        .get("node_template")
        .ok_or("materialized family has no node template")?;
    for (field, hash) in [
        ("kernel", hashes.kernel),
        ("root_image", hashes.root_image),
        ("initrd", hashes.initrd),
    ] {
        if node_template.get(field).and_then(toml::Value::as_str)
            != Some(format!("blake3:{}", hash.to_hex()).as_str())
        {
            return Err(format!("materialized family has a mismatched {field}").into());
        }
    }
    Ok(materialized)
}

fn main() -> Result<(), Box<dyn Error>> {
    let paths = std::env::args_os()
        .skip(1)
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    let [search_kernel, fuzz_kernel, root_image, initrd, output] = paths.as_slice() else {
        return Err(
            "usage: phase5_live_asset_fixture SEARCH_KERNEL FUZZ_KERNEL ROOT_IMAGE INITRD OUTPUT_DIR"
                .into(),
        );
    };
    let search_hashes = GuestAssetHashes::from_files(search_kernel, root_image, initrd)?;
    let fuzz_hashes = GuestAssetHashes {
        kernel: ContentHash::from_reader(File::open(fuzz_kernel)?)?,
        ..search_hashes
    };
    let source = ScenarioDefForm::from_canonical_toml(SEARCH_TEMPLATE)?;
    let search = materialize_search(SEARCH_TEMPLATE, search_hashes)?;
    let fuzz = materialize_fuzz(FUZZ_TEMPLATE, &source, fuzz_hashes)?;

    fs::create_dir_all(output)?;
    fs::write(output.join("search.scenario.toml"), search)?;
    fs::write(output.join("fuzz.family.toml"), fuzz)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_file_hashes_are_bound_to_both_packaged_fixtures() -> Result<(), Box<dyn Error>> {
        let search_hashes = GuestAssetHashes {
            kernel: ContentHash::from_bytes(b"selected search kernel"),
            root_image: ContentHash::from_bytes(b"selected root image"),
            initrd: ContentHash::from_bytes(b"selected initrd"),
        };
        let fuzz_hashes = GuestAssetHashes {
            kernel: ContentHash::from_bytes(b"selected fuzz kernel"),
            ..search_hashes
        };
        let source = ScenarioDefForm::from_canonical_toml(SEARCH_TEMPLATE)?;
        let search = materialize_search(SEARCH_TEMPLATE, search_hashes)?;
        let fuzz = materialize_fuzz(FUZZ_TEMPLATE, &source, fuzz_hashes)?;

        assert_ne!(search, SEARCH_TEMPLATE);
        assert_ne!(fuzz, FUZZ_TEMPLATE);
        assert!(!search.contains(&format!("blake3:{}", fuzz_hashes.kernel.to_hex())));
        assert!(!fuzz.contains(&format!("blake3:{}", search_hashes.kernel.to_hex())));
        for hash in [search_hashes.root_image, search_hashes.initrd] {
            let reference = format!("blake3:{}", hash.to_hex());
            assert!(search.contains(&reference));
            assert!(fuzz.contains(&reference));
        }
        assert!(search.contains(&format!("blake3:{}", search_hashes.kernel.to_hex())));
        assert!(fuzz.contains(&format!("blake3:{}", fuzz_hashes.kernel.to_hex())));
        Ok(())
    }
}
