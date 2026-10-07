//! Guards the portable Agent's resolved production dependency boundary.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::process::Command;

use serde_json::Value;

#[test]
fn agent_production_graph_has_no_linux_or_effect_owner() -> Result<(), Box<dyn Error>> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = Command::new(cargo)
        .args(["metadata", "--format-version", "1", "--locked", "--offline"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()?;
    assert!(
        output.status.success(),
        "Cargo dependency resolution failed: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    let metadata: Value = serde_json::from_slice(&output.stdout)?;
    let packages = metadata["packages"].as_array().ok_or("missing packages")?;
    let nodes = metadata["resolve"]["nodes"]
        .as_array()
        .ok_or("missing resolved nodes")?;
    let packages_by_id: BTreeMap<_, _> = packages
        .iter()
        .filter_map(|package| package["id"].as_str().map(|id| (id, package)))
        .collect();
    let nodes_by_id: BTreeMap<_, _> = nodes
        .iter()
        .filter_map(|node| node["id"].as_str().map(|id| (id, node)))
        .collect();
    let root = packages
        .iter()
        .find(|package| package["name"].as_str() == Some("aos-sandbox-agent"))
        .ok_or("missing Agent package")?;

    assert!(
        root["targets"]
            .as_array()
            .ok_or("missing targets")?
            .iter()
            .all(|target| !target["kind"]
                .as_array()
                .is_some_and(|kinds| { kinds.iter().any(|kind| kind.as_str() == Some("bin")) })),
        "portable Agent must not own an executable target",
    );

    let mut pending = vec![root["id"].as_str().ok_or("missing Agent id")?];
    let mut visited = BTreeSet::new();
    while let Some(id) = pending.pop() {
        if !visited.insert(id) {
            continue;
        }
        let package = packages_by_id.get(id).ok_or("missing package")?;
        let name = package["name"].as_str().ok_or("missing package name")?;
        if package["source"].is_null() {
            assert!(
                ["aos-sandbox-agent", "aos-sandbox-core", "aos-proto"].contains(&name),
                "portable Agent reaches implementation crate {name}",
            );
        }
        assert!(
            !["nix", "rustix", "linux-raw-sys"].contains(&name),
            "portable Agent reaches Linux dependency {name}",
        );

        let node = nodes_by_id.get(id).ok_or("missing dependency node")?;
        for dependency in node["deps"].as_array().ok_or("missing dependencies")? {
            let kinds = dependency["dep_kinds"].as_array().ok_or("missing kinds")?;
            // Traverse normal edges on every declared target. Code generators
            // can use host tools without linking their implementation into a
            // wire consumer; build and test edges are deliberately separate.
            if kinds.iter().any(|kind| kind["kind"].is_null()) {
                pending.push(dependency["pkg"].as_str().ok_or("missing dependency id")?);
            }
        }
    }
    Ok(())
}
