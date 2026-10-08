//! Guards the normal package dependency boundaries of the portable wire roots.
//!
//! Workspace metadata does not prove isolated active feature selection or the
//! absence of external transport runtimes. Coordinator generation is checked
//! separately by the Proto crate's descriptor tests.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::process::Command;

use serde_json::Value;

#[test]
fn portable_production_graphs_have_no_linux_or_effect_owner() -> Result<(), Box<dyn Error>> {
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

    let roots: [(&str, &[&str]); 3] = [
        ("aos-sandbox-core", &["aos-sandbox-core"]),
        (
            "aos-sandbox-agent",
            &["aos-sandbox-agent", "aos-sandbox-core"],
        ),
        (
            "aos-sandbox-protocol",
            &[
                "aos-sandbox-protocol",
                "aos-sandbox-agent",
                "aos-sandbox-core",
                "aos-proto",
                "aos-sandbox-broker-session-protocol",
                "aos-sandbox-source-provider-protocol",
            ],
        ),
    ];
    for (root_name, allowed_path_packages) in roots {
        check_production_graph(
            root_name,
            allowed_path_packages,
            packages,
            &packages_by_id,
            &nodes_by_id,
        )?;
    }
    Ok(())
}

// Keep each root's boundary independent: Protocol's wider wire closure must
// not permit an Agent or Core dependency backedge.
fn check_production_graph(
    root_name: &str,
    allowed_path_packages: &[&str],
    packages: &[Value],
    packages_by_id: &BTreeMap<&str, &Value>,
    nodes_by_id: &BTreeMap<&str, &Value>,
) -> Result<(), Box<dyn Error>> {
    let root = packages
        .iter()
        .find(|package| package["name"].as_str() == Some(root_name))
        .ok_or("missing portable root package")?;

    assert!(
        root["targets"]
            .as_array()
            .ok_or("missing targets")?
            .iter()
            .all(|target| !target["kind"]
                .as_array()
                .is_some_and(|kinds| { kinds.iter().any(|kind| kind.as_str() == Some("bin")) })),
        "portable root {root_name} must not own an executable target",
    );

    let mut pending = vec![root["id"].as_str().ok_or("missing portable root id")?];
    let mut visited = BTreeSet::new();
    while let Some(id) = pending.pop() {
        if !visited.insert(id) {
            continue;
        }
        let package = packages_by_id.get(id).ok_or("missing package")?;
        let name = package["name"].as_str().ok_or("missing package name")?;
        if package["source"].is_null() {
            assert!(
                allowed_path_packages.contains(&name),
                "portable root {root_name} reaches implementation crate {name}",
            );
        }
        assert!(
            !["nix", "rustix", "linux-raw-sys"].contains(&name),
            "portable root {root_name} reaches Linux dependency {name}",
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
