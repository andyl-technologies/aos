//! Guards normal dependency boundaries of portable wire and pure compiler roots.
//!
//! Workspace metadata does not prove isolated active feature selection or the
//! absence of external transport runtimes. Coordinator generation is checked
//! separately by the Proto crate's descriptor tests.

use std::collections::BTreeSet;
use std::error::Error;
use std::process::Command;

use serde_json::Value;

#[test]
fn portable_production_graphs_have_no_linux_or_effect_owner() -> Result<(), Box<dyn Error>> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = Command::new(&cargo)
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
    let roots: [(&str, &[&str]); 6] = [
        ("aos-sandbox-core", &["aos-sandbox-core"]),
        // Generic Journal DATA/framing mechanics remain an independently closed foundation.
        ("aos-sandbox-journal", &["aos-sandbox-journal"]),
        (
            "aos-sandbox-agent",
            &["aos-sandbox-agent", "aos-sandbox-core"],
        ),
        (
            "aos-sandbox-policy",
            &["aos-sandbox-policy", "aos-sandbox-core"],
        ),
        (
            "aos-sandbox-ownership",
            &[
                "aos-sandbox-ownership",
                "aos-sandbox-ownership-protocol",
                "aos-sandbox-core",
            ],
        ),
        (
            "aos-sandbox-protocol",
            &[
                "aos-sandbox-protocol",
                "aos-sandbox-policy",
                "aos-sandbox-ownership-protocol",
                "aos-sandbox-agent",
                "aos-sandbox-core",
                "aos-sandbox-journal",
                "aos-proto",
                "aos-sandbox-broker-session-protocol",
                "aos-sandbox-source-provider-protocol",
            ],
        ),
    ];
    for (root_name, allowed_path_packages) in roots {
        check_production_graph(root_name, allowed_path_packages, packages, &cargo)?;
    }
    Ok(())
}

// Keep each root's boundary independent: Protocol's wider wire closure must
// not permit an Agent, Core, or pure Policy dependency backedge.
fn check_production_graph(
    root_name: &str,
    allowed_path_packages: &[&str],
    packages: &[Value],
    cargo: &std::ffi::OsStr,
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

    // Resolve each real root with its own default features. Workspace metadata
    // can unify Domain's explicitly selected physical feature into this node.
    let output = Command::new(cargo)
        .args([
            "tree",
            "--package",
            root_name,
            "--edges",
            "normal",
            "--target",
            "all",
            "--prefix",
            "none",
            "--format",
            "{p}",
            "--locked",
            "--offline",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()?;
    assert!(
        output.status.success(),
        "Cargo dependency resolution failed: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    let graph = std::str::from_utf8(&output.stdout)?;
    let mut visited = BTreeSet::new();
    for line in graph.lines() {
        let name = line
            .split_whitespace()
            .next()
            .ok_or("missing package name")?;
        if !visited.insert(name) {
            continue;
        }
        let package = packages
            .iter()
            .find(|package| package["name"].as_str() == Some(name))
            .ok_or("missing package")?;
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
    }
    Ok(())
}
