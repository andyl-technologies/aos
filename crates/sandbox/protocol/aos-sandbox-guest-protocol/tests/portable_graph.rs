//! Guards normal dependency boundaries of portable wire and pure compiler roots.
//!
//! Workspace metadata does not prove isolated active feature selection or the
//! absence of external transport runtimes. Coordinator generation is checked
//! separately by the Proto crate's descriptor tests.

use std::collections::BTreeSet;
use std::error::Error;
use std::process::Command;

use serde_json::Value;

#[derive(Clone, Copy)]
enum Boundary {
    Portable,
    LocalNative,
}

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
    let roots: [(&str, &[&str]); 7] = [
        ("aos-sandbox-model", &["aos-sandbox-model"]),
        // Generic Journal DATA/framing mechanics remain an independently closed foundation.
        ("aos-sandbox-journal", &["aos-sandbox-journal"]),
        (
            "aos-sandbox-guest-protocol",
            &["aos-sandbox-guest-protocol", "aos-sandbox-model"],
        ),
        (
            "aos-sandbox-policy",
            &[
                "aos-sandbox-policy",
                "aos-sandbox-protocol",
                "aos-sandbox-ownership-protocol",
                "aos-sandbox-guest-protocol",
                "aos-sandbox-model",
                "aos-sandbox-journal",
                "aos-sandbox-api",
                "aos-sandbox-broker-session-protocol",
                "aos-sandbox-source-provider-protocol",
                "aos-sandbox-source-provider-ledger",
            ],
        ),
        (
            "aos-sandbox-ownership-protocol",
            &[
                "aos-sandbox-ownership-protocol",
                "aos-sandbox-model",
            ],
        ),
        (
            "aos-sandbox-protocol",
            &[
                "aos-sandbox-protocol",
                "aos-sandbox-ownership-protocol",
                "aos-sandbox-guest-protocol",
                "aos-sandbox-model",
                "aos-sandbox-journal",
                "aos-sandbox-api",
                "aos-sandbox-broker-session-protocol",
                "aos-sandbox-source-provider-protocol",
                "aos-sandbox-source-provider-ledger",
            ],
        ),
        (
            "aos-sandbox-source-provider-ledger",
            &[
                "aos-sandbox-source-provider-ledger",
                "aos-sandbox-source-provider-protocol",
                "aos-sandbox-model",
            ],
        ),
    ];
    for (root_name, allowed_path_packages) in roots {
        check_production_graph(root_name, allowed_path_packages, packages, &cargo, Boundary::Portable)?;
    }

    // The local protected lease issuer owns native custody. Its protocol stays
    // portable, and its implementation must remain below Controller/Coordinator.
    check_production_graph(
        "aos-sandbox-ownership",
        &[
            "aos-sandbox-ownership",
            "aos-sandbox-ownership-protocol",
            "aos-sandbox-model",
            "aos-sandbox-journal",
            "aos-sandbox-linux",
            "aos-sandbox-broker",
            "aos-systemd-client",
            "aos-sandbox-protocol",
            "aos-sandbox-guest-protocol",
            "aos-sandbox-api",
            "aos-sandbox-broker-session-protocol",
            "aos-sandbox-source-provider-protocol",
            "aos-sandbox-source-provider-ledger",
        ],
        packages,
        &cargo,
        Boundary::LocalNative,
    )?;
    Ok(())
}

// Keep each root's boundary independent. Policy consumes Protocol's portable
// DATA; Protocol must not reach Policy, and Core and Agent stay narrower.
fn check_production_graph(
    root_name: &str,
    allowed_path_packages: &[&str],
    packages: &[Value],
    cargo: &std::ffi::OsStr,
    boundary: Boundary,
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
        "library root {root_name} must not own an executable target",
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
                "root {root_name} reaches implementation crate {name}",
            );
        }
        if matches!(boundary, Boundary::Portable) {
            assert!(
                !["nix", "rustix", "linux-raw-sys"].contains(&name),
                "portable root {root_name} reaches Linux dependency {name}",
            );
        }
    }
    Ok(())
}
