//! Checks production dependency boundaries across the AOS Rust monorepo.
//!
//! The Cargo package name establishes ownership regardless of its member path.
//! Development dependencies are excluded because integration tests deliberately
//! exercise adapters above the portable interfaces they verify.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use toml::Value;

struct Workspace {
    manifests: BTreeMap<String, Value>,
    production: BTreeMap<String, BTreeSet<String>>,
}

impl Workspace {
    fn load() -> Result<Self, Box<dyn Error>> {
        let directory = workspace_directory()?;
        let workspace: Value = fs::read_to_string(directory.join("Cargo.toml"))?.parse()?;
        let members = workspace["workspace"]["members"]
            .as_array()
            .ok_or("workspace.members must be an array")?;
        let inherited = workspace["workspace"]["dependencies"]
            .as_table()
            .ok_or("workspace.dependencies must be a table")?;
        let mut manifests = BTreeMap::new();
        let mut production = BTreeMap::new();

        for member in members {
            let member = member.as_str().ok_or("workspace member must be a string")?;
            let manifest: Value =
                fs::read_to_string(directory.join(member).join("Cargo.toml"))?.parse()?;
            let name = manifest["package"]["name"]
                .as_str()
                .ok_or("package.name must be a string")?
                .to_owned();
            let mut dependencies = BTreeSet::new();
            collect_dependencies(&manifest, inherited, &mut dependencies);
            production.insert(name.clone(), dependencies);
            manifests.insert(name, manifest);
        }

        Ok(Self {
            manifests,
            production,
        })
    }

    fn assert_independent(&self, source: &str, forbidden: &[&str]) {
        assert!(
            self.manifests.contains_key(source),
            "missing package {source}"
        );
        let mut pending = vec![source.to_owned()];
        let mut visited = BTreeSet::new();

        while let Some(package) = pending.pop() {
            if !visited.insert(package.clone()) {
                continue;
            }
            assert!(
                !forbidden.contains(&package.as_str()),
                "{source} has a production dependency path to {package}"
            );
            if let Some(dependencies) = self.production.get(&package) {
                pending.extend(dependencies.iter().cloned());
            }
        }
    }
}

fn workspace_directory() -> Result<PathBuf, Box<dyn Error>> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .find(|directory| {
            fs::read_to_string(directory.join("Cargo.toml"))
                .is_ok_and(|manifest| manifest.lines().any(|line| line.trim() == "[workspace]"))
        })
        .map(Path::to_path_buf)
        .ok_or_else(|| "application package has no enclosing Cargo workspace".into())
}

fn collect_dependencies(
    manifest: &Value,
    inherited: &toml::map::Map<String, Value>,
    dependencies: &mut BTreeSet<String>,
) {
    for section in ["dependencies", "build-dependencies"] {
        if let Some(table) = manifest.get(section).and_then(Value::as_table) {
            for (alias, declaration) in table {
                let declaration =
                    if declaration.get("workspace").and_then(Value::as_bool) == Some(true) {
                        inherited.get(alias).unwrap_or(declaration)
                    } else {
                        declaration
                    };
                let package = declaration
                    .get("package")
                    .and_then(Value::as_str)
                    .unwrap_or(alias);
                dependencies.insert(package.to_owned());
            }
        }
    }

    if let Some(targets) = manifest.get("target").and_then(Value::as_table) {
        for target in targets.values() {
            collect_dependencies(target, inherited, dependencies);
        }
    }
}

#[test]
fn shared_foundation_remains_portable_and_project_independent() -> Result<(), Box<dyn Error>> {
    let workspace = Workspace::load()?;
    let dependencies = workspace
        .production
        .get("aos-core")
        .ok_or("missing aos-core")?;

    for dependency in dependencies {
        assert!(
            !dependency.starts_with("aos-") && !dependency.starts_with("crucible-"),
            "portable core imports project or domain capability {dependency}"
        );
    }
    workspace.assert_independent(
        "aos-core",
        &["clap", "git2", "libc", "nix", "openssl", "rustix", "tokio"],
    );
    Ok(())
}

#[test]
fn reusable_project_libraries_do_not_depend_on_their_applications() -> Result<(), Box<dyn Error>> {
    let workspace = Workspace::load()?;
    workspace.assert_independent("aos-deployment", &["aos-package-manager", "aos-cli"]);
    workspace.assert_independent(
        "aos-registry-authoring",
        &["aos-package-manager", "aos-cli"],
    );
    workspace.assert_independent(
        "aos-registry-client",
        &[
            "aos-package-manager",
            "aos-cli",
            "aos-cli-ui",
            "indicatif",
            "console",
            "terminal_size",
        ],
    );
    workspace.assert_independent("aos-hub-db", &["aos-hub-service", "aos-hub-native"]);
    workspace.assert_independent("crucible-control-api", &["crucible-qemu-host"]);
    workspace.assert_independent("crucible-control-client", &["crucible-qemu-host"]);
    Ok(())
}

#[test]
fn qemu_boundary_remains_permissive_and_independent() -> Result<(), Box<dyn Error>> {
    let workspace = Workspace::load()?;

    for package in ["crucible-qemu-protocol", "crucible-qemu-shmem"] {
        let manifest = workspace
            .manifests
            .get(package)
            .ok_or("missing boundary package")?;
        assert_eq!(
            manifest["package"]["license"].as_str(),
            Some("MIT OR Apache-2.0")
        );
        workspace.assert_independent(
            package,
            &[
                "crucible-qemu-host",
                "crucible-qemu-plugin",
                "crucible-qemu-debug-gateway",
            ],
        );
    }
    Ok(())
}
