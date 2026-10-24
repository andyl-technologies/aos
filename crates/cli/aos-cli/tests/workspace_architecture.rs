//! Checks production dependency boundaries across the AOS Rust monorepo.
//!
//! Bazel runs use the declared all-profile production graph. Cargo runs retain
//! an independent manifest oracle during migration. Both exclude development
//! dependencies because integration tests deliberately exercise adapters above
//! the portable interfaces they verify. Metadata-only packages cannot establish
//! independence: a dependency walk that reaches one fails closed.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use toml::Value;

struct Workspace {
    licenses: BTreeMap<String, String>,
    production: BTreeMap<String, BTreeSet<String>>,
}

#[derive(Deserialize)]
struct Architecture {
    schema_version: u32,
    packages: Vec<ArchitecturePackage>,
}

#[derive(Deserialize)]
struct ArchitecturePackage {
    name: String,
    license: String,
    production_targets: Vec<String>,
    production_dependencies: Option<Vec<String>>,
}

impl Workspace {
    fn load() -> Result<Self, Box<dyn Error>> {
        // Bazel must never silently fall back to the temporary Cargo oracle.
        if std::env::var_os("TEST_SRCDIR").is_some() {
            let metadata = Path::new(env!("CARGO_MANIFEST_DIR"))
                .ancestors()
                .map(|directory| directory.join("build/bazel-architecture.json"))
                .find(|path| path.is_file())
                .ok_or("Bazel architecture metadata is missing from declared test inputs")?;
            return Self::from_bazel_document(&fs::read_to_string(metadata)?);
        }

        Self::load_cargo()
    }

    fn from_bazel_document(document: &str) -> Result<Self, Box<dyn Error>> {
        let architecture: Architecture = serde_json::from_str(document)?;
        if architecture.schema_version != 1 || architecture.packages.is_empty() {
            return Err("unsupported or empty Bazel architecture metadata".into());
        }
        let mut licenses = BTreeMap::new();
        let mut production = BTreeMap::new();

        for package in architecture.packages {
            if package.name.is_empty()
                || package.license.is_empty()
                || licenses
                    .insert(package.name.clone(), package.license)
                    .is_some()
            {
                return Err("invalid or duplicate Bazel architecture package".into());
            }
            match package.production_dependencies {
                Some(dependencies) if !package.production_targets.is_empty() => {
                    let declared_count = dependencies.len();
                    let dependencies: BTreeSet<_> = dependencies.into_iter().collect();
                    if dependencies.len() != declared_count {
                        return Err("duplicate Bazel architecture dependency".into());
                    }
                    production.insert(package.name, dependencies);
                }
                None if package.production_targets.is_empty() => {}
                _ => return Err("Bazel production targets and dependency model disagree".into()),
            }
        }

        Ok(Self {
            licenses,
            production,
        })
    }

    fn load_cargo() -> Result<Self, Box<dyn Error>> {
        let directory = workspace_directory()?;
        let workspace: Value = fs::read_to_string(directory.join("Cargo.toml"))?.parse()?;
        let members = workspace["workspace"]["members"]
            .as_array()
            .ok_or("workspace.members must be an array")?;
        let inherited = workspace["workspace"]["dependencies"]
            .as_table()
            .ok_or("workspace.dependencies must be a table")?;
        let mut licenses = BTreeMap::new();
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
            let declaration = &manifest["package"]["license"];
            let license = if declaration.get("workspace").and_then(Value::as_bool) == Some(true) {
                workspace["workspace"]["package"]["license"].as_str()
            } else {
                declaration.as_str()
            }
            .ok_or("package.license must be a string")?
            .to_owned();
            if licenses.insert(name, license).is_some() {
                return Err("duplicate Cargo architecture package".into());
            }
        }

        Ok(Self {
            licenses,
            production,
        })
    }

    fn assert_independent(&self, source: &str, forbidden: &[&str]) {
        assert!(
            self.licenses.contains_key(source),
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
            if self.licenses.contains_key(&package) {
                let dependencies = self.production.get(&package).unwrap_or_else(|| {
                    panic!("{source} reaches unmodeled production package {package}")
                });
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
        let license = workspace
            .licenses
            .get(package)
            .ok_or("missing boundary package")?;
        assert_eq!(license, "MIT OR Apache-2.0");
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

#[test]
fn bazel_metadata_preserves_licenses_and_production_edges() -> Result<(), Box<dyn Error>> {
    let workspace = Workspace::from_bazel_document(
        r#"{"schema_version":1,"packages":[
            {"name":"app","license":"Apache-2.0","production_targets":["//crates/app:lib"],
             "production_dependencies":["library","upstream"]},
            {"name":"library","license":"MIT OR Apache-2.0","production_targets":["//crates/library:lib"],
             "production_dependencies":[]}
        ]}"#,
    )?;

    assert_eq!(workspace.licenses["library"], "MIT OR Apache-2.0");
    assert_eq!(
        workspace.production["app"],
        BTreeSet::from(["library".to_owned(), "upstream".to_owned()])
    );
    workspace.assert_independent("app", &["forbidden"]);
    Ok(())
}

#[test]
fn bazel_metadata_rejects_invalid_or_ambiguous_catalogues() {
    let package = serde_json::json!({
        "name": "app", "license": "MIT", "production_targets": ["//crates/app:lib"],
        "production_dependencies": ["upstream"],
    });
    let valid = serde_json::json!({"schema_version": 1, "packages": [package.clone()]});
    let mut invalid = vec![
        serde_json::json!({"schema_version": 2, "packages": [package.clone()]}),
        serde_json::json!({"schema_version": 1, "packages": []}),
        serde_json::json!({"schema_version": 1, "packages": [package.clone(), package]}),
    ];
    for (field, value) in [
        ("name", serde_json::json!("")),
        ("license", serde_json::json!("")),
        ("production_dependencies", serde_json::Value::Null),
        (
            "production_dependencies",
            serde_json::json!(["upstream", "upstream"]),
        ),
        ("production_targets", serde_json::json!([])),
    ] {
        let mut document = valid.clone();
        document["packages"][0][field] = value;
        invalid.push(document);
    }

    for document in invalid {
        assert!(Workspace::from_bazel_document(&document.to_string()).is_err());
    }
}

#[test]
#[should_panic(expected = "app reaches unmodeled production package pending")]
fn bazel_metadata_rejects_unmodeled_reachable_packages() {
    let workspace = Workspace::from_bazel_document(
        r#"{"schema_version":1,"packages":[
            {"name":"app","license":"MIT","production_targets":["//crates/app:lib"],
             "production_dependencies":["pending"]},
            {"name":"pending","license":"MIT","production_targets":[],
             "production_dependencies":null}
        ]}"#,
    )
    .unwrap();

    workspace.assert_independent("app", &[]);
}
