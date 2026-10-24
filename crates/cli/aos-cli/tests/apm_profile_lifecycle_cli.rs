//! End-to-end CLI coverage for user profile lifecycle operations.
//!
//! The fixture publishes signed native packages and installs them through the
//! shipped CLI before exercising maintenance commands. Every test owns a private
//! Nix database and retains the real store protocol and admission checks.

#![cfg(unix)]

#[macro_use]
#[path = "support/binaries.rs"]
mod binaries;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde_json::Value;

#[cfg(unix)]
#[test]
fn apm_profile_lifecycle_cli_lists_holds_executes_and_rolls_back() -> Result<()> {
    let fixture = LifecycleFixture::new()?;
    fixture.write_profile()?;

    assert_eq!(fixture.run_profile_command("alpha")?, "alpha 2.0.0\n");
    assert_eq!(fixture.run_profile_command("beta")?, "beta 1.0.0\n");

    let installed = fixture.run_json(
        &["--json", "list", "--installed", "--registry", "lifecycle"],
        "list installed",
    )?;
    assert_package_list(
        &installed,
        &[
            ("alpha", "2.0.0", "installed"),
            ("beta", "1.0.0", "installed"),
        ],
    )?;

    let search = fixture.run_json(
        &["--json", "search", "alpha", "--registry", "lifecycle"],
        "search alpha",
    )?;
    assert_package_list(&search, &[("alpha", "2.0.0", "")])?;

    let shown = fixture.run_json(
        &["--json", "show", "alpha", "--registry", "lifecycle"],
        "show alpha",
    )?;
    assert_eq!(shown["name"], "alpha");
    assert_eq!(shown["version"], "2.0.0");
    assert_eq!(shown["registry"], "lifecycle");
    assert_eq!(shown["installed"], true);

    let policy = fixture.run_json(&["--json", "policy", "alpha"], "policy alpha")?;
    assert_eq!(policy["package"], "alpha");
    assert_eq!(policy["installed"], "2.0.0");
    assert_eq!(policy["candidate"], "2.0.0");
    assert_policy_versions(&policy, &[("2.0.0", true), ("1.0.0", false)])?;

    let files = fixture.run_json(&["--json", "files", "alpha"], "files alpha")?;
    assert_eq!(
        files,
        serde_json::json!(["bin/alpha", "nix-support/aos-target-platform"])
    );

    let held = fixture.run_json(&["--json", "held"], "held before hold")?;
    assert_eq!(
        held.as_array()
            .context("held output should be an array")?
            .len(),
        0
    );

    let held_alpha = fixture.run_json(&["--json", "hold", "alpha"], "hold alpha")?;
    assert_eq!(held_alpha["action"], "hold");
    assert_eq!(held_alpha["status"], "held");
    assert_eq!(held_alpha["package"], "alpha");
    assert_eq!(held_alpha["held"], true);

    let held = fixture.run_json(&["--json", "held"], "held after hold")?;
    assert_package_list(&held, &[("alpha", "2.0.0", "")])?;
    let listed_held = fixture.run_json(
        &["--json", "list", "--held", "--registry", "lifecycle"],
        "list held",
    )?;
    assert_package_list(&listed_held, &[("alpha", "2.0.0", "held")])?;

    let unheld_alpha = fixture.run_json(&["--json", "unhold", "alpha"], "unhold alpha")?;
    assert_eq!(unheld_alpha["action"], "unhold");
    assert_eq!(unheld_alpha["status"], "unheld");
    assert_eq!(unheld_alpha["package"], "alpha");
    assert_eq!(unheld_alpha["held"], false);

    let removed_beta = fixture.run_json(&["--json", "--yes", "remove", "beta"], "remove beta")?;
    assert_eq!(removed_beta["action"], "remove");
    assert_eq!(removed_beta["status"], "removed");
    assert_eq!(removed_beta["removed"], 1);
    assert_eq!(removed_beta["explicit_removed"], 1);
    assert_eq!(removed_beta["orphan_removed"], 0);
    assert_eq!(removed_beta["generation"], 3);
    assert_eq!(removed_beta["packages"][0]["name"], "beta");
    assert_eq!(fixture.current_generation()?, "gen-3");
    assert_eq!(fixture.run_profile_command("alpha")?, "alpha 2.0.0\n");
    assert!(
        !fixture.profile_bin("beta").exists(),
        "remove should delete beta from the active profile bin directory"
    );

    let installed = fixture.run_json(
        &["--json", "list", "--installed", "--registry", "lifecycle"],
        "list installed after remove",
    )?;
    assert_package_list(&installed, &[("alpha", "2.0.0", "installed")])?;

    let planned = fixture.run_json(
        &["--json", "--dry-run", "rollback", "--generation", "1"],
        "rollback dry-run",
    )?;
    assert_eq!(planned["action"], "rollback");
    assert_eq!(planned["status"], "planned");
    assert_eq!(planned["from_generation"], 3);
    assert_eq!(planned["to_generation"], 1);
    assert_root_names(&planned["restored"], &[("alpha", "1.0.0")])?;
    assert_root_names(&planned["removed"], &[("alpha", "2.0.0")])?;
    assert_eq!(fixture.run_profile_command("alpha")?, "alpha 2.0.0\n");

    let rolled_back = fixture.run_json(&["--json", "rollback", "--generation", "1"], "rollback")?;
    assert_eq!(rolled_back["action"], "rollback");
    assert_eq!(rolled_back["status"], "rolled_back");
    // Native rollback restores old roots in a new immutable generation.
    assert_eq!(rolled_back["generation"], 4);
    assert_eq!(fixture.current_generation()?, "gen-4");
    assert_eq!(fixture.run_profile_command("alpha")?, "alpha 1.0.0\n");
    assert!(
        !fixture.profile_bin("beta").exists(),
        "rollback should remove beta from the active profile bin directory"
    );

    let installed = fixture.run_json(
        &["--json", "list", "--installed", "--registry", "lifecycle"],
        "list installed after rollback",
    )?;
    assert_package_list(&installed, &[("alpha", "1.0.0", "installed")])?;

    let disabled = fixture.run_json(
        &["--json", "registry", "disable", "lifecycle"],
        "registry disable",
    )?;
    assert_eq!(disabled["action"], "registry_disable");
    assert_eq!(disabled["status"], "disabled");
    assert_eq!(disabled["registry"], "lifecycle");
    assert_eq!(disabled["enabled"], false);
    assert_eq!(disabled["previous_enabled"], true);
    assert_eq!(disabled["changed"], true);

    let orphans = fixture.run_json(&["--json", "orphans"], "orphans while disabled")?;
    assert_orphans(&orphans, &[])?;

    let installed = fixture.run_json(
        &["--json", "list", "--installed", "--registry", "lifecycle"],
        "list installed while disabled",
    )?;
    assert_package_list(&installed, &[("alpha", "1.0.0", "unavailable")])?;

    let enabled = fixture.run_json(
        &["--json", "registry", "enable", "lifecycle"],
        "registry enable",
    )?;
    assert_eq!(enabled["action"], "registry_enable");
    assert_eq!(enabled["status"], "enabled");
    assert_eq!(enabled["registry"], "lifecycle");
    assert_eq!(enabled["enabled"], true);
    assert_eq!(enabled["previous_enabled"], false);
    assert_eq!(enabled["changed"], true);

    let installed = fixture.run_json(
        &["--json", "list", "--installed", "--registry", "lifecycle"],
        "list installed after enable",
    )?;
    assert_package_list(&installed, &[("alpha", "1.0.0", "installed")])?;

    let removed = fixture.run_json(
        &["--json", "registry", "remove", "lifecycle", "--force"],
        "registry remove",
    )?;
    assert_eq!(removed["action"], "registry_remove");
    assert_eq!(removed["status"], "removed");
    assert_eq!(removed["registry"], "lifecycle");
    assert_eq!(removed["config_removed"], true);
    assert_eq!(removed["cache_removed"], true);
    assert!(
        !fixture
            .xdg_config
            .join("apm/registries.d/lifecycle.toml")
            .exists(),
        "registry remove should delete the config file"
    );
    assert_eq!(fixture.run_profile_command("alpha")?, "alpha 1.0.0\n");

    let orphans = fixture.run_json(&["--json", "orphans"], "orphans")?;
    assert_orphans(&orphans, &[("alpha", "1.0.0", "lifecycle")])?;

    let installed = fixture.run_json(&["--json", "list", "--installed"], "list orphaned")?;
    assert_package_list(&installed, &[("alpha", "1.0.0", "unavailable")])?;

    let search_installed = fixture.run_json(
        &["--json", "search", "--installed", "alpha"],
        "search installed orphaned",
    )?;
    assert_eq!(
        search_installed[0]["description"], "installed package unavailable in registry",
        "{search_installed}",
    );

    let orphan_policy = fixture.run_json(&["--json", "policy", "alpha"], "policy orphaned")?;
    assert_eq!(orphan_policy["installed"], "1.0.0");
    assert!(orphan_policy["candidate"].is_null(), "{orphan_policy}");
    assert_eq!(
        orphan_policy["versions"]
            .as_array()
            .context("policy versions should be an array")?
            .len(),
        0
    );
    assert_eq!(
        orphan_policy["unavailable_installed"],
        serde_json::json!([{"registry": "lifecycle", "version": "1.0.0"}])
    );

    Ok(())
}

#[cfg(unix)]
#[test]
fn apm_profile_lifecycle_cli_autoremoves_dependency_roots() -> Result<()> {
    let fixture = LifecycleFixture::with_dependency()?;
    fixture.write_autoremove_profile()?;

    assert_eq!(fixture.run_profile_command("beta")?, "beta 1.0.0\n");
    assert_eq!(
        fixture.run_profile_command("beta-helper")?,
        "beta-helper 1.0.0\n"
    );

    let removed = fixture.run_json(
        &["--json", "--yes", "remove", "--autoremove", "beta"],
        "remove beta with autoremove",
    )?;
    assert_eq!(removed["action"], "remove");
    assert_eq!(removed["status"], "removed");
    assert_eq!(removed["removed"], 2);
    assert_eq!(removed["explicit_removed"], 1);
    assert_eq!(removed["orphan_removed"], 1);
    assert_eq!(removed["generation"], 2);
    assert_eq!(removed["packages"][0]["name"], "beta");
    assert_eq!(removed["orphans"][0]["name"], "beta-helper");
    assert_eq!(fixture.current_generation()?, "gen-2");
    assert!(
        !fixture.profile_bin("beta").exists(),
        "remove --autoremove should delete beta from the active profile bin directory"
    );
    assert!(
        !fixture.profile_bin("beta-helper").exists(),
        "remove --autoremove should delete orphaned dependency commands"
    );

    let installed = fixture.run_json(
        &["--json", "list", "--installed", "--registry", "lifecycle"],
        "list installed after autoremove",
    )?;
    assert_package_list(&installed, &[])?;

    let rolled_back = fixture.run_json(&["--json", "rollback"], "rollback autoremove")?;
    assert_eq!(rolled_back["action"], "rollback");
    assert_eq!(rolled_back["status"], "rolled_back");
    assert_eq!(rolled_back["generation"], 3);
    assert_eq!(fixture.current_generation()?, "gen-3");
    assert_eq!(fixture.run_profile_command("beta")?, "beta 1.0.0\n");
    assert_eq!(
        fixture.run_profile_command("beta-helper")?,
        "beta-helper 1.0.0\n"
    );

    Ok(())
}

#[cfg(unix)]
#[test]
fn apm_profile_lifecycle_cli_full_upgrades_and_executes_new_generation() -> Result<()> {
    let fixture = LifecycleFixture::new()?;
    fixture.write_upgrade_profile()?;

    assert_eq!(fixture.current_generation()?, "gen-1");
    assert_eq!(fixture.run_profile_command("alpha")?, "alpha 1.0.0\n");

    let excluded = fixture.run_json(
        &["--json", "upgrade", "--exclude", "alpha"],
        "upgrade excluding alpha",
    )?;
    assert_eq!(excluded["action"], "upgrade");
    assert_eq!(excluded["status"], "held_back", "{excluded}");
    assert_eq!(excluded["upgraded"], 0, "{excluded}");
    assert_eq!(excluded["held_back"][0]["name"], "alpha");
    assert_eq!(excluded["held_back"][0]["old_version"], "1.0.0");
    assert_eq!(excluded["held_back"][0]["new_version"], "2.0.0");
    assert_eq!(fixture.current_generation()?, "gen-1");
    assert_eq!(fixture.run_profile_command("alpha")?, "alpha 1.0.0\n");

    let upgraded = fixture.run_json(&["--json", "--yes", "full-upgrade"], "full-upgrade")?;
    assert_eq!(upgraded["action"], "upgrade");
    assert_eq!(upgraded["status"], "upgraded", "{upgraded}");
    assert_eq!(upgraded["requested"], serde_json::json!([]));
    assert_eq!(upgraded["exclude"], serde_json::json!([]));
    assert_eq!(upgraded["upgraded"], 1, "{upgraded}");
    assert_eq!(upgraded["generation"], 2, "{upgraded}");
    assert_eq!(upgraded["downloads"]["planned"], 0, "{upgraded}");
    assert_eq!(upgraded["downloads"]["downloaded"], 0, "{upgraded}");
    assert_eq!(upgraded["downloads"]["imported"], 0, "{upgraded}");
    assert_eq!(upgraded["upgrades"][0]["name"], "alpha");
    assert_eq!(upgraded["upgrades"][0]["old_version"], "1.0.0");
    assert_eq!(upgraded["upgrades"][0]["new_version"], "2.0.0");
    assert_eq!(
        upgraded["upgrades"][0]["new_store_hash"],
        fixture.packages.alpha_v2.hash,
    );

    assert_eq!(fixture.current_generation()?, "gen-2");
    assert_eq!(fixture.run_profile_command("alpha")?, "alpha 2.0.0\n");
    assert!(
        !fixture
            .profile
            .join("meta")
            .join(format!("{}.json", fixture.packages.alpha_v1.hash))
            .exists(),
        "full-upgrade should remove obsolete alpha 1.0.0 metadata"
    );
    assert!(
        fixture
            .profile
            .join("meta")
            .join(format!("{}.json", fixture.packages.alpha_v2.hash))
            .exists(),
        "full-upgrade should write alpha 2.0.0 metadata"
    );

    let installed = fixture.run_json(
        &["--json", "list", "--installed", "--registry", "lifecycle"],
        "list installed after full-upgrade",
    )?;
    assert_package_list(&installed, &[("alpha", "2.0.0", "installed")])?;
    let nix_store_calls =
        fs::read_to_string(fixture.nix_store_log()).context("reading real nix-store call log")?;
    assert!(
        nix_store_calls.contains(&format!(
            "--check-validity {}",
            fixture.packages.alpha_v2.store_path.display()
        )),
        "full-upgrade should check the upgraded store path for validity:\n{nix_store_calls}",
    );

    Ok(())
}

#[cfg(unix)]
#[test]
fn apm_registry_dependency_cli_uses_store_graph() -> Result<()> {
    let fixture = LifecycleFixture::with_dependency()?;

    let depends = fixture.run_json(&["--json", "depends", "beta"], "depends beta")?;
    assert_eq!(depends["package"], "beta");
    assert_eq!(depends["registry"], "lifecycle");
    assert_eq!(depends["installed"], false);
    assert_eq!(depends["unique_store_paths"], 3);
    assert_dependency_tree(
        &depends["tree"],
        "beta",
        "1.0.0",
        &["unknown", "beta-helper"],
    )?;
    assert_eq!(
        depends["tree"]["children"][0]["store_hash"],
        depends["tree"]["children"][1]["children"][0]["store_hash"],
        "the shared shell dependency should be counted once",
    );

    fixture.write_profile()?;
    let rdepends = fixture.run_json(
        &["--json", "rdepends", "beta-helper"],
        "rdepends beta-helper",
    )?;
    assert_eq!(rdepends["package"], "beta-helper");
    assert_eq!(rdepends["target_versions"], "1.0.0");
    assert_package_list(&rdepends["dependents"], &[("beta", "1.0.0", "")])?;

    Ok(())
}

struct LifecycleFixture {
    temporary: tempfile::TempDir,
    xdg_config: PathBuf,
    profile: PathBuf,
    packages: LifecyclePackages,
    environment: BTreeMap<String, String>,
    manifest: PathBuf,
}

#[derive(serde::Deserialize)]
struct LifecyclePackages {
    alpha_v1: PackageFixture,
    alpha_v2: PackageFixture,
}

#[derive(serde::Deserialize)]
struct PackageFixture {
    hash: String,
    store_path: PathBuf,
}

impl LifecycleFixture {
    fn new() -> Result<Self> {
        Self::build(false)
    }

    fn with_dependency() -> Result<Self> {
        Self::build(true)
    }

    fn build(with_dependencies: bool) -> Result<Self> {
        let temporary = tempfile::TempDir::new()?;
        let manifest = PathBuf::from(
            std::env::var_os("AOS_LIFECYCLE_FIXTURES")
                .context("native lifecycle fixture manifest must be declared")?,
        );
        let metadata: Value = serde_json::from_slice(&fs::read(&manifest)?)?;
        let packages = serde_json::from_value(metadata["packages"].clone())?;
        run_registry_helper(temporary.path(), &manifest, "initialize", with_dependencies)?;

        let environment: BTreeMap<String, String> =
            serde_json::from_slice(&fs::read(temporary.path().join("environment.json"))?)?;
        let xdg_config = PathBuf::from(
            environment
                .get("XDG_CONFIG_HOME")
                .context("fixture config path")?,
        );
        let profile = temporary.path().join("profiles/per-user/apmtest");
        Ok(Self {
            temporary,
            xdg_config,
            profile,
            packages,
            environment,
            manifest,
        })
    }

    fn publish_upgrade(&self) -> Result<()> {
        run_registry_helper(
            self.temporary.path(),
            &self.manifest,
            "publish-upgrade",
            false,
        )
    }

    fn write_profile(&self) -> Result<()> {
        self.run_json(
            &[
                "--json",
                "--yes",
                "install",
                "alpha",
                "--registry",
                "lifecycle",
            ],
            "install initial alpha",
        )?;
        self.publish_upgrade()?;
        self.run_json(
            &[
                "--json",
                "--yes",
                "install",
                "alpha",
                "beta",
                "--registry",
                "lifecycle",
            ],
            "install updated profile",
        )?;
        Ok(())
    }

    fn write_autoremove_profile(&self) -> Result<()> {
        self.run_json(
            &[
                "--json",
                "--yes",
                "install",
                "beta",
                "--registry",
                "lifecycle",
            ],
            "install beta and its dependency",
        )?;
        Ok(())
    }

    fn write_upgrade_profile(&self) -> Result<()> {
        self.run_json(
            &[
                "--json",
                "--yes",
                "install",
                "alpha",
                "--registry",
                "lifecycle",
            ],
            "install initial alpha",
        )?;
        self.publish_upgrade()
    }

    fn nix_store_log(&self) -> PathBuf {
        self.temporary.path().join("nix-store-calls.log")
    }

    fn run_json(&self, args: &[&str], action: &str) -> Result<Value> {
        let output = Command::new(cli_binary!("CARGO_BIN_EXE_apm"))
            .envs(&self.environment)
            .args(args)
            .output()
            .with_context(|| format!("running apm {action}"))?;
        if !output.status.success() {
            let nix_store_calls = fs::read_to_string(self.nix_store_log()).unwrap_or_default();
            bail!(
                "apm {action} failed:\nstdout:\n{}\nstderr:\n{}\nnix-store calls:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
                nix_store_calls,
            );
        }
        assert!(
            output.stderr.is_empty(),
            "JSON apm {action} should keep stderr clean:\n{}",
            String::from_utf8_lossy(&output.stderr),
        );
        serde_json::from_slice(&output.stdout)
            .with_context(|| format!("parsing apm {action} JSON from stdout"))
    }

    fn run_profile_command(&self, command: &str) -> Result<String> {
        let profile_bin = self.profile_bin(command);
        let output = Command::new(&profile_bin)
            .envs(&self.environment)
            .env("PATH", path_with_prefix_first(&self.current_bin())?)
            .output()
            .with_context(|| format!("running profile command {}", profile_bin.display()))?;
        if !output.status.success() {
            bail!(
                "profile command {command} failed:\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    fn current_bin(&self) -> PathBuf {
        self.profile.join("current/bin")
    }

    fn profile_bin(&self, command: &str) -> PathBuf {
        self.current_bin().join(command)
    }

    fn current_generation(&self) -> Result<String> {
        Ok(fs::read_link(self.profile.join("current"))?
            .to_string_lossy()
            .into_owned())
    }
}

fn run_registry_helper(
    root: &Path,
    manifest: &Path,
    operation: &str,
    with_dependencies: bool,
) -> Result<()> {
    let python = std::env::var_os("AOS_LIFECYCLE_PYTHON")
        .context("AOS-built lifecycle fixture Python must be declared")?;
    let script = std::env::var_os("AOS_LIFECYCLE_REGISTRY_SCRIPT")
        .context("lifecycle registry producer must be declared")?;
    let mut command = Command::new(python);
    command.arg(script).arg(operation);
    if with_dependencies {
        command.arg("--with-dependencies");
    }
    let output = command
        .arg("--root")
        .arg(root)
        .arg("--fixtures")
        .arg(manifest)
        .args(["--apr", cli_binary!("CARGO_BIN_EXE_apr")])
        .args(["--apm", cli_binary!("CARGO_BIN_EXE_apm")])
        .args([
            "--runtime",
            cli_binary!("CARGO_BIN_EXE_aos-package-runtime"),
        ])
        .output()
        .context("running signed native lifecycle registry producer")?;
    if !output.status.success() {
        bail!(
            "lifecycle registry {operation} failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
    Ok(())
}

fn assert_package_list(json: &Value, expected: &[(&str, &str, &str)]) -> Result<()> {
    let entries = json.as_array().context("package list should be an array")?;
    assert_eq!(entries.len(), expected.len(), "{json}");
    for (entry, (name, version, status_fragment)) in entries.iter().zip(expected.iter()) {
        assert_eq!(entry["name"], *name, "{json}");
        assert_eq!(entry["version"], *version, "{json}");
        if !status_fragment.is_empty() {
            assert!(
                entry["status"]
                    .as_str()
                    .is_some_and(|status| status.contains(status_fragment)),
                "{json}",
            );
        }
    }
    Ok(())
}

fn assert_policy_versions(json: &Value, expected: &[(&str, bool)]) -> Result<()> {
    let versions = json["versions"]
        .as_array()
        .context("policy versions should be an array")?;
    assert_eq!(versions.len(), expected.len(), "{json}");
    for (entry, (version, installed)) in versions.iter().zip(expected.iter()) {
        assert_eq!(entry["version"], *version, "{json}");
        assert_eq!(entry["registry"], "lifecycle", "{json}");
        assert_eq!(entry["installed"], *installed, "{json}");
    }
    Ok(())
}

fn assert_orphans(json: &Value, expected: &[(&str, &str, &str)]) -> Result<()> {
    let entries = json.as_array().context("orphans should be an array")?;
    assert_eq!(entries.len(), expected.len(), "{json}");
    for (entry, (name, version, registry)) in entries.iter().zip(expected.iter()) {
        assert_eq!(entry["name"], *name, "{json}");
        assert_eq!(entry["version"], *version, "{json}");
        assert_eq!(entry["registry"], *registry, "{json}");
    }
    Ok(())
}

fn assert_dependency_tree(
    json: &Value,
    name: &str,
    version: &str,
    child_names: &[&str],
) -> Result<()> {
    assert_eq!(json["name"], name, "{json}");
    assert_eq!(json["version"], version, "{json}");
    let children = json["children"]
        .as_array()
        .context("dependency tree children should be an array")?;
    assert_eq!(children.len(), child_names.len(), "{json}");
    for (child, expected_name) in children.iter().zip(child_names.iter()) {
        assert_eq!(child["name"], *expected_name, "{json}");
    }
    Ok(())
}

fn assert_root_names(json: &Value, expected: &[(&str, &str)]) -> Result<()> {
    let entries = json.as_array().context("root list should be an array")?;
    let mut actual = entries
        .iter()
        .map(|entry| {
            (
                entry["package"]["name"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                entry["package"]["version"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
            )
        })
        .collect::<Vec<_>>();
    actual.sort();
    let mut expected = expected
        .iter()
        .map(|(name, version)| ((*name).to_string(), (*version).to_string()))
        .collect::<Vec<_>>();
    expected.sort();
    assert_eq!(actual, expected, "{json}");
    Ok(())
}

fn path_with_prefix_first(prefix: &Path) -> Result<std::ffi::OsString> {
    let mut paths = vec![prefix.to_path_buf()];
    if let Some(current) = std::env::var_os("PATH") {
        paths.extend(std::env::split_paths(&current));
    }
    std::env::join_paths(paths).context("joining PATH for profile command")
}
