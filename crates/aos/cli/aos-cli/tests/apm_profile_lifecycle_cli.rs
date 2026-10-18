//! End-to-end CLI coverage for user profile lifecycle operations.
//!
//! The fixture starts from a profile that looks like a consumer has already
//! installed packages from a registry, then drives ordinary `apm`
//! maintenance commands against that state.

#![cfg(unix)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde_json::Value;

#[cfg(unix)]
#[test]
fn apm_profile_lifecycle_cli_lists_holds_executes_and_rolls_back() -> Result<()> {
    let fixture = LifecycleFixture::new()?;
    fixture.write_registry_cache()?;
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
    assert_policy_versions(&policy, &[("2.0.0", true)])?;

    let files = fixture.run_json(&["--json", "files", "alpha"], "files alpha")?;
    assert_eq!(files, serde_json::json!(["bin/alpha"]));

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
    assert_eq!(rolled_back["generation"], 1);
    assert_eq!(fixture.current_generation()?, "gen-1");
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
    let fixture = LifecycleFixture::new()?;
    fixture.write_registry_cache()?;
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
    assert_eq!(rolled_back["generation"], 1);
    assert_eq!(fixture.current_generation()?, "gen-1");
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
    fixture.write_registry_cache()?;
    fixture.write_upgrade_profile()?;
    fixture.write_nix_store_check_validity_stub()?;

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
            .join("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.json")
            .exists(),
        "full-upgrade should remove obsolete alpha 1.0.0 metadata"
    );
    assert!(
        fixture
            .profile
            .join("meta")
            .join("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.json")
            .exists(),
        "full-upgrade should write alpha 2.0.0 metadata"
    );

    let installed = fixture.run_json(
        &["--json", "list", "--installed", "--registry", "lifecycle"],
        "list installed after full-upgrade",
    )?;
    assert_package_list(&installed, &[("alpha", "2.0.0", "installed")])?;
    let nix_store_calls = fs::read_to_string(fixture.nix_store_stub_log())
        .context("reading nix-store stub call log")?;
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
    let fixture = LifecycleFixture::new()?;
    fixture.write_registry_cache()?;
    fixture.write_dependency_store_records()?;

    let depends = fixture.run_json(&["--json", "depends", "beta"], "depends beta")?;
    assert_eq!(depends["package"], "beta");
    assert_eq!(depends["registry"], "lifecycle");
    assert_eq!(depends["installed"], false);
    assert_eq!(depends["unique_store_paths"], 2);
    assert_dependency_tree(&depends["tree"], "beta", "1.0.0", &["beta-helper"])?;

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
    _tmp: tempfile::TempDir,
    home: PathBuf,
    xdg_config: PathBuf,
    xdg_data: PathBuf,
    xdg_cache: PathBuf,
    profile_root: PathBuf,
    system_config: PathBuf,
    profile: PathBuf,
    tools_dir: PathBuf,
    packages: LifecyclePackages,
}

struct LifecyclePackages {
    alpha_v1: PackageFixture,
    alpha_v2: PackageFixture,
    beta: PackageFixture,
    beta_helper: PackageFixture,
}

#[derive(Clone)]
struct PackageFixture {
    name: &'static str,
    version: &'static str,
    hash: &'static str,
    store_path: PathBuf,
}

impl LifecycleFixture {
    fn new() -> Result<Self> {
        let tmp = tempfile::TempDir::new()?;
        let home = tmp.path().join("home");
        let xdg_config = tmp.path().join("xdg-config");
        let xdg_data = tmp.path().join("xdg-data");
        let xdg_cache = tmp.path().join("xdg-cache");
        let profile_root = tmp.path().join("profiles");
        let system_config = tmp.path().join("etc-apm");
        let profile = profile_root.join("per-user/apmtest");
        let tools_dir = tmp.path().join("tools");
        let store = tmp.path().join("store");

        let packages = LifecyclePackages {
            alpha_v1: PackageFixture::new(
                &store,
                "alpha",
                "1.0.0",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            alpha_v2: PackageFixture::new(
                &store,
                "alpha",
                "2.0.0",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ),
            beta: PackageFixture::new(&store, "beta", "1.0.0", "cccccccccccccccccccccccccccccccc"),
            beta_helper: PackageFixture::new(
                &store,
                "beta-helper",
                "1.0.0",
                "dddddddddddddddddddddddddddddddd",
            ),
        };

        Ok(Self {
            _tmp: tmp,
            home,
            xdg_config,
            xdg_data,
            xdg_cache,
            profile_root,
            system_config,
            profile,
            tools_dir,
            packages,
        })
    }

    fn write_registry_cache(&self) -> Result<()> {
        let config_dir = self.xdg_config.join("apm/registries.d");
        let registry_cache = self.xdg_data.join("apm/remote/lifecycle");
        fs::create_dir_all(&config_dir)?;
        fs::create_dir_all(registry_cache.join("packages/a"))?;
        fs::create_dir_all(registry_cache.join("packages/b"))?;
        fs::write(
            config_dir.join("lifecycle.toml"),
            "[registry]\nname = \"lifecycle\"\nurl = \"file:///unused-lifecycle-registry\"\n",
        )?;
        fs::write(
            registry_cache.join("packages/a/alpha.toml"),
            package_toml("alpha", &[&self.packages.alpha_v1, &self.packages.alpha_v2]),
        )?;
        fs::write(
            registry_cache.join("packages/b/beta.toml"),
            package_toml("beta", &[&self.packages.beta]),
        )?;
        fs::write(
            registry_cache.join("packages/b/beta-helper.toml"),
            package_toml("beta-helper", &[&self.packages.beta_helper]),
        )?;
        Ok(())
    }

    fn write_dependency_store_records(&self) -> Result<()> {
        // The `store/` realisation graph (RFC-0005): one sharded file per IA
        // store path, recording its blessed NAR and dependency edges. beta
        // depends on beta-helper; beta-helper is a leaf.
        const NAR: &str = "nar:sha256:1b8m6vizwgzrbq6ks7yk3pnjnj91xbcrz0v6dyqgxqkj3ka2lkfy:1";
        let store_dir = self.xdg_data.join("apm/remote/lifecycle/store");
        let write_record = |hash: &str, body: String| -> Result<()> {
            let dir = store_dir.join(&hash[..2]);
            fs::create_dir_all(&dir)?;
            fs::write(dir.join(hash), body)?;
            Ok(())
        };
        write_record(
            self.packages.beta.hash,
            format!("{NAR}\n\tia:sha256:{}\n", self.packages.beta_helper.hash),
        )?;
        write_record(self.packages.beta_helper.hash, format!("{NAR}\n"))?;
        Ok(())
    }

    fn write_profile(&self) -> Result<()> {
        fs::create_dir_all(self.profile.join("meta"))?;
        fs::write(
            self.profile.join("state.json"),
            r#"{"current_generation":2,"next_generation":3}"#,
        )?;

        self.write_store_command(&self.packages.alpha_v1)?;
        self.write_store_command(&self.packages.alpha_v2)?;
        self.write_store_command(&self.packages.beta)?;

        self.write_generation(1, &[&self.packages.alpha_v1])?;
        self.write_generation(2, &[&self.packages.alpha_v2, &self.packages.beta])?;
        replace_symlink(Path::new("gen-2"), &self.profile.join("current"))?;

        self.write_root_meta(&self.packages.alpha_v2, false)?;
        self.write_root_meta(&self.packages.beta, false)?;

        Ok(())
    }

    fn write_autoremove_profile(&self) -> Result<()> {
        fs::create_dir_all(self.profile.join("meta"))?;
        fs::write(
            self.profile.join("state.json"),
            r#"{"current_generation":1,"next_generation":2}"#,
        )?;

        self.write_store_command(&self.packages.beta)?;
        self.write_store_command(&self.packages.beta_helper)?;

        let gen_dir = self.profile.join("gen-1");
        fs::create_dir_all(gen_dir.join("usr"))?;
        fs::create_dir_all(gen_dir.join("meta"))?;
        fs::create_dir_all(gen_dir.join("bin"))?;
        self.link_package_into_generation(&gen_dir, &self.packages.beta, true)?;
        self.link_package_into_generation(&gen_dir, &self.packages.beta_helper, false)?;
        replace_symlink(Path::new("gen-1"), &self.profile.join("current"))?;

        self.write_root_meta(&self.packages.beta, false)?;
        self.write_root_auto_meta(&self.packages.beta_helper)?;

        Ok(())
    }

    fn write_upgrade_profile(&self) -> Result<()> {
        fs::create_dir_all(self.profile.join("meta"))?;
        fs::write(
            self.profile.join("state.json"),
            r#"{"current_generation":1,"next_generation":2}"#,
        )?;

        self.write_store_command(&self.packages.alpha_v1)?;
        self.write_store_command(&self.packages.alpha_v2)?;

        self.write_generation(1, &[&self.packages.alpha_v1])?;
        replace_symlink(Path::new("gen-1"), &self.profile.join("current"))?;
        self.write_root_meta(&self.packages.alpha_v1, false)?;

        Ok(())
    }

    fn write_nix_store_check_validity_stub(&self) -> Result<()> {
        let shell = find_shell()?;

        fs::create_dir_all(&self.tools_dir)?;
        fs::write(
            self.nix_store_valid_paths(),
            format!(
                "{}\n{}\n{}\n{}\n",
                self.packages.alpha_v1.store_path.display(),
                self.packages.alpha_v2.store_path.display(),
                self.packages.beta.store_path.display(),
                self.packages.beta_helper.store_path.display(),
            ),
        )?;
        let script = self.tools_dir.join("nix-store");
        fs::write(
            &script,
            format!(
                r#"#!{}
log="${{APM_NIX_STORE_STUB_LOG:?}}"
valid_paths="${{APM_NIX_STORE_STUB_VALID_PATHS:?}}"
printf '%s\n' "$*" >> "$log"

if [ "$1" = "--check-validity" ]; then
  shift
  for store_path in "$@"; do
    found=0
    while IFS= read -r valid_path; do
      if [ "$store_path" = "$valid_path" ]; then
        found=1
        break
      fi
    done < "$valid_paths"
    if [ "$found" != 1 ]; then
      printf '%s\n' "missing $store_path" >> "$log"
      exit 1
    fi
  done
  exit 0
fi
printf '%s\n' "unexpected nix-store invocation: $*" >&2
exit 64
"#,
                shell.display(),
            ),
        )?;
        make_executable(&script)?;
        Ok(())
    }

    fn nix_store_valid_paths(&self) -> PathBuf {
        self.tools_dir.join("nix-store-valid-paths")
    }

    fn nix_store_stub_log(&self) -> PathBuf {
        self.tools_dir.join("nix-store-calls.log")
    }

    fn write_store_command(&self, package: &PackageFixture) -> Result<()> {
        let shell = find_shell()?;
        let bin = package.store_path.join("bin");
        fs::create_dir_all(&bin)?;
        let command = bin.join(package.name);
        fs::write(
            &command,
            format!(
                "#!{}\nprintf '{} {}\\n'\n",
                shell.display(),
                package.name,
                package.version,
            ),
        )?;
        make_executable(&command)?;
        Ok(())
    }

    fn write_generation(&self, number: u32, packages: &[&PackageFixture]) -> Result<()> {
        let gen_dir = self.profile.join(format!("gen-{number}"));
        fs::create_dir_all(gen_dir.join("usr"))?;
        fs::create_dir_all(gen_dir.join("meta"))?;
        fs::create_dir_all(gen_dir.join("bin"))?;
        for package in packages {
            self.link_package_into_generation(&gen_dir, package, true)?;
        }
        Ok(())
    }

    fn link_package_into_generation(
        &self,
        gen_dir: &Path,
        package: &PackageFixture,
        explicit: bool,
    ) -> Result<()> {
        replace_symlink(&package.store_path, &gen_dir.join("usr").join(package.hash))?;
        replace_symlink(
            &package.store_path.join("bin").join(package.name),
            &gen_dir.join("bin").join(package.name),
        )?;
        self.write_generation_meta(gen_dir, package, false, explicit)
    }

    fn write_root_meta(&self, package: &PackageFixture, held: bool) -> Result<()> {
        write_meta_file(&self.profile.join("meta"), package, held, true)
    }

    fn write_root_auto_meta(&self, package: &PackageFixture) -> Result<()> {
        write_meta_file(&self.profile.join("meta"), package, false, false)
    }

    fn write_generation_meta(
        &self,
        gen_dir: &Path,
        package: &PackageFixture,
        held: bool,
        explicit: bool,
    ) -> Result<()> {
        write_meta_file(&gen_dir.join("meta"), package, held, explicit)
    }

    fn run_json(&self, args: &[&str], action: &str) -> Result<Value> {
        let output = self
            .package_command(args)?
            .output()
            .with_context(|| format!("running apm {action}"))?;
        if !output.status.success() {
            let nix_store_calls = fs::read_to_string(self.nix_store_stub_log()).unwrap_or_default();
            bail!(
                "apm {action} failed:\nstdout:\n{}\nstderr:\n{}\nnix-store calls:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
                nix_store_calls,
            );
        }
        assert!(
            String::from_utf8_lossy(&output.stderr).is_empty(),
            "JSON apm {action} should keep stderr clean:\n{}",
            String::from_utf8_lossy(&output.stderr),
        );
        serde_json::from_slice(&output.stdout)
            .with_context(|| format!("parsing apm {action} JSON from stdout"))
    }

    fn package_command(&self, args: &[&str]) -> Result<Command> {
        let mut command = Command::new(env!("CARGO_BIN_EXE_apm"));
        command
            .env("HOME", &self.home)
            .env("USER", "apmtest")
            .env("XDG_CONFIG_HOME", &self.xdg_config)
            .env("XDG_DATA_HOME", &self.xdg_data)
            .env("XDG_CACHE_HOME", &self.xdg_cache)
            .env("AOS_PROFILE_ROOT", &self.profile_root)
            .env("APM_SYSTEM_CONFIG_DIR", &self.system_config)
            .env("APM_NIX_STORE_STUB_LOG", self.nix_store_stub_log())
            .env(
                "APM_NIX_STORE_STUB_VALID_PATHS",
                self.nix_store_valid_paths(),
            )
            .env("PATH", path_with_prefix_first(&self.tools_dir)?)
            .args(args);
        Ok(command)
    }

    fn run_profile_command(&self, command: &str) -> Result<String> {
        let profile_bin = self.profile_bin(command);
        let output = Command::new(&profile_bin)
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
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
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
            .to_string())
    }
}

impl PackageFixture {
    fn new(store: &Path, name: &'static str, version: &'static str, hash: &'static str) -> Self {
        Self {
            name,
            version,
            hash,
            store_path: store.join(format!("{hash}-{name}-{version}")),
        }
    }
}

fn package_toml(name: &str, packages: &[&PackageFixture]) -> String {
    let platform = current_platform();
    let mut out = format!(
        r#"[package]
name = "{name}"
description = "{name} lifecycle fixture"
license = "MIT"
maintainer = "registry@example.com"
"#
    );
    for package in packages {
        out.push_str(&format!(
            r#"
[[versions]]
version = "{}"

{}
"#,
            package.version,
            fixture_platform_toml("x86_64-linux", package),
        ));
        if platform != "x86_64-linux" {
            out.push('\n');
            out.push_str(&fixture_platform_toml(&platform, package));
        }
    }
    out
}

fn fixture_platform_toml(platform: &str, package: &PackageFixture) -> String {
    format!(
        r#"[versions.platforms.{platform}]
store_path = "{}"
nar_hash = "sha256:placeholder"
nar_size = 1
closure_size = 1
source_drv = ""
source_nar_hash = ""
references = []
"#,
        package.store_path.display(),
    )
}

fn current_platform() -> String {
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        "arm" => "armv7l",
        other => other,
    };
    let os = match std::env::consts::OS {
        "linux" => "linux",
        "macos" => "darwin",
        other => other,
    };
    format!("{arch}-{os}")
}

fn write_meta_file(dir: &Path, package: &PackageFixture, held: bool, explicit: bool) -> Result<()> {
    fs::create_dir_all(dir)?;
    let meta = serde_json::json!({
        "store_path": package.store_path,
        "pushed_at": 1770000000_i64,
        "pushed_by": "apm",
        "expires_at": null,
        "is_root": true,
        "last_accessed": 1770000000_i64,
        "access_count": 0_u64,
        "apm": {
            "name": package.name,
            "version": package.version,
            "explicit": explicit,
            "registry": "lifecycle",
            "installed_at": "2026-02-16T00:00:00Z",
            "held": held,
            "source_drv": "",
            "source_nar_hash": "",
        }
    });
    fs::write(
        dir.join(format!("{}.json", package.hash)),
        serde_json::to_string_pretty(&meta)?,
    )?;
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

fn find_shell() -> Result<PathBuf> {
    let path = std::env::var_os("PATH").context("PATH must be set to locate sh")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join("sh");
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    bail!("sh not found in PATH");
}

#[cfg(unix)]
fn replace_symlink(target: &Path, link: &Path) -> Result<()> {
    use std::os::unix::fs::symlink;

    if let Some(parent) = link.parent() {
        fs::create_dir_all(parent)?;
    }
    if link.symlink_metadata().is_ok() {
        fs::remove_file(link)?;
    }
    symlink(target, link).with_context(|| {
        format!(
            "creating symlink {} -> {}",
            link.display(),
            target.display()
        )
    })
}

#[cfg(unix)]
fn make_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
        .with_context(|| format!("marking {} executable", path.display()))
}
