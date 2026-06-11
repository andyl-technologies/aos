//! End-to-end CLI coverage for user profile lifecycle operations.
//!
//! The fixture starts from a profile that looks like a consumer has already
//! installed packages from a registry, then drives ordinary `aos package`
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

    let planned = fixture.run_json(&["--json", "--dry-run", "rollback"], "rollback dry-run")?;
    assert_eq!(planned["action"], "rollback");
    assert_eq!(planned["status"], "planned");
    assert_eq!(planned["from_generation"], 2);
    assert_eq!(planned["to_generation"], 1);
    assert_root_names(&planned["restored"], &[("alpha", "1.0.0")])?;
    assert_root_names(
        &planned["removed"],
        &[("alpha", "2.0.0"), ("beta", "1.0.0")],
    )?;
    assert_eq!(fixture.run_profile_command("alpha")?, "alpha 2.0.0\n");

    let rolled_back = fixture.run_json(&["--json", "rollback"], "rollback")?;
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
    packages: LifecyclePackages,
}

struct LifecyclePackages {
    alpha_v1: PackageFixture,
    alpha_v2: PackageFixture,
    beta: PackageFixture,
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

    fn write_store_command(&self, package: &PackageFixture) -> Result<()> {
        let bin = package.store_path.join("bin");
        fs::create_dir_all(&bin)?;
        let command = bin.join(package.name);
        fs::write(
            &command,
            format!("printf '{} {}\\n'\n", package.name, package.version),
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
            replace_symlink(&package.store_path, &gen_dir.join("usr").join(package.hash))?;
            replace_symlink(
                &package.store_path.join("bin").join(package.name),
                &gen_dir.join("bin").join(package.name),
            )?;
            self.write_generation_meta(&gen_dir, package, false)?;
        }
        Ok(())
    }

    fn write_root_meta(&self, package: &PackageFixture, held: bool) -> Result<()> {
        write_meta_file(&self.profile.join("meta"), package, held)
    }

    fn write_generation_meta(
        &self,
        gen_dir: &Path,
        package: &PackageFixture,
        held: bool,
    ) -> Result<()> {
        write_meta_file(&gen_dir.join("meta"), package, held)
    }

    fn run_json(&self, args: &[&str], action: &str) -> Result<Value> {
        let output = self
            .package_command(args)
            .output()
            .with_context(|| format!("running aos package {action}"))?;
        if !output.status.success() {
            bail!(
                "aos package {action} failed:\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
        }
        assert!(
            String::from_utf8_lossy(&output.stderr).is_empty(),
            "JSON aos package {action} should keep stderr clean:\n{}",
            String::from_utf8_lossy(&output.stderr),
        );
        serde_json::from_slice(&output.stdout)
            .with_context(|| format!("parsing aos package {action} JSON from stdout"))
    }

    fn package_command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_aos"));
        command
            .env("HOME", &self.home)
            .env("USER", "apmtest")
            .env("XDG_CONFIG_HOME", &self.xdg_config)
            .env("XDG_DATA_HOME", &self.xdg_data)
            .env("XDG_CACHE_HOME", &self.xdg_cache)
            .env("AOS_PROFILE_ROOT", &self.profile_root)
            .env("APM_SYSTEM_CONFIG_DIR", &self.system_config)
            .arg("package")
            .args(args);
        command
    }

    fn run_profile_command(&self, command: &str) -> Result<String> {
        let output = Command::new("sh")
            .arg("-c")
            .arg(command)
            .env("PATH", path_with_profile_bin_first(&self.current_bin())?)
            .output()
            .with_context(|| format!("running profile command {command}"))?;
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

fn write_meta_file(dir: &Path, package: &PackageFixture, held: bool) -> Result<()> {
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
            "explicit": true,
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

fn path_with_profile_bin_first(profile_bin: &Path) -> Result<std::ffi::OsString> {
    let mut paths = vec![profile_bin.to_path_buf()];
    if let Some(current) = std::env::var_os("PATH") {
        paths.extend(std::env::split_paths(&current));
    }
    std::env::join_paths(paths).context("joining PATH for profile command")
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
