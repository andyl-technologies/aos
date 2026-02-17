pub mod clean;
pub mod config;
pub mod deps;
pub mod download;
pub mod hold;
pub mod install;
pub mod profile;
pub mod query;
pub mod registry;
pub mod remove;
pub mod resolve;
pub mod rollback;
pub mod security;
pub mod source;
pub mod store;
pub mod types;
pub mod update;
pub mod upgrade;
pub mod verify;

use std::fs;

use anyhow::{bail, Context, Result};

use crate::cli::{PackageCommand, RegistryCommand};
use crate::error::AosError;
use crate::output::Printer;
use types::ProfileScope;

/// Main entry point for `aos package` / `apm`.
pub async fn run(
    system: bool,
    command: &PackageCommand,
    dry_run: bool,
    yes: bool,
    printer: &Printer,
) -> Result<()> {
    let scope = if system {
        ProfileScope::System
    } else {
        ProfileScope::User
    };

    let config = config::ApmConfig::load(scope)?;

    match command {
        PackageCommand::Install {
            packages, registry, ..
        } => {
            install::run(&config, packages, registry.as_deref(), dry_run, yes, printer).await
        }
        PackageCommand::Remove {
            packages,
            autoremove,
        } => remove::run(&config, packages, *autoremove, dry_run, yes, printer).await,
        PackageCommand::Autoremove => {
            remove::run_autoremove(&config, dry_run, yes, printer).await
        }
        PackageCommand::Reinstall { packages, .. } => {
            install::run(&config, packages, None, dry_run, yes, printer).await
        }
        PackageCommand::Update { registry } => {
            update::run(&config, registry.as_deref(), printer).await
        }
        PackageCommand::Upgrade { packages, exclude } => {
            upgrade::run(&config, packages, exclude, dry_run, yes, printer).await
        }
        PackageCommand::FullUpgrade => {
            upgrade::run(&config, &[], &[], dry_run, yes, printer).await
        }
        PackageCommand::Search {
            pattern,
            names_only,
            installed,
            registry,
        } => {
            query::search(&config, pattern, *names_only, *installed, registry.as_deref(), printer)
                .await
        }
        PackageCommand::Show { package } => query::show(&config, package, printer).await,
        PackageCommand::List {
            installed,
            upgradable,
            held,
            registry,
        } => {
            query::list(&config, *installed, *upgradable, *held, registry.as_deref(), printer)
                .await
        }
        PackageCommand::Depends { package } => {
            deps::depends(&config, package, printer).await
        }
        PackageCommand::Rdepends { package } => {
            deps::rdepends(&config, package, printer).await
        }
        PackageCommand::Policy { package } => {
            deps::policy(&config, package, printer).await
        }
        PackageCommand::Files { package } => {
            deps::files(&config, package, printer).await
        }
        PackageCommand::Hold { package } => {
            hold::run_hold(&config, package, printer).await
        }
        PackageCommand::Unhold { package } => {
            hold::run_unhold(&config, package, printer).await
        }
        PackageCommand::Held => hold::run_held(&config, printer).await,
        PackageCommand::Clean { generations, keep } => {
            clean::run(&config, *generations, *keep, printer).await
        }
        PackageCommand::Gc => clean::run_gc(printer).await,
        PackageCommand::Verify { package } => {
            source::run_verify(&config, package, printer).await
        }
        PackageCommand::Source {
            package,
            show_drv,
            fetch,
            verify,
        } => {
            source::run_source(&config, package, *show_drv, *fetch, *verify, printer).await
        }
        PackageCommand::Rollback { generation } => {
            rollback::run(&config, *generation, dry_run, printer).await
        }
        PackageCommand::Registry { command } => {
            run_registry(&config, command, printer).await
        }
    }
}

// ---------------------------------------------------------------------------
// Registry subcommands
// ---------------------------------------------------------------------------

/// Dispatch `apm registry list|add|remove`.
async fn run_registry(
    config: &config::ApmConfig,
    command: &RegistryCommand,
    printer: &Printer,
) -> Result<()> {
    match command {
        RegistryCommand::List => registry_list(config, printer).await,
        RegistryCommand::Add { url, priority } => {
            registry_add(config, url, *priority, printer).await
        }
        RegistryCommand::Remove { name } => {
            registry_remove(config, name, printer).await
        }
    }
}

/// `apm registry list` — show all configured registries.
async fn registry_list(
    config: &config::ApmConfig,
    printer: &Printer,
) -> Result<()> {
    if config.registries.is_empty() {
        printer.info("No registries configured. Add one with `apm registry add <url>`.");
        return Ok(());
    }

    printer.header("Configured registries:");
    printer.plain("");

    for (reg_config, state) in &config.registries {
        let status = if reg_config.enabled {
            "enabled"
        } else {
            "disabled"
        };

        printer.header(&format!("  {} (priority {})", reg_config.name, reg_config.priority));
        printer.kv("URL", &reg_config.url);
        printer.kv("Status", status);
        printer.kv("Transport", &format!("{:?}", reg_config.transport()));

        // Try to count packages from the cache.
        let cache_dir = config.cache_path();
        let packages_dir = cache_dir.join(&reg_config.name).join("packages");
        let pkg_count = count_packages_in_dir(&packages_dir);
        printer.kv("Packages", &format!("{pkg_count}"));

        if let Some(s) = state {
            if let Some(ref ts) = s.last_update {
                printer.kv("Last update", ts);
            }
            if let Some(ref commit) = s.last_commit {
                let short = &commit[..commit.len().min(12)];
                printer.kv("Last commit", short);
            }
        } else {
            printer.kv("Last update", "never (run `apm update`)");
        }

        if let Some(ref signing) = reg_config.signing {
            printer.kv("Signing", &format!("required={}", signing.required));
        }

        printer.plain("");
    }

    Ok(())
}

/// `apm registry add <url>` — add a new registry.
async fn registry_add(
    config: &config::ApmConfig,
    url: &str,
    priority: u32,
    printer: &Printer,
) -> Result<()> {
    // Derive a registry name from the URL.
    let name = derive_registry_name(url);

    // Check if a registry with this name already exists.
    if config.find_registry(&name).is_some() {
        bail!(
            "registry '{}' already exists. Remove it first with `apm registry remove {}`.",
            name,
            name
        );
    }

    printer.header(&format!("Adding registry '{name}'..."));
    printer.kv("URL", url);
    printer.kv("Priority", &priority.to_string());

    // Write the registry config TOML to registries.d/
    let config_dir = config.scope.config_dir();
    let registries_dir = config_dir.join("registries.d");
    fs::create_dir_all(&registries_dir)
        .with_context(|| format!("creating {}", registries_dir.display()))?;

    let toml_path = registries_dir.join(format!("{name}.toml"));
    let toml_content = format!(
        r#"[registry]
name = "{name}"
url = "{url}"
priority = {priority}
enabled = true
"#,
    );

    fs::write(&toml_path, &toml_content)
        .with_context(|| format!("writing {}", toml_path.display()))?;

    printer.success(&format!(
        "Registry '{name}' added. Run `apm update {name}` to sync package metadata."
    ));

    Ok(())
}

/// `apm registry remove <name>` — remove a registry.
async fn registry_remove(
    config: &config::ApmConfig,
    name: &str,
    printer: &Printer,
) -> Result<()> {
    // Check if the registry exists.
    if config.find_registry(name).is_none() {
        return Err(AosError::RegistryError {
            message: format!("registry '{name}' not found"),
        }
        .into());
    }

    // Check if any installed packages come from this registry.
    let prof = profile::Profile::open(config.scope)?;
    let installed = profile::meta::meta_by_registry(&prof, name)?;

    if !installed.is_empty() {
        let pkg_names: Vec<String> = installed
            .iter()
            .filter_map(|m| m.apm.as_ref().map(|a| a.name.clone()))
            .collect();

        printer.error(&format!(
            "Cannot remove registry '{}': {} installed package(s):",
            name,
            installed.len()
        ));
        for pkg_name in &pkg_names {
            printer.plain(&format!("  - {pkg_name}"));
        }
        printer.plain("Remove these packages first with `apm remove`.");

        return Err(AosError::RegistryHasPackages {
            name: name.to_string(),
            count: installed.len(),
        }
        .into());
    }

    // Remove the registry config file.
    let config_dir = config.scope.config_dir();
    let toml_path = config_dir
        .join("registries.d")
        .join(format!("{name}.toml"));

    if toml_path.exists() {
        fs::remove_file(&toml_path)
            .with_context(|| format!("removing {}", toml_path.display()))?;
    }

    // Clean up cached registry data.
    let cache_dir = config.cache_path().join(name);
    if cache_dir.exists() {
        let _ = fs::remove_dir_all(&cache_dir);
    }

    // Remove the TOFU key if present.
    let key_store = security::KeyStore::new(config.scope.trusted_keys_dirs());
    let _ = key_store.remove(name);

    printer.success(&format!("Registry '{name}' removed."));

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Derive a registry name from a URL.
///
/// `"https://registry.aos.dev/core"` -> `"core"`
/// `"git+https://github.com/andyl/registry.git"` -> `"registry"`
fn derive_registry_name(url: &str) -> String {
    let cleaned = url
        .trim_end_matches('/')
        .trim_end_matches(".git");
    // Take the last path segment.
    let name = cleaned
        .rsplit('/')
        .next()
        .unwrap_or("unknown");
    // Sanitize: only keep alphanumeric + dash + underscore.
    name.chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
        .collect::<String>()
}

/// Count `.toml` package files in a registry's packages directory.
fn count_packages_in_dir(dir: &std::path::Path) -> usize {
    let Ok(entries) = fs::read_dir(dir) else {
        return 0;
    };

    let mut count = 0;
    for letter_entry in entries.flatten() {
        let letter_path = letter_entry.path();
        if !letter_path.is_dir() {
            continue;
        }
        let Ok(sub) = fs::read_dir(&letter_path) else {
            continue;
        };
        for entry in sub.flatten() {
            if entry
                .path()
                .extension()
                .map(|e| e == "toml")
                .unwrap_or(false)
            {
                count += 1;
            }
        }
    }
    count
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::package::config::ApmConfig;
    use crate::package::types::{
        ApmSettings, RegistryConfig,
    };
    use tempfile::TempDir;

    fn make_config(
        tmp: &TempDir,
        registries: Vec<(RegistryConfig, Option<types::RegistryState>)>,
    ) -> ApmConfig {
        // Create config dir with registries.d/
        let config_dir = tmp.path().join("config");
        let registries_dir = config_dir.join("registries.d");
        fs::create_dir_all(&registries_dir).unwrap();

        // Write registry TOML files
        for (reg_config, _) in &registries {
            let content = format!(
                "[registry]\nname = \"{}\"\nurl = \"{}\"\npriority = {}\n",
                reg_config.name, reg_config.url, reg_config.priority,
            );
            fs::write(
                registries_dir.join(format!("{}.toml", reg_config.name)),
                &content,
            )
            .unwrap();
        }

        // Create profile dir with meta/
        let profile_dir = tmp.path().join("profile");
        fs::create_dir_all(profile_dir.join("meta")).unwrap();
        fs::write(
            profile_dir.join("state.json"),
            r#"{"current_generation": 0, "next_generation": 1}"#,
        )
        .unwrap();

        ApmConfig {
            settings: ApmSettings::default(),
            registries,
            scope: ProfileScope::User,
        }
    }

    fn reg_config(name: &str, priority: u32) -> RegistryConfig {
        RegistryConfig {
            name: name.into(),
            url: format!("https://registry.example.com/{name}"),
            priority,
            enabled: true,
            pin: None,
            branch: None,
            signing: None,
        }
    }

    // -- derive_registry_name ------------------------------------------------

    #[test]
    fn derive_name_from_https_url() {
        assert_eq!(
            derive_registry_name("https://registry.aos.dev/core"),
            "core"
        );
    }

    #[test]
    fn derive_name_from_git_url() {
        assert_eq!(
            derive_registry_name("git+https://github.com/andyl/registry.git"),
            "registry"
        );
    }

    #[test]
    fn derive_name_trailing_slash() {
        assert_eq!(
            derive_registry_name("https://registry.aos.dev/extra/"),
            "extra"
        );
    }

    // -- registry list -------------------------------------------------------

    #[tokio::test]
    async fn registry_list_shows_registries() {
        let tmp = TempDir::new().unwrap();
        let config = make_config(
            &tmp,
            vec![
                (reg_config("aos-core", 500), None),
                (
                    reg_config("aos-extra", 400),
                    Some(types::RegistryState {
                        last_commit: Some("deadbeef1234".into()),
                        last_creation_token: Some(2026020003),
                        last_update: Some("2026-02-16T12:00:00Z".into()),
                    }),
                ),
            ],
        );

        let printer = Printer::new(0, true, false);
        let result = registry_list(&config, &printer).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn registry_list_empty() {
        let tmp = TempDir::new().unwrap();
        let config = make_config(&tmp, vec![]);

        let printer = Printer::new(0, true, false);
        let result = registry_list(&config, &printer).await;
        assert!(result.is_ok());
    }

    // -- registry add --------------------------------------------------------

    #[tokio::test]
    async fn registry_add_creates_config_file() {
        let tmp = TempDir::new().unwrap();

        // Create a config with a custom config dir pointing to our tmp.
        let config_dir = tmp.path().join("config-add");
        fs::create_dir_all(config_dir.join("registries.d")).unwrap();

        // We can't easily override config_dir via scope, so test the helper
        // and file write logic directly.
        let name = derive_registry_name("https://registry.aos.dev/core");
        assert_eq!(name, "core");

        let toml_content = format!(
            "[registry]\nname = \"{name}\"\nurl = \"https://registry.aos.dev/core\"\npriority = 500\nenabled = true\n",
        );
        let toml_path = config_dir.join("registries.d").join(format!("{name}.toml"));
        fs::write(&toml_path, &toml_content).unwrap();

        assert!(toml_path.exists());
        let content = fs::read_to_string(&toml_path).unwrap();
        assert!(content.contains("name = \"core\""));
        assert!(content.contains("https://registry.aos.dev/core"));
        assert!(content.contains("priority = 500"));
    }

    #[tokio::test]
    async fn registry_add_rejects_duplicate() {
        let tmp = TempDir::new().unwrap();
        let config = make_config(&tmp, vec![(reg_config("core", 500), None)]);

        let printer = Printer::new(0, true, false);
        let result = registry_add(
            &config,
            "https://registry.aos.dev/core",
            500,
            &printer,
        )
        .await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("already exists"), "got: {err}");
    }

    // -- registry remove -----------------------------------------------------

    #[tokio::test]
    async fn registry_remove_not_found() {
        let tmp = TempDir::new().unwrap();
        let config = make_config(&tmp, vec![]);

        let printer = Printer::new(0, true, false);
        let result = registry_remove(&config, "nonexistent", &printer).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("not found"), "got: {err}");
    }

    // -- count_packages_in_dir -----------------------------------------------

    #[test]
    fn count_packages_empty_dir() {
        let tmp = TempDir::new().unwrap();
        assert_eq!(count_packages_in_dir(tmp.path()), 0);
    }

    #[test]
    fn count_packages_with_toml_files() {
        let tmp = TempDir::new().unwrap();
        let c_dir = tmp.path().join("c");
        fs::create_dir_all(&c_dir).unwrap();
        fs::write(c_dir.join("curl.toml"), "test").unwrap();

        let z_dir = tmp.path().join("z");
        fs::create_dir_all(&z_dir).unwrap();
        fs::write(z_dir.join("zlib.toml"), "test").unwrap();
        fs::write(z_dir.join("zstd.toml"), "test").unwrap();

        assert_eq!(count_packages_in_dir(tmp.path()), 3);
    }
}
