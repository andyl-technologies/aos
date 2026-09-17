//! Atomic ordinary-package publication from one evaluated Nix inventory.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use aos_core::output::Printer;

use super::git::{commit_registry_paths, current_git_head, git, refresh_registry_object_store};
use super::package_contract::PackageContractSelectorRegistry;
use super::provenance::resolve_package_provenance_signer;
use super::publication_inventory::evaluate_package;
use super::publish::{
    RegistryPublishLock, ensure_writable_registry_clone, publish_canonical_named_output,
    publish_package_contract, publish_to_registry_directory,
};
use super::signing::resolve_producer_signing_key;
use super::store_paths::{
    first_letter, introspect_store_path, resolve_publish_platform,
    validate_store_path_release_policy,
};
use crate::config::ApmConfig;
use crate::registry::store;
use crate::types::validate_registry_name;

#[allow(clippy::too_many_arguments)]
pub(super) async fn publish_evaluated_package(
    config: &ApmConfig,
    registry_dir: &Path,
    registry_name: &str,
    store_path: &str,
    name_override: Option<&str>,
    version_override: Option<&str>,
    platform_override: Option<&str>,
    description: Option<&str>,
    homepage: Option<&str>,
    license: Option<&str>,
    maintainer: Option<&str>,
    previous: Option<&str>,
    source_drv: Option<&str>,
    bless: bool,
    no_ca: bool,
    no_commit: bool,
    message: Option<&str>,
    key: Option<&str>,
    key_id: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    if name_override.is_some()
        || version_override.is_some()
        || description.is_some()
        || homepage.is_some()
        || license.is_some()
        || maintainer.is_some()
        || source_drv.is_some()
    {
        bail!(
            "ordinary package publication takes name, version, documentation, and source identity from evaluated Nix metadata; manual metadata flags are valid only with --sysroot"
        );
    }
    if no_commit {
        bail!(
            "ordinary package publication is an atomic signed commit; --no-commit is valid only with --sysroot"
        );
    }

    validate_registry_name(registry_name)?;
    ensure_writable_registry_clone(registry_name, registry_dir)?;
    let info = introspect_store_path(store_path)?;
    validate_store_path_release_policy(&info)?;
    let platform = resolve_publish_platform(&info.path, platform_override)?;
    let (inventory, package) = evaluate_package(&info.path, &platform)?;
    let publication = package
        .publication
        .as_ref()
        .context("selected evaluated package lacks publication metadata")?;
    let maintainer = publication.maintainers.join(", ");
    let selectors = package
        .contract
        .as_ref()
        .map(|_| {
            PackageContractSelectorRegistry::from_inventory_contract(&inventory, &package.name)
        })
        .transpose()?;

    let signing_key =
        resolve_producer_signing_key(config, registry_dir, registry_name, key, key_id)?;
    let mut provenance_signer =
        resolve_package_provenance_signer(registry_dir, registry_name, Some(&signing_key), key_id)?;

    let _publish_lock = RegistryPublishLock::acquire(registry_dir)?;
    require_clean_publication_tree(registry_dir)?;
    let internal_printer = Printer::new(0, true, false);
    let publication_result = async {
        publish_to_registry_directory(
            config,
            registry_dir,
            registry_name,
            &info.path,
            Some(&package.name),
            Some(&publication.version),
            Some(&platform),
            Some(&publication.description),
            publication.homepage.as_deref(),
            Some(&publication.license_expression),
            Some(&maintainer),
            false,
            previous,
            Some(&package.derivation),
            &[],
            &[],
            &[],
            &[],
            &[],
            bless,
            no_ca,
            true,
            None,
            None,
            None,
            Some(&mut provenance_signer),
            &internal_printer,
        )
        .await?;

        for output in package.outputs.iter().filter(|output| output.name != "out") {
            publish_canonical_named_output(
                registry_dir,
                registry_name,
                &output.store_path,
                &package.name,
                &publication.version,
                &platform,
                &output.name,
                &internal_printer,
            )?;
        }

        if let Some(contract) = &package.contract {
            publish_package_contract(
                registry_dir,
                registry_name,
                &contract.document.store_path,
                &package.name,
                &publication.version,
                &platform,
                selectors
                    .as_ref()
                    .context("evaluated package contract lacks selector authority")?,
                &mut provenance_signer,
                &internal_printer,
            )
            .await?;
        }

        Ok::<(), anyhow::Error>(())
    }
    .await;
    if let Err(error) = publication_result {
        rollback_publication_tree(registry_dir)?;
        return Err(error.context("publishing the evaluated package transaction"));
    }

    let letter = first_letter(&package.name);
    let package_file = registry_dir
        .join("packages")
        .join(letter)
        .join(format!("{}.toml", package.name));
    let staged_paths = [
        package_file,
        registry_dir.join(store::STORE_DIR),
        registry_dir.join("provenance"),
        registry_dir.join("transparency"),
    ];
    let default_message = format!(
        "publish {} {} ({platform})",
        package.name, publication.version
    );
    let commit_message = message.unwrap_or(&default_message);
    if let Err(error) = commit_registry_paths(
        registry_dir,
        commit_message,
        &staged_paths,
        Some(signing_key.path()),
    ) {
        rollback_publication_tree(registry_dir)?;
        return Err(error.context("committing the evaluated package transaction"));
    }
    refresh_registry_object_store(registry_dir)?;

    if printer.json_if_active(&serde_json::json!({
        "action": "publish",
        "authority": "evaluated-derivation-inventory",
        "registry": registry_name,
        "package": package.name,
        "version": publication.version,
        "platform": platform,
        "store_path": info.path,
        "outputs": package.outputs,
        "contract": package.contract,
        "committed": true,
        "head": current_git_head(registry_dir)?,
    })) {
        return Ok(());
    }
    printer.success(&format!(
        "Published authenticated package {} {} ({platform}){}",
        package.name,
        publication.version,
        if package.contract.is_some() {
            " with its package contract"
        } else {
            ""
        }
    ));
    Ok(())
}

fn require_clean_publication_tree(dir: &Path) -> Result<()> {
    if !git(dir, &["status", "--porcelain", "--untracked-files=all"])?.is_empty() {
        bail!("atomic package publication requires a clean registry authoring tree");
    }
    Ok(())
}

fn rollback_publication_tree(dir: &Path) -> Result<()> {
    git(dir, &["read-tree", "-u", "--reset", "HEAD"])
        .context("restoring tracked registry files after failed publication")?;
    let untracked = git(dir, &["ls-files", "--others", "--exclude-standard"])?;
    let mut parents = Vec::new();
    for relative in untracked.lines().map(Path::new).filter(|relative| {
        ["packages", "store", "provenance", "transparency"]
            .iter()
            .any(|root| relative.starts_with(root))
    }) {
        let path = dir.join(relative);
        fs::remove_file(&path)
            .with_context(|| format!("removing partial publication file {}", path.display()))?;
        if let Some(parent) = path.parent() {
            parents.push(parent.to_path_buf());
        }
    }
    parents.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    parents.dedup();
    for parent in parents {
        remove_empty_ancestors(dir, parent)?;
    }
    Ok(())
}

fn remove_empty_ancestors(root: &Path, mut path: PathBuf) -> Result<()> {
    let relative = path
        .strip_prefix(root)
        .with_context(|| format!("publication path {} escaped registry root", path.display()))?;
    let top_level = relative
        .components()
        .next()
        .context("publication path has no registry-relative component")?;
    let boundary = root.join(top_level.as_os_str());
    while path != boundary {
        match fs::remove_dir(&path) {
            Ok(()) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::NotFound | ErrorKind::DirectoryNotEmpty
                ) =>
            {
                break;
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("removing empty directory {}", path.display()));
            }
        }
        let Some(parent) = path.parent() else {
            break;
        };
        path = parent.to_path_buf();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::{require_clean_publication_tree, rollback_publication_tree};
    use crate::registry_ops::test_support::init_authoring_clone;

    #[test]
    fn failed_transaction_restores_its_clean_authoring_tree() {
        let registry = TempDir::new().unwrap();
        init_authoring_clone(registry.path());
        fs::create_dir_all(registry.path().join("packages/d")).unwrap();
        let package = registry.path().join("packages/d/demo.toml");
        fs::write(&package, b"original\n").unwrap();
        crate::testutil::git(registry.path(), &["add", "packages/d/demo.toml"]);
        crate::testutil::git(registry.path(), &["commit", "-m", "package fixture"]);
        require_clean_publication_tree(registry.path()).unwrap();

        fs::write(&package, b"partial\n").unwrap();
        fs::create_dir_all(registry.path().join("store/aa")).unwrap();
        fs::write(registry.path().join("store/aa/new"), b"partial").unwrap();
        fs::create_dir_all(registry.path().join("provenance/d/demo")).unwrap();
        fs::write(
            registry.path().join("provenance/d/demo/partial.jsonl"),
            b"partial",
        )
        .unwrap();

        rollback_publication_tree(registry.path()).unwrap();

        assert_eq!(fs::read(&package).unwrap(), b"original\n");
        assert!(registry.path().join("packages").is_dir());
        assert!(!registry.path().join("store/aa/new").exists());
        assert!(
            !registry
                .path()
                .join("provenance/d/demo/partial.jsonl")
                .exists()
        );
        require_clean_publication_tree(registry.path()).unwrap();
    }
}
