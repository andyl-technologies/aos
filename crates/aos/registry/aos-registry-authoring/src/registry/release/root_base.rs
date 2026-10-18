//! The root commit of a new registry as the base of its first release.
//!
//! `apr create` writes a registry's signed root commit and nothing else. Until
//! a surface serves the registry, that commit is the only base a canonical
//! release can start from: the release plans it, and the signed bootstrap
//! installs it on each surface before anything is published there.
//!
//! [`inspect_root_base`] reads that commit from the operator's authoring clone
//! and refuses any clone that holds more than the root commit, so a first
//! release can never quietly adopt unreviewed registry history as its base.

use std::path::Path;

use anyhow::{Context as _, Result, bail};
use git2::Repository;

/// Hex length of a SHA-256 Git object id.
const SHA256_OID_HEX_LENGTH: usize = 64;

/// Root commit and authoring name of a new registry's clone.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootRegistryBase {
    /// SHA-256 object id of the registry's only commit.
    pub commit: String,
    /// Local authoring name committed in the clone's `registry.toml`.
    pub name: String,
}

/// Reads the root commit of a clean authoring clone that holds nothing else.
///
/// Every reference in the clone must name that same root commit, so a branch,
/// tag, or stash carrying further history is refused as well as a `HEAD` that
/// has moved past the root.
///
/// # Errors
///
/// Returns an error when `source` is not a non-bare Git repository, has
/// uncommitted or untracked changes, does not use SHA-256 object ids, holds
/// any commit other than its root, has a reference that does not name a
/// commit, or lacks a valid registry manifest.
pub fn inspect_root_base(source: &Path) -> Result<RootRegistryBase> {
    let repository = Repository::open(source)
        .with_context(|| format!("opening source registry {}", source.display()))?;
    if repository.is_bare() {
        bail!(
            "source registry {} must be a working clone, not a bare repository",
            source.display()
        );
    }
    super::require_clean(&repository)?;

    let head = repository
        .head()
        .and_then(|head| head.peel_to_commit())
        .context("source registry has no HEAD commit")?;
    let commit = head.id().to_string();
    if commit.len() != SHA256_OID_HEX_LENGTH {
        bail!("source registry must use SHA-256 Git object ids");
    }
    if head.parent_count() != 0 {
        bail!("source registry HEAD {commit} is not the registry's root commit");
    }
    require_only_commit(&repository, head.id())?;

    let name = crate::registry_ops::local_registry_name(source)?;
    Ok(RootRegistryBase { commit, name })
}

/// Requires every commit reachable from any reference to be `root`.
fn require_only_commit(repository: &Repository, root: git2::Oid) -> Result<()> {
    let mut walk = repository.revwalk()?;
    walk.push(root)?;
    for reference in repository.references()? {
        let reference = reference?;
        let name = reference
            .name()
            .unwrap_or("<non-UTF-8 reference>")
            .to_owned();
        let target = reference
            .peel_to_commit()
            .with_context(|| format!("source registry reference {name} does not name a commit"))?;
        walk.push(target.id())?;
    }
    for oid in walk {
        if oid? != root {
            bail!(
                "source registry holds more than its root commit; a first release starts \
                 from a clone that `apr create` wrote and nothing else"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    /// Creates a single-commit SHA-256 registry clone named `name`.
    fn root_clone(directory: &Path, name: &str) -> Result<(Repository, git2::Oid)> {
        let mut options = git2::RepositoryInitOptions::new();
        options
            .object_format(git2::ObjectFormat::Sha256)
            .initial_head("stable");
        let repository = Repository::init_opts(directory, &options)?;
        fs::write(
            directory.join("registry.toml"),
            format!("[registry]\nname = \"{name}\"\n"),
        )?;
        let root = commit_all(&repository, "registry root", &[])?;
        Ok((repository, root))
    }

    /// Commits every worktree file on `HEAD` with the given parents.
    fn commit_all(
        repository: &Repository,
        message: &str,
        parents: &[git2::Oid],
    ) -> Result<git2::Oid> {
        let mut index = repository.index()?;
        index.add_all(["*"], git2::IndexAddOption::DEFAULT, None)?;
        index.write()?;
        let tree = repository.find_tree(index.write_tree()?)?;
        let author = git2::Signature::now("Registry author", "registry@example.invalid")?;
        let parents = parents
            .iter()
            .map(|parent| repository.find_commit(*parent))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let parents: Vec<&git2::Commit<'_>> = parents.iter().collect();
        Ok(repository.commit(Some("HEAD"), &author, &author, message, &tree, &parents)?)
    }

    fn error_text(result: Result<RootRegistryBase>) -> String {
        match result {
            Ok(base) => panic!("expected an error, inspected {base:?}"),
            Err(error) => format!("{error:#}"),
        }
    }

    #[test]
    fn accepts_a_clean_single_commit_clone() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let (_, root) = root_clone(temporary.path(), "andyl-experimental")?;

        let base = inspect_root_base(temporary.path())?;

        assert_eq!(base.commit, root.to_string());
        assert_eq!(base.commit.len(), SHA256_OID_HEX_LENGTH);
        assert_eq!(base.name, "andyl-experimental");
        Ok(())
    }

    #[test]
    fn refuses_untracked_and_modified_files() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        root_clone(temporary.path(), "main")?;

        fs::write(temporary.path().join("stray.txt"), "untracked\n")?;
        assert!(error_text(inspect_root_base(temporary.path())).contains("not clean"));

        fs::remove_file(temporary.path().join("stray.txt"))?;
        fs::write(
            temporary.path().join("registry.toml"),
            "[registry]\nname = \"other\"\n",
        )?;
        assert!(error_text(inspect_root_base(temporary.path())).contains("not clean"));
        Ok(())
    }

    #[test]
    fn refuses_history_beyond_the_root_commit() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let (repository, root) = root_clone(temporary.path(), "main")?;
        fs::write(temporary.path().join("README.md"), "second\n")?;
        let second = commit_all(&repository, "second", &[root])?;

        assert!(
            error_text(inspect_root_base(temporary.path())).contains("not the registry's root")
        );

        // Moving HEAD back to the root still leaves the second commit on a branch.
        repository.branch("later", &repository.find_commit(second)?, false)?;
        repository.reset(
            repository.find_commit(root)?.as_object(),
            git2::ResetType::Hard,
            None,
        )?;
        assert!(error_text(inspect_root_base(temporary.path())).contains("more than its root"));
        Ok(())
    }

    #[test]
    fn refuses_sha1_clones_and_missing_manifests() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let sha1 = temporary.path().join("sha1");
        fs::create_dir(&sha1)?;
        let repository = Repository::init(&sha1)?;
        fs::write(sha1.join("registry.toml"), "[registry]\nname = \"main\"\n")?;
        commit_all(&repository, "registry root", &[])?;
        assert!(error_text(inspect_root_base(&sha1)).contains("SHA-256"));

        let unnamed = temporary.path().join("unnamed");
        fs::create_dir(&unnamed)?;
        let mut options = git2::RepositoryInitOptions::new();
        options.object_format(git2::ObjectFormat::Sha256);
        let repository = Repository::init_opts(&unnamed, &options)?;
        fs::write(unnamed.join("README.md"), "no manifest\n")?;
        commit_all(&repository, "registry root", &[])?;
        assert!(error_text(inspect_root_base(&unnamed)).contains("registry manifest"));
        Ok(())
    }
}
