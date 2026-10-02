//! Published release ancestry and conflict-checked authoring tree composition.
//!
//! A maintainer branch may intentionally remain independent of generated
//! release commits. The next candidate carries its authored changes forward
//! together with the preceding published catalog, and its signed commit binds
//! both histories so consumers can enforce fast-forward updates.

use std::path::Path;

use anyhow::{Context as _, Result, bail};
use git2::Repository;

/// Resolves the nearest preceding published version and authenticates its tag.
pub(super) fn predecessor(directory: &Path, release: &semver::Version) -> Result<Option<String>> {
    let Some(version) = crate::registry_ops::semver_tag_versions(directory)?
        .into_iter()
        .filter(|version| version < release)
        .max()
    else {
        return Ok(None);
    };
    let roster = crate::registry::keys::load_keys_toml(directory)?
        .context("published release lineage requires a committed trust roster")?;
    let trusted_keys = roster
        .active
        .into_iter()
        .map(|key| key.key)
        .chain(roster.revoked.into_iter().filter_map(|key| key.key))
        .collect::<Vec<_>>();
    if !crate::security::verify_tag_signature(directory, &version.to_string(), &trusted_keys)? {
        bail!(
            "published release predecessor {version} is not signed by a known registry authority"
        );
    }
    Ok(Some(crate::registry_ops::release_commit(
        directory, &version,
    )?))
}

/// Merges the published catalog into a clean author's isolated workspace.
pub(super) fn compose(directory: &Path, release: &semver::Version) -> Result<Option<String>> {
    let Some(predecessor) = predecessor(directory, release)? else {
        return Ok(None);
    };
    compose_with_predecessor(directory, &predecessor)?;
    Ok(Some(predecessor))
}

fn compose_with_predecessor(directory: &Path, predecessor: &str) -> Result<()> {
    let repository = Repository::open(directory)?;
    let author = repository.head()?.peel_to_commit()?;
    let previous = repository.find_commit(git2::Oid::from_str_ext(
        predecessor,
        repository.object_format(),
    )?)?;
    if author.id() == previous.id() || repository.graph_descendant_of(author.id(), previous.id())? {
        return Ok(());
    }
    let ancestor = repository
        .merge_base(author.id(), previous.id())
        .context("authoring and published release histories have no common ancestor")?;
    let ancestor = repository.find_commit(ancestor)?;
    let mut merged =
        repository.merge_trees(&ancestor.tree()?, &previous.tree()?, &author.tree()?, None)?;
    if merged.has_conflicts() {
        bail!(
            "authored changes conflict with the published catalog; merge the preceding release into the maintainer branch and review the result"
        );
    }
    let mut checkout = git2::build::CheckoutBuilder::new();
    checkout.safe();
    repository
        .checkout_index(Some(&mut merged), Some(&mut checkout))
        .context("materializing the merged authoring and published catalog")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn commit(repository: &Repository, message: &str) -> Result<git2::Oid> {
        let mut index = repository.index()?;
        index.update_all(["*"], None)?;
        index.add_all(["*"], git2::IndexAddOption::DEFAULT, None)?;
        index.write()?;
        let tree = repository.find_tree(index.write_tree()?)?;
        let signature = git2::Signature::now("Registry test", "registry@example.invalid")?;
        let parent = repository
            .head()
            .ok()
            .map(|head| head.peel_to_commit())
            .transpose()?;
        let parents = parent.iter().collect::<Vec<_>>();
        Ok(repository.commit(
            Some("HEAD"),
            &signature,
            &signature,
            message,
            &tree,
            &parents,
        )?)
    }

    #[test]
    fn merged_catalog_survives_final_index_capture_without_moving_author_head() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let repository = Repository::init(temporary.path())?;
        std::fs::write(temporary.path().join("shared"), "base\n")?;
        let base = commit(&repository, "base")?;

        std::fs::write(temporary.path().join("published-package"), "published\n")?;
        let previous = commit(&repository, "published catalog")?;
        repository.reference("refs/heads/maintainer", base, false, "author branch")?;
        repository.set_head("refs/heads/maintainer")?;
        repository.checkout_head(Some(git2::build::CheckoutBuilder::new().force()))?;
        std::fs::write(temporary.path().join("author-package"), "authored\n")?;
        let author = commit(&repository, "author change")?;

        compose_with_predecessor(temporary.path(), &previous.to_string())?;
        let mut index = repository.index()?;
        index.update_all(["*"], None)?;
        index.add_all(["*"], git2::IndexAddOption::DEFAULT, None)?;
        let merged = repository.find_tree(index.write_tree()?)?;

        assert!(merged.get_name("published-package").is_some());
        assert!(merged.get_name("author-package").is_some());
        assert_eq!(repository.head()?.peel_to_commit()?.id(), author);
        Ok(())
    }
}
