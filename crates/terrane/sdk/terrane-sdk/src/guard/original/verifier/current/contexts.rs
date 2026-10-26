//! Rebinds new local Original records within an actual current read's exclusions.
//!
//! A reader's startup context inventory is incomplete after another writer
//! publishes. Protected records are inputs to the existing native binders, never
//! authority by themselves. Newly checked contexts stay local to this operation;
//! complete signed history, selected publication and current ACL checks follow.

use std::collections::BTreeMap;

use crate::{
    bucket::{BucketBinding, FileBucket, held::HeldIdentity},
    guard::{Guard, OriginalAuthority, RetainedControls, original::control::ControlExclusion},
    repository::local_authority::retention::{BootstrapRecord, CommitAssociation, Record},
    store::{Clock, ContentValidator, LocalFs, StoreFailure},
};

use super::{invalid, unavailable};

/// Refreshes local administrative associations without installing serving authority.
///
/// # Errors
/// Refuses unsafe or conflicting protected records, changed physical bindings,
/// missing baselines and any unavailable native exclusion or canonical check.
pub(super) async fn refresh_local<F, B, V, S, C>(
    concrete: &Guard<FileBucket<F, B, V>, ()>,
    operation: &Guard<S, C>,
    authority: &OriginalAuthority,
    held: &HeldIdentity<'_>,
    exclusion: &mut ControlExclusion<'_, F>,
    named: &mut BTreeMap<String, Vec<u8>>,
) -> Result<RetainedControls, StoreFailure>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
{
    let mut baselines = BTreeMap::new();
    let mut associations = BTreeMap::new();
    exclusion.revalidate().await?;
    let paths = concrete
        .store()
        .fs()
        .read_dir(authority.control())
        .await
        .map_err(super::super::super::io_failure)?;
    for path in paths {
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(invalid)?;
        if name.starts_with("bootstrap-") {
            let bytes = exclusion.read_record(name).await?;
            let row = BootstrapRecord::decode(&bytes).map_err(|_| invalid())?;
            if row.id != *authority.id() || row.selector().map_err(|_| invalid())? != name {
                return Err(invalid());
            }
            if baselines
                .insert((row.reference.clone(), row.epoch), row)
                .is_some()
            {
                return Err(invalid());
            }
            insert_record(named, name, bytes)?;
        } else if name.starts_with("commit-") {
            let bytes = exclusion.read_record(name).await?;
            let row = CommitAssociation::decode(&bytes).map_err(|_| invalid())?;
            if row.id != *authority.id() || row.selector() != name {
                return Err(invalid());
            }
            if associations.insert(row.commit, row).is_some() {
                return Err(invalid());
            }
            insert_record(named, name, bytes)?;
        }
    }
    let retained = exclusion
        .retain_named(
            &named
                .iter()
                .map(|(key, bytes)| (key.clone(), bytes.clone()))
                .collect::<Vec<_>>(),
        )
        .await?;

    let mut checked_baselines = BTreeMap::new();
    for (key, row) in baselines {
        let checked = concrete
            .bind_original_bootstrap_at(authority, row.view(), Some(held), Some(&retained))
            .await?;
        {
            let mut installed = operation
                .original_baselines
                .write()
                .map_err(|_| unavailable())?;
            if installed
                .get(&key)
                .is_some_and(|previous| previous != &checked)
            {
                return Err(invalid());
            }
            installed.insert(key.clone(), checked.clone());
        }
        checked_baselines.insert(key, checked);
    }
    for (commit, row) in associations {
        // Preserve previously checked contexts, including richer imported
        // supplements. The enclosing read freshly pins and checks every known
        // context's actual records before using any of them for history.
        if operation
            .original_commits
            .read()
            .map_err(|_| unavailable())?
            .contains_key(&commit)
        {
            continue;
        }
        let key = (row.reference.clone(), row.epoch);
        let baseline = checked_baselines.get(&key).ok_or_else(invalid)?;
        let checked = concrete
            .bind_original_commit_at(baseline, row.view(), Some(held), Some(&retained))
            .await?;
        let mut installed = operation
            .original_commits
            .write()
            .map_err(|_| unavailable())?;
        if installed
            .get(&commit)
            .is_some_and(|previous| previous != &checked)
        {
            return Err(invalid());
        }
        installed.insert(commit, checked);
    }
    Ok(retained)
}

fn insert_record(
    named: &mut BTreeMap<String, Vec<u8>>,
    name: &str,
    bytes: Vec<u8>,
) -> Result<(), StoreFailure> {
    if named.get(name).is_some_and(|previous| previous != &bytes) {
        return Err(invalid());
    }
    named.insert(name.to_owned(), bytes);
    Ok(())
}
