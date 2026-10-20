//! Retains active candidate roots and durable retirement grace periods.

use std::time::{SystemTime, UNIX_EPOCH};

use super::*;

/// Minimum lifetime of discarded and superseded candidate roots.
pub const RETIRED_ROOT_GRACE_SECONDS: u64 = 24 * 60 * 60;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Retirement {
    retired_at: u64,
}

impl LocalStageStore {
    /// Lists exact immutable objects protected by active or grace-period stages.
    ///
    /// # Errors
    ///
    /// Returns an error when the clock or a durable candidate record is invalid.
    pub fn retained_objects(&self) -> Result<Vec<StageObject>> {
        let mut objects = std::collections::BTreeMap::new();
        for revision in self.retained_revisions_at(now()?)? {
            for object in revision.inventory {
                objects.insert((object.path.clone(), object.sha256.clone()), object);
            }
        }
        Ok(objects.into_values().collect())
    }

    /// Lists store outputs protected by active or grace-period stages.
    ///
    /// # Errors
    ///
    /// Returns an error when the clock or a durable candidate record is invalid.
    pub fn retained_store_roots(&self) -> Result<Vec<String>> {
        Ok(self
            .retained_revisions_at(now()?)?
            .into_iter()
            .flat_map(|revision| revision.store_roots)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect())
    }

    pub(super) fn retained_revisions_at(&self, now: u64) -> Result<Vec<StageRevision>> {
        let current: std::collections::BTreeMap<_, _> = self
            .list()?
            .into_iter()
            .map(|record| (record.revision.id.clone(), record))
            .collect();
        let root = self.root.join("revisions");
        if !root.exists() {
            return Ok(Vec::new());
        }
        let mut retained = Vec::new();
        for (relative, path) in super::capture::regular_files(&root)? {
            if relative.ends_with(".targets.json") {
                continue;
            }
            let revision: StageRevision = serde_json::from_slice(&fs::read(&path)?)?;
            revision.validate()?;
            if path != self.revision_path(&revision.id, revision.revision) {
                bail!("retained candidate revision filename differs from its identity");
            }
            let active = current.get(&revision.id).is_some_and(|record| {
                record.revision.revision == revision.revision
                    && record.state != StageState::Discarded
            });
            let retirement = self.retirement_path(&revision.id, revision.revision);
            let retired_at = if retirement.exists() {
                serde_json::from_slice::<Retirement>(&fs::read(retirement)?)?.retired_at
            } else {
                // Immutable orphan records can survive interruption before the
                // mutable selector is replaced. Protect them for a full day.
                fs::metadata(&path)?
                    .modified()?
                    .duration_since(UNIX_EPOCH)?
                    .as_secs()
            };
            if active || now.saturating_sub(retired_at) < RETIRED_ROOT_GRACE_SECONDS {
                retained.push(revision);
            }
        }
        Ok(retained)
    }

    pub(super) fn retire_revision_roots(&self, id: &str, revision: u64) -> Result<()> {
        let path = self.retirement_path(id, revision);
        // Callers invoke this only while the old revision remains active. A
        // failed selector replacement must not consume its eventual grace;
        // retrying that incomplete transition starts a fresh retirement clock.
        self.write_replace(
            &path,
            &serde_json::to_vec(&Retirement { retired_at: now()? })?,
        )?;
        Ok(())
    }

    fn retirement_path(&self, id: &str, revision: u64) -> PathBuf {
        self.root
            .join("retention")
            .join(id)
            .join(format!("{revision}.json"))
    }
}

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
