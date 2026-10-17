//! Retains exact selected input rows through later windows and publication ACKs.
//!
//! Body authentication remains in the owning source input verifier. This registry
//! retains only its accepted original row metadata; missing codecs stay missing.
//! Capacity is finite before the native child is realized, and all insertion
//! allocations complete before input acceptance or native Stage.

use crucible_node_contract::ContentRef;

use crate::{
    ProviderError,
    reference_lineage::{InputLineageInventory, InputLineageRow},
};

pub(super) struct InputReaderRows {
    rows: Vec<InputLineageRow>,
    manifests: Vec<ContentRef>,
    bytes: u64,
    edges: usize,
}

impl InputReaderRows {
    pub(super) fn new() -> Result<Self, ProviderError> {
        let mut rows = Vec::new();
        let mut manifests = Vec::new();
        rows.try_reserve_exact(4096).map_err(|_| exhausted())?;
        manifests.try_reserve_exact(64).map_err(|_| exhausted())?;
        Ok(Self {
            rows,
            manifests,
            bytes: 0,
            edges: 0,
        })
    }

    pub(super) fn row(&self, object: &ContentRef) -> Option<&InputLineageRow> {
        self.rows
            .binary_search_by(|row| row.object.cmp(object))
            .ok()
            .map(|index| &self.rows[index])
    }

    pub(super) fn is_original_manifest(&self, reference: &ContentRef) -> bool {
        self.manifests.contains(reference)
    }

    pub(super) fn retain(
        &mut self,
        reference: ContentRef,
        inventory: &InputLineageInventory,
    ) -> Result<(), ProviderError> {
        if self.manifests.contains(&reference) {
            return Ok(());
        }
        let mut bytes = self.bytes;
        let mut edges = self.edges;
        let mut new_count = 0usize;
        for row in &inventory.dependencies {
            if let Some(original) = self.row(&row.object) {
                if original.dependencies != row.dependencies {
                    return Err(ProviderError::Conflict(
                        "original selected lineage row changed",
                    ));
                }
            } else {
                bytes = bytes
                    .checked_add(row.object.length.get())
                    .ok_or_else(exhausted)?;
                edges = edges
                    .checked_add(row.dependencies.len())
                    .ok_or_else(exhausted)?;
                new_count += 1;
            }
        }
        if self.manifests.len() >= 64
            || self.rows.len() + new_count > 4096
            || bytes > 64 * 1024 * 1024
            || edges > 65_536
        {
            return Err(exhausted());
        }
        let mut pending = Vec::new();
        pending
            .try_reserve_exact(new_count)
            .map_err(|_| exhausted())?;
        for row in &inventory.dependencies {
            if self.row(&row.object).is_none() {
                let mut dependencies = Vec::new();
                dependencies
                    .try_reserve_exact(row.dependencies.len())
                    .map_err(|_| exhausted())?;
                dependencies.extend(row.dependencies.iter().cloned());
                pending.push(InputLineageRow {
                    object: row.object.clone(),
                    dependencies,
                });
            }
        }
        // The commit uses the original pre-reserved slots only. Allocation or
        // credit failure above leaves the entire prior accepted registry intact.
        self.rows.extend(pending);
        self.rows.sort_by(|a, b| a.object.cmp(&b.object));
        self.manifests.push(reference);
        self.bytes = bytes;
        self.edges = edges;
        Ok(())
    }
}

fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("selected original input row lifetime credit")
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- Atomic finite-row custody regressions never create source authority.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crucible_node_contract::{Id, U64, canonical};

    fn inventory(rows: Vec<InputLineageRow>) -> InputLineageInventory {
        InputLineageInventory {
            schema_version: 1,
            execution_owner_id: Id::new("owner/consumer").unwrap(),
            owner_generation: U64::new(1),
            input_epoch: Id::new("input/1").unwrap(),
            batch_id: Id::new("batch/1").unwrap(),
            batch_sequence: U64::new(1),
            entries: Vec::new(),
            dependencies: rows,
        }
    }

    #[test]
    fn accepted_original_rows_survive_following_cut_and_conflict_refusal() {
        let body = canonical::content_ref(b"body", "application/json").unwrap();
        let dependency = canonical::content_ref(b"dependency", "application/octet-stream").unwrap();
        let root = canonical::content_ref(b"cut/1", "application/json").unwrap();
        let later = canonical::content_ref(b"cut/2", "application/json").unwrap();
        let mut registry = InputReaderRows::new().unwrap();
        let original = InputLineageRow {
            object: body.clone(),
            dependencies: vec![dependency.clone()],
        };
        registry
            .retain(root.clone(), &inventory(vec![original.clone()]))
            .unwrap();
        registry.retain(later, &inventory(vec![])).unwrap();
        assert!(registry.is_original_manifest(&root));
        assert_eq!(registry.row(&body).unwrap().dependencies, vec![dependency]);
        let foreign = canonical::content_ref(b"changed cut", "application/json").unwrap();
        assert!(
            registry
                .retain(
                    foreign.clone(),
                    &inventory(vec![InputLineageRow {
                        object: body.clone(),
                        dependencies: vec![]
                    }])
                )
                .is_err()
        );
        assert!(!registry.is_original_manifest(&foreign));
        assert_eq!(
            registry.row(&body).unwrap().dependencies,
            original.dependencies
        );
    }

    #[test]
    fn lifetime_credit_failure_retains_all_prior_rows_and_manifest_inventory() {
        let mut registry = InputReaderRows::new().unwrap();
        let root = canonical::content_ref(b"first", "application/json").unwrap();
        registry.retain(root.clone(), &inventory(vec![])).unwrap();
        let changed = canonical::content_ref(b"over-limit", "application/json").unwrap();
        let mut extent =
            canonical::content_ref(b"never allocated", "application/octet-stream").unwrap();
        extent.length = U64::new(64 * 1024 * 1024 + 1);
        assert!(
            registry
                .retain(
                    changed.clone(),
                    &inventory(vec![InputLineageRow {
                        object: extent.clone(),
                        dependencies: vec![]
                    }])
                )
                .is_err()
        );
        assert!(registry.is_original_manifest(&root));
        assert!(!registry.is_original_manifest(&changed));
        assert!(registry.row(&extent).is_none());
        assert_eq!(registry.bytes, 0);
        assert_eq!(registry.edges, 0);
    }
}
