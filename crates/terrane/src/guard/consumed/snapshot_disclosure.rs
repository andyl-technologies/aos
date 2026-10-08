//! Canonical ordinary disclosure inputs for complete configuration comparisons.
//!
//! This projection owns public row data only. It grants no lineage completion,
//! Original association, current rights, or publication permission. Its caller
//! separately captures native configuration under genuine retained controls.

use std::collections::BTreeMap;

use terrane_core::gc::publication::evidence::DisclosureRow;

use super::super::invalid;
use crate::store::StoreFailure;

/// Owns canonical ordinary disclosure rows without any checked capability.
pub(crate) struct SnapshotDisclosureInputs {
    rows: Vec<DisclosureRow>,
}

impl SnapshotDisclosureInputs {
    /// Canonicalizes ordinary rows supplied by the private configuration producer.
    ///
    /// Identical repetitions coalesce; a selector cannot choose different data.
    /// Row schema and interval validation remain in complete snapshot encoding.
    /// This constructor supplies no authority or trusted-source qualification.
    ///
    /// # Errors
    /// Rejects conflicting repository/domain/key/valid-from selector data.
    pub(crate) fn from_rows(
        rows: impl IntoIterator<Item = DisclosureRow>,
    ) -> Result<Self, StoreFailure> {
        let mut canonical = BTreeMap::new();
        for row in rows {
            let selector = (
                row.repository.clone(),
                row.domain.clone(),
                row.public_key,
                row.not_before,
            );
            if canonical
                .get(&selector)
                .is_some_and(|previous| previous != &row)
            {
                return Err(invalid());
            }
            canonical.insert(selector, row);
        }
        Ok(Self {
            rows: canonical.into_values().collect(),
        })
    }

    /// Borrows canonical input rows without conferring trust in their contents.
    pub(super) fn rows(&self) -> &[DisclosureRow] {
        &self.rows
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(repository: &str, until: u64) -> DisclosureRow {
        DisclosureRow {
            repository: repository.repeat(64),
            domain: "public".into(),
            public_key: [7; 32],
            not_before: 1,
            not_after: Some(until),
        }
    }

    #[test]
    fn ordinary_rows_sort_and_coalesce_identical_selectors() -> Result<(), StoreFailure> {
        let first = row("a", 20);
        let second = row("b", 30);
        let inputs =
            SnapshotDisclosureInputs::from_rows([second.clone(), first.clone(), second.clone()])?;
        assert_eq!(inputs.rows(), &[first, second]);
        Ok(())
    }

    #[test]
    fn ordinary_rows_refuse_conflicting_selector_data_in_either_order() {
        let first = row("a", 20);
        let changed = row("a", 21);
        assert!(SnapshotDisclosureInputs::from_rows([first.clone(), changed.clone()]).is_err());
        assert!(SnapshotDisclosureInputs::from_rows([changed, first]).is_err());
    }
}
