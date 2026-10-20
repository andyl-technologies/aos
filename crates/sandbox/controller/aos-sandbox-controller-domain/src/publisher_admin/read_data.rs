//! Borrows saved Publisher rows for nonauthorizing canonical comparisons.
//!
//! A native store keeps its own protected admission before lending these rows.
//! Root lends only its completed same-file/indexed/full-cold readonly map. This
//! private DATA view cannot construct a store, native owner or current decision.

use crate::{Journal, RecordNamespace};
use std::collections::BTreeMap;

#[derive(Clone, Copy)]
pub(crate) struct PublisherReadDataV2<'rows> {
    state: &'rows BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
}

impl<'rows> PublisherReadDataV2<'rows> {
    pub(crate) fn from_journal_v2(journal: &'rows Journal) -> Self {
        Self::from_state_v2(journal.historical_read_view_v1().materialized_state_v1())
    }

    pub(crate) fn from_state_v2(
        state: &'rows BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    ) -> Self {
        Self { state }
    }

    pub(crate) fn get(self, namespace: RecordNamespace, key: &[u8]) -> Option<&'rows [u8]> {
        self.state
            .get(&(namespace, key.to_vec()))
            .map(Vec::as_slice)
    }

    pub(crate) fn records(
        self,
        namespace: RecordNamespace,
    ) -> impl Iterator<Item = (&'rows [u8], &'rows [u8])> + 'rows {
        self.state
            .range((namespace, Vec::new())..)
            .take_while(move |((actual, _), _)| *actual == namespace)
            .map(|((_, key), value)| (key.as_slice(), value.as_slice()))
    }
}
