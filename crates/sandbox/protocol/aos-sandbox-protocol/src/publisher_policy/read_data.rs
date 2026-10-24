//! Borrows saved Publisher rows for nonauthorizing canonical comparisons.
//!
//! A native store keeps its own protected admission before lending these rows.
//! Root lends only its completed same-file/indexed/full-cold readonly map. This
//! DATA view cannot construct a store, native owner or current decision.

use aos_sandbox_model::RecordNamespace;
use std::collections::BTreeMap;

/// Borrows supplied Publisher rows without authenticating their origin.
#[derive(Clone, Copy)]
pub struct PublisherReadDataV2<'rows> {
    state: &'rows BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
}

impl<'rows> PublisherReadDataV2<'rows> {


    /// Borrows the supplied materialized map as comparison DATA.
    pub fn from_state_v2(
        state: &'rows BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    ) -> Self {
        Self { state }
    }

    /// Borrows one exact namespace/key value.
    pub fn get(self, namespace: RecordNamespace, key: &[u8]) -> Option<&'rows [u8]> {
        self.state
            .get(&(namespace, key.to_vec()))
            .map(Vec::as_slice)
    }

    /// Iterates one namespace in its established bytewise order.
    pub fn records(
        self,
        namespace: RecordNamespace,
    ) -> impl Iterator<Item = (&'rows [u8], &'rows [u8])> + 'rows {
        self.state
            .range((namespace, Vec::new())..)
            .take_while(move |((actual, _), _)| *actual == namespace)
            .map(|((_, key), value)| (key.as_slice(), value.as_slice()))
    }
}
