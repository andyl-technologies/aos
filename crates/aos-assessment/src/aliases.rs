//! Snapshot-specific advisory equivalence, excluding related/upstream edges.

use std::collections::{BTreeMap, BTreeSet};

use crate::advisory::AdvisoryRecordV1;

/// Builds deterministic equivalence sets once for a complete pinned record set.
pub(crate) struct AliasIndex {
    representatives: BTreeMap<String, usize>,
    groups: BTreeMap<usize, Vec<String>>,
}

impl AliasIndex {
    pub(crate) fn identities(&self, id: &str) -> Option<&[String]> {
        self.representatives
            .get(id)
            .and_then(|root| self.groups.get(root))
            .map(Vec::as_slice)
    }
}

pub(crate) fn equivalence(records: &[AdvisoryRecordV1]) -> AliasIndex {
    let identifiers = records
        .iter()
        .flat_map(|record| std::iter::once(&record.id).chain(&record.aliases))
        .cloned()
        .collect::<BTreeSet<_>>();
    let keys = identifiers.into_iter().collect::<Vec<_>>();
    let indexes = keys
        .iter()
        .enumerate()
        .map(|(index, key)| (key.as_str(), index))
        .collect::<BTreeMap<_, _>>();
    let mut parents = (0..keys.len()).collect::<Vec<_>>();
    for record in records {
        let Some(&record_index) = indexes.get(record.id.as_str()) else {
            continue;
        };
        for alias in &record.aliases {
            let Some(&alias_index) = indexes.get(alias.as_str()) else {
                continue;
            };
            let record_root = root(&mut parents, record_index);
            let alias_root = root(&mut parents, alias_index);
            parents[record_root.max(alias_root)] = record_root.min(alias_root);
        }
    }
    let mut groups = BTreeMap::<usize, Vec<String>>::new();
    for (index, key) in keys.iter().enumerate() {
        groups
            .entry(root(&mut parents, index))
            .or_default()
            .push(key.clone());
    }
    let representatives = keys
        .iter()
        .enumerate()
        .map(|(index, key)| (key.clone(), root(&mut parents, index)))
        .collect();
    AliasIndex {
        representatives,
        groups,
    }
}

fn root(parents: &mut [usize], mut current: usize) -> usize {
    while parents[current] != current {
        parents[current] = parents[parents[current]];
        current = parents[current];
    }
    current
}
