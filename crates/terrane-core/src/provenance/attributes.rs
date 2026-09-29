//! Resolves attribute producers and acceptance through separate signed receipts.
//!
//! Equal values on changed content are not evidence of a preserved derivation.
//! Attribute selectors use their own carried-value history rather than the
//! content entry's acceptance history.

use super::{EntryLocation, Rejected, VerifiedHistory, same_content};
use crate::{identity::Digest, refs::EntryOrigin};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec,
    vec::Vec,
};

impl VerifiedHistory {
    fn attribute_dependencies(
        &self,
        location: &EntryLocation,
        name: &str,
    ) -> Result<Option<Vec<EntryLocation>>, Rejected> {
        let entry = self.entry(location)?;
        let value = entry
            .attrs
            .iter()
            .find(|attribute| attribute.name == name)
            .ok_or(Rejected)?
            .value;
        let record = self.commits.get(&location.commit).ok_or(Rejected)?.commit();
        let origin = record
            .profile_pair
            .entry_receipts
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .find(|receipt| receipt.root == location.root && receipt.path == location.path)
            .and_then(|receipt| receipt.attributes.as_deref())
            .and_then(|attributes| attributes.iter().find(|(candidate, _)| candidate == name))
            .map(|(_, origin)| origin);
        match origin {
            Some(EntryOrigin::Current) => Ok(None),
            Some(EntryOrigin::Source(source)) => {
                if source.commit == location.commit {
                    return Err(Rejected);
                }
                let source = EntryLocation {
                    commit: source.commit,
                    root: source.root,
                    path: source.path.clone(),
                };
                let previous = self.entry(&source)?;
                if !same_content(&entry, &previous)
                    || previous
                        .attrs
                        .iter()
                        .find(|attribute| attribute.name == name)
                        .map(|attribute| attribute.value)
                        != Some(value)
                {
                    return Err(Rejected);
                }
                Ok(Some(vec![source]))
            }
            None => {
                let mut parents = Vec::new();
                for parent in &record.parents {
                    let parent_record = self.commits.get(parent).ok_or(Rejected)?.commit();
                    let root = if location.root == record.tree {
                        parent_record.tree
                    } else {
                        location.root
                    };
                    if !self.root_presence(*parent, root)? {
                        continue;
                    }
                    let source = EntryLocation {
                        commit: *parent,
                        root,
                        path: location.path.clone(),
                    };
                    if let Ok(previous) = self.entry(&source)
                        && same_content(&entry, &previous)
                        && previous
                            .attrs
                            .iter()
                            .any(|attribute| attribute.name == name && attribute.value == value)
                    {
                        parents.push(source);
                    }
                }
                Ok(Some(parents))
            }
        }
    }

    /// Resolves an attribute's producer independently of content introduction.
    ///
    /// # Errors
    /// Returns [`Rejected`] for missing attributes or evidence, invalid source
    /// receipts, changed inherited content/values, or ambiguous producer ancestry.
    pub fn attribute_producer(
        &self,
        location: &EntryLocation,
        name: &str,
    ) -> Result<Digest, Rejected> {
        let mut pending = vec![(location.clone(), false)];
        let mut resolved = BTreeMap::new();
        let mut active = BTreeSet::new();
        while let Some((current, finishing)) = pending.pop() {
            if resolved.contains_key(&current) {
                continue;
            }
            let Some(dependencies) = self.attribute_dependencies(&current, name)? else {
                resolved.insert(current.clone(), current.commit);
                continue;
            };
            if dependencies.is_empty() {
                return Err(Rejected);
            }
            if !finishing {
                if !active.insert(current.clone()) {
                    return Err(Rejected);
                }
                pending.push((current, true));
                for source in dependencies.into_iter().rev() {
                    pending.push((source, false));
                }
                continue;
            }
            let first = *resolved.get(&dependencies[0]).ok_or(Rejected)?;
            if dependencies
                .iter()
                .any(|source| resolved.get(source) != Some(&first))
            {
                return Err(Rejected);
            }
            active.remove(&current);
            resolved.insert(current, first);
        }
        resolved.get(location).copied().ok_or(Rejected)
    }

    pub(super) fn attribute_acceptance_commits(
        &self,
        location: &EntryLocation,
        name: &str,
        producer: Digest,
    ) -> Vec<Digest> {
        let mut accepted = BTreeSet::new();
        let mut seen = BTreeSet::new();
        let mut pending = vec![location.clone()];
        while let Some(current) = pending.pop() {
            if !seen.insert(current.clone())
                || self.attribute_producer(&current, name) != Ok(producer)
            {
                continue;
            }
            if current.commit != producer {
                accepted.insert(current.commit);
            }
            if let Ok(Some(dependencies)) = self.attribute_dependencies(&current, name) {
                pending.extend(dependencies);
            }
        }
        let Ok(entry) = self.entry(location) else {
            return Vec::new();
        };
        let Some(view) = self.commits.get(&location.commit) else {
            return Vec::new();
        };
        let value = entry
            .attrs
            .iter()
            .find(|attribute| attribute.name == name)
            .map(|attribute| attribute.value);
        for (identity, commit) in &self.commits {
            if *identity == producer
                || self.graph.is_ancestor(*identity, location.commit) != Ok(true)
            {
                continue;
            }
            let root = if location.root == view.commit().tree {
                commit.commit().tree
            } else {
                location.root
            };
            let candidate = EntryLocation {
                commit: *identity,
                root,
                path: location.path.clone(),
            };
            if let Ok(previous) = self.entry(&candidate)
                && same_content(&entry, &previous)
                && previous
                    .attrs
                    .iter()
                    .find(|attribute| attribute.name == name)
                    .map(|attribute| attribute.value)
                    == value
                && self.attribute_producer(&candidate, name) == Ok(producer)
            {
                accepted.insert(*identity);
            }
        }
        accepted.into_iter().collect()
    }
}
