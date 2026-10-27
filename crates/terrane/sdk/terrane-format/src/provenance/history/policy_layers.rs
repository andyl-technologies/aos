//! Retains canonical physical root properties and occurrence overrides separately.
//!
//! These layers are ordinary traversal data. They select no property revision,
//! register no later names, and establish no current policy or authority.

use super::{EntryLocation, Rejected, VerifiedHistory};
use crate::{
    identity::Digest,
    tree_format::{self, EntryKind, Property},
};
use alloc::{collections::BTreeSet, vec::Vec};

#[cfg(test)]
mod tests;

/// Retains one root's original values and its occurrence-local replacement map.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::provenance) struct PolicyLayer<'a> {
    /// Selected view, physical root and remaining root-local entry path.
    pub(in crate::provenance) location: EntryLocation,
    /// Full view-relative graft prefix reaching this root; empty for the top root.
    pub(in crate::provenance) occurrence: Vec<u8>,
    /// Exact original root bindings, before any occurrence replacement.
    pub(in crate::provenance) properties: Vec<Property<'a>>,
    /// Incoming graft bindings, preserving absent versus present-empty maps.
    pub(in crate::provenance) overrides: Option<Vec<Property<'a>>>,
}

impl VerifiedHistory {
    /// Traverses an explicit ordinary physical selection without authenticating it.
    ///
    /// Production supplies the selected root through `locate_policy_layers`;
    /// direct fixture calls establish only canonical physical layer behavior.
    ///
    /// # Errors
    /// Rejects invalid keys, missing paths/evidence, cycles and excessive depth.
    pub(super) fn policy_layers_from_root(
        &self,
        view: Digest,
        mut root: Digest,
        path: &[u8],
    ) -> Result<(EntryLocation, Vec<PolicyLayer<'_>>), Rejected> {
        if self.usage.get(&root) == Some(&tree_format::TreeUse::Index) {
            tree_format::validate_index_key(path).map_err(|_| Rejected)?;
        } else {
            tree_format::validate_key(path).map_err(|_| Rejected)?;
        }
        let mut relative = path;
        let mut roots = BTreeSet::new();
        let mut layers = Vec::new();
        let mut occurrence = Vec::new();
        let mut overrides = None;
        loop {
            if !roots.insert(root) || roots.len() > tree_format::MAX_GRAFT_DEPTH + 1 {
                return Err(Rejected);
            }
            let location = EntryLocation {
                commit: view,
                root,
                path: relative.to_vec(),
            };
            layers.push(PolicyLayer {
                location,
                occurrence,
                properties: self.root_properties(root)?,
                overrides,
            });
            if self.root_entry(root, relative).is_ok() {
                let location = layers.last().ok_or(Rejected)?.location.clone();
                return Ok((location, layers));
            }

            let mut selected = None;
            for (position, byte) in relative.iter().enumerate() {
                if *byte != b'/' {
                    continue;
                }
                let Ok(entry) = self.root_entry(root, &relative[..position]) else {
                    continue;
                };
                if let EntryKind::Tree {
                    root: target,
                    props,
                } = &entry.kind
                {
                    selected = Some((*target, position, props.clone()));
                    break;
                }
            }
            let (target, position, incoming) = selected.ok_or(Rejected)?;
            // Extend the retained occurrence rather than caching policy by root
            // digest; repeated grafts can reach identical bytes through two paths.
            occurrence = layers.last().ok_or(Rejected)?.occurrence.clone();
            if !occurrence.is_empty() {
                occurrence.push(b'/');
            }
            occurrence.extend_from_slice(&relative[..position]);
            relative = &relative[position + 1..];
            root = target;
            overrides = incoming;
        }
    }
}

/// Applies the existing replacement projection for legacy callers.
pub(super) fn legacy_properties(layers: Vec<PolicyLayer<'_>>) -> Vec<Vec<Property<'_>>> {
    layers
        .into_iter()
        .map(|layer| {
            let mut properties = layer.properties;
            if let Some(overrides) = layer.overrides {
                // Preserve the original retain-then-append order and the incoming
                // map's independent canonical order.
                for replacement in overrides {
                    properties.retain(|property| property.name != replacement.name);
                    properties.push(replacement);
                }
            }
            properties
        })
        .collect()
}
