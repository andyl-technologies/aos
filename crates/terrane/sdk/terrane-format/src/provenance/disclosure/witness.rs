//! Enumerates complete canonical destination roots and their physical view paths.

use super::super::{EntryLocation, Rejected, VerifiedHistory};
use super::candidate::Interpretation;
use crate::{
    identity::Digest,
    properties::semantics::RecordedContext,
    properties::{self, Defaults, RootLayer, Value},
    tree_format::{EntryKind, MAX_GRAFT_DEPTH, Property},
};
use alloc::{collections::BTreeSet, string::String, string::ToString, vec, vec::Vec};

#[derive(Clone, Debug)]
/// Records one actual namespace entry occurrence and its effective domain.
pub(super) struct Target {
    /// Exact checked view, physical containing root and root-local entry path.
    pub location: EntryLocation,
    /// Effective disclosure domain at this occurrence.
    pub domain: String,
    /// Absolute path of this occurrence's containing namespace root.
    pub root_path: Vec<u8>,
}

#[derive(Clone, Debug)]
/// Retains complete actual entry and root occurrences for candidate checking.
pub(super) struct Witness {
    /// All entries, including repeated physical locations under distinct prefixes.
    pub entries: Vec<Target>,
    /// Sorted unique absolute root paths and effective domains.
    pub roots: Vec<(Vec<u8>, String)>,
}

/// Resolves an actual current-mode path without erasing active placement checks.
///
/// # Errors
/// Rejects missing canonical view/path evidence, invalid current root or graft
/// maps, unsupported active placement and domain-resolution failures.
pub(super) fn selected_domain(
    history: &VerifiedHistory,
    view: Digest,
    path: &[u8],
    defaults: Defaults<'_>,
) -> Result<(EntryLocation, String), Rejected> {
    let root = history.commit(&view).ok_or(Rejected)?.commit().tree;
    let private_domain = super::super::root_context::canonical_private_domain(root)?;
    let defaults = Defaults {
        private_domain: &private_domain,
        ..defaults
    };
    let (location, raw) = history.locate_policy_layers(view, path)?;
    let selected = history.view_selection(view)?;
    let layers: Vec<_> = raw
        .iter()
        .map(|layer| RootLayer {
            properties: &layer.properties,
            overrides: layer.overrides.as_deref().unwrap_or(&[]),
        })
        .collect();
    let effective = selected.resolve(&layers, defaults).map_err(|_| Rejected)?;
    effective.domain().map_err(|_| Rejected)?;
    let domain = match effective.get(properties::PropertyName::Domain) {
        Some(Value::Text(value)) => (*value).to_string(),
        _ => return Err(Rejected),
    };
    Ok((location, domain))
}

fn selected_domain_with_properties(
    history: &VerifiedHistory,
    view: Digest,
    path: &[u8],
    defaults: Defaults<'_>,
    properties: Option<&RecordedContext>,
) -> Result<(EntryLocation, String), Rejected> {
    let Some(properties) = properties else {
        return selected_domain(history, view, path, defaults);
    };
    let (location, layers) = history.locate_policy_layers(view, path)?;
    let layers: Vec<_> = layers
        .iter()
        .map(|layer| RootLayer {
            properties: &layer.properties,
            overrides: layer.overrides.as_deref().unwrap_or(&[]),
        })
        .collect();
    let effective = properties
        .resolve(&layers, defaults)
        .map_err(|_| Rejected)?;
    effective.domain().map_err(|_| Rejected)?;
    match effective.get(properties::PropertyName::Domain) {
        Some(Value::Text(domain)) => Ok((location, (*domain).to_string())),
        _ => Err(Rejected),
    }
}

// Raw maps stay in their namespace/occurrence roles until the selected resolver
// validates placement. The compatibility mode retains its prior merged order.
fn occurrence_domain(
    layers: &[(Vec<Property<'_>>, Vec<Property<'_>>)],
    defaults: Defaults<'_>,
    properties: Option<&RecordedContext>,
    selection: &crate::properties::selected::Selection,
) -> Result<String, Rejected> {
    if let Some(properties) = properties {
        let layers: Vec<_> = layers
            .iter()
            .map(|(local, overrides)| RootLayer {
                properties: local,
                overrides,
            })
            .collect();
        let effective = properties
            .resolve(&layers, defaults)
            .map_err(|_| Rejected)?;
        effective.domain().map_err(|_| Rejected)?;
        return match effective.get(properties::PropertyName::Domain) {
            Some(Value::Text(domain)) => Ok((*domain).to_string()),
            _ => Err(Rejected),
        };
    }
    let raw: Vec<_> = layers
        .iter()
        .map(|(local, overrides)| RootLayer {
            properties: local,
            overrides,
        })
        .collect();
    let effective = selection.resolve(&raw, defaults).map_err(|_| Rejected)?;
    effective.domain().map_err(|_| Rejected)?;
    match effective.get(properties::PropertyName::Domain) {
        Some(Value::Text(value)) => Ok((*value).to_string()),
        _ => Err(Rejected),
    }
}

/// Enumerates every actual occurrence under one selected enclosing interpretation.
///
/// # Errors
/// Rejects missing or inconsistent associations/evidence, invalid properties or
/// placement, cycles, excessive depth and contradictory flattened mappings.
pub(super) fn enumerate(
    history: &VerifiedHistory,
    view: Digest,
    defaults: Defaults<'_>,
    interpretation: &Interpretation,
) -> Result<Witness, Rejected> {
    interpretation.with_properties(history, view, |properties| {
        enumerate_with_properties(history, view, defaults, properties)
    })
}

fn enumerate_with_properties(
    history: &VerifiedHistory,
    view: Digest,
    defaults: Defaults<'_>,
    properties: Option<&RecordedContext>,
) -> Result<Witness, Rejected> {
    let root = history.commit(&view).ok_or(Rejected)?.commit().tree;
    let private_domain = super::super::root_context::canonical_private_domain(root)?;
    let defaults = Defaults {
        private_domain: &private_domain,
        ..defaults
    };
    let mut pending = vec![(
        root,
        Vec::new(),
        Vec::new(),
        Vec::<Property<'_>>::new(),
        BTreeSet::new(),
    )];
    let mut result = Witness {
        entries: Vec::new(),
        roots: Vec::new(),
    };
    while let Some((root, prefix, mut layers, overrides, mut ancestors)) = pending.pop() {
        if !ancestors.insert(root) || ancestors.len() > MAX_GRAFT_DEPTH + 1 {
            return Err(Rejected);
        }
        layers.push((history.root_properties(root)?, overrides));
        let effective_domain = occurrence_domain(
            &layers,
            defaults,
            properties,
            &history.view_selection(view)?,
        )?;
        let mut absolute = vec![b'/'];
        absolute.extend_from_slice(&prefix);
        result
            .roots
            .push((absolute.clone(), effective_domain.clone()));
        for item in history.root_items(root)? {
            let mut full_path = prefix.clone();
            if !full_path.is_empty() {
                full_path.push(b'/');
            }
            full_path.extend_from_slice(&item.key);
            let location = EntryLocation {
                commit: view,
                root,
                path: item.key,
            };
            // Complete enumeration also checks the actual flattened namespace:
            // grafted paths must resolve to this exact occurrence and policy.
            let (actual, actual_domain) =
                selected_domain_with_properties(history, view, &full_path, defaults, properties)?;
            if actual != location || actual_domain != effective_domain {
                return Err(Rejected);
            }
            result.entries.push(Target {
                location,
                domain: effective_domain.clone(),
                root_path: absolute.clone(),
            });
            if let EntryKind::Tree { root: child, props } = &item.entry.kind {
                pending.push((
                    *child,
                    full_path,
                    layers.clone(),
                    props.clone().unwrap_or_default(),
                    ancestors.clone(),
                ));
            }
        }
    }
    result.roots.sort();
    result.roots.dedup();
    Ok(result)
}

/// Checks full retained records, including siblings and all ordinary metadata edges.
///
/// # Errors
/// Rejects missing or unfinished history, interpretation conflicts, invalid
/// canonical/property evidence, private retained metadata and unavailable
/// content or independent attribute-producer dependencies.
pub(super) fn retention_closure(
    history: &VerifiedHistory,
    seed: Digest,
    target_domain: &str,
    defaults: Defaults<'_>,
    interpretation: &Interpretation,
) -> Result<Vec<Digest>, Rejected> {
    let target = properties::Domain::parse(target_domain).map_err(|_| Rejected)?;
    let mut pending = vec![seed];
    let mut seen = BTreeSet::new();
    while let Some(view) = pending.pop() {
        if !seen.insert(view) {
            continue;
        }
        history.require_disclosure_validation(view)?;
        interpretation.check_scope(history, view)?;
        let witness = enumerate(history, view, defaults, interpretation)?;
        for (_, domain) in &witness.roots {
            if !target.permits_reference(properties::Domain::parse(domain).map_err(|_| Rejected)?) {
                return Err(Rejected);
            }
        }
        let record = history.commit(&view).ok_or(Rejected)?.commit();
        pending.extend(
            record
                .parents
                .iter()
                .copied()
                .filter(|parent| !history.disclosure_parents.contains(&(view, *parent))),
        );
        for receipt in record.profile_pair.entry_receipts.iter().flatten() {
            if let crate::refs::EntryOrigin::Source(source) = &receipt.origin {
                pending.push(source.commit);
            }
            if receipt.disclosure_proof.is_none()
                && let Some(source) = &receipt.reintroduced_from
            {
                pending.push(source.commit);
            }
            for (_, origin) in receipt.attributes.iter().flatten() {
                if let crate::refs::EntryOrigin::Source(source) = origin {
                    pending.push(source.commit);
                }
            }
        }
        // A retained public root may not hide a private origin in an unrelated
        // entry. Whole records are retained, so their complete live tree and
        // attribute provenance must also remain independently verifiable.
        for entry in witness.entries {
            history.introducing_commit(&entry.location)?;
            pending.extend(
                history
                    .dependencies(&entry.location)?
                    .into_iter()
                    .flatten()
                    .map(|source| source.commit),
            );
            for attribute in history.entry(&entry.location)?.attrs {
                history.attribute_producer(&entry.location, attribute.name)?;
                pending.extend(
                    history
                        .attribute_dependencies(&entry.location, attribute.name)?
                        .into_iter()
                        .flatten()
                        .map(|source| source.commit),
                );
            }
        }
    }
    Ok(seen.into_iter().collect())
}
