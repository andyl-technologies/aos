//! Independently inventories complete old/new logical states outside discovery.

use super::*;

type Path = Vec<Vec<u8>>;
type Entries = BTreeMap<Path, (Address, Entry<'static>)>;
type Roots = BTreeMap<Path, (Address, Digest, Option<Vec<Property<'static>>>)>;

fn inventory(
    root: Digest,
    graph: &BTreeMap<Digest, Tree<'static>>,
    hops: &[Hop],
    entries: &mut Entries,
    roots: &mut Roots,
) {
    let source = &graph[&root];
    roots.insert(
        path(hops),
        (hops.to_vec(), root, source.props().map(<[_]>::to_vec)),
    );
    for item in source.iter() {
        let mut address = hops.to_vec();
        address.push(Hop {
            source: root,
            key: item.key.clone(),
        });
        entries.insert(path(&address), (address.clone(), item.entry.clone()));
        if let EntryKind::Tree { root, .. } = item.entry.kind {
            inventory(root, graph, &address, entries, roots);
        }
    }
}

fn path(address: &[Hop]) -> Path {
    address.iter().map(|hop| hop.key.clone()).collect()
}

fn selected(entry: &Entry<'static>) -> Option<FileState> {
    if let EntryKind::File { content, .. } = entry.kind {
        Some(FileState {
            content,
            value: entry
                .attrs
                .iter()
                .find(|attribute| attribute.name == "uid")
                .map(|attribute| attribute.value.to_vec()),
        })
    } else {
        None
    }
}

fn change_path(old: Option<&Address>, new: Option<&Address>) -> Path {
    path(new.or(old).unwrap())
}

/// Compares every calculated transition against independent complete source states.
///
/// # Panics
/// Panics if any address, source root, entry, content tag/value or binding differs.
pub(super) fn complete(
    result: &Discovery<'_, 'static>,
    old: Digest,
    before: &BTreeMap<Digest, Tree<'static>>,
    new: Digest,
    after: &BTreeMap<Digest, Tree<'static>>,
) {
    let mut old_entries = Entries::new();
    let mut new_entries = Entries::new();
    let mut old_roots = Roots::new();
    let mut new_roots = Roots::new();
    inventory(old, before, &[], &mut old_entries, &mut old_roots);
    inventory(new, after, &[], &mut new_entries, &mut new_roots);
    let keys: alloc::collections::BTreeSet<_> = old_entries
        .keys()
        .chain(new_entries.keys())
        .cloned()
        .collect();
    let mut inputs = BTreeMap::new();
    let mut data = BTreeMap::new();
    for key in keys {
        let left = old_entries.get(&key);
        let right = new_entries.get(&key);
        if left.map(|(_, entry)| entry) != right.map(|(_, entry)| entry) {
            inputs.insert(
                key.clone(),
                InputChange {
                    old_address: left.map(|(address, _)| address.clone()),
                    new_address: right.map(|(address, _)| address.clone()),
                    old: left.map(|(_, entry)| entry.clone()),
                    new: right.map(|(_, entry)| entry.clone()),
                },
            );
        }
        let old_state = left.and_then(|(_, entry)| selected(entry));
        let new_state = right.and_then(|(_, entry)| selected(entry));
        let old_state = if result.sources().mode() == PopulationMode::NewlyEnabled {
            None
        } else {
            old_state
        };
        if old_state != new_state {
            data.insert(
                key,
                DataChange {
                    old_address: old_state
                        .as_ref()
                        .and_then(|_| left.map(|(address, _)| address.clone())),
                    new_address: new_state
                        .as_ref()
                        .and_then(|_| right.map(|(address, _)| address.clone())),
                    old: old_state,
                    new: new_state,
                },
            );
        }
    }
    assert_eq!(result.inputs.len(), inputs.len());
    assert_eq!(result.data.len(), data.len());
    assert_eq!(result.delta_data(), data.len());
    let expected_inputs = inputs.len();
    assert_eq!(
        result
            .inputs
            .iter()
            .map(|change| (
                change_path(change.old_address.as_ref(), change.new_address.as_ref()),
                change.clone()
            ))
            .collect::<BTreeMap<_, _>>(),
        inputs
    );
    assert_eq!(
        result
            .data
            .iter()
            .map(|change| (
                change_path(change.old_address.as_ref(), change.new_address.as_ref()),
                change.clone()
            ))
            .collect::<BTreeMap<_, _>>(),
        data
    );
    let keys: alloc::collections::BTreeSet<_> =
        old_roots.keys().chain(new_roots.keys()).cloned().collect();
    let mut properties = BTreeMap::new();
    let mut envelopes = BTreeMap::new();
    for key in keys {
        let left = old_roots.get(&key);
        let right = new_roots.get(&key);
        if let (Some((old_hops, old_root, old_props)), Some((new_hops, new_root, new_props))) =
            (left, right)
            && old_props.is_some() != new_props.is_some()
        {
            envelopes.insert(
                key.clone(),
                RootEnvelopeChange {
                    old_root: *old_root,
                    new_root: *new_root,
                    old_hops: old_hops.clone(),
                    new_hops: new_hops.clone(),
                    old_present: old_props.is_some(),
                    new_present: new_props.is_some(),
                },
            );
        }
        let old_props: BTreeMap<_, _> = left
            .and_then(|(_, _, props)| props.as_ref())
            .into_iter()
            .flatten()
            .map(|binding| (binding.name, *binding))
            .collect();
        let new_props: BTreeMap<_, _> = right
            .and_then(|(_, _, props)| props.as_ref())
            .into_iter()
            .flatten()
            .map(|binding| (binding.name, *binding))
            .collect();
        let names: alloc::collections::BTreeSet<_> =
            old_props.keys().chain(new_props.keys()).copied().collect();
        for name in names {
            if old_props.get(name) != new_props.get(name) {
                properties.insert(
                    (key.clone(), name),
                    PropertyChange {
                        old_hops: left.map(|(hops, _, _)| hops.clone()),
                        new_hops: right.map(|(hops, _, _)| hops.clone()),
                        old_root: left.map(|(_, root, _)| *root),
                        new_root: right.map(|(_, root, _)| *root),
                        old: old_props.get(name).copied(),
                        new: new_props.get(name).copied(),
                    },
                );
            }
        }
    }
    assert_eq!(result.properties.len(), properties.len());
    assert_eq!(result.envelopes.len(), envelopes.len());
    assert_eq!(result.delta_input(), expected_inputs + properties.len());
    assert_eq!(
        result
            .properties
            .iter()
            .map(|change| (
                (
                    path(
                        change
                            .new_hops
                            .as_deref()
                            .or(change.old_hops.as_deref())
                            .unwrap()
                    ),
                    change.new.or(change.old).unwrap().name
                ),
                change.clone()
            ))
            .collect::<BTreeMap<_, _>>(),
        properties
    );
    assert_eq!(
        result
            .envelopes
            .iter()
            .map(|change| (path(&change.new_hops), change.clone()))
            .collect::<BTreeMap<_, _>>(),
        envelopes
    );
}
