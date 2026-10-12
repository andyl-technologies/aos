//! Expands finite namespace models independently of incremental maintenance.

use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};

use super::*;
use crate::cbor;
use crate::tree_format::{NodeItems, Property};

type Properties =
    BTreeMap<(Vec<Vec<u8>>, alloc::string::String), (Digest, Address, Property<'static>)>;

/// Maps contextual coordinates and local keys to complete logical row/binding values.
pub(super) type Logical = BTreeMap<(Coordinate, Vec<u8>), RouteValue>;

/// Owns independently expanded namespace states and their canonical index closure.
pub(super) struct Model {
    /// Canonical auxiliary closure built from the complete finite namespace model.
    pub(super) data: IndexData,
    /// Complete row and gap/owner-binding values keyed by coordinate and local key.
    pub(super) logical: Logical,
    /// Namespace root at each local graft-key sequence, retaining repeated occurrences.
    pub(super) sources: BTreeMap<Vec<Vec<u8>>, Digest>,
    /// Complete namespace entries and source-bearing addresses at expanded key sequences.
    pub(super) inputs: BTreeMap<Vec<Vec<u8>>, (Address, Entry<'static>)>,
    properties: Properties,
}

fn binding(attribute: Option<&str>, root: Digest) -> Vec<u8> {
    let mut bytes = Vec::new();
    cbor::write_map(&mut bytes, 2);
    cbor::write_text(&mut bytes, "value");
    if let Some(attribute) = attribute {
        cbor::write_map(&mut bytes, 1);
        cbor::write_text(&mut bytes, attribute);
    }
    let hex: alloc::string::String = root
        .iter()
        .map(|byte| alloc::format!("{byte:02x}"))
        .collect();
    cbor::write_text(&mut bytes, &hex);
    cbor::write_text(&mut bytes, "inherit");
    bytes.push(0xf4);
    bytes
}

impl Model {
    /// Expands a finite uid namespace into independent source and index models.
    ///
    /// # Panics
    /// Panics if a referenced source is absent, an inventoried predicate lacks a
    /// route, index Tree construction fails or logical row keys collide. The graph
    /// must be acyclic.
    pub(super) fn new(graph: &Graph, owner: Digest) -> Self {
        let mut model = Self {
            data: IndexData {
                root: [0; 32],
                nodes: BTreeMap::new(),
                work: Default::default(),
            },
            logical: BTreeMap::new(),
            sources: BTreeMap::new(),
            inputs: BTreeMap::new(),
            properties: BTreeMap::new(),
        };
        let mut predicates = BTreeSet::new();
        model.inventory(graph, owner, Vec::new(), Vec::new(), &mut predicates);
        let mut present = Vec::new();
        let mut missing = Vec::new();
        for predicate in predicates {
            let route = model.route(graph, owner, &predicate, Vec::new()).unwrap();
            let mut key = predicate.value.clone().unwrap_or_default();
            key.extend_from_slice(&predicate.object);
            let row = RouteValue::Row {
                object: predicate.object,
                route: Some(route),
            };
            if predicate.value.is_some() {
                present.push((key, row));
            } else {
                missing.push((key, row));
            }
        }
        present.sort_by(|left, right| left.0.cmp(&right.0));
        missing.sort_by(|left, right| left.0.cmp(&right.0));
        let gap = if missing.is_empty() {
            None
        } else {
            Some(model.tree(Coordinate::Gap, missing, None))
        };
        let properties = gap.map(|root| binding(None, root));
        let primary = model.tree(Coordinate::Primary, present, properties.as_deref());
        if let Some(bytes) = properties {
            model.logical.insert(
                (Coordinate::Primary, b"index-gaps".to_vec()),
                RouteValue::Binding { bytes },
            );
        }
        model.logical.insert(
            (Coordinate::Primary, b"uid".to_vec()),
            RouteValue::Binding {
                bytes: binding(Some("uid"), primary),
            },
        );
        model.data.root = primary;
        model
    }

    fn inventory(
        &mut self,
        graph: &Graph,
        root: Digest,
        hops: Vec<Vec<u8>>,
        address: Address,
        predicates: &mut BTreeSet<Predicate>,
    ) {
        self.sources.insert(hops.clone(), root);
        for property in graph[&root].props().unwrap_or_default() {
            self.properties.insert(
                (hops.clone(), property.name.into()),
                (root, address.clone(), *property),
            );
        }
        for item in graph[&root].iter() {
            let mut keys = hops.clone();
            keys.push(item.key.clone());
            let mut occurrence = address.clone();
            occurrence.push(Hop {
                source: root,
                key: item.key.clone(),
            });
            self.inputs
                .insert(keys.clone(), (occurrence.clone(), item.entry.clone()));
            match &item.entry.kind {
                EntryKind::File { content, .. } => {
                    predicates.insert(Predicate {
                        object: object(*content),
                        value: item
                            .entry
                            .attrs
                            .iter()
                            .find(|attribute| attribute.name == "uid")
                            .map(|attribute| attribute.value.to_vec()),
                    });
                }
                EntryKind::Tree { root, .. } => {
                    self.inventory(graph, *root, keys, occurrence, predicates)
                }
                _ => {}
            }
        }
    }

    fn route(
        &mut self,
        graph: &Graph,
        root: Digest,
        predicate: &Predicate,
        hops: Vec<Vec<u8>>,
    ) -> Option<Digest> {
        let mut rows = Vec::new();
        for item in graph[&root].iter() {
            let value = match &item.entry.kind {
                EntryKind::File { content, .. }
                    if object(*content) == predicate.object
                        && item
                            .entry
                            .attrs
                            .iter()
                            .find(|attribute| attribute.name == "uid")
                            .map(|attribute| attribute.value)
                            == predicate.value.as_deref() =>
                {
                    Some(RouteValue::Row {
                        object: predicate.object,
                        route: None,
                    })
                }
                EntryKind::Tree { root, .. } => {
                    let mut child_hops = hops.clone();
                    child_hops.push(item.key.clone());
                    self.route(graph, *root, predicate, child_hops)
                        .map(|route| RouteValue::Row {
                            object: predicate.object,
                            route: Some(route),
                        })
                }
                _ => None,
            };
            if let Some(value) = value {
                rows.push((item.key.clone(), value));
            }
        }
        (!rows.is_empty()).then(|| {
            self.tree(
                Coordinate::Route {
                    predicate: predicate.clone(),
                    hops,
                },
                rows,
                None,
            )
        })
    }

    fn tree(
        &mut self,
        coordinate: Coordinate,
        rows: Vec<(Vec<u8>, RouteValue)>,
        gap: Option<&[u8]>,
    ) -> Digest {
        let pointers: Vec<_> = rows
            .iter()
            .map(|(_, value)| {
                let mut bytes = Vec::new();
                if let RouteValue::Row {
                    route: Some(root), ..
                } = value
                {
                    cbor::write_bytes(&mut bytes, root);
                }
                bytes
            })
            .collect();
        let entries = rows
            .iter()
            .zip(&pointers)
            .map(|((key, value), bytes)| {
                let RouteValue::Row { object, route } = value else {
                    panic!("oracle expected row");
                };
                LeafItem {
                    key: key.clone(),
                    entry: Entry {
                        kind: EntryKind::Index {
                            targets: alloc::vec![*object],
                        },
                        attrs: if route.is_some() {
                            alloc::vec![Attribute {
                                name: "index.occurrences",
                                value: bytes
                            }]
                        } else {
                            Vec::new()
                        },
                        attrs_present: route.is_some(),
                        xattrs: Vec::new(),
                        xattrs_present: false,
                        provenance: None,
                    },
                }
            })
            .collect();
        let properties = gap.map(|value| {
            alloc::vec![Property {
                name: "index-gaps",
                value
            }]
        });
        let tree = Tree::build(entries, properties, MINIMUM, TreeUse::Index).unwrap();
        for node in tree.nodes() {
            if let NodeItems::Leaf(items) = node.items() {
                for item in items {
                    assert!(matches!(item.entry.kind, EntryKind::Index { .. }));
                }
            }
            self.data
                .nodes
                .insert(node.identity(), node.encoded().to_vec());
        }
        for (key, row) in rows {
            assert!(
                self.logical
                    .insert((coordinate.clone(), key), row)
                    .is_none()
            );
        }
        tree.root_identity()
    }
}

/// Compares discovery inputs, participating states and properties with full models.
///
/// # Panics
/// Panics if transitions/counts differ, transition addresses are absent or model
/// source paths are incomplete.
pub(super) fn assert_discovery(old: &Model, new: &Model, discovery: &Discovery<'_, '_>) {
    let keys: BTreeSet<_> = old
        .inputs
        .keys()
        .chain(new.inputs.keys())
        .cloned()
        .collect();
    let mut inputs = Vec::new();
    let mut data = Vec::new();
    for key in keys {
        let previous = old.inputs.get(&key);
        let replacement = new.inputs.get(&key);
        if previous.map(|(_, entry)| entry) != replacement.map(|(_, entry)| entry) {
            inputs.push(InputChange {
                old_address: previous.map(|(address, _)| address.clone()),
                new_address: replacement.map(|(address, _)| address.clone()),
                old: previous.map(|(_, entry)| entry.clone()),
                new: replacement.map(|(_, entry)| entry.clone()),
            });
        }
        let state = |side: Option<&(Address, Entry<'static>)>| {
            side.and_then(|(_, entry)| match entry.kind {
                EntryKind::File { content, .. } => Some(FileState {
                    content,
                    value: entry
                        .attrs
                        .iter()
                        .find(|attribute| attribute.name == "uid")
                        .map(|attribute| attribute.value.to_vec()),
                }),
                _ => None,
            })
        };
        let before = state(previous);
        let after = state(replacement);
        if before != after {
            data.push(DataChange {
                old_address: before
                    .as_ref()
                    .and(previous.map(|(address, _)| address.clone())),
                new_address: after
                    .as_ref()
                    .and(replacement.map(|(address, _)| address.clone())),
                old: before,
                new: after,
            });
        }
    }
    fn sort_inputs<'a>(rows: &[InputChange<'a>]) -> BTreeMap<Vec<Vec<u8>>, InputChange<'a>> {
        rows.iter()
            .map(|row| {
                (
                    row.old_address
                        .as_ref()
                        .or(row.new_address.as_ref())
                        .unwrap()
                        .iter()
                        .map(|hop| hop.key.clone())
                        .collect::<Vec<_>>(),
                    row.clone(),
                )
            })
            .collect()
    }
    let sort_data = |rows: &[DataChange]| -> BTreeMap<_, _> {
        rows.iter()
            .map(|row| {
                (
                    row.old_address
                        .as_ref()
                        .or(row.new_address.as_ref())
                        .unwrap()
                        .iter()
                        .map(|hop| hop.key.clone())
                        .collect::<Vec<_>>(),
                    row.clone(),
                )
            })
            .collect()
    };
    assert_eq!(discovery.inputs().len(), inputs.len());
    assert_eq!(sort_inputs(discovery.inputs()), sort_inputs(&inputs));
    assert_eq!(discovery.data().len(), data.len());
    assert_eq!(sort_data(discovery.data()), sort_data(&data));
    assert_eq!(discovery.delta_data(), data.len());
    let property_keys: BTreeSet<_> = old
        .properties
        .keys()
        .chain(new.properties.keys())
        .cloned()
        .collect();
    let mut properties = Vec::new();
    for key in property_keys {
        let before = old.properties.get(&key);
        let after = new.properties.get(&key);
        if before.map(|(_, _, property)| property) != after.map(|(_, _, property)| property) {
            properties.push(crate::indexing::incremental::PropertyChange {
                old_hops: old.sources.get(&key.0).map(|_| {
                    before.map_or_else(
                        || address_for(old, &key.0),
                        |(_, address, _)| address.clone(),
                    )
                }),
                new_hops: new.sources.get(&key.0).map(|_| {
                    after.map_or_else(
                        || address_for(new, &key.0),
                        |(_, address, _)| address.clone(),
                    )
                }),
                old_root: old.sources.get(&key.0).copied(),
                new_root: new.sources.get(&key.0).copied(),
                old: before.map(|(_, _, property)| *property),
                new: after.map(|(_, _, property)| *property),
            });
        }
    }
    let by_property =
        |rows: &[crate::indexing::incremental::PropertyChange<'static>]| -> BTreeMap<_, _> {
            rows.iter()
                .map(|row| {
                    (
                        (
                            row.old_hops
                                .as_ref()
                                .or(row.new_hops.as_ref())
                                .unwrap()
                                .iter()
                                .map(|hop| hop.key.clone())
                                .collect::<Vec<_>>(),
                            row.old.as_ref().or(row.new.as_ref()).unwrap().name,
                        ),
                        row.clone(),
                    )
                })
                .collect()
        };
    assert_eq!(discovery.properties().len(), properties.len());
    // Compare the full borrowed values without assigning them a static lifetime.
    for expected in &properties {
        assert!(
            discovery
                .properties()
                .iter()
                .any(|actual| actual == expected)
        );
    }
    assert_eq!(by_property(&properties).len(), properties.len());
    assert_eq!(discovery.delta_input(), inputs.len() + properties.len());
}

fn address_for(model: &Model, hops: &[Vec<u8>]) -> Address {
    let mut address = Vec::new();
    for (index, key) in hops.iter().enumerate() {
        address.push(Hop {
            source: model.sources[&hops[..index].to_vec()],
            key: key.clone(),
        });
    }
    address
}

/// Compares complete route transitions and closure work with full model differences.
///
/// # Panics
/// Panics if model Node decoding fails or route/closure fields and counts differ.
pub(super) fn assert_routes(old: &Model, new: &Model, work: &UpdateWork) {
    let added: Vec<_> = new
        .data
        .nodes
        .iter()
        .filter(|(identity, _)| !old.data.nodes.contains_key(*identity))
        .collect();
    let removed: Vec<_> = old
        .data
        .nodes
        .iter()
        .filter(|(identity, _)| !new.data.nodes.contains_key(*identity))
        .collect();
    fn edges(bytes: &[u8]) -> usize {
        let node =
            crate::tree_format::decode_node_for(bytes, true, MINIMUM, TreeUse::Index).unwrap();
        let rows = match node.items {
            NodeItems::Internal(children) => children.len(),
            NodeItems::Leaf(rows) => rows
                .iter()
                .filter(|row| {
                    row.entry
                        .attrs
                        .iter()
                        .any(|attribute| attribute.name == "index.occurrences")
                })
                .count(),
        };
        rows + usize::from(node.props.as_ref().is_some_and(|properties| {
            properties
                .iter()
                .any(|property| property.name == "index-gaps")
        }))
    }
    assert_eq!(work.closure_added, added.len());
    assert_eq!(work.closure_removed, removed.len());
    let expected_edges: usize = added
        .iter()
        .chain(&removed)
        .map(|(_, bytes)| edges(bytes))
        .sum();
    assert_eq!(work.closure_edges, expected_edges);
    let keys: BTreeSet<_> = old
        .logical
        .keys()
        .chain(new.logical.keys())
        .cloned()
        .collect();
    let expected: BTreeMap<_, _> = keys
        .into_iter()
        .filter_map(|(coordinate, key)| {
            let previous = old.logical.get(&(coordinate.clone(), key.clone()));
            let replacement = new.logical.get(&(coordinate.clone(), key.clone()));
            if previous == replacement {
                return None;
            }
            let (old_source, new_source) = match &coordinate {
                Coordinate::Route { hops, .. } => (
                    old.sources.get(hops).copied(),
                    new.sources.get(hops).copied(),
                ),
                Coordinate::Primary if key == b"uid" => (
                    old.sources.get(&Vec::new()).copied(),
                    new.sources.get(&Vec::new()).copied(),
                ),
                _ => (None, None),
            };
            Some((
                (coordinate.clone(), key.clone()),
                RouteChange {
                    coordinate,
                    key,
                    old: previous.cloned(),
                    new: replacement.cloned(),
                    old_source,
                    new_source,
                },
            ))
        })
        .collect();
    assert_eq!(work.routes.len(), expected.len());
    assert_eq!(work.delta_route, expected.len());
    let actual: BTreeMap<_, _> = work
        .routes
        .iter()
        .cloned()
        .map(|row| ((row.coordinate.clone(), row.key.clone()), row))
        .collect();
    assert_eq!(actual.len(), work.routes.len());
    assert_eq!(actual, expected);
}
