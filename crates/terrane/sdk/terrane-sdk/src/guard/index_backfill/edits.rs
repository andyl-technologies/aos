//! Batches ordinary inline edits and initializes only genuinely absent bindings.

use std::collections::{BTreeMap, BTreeSet};

use terrane_format::derived::{AttributeName, AttributeValue, Magic};
use terrane_format::identity::{Digest, IdentityKind};
use terrane_format::indexing::{
    IndexEvaluationRecipe, IndexRoots, carrier::SemanticContext, completion, incremental,
    maintenance,
};
use terrane_format::properties::{PropertyName, RootLayer, Value};
use terrane_format::tree_format::{Attribute, ContentRef, Entry, EntryKind};

use crate::derived::Requirements;
use crate::guard::{AuthorizedSnapshot, Guard, StagedUpload};
use crate::repository::PreparedTree;
use crate::store::{Clock, Store, StoreFailure};

use super::records::Records;
use super::{
    IndexBackfillCopy, IndexBackfillGap, IndexBackfillGapReason, IndexBackfillInitialization,
    IndexBackfillReport, PreparedIndexBackfill,
};

type FileKey = (Digest, Vec<u8>);

struct File {
    object: Digest,
    inline: BTreeMap<String, Vec<u8>>,
    required: BTreeMap<String, Vec<Vec<u8>>>,
    unknown: BTreeMap<String, Vec<Vec<u8>>>,
}

struct Copy {
    value: Vec<u8>,
    attribution: IndexBackfillCopy,
}

struct Plan {
    copies: BTreeMap<FileKey, BTreeMap<String, Copy>>,
    indexes: BTreeMap<Digest, BTreeSet<String>>,
    depth: BTreeMap<Digest, usize>,
    report: IndexBackfillReport,
}

/// Retains a preparation diagnostic as the source of a malformed-request refusal.
pub(super) fn failure<E>(error: E) -> StoreFailure
where
    E: std::error::Error + Send + Sync + 'static,
{
    StoreFailure::with_source(crate::guard::invalid().kind().clone(), error)
}

fn path(root: &[u8], key: &[u8]) -> Vec<u8> {
    let mut path = root.to_vec();
    if path != b"/" {
        path.push(b'/');
    }
    path.extend_from_slice(key);
    path
}

fn require(file: &mut File, name: &str, path: &[u8]) {
    file.required
        .entry(name.to_owned())
        .or_default()
        .push(path.to_vec());
}

fn gap(
    report: &mut IndexBackfillReport,
    owner: Digest,
    name: &str,
    paths: &[Vec<u8>],
    reason: IndexBackfillGapReason,
) {
    report
        .gaps
        .extend(paths.iter().map(|path| IndexBackfillGap {
            owner,
            path: path.clone(),
            attribute: name.to_owned(),
            reason: reason.clone(),
        }));
}

fn magic(file: &File, records: &Records) -> Result<Option<Magic>, StoreFailure> {
    let Some(record) = records
        .table
        .current(file.object, AttributeName::Magic, true)
    else {
        return Ok(None);
    };
    let value = record.value.encode().map_err(failure)?;
    if let Some(inline) = file.inline.get("class.magic")
        && inline != &value
    {
        return Ok(None);
    }
    if records
        .table
        .agree_inline(file.object, AttributeName::Magic, &record.function, &value)
        .is_err()
    {
        return Ok(None);
    }
    match record.value {
        AttributeValue::Magic(magic) => Ok(Some(magic)),
        _ => Err(crate::guard::invalid()),
    }
}

fn plan<S: Store, C: Clock>(
    guard: &Guard<S, C>,
    snapshot: &AuthorizedSnapshot,
    records: &Records,
) -> Result<Plan, StoreFailure> {
    let minimum = guard.config().min_chunk_size;
    let occurrences = snapshot.evidence.occurrences(minimum)?;
    let mut files: BTreeMap<FileKey, File> = BTreeMap::new();
    let mut plan = Plan {
        copies: BTreeMap::new(),
        indexes: BTreeMap::new(),
        depth: BTreeMap::new(),
        report: IndexBackfillReport {
            source_view: snapshot.commit.identity(),
            ..IndexBackfillReport::default()
        },
    };
    plan.report.coverage.root_occurrences = occurrences.len();
    for occurrence in occurrences {
        plan.depth
            .entry(occurrence.root)
            .and_modify(|depth| *depth = (*depth).max(occurrence.path.len()))
            .or_insert(occurrence.path.len());
        let layers = occurrence
            .layers
            .iter()
            .map(|(properties, overrides)| RootLayer {
                properties,
                overrides,
            })
            .collect::<Vec<_>>();
        let effective = snapshot
            .interpretation
            .resolve(&layers, guard.defaults_for(&snapshot.evidence))?;
        let requirements = Requirements::from_effective(&effective).map_err(failure)?;
        let Some(Value::Names(indexes)) = effective.get(PropertyName::Index) else {
            return Err(crate::guard::invalid());
        };
        plan.indexes
            .entry(occurrence.root)
            .or_default()
            .extend(indexes.iter().map(|name| (*name).to_owned()));
        let tree = snapshot.evidence.tree(occurrence.root, minimum)?;
        for item in tree.iter() {
            let full = path(&occurrence.path, &item.key);
            let object = match &item.entry.kind {
                EntryKind::File {
                    content: ContentRef::Inline(object) | ContentRef::Manifest(object),
                    ..
                } => *object,
                EntryKind::Conflict { .. } => {
                    let names = indexes
                        .iter()
                        .map(|name| (*name).to_owned())
                        .chain(
                            requirements
                                .names(None)
                                .into_iter()
                                .map(|name| name.as_str().to_owned()),
                        )
                        .collect::<BTreeSet<_>>();
                    for name in names {
                        gap(
                            &mut plan.report,
                            occurrence.root,
                            &name,
                            std::slice::from_ref(&full),
                            IndexBackfillGapReason::UnsupportedOccurrence,
                        );
                    }
                    continue;
                }
                _ => continue,
            };
            plan.report.coverage.file_occurrences += 1;
            let file = files
                .entry((occurrence.root, item.key.clone()))
                .or_insert_with(|| File {
                    object,
                    inline: item
                        .entry
                        .attrs
                        .iter()
                        .map(|attribute| (attribute.name.to_owned(), attribute.value.to_vec()))
                        .collect(),
                    required: BTreeMap::new(),
                    unknown: BTreeMap::new(),
                });
            let classifier = magic(file, records)?;
            for name in requirements.names(classifier) {
                require(file, name.as_str(), &full);
            }
            for name in indexes {
                if !file.inline.contains_key(*name) {
                    plan.report.coverage.raw_missing_index_inputs += 1;
                }
                let conditional = match *name {
                    "class.elf" => Some(Magic::Elf),
                    "class.shebang" => Some(Magic::Shebang),
                    _ => None,
                };
                if let Some(expected) = conditional {
                    if file.inline.contains_key(*name) {
                        require(file, name, &full);
                    } else {
                        require(file, "class.magic", &full);
                        match classifier {
                            Some(actual) if actual == expected => require(file, name, &full),
                            Some(_) => {}
                            None => file
                                .unknown
                                .entry((*name).to_owned())
                                .or_default()
                                .push(full.clone()),
                        }
                    }
                } else {
                    require(file, name, &full);
                }
            }
            // Classify-only conditional details also need positive evidence;
            // names(None) is not a proof that ELF/shebang is inapplicable.
            if classifier.is_none() {
                for classifier in &requirements.classify {
                    let name = match classifier {
                        Magic::Elf => "class.elf",
                        Magic::Shebang => "class.shebang",
                        _ => continue,
                    };
                    file.unknown
                        .entry(name.to_owned())
                        .or_default()
                        .push(full.clone());
                }
            }
        }
    }
    for ((owner, key), mut file) in files {
        for paths in file.required.values_mut().chain(file.unknown.values_mut()) {
            paths.sort();
            paths.dedup();
        }
        plan.report.coverage.required_inputs += file.required.values().map(Vec::len).sum::<usize>()
            + file.unknown.values().map(Vec::len).sum::<usize>();
        let mut copies = BTreeMap::new();
        let mut blocked = !file.unknown.is_empty();
        let mut failures = BTreeMap::new();
        for (name, paths) in &file.required {
            let parsed = AttributeName::parse(name);
            if let Some(inline) = file.inline.get(name) {
                if let Ok(name) = parsed {
                    AttributeValue::decode(name, inline).map_err(failure)?;
                    if let Some(record) = records.table.current(file.object, name, true)
                        && records
                            .table
                            .agree_inline(file.object, name, &record.function, inline)
                            .is_err()
                    {
                        failures.insert(
                            name.as_str().to_owned(),
                            IndexBackfillGapReason::ValueDisagreement,
                        );
                        blocked = true;
                    }
                }
                continue;
            }
            let name = match parsed {
                Ok(name) => name,
                Err(_) => {
                    failures.insert(name.clone(), IndexBackfillGapReason::UnsupportedInput);
                    blocked = true;
                    continue;
                }
            };
            let Some(record) = records.table.current(file.object, name, true) else {
                failures.insert(name.as_str().to_owned(), records.missing(file.object, name));
                blocked = true;
                continue;
            };
            let value = record.value.encode().map_err(failure)?;
            if records
                .table
                .agree_inline(file.object, name, &record.function, &value)
                .is_err()
            {
                failures.insert(
                    name.as_str().to_owned(),
                    IndexBackfillGapReason::ValueDisagreement,
                );
                blocked = true;
                continue;
            }
            let checked = records.selected(record)?;
            copies.insert(
                name.as_str().to_owned(),
                Copy {
                    value: value.clone(),
                    attribution: IndexBackfillCopy {
                        record: record.identity().map_err(failure)?,
                        producer: checked.record.producer,
                        producer_path: checked.path.clone(),
                        object: file.object,
                        attribute: name.as_str().to_owned(),
                        function: checked.record.function.clone(),
                        value,
                        paths: paths.clone(),
                    },
                },
            );
        }
        for (name, paths) in &file.unknown {
            gap(
                &mut plan.report,
                owner,
                name,
                paths,
                IndexBackfillGapReason::UnknownApplicability,
            );
        }
        if blocked {
            for (name, paths) in &file.required {
                let reason = failures.get(name).cloned().or_else(|| {
                    (!file.inline.contains_key(name))
                        .then_some(IndexBackfillGapReason::DeferredFile)
                });
                if let Some(reason) = reason {
                    gap(&mut plan.report, owner, name, paths, reason);
                }
            }
        } else if !copies.is_empty() {
            for copy in copies.values() {
                plan.report.coverage.materialized_inputs += copy.attribution.paths.len();
                plan.report.copied.push(copy.attribution.clone());
            }
            plan.copies.insert((owner, key), copies);
        }
    }
    Ok(plan)
}

fn replace_targets(entry: &mut Entry<'_>, replacements: &BTreeMap<Digest, Digest>) -> bool {
    let mut changed = false;
    let mut entries = vec![entry];
    while let Some(entry) = entries.pop() {
        match &mut entry.kind {
            EntryKind::Tree { root, .. } => {
                if let Some(replacement) = replacements.get(root) {
                    *root = *replacement;
                    changed = true;
                }
            }
            EntryKind::Conflict { candidates, base } => {
                entries.extend(candidates.iter_mut());
                if let Some(Some(base)) = base {
                    entries.push(base);
                }
            }
            _ => {}
        }
    }
    changed
}

/// Prepares canonical backfill edits from authenticated snapshot and side records.
///
/// # Errors
/// Rejects incomplete or contradictory evidence and preserves canonical tree,
/// index preparation, attribute-value and encoding failures.
pub(super) fn execute<S: Store, C: Clock>(
    guard: &Guard<S, C>,
    snapshot: &AuthorizedSnapshot,
    records: &Records,
) -> Result<PreparedIndexBackfill, StoreFailure> {
    let mut plan = plan(guard, snapshot, records)?;
    let minimum = guard.config().min_chunk_size;
    let context = SemanticContext::new(3, 2, 1).map_err(failure)?;
    let arena = maintenance::ByteArena::new(usize::MAX).map_err(failure)?;
    let mut graph = snapshot
        .evidence
        .roots
        .iter()
        .map(|root| Ok((*root, snapshot.evidence.tree(*root, minimum)?)))
        .collect::<Result<BTreeMap<_, _>, StoreFailure>>()?;
    let mut order = plan
        .depth
        .iter()
        .map(|(owner, depth)| (*owner, *depth))
        .collect::<Vec<_>>();
    order.sort_by(|left, right| right.1.cmp(&left.1).then(left.0.cmp(&right.0)));
    let mut replacements = BTreeMap::new();
    let mut nodes = BTreeMap::new();
    for (owner, _) in order {
        let original = graph.get(&owner).ok_or_else(crate::guard::invalid)?.clone();
        let mut changes = Vec::new();
        for item in original.iter() {
            let mut entry = item.entry.clone();
            let mut changed = replace_targets(&mut entry, &replacements);
            if let Some(copies) = plan.copies.get(&(owner, item.key.clone())) {
                for (name, copy) in copies {
                    entry.attrs.push(Attribute {
                        name,
                        value: &copy.value,
                    });
                }
                entry.attrs.sort_by(|left, right| left.name.cmp(right.name));
                changed = true;
            }
            if changed {
                changes.push((item.key.clone(), Some(entry)));
            }
        }
        let current = if changes.is_empty() {
            owner
        } else {
            let edited = original.edit_entries(&changes).map_err(failure)?;
            for node in &edited.emitted {
                nodes.insert(node.identity(), node.encoded().to_vec());
            }
            let root = edited.tree.root_identity();
            plan.report.edits.push(edited.work);
            graph.insert(root, edited.tree);
            root
        };
        let tree = graph.get(&current).ok_or_else(crate::guard::invalid)?;
        let bindings = tree
            .props()
            .unwrap_or_default()
            .iter()
            .find(|property| property.name == "index-roots")
            .map(|property| IndexRoots::decode_binding(property.value))
            .transpose()
            .map_err(failure)?
            .unwrap_or_default();
        let missing = plan
            .indexes
            .get(&owner)
            .into_iter()
            .flatten()
            .filter(|name| bindings.get(name).is_none())
            .cloned()
            .collect::<Vec<_>>();
        let mut data = BTreeMap::new();
        for attribute in missing {
            let recipe = IndexEvaluationRecipe::new(current, &attribute).map_err(failure)?;
            let source = incremental::PreparedSource::new(&recipe, &graph, minimum, context)
                .map_err(failure)?;
            let (initialized, construction) =
                maintenance::initialize(&recipe, &source, &arena, minimum, context)
                    .map_err(failure)?;
            let (output, export) = initialized.materialize().map_err(failure)?;
            nodes.extend(
                output
                    .nodes
                    .iter()
                    .map(|(identity, bytes)| (*identity, bytes.clone())),
            );
            plan.report
                .initialization
                .push(IndexBackfillInitialization {
                    owner: current,
                    attribute: attribute.clone(),
                    construction,
                    export,
                });
            data.insert(attribute, output);
        }
        let current = if data.is_empty() {
            current
        } else {
            let selections = data
                .iter()
                .map(|(attribute, data)| completion::Selection { attribute, data })
                .collect::<Vec<_>>();
            let completed = completion::complete(
                current,
                &graph,
                &selections,
                &arena,
                minimum,
                context,
                completion::MemoPolicy::Omit,
            )
            .map_err(failure)?;
            for node in &completed.owner.emitted {
                nodes.insert(node.identity(), node.encoded().to_vec());
            }
            let root = completed.owner.tree.root_identity();
            plan.report.completion.push(completed.work);
            graph.insert(root, completed.owner.tree);
            root
        };
        if current != owner {
            replacements.insert(owner, current);
        }
    }
    let root = replacements
        .get(&snapshot.evidence.root)
        .copied()
        .unwrap_or(snapshot.evidence.root);
    let tree = if root == snapshot.evidence.root {
        None
    } else {
        let mut prepared =
            PreparedTree::from_tree(graph.get(&root).ok_or_else(crate::guard::invalid)?)
                .map_err(failure)?;
        let existing = prepared
            .uploads
            .iter()
            .filter_map(|upload| match upload {
                StagedUpload::Meta {
                    kind: IdentityKind::Node,
                    bytes,
                } => Some(bytes.clone()),
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        prepared.uploads.extend(
            nodes
                .into_values()
                .filter(|bytes| !existing.contains(bytes))
                .map(|bytes| StagedUpload::Meta {
                    kind: IdentityKind::Node,
                    bytes,
                }),
        );
        Some(prepared)
    };
    let selected = plan
        .report
        .copied
        .iter()
        .map(|copy| {
            Ok((
                super::records::record_key(&copy.record)?,
                copy.record.clone(),
            ))
        })
        .collect::<Result<BTreeMap<_, _>, StoreFailure>>()?;
    let mut uploads = Vec::new();
    for identity in selected.into_values() {
        let copy = plan
            .report
            .copied
            .iter()
            .find(|copy| copy.record == identity)
            .ok_or_else(crate::guard::invalid)?;
        let name = AttributeName::parse(&copy.attribute).map_err(failure)?;
        let record = records
            .table
            .current(copy.object, name, true)
            .ok_or_else(crate::guard::invalid)?;
        if record.identity().map_err(failure)? != identity {
            return Err(crate::guard::invalid());
        }
        uploads.push(StagedUpload::Meta {
            kind: IdentityKind::Attribute,
            bytes: record.encode().map_err(failure)?,
        });
    }
    // Conditional exclusions can depend on an already present Magic value.
    // Retain its authentic side evidence for ordinary changed-file admission.
    for copy in &plan.report.copied {
        if let Some(record) = records
            .table
            .current(copy.object, AttributeName::Magic, true)
        {
            let encoded = record.encode().map_err(failure)?;
            let already_uploaded = uploads.iter().any(|upload| match upload {
                StagedUpload::Meta {
                    kind: IdentityKind::Attribute,
                    bytes,
                } => bytes == &encoded,
                _ => false,
            });

            if !already_uploaded {
                uploads.push(StagedUpload::Meta {
                    kind: IdentityKind::Attribute,
                    bytes: encoded,
                });
            }
        }
    }
    Ok(PreparedIndexBackfill {
        #[cfg(unix)]
        references: None,
        tree,
        uploads,
        report: plan.report,
    })
}
