//! Executes borrowed pure maintenance after all native input acquisition ends.
//!
//! Child completion precedes containing-root edits. Every exported owner and
//! auxiliary Node is ordinary immutable data awaiting the existing publication.

use std::collections::{BTreeMap, BTreeSet};

use terrane_format::identity::Digest;
use terrane_format::indexing::{
    IndexEvaluationRecipe, carrier::SemanticContext, completion, incremental, maintenance,
};

use super::{
    Acquired, DroppedBinding, IndexBindingGap, IndexOperationWork, IndexPublicationWork, Output,
};
use crate::guard::history::completion::indexes::failure;
use crate::guard::invalid;
use crate::store::StoreFailure;

/// Completes actual measured maintenance after native input acquisition.
///
/// # Errors
/// Preserves source/relationship/update/completion failures and refuses omitted
/// valid required bindings or inconsistent repeated old occurrence contexts.
pub(super) fn execute(acquired: Acquired, minimum: u64) -> Result<Output, StoreFailure> {
    let sources = acquired.namespace.sources().map_err(failure)?;
    let context = SemanticContext::new(3, 2, 1).map_err(error)?;
    let arena = maintenance::ByteArena::new(usize::MAX).map_err(error)?;
    let mut graph = sources.trees;
    let mut targets = super::propagation::PreparedTargets::new(&graph, &acquired.plans)?;
    let mut work = IndexPublicationWork {
        namespace_loading: Some(acquired.namespace.loading()),
        namespace_inputs: Some(acquired.namespace_reads),
        namespace_reconstruction: Some(sources.work),
        graft_validation: Some(targets.validation()),
        graft_preparation: Some(targets.preparation()),
        ..IndexPublicationWork::default()
    };
    let mut replacements = BTreeMap::new();
    let mut nodes = BTreeMap::new();
    let mut charged_old_inputs = BTreeSet::new();
    let mut charged_supplied_inputs = BTreeSet::new();

    for plan in &acquired.plans {
        let original = graph.get(&plan.owner).ok_or_else(invalid)?;
        let edits = targets.take_edits(plan.owner, original, &replacements)?;
        let owner = if edits.is_empty() {
            plan.owner
        } else {
            let mutation = original.edit_entries(&edits).map_err(error)?;
            for node in &mutation.emitted {
                insert_output(
                    &mut nodes,
                    node.identity(),
                    node.encoded().to_vec(),
                    true,
                    &mut work,
                )?;
            }
            let root = mutation.tree.root_identity();
            graph.insert(root, mutation.tree);
            work.propagation.push(mutation.work);
            root
        };
        let mut data = BTreeMap::new();
        let mut operations = Vec::new();
        let mut publications = Vec::new();
        let mut initial_exports = BTreeSet::new();
        let gap_start = work.gaps.len();
        for attribute in plan.attributes.values() {
            for (prior, paths) in &attribute.prior {
                if prior.is_none() && attribute.binding.is_none() {
                    work.gaps.push(IndexBindingGap {
                        owner,
                        attribute: attribute.attribute.clone(),
                        paths: paths.clone(),
                    });
                    continue;
                }
                let recipe =
                    IndexEvaluationRecipe::new(owner, &attribute.attribute).map_err(error)?;
                let new_source =
                    incremental::PreparedSource::new(&recipe, &graph, minimum, context)
                        .map_err(error)?;
                let supplied = acquired
                    .supplied
                    .get(&(plan.owner, attribute.attribute.clone()))
                    .map(|(loaded, reads)| {
                        let supplied_sources = loaded.sources().map_err(failure)?;
                        let prepared = loaded.prepare(&supplied_sources.trees).map_err(failure)?;
                        Ok::<_, StoreFailure>((
                            prepared.preparation().clone(),
                            *reads,
                            loaded.loading(),
                            supplied_sources.work,
                        ))
                    })
                    .transpose()?;
                let supplied_index = supplied
                    .as_ref()
                    .map(|(preparation, _, _, _)| preparation.clone());
                // Acquisition is shared by exact owner/name; pure reconstruction
                // and preparation below really execute for each occurrence group.
                let charge_supplied = supplied.is_some()
                    && charged_supplied_inputs.insert((plan.owner, attribute.attribute.clone()));
                let supplied_inputs = supplied
                    .as_ref()
                    .filter(|_| charge_supplied)
                    .map(|(_, reads, _, _)| *reads);
                let supplied_loading = supplied
                    .as_ref()
                    .filter(|_| charge_supplied)
                    .map(|(_, _, loading, _)| *loading);
                let supplied_reconstruction = supplied
                    .as_ref()
                    .map(|(_, _, _, reconstruction)| *reconstruction);
                let (updated, operation) = if let Some(prior) = prior {
                    let (loaded, old_inputs) = acquired
                        .old
                        .get(&(prior.owner, attribute.attribute.clone()))
                        .ok_or_else(invalid)?;
                    let old_sources = loaded.sources().map_err(failure)?;
                    let old_recipe = IndexEvaluationRecipe::new(prior.owner, &attribute.attribute)
                        .map_err(error)?;
                    let old_source = incremental::PreparedSource::new(
                        &old_recipe,
                        &old_sources.trees,
                        minimum,
                        context,
                    )
                    .map_err(error)?;
                    let (old_index, old_preparation) = maintenance::prepare(
                        &old_recipe,
                        &old_source,
                        &old_sources.trees,
                        loaded.index_data(),
                        &arena,
                        minimum,
                        context,
                    )
                    .map_err(error)?;
                    if prior.required && attribute.binding.is_none() {
                        return Err(StoreFailure::with_source(
                            invalid().kind().clone(),
                            DroppedBinding {
                                owner: plan.owner,
                                attribute: attribute.attribute.clone(),
                            },
                        ));
                    }
                    let discovery =
                        incremental::discover(&old_source, &new_source).map_err(error)?;
                    let (updated, update, publication) =
                        maintenance::update_with_publication(&old_index, &discovery)
                            .map_err(error)?;
                    let publication_work = publication.work;
                    // Retain only emitted identities for exact output witnesses.
                    // This bounded pass visits and copies publication.nodes.len() identities,
                    // and its cost is charged by publication_nodes.len().
                    let publication_nodes = publication
                        .nodes
                        .iter()
                        .map(|(identity, _)| *identity)
                        .collect();
                    publications.push(publication.nodes);
                    let boundary = update.boundary_cost().map_err(error)?;
                    let (data, export) = updated.materialize().map_err(error)?;
                    let charge_old =
                        charged_old_inputs.insert((prior.owner, attribute.attribute.clone()));
                    (
                        data,
                        Operation {
                            old_owner: Some(prior.owner),
                            paths: paths.clone(),
                            old_loading: charge_old.then(|| loaded.loading()),
                            old_inputs: charge_old.then_some(*old_inputs),
                            old_reconstruction: Some(old_sources.work),
                            old_source: Some(old_source.preparation_work()),
                            new_source: new_source.preparation_work(),
                            old_index: Some(old_preparation),
                            supplied_index,
                            supplied_inputs,
                            supplied_loading,
                            supplied_reconstruction,
                            update: Some(update),
                            boundary: Some(boundary),
                            initialization: None,
                            export,
                            publication: Some(publication_work),
                            publication_nodes,
                        },
                    )
                } else {
                    let (initialized, initialization) =
                        maintenance::initialize(&recipe, &new_source, &arena, minimum, context)
                            .map_err(error)?;
                    let (data, export) = initialized.materialize().map_err(error)?;
                    initial_exports.insert(attribute.attribute.clone());
                    (
                        data,
                        Operation {
                            old_owner: None,
                            paths: paths.clone(),
                            old_loading: None,
                            old_inputs: None,
                            old_reconstruction: None,
                            old_source: None,
                            new_source: new_source.preparation_work(),
                            old_index: None,
                            supplied_index,
                            supplied_inputs,
                            supplied_loading,
                            supplied_reconstruction,
                            update: None,
                            boundary: None,
                            initialization: Some(initialization),
                            export,
                            publication: None,
                            publication_nodes: Vec::new(),
                        },
                    )
                };
                // Different genuine old occurrence contexts must converge to the same canonical result.
                if data.get(&attribute.attribute).is_some_and(
                    |previous: &terrane_format::indexing::evaluation::IndexData| {
                        previous.root != updated.root || previous.nodes != updated.nodes
                    },
                ) {
                    return Err(invalid());
                }
                data.insert(attribute.attribute.clone(), updated);
                operations.push((attribute.attribute.clone(), operation));
            }
        }
        let final_owner = if data.is_empty() {
            owner
        } else {
            let selections = data
                .iter()
                .map(|(attribute, data)| completion::Selection { attribute, data })
                .collect::<Vec<_>>();
            let completed = completion::complete(
                owner,
                &graph,
                &selections,
                &arena,
                minimum,
                context,
                completion::MemoPolicy::Omit,
            )
            .map_err(error)?;
            for (attribute, operation) in operations {
                let association = completed
                    .associations
                    .iter()
                    .find(|association| association.attribute == attribute)
                    .ok_or_else(invalid)?
                    .clone();
                work.operations.push(operation.report(
                    completed.owner.tree.root_identity(),
                    attribute,
                    association,
                ));
            }
            work.gaps
                .drain(gap_start..)
                .filter(|gap| !data.contains_key(&gap.attribute))
                .collect::<Vec<_>>()
                .into_iter()
                .for_each(|gap| work.gaps.push(gap));
            // Full data remains available through independent completion.
            // Existing maintenance publishes only reachable emitted bytes;
            // initialization moves its explicitly constructed full population.
            for publication in publications {
                for (identity, bytes) in publication {
                    insert_output(&mut nodes, identity, bytes, true, &mut work)?;
                }
            }
            for attribute in initial_exports {
                let value = data.remove(&attribute).ok_or_else(invalid)?;
                for (identity, bytes) in value.nodes {
                    insert_output(&mut nodes, identity, bytes, false, &mut work)?;
                }
            }
            for node in &completed.owner.emitted {
                insert_output(
                    &mut nodes,
                    node.identity(),
                    node.encoded().to_vec(),
                    true,
                    &mut work,
                )?;
            }
            let root = completed.owner.tree.root_identity();
            graph.insert(root, completed.owner.tree);
            work.completion.push(completed.work);
            root
        };
        for gap in work.gaps.iter_mut().skip(gap_start) {
            gap.owner = final_owner;
        }
        replacements.insert(plan.owner, final_owner);
        targets.complete(plan.owner, final_owner)?;
    }
    work.graft_propagation = targets.work();

    let root = replacements
        .get(&acquired.namespace.owner())
        .copied()
        .ok_or_else(invalid)?;
    Ok(Output { root, nodes, work })
}

struct Operation {
    old_owner: Option<Digest>,
    paths: Vec<Vec<u8>>,
    old_loading: Option<crate::indexing::Loading>,
    old_inputs: Option<super::IndexInputReads>,
    old_reconstruction: Option<crate::indexing::Reconstruction>,
    old_source: Option<incremental::PreparationWork>,
    new_source: incremental::PreparationWork,
    old_index: Option<maintenance::PreparationWork>,
    supplied_index: Option<terrane_format::indexing::lookup::Preparation>,
    supplied_inputs: Option<super::IndexInputReads>,
    supplied_loading: Option<crate::indexing::Loading>,
    supplied_reconstruction: Option<crate::indexing::Reconstruction>,
    update: Option<maintenance::UpdateWork>,
    boundary: Option<usize>,
    initialization: Option<maintenance::ConstructionWork>,
    export: maintenance::ExportWork,
    publication: Option<maintenance::PublicationWork>,
    publication_nodes: Vec<Digest>,
}

impl Operation {
    fn report(
        self,
        owner: Digest,
        attribute: String,
        association: completion::Association,
    ) -> IndexOperationWork {
        IndexOperationWork {
            old_owner: self.old_owner,
            owner,
            attribute,
            paths: self.paths,
            old_loading: self.old_loading,
            old_inputs: self.old_inputs,
            old_reconstruction: self.old_reconstruction,
            old_source: self.old_source,
            new_source: self.new_source,
            old_index: self.old_index,
            supplied_index: self.supplied_index,
            supplied_inputs: self.supplied_inputs,
            supplied_loading: self.supplied_loading,
            supplied_reconstruction: self.supplied_reconstruction,
            update: self.update,
            boundary: self.boundary,
            initialization: self.initialization,
            export: self.export,
            publication: self.publication,
            publication_nodes: self.publication_nodes,
            association,
        }
    }
}

/// Charges every output insertion, including replacements of repeated identities.
///
/// The key is a 256-bit digest. The alloc BTreeMap geometry described by core
/// maintenance's temporary-map accounting bounds comparisons by 2827 per
/// requested insertion, independently of complete index population. This report
/// counts insertion requests and byte work, not those internal comparisons.
fn insert_output(
    nodes: &mut BTreeMap<Digest, Vec<u8>>,
    identity: Digest,
    bytes: Vec<u8>,
    copied: bool,
    work: &mut IndexPublicationWork,
) -> Result<(), StoreFailure> {
    work.output_node_insertions = work
        .output_node_insertions
        .checked_add(1)
        .ok_or_else(invalid)?;
    work.output_bytes = work
        .output_bytes
        .checked_add(bytes.len())
        .ok_or_else(invalid)?;
    if copied {
        work.output_bytes_copied = work
            .output_bytes_copied
            .checked_add(bytes.len())
            .ok_or_else(invalid)?;
    }
    nodes.insert(identity, bytes);
    Ok(())
}

fn error(error: impl std::error::Error + Send + Sync + 'static) -> StoreFailure {
    StoreFailure::with_source(invalid().kind().clone(), error)
}
