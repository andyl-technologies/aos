//! Replays complete logical Delete graph DATA through the sole canonical folds.
//!
//! Native C17 and independent Root readers supply their own protected Source,
//! Controller and exact hash-verified metadata models. This module owns only
//! historical comparison DATA: no native file, currentness, financial borrower,
//! authorization, mutation, graph admission or six-owner grant is produced.

use std::collections::BTreeMap;

use aos_sandbox_model::{ObjectDescriptor, ProjectId, RecordNamespace, ViewId};
use aos_sandbox_model::model::{ExternalDependency, ViewSource};
use aos_sandbox_protocol::domain_ledger::lifecycle_model::{
    LifecycleResourceV1 as Resource, LifecycleDependencyEdgeV1 as Edge,
};
use aos_sandbox_protocol::domain_ledger::delete_batch::DeleteDependencyClassDataV2 as Class;
use aos_sandbox_protocol::public_api::projection::{
    PublicProjectionError, PublicProjectionRecordV1, PublicProjectionResourceV1 as Projection,
    projection_key,
};
use aos_sandbox_protocol::public_api::projection::dependencies::{
    object_descriptor_matches_data_v2 as descriptor_matches_v2, projection_dependencies_data_v2,
};
use aos_sandbox_protocol::domain_ledger::provisioning_resources::{
    ProvisioningResourceRecordsV1, ProvisioningResourceRowKindV1 as CompanionKind,
    decode_provisioning_resource_row_v1, validate_provisioning_resource_links_v1,
};
use crate::replay::tree_lineage::{
    ClosedTreeLineageHeadV1, verify_closed_tree_lineage_projection_v1,
};
use crate::replay::hierarchy_records::{
    HierarchyProtectedJournalSchemaV1 as Schema, HierarchyProtectedRecordKindV1 as Kind,
    replay_validator_from_saved_rows_v1,
    claims::{RecordedViewSourceEvidenceV1, RecordedSnapshotManifestV1},
    evidence_codec::{HierarchyProtectedEvidenceV1, decode_hierarchy_protected_evidence_v1},
};
use aos_sandbox_protocol::domain_ledger::records::{
    current_record_candidates_from_rows, replay_projection_records, decode_reducer_payload_with_validator,
};

mod selection;
pub use selection::{DeleteGraphSelectionDataV2, DeleteGraphSelectionErrorV2};

type State = BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;

/// Borrows an exact canonical object model and its complete saved identity.
///
/// These are passive supplied DATA. Real callers separately verify immutable
/// bytes against their own protected descriptors before constructing a borrow.
#[derive(Clone, Copy)]
pub enum DeleteGraphMetadataDataV2<'model> {
    /// Borrows one Snapshot and its Source-recorded canonical descriptor.
    Snapshot {
        /// Borrows the complete canonical saved Source manifest claim.
        saved: &'model crate::replay::hierarchy_records::claims::RecordedSnapshotManifestV1,
        /// Borrows the exact portable Snapshot decoded from verified bytes.
        model: &'model aos_sandbox_model::model::Snapshot,
    },
    /// Borrows one current logical View and its exact canonical object model.
    View {
        /// Names the actual current Controller logical View.
        id: ViewId,
        /// Borrows its complete current Controller content descriptor.
        descriptor: &'model ObjectDescriptor,
        /// Borrows the canonical View decoded from those exact bytes.
        model: &'model aos_sandbox_model::model::View,
    },
}

impl<'model> DeleteGraphMetadataDataV2<'model> {
    /// Returns a supplied View's full comparison preimage, if this is a View.
    #[must_use]
    pub fn view_v2(self) -> Option<(ViewId, &'model ObjectDescriptor, &'model aos_sandbox_model::model::View)> {
        match self { Self::View { id, descriptor, model } => Some((id, descriptor, model)), Self::Snapshot { .. } => None }
    }
}

/// Reports invalid or incomplete saved logical graph DATA.
#[derive(Debug, thiserror::Error)]
pub enum DeleteGraphDataErrorV2 {
    /// The canonical seven-family Source fold refused the supplied history.
    #[error(transparent)]
    Source(#[from] aos_sandbox_protocol::domain_ledger::DomainLedgerDataError),
    /// A complete public row failed its existing canonical codec.
    #[error(transparent)]
    Projection(#[from] PublicProjectionError),
    /// A live provisioning triple failed its sole full-link validator.
    #[error(transparent)]
    Companion(#[from] aos_sandbox_protocol::domain_ledger::provisioning_resources::ProvisioningResourceLinkErrorV1),
    /// Public projections cannot establish the separate protected grant roster.
    #[error("the complete protected capability registry has not been joined to the dependency graph")]
    CapabilityRegistryUnresolved,
    /// Complete supplied preimages disagree or leave a managed relation unresolved.
    #[error("the complete Source and Controller resource relations differ")]
    Relation,
    /// A current public immutable descriptor failed its sole conversion.
    #[error(transparent)]
    Descriptor(#[from] aos_sandbox_protocol::public_api::mutation::PublicMutationResolutionErrorV1),
    /// A paid bounded pure-work allocation failed.
    #[error("a bounded logical dependency allocation failed: {0}")]
    Allocation(#[from] std::collections::TryReserveError),
}

/// Retains a complete supplied canonical registry model and its original bytes.
///
/// Actual Native and Root callers must run the same full registry codec, parent,
/// handle, fanout and Runtime-history validator before supplying these DATA.
pub struct DeleteGraphCapabilityDataV2 {
    /// Retains the exact protected capability key.
    pub key: Vec<u8>,
    /// Retains the complete canonical protected value, including provenance.
    pub original: Vec<u8>,
    /// Retains the complete decoded closed capability model.
    pub capability: aos_sandbox_model::CapabilityRecord,
    /// Retains the canonical active/revoked comparison state.
    pub state: aos_sandbox_protocol::domain_ledger::delete_batch::
        capability_retention::CapabilityRegistryStateDataV2,
}

/// Retains one supplied canonical Controller projection and its original bytes.
pub struct DeleteGraphProjectionDataV2 {
    /// Names the exact logical resource carried by the row.
    pub resource: Resource,
    /// Retains its complete canonical checked public model.
    pub record: PublicProjectionRecordV1,
    /// Retains its exact native DesiredState key.
    pub key: Vec<u8>,
    /// Retains its exact complete native value bytes.
    pub original: Vec<u8>,
}

/// Retains one typed dependency and its explicit current V2 relation class.
pub struct DeleteGraphEdgeDataV2 {
    /// Retains the two typed dependent-before-dependency endpoints.
    pub edge: Edge,
    /// Names the explicit current V2 relation.
    pub class: Class,
}

/// Retains every logical preimage used by the actual candidate producer.
///
/// All fields are supplied comparison DATA. The real native wrappers retain
/// their original maps, immutable bytes and complete independent posts. These
/// values cannot release writers or replace later fresh preaccept cuts.
pub struct DeleteDependencyGraphDataV2 {
    /// Names the supplied exact project partition.
    pub project: ProjectId,
    /// Retains the sole complete saved Source Tree and Lineage reconstruction.
    pub tree: ClosedTreeLineageHeadV1,
    /// Retains every current logical public row in the project.
    pub projections: Vec<DeleteGraphProjectionDataV2>,
    /// Retains complete saved View-source claims matching current exact descriptors.
    pub views: Vec<RecordedViewSourceEvidenceV1>,
    /// Retains complete current-matching saved Source Snapshot claims.
    pub snapshots: Vec<RecordedSnapshotManifestV1>,
    /// Retains every validated original three-row provisioning set.
    pub companions: Vec<ProvisioningResourceRecordsV1>,
    /// Retains all complete typed managed relations in canonical order.
    pub edges: Vec<DeleteGraphEdgeDataV2>,
    /// Retains the complete canonical registry census, including other projects.
    pub capabilities: Vec<DeleteGraphCapabilityDataV2>,
}

/// Retains the exact logical base before immutable metadata is joined.
///
/// This is historical comparison DATA, never a completed graph or native proof.
/// A real reader may capture it at the actual pre-Planned BEGIN frontier and
/// finish it only after its own exact descriptor-byte/model observations.
pub struct DeleteDependencyGraphBaseDataV2 {
    graph: DeleteDependencyGraphDataV2,
    source_rows: usize,
}

/// Names an exact current logical object's required immutable metadata.
///
/// This is comparison DATA; it grants no Cache/Root file or disclosure access.
pub enum DeleteGraphMetadataRequestDataV2 {
    /// Retains the complete saved Source Snapshot manifest relation.
    Snapshot(RecordedSnapshotManifestV1),
    /// Names one current logical View and its exact whole descriptor.
    View {
        /// Names the logical View, never a descriptor digest cast to an ID.
        view: ViewId,
        /// Retains its complete current immutable descriptor.
        descriptor: ObjectDescriptor,
    },
}

impl DeleteGraphMetadataRequestDataV2 {
    /// Borrows the exact current content descriptor.
    #[must_use]
    pub fn descriptor_v2(&self) -> &ObjectDescriptor {
        match self { Self::Snapshot(saved) => saved.manifest(), Self::View { descriptor, .. } => descriptor }
    }

    /// Borrows the full saved Snapshot relation, if selected.
    #[must_use]
    pub fn snapshot_saved_v2(&self) -> Option<&RecordedSnapshotManifestV1> {
        match self { Self::Snapshot(saved) => Some(saved), Self::View { .. } => None }
    }

    /// Returns the exact logical View identity, if selected.
    #[must_use]
    pub fn view_v2(&self) -> Option<ViewId> {
        match self { Self::View { view, .. } => Some(*view), Self::Snapshot(_) => None }
    }
}

impl DeleteDependencyGraphBaseDataV2 {
    /// Prices the same complete finish while this actual base remains resident.
    ///
    /// The row count was captured from the actual Source prefix at construction;
    /// it cannot be substituted by current-state subtraction or supplied DATA.
    #[must_use]
    pub fn finishing_receiving_bytes_v2(&self, controller: &State, metadata_links: usize)
        -> Option<usize>
    {
        delete_dependency_graph_prefix_receiving_bytes_v2(self.source_rows, controller, metadata_links)
    }

    /// Prices actual request vector, descriptor and saved-claim clone planes.
    ///
    /// The caller pays this bound before the request builder below. Media names
    /// come from the same already-decoded complete rows; no descriptor is decoded
    /// or cloned to obtain this geometry.
    #[must_use]
    pub fn metadata_requests_receiving_bytes_v2(&self) -> Option<usize> {
        let count = self.graph.projections.len();
        let names = self.graph.snapshots.iter().try_fold(0usize, |bytes, saved|
            bytes.checked_add(saved.manifest().media_type().as_str().len()))?;
        let names = self.graph.projections.iter().try_fold(names, |bytes, row| {
            let name = match row.record.resource() {
                Projection::FilesystemView(view) => view.revision.as_option()
                    .map_or(0, |descriptor| descriptor.media_type.len()),
                _ => 0,
            };
            bytes.checked_add(name)
        })?;
        count.checked_mul(std::mem::size_of::<DeleteGraphMetadataRequestDataV2>())?
            .checked_add(names)?.checked_mul(3)?
            .checked_add(3 * std::mem::size_of::<Vec<DeleteGraphMetadataRequestDataV2>>())
    }

    /// Selects exact immutable inputs from this same complete saved base.
    ///
    /// # Errors
    /// Refuses a current Snapshot lacking its exact saved manifest relation,
    /// invalid current descriptor or prepaid bounded allocation refusal.
    pub fn metadata_requests_data_v2(&self)
        -> Result<Vec<DeleteGraphMetadataRequestDataV2>, DeleteGraphDataErrorV2>
    {
        let mut requests = Vec::new();
        for row in &self.graph.projections {
            match row.record.resource() {
                Projection::FilesystemView(view) => {
                    let descriptor = view.revision.as_option().ok_or(DeleteGraphDataErrorV2::Relation)?;
                    let descriptor = aos_sandbox_protocol::public_api::mutation::object_descriptor(descriptor)?;
                    let id = view.view_id.as_slice().try_into().map_err(|_| DeleteGraphDataErrorV2::Relation)?;
                    requests.try_reserve(1)?;
                    requests.push(DeleteGraphMetadataRequestDataV2::View {
                        view: ViewId::from_bytes(id), descriptor });
                }
                Projection::Snapshot(snapshot) => {
                    let mut saved = self.graph.snapshots.iter().filter(|saved|
                        saved.snapshot().as_bytes().as_slice() == snapshot.snapshot_id.as_slice());
                    let actual = saved.next().ok_or(DeleteGraphDataErrorV2::Relation)?;
                    if saved.next().is_some() || actual.project() != self.graph.project
                        || snapshot.project_id.as_slice() != actual.project().as_bytes()
                        || snapshot.source_sandbox_id.as_slice() != actual.sandbox().as_bytes()
                        || !snapshot.manifest.as_option().is_some_and(|descriptor|
                            descriptor_matches_v2(descriptor, actual.manifest()))
                    { return Err(DeleteGraphDataErrorV2::Relation); }
                    requests.try_reserve(1)?;
                    requests.push(DeleteGraphMetadataRequestDataV2::Snapshot(actual.clone()));
                }
                _ => {}
            }
        }
        Ok(requests)
    }
}

/// Reconstructs supplied complete Source/C graph DATA with the shared schemas.
///
/// The caller pays full semantic, retained-row and object-model peaks before
/// entry and authenticates every supplied native and immutable-content input.
///
/// # Errors
/// Refuses noncanonical rows, mismatched current Source/C relations, incomplete
/// metadata/companions, dangling typed resources or bounded allocation failure.
pub fn replay_delete_dependency_graph_data_v2<'metadata>(
    source: &State, controller: &State, project: ProjectId,
    metadata: &[DeleteGraphMetadataDataV2<'metadata>],
    capabilities: Vec<DeleteGraphCapabilityDataV2>,
) -> Result<DeleteDependencyGraphDataV2, DeleteGraphDataErrorV2> {
    let base = prepare_delete_dependency_graph_base_data_v2(
        source, controller, project, capabilities)?;
    finish_delete_dependency_graph_metadata_data_v2(base, controller, metadata)
}

/// Captures complete Source/C logical preimages without inventing object models.
///
/// The real caller pays the complete actual prefix/model/census peak before
/// entry. A returned base does not prove immutable object presence or graph
/// completeness; the same metadata join below remains mandatory.
///
/// # Errors
/// Refuses the same canonical Source/C rows, census and saved relations.
pub fn prepare_delete_dependency_graph_base_data_v2(
    source: &State, controller: &State, project: ProjectId,
    capabilities: Vec<DeleteGraphCapabilityDataV2>,
) -> Result<DeleteDependencyGraphBaseDataV2, DeleteGraphDataErrorV2> {
    // A public projection is not the separate protected registry's census.
    // Both real callers run the sole full codec before supplying these models.
    let raw = controller.iter().filter(|((namespace, _), _)|
        *namespace == RecordNamespace::PublisherAuthority);
    if raw.clone().count() != capabilities.len() {
        return Err(DeleteGraphDataErrorV2::CapabilityRegistryUnresolved);
    }
    for (((_, key), value), record) in raw.zip(&capabilities) {
        if key != &record.key || value != &record.original {
            return Err(DeleteGraphDataErrorV2::CapabilityRegistryUnresolved);
        }
        // The classifier applies the complete current contract uniformly;
        // a valid project or Delete grant is not an administrative retention.
        use aos_sandbox_protocol::domain_ledger::delete_batch::capability_retention::{
            capability_delete_retention_data_v2, CapabilityDeleteRetentionDataV2,
        };
        match capability_delete_retention_data_v2(&record.capability, record.state) {
            CapabilityDeleteRetentionDataV2::NoAdministrativeRetention => {}
        }
    }
    let candidates = current_record_candidates_from_rows::<Schema>(source.iter().map(|((namespace, key), value)| (*namespace, key.as_slice(), value.as_slice())))?;
    let validator = replay_validator_from_saved_rows_v1(&candidates)?;
    let projection = replay_projection_records::<Schema>(source.iter().map(|((namespace, key), value)| (*namespace, key.as_slice(), value.as_slice())), &validator)?;
    let mut trees = verify_closed_tree_lineage_projection_v1(&projection, &validator)?;
    let tree = trees.remove(&project).ok_or(DeleteGraphDataErrorV2::Relation)?;
    let mut graph = DeleteDependencyGraphDataV2 {
        project, tree, projections: Vec::new(), views: Vec::new(), snapshots: Vec::new(),
        companions: Vec::new(), edges: Vec::new(), capabilities,
    };

    // Decode the whole reserved prefix, including other projects, through
    // the same ordinary public-row codec before selecting this partition.
    for row in aos_sandbox_protocol::public_api::projection::iter_public_projection_rows_data_v2(
        controller.iter().filter(|((namespace, _), _)| *namespace == RecordNamespace::DesiredState)
            .map(|((_, key), value)| (key.as_slice(), value.as_slice())), None,
    ) {
        let row = row?;
        if row.project() != project { continue; }
        let explicit = projection_dependencies_data_v2(&row)?;
        let Some(resource) = explicit.resource_v2() else { continue; };
        if matches!(resource, Resource::Capability(_)) {
            graph.push_projection_v2(controller, row, resource)?;
            continue;
        }
        for edge in explicit.edges_v2() {
            // A historical Snapshot may retain a source/ancestor whose
            // logical deletion is already proven by the same Source Tree.
            if matches!(resource, Resource::Snapshot(_))
                && matches!(edge.dependency(), Resource::Sandbox(id) if graph.tree.tree.tombstones().any(|old| old == id))
            { continue; }
            let class = match resource {
                Resource::Sandbox(_) => Class::SandboxParent,
                Resource::Execution(_) => Class::ExecutionOwner,
                Resource::Attachment(_) if matches!(edge.dependency(), Resource::View(_)) => Class::LogicalView,
                Resource::Attachment(_) => Class::AttachmentDestination,
                Resource::Snapshot(_) => Class::SnapshotRetention,
                _ => return Err(DeleteGraphDataErrorV2::Relation),
            };
            graph.push_edge_v2(edge.dependent(), edge.dependency(), class)?;
        }
        graph.push_projection_v2(controller, row, resource)?;
    }
    graph.require_tree_v2()?;

    for record in projection.records() {
        if record.key().kind() != Kind::Evidence { continue; }
        let payload = decode_reducer_payload_with_validator::<Schema>(
            record.key(), record.payload(), &validator)?;
        let evidence = decode_hierarchy_protected_evidence_v1(payload.body())
            .ok_or(DeleteGraphDataErrorV2::Relation)?;
        if let HierarchyProtectedEvidenceV1::SnapshotManifest(saved) = &evidence {
            if saved.project() == project && graph.contains_v2(Resource::Snapshot(saved.snapshot())) {
                graph.snapshots.try_reserve(1)?;
                graph.snapshots.push(saved.clone());
            }
        }
        if let HierarchyProtectedEvidenceV1::ViewSource(saved) = evidence {
            if saved.project() != project { continue; }
            if graph.projections.iter().any(|row| {
                let Projection::FilesystemView(view) = row.record.resource() else { return false; };
                view.view_id.as_slice() == saved.view().as_bytes()
                    && view.revision.as_option().is_some_and(|descriptor|
                        descriptor_matches_v2(descriptor, saved.view_descriptor()))
            })
            {
                graph.views.try_reserve(1)?;
                graph.views.push(saved);
            }
        }
    }
    Ok(DeleteDependencyGraphBaseDataV2 { graph, source_rows: source.len() })
}

/// Joins exact independently verified immutable models to the retained base.
///
/// The base and metadata remain comparison DATA. Actual callers keep the same
/// Source/C native originals, financial scope and independently owed posts.
///
/// # Errors
/// Refuses absent/duplicate/substituted objects, saved live-owner mismatches,
/// dangling logical references and the original bounded allocation errors.
pub fn finish_delete_dependency_graph_metadata_data_v2(
    base: DeleteDependencyGraphBaseDataV2, controller: &State,
    metadata: &[DeleteGraphMetadataDataV2<'_>],
) -> Result<DeleteDependencyGraphDataV2, DeleteGraphDataErrorV2> {
    let mut graph = base.graph;
    graph.require_metadata_coverage_v2(metadata)?;
    graph.join_metadata_v2(metadata)?;
    graph.join_assignment_consumers_v2()?;
    graph.join_companions_v2(controller)?;
    graph.edges.sort_by_key(|value| (value.edge.dependent(), value.edge.dependency(), value.class));
    graph.edges.dedup_by(|left, right| left.edge == right.edge && left.class == right.class);
    if graph.edges.iter().any(|value|
        !graph.contains_v2(value.edge.dependent()) || !graph.contains_v2(value.edge.dependency()))
    {
        return Err(DeleteGraphDataErrorV2::Relation);
    }
    Ok(graph)
}


impl DeleteDependencyGraphDataV2 {
    fn contains_v2(&self, resource: Resource) -> bool {
        self.projections.iter().any(|row| row.resource == resource)
            || self.companions.iter().any(|rows| {
                let fields = rows.fields_v1();
                resource == Resource::Other(fields.assignment) || resource == Resource::Other(fields.reservation)
            })
    }

    fn push_projection_v2(&mut self, controller: &State, row: PublicProjectionRecordV1,
        resource: Resource,
    ) -> Result<(), DeleteGraphDataErrorV2> {
        if self.projections.iter().any(|old| old.resource == resource) {
            return Err(DeleteGraphDataErrorV2::Relation);
        }
        let id: [u8; 16] = row.resource().resource_id().try_into()
            .map_err(|_| DeleteGraphDataErrorV2::Relation)?;
        let key = projection_key(row.resource().kind(), id);
        let raw = controller.get(&(RecordNamespace::DesiredState, key.clone()))
            .ok_or(DeleteGraphDataErrorV2::Relation)?;
        let mut original = Vec::new();
        original.try_reserve_exact(raw.len())?;
        original.extend_from_slice(raw);
        self.projections.try_reserve(1)?;
        self.projections.push(DeleteGraphProjectionDataV2 { resource, record: row, key, original });
        Ok(())
    }

    fn push_edge_v2(&mut self, dependent: Resource, dependency: Resource, class: Class)
        -> Result<(), DeleteGraphDataErrorV2>
    {
        Class::from_endpoints_v2(class.code_v2(), dependent, dependency)
            .map_err(|_| DeleteGraphDataErrorV2::Relation)?;
        self.edges.try_reserve(1)?;
        self.edges.push(DeleteGraphEdgeDataV2 {
            edge: Edge::new(dependent, dependency).map_err(|_| DeleteGraphDataErrorV2::Relation)?, class,
        });
        Ok(())
    }

    fn require_tree_v2(&self) -> Result<(), DeleteGraphDataErrorV2> {
        for saved in self.tree.tree.records() {
            let actual = self.projections.iter().find(|row| row.resource == Resource::Sandbox(saved.sandbox()))
                .ok_or(DeleteGraphDataErrorV2::Relation)?;
            let Projection::Sandbox(sandbox) = actual.record.resource() else {
                return Err(DeleteGraphDataErrorV2::Relation);
            };
            let parent_matches = match saved.parent() {
                Some(parent) => sandbox.parent_sandbox_id.as_slice() == parent.as_bytes(),
                None => sandbox.parent_sandbox_id.is_empty(),
            };
            if !parent_matches
                || sandbox.desired.as_option().map(|desired| desired.generation) != Some(saved.desired_generation().get())
            { return Err(DeleteGraphDataErrorV2::Relation); }
        }
        if self.projections.iter().any(|row|
            matches!(row.resource, Resource::Sandbox(id) if self.tree.tree.record(id).is_none()))
        { return Err(DeleteGraphDataErrorV2::Relation); }
        Ok(())
    }

    fn require_metadata_coverage_v2(&self, metadata: &[DeleteGraphMetadataDataV2<'_>])
        -> Result<(), DeleteGraphDataErrorV2>
    {
        for row in &self.projections {
            match row.record.resource() {
                Projection::FilesystemView(view) => {
                    let mut matches = metadata.iter().filter(|model| matches!(model,
                        DeleteGraphMetadataDataV2::View { id, descriptor, .. }
                            if id.as_bytes().as_slice() == view.view_id.as_slice()
                                && view.revision.as_option().is_some_and(|actual| descriptor_matches_v2(actual, descriptor))));
                    if matches.next().is_none() || matches.next().is_some() {
                        return Err(DeleteGraphDataErrorV2::Relation);
                    }
                }
                Projection::Snapshot(snapshot) => {
                    let mut matches = metadata.iter().filter_map(|model| match model {
                        DeleteGraphMetadataDataV2::Snapshot { saved, .. }
                            if saved.snapshot().as_bytes().as_slice() == snapshot.snapshot_id.as_slice()
                                && saved.sandbox().as_bytes().as_slice() == snapshot.source_sandbox_id.as_slice()
                                && saved.project() == self.project
                                && self.snapshots.iter().any(|actual| actual == *saved)
                                && snapshot.manifest.as_option().is_some_and(|actual| descriptor_matches_v2(actual, saved.manifest())) => Some(saved),
                        _ => None,
                    });
                    if matches.next().is_none() || matches.next().is_some() {
                        return Err(DeleteGraphDataErrorV2::Relation);
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn join_assignment_consumers_v2(&mut self) -> Result<(), DeleteGraphDataErrorV2> {
        for execution in 0..self.projections.len() {
            if !matches!(self.projections[execution].resource, Resource::Execution(_)) { continue; }
            for attachment in 0..self.projections.len() {
                if !matches!(self.projections[attachment].resource, Resource::Attachment(_)) { continue; }
                let edge = aos_sandbox_protocol::public_api::projection::dependencies::
                    assignment_attachment_consumer_data_v2(&self.projections[execution].record,
                        &self.projections[attachment].record)?;
                if let Some(edge) = edge {
                    self.push_edge_v2(edge.dependent(), edge.dependency(), Class::AssignmentAttachmentConsumer)?;
                }
            }
        }
        Ok(())
    }

    fn join_metadata_v2<'metadata>(&mut self,
        metadata: &[DeleteGraphMetadataDataV2<'metadata>],
    ) -> Result<(), DeleteGraphDataErrorV2> {
        for model in metadata.iter().copied() {
            match model {
                DeleteGraphMetadataDataV2::View { id, descriptor, model: view } => {
                    if !self.contains_v2(Resource::View(id)) { return Err(DeleteGraphDataErrorV2::Relation); }
                    if let ViewSource::LiveExport { owner_sandbox, export, .. } = view.source() {
                        if !self.views.iter().any(|saved| saved.view() == id
                            && saved.owner() == *owner_sandbox && saved.export() == *export
                            && saved.view_descriptor() == descriptor)
                        { return Err(DeleteGraphDataErrorV2::Relation); }
                        self.push_edge_v2(Resource::View(id), Resource::Sandbox(*owner_sandbox), Class::LiveViewOwner)?;
                    }
                }
                DeleteGraphMetadataDataV2::Snapshot { saved, model: snapshot } => {
                    let resource = Resource::Snapshot(saved.snapshot());
                    if !self.contains_v2(resource) { return Err(DeleteGraphDataErrorV2::Relation); }
                    for ancestor in snapshot.ancestry() {
                        if self.tree.tree.tombstones().any(|old| old == *ancestor) { continue; }
                        self.push_edge_v2(resource, Resource::Sandbox(*ancestor), Class::SnapshotRetention)?;
                    }
                    for view in snapshot.attachments().iter().map(|attachment| attachment.view())
                        .chain(snapshot.external_dependencies().iter().filter_map(|dependency|
                            match dependency { ExternalDependency::ImmutableView { view, .. } => Some(view), _ => None }))
                    {
                        // Descriptors name immutable content, never logical IDs.
                        // Every actual current logical View with those complete
                        // bytes contributes its explicit ID relation.
                        for target in metadata.iter().copied().filter_map(DeleteGraphMetadataDataV2::view_v2)
                            .filter(|(_, descriptor, _)| *descriptor == view)
                        {
                            self.push_edge_v2(resource, Resource::View(target.0), Class::LogicalView)?;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn join_companions_v2(&mut self, controller: &State) -> Result<(), DeleteGraphDataErrorV2> {
        validate_provisioning_resource_links_v1(controller)?;
        for ((_, key), value) in controller.iter().filter(|((namespace, _), _)| *namespace == RecordNamespace::DesiredState) {
            let Some((CompanionKind::Parent, rows)) = decode_provisioning_resource_row_v1(key, value)
                .map_err(aos_sandbox_protocol::domain_ledger::provisioning_resources::ProvisioningResourceLinkErrorV1::from)?
            else { continue; };
            let fields = rows.fields_v1();
            if fields.project != self.project { continue; }
            if !self.contains_v2(Resource::Sandbox(fields.sandbox)) {
                return Err(DeleteGraphDataErrorV2::Relation);
            }
            self.companions.try_reserve(1)?;
            self.companions.push(rows);
            self.push_edge_v2(Resource::Other(fields.assignment), Resource::Sandbox(fields.sandbox), Class::ProvisioningCompanion)?;
            self.push_edge_v2(Resource::Other(fields.assignment), Resource::Other(fields.reservation), Class::ProvisioningCompanion)?;
            self.push_edge_v2(Resource::Other(fields.reservation), Resource::Sandbox(fields.sandbox), Class::ProvisioningCompanion)?;
        }
        Ok(())
    }
}

/// Bounds retained typed graph/row/index work from supplied actual extents.
///
/// `metadata_links` is the actual bounded ancestry/reference match count. The
/// caller separately admits both complete native semantic prefixes and all
/// already-retained canonical object models. No resource authority is created.
#[must_use]
pub fn delete_dependency_graph_receiving_bytes_v2(source: &State, controller: &State,
    metadata_links: usize,
) -> Option<usize> {
    delete_dependency_graph_prefix_receiving_bytes_v2(source.len(), controller, metadata_links)
}

/// Bounds the same graph planes from an actually observed prior-prefix row count.
///
/// The Source audit supplies the count at every actual COMMIT frontier, including
/// replaced or removed rows. This computes representation DATA only; no model,
/// native authority or graph is materialized by a count.
#[must_use]
pub fn delete_dependency_graph_prefix_receiving_bytes_v2(
    source_rows: usize, controller: &State, metadata_links: usize,
) -> Option<usize> {
    let rows = source_rows.checked_add(controller.len())?;
    let width = std::mem::size_of::<DeleteGraphProjectionDataV2>()
        .checked_add(std::mem::size_of::<DeleteGraphMetadataRequestDataV2>())
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<RecordedViewSourceEvidenceV1>()))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<RecordedSnapshotManifestV1>()))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<ProvisioningResourceRecordsV1>()))
        .and_then(|bytes| bytes.checked_add(4 * std::mem::size_of::<DeleteGraphEdgeDataV2>()))
        ?;
    let prefix = aos_sandbox_protocol::public_api::projection::PROJECTION_KEY_PREFIX;
    let count_kind = |kind: aos_sandbox_protocol::public_api::projection::PublicProjectionKindV1|
        controller.keys().filter(|(namespace, key)| *namespace == RecordNamespace::DesiredState
            && key.starts_with(prefix) && key.get(prefix.len()) == Some(&(kind as u8))).count();
    let consumers = count_kind(aos_sandbox_protocol::public_api::projection::PublicProjectionKindV1::Execution)
        .checked_mul(count_kind(aos_sandbox_protocol::public_api::projection::PublicProjectionKindV1::Attachment))?;
    let fixed = std::mem::size_of::<DeleteDependencyGraphDataV2>().checked_mul(3)
        .and_then(|bytes| bytes.checked_add(rows.checked_mul(width)?.checked_mul(3)?))
        .and_then(|bytes| bytes.checked_add(consumers.checked_mul(
            std::mem::size_of::<DeleteGraphEdgeDataV2>())?.checked_mul(3)?))
        .and_then(|bytes| bytes.checked_add(metadata_links.checked_mul(
            std::mem::size_of::<DeleteGraphEdgeDataV2>())?.checked_mul(3)?))
        ?;
    let typed = controller.iter().filter(|((namespace, _), _)| *namespace == RecordNamespace::DesiredState).map(|((_, key), value)| (key.as_slice(), value.as_slice()))
        .filter(|(key, _)| key.starts_with(aos_sandbox_protocol::public_api::projection::PROJECTION_KEY_PREFIX))
        .try_fold(0usize, |bytes, (_, value)| bytes.checked_add(
            aos_sandbox_protocol::public_api::projection::dependencies::
                projection_dependencies_receiving_bytes_v2(value.len())?))
        ?;
    let copied = controller.iter().filter(|((namespace, _), _)| *namespace == RecordNamespace::DesiredState).map(|((_, key), value)| (key.as_slice(), value.as_slice()))
        .try_fold(0usize, |bytes, (key, value)| bytes.checked_add(key.len())?.checked_add(value.len()))
        .and_then(|bytes| bytes.checked_mul(3)).and_then(|bytes| bytes.checked_add(fixed))
        .and_then(|bytes| bytes.checked_add(typed))
        ?;
    Some(copied)
}
