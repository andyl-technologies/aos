//! Selects the concrete complete common-state capture implementation separately.
//!
//! Source-one and the earlier source-two component keep their unsupported
//! constructors. This factory binds the actual ticketed snapshot codec and
//! joint administrative restoration route, rather than a caller capability flag.

use super::preservation::{Edition, PROFILE};
use super::*;
use crate::node_contract::FacetKind;
use crucible_node_format::{
    CaptureScope, Continuation, FacetSelection, GuaranteeProfile, Repeatability,
};

/// Encodes the concrete original common-state capture and fresh-installation contract.
///
/// # Errors
/// Reports canonical encoding failure of the fixed installed definition.
pub fn host_scheduling_complete_owner_definition() -> Result<Vec<u8>, OperationFailure> {
    canonical::canonical_json(&json!({
        "schema":"source-owned.host-scheduling-complete-owner/2",
        "state":"same original Runtime7/Scheduling1 allocation plus all retained original payload and lineage bodies",
        "capture":"core-issued unchanged-cut administrative ticket; original producer before any native request; once-owned snapshot transfer; explicit host settlement journal",
        "restore":"signed complete index3 and genuine fresh Runtime7 context; original host snapshot plus core administrative lifetime ledger before Arm; one original scheduler installation; no replay",
        "profile":PROFILE,
        "native_scope":"host coordinator and declared connection resources only; native peers require independently installed native-five capture and genuine fresh adoption"
    })).map_err(failure)
}

/// Encodes the complete factory initializer with explicit common-owned domains.
///
/// # Errors
/// Refuses incomplete or duplicate domains and canonical encoding failure.
pub fn host_scheduling_complete_owner_configuration(
    domains: &HostSchedulingDomains,
) -> Result<Vec<u8>, OperationFailure> {
    validate_domains(domains)?;
    canonical::canonical_json(&json!({"schema":"source-owned.host-scheduling-complete-configuration/2", "definition":preservation::definition(Edition::CompleteOriginalLineage)?, "domains":domains})).map_err(failure)
}

/// Binds the actual complete factory's original preparation codec.
///
/// # Errors
/// Reports invalid fixed identity or definition encoding failure.
pub fn host_scheduling_complete_owner_preparation_schema() -> Result<SchemaRef, OperationFailure> {
    Ok(SchemaRef {
        id: Id::new("source-owned.host-scheduling-complete-preparation/2").map_err(failure)?,
        version: 2,
        definition: preservation::definition(Edition::CompleteOriginalLineage)?,
        extensions: Default::default(),
    })
}

/// Binds the complete source-two state codec independently of native peer schemas.
///
/// # Errors
/// Reports invalid fixed identity or canonical definition encoding failure.
pub fn host_scheduling_complete_continuation_schema() -> Result<SchemaRef, OperationFailure> {
    let bytes = canonical::canonical_json(&json!({
        "schema":"source-owned.host-scheduling-continuation/2",
        "fields":["schema_version","source","runtime","scheduling","objects"],
        "runtime":"closed original-lineage Runtime7; complete native ancestry and typed original bodies",
        "administration":"separate runtime-original-capture-journal/1 in index3; unchanged Runtime7 and Coordinator7"
    })).map_err(failure)?;
    Ok(SchemaRef {
        id: Id::new("source-owned.host-scheduling-continuation/2").map_err(failure)?,
        version: 2,
        definition: canonical::content_ref(&bytes, "application/json").map_err(failure)?,
        extensions: Default::default(),
    })
}

/// Selects the concrete common-state preservation facet with exact installed references.
///
/// # Errors
/// Reports invalid fixed identity.
pub fn host_scheduling_complete_preservation_facet(
    configuration: ContentRef,
    guarantees: ContentRef,
) -> Result<FacetSelection, OperationFailure> {
    Ok(FacetSelection {
        id: Id::new(PROFILE).map_err(failure)?,
        version: 2,
        configuration_ref: configuration,
        guarantees_ref: guarantees,
        extensions: Default::default(),
    })
}

pub(super) struct SelectedPreservation {
    profile: Id,
}

impl crate::node_contract::FacetDescription for SelectedPreservation {
    fn profile(&self) -> &Id {
        &self.profile
    }
}

pub(super) fn selected_facet(
    edition: Edition,
    selection: &HostSchedulingSelection,
) -> Option<SelectedPreservation> {
    if edition != Edition::CompleteOriginalLineage {
        return None;
    }
    selection
        .binding
        .compatibility
        .operating_contract
        .facets
        .first()
        .map(|facet| SelectedPreservation {
            profile: facet.id.clone(),
        })
}

/// Selects the actual node facet roster from its private factory edition.
pub(super) fn selected_facets(edition: Edition) -> (&'static [FacetKind], &'static [&'static str]) {
    if edition == Edition::CompleteOriginalLineage {
        (&[FacetKind::Preservation], &["preservation"])
    } else {
        (&[], &[])
    }
}

pub(super) fn valid_facets(edition: Edition, selection: &HostSchedulingSelection) -> bool {
    let binding = &selection.binding.compatibility;
    if edition != Edition::CompleteOriginalLineage {
        return binding.operating_contract.facets.is_empty();
    }
    let facets = &binding.operating_contract.facets;
    facets.len() == 1
        && facets[0].id.as_str() == PROFILE
        && facets[0].version == 2
        && facets[0].configuration_ref == binding.configuration_ref
        && facets[0].guarantees_ref == binding.guarantees_ref
        && facets[0].extensions.is_empty()
        && host_scheduling_complete_continuation_schema()
            .is_ok_and(|schema| binding.implementation.formats.contains(&schema))
}

pub(super) fn valid_guarantees(edition: Edition, guarantee: &GuaranteeProfile) -> bool {
    let common = guarantee.repeatability == Repeatability::Unqualified
        && !guarantee.isolated_fork
        && !guarantee.conditional_replay;
    if edition == Edition::CompleteOriginalLineage {
        common
            && guarantee.capture_scope == CaptureScope::CompleteModel
            && guarantee.continuation == Continuation::Exact
            && guarantee.durable_restart
    } else {
        common
            && guarantee.capture_scope == CaptureScope::None
            && guarantee.continuation == Continuation::Unsupported
            && !guarantee.durable_restart
    }
}

impl HostSchedulingOwner {
    /// Creates the concrete complete common-state factory without creating native state.
    ///
    /// Complete-world use additionally requires the genuine installed native-five
    /// factory and authentic whole-world capture/restoration admission.
    ///
    /// # Errors
    /// Refuses metadata from an earlier unsupported factory, incomplete native
    /// schema/facet selection or inconsistent complete host capability contracts.
    pub fn new_complete_original_continuation(
        selection: HostSchedulingSelection,
        world: HashRef,
    ) -> Result<Self, OperationFailure> {
        Self::create(selection, world, Edition::CompleteOriginalLineage, None)
    }

    /// Restores the concrete host factory from one source-verified signed archive ticket.
    ///
    /// Historical identities are preserved in the ticket; only the fresh binding
    /// supplies the new process incarnation. The fresh runtime must install the
    /// same original administrative source and native journals before Arm.
    ///
    /// # Errors
    /// Refuses foreign ticket custody, changed complete selection or exhausted
    /// fresh private source construction.
    pub fn restore_complete_original_continuation(
        selection: HostSchedulingSelection,
        world: HashRef,
        ticket: crate::node_state::CompleteOriginalHostTicket,
    ) -> Result<Self, OperationFailure> {
        ticket.authenticate_birth().map_err(failure)?;
        let record = ticket.record().map_err(failure)?;
        if record.source.descriptor.model_ref
            != preservation::definition(Edition::CompleteOriginalLineage)?
            || record.source.descriptor != selection.descriptor
            || record.source.binding.compatibility != selection.binding.compatibility
            || record.source.domains != selection.domains
            || record.source.operating_policy != selection.operating_policy
            || record.source.guarantees != selection.guarantees
            || record.source.owner.owner != selection.owner.owner
            || record.scheduling.world_binding_hash != world
            || !matches!(
                record.runtime,
                HostSchedulingRuntimeRecord::OriginalLineage(_)
            )
        {
            return Err(failure(
                "fresh complete host selection differs from archived source",
            ));
        }
        let mut owner = Self::create(selection, world, Edition::CompleteOriginalLineage, None)?;
        Rc::get_mut(&mut owner.source)
            .ok_or_else(|| failure("fresh complete host source was already shared"))?
            .archive_ticket = Some(ticket);
        Ok(owner)
    }
}

impl HostSchedulingSource {
    /// Creates the concrete fresh host node from the same verified archive source.
    ///
    /// This distinct restoration route carries no collecting plan. The actual
    /// fresh runtime must attach its original scheduler allocation and admit
    /// native/admin restoration before Arm; metadata cannot create readiness.
    ///
    /// # Errors
    /// Refuses another archive, changed complete graph/owner/activation tuple,
    /// repeated preparation or reentrant original anchor retention.
    pub fn prepare_complete_restoration_node(
        self: &Rc<Self>,
        graph: &crate::node_admission::AdmittedGraph,
        activation: &ActivationRecord,
        archive: &crate::node_state::CompleteOriginalRestorationSource,
    ) -> Result<PreparedHostSchedulingNode, OperationFailure> {
        self.prepare_complete_restoration_node_scoped(graph, activation, archive, None)
    }

    pub(crate) fn prepare_complete_collecting_restoration_node(
        self: &Rc<Self>,
        graph: &crate::node_admission::AdmittedGraph,
        activation: &ActivationRecord,
        archive: &crate::node_state::CompleteOriginalRestorationSource,
        plan: &crate::node_admission::InstalledConformancePlan,
    ) -> Result<PreparedHostSchedulingNode, OperationFailure> {
        archive.inner.authenticate_birth().map_err(failure)?;
        plan.reauthenticate().map_err(failure)?;
        if !archive
            .inner
            .collecting_plan()
            .map_err(failure)?
            .is_some_and(|original| original.same_original(plan))
        {
            return Err(failure("complete host belongs to another collecting plan"));
        }
        self.prepare_complete_restoration_node_scoped(
            graph,
            activation,
            archive,
            Some(plan.retained()),
        )
    }

    fn prepare_complete_restoration_node_scoped(
        self: &Rc<Self>,
        graph: &crate::node_admission::AdmittedGraph,
        activation: &ActivationRecord,
        archive: &crate::node_state::CompleteOriginalRestorationSource,
        plan: Option<crate::node_admission::InstalledConformancePlan>,
    ) -> Result<PreparedHostSchedulingNode, OperationFailure> {
        archive.inner.authenticate_birth().map_err(failure)?;
        self.authenticate_complete_archive_source(&archive.inner)?;
        let selected = self.selection();
        if self.node_created.get()
            || graph.world_binding_hash() != &self.world
            || graph.descriptor(&selected.descriptor.id) != Some(&selected.descriptor)
            || graph.binding(&selected.descriptor.id) != Some(&selected.binding)
            || graph.owner(&selected.owner.owner.id) != Some(&selected.owner)
            || graph.operating_policy(&selected.descriptor.id) != Some(&selected.operating_policy)
            || graph.guarantees(&selected.descriptor.id) != Some(&selected.guarantees)
            || activation.world_binding_hash != self.world
        {
            return Err(failure(
                "complete fresh host differs from its actual admitted graph",
            ));
        }
        let owner = OwnerIdentity {
            owner: selected.owner.owner.id.clone(),
            incarnation: selected.binding.authority.incarnation_id.clone(),
            generation: selected.binding.authority.owner_generation,
        };
        if !activation.owners.contains(&owner) {
            return Err(failure(
                "complete fresh host owner is absent from actual target",
            ));
        }
        let anchor = Rc::new(());
        *self.node.try_borrow_mut().map_err(failure)? = Rc::downgrade(&anchor);
        self.node_created.set(true);
        Ok(PreparedHostSchedulingNode::new_complete_restoration(
            Rc::clone(self),
            anchor,
            plan,
            activation.clone(),
            NodeRoute {
                node: selected.descriptor.id.clone(),
                owners: vec![owner],
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    // Closed source-selection controls panic only on invalid fixture setup.
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn complete_selection() -> (HostSchedulingSelection, HashRef) {
        let original = super::super::tests::source_owner();
        let source = original.source();
        assert_eq!(source.initial_node_record().unwrap()["facets"], json!([]));
        assert!(
            source
                .authenticate_complete_preparation_source(source.world())
                .is_err()
        );
        let mut selection = source.selection().clone();
        let definition = preservation::definition(Edition::CompleteOriginalLineage).unwrap();
        let configuration = canonical::content_ref(
            &host_scheduling_complete_owner_configuration(&selection.domains).unwrap(),
            "application/json",
        )
        .unwrap();
        selection.descriptor.model_ref = definition.clone();
        selection.descriptor.configuration_ref = configuration.clone();
        selection.descriptor.initialization_ref = configuration.clone();
        selection.binding.compatibility.profile_ref = definition;
        selection.binding.compatibility.configuration_ref = configuration;
        selection.guarantees.capture_scope = CaptureScope::CompleteModel;
        selection.guarantees.continuation = Continuation::Exact;
        selection.guarantees.durable_restart = true;
        let guarantees = canonical::content_ref(
            &canonical::canonical_json(&serde_json::to_value(&selection.guarantees).unwrap())
                .unwrap(),
            "application/json",
        )
        .unwrap();
        selection.binding.compatibility.guarantees_ref = guarantees.clone();
        selection.binding.compatibility.operating_contract.facets = vec![
            host_scheduling_complete_preservation_facet(
                selection.binding.compatibility.configuration_ref.clone(),
                guarantees,
            )
            .unwrap(),
        ];
        let formats = &mut selection.binding.compatibility.implementation.formats;
        formats.retain(|schema| {
            !schema
                .id
                .as_str()
                .starts_with("source-owned.host-scheduling-owner-preparation/")
        });
        formats.push(host_scheduling_complete_owner_preparation_schema().unwrap());
        formats.push(host_scheduling_complete_continuation_schema().unwrap());
        formats.sort_by(|left, right| left.id.cmp(&right.id));
        selection.owner.node_bindings[0].binding_hash = selection.binding.identity().unwrap();
        (selection, source.world().clone())
    }

    #[test]
    fn prebirth_original_host_guard_counts_actual_spares_without_runtime_permission() {
        let (selection, world) = complete_selection();
        let mut owner =
            HostSchedulingOwner::new_complete_original_continuation(selection, world).unwrap();
        let source = Rc::get_mut(&mut owner.source).unwrap();
        source.authenticate_original_report_startup_data().unwrap();
        let before = source
            .retained_prebirth_host_metadata_data(usize::MAX)
            .unwrap();
        source.selection.domains.connections.reserve_exact(32);
        let after = source
            .retained_prebirth_host_metadata_data(usize::MAX)
            .unwrap();

        assert!(after > before);
        assert_eq!(
            source.retained_prebirth_host_metadata_data(after).unwrap(),
            after
        );
        assert!(
            source
                .retained_prebirth_host_metadata_data(after - 1)
                .is_err()
        );
        assert!(source.authenticate_current().is_err());
        source.attachment_attempted.set(true);
        assert!(source.authenticate_original_report_startup_data().is_err());
        assert!(source.attachment_attempted.get());
    }

    #[test]
    fn prebirth_host_origin_refuses_before_busy_loans_and_preserves_spent_node() {
        let (selection, world) = complete_selection();
        let mut owner =
            HostSchedulingOwner::new_complete_original_continuation(selection, world).unwrap();
        let source = Rc::get_mut(&mut owner.source).unwrap();
        let current = source.process;
        source.process = 0;
        let loan = source.attached.borrow_mut();
        assert!(matches!(
            source.authenticate_prebirth_storage_data(None),
            Err(RuntimeError::ForeignAuthority)
        ));
        drop(loan);
        source.process = current;
        let loan = source.attached.borrow_mut();
        assert!(matches!(
            source.authenticate_prebirth_storage_data(None),
            Err(RuntimeError::OutstandingObligations)
        ));
        drop(loan);
        source.node_created.set(true);
        assert!(source.authenticate_original_report_startup_data().is_err());
        assert!(source.node_created.get());
    }

    #[test]
    fn complete_factory_selection_is_distinct_and_does_not_create_live_permission() {
        let (selection, world) = complete_selection();
        assert!(HostSchedulingOwner::new(selection.clone(), world.clone()).is_err());
        assert!(HostSchedulingOwner::new_continuation(selection.clone(), world.clone()).is_err());
        let owner =
            HostSchedulingOwner::new_complete_original_continuation(selection, world).unwrap();
        let source = owner.source();
        assert_eq!(
            source.initial_node_record().unwrap()["facets"],
            json!(["preservation"])
        );
        assert!(
            source
                .authenticate_preparation_source(source.world())
                .is_ok()
        );
        assert!(
            source
                .authenticate_complete_preparation_source(source.world())
                .is_ok()
        );
        let foreign_world = canonical::hash("test.foreign-world", b"different").unwrap();
        assert!(
            source
                .authenticate_complete_preparation_source(&foreign_world)
                .is_err()
        );
        assert!(source.authenticate_current().is_err());
        assert!(source.archive_ticket.is_none());
        assert!(source.original_restoration_record().is_err());
    }

    #[test]
    fn complete_factory_refuses_missing_installed_codec_or_preservation_facet() {
        let (selection, world) = complete_selection();
        for drop_codec in [false, true] {
            let mut changed = selection.clone();
            if drop_codec {
                changed
                    .binding
                    .compatibility
                    .implementation
                    .formats
                    .retain(|schema| {
                        schema.id.as_str() != "source-owned.host-scheduling-continuation/2"
                    });
            } else {
                changed
                    .binding
                    .compatibility
                    .operating_contract
                    .facets
                    .clear();
            }
            changed.owner.node_bindings[0].binding_hash = changed.binding.identity().unwrap();
            assert!(
                HostSchedulingOwner::new_complete_original_continuation(changed, world.clone())
                    .is_err()
            );
        }
    }

    #[test]
    fn complete_factory_refuses_unsupported_guarantees_and_old_definition() {
        let (selection, world) = complete_selection();
        let mut changed = selection.clone();
        changed.guarantees.capture_scope = CaptureScope::None;
        changed.binding.compatibility.guarantees_ref = canonical::content_ref(
            &canonical::canonical_json(&serde_json::to_value(&changed.guarantees).unwrap())
                .unwrap(),
            "application/json",
        )
        .unwrap();
        changed.owner.node_bindings[0].binding_hash = changed.binding.identity().unwrap();
        assert!(
            HostSchedulingOwner::new_complete_original_continuation(changed, world.clone())
                .is_err()
        );
        let old = super::super::tests::source_owner();
        assert!(
            HostSchedulingOwner::new_complete_original_continuation(
                old.source().selection().clone(),
                world
            )
            .is_err()
        );
    }
    #[test]
    fn original_complete_source_observer_counts_original_spare_metadata_and_exact_limit() {
        // Genuine source creation remains preparation-only; no runtime/Ready or
        // historical restoration authority is inferred from this data observer.
        let (selection, world) = complete_selection();
        let mut owner =
            HostSchedulingOwner::new_complete_original_continuation(selection, world).unwrap();
        let before = owner
            .source
            .retained_original_metadata_bytes_excluding_runtime(1024 * 1024)
            .unwrap();
        let source = Rc::get_mut(&mut owner.source).unwrap();
        let previous = source.prepared_token.allocated_capacity();
        let mut token = String::with_capacity(128 * 1024);
        token.push_str(source.prepared_token.as_str());
        source.prepared_token = Id::new(token).unwrap();
        let added = source.prepared_token.allocated_capacity() - previous;
        let after = source
            .retained_original_metadata_bytes_excluding_runtime(1024 * 1024)
            .unwrap();
        assert_eq!(after, before + added);
        assert_eq!(
            source
                .retained_original_metadata_bytes_excluding_runtime(after)
                .unwrap(),
            after
        );
        assert!(
            source
                .retained_original_metadata_bytes_excluding_runtime(after - 1)
                .is_err()
        );
        source.process = source.process.wrapping_add(1);
        assert!(
            source
                .retained_original_metadata_bytes_excluding_runtime(usize::MAX)
                .is_err()
        );
    }

    fn collection_activation(source: &HostSchedulingSource) -> ActivationRecord {
        ActivationRecord {
            generation: 1.into(),
            activation_id: Id::new("host/collection-construction").unwrap(),
            world_binding_hash: source.world().clone(),
            owners: vec![OwnerIdentity {
                owner: source.selection.owner.owner.id.clone(),
                incarnation: source.selection.binding.authority.incarnation_id.clone(),
                generation: source.selection.binding.authority.owner_generation,
            }],
            boundary: crucible_node_format::Position::new(
                0.into(),
                0.into(),
                crucible_node_format::Phase::BoundaryControl,
            ),
        }
    }

    #[test]
    fn collecting_node_quote_counts_actual_clone_backing_and_preserves_unspent_source() {
        let (selection, world) = complete_selection();
        let owner =
            HostSchedulingOwner::new_complete_original_continuation(selection, world).unwrap();
        let source = owner.source();
        let mut activation = collection_activation(&source);
        activation.owners.reserve_exact(7);
        let original_capacity = activation.owners.capacity();
        let data = source
            .original_collection_node_construction_storage_data(&activation, usize::MAX)
            .unwrap();
        let peak = data.retained_requested_bytes()
            + data.maximum_simultaneous_transient_bytes()
            + data.declared_counter_scratch_bytes();

        assert_eq!(
            source
                .original_collection_node_construction_storage_data(&activation, peak)
                .unwrap(),
            data
        );
        assert!(
            source
                .original_collection_node_construction_storage_data(&activation, peak - 1)
                .is_err()
        );
        assert_eq!(activation.owners.capacity(), original_capacity);
        assert!(!source.node_created.get());
        assert!(!source.attachment_attempted.get());
        assert!(source.node.borrow().upgrade().is_none());

        // Compare the prospective row with the existing typed owning visitor on
        // actual cloned values. This creates no graph/node or attachment grant.
        let cloned = activation.clone();
        let route = NodeRoute {
            node: source.selection.descriptor.id.clone(),
            owners: vec![activation.owners[0].clone()],
        };
        let actual = std::mem::size_of::<PreparedHostSchedulingNode>()
            + crate::node_contract::NodeRuntime::capture_shared_allocation_storage::<()>()
            + crate::node_contract::NodeRuntime::capture_host_node_metadata_storage(
                &cloned, &route, None,
            )
            .unwrap();
        assert!(data.retained_requested_bytes() >= actual);
    }

    #[test]
    fn collecting_node_quote_refuses_foreign_owner_world_and_spent_phase() {
        let (selection, world) = complete_selection();
        let owner =
            HostSchedulingOwner::new_complete_original_continuation(selection, world).unwrap();
        let source = owner.source();
        let activation = collection_activation(&source);
        let mut foreign = activation.clone();
        foreign.owners[0].incarnation = Id::new("another/host-incarnation").unwrap();
        assert!(
            source
                .original_collection_node_construction_storage_data(&foreign, usize::MAX)
                .is_err()
        );
        foreign = activation.clone();
        foreign.world_binding_hash.digest.push('0');
        assert!(
            source
                .original_collection_node_construction_storage_data(&foreign, usize::MAX)
                .is_err()
        );

        let busy = source.node.borrow_mut();
        assert!(
            source
                .original_collection_node_construction_storage_data(&activation, usize::MAX)
                .is_err()
        );
        drop(busy);
        assert!(!source.node_created.get());
        source.node_created.set(true);
        assert!(
            source
                .original_collection_node_construction_storage_data(&activation, usize::MAX)
                .is_err()
        );
        assert!(!source.attachment_attempted.get());
    }

    #[test]
    fn real_original_scheduler_attachment_matches_the_prospective_host_report() {
        use crate::node_contract::runtime::scheduling_state::OriginalSchedulingState;

        let (selection, mut world) = complete_selection();
        world.digest.reserve_exact(257);
        let owner =
            HostSchedulingOwner::new_complete_original_continuation(selection, world).unwrap();
        let source = owner.source();
        let before = source
            .retained_original_metadata_bytes_excluding_runtime_precredit_data(usize::MAX)
            .unwrap();
        let quoted = source
            .original_unattached_runtime_storage_data(usize::MAX)
            .unwrap();
        let component = quoted.existing_source_observation_bytes()
            + quoted.attached_observation_bytes().unwrap();
        assert_eq!(
            source
                .original_unattached_runtime_storage_data(component)
                .unwrap(),
            quoted
        );
        assert_eq!(
            source.original_unattached_runtime_storage_data(component - 1),
            Err(RuntimeError::ResourceLimit),
        );
        assert!(!source.attachment_attempted.get());
        assert!(source.attached.borrow().is_none());

        // String clones may trim the deliberately spare world capacity, so the
        // prospective world term is a bound on the observed clone.
        // These are the real uninitialized Core scheduler and Source handle.
        // No fake node observer, graph authority, runtime grant or Provider is used.
        let authority = Rc::new(());
        let scheduler = OriginalSchedulingState::new(&authority, source.world.clone());
        source.begin_attachment().unwrap();
        source.attach(scheduler.source()).unwrap();

        let after = source
            .retained_original_metadata_bytes_excluding_runtime_precredit_data(usize::MAX)
            .unwrap();
        let actual_growth = after - before;
        assert!(quoted.attached_observation_bytes().unwrap() >= actual_growth);
        assert!(actual_growth >= quoted.attached_weak_observation_bytes());
        assert!(
            quoted.retained_requested_bytes()
                >= actual_growth - quoted.attached_weak_observation_bytes()
        );
        assert_eq!(
            source
                .retained_original_metadata_bytes_excluding_runtime_precredit_data(after)
                .unwrap(),
            after,
        );
        assert_eq!(
            source.retained_original_metadata_bytes_excluding_runtime_precredit_data(after - 1),
            Err(RuntimeError::ResourceLimit),
        );
        assert_eq!(
            source.original_unattached_runtime_storage_data(usize::MAX),
            Err(RuntimeError::ForeignAuthority)
        );
    }

    #[test]
    fn prospective_host_attachment_refuses_spent_or_foreign_originals() {
        let (selection, world) = complete_selection();
        let owner =
            HostSchedulingOwner::new_complete_original_continuation(selection, world).unwrap();
        let source = owner.source();
        let before = source
            .original_unattached_runtime_storage_data(usize::MAX)
            .unwrap();
        source.begin_attachment().unwrap();
        assert_eq!(
            source.original_unattached_runtime_storage_data(usize::MAX),
            Err(RuntimeError::ForeignAuthority)
        );
        assert!(source.attached.borrow().is_none());
        assert!(before.retained_requested_bytes() > 0);

        let ordinary = super::super::tests::source_owner();
        assert_eq!(
            ordinary
                .source()
                .original_unattached_runtime_storage_data(usize::MAX),
            Err(RuntimeError::ForeignAuthority)
        );
    }
}

impl SelectedPreservation {
    pub(super) fn cloned_metadata_data(&self) -> Self {
        Self {
            profile: self.profile.clone(),
        }
    }

    pub(super) fn retained_requested_storage(&self) -> usize {
        self.profile.allocated_capacity()
    }
}
