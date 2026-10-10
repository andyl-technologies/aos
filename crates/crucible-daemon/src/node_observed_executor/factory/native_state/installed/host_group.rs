//! Prepares one complete native CPU and independent storage group under original custody.
//!
//! Every inactive Host model, full graph credit, artifact and node slot precedes
//! child birth. The original native capsule then remains owned by the same
//! supervisor while both source-installed predicates seal one complete world.
//! No subworld is activated and no callback reconstructs an original owner.

use std::collections::BTreeMap;

use super::super::super::{
    InstalledNodeCatalog, InstalledNodeSelection, prepared_models::PreparedModelRoster,
    trust::InstalledEvidence,
};
use super::super::host_group::{
    evidence::IndependentGroupEvidence, profile::IndependentGroupProfile,
    selection::IndependentGroupSelection,
};
use super::*;
use crucible_node_contract::{ContentRef, NodeBinding, canonical};

pub(in crate::node_observed_executor::factory::native_state) struct IndependentLiveWorld {
    pub(in crate::node_observed_executor::factory::native_state) profile:
        Rc<IndependentGroupProfile>,
    pub(in crate::node_observed_executor::factory::native_state) graph: Rc<AdmittedGraph>,
    pub(in crate::node_observed_executor::factory::native_state) realization: PreparedRealization,
    pub(in crate::node_observed_executor::factory::native_state) target: ActivationRecord,
}

impl InstalledMixedEngine {
    pub(in crate::node_observed_executor::factory::native_state) fn prepare_independent_group(
        &self,
        catalog: &InstalledNodeCatalog,
        selections: &[InstalledNodeSelection],
        expected: &crate::node_scenario::NodeScenario,
        activation_id: Id,
        capabilities: Option<&super::super::super::ResolvedCapabilityWorld>,
    ) -> Result<IndependentLiveWorld, NodeObservedError> {
        let selected = IndependentGroupSelection::new(selections)?;
        let profile = IndependentGroupProfile::build(self.installed.clone(), catalog, selections)?;
        let profile = Rc::new(match capabilities {
            Some(resolved) => profile.with_capabilities(resolved)?,
            None => profile,
        });
        if profile.scenario.canonical_bytes()? != expected.canonical_bytes()?
            || measure_executable(&catalog.host_executable)? != catalog.host_identity
            || measure_executable(&catalog.device_executable)? != catalog.device_identity
        {
            return Err(refused(
                "complete independent group differs from actual installed source",
            ));
        }
        let limits = RuntimeLimits {
            maximum_nodes: 4,
            maximum_owners: 4,
            ..runtime_limits()
        };
        let clock = HostModel::Clock(VirtualClock::new());
        let (mut models, mut nodes) =
            PreparedModelRoster::new(selected.selections, &profile.scenario, &catalog.artifacts)?
                .into_parts();
        nodes.try_reserve_exact(2).map_err(error)?;
        let mut all_bindings = Vec::new();
        all_bindings.try_reserve_exact(4).map_err(error)?;
        let target = target(&profile.scenario, activation_id)?;
        let runtime_slot = self.runtime.reserve_world(&target, limits).map_err(error)?;
        let host_receipt_bytes = canonical::canonical_json(&serde_json::json!({
            "schema":"crucible.independent-group-original-enrollment.v1",
            "world":profile.scenario.world.identity()?,"activation":target.activation_id,"owners":target.owners.iter().map(|owner| (&owner.owner,&owner.incarnation,owner.generation)).collect::<Vec<_>>(),
            "host":catalog.host_identity,"device":catalog.device_identity,
            "models":profile.group.descriptors.iter().map(|node| (&node.id,&node.initialization_ref)).collect::<Vec<_>>(),
        }))?;
        let host_receipt = canonical::content_ref(&host_receipt_bytes, "application/json")?;
        let host_bindings = source_bindings(&profile.group, &target, &host_receipt)?;
        let mut host_content: BTreeMap<String, (ContentRef, Vec<u8>)> = profile
            .group
            .content
            .iter()
            .map(|body| {
                (
                    body.reference.hash.digest.clone(),
                    (body.reference.clone(), body.bytes.clone()),
                )
            })
            .collect();
        host_content.insert(
            host_receipt.hash.digest.clone(),
            (host_receipt.clone(), host_receipt_bytes),
        );
        let assets = BTreeMap::from([
            (
                catalog.host_identity.hash.digest.clone(),
                (
                    catalog.host_identity.clone(),
                    catalog.host_executable.clone(),
                ),
            ),
            (
                catalog.device_identity.hash.digest.clone(),
                (
                    catalog.device_identity.clone(),
                    catalog.device_executable.clone(),
                ),
            ),
        ]);
        let host_evidence = InstalledEvidence::new(
            &profile.group,
            &host_bindings,
            &BTreeMap::new(),
            &models,
            host_content,
            assets,
        )?;
        // The original source graph is data about these exact already-owned Host
        // instances, not an activated child world or a second scheduler.
        profile
            .group
            .admit(&host_bindings, &host_evidence, admission_limits())
            .map_err(error)?;
        // Narrow the selected public facade before native birth, retaining the
        // exact separately authenticated original model tuple for its evidence.
        for original in &host_bindings {
            let mut selected = original.clone();
            selected.compatibility = profile
                .scenario
                .compatibility
                .iter()
                .find(|binding| binding.node_id == original.compatibility.node_id)
                .ok_or_else(|| refused("selected original model tuple is absent"))?
                .clone();
            all_bindings.push(selected);
        }
        let files = [
            "native_executable",
            "controller",
            "model",
            "dmtcp_launch",
            "dmtcp_restart",
            "mtcp_restart",
            "image_guard",
            "auditor",
        ]
        .into_iter()
        .map(|name| {
            self.installed
                .artifact(name)
                .and_then(|asset| File::open(asset.path).map_err(error))
        })
        .chain(std::iter::once(
            self.installed
                .guest("x86_64")
                .and_then(|guest| File::open(guest.path).map_err(error)),
        ))
        .collect::<Result<Vec<_>, _>>()?;
        let cpu = cpu_owner(&target)?;
        let slot = self
            .native
            .reserve(NativeOwnerScope {
                activation: target.clone(),
                owner: cpu.clone(),
                publication: PublicationKnowledge::NotAttempted,
                backing: NativeBacking::Fresh { files },
            })
            .map_err(error)?;
        let namespace = self.namespace()?;
        let mut native =
            Gem5NativeProcess::spawn(launch(&self.installed, "x86_64", &cpu, &namespace)?, slot)
                .map_err(error)?;
        let capture = native
            .capture(
                Id::new(format!("initial/{}", fresh_nonce()?))?,
                &namespace.join("initial"),
            )
            .map_err(error)?;
        let auditor = self.installed.artifact("auditor")?;
        let certificate = native
            .qualify_capture(&capture, &namespace, &auditor, self.installed.as_ref())
            .map_err(error)?;
        let authority = native
            .qualify_exact(
                &capture,
                &certificate,
                &auditor,
                self.installed.as_ref(),
                self.installed.maximum_microsteps(),
            )
            .map_err(error)?;
        let native_receipt =
            MixedEvidence::live_enrollment_receipt(&profile.native, &clock, &native, &authority)?;
        let native_bindings = bindings(&profile.native, &target, &native_receipt.reference)?;
        let native_evidence = Rc::new(MixedEvidence::enroll_live(
            &profile.native,
            &native_bindings,
            &clock,
            &native,
            &authority,
            &self.host,
        )?);
        let original_native_graph = Rc::new(
            profile
                .native
                .scenario
                .admit(
                    &native_bindings,
                    native_evidence.as_ref(),
                    admission_limits(),
                )
                .map_err(error)?,
        );
        all_bindings.extend(native_bindings);
        all_bindings
            .sort_by(|left, right| left.compatibility.node_id.cmp(&right.compatibility.node_id));
        let evidence = IndependentGroupEvidence::new(
            profile.clone(),
            all_bindings,
            native_evidence,
            host_evidence,
            host_bindings,
            original_native_graph,
        )?;
        let capability_admission = capabilities.map(|resolved| {
            super::super::super::capabilities::admission::CapabilityAdmission {
                original: &evidence,
                resolved,
            }
        });
        let admission: &dyn crucible::node_admission::AdmissionEvidence =
            match &capability_admission {
                Some(admission) => admission,
                None => &evidence,
            };
        let graph = Rc::new(
            profile
                .scenario
                .admit(evidence.bindings(), admission, admission_limits())
                .map_err(error)?,
        );
        let mut actual_clock = HostModelNode::new(
            &graph,
            &Id::new("clock")?,
            clock,
            &evidence,
            host_resources(),
        )
        .map_err(|failure| refused(&failure.reason))?;
        actual_clock
            .qualify_public_initial_clock(&graph, &evidence)
            .map_err(|failure| refused(&failure.reason))?;
        let qualification = evidence.qualify_prepared(&native, &authority, graph.clone())?;
        let prepared =
            Gem5NodePreparation::from_prepared(&graph, &Id::new("cpu")?, native, &qualification)
                .map_err(|failure| refused(&failure.error.reason))?;
        let cpu = prepared
            .into_qualified_simulation_node(&graph, authority, native_resources("x86_64")?)
            .map_err(|failure| refused(&failure.error.reason))?
            .into_public_initial_preparation(&graph, &qualification)
            .map_err(|failure| refused(&failure.error.reason))?;
        nodes.push(Box::new(actual_clock));
        nodes.push(Box::new(cpu));
        for selected in selected.selections {
            let model = models
                .remove(&selected.node)
                .ok_or_else(|| refused("original independent model custody is absent"))?;
            let mut original_model = HostModelNode::new(
                &graph,
                &selected.node,
                model,
                &evidence,
                HostModelResources::default(),
            )
            .map_err(|failure| refused(&failure.reason))?;
            original_model
                .qualify_public_initial_owned_model(&graph, &evidence)
                .map_err(|failure| refused(&failure.reason))?;
            nodes.push(Box::new(original_model));
        }
        if !models.is_empty() {
            return Err(refused(
                "independent group retained an unclaimed native model",
            ));
        }
        drop(qualification);
        Ok(IndependentLiveWorld {
            profile,
            graph,
            realization: PreparedRealization::new(nodes, target.clone(), limits, runtime_slot),
            target,
        })
    }
}

fn target(
    scenario: &crate::node_scenario::NodeScenario,
    activation_id: Id,
) -> Result<ActivationRecord, NodeObservedError> {
    let mut owners = scenario
        .owners
        .iter()
        .map(|binding| {
            Ok(OwnerIdentity {
                owner: binding.owner.id.clone(),
                incarnation: Id::new(format!("mixed/{}", fresh_nonce()?))?,
                generation: U64::new(1),
            })
        })
        .collect::<Result<Vec<_>, NodeObservedError>>()?;
    owners.sort();
    Ok(ActivationRecord {
        generation: U64::new(1),
        activation_id,
        world_binding_hash: scenario.world.identity()?,
        owners,
        boundary: Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl),
    })
}

fn source_bindings(
    scenario: &crate::node_scenario::NodeScenario,
    target: &ActivationRecord,
    receipt: &ContentRef,
) -> Result<Vec<NodeBinding>, NodeObservedError> {
    let session = Id::new(format!("mixed/{}", fresh_nonce()?))?;
    scenario
        .compatibility
        .iter()
        .map(|selected| {
            let owner = target
                .owners
                .iter()
                .find(|owner| owner.owner == selected.execution_owner.id)
                .ok_or_else(|| refused("original group owner is absent from complete target"))?;
            Ok(NodeBinding {
                compatibility: selected.clone(),
                authority: LiveAuthority {
                    schema_version: 1,
                    session_id: session.clone(),
                    incarnation_id: owner.incarnation.clone(),
                    realization_id: session.clone(),
                    activation_id: None,
                    world_generation: U64::new(0),
                    owner_generation: owner.generation,
                    input_epoch: session.clone(),
                    host_receipt: receipt.clone(),
                    extensions: Default::default(),
                },
                extensions: Default::default(),
            })
        })
        .collect()
}
