//! Reserves one complete fresh four-owner world from an authenticated archive.
//!
//! All installed identities, immutable input bytes, independent models and owner
//! slots precede native reconstruction. The complete signed source remains in
//! the actual CPU lease; the unchanged two-owner implementation policy supplies
//! only its separate installed CPU and Clock predicates.

use std::collections::BTreeMap;

use super::super::super::{
    InstalledNodeCatalog, InstalledNodeSelection, prepared_models::PreparedModelRoster,
    trust::InstalledEvidence,
};
use super::super::host_group::{
    artifacts::GroupArtifacts, evidence::IndependentGroupEvidence,
    profile::IndependentGroupProfile, reservation::ReservedGroupRestore,
    selection::IndependentGroupSelection,
};
use super::host_group::source_bindings;
use super::*;
use crucible_node_contract::canonical;

/// Owns the source lease and every inactive fresh Host model before native birth.
pub(in crate::node_observed_executor::factory::native_state) struct IndependentColdWorld {
    pub(in crate::node_observed_executor::factory::native_state) profile:
        Rc<IndependentGroupProfile>,
    pub(in crate::node_observed_executor::factory::native_state) graph: Rc<AdmittedGraph>,
    pub(in crate::node_observed_executor::factory::native_state) evidence:
        Rc<IndependentGroupEvidence>,
    pub(in crate::node_observed_executor::factory::native_state) native_evidence: Rc<MixedEvidence>,
    pub(in crate::node_observed_executor::factory::native_state) target: ActivationRecord,
    pub(in crate::node_observed_executor::factory::native_state) archive: NativeArchiveRecord,
    pub(in crate::node_observed_executor::factory::native_state) slot: Box<dyn Gem5CustodySlot>,
    pub(in crate::node_observed_executor::factory::native_state) namespace: PathBuf,
    pub(in crate::node_observed_executor::factory::native_state) models: BTreeMap<Id, HostModel>,
}

impl InstalledMixedEngine {
    /// Authenticates and reserves the distinct complete Script/Block source family.
    ///
    /// # Errors
    /// Refuses foreign source or selections, missing independently enrolled signed
    /// immutable bytes, changed host/device code, stale owners or unavailable slots.
    pub(in crate::node_observed_executor::factory::native_state) fn prepare_independent_cold_group(
        &self,
        catalog: &InstalledNodeCatalog,
        selections: &[InstalledNodeSelection],
        archive: NativeArchiveRecord,
    ) -> Result<IndependentColdWorld, NodeObservedError> {
        self.prepare_independent_cold_group_selected(catalog, selections, archive, None)
    }

    pub(in crate::node_observed_executor::factory::native_state) fn prepare_independent_cold_capability_group(
        &self,
        catalog: &InstalledNodeCatalog,
        selections: &[InstalledNodeSelection],
        archive: NativeArchiveRecord,
        capabilities: &super::super::super::ResolvedCapabilityWorld,
    ) -> Result<IndependentColdWorld, NodeObservedError> {
        self.prepare_independent_cold_group_selected(
            catalog,
            selections,
            archive,
            Some(capabilities),
        )
    }

    fn prepare_independent_cold_group_selected(
        &self,
        catalog: &InstalledNodeCatalog,
        selections: &[InstalledNodeSelection],
        archive: NativeArchiveRecord,
        capabilities: Option<&super::super::super::ResolvedCapabilityWorld>,
    ) -> Result<IndependentColdWorld, NodeObservedError> {
        let selected = IndependentGroupSelection::new_preserving(selections)?;
        let artifacts = GroupArtifacts::materialize(catalog, selections, &archive)?;
        let profile = IndependentGroupProfile::build_preserving_scoped(
            self.installed.clone(),
            catalog,
            selections,
            artifacts.registry(),
        )?;
        let profile = Rc::new(match capabilities {
            None => profile,
            Some(resolved) => profile.with_capabilities(resolved)?,
        });
        if archive.manifest().world_binding_hash != profile.scenario.world.identity()?
            || measure_executable(&catalog.host_executable)? != catalog.host_identity
            || measure_executable(&catalog.device_executable)? != catalog.device_identity
        {
            return Err(refused(
                "complete group archive differs from regenerated source",
            ));
        }
        let target = fresh_group_target(&profile, &archive)?;
        let clock = HostModel::Clock(VirtualClock::new());
        let (models, _empty_nodes) =
            PreparedModelRoster::new(selected.selections, &profile.scenario, artifacts.registry())?
                .into_parts();
        let mut all_bindings = Vec::new();
        all_bindings.try_reserve_exact(4).map_err(error)?;
        let host_receipt_bytes = canonical::canonical_json(&serde_json::json!({
            "schema": "crucible.independent-group-reserved-host-enrollment.v1",
            "world": profile.scenario.world.identity()?,
            "source": archive.artifact(),
            "target": crucible::node_contract::SavedRuntimeActivation::from(&target),
            "host": catalog.host_identity,
            "device": catalog.device_identity,
            "models": profile.group.descriptors.iter()
                .map(|node| (&node.id, &node.initialization_ref)).collect::<Vec<_>>(),
            "native_readiness": false,
        }))?;
        let host_receipt = canonical::content_ref(&host_receipt_bytes, "application/json")?;
        let host_bindings = source_bindings(&profile.group, &target, &host_receipt)?;
        let mut host_content = BTreeMap::new();
        for body in &profile.group.content {
            host_content.insert(
                body.reference.hash.digest.clone(),
                (body.reference.clone(), body.bytes.clone()),
            );
        }
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
        profile
            .group
            .admit(&host_bindings, &host_evidence, admission_limits())
            .map_err(error)?;
        for original in &host_bindings {
            let mut binding = original.clone();
            binding.compatibility = profile
                .scenario
                .compatibility
                .iter()
                .find(|binding| binding.node_id == original.compatibility.node_id)
                .ok_or_else(|| refused("reserved group selected model facade is absent"))?
                .clone();
            all_bindings.push(binding);
        }

        let cpu = cpu_owner(&target)?;
        let slot = self
            .native
            .reserve(NativeOwnerScope {
                activation: target.clone(),
                owner: cpu.clone(),
                publication: PublicationKnowledge::NotAttempted,
                backing: NativeBacking::Archived {
                    artifacts: archive.owner_artifacts(&cpu.owner).map_err(error)?,
                    source: Box::new(archive.clone()),
                },
            })
            .map_err(error)?;
        let reservation = ReservedGroupRestore::new(
            profile.clone(),
            archive.clone(),
            target.clone(),
            self.native.clone(),
        )?;
        let receipt = MixedEvidence::reserved_group_enrollment_receipt(
            &profile.native,
            &clock,
            &reservation,
        )?;
        let native_bindings = bindings(&profile.native, &target, &receipt.reference)?;
        let native_evidence = Rc::new(MixedEvidence::enroll_reserved_group_restore(
            &profile.native,
            &native_bindings,
            &clock,
            reservation,
            &self.host,
        )?);
        // This regenerated two-node graph is implementation metadata only. The
        // reserved native backing and the eventual activation remain full-world.
        let native_graph = Rc::new(
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
        let evidence = Rc::new(IndependentGroupEvidence::new(
            profile.clone(),
            all_bindings,
            native_evidence.clone(),
            host_evidence,
            host_bindings,
            native_graph,
        )?);
        let capability_admission = capabilities.map(|resolved| {
            super::super::super::capabilities::admission::CapabilityAdmission {
                original: evidence.as_ref(),
                resolved,
            }
        });
        let admission: &dyn crucible::node_admission::AdmissionEvidence =
            match &capability_admission {
                None => evidence.as_ref(),
                Some(admission) => admission,
            };
        let graph = Rc::new(
            profile
                .scenario
                .admit(evidence.bindings(), admission, admission_limits())
                .map_err(error)?,
        );
        let namespace = self.namespace()?;
        Ok(IndependentColdWorld {
            profile,
            graph,
            evidence,
            native_evidence,
            target,
            archive,
            slot,
            namespace,
            models,
        })
    }
}

fn fresh_group_target(
    profile: &IndependentGroupProfile,
    archive: &NativeArchiveRecord,
) -> Result<ActivationRecord, NodeObservedError> {
    let previous = archive.source_activation().map_err(error)?;
    if previous.world_binding_hash != profile.scenario.world.identity()?
        || previous.owners.len() != 4
        || profile.scenario.owners.len() != 4
    {
        return Err(refused("reserved group original activation roster differs"));
    }
    let mut owners = Vec::new();
    owners.try_reserve_exact(4).map_err(error)?;
    for binding in &profile.scenario.owners {
        let original = previous
            .owners
            .iter()
            .find(|owner| owner.owner == binding.owner.id)
            .ok_or_else(|| refused("reserved group original owner is absent"))?;
        owners.push(OwnerIdentity {
            owner: original.owner.clone(),
            incarnation: Id::new(format!("mixed/{}", fresh_nonce()?))?,
            generation: original.generation.checked_add(U64::new(1))?,
        });
    }
    owners.sort();
    Ok(ActivationRecord {
        generation: previous.generation.checked_add(U64::new(1))?,
        activation_id: Id::new(format!("mixed/{}", fresh_nonce()?))?,
        world_binding_hash: profile.scenario.world.identity()?,
        owners,
        boundary: archive.manifest().cut,
    })
}
