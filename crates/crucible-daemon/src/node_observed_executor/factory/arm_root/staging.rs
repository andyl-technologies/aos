//! Restores complete Root owners beneath an already installed owning capsule.
//!
//! Imported historical images and their pinned source remain owned before every
//! native allocation. Fresh readiness requires independently recapturing and
//! auditing the actual reconstructed peer, then reattaching original custody.

use std::{
    collections::BTreeMap,
    rc::Rc,
    task::{Context, Poll},
    time::Duration,
};

use crucible::{
    node_adapters::arm_root::{
        ArmRootArchiveInstallation, ArmRootNodePreparation, ArmRootNodeResources,
    },
    node_admission::AdmittedGraph,
    node_contract::{
        ActivationRecord, NativeRuntimeContinuationEvidence, NativeRuntimeContinuationVerifier,
        ReadyAttestation, RuntimeError, RuntimeSnapshot, SimulationNode,
    },
    node_scheduling::SchedulingSnapshot,
    node_state::{
        NativeArchiveRecord, NativeRestoreStaging, OriginalWorldDisposition, PublicationKnowledge,
        RestoreReservations, RestoredOwnerAttestation, StateError, StateErrorCode, VerifiedCapture,
    },
};
use crucible_node_contract::{CapturedOwner, ContentRef, Id, canonical};
use crucible_node_provider::gem5::{
    ArmRootCustodySlot, ArmRootNativeProcess, ArmRootRestoreTarget,
};

use super::{
    archive::MaterializedRootArchive, custody::RootCustodyQueue, evidence::RootEvidence,
    profile::RootWorldProfile, qualification::RootPreparedQualification,
};

pub(super) struct RootStaging {
    pub(super) graph: Rc<AdmittedGraph>,
    pub(super) archive: NativeArchiveRecord,
    pub(super) profile: Rc<RootWorldProfile>,
    pub(super) evidence: Rc<RootEvidence>,
    pub(super) target: ActivationRecord,
    pub(super) reservations: RestoreReservations,
    pub(super) queue: RootCustodyQueue,
    pub(super) slot: Option<Box<dyn ArmRootCustodySlot>>,
    pub(super) namespace: std::path::PathBuf,
    pub(super) imported: Option<MaterializedRootArchive>,
    pub(super) native: Option<ArmRootNativeProcess>,
    pub(super) failed_authority: Option<crucible_node_provider::gem5::ArmRootExactAuthority>,
    pub(super) nodes: BTreeMap<Id, Box<dyn SimulationNode>>,
    pub(super) proofs: BTreeMap<Id, NativeRuntimeContinuationEvidence>,
    pub(super) owners: BTreeMap<Id, RestoredOwnerAttestation>,
    pub(super) coordinator: Option<ContentRef>,
    pub(super) quarantined: bool,
    pub(super) transferred: bool,
}

impl RootStaging {
    fn prepare_root(&mut self, capture: &VerifiedCapture, node: &Id) -> Result<(), StateError> {
        if self.imported.is_some()
            || self.native.is_some()
            || !self.nodes.contains_key(&id("clock")?)
        {
            return Err(refusal(
                "Root CPU restore requires original clock and unused native capsule",
            ));
        }
        let saved = self.archive.runtime_snapshot()?;
        let owner = self
            .graph
            .binding(node)
            .ok_or_else(|| refusal("Root CPU binding absent"))?
            .compatibility
            .capture_owner
            .id
            .clone();
        let source = self
            .archive
            .authenticated_source(&owner, &saved, capture.content())?;
        let target_owner = self
            .target
            .owners
            .iter()
            .find(|owner| owner.owner.as_str() == "owner/root")
            .ok_or_else(|| refusal("Root target CPU absent"))?;
        let artifacts = self
            .queue
            .reserved_artifacts(&self.target, target_owner, &self.archive)
            .map_err(state_error)?;
        self.imported = Some(MaterializedRootArchive::prepare(
            &self.graph,
            &source,
            node,
            self.profile.clone(),
            artifacts,
            &self.namespace.join("historical"),
        )?);
        let materialized = self
            .imported
            .as_ref()
            .ok_or_else(|| refusal("Root owned historical image absent"))?;
        if materialized.root != self.namespace.join("historical")
            || materialized.artifacts.len() != source.owner().artifacts.len()
        {
            return Err(refusal("Root owned historical artifact scope differs"));
        }
        let target_owner = self
            .target
            .owners
            .iter()
            .find(|owner| owner.owner.as_str() == "owner/root")
            .ok_or_else(|| refusal("Root target CPU absent"))?;
        let target = ArmRootRestoreTarget {
            incarnation: target_owner.incarnation.clone(),
            generation: target_owner.generation,
            resource_root: self.namespace.join("native"),
            image_root: self.namespace.join("images"),
            temporary_root: self.namespace.join("temporary"),
            timeout: Duration::from_secs(60),
        };
        let slot = self
            .slot
            .take()
            .ok_or_else(|| refusal("Root pre-reserved native slot already consumed"))?;
        let image = &self
            .imported
            .as_ref()
            .ok_or_else(|| refusal("Root historical image absent"))?
            .image;
        // Retain the genuine fresh peer in this capsule before any capture,
        // auditor, qualifier or common-node promotion can fail or unwind.
        self.native =
            Some(ArmRootNativeProcess::restore(image, target, slot).map_err(state_error)?);
        let native = self
            .native
            .as_mut()
            .ok_or_else(|| refusal("Root reconstructed native absent"))?;
        let image = native
            .capture(
                id("fresh/unchanged-cut")?,
                &self.namespace.join("initial-image"),
            )
            .map_err(state_error)?;
        let certificate = native
            .qualify_capture(&image, &self.namespace)
            .map_err(state_error)?;
        let authority = native
            .qualify_exact(&image, &certificate)
            .map_err(state_error)?;
        let continuation = self
            .imported
            .as_ref()
            .and_then(|imported| imported.continuation.as_ref())
            .ok_or_else(|| refusal("Root authenticated original context is absent"))?;
        let qualification = RootPreparedQualification::new(
            &self.profile,
            &self.graph,
            native,
            &authority,
            Some(continuation),
        )
        .map_err(state_error)?;
        let native = self
            .native
            .take()
            .ok_or_else(|| refusal("Root fresh peer unavailable"))?;
        let preparation = match ArmRootNodePreparation::from_prepared(
            &self.graph,
            node,
            native,
            &qualification,
        ) {
            Ok(preparation) => preparation,
            Err(failure) => {
                self.failed_authority = Some(authority);
                let failure = *failure;
                self.native = Some(failure.native);
                return Err(refusal(failure.error.reason));
            }
        };
        let continuation = self
            .imported
            .as_mut()
            .and_then(|imported| imported.continuation.take())
            .ok_or_else(|| refusal("Root original continuation already attached"))?;
        let actual = match preparation.into_qualified_restored_node(
            &self.graph,
            authority,
            ArmRootNodeResources::default(),
            ArmRootArchiveInstallation {
                owned_scope: self.namespace.clone(),
                captures_root: self.namespace.join("captures"),
                maximum_captures: 8,
            },
            continuation,
        ) {
            Ok(actual) => actual,
            Err(failure) => {
                let failure = *failure;
                self.failed_authority = Some(failure.authority);
                self.native = Some(failure.preparation.into_native());
                if let Some(imported) = self.imported.as_mut() {
                    imported.continuation = failure.restored;
                }
                return Err(refusal(failure.error.reason));
            }
        };
        let proof = match actual.restored_continuation_evidence(&saved, &self.target) {
            Ok(proof) => proof,
            Err(failure) => {
                self.nodes.insert(node.clone(), Box::new(actual));
                return Err(refusal(failure.reason));
            }
        };
        self.proofs.insert(node.clone(), proof);
        self.nodes.insert(node.clone(), Box::new(actual));
        Ok(())
    }

    fn receipt(&self, value: &impl serde::Serialize) -> Result<ContentRef, StateError> {
        let bytes = super::evidence::metadata_bytes(value).map_err(state_error)?;
        canonical::content_ref(&bytes, "application/json").map_err(state_error)
    }
}

impl NativeRuntimeContinuationVerifier for RootStaging {
    fn verify_runtime_continuation(
        &mut self,
        snapshot: &RuntimeSnapshot,
        scheduling: &SchedulingSnapshot,
        target: &ActivationRecord,
    ) -> Result<NativeRuntimeContinuationEvidence, RuntimeError> {
        if self.quarantined
            || target != &self.target
            || self.proofs.len() != 2
            || self.coordinator.is_none()
            || self
                .archive
                .runtime_snapshot()
                .map_err(|error| RuntimeError::SchedulerRefused(error.to_string()))?
                != *snapshot
            || self
                .archive
                .scheduling_snapshot()
                .map_err(|error| RuntimeError::SchedulerRefused(error.to_string()))?
                != *scheduling
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let mut acknowledgements = self
            .proofs
            .values()
            .flat_map(|proof| proof.input_acknowledgements.iter().cloned())
            .collect::<Vec<_>>();
        acknowledgements.sort_by(|left, right| left.stage_operation.cmp(&right.stage_operation));
        let references = self
            .proofs
            .values()
            .map(|proof| &proof.proof)
            .collect::<Vec<_>>();
        let proof = self
            .receipt(&FreshContinuationBody {
                schema: "crucible/arm-root-fresh-continuation/1",
                source: self.archive.artifact(),
                target: crucible::node_contract::SavedRuntimeActivation::from(target),
                native_proofs: &references,
            })
            .map_err(|error| RuntimeError::SchedulerRefused(error.to_string()))?;
        Ok(NativeRuntimeContinuationEvidence {
            proof,
            input_acknowledgements: acknowledgements,
        })
    }
}

impl NativeRestoreStaging for RootStaging {
    fn reservations(&self) -> RestoreReservations {
        self.reservations
    }

    fn original_disposition(&self) -> OriginalWorldDisposition {
        OriginalWorldDisposition::Unknown
    }

    fn prepare_owner(
        &mut self,
        capture: &VerifiedCapture,
        owner: &CapturedOwner,
        target: &ActivationRecord,
    ) -> Result<RestoredOwnerAttestation, StateError> {
        if self.quarantined
            || target != &self.target
            || capture.artifact() != self.archive.artifact()
            || self.owners.contains_key(&owner.capture_owner_id)
            || owner.participant_ids.len() != 1
        {
            return Err(refusal("Root original owner, source or target differs"));
        }
        let node = &owner.participant_ids[0];
        if node.as_str() == "clock" {
            let saved = self.archive.runtime_snapshot()?;
            let source = self.archive.authenticated_source(
                &owner.capture_owner_id,
                &saved,
                capture.content(),
            )?;
            let mut actual = crucible::node_adapters::HostModelNode::new(
                &self.graph,
                node,
                crucible::node_adapters::HostModel::Clock(
                    crucible_device::clock::VirtualClock::new(),
                ),
                self.evidence.as_ref(),
                crucible::node_adapters::HostModelResources::default(),
            )
            .map_err(|error| refusal(error.reason))?;
            let proof = actual
                .prepare_public_clock_continuation(
                    &self.graph,
                    &source,
                    &self.target,
                    self.evidence.as_ref(),
                )
                .map_err(|error| refusal(error.reason))?;
            self.nodes.insert(node.clone(), Box::new(actual));
            self.proofs.insert(node.clone(), proof);
        } else if node.as_str() == "root" {
            self.prepare_root(capture, node)?;
        } else {
            return Err(refusal("Root capsule refuses an uninstalled native owner"));
        }
        let actual = self
            .nodes
            .get_mut(node)
            .ok_or_else(|| refusal("Root prepared owner absent"))?;
        let ready = actual.arm(target).map_err(|error| refusal(error.reason))?;
        actual
            .validate_readiness(target, &ready)
            .map_err(|error| refusal(error.reason))?;
        let identity = ready
            .owners
            .iter()
            .find(|identity| identity.owner == owner.capture_owner_id)
            .cloned()
            .ok_or_else(|| refusal("Root actual ready identity absent"))?;
        let attestation = RestoredOwnerAttestation {
            identity,
            state_domain_ids: owner.state_domain_ids.clone(),
            binding_hashes: owner.binding_hashes.clone(),
            cut: capture.manifest().cut,
            event_ordinal: capture.manifest().event_ordinal,
            state_inventory: ready.state_inventory,
            ready_receipt: ready.ready_receipt,
        };
        self.owners
            .insert(owner.capture_owner_id.clone(), attestation.clone());
        Ok(attestation)
    }

    fn verify_prepared_owner(
        &self,
        capture: &VerifiedCapture,
        target: &ActivationRecord,
        attestation: &RestoredOwnerAttestation,
    ) -> Result<(), StateError> {
        if self.quarantined
            || target != &self.target
            || self
                .owners
                .get(&attestation.identity.owner)
                .is_none_or(|original| {
                    original.identity != attestation.identity
                        || original.state_domain_ids != attestation.state_domain_ids
                        || original.binding_hashes != attestation.binding_hashes
                        || original.cut != attestation.cut
                        || original.event_ordinal != attestation.event_ordinal
                        || original.state_inventory != attestation.state_inventory
                        || original.ready_receipt != attestation.ready_receipt
                })
        {
            return Err(refusal("Root actual prepared receipt differs"));
        }
        let owner = capture
            .manifest()
            .owners
            .iter()
            .find(|owner| owner.capture_owner_id == attestation.identity.owner)
            .ok_or_else(|| refusal("Root captured owner absent"))?;
        let node = owner
            .participant_ids
            .first()
            .and_then(|node| self.nodes.get(node))
            .ok_or_else(|| refusal("Root actual prepared native absent"))?;
        node.validate_readiness(
            target,
            &ReadyAttestation {
                owners: vec![attestation.identity.clone()],
                boundary: attestation.cut,
                state_inventory: attestation.state_inventory.clone(),
                ready_receipt: attestation.ready_receipt.clone(),
            },
        )
        .map_err(|failure| refusal(failure.reason))
    }

    fn prepare_coordinator(
        &mut self,
        capture: &VerifiedCapture,
        target: &ActivationRecord,
    ) -> Result<ContentRef, StateError> {
        if self.quarantined
            || target != &self.target
            || self.owners.len() != 2
            || capture.manifest().owners.len() != 2
        {
            return Err(refusal("Root whole owner barrier is incomplete"));
        }
        let receipt = self.receipt(&CoordinatorReadyBody {
            schema: "crucible/arm-root-coordinator-ready/1",
            source: self.archive.artifact(),
            original_coordinator: &capture.manifest().coordinator_state_ref,
            target: crucible::node_contract::SavedRuntimeActivation::from(target),
        })?;
        self.coordinator = Some(receipt.clone());
        Ok(receipt)
    }

    fn verify_prepared_world(
        &self,
        capture: &VerifiedCapture,
        target: &ActivationRecord,
        owners: &[RestoredOwnerAttestation],
        receipt: &ContentRef,
    ) -> Result<(), StateError> {
        if owners.len() != 2 || self.owners.len() != 2 || self.coordinator.as_ref() != Some(receipt)
        {
            return Err(refusal("Root whole world ready barrier differs"));
        }
        for owner in owners {
            self.verify_prepared_owner(capture, target, owner)?;
        }
        Ok(())
    }

    fn take_nodes(&mut self) -> Result<Vec<Box<dyn SimulationNode>>, StateError> {
        if self.quarantined
            || self.transferred
            || self.coordinator.is_none()
            || self.nodes.len() != 2
        {
            return Err(refusal(
                "Root native custody is unavailable or already transferred",
            ));
        }
        self.transferred = true;
        Ok(std::mem::take(&mut self.nodes).into_values().collect())
    }

    fn contain_uncertain_publication(
        &mut self,
        target: &ActivationRecord,
    ) -> Result<(), StateError> {
        if target != &self.target {
            return Err(refusal("Root containment generation differs"));
        }
        self.queue
            .record_publication(target, PublicationKnowledge::Unknown)
            .map_err(state_error)?;
        for (node, actual) in &self.nodes {
            let binding = self
                .graph
                .binding(node)
                .ok_or_else(|| refusal("Root containment binding absent"))?;
            let owner = self
                .owners
                .get(&binding.compatibility.capture_owner.id)
                .ok_or_else(|| refusal("Root containment owner absent"))?;
            actual
                .validate_readiness(
                    target,
                    &ReadyAttestation {
                        owners: vec![owner.identity.clone()],
                        boundary: owner.cut,
                        state_inventory: owner.state_inventory.clone(),
                        ready_receipt: owner.ready_receipt.clone(),
                    },
                )
                .map_err(|failure| refusal(failure.reason))?;
        }
        Ok(())
    }

    fn quarantine_resources(
        &mut self,
        target: &ActivationRecord,
        publication: PublicationKnowledge,
    ) {
        self.quarantined = true;
        // A foreign caller record cannot rebase or discharge the owned native
        // world. Cleanup always follows the original reservation; uncertainty
        // is retained until that original publication can be reconciled.
        let original_publication = if target == &self.target {
            publication
        } else {
            PublicationKnowledge::Unknown
        };
        let _ = self
            .queue
            .record_publication(&self.target, original_publication);
        for node in self.nodes.values_mut() {
            node.quarantine_resources();
        }
        // Drop transfers the raw native capsule into the pre-reserved global
        // supervisor; source image/ledger/backing remain held by this capsule.
        self.native.take();
    }

    fn poll_reclamation(&mut self, context: &mut Context<'_>) -> Poll<Result<(), StateError>> {
        if self.transferred && self.nodes.is_empty() && self.native.is_none() {
            return Poll::Ready(Ok(()));
        }
        let mut pending = false;
        for (node, actual) in &mut self.nodes {
            let Some(owner) = self.target.owners.iter().find(|owner| {
                self.graph
                    .binding(node)
                    .is_some_and(|binding| binding.compatibility.execution_owner.id == owner.owner)
            }) else {
                return Poll::Ready(Err(refusal("Root reclamation owner absent")));
            };
            match actual.poll_reclamation(owner, context) {
                Poll::Pending => pending = true,
                Poll::Ready(Err(failure)) => return Poll::Ready(Err(refusal(failure.reason))),
                Poll::Ready(Ok(receipt)) => {
                    if let Err(failure) = actual.validate_reclamation(&receipt) {
                        return Poll::Ready(Err(refusal(failure.reason)));
                    }
                }
            }
        }
        if pending {
            return Poll::Pending;
        }
        self.nodes.clear();
        if self.slot.is_some() {
            self.slot.take();
            return Poll::Ready(Ok(()));
        }
        match self.queue.original_group_reclaimed(&self.target) {
            Ok(true) => Poll::Ready(Ok(())),
            Ok(false) => Poll::Pending,
            Err(error) => Poll::Ready(Err(state_error(error))),
        }
    }
}

fn id(value: &str) -> Result<Id, StateError> {
    Id::new(value).map_err(state_error)
}
fn refusal(reason: impl Into<String>) -> StateError {
    StateError::new(
        StateErrorCode::NativeEvidence,
        "installed Root native staging",
        reason,
    )
}
fn state_error(error: impl std::fmt::Display) -> StateError {
    refusal(error.to_string())
}

#[derive(serde::Serialize)]
struct FreshContinuationBody<'a> {
    schema: &'static str,
    source: &'a ContentRef,
    target: crucible::node_contract::SavedRuntimeActivation,
    native_proofs: &'a [&'a ContentRef],
}

#[derive(serde::Serialize)]
struct CoordinatorReadyBody<'a> {
    schema: &'static str,
    source: &'a ContentRef,
    original_coordinator: &'a ContentRef,
    target: crucible::node_contract::SavedRuntimeActivation,
}
