//! Retains the genuine source-installed native admission under collected witnesses.
//!
//! The constructor is private to the owning ordinary fixture. Hashes, runtime
//! result DTOs and provider tags cannot create this source qualification scope.

use std::rc::Rc;

use crucible_engine::{
    node_admission::{AdmissionEvidence, AdmittedGraph},
    node_contract::{ActivationRecord, NodeRoute, WorldActivation},
};
use crucible_node_format::{HashRef, Id};

use super::super::{
    host_group::evidence::IndependentGroupEvidence, installed::host_group::IndependentLiveWorld,
};
use crate::node_qualification::QualificationError;

/// Borrows the complete original script and base identities with their bodies.
type OriginalStorageSources<'a> = (
    &'a crucible_node_format::ContentRef,
    &'a [u8],
    &'a crucible_node_format::ContentRef,
    &'a [u8],
);

pub(super) struct Gem5CaseScope {
    graph: Rc<AdmittedGraph>,
    evidence: Rc<IndependentGroupEvidence>,
    profile: Rc<super::super::host_group::profile::IndependentGroupProfile>,
    target: ActivationRecord,
    activation: Option<WorldActivation>,
    script: crucible_node_format::ContentRef,
    base: crucible_node_format::ContentRef,
    storage: Id,
}

impl Gem5CaseScope {
    pub(super) fn from_prepared(
        original: &IndependentLiveWorld,
        selections: &[super::super::super::InstalledNodeSelection],
    ) -> Result<Self, QualificationError> {
        if original.graph.node_ids().count() != 4
            || original.graph.owners().count() != 4
            || original.graph.world_binding_hash() != &original.profile.scenario.world.identity()?
            || original.target.world_binding_hash != *original.graph.world_binding_hash()
        {
            return Err(QualificationError::Refused(
                "incomplete original gem5 prepared scope",
            ));
        }
        let selected =
            super::super::host_group::selection::IndependentGroupSelection::new(selections)
                .map_err(evidence)?;
        let super::super::super::InstalledNodeKind::HostScripted { profile: source } =
            &selected.source.kind
        else {
            return Err(QualificationError::Refused(
                "original storage source unavailable",
            ));
        };
        let super::super::super::InstalledNodeKind::HostIo {
            profile: super::super::super::InstalledHostIoProfile::Block { base_image, .. },
        } = &selected.block.kind
        else {
            return Err(QualificationError::Refused(
                "original Block source unavailable",
            ));
        };
        Ok(Self {
            graph: original.graph.clone(),
            evidence: original.evidence.clone(),
            profile: original.profile.clone(),
            target: original.target.clone(),
            activation: None,
            script: source.script.clone(),
            base: base_image.clone(),
            storage: selected.block.node.clone(),
        })
    }

    pub(super) fn mark_activated(
        &mut self,
        activation: &WorldActivation,
    ) -> Result<(), QualificationError> {
        if self.activation.is_some()
            || activation.record() != &self.target
            || activation
                .prepared_owners()
                .is_none_or(|owners| owners.len() != 4)
        {
            return Err(QualificationError::Refused(
                "original complete preparation was not activated",
            ));
        }
        self.activation = Some(activation.clone());
        self.authenticate_world_hash(&self.target.world_binding_hash)
    }

    pub(super) fn authenticate_activation(
        &self,
        activation: &WorldActivation,
    ) -> Result<(), QualificationError> {
        self.validate_activation(activation)?;
        self.authenticate_world_hash(&activation.record().world_binding_hash)
    }

    fn validate_activation(&self, activation: &WorldActivation) -> Result<(), QualificationError> {
        let original = self
            .activation
            .as_ref()
            .ok_or(QualificationError::Refused("original activation absent"))?;
        if !activation.same_authority(original) || activation.record() != &self.target {
            return Err(QualificationError::Refused(
                "case uses another opaque runtime activation",
            ));
        }
        Ok(())
    }

    /// Checks the complete immutable CPU tuple, then performs one fresh world
    /// admission and original native-owner read at this collection boundary.
    /// No file measurement or native authority is cached between boundaries.
    pub(super) fn authenticate_cpu_case(
        &self,
        activation: &WorldActivation,
        hash: &HashRef,
        route: &NodeRoute,
    ) -> Result<(), QualificationError> {
        authenticate_joint_scope(
            || {
                self.validate_activation(activation)?;
                self.validate_cpu_route(route)
            },
            || self.authenticate_world_hash(hash),
        )
    }

    pub(super) fn authenticate_world_hash(&self, hash: &HashRef) -> Result<(), QualificationError> {
        if hash != self.graph.world_binding_hash()
            || self
                .activation
                .as_ref()
                .is_none_or(|activation| activation.record() != &self.target)
        {
            return Err(QualificationError::Refused(
                "case does not belong to original activated world",
            ));
        }
        // Reauthentication calls the fixed installed native and Host policies;
        // this scope has no caller-selected evidence implementation.
        let current = self
            .profile
            .scenario
            .admit(
                self.evidence.bindings(),
                self.evidence.as_ref(),
                super::super::installed::admission_limits(),
            )
            .map_err(evidence)?;
        if current.world_binding_hash() != self.graph.world_binding_hash()
            || current.node_ids().any(|node| {
                current.binding(node) != self.graph.binding(node)
                    || current.descriptor(node) != self.graph.descriptor(node)
            })
        {
            return Err(QualificationError::Refused(
                "original source admission changed",
            ));
        }
        // The native owner check follows every complete graph predicate.
        let cpu = Id::new("cpu")?;
        let binding = self.graph.binding(&cpu).ok_or(QualificationError::Refused(
            "source CPU binding unavailable",
        ))?;
        self.evidence
            .authenticate_authority(binding)
            .map_err(evidence)
    }

    pub(super) fn original_storage_sources(
        &self,
    ) -> Result<OriginalStorageSources<'_>, QualificationError> {
        self.authenticate_world_hash(&self.target.world_binding_hash)?;
        let body =
            |reference: &crucible_node_format::ContentRef| -> Result<&[u8], QualificationError> {
                let object = self
                    .profile
                    .scenario
                    .content
                    .iter()
                    .find(|object| &object.reference == reference)
                    .ok_or(QualificationError::Refused("original storage body absent"))?;
                if object.bytes.len() > 4 * 1024 * 1024 {
                    return Err(QualificationError::Refused("original storage body credit"));
                }
                reference.verify(&object.bytes)?;
                Ok(&object.bytes)
            };
        Ok((
            &self.script,
            body(&self.script)?,
            &self.base,
            body(&self.base)?,
        ))
    }

    pub(super) fn authenticate_storage_route(
        &self,
        route: &NodeRoute,
    ) -> Result<(), QualificationError> {
        self.authenticate_world_hash(&self.target.world_binding_hash)?;
        let binding = self
            .graph
            .binding(&self.storage)
            .ok_or(QualificationError::Refused(
                "original storage binding absent",
            ))?;
        let descriptor = self
            .profile
            .scenario
            .descriptors
            .iter()
            .find(|descriptor| descriptor.id == self.storage)
            .ok_or(QualificationError::Refused(
                "original storage descriptor absent",
            ))?;
        let owner = self
            .target
            .owners
            .iter()
            .find(|owner| owner.owner == binding.compatibility.execution_owner.id)
            .ok_or(QualificationError::Refused("original storage owner absent"))?;
        if route.node != self.storage
            || route.owners.as_slice() != std::slice::from_ref(owner)
            || self.graph.descriptor(&self.storage) != Some(descriptor)
            || binding.compatibility.descriptor_hash != descriptor.identity()?
            || binding.authority.incarnation_id != owner.incarnation
            || binding.authority.owner_generation != owner.generation
        {
            return Err(QualificationError::Refused(
                "storage case changed original route",
            ));
        }
        self.evidence
            .authenticate_authority(binding)
            .map_err(evidence)
    }

    fn validate_cpu_route(&self, route: &NodeRoute) -> Result<(), QualificationError> {
        let cpu = Id::new("cpu")?;
        let source = self
            .profile
            .native
            .scenario
            .compatibility
            .iter()
            .find(|binding| binding.node_id == cpu)
            .ok_or(QualificationError::Refused(
                "original native CPU source unavailable",
            ))?;
        let binding = self.graph.binding(&cpu).ok_or(QualificationError::Refused(
            "original CPU binding unavailable",
        ))?;
        let descriptor = self
            .profile
            .native
            .scenario
            .descriptors
            .iter()
            .find(|descriptor| descriptor.id == cpu)
            .ok_or(QualificationError::Refused(
                "original native CPU descriptor unavailable",
            ))?;
        let owner = self
            .target
            .owners
            .iter()
            .find(|owner| owner.owner == source.execution_owner.id)
            .ok_or(QualificationError::Refused(
                "original CPU owner unavailable",
            ))?;
        if route.node != cpu
            || route.owners.as_slice() != std::slice::from_ref(owner)
            || &binding.compatibility != source
            || self.graph.descriptor(&cpu) != Some(descriptor)
            || binding.authority.incarnation_id != owner.incarnation
            || binding.authority.owner_generation != owner.generation
        {
            return Err(QualificationError::Refused(
                "case lost actual original CPU route/source tuple",
            ));
        }
        Ok(())
    }
}

// Immutable tuple checks do not run provider or file callbacks. The following
// full current read is the final authority conjunct, once per joint boundary.
fn authenticate_joint_scope(
    validate_original: impl FnOnce() -> Result<(), QualificationError>,
    authenticate_current: impl FnOnce() -> Result<(), QualificationError>,
) -> Result<(), QualificationError> {
    validate_original()?;
    authenticate_current()
}

#[cfg(test)]
#[path = "joint_scope_tests.rs"]
mod joint_scope_tests;

fn evidence(error: impl std::fmt::Display) -> QualificationError {
    QualificationError::Evidence(error.to_string())
}
