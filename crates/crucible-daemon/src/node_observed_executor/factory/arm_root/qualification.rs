//! Enrolls actual current Root preparation beneath the fixed installed world.
//!
//! Construction borrows a genuine opaque authority and Original or Restored
//! session. The retained portable commitment is correlation data only; common
//! conversion still checks the actual peer and its own current authority.

use std::collections::BTreeMap;

use crucible::{
    node_adapters::arm_root::{ArmRootPreparationQualification, AuthenticatedArmRootContinuation},
    node_admission::AdmittedGraph,
    node_contract::{EffectKnowledge, OperationFailure},
};
use crucible_node_contract::{ContentRef, HashRef, Id, NodeBinding, NodeDescriptor, canonical};
use crucible_node_provider::gem5::{ArmRootExactAuthority, ArmRootNativeProcess, Gem5Boundary};
use serde::{Deserialize, Serialize};

use super::super::{NodeObservedError, refused};
use super::profile::RootWorldProfile;

pub(super) struct RootPreparedQualification {
    world: HashRef,
    descriptor: NodeDescriptor,
    binding: NodeBinding,
    peer: RootPeer,
}

#[derive(Serialize)]
pub(super) struct RootPeer {
    owner: Id,
    incarnation: Id,
    generation: crucible_node_contract::U64,
    profile: ContentRef,
    bindings: BTreeMap<String, ContentRef>,
    boundary: Gem5Boundary,
    packet: ContentRef,
    session: ContentRef,
    token: Id,
    source_capture: Option<Id>,
    kernel: KernelPeer,
    packets: Vec<ContentRef>,
    closure: ContentRef,
    outcomes: usize,
}

impl RootPeer {
    pub(super) fn measure(
        profile: &RootWorldProfile,
        native: &ArmRootNativeProcess,
        authority: &ArmRootExactAuthority,
        source: Option<&AuthenticatedArmRootContinuation>,
    ) -> Result<Self, NodeObservedError> {
        let session = match source {
            Some(source) => native.restored_prepared_session(authority, source.capture()),
            None => native.initial_prepared_session(authority),
        }
        .map_err(error)?;
        native.next_publication_bound(authority).map_err(error)?;
        let launch = native.launch().map_err(error)?;
        if launch.profile() != &profile.installed
            || !launch.bindings().eq(profile
                .bindings
                .iter()
                .map(|(role, content)| (role.as_str(), content)))
        {
            return Err(refused(
                "Root qualified peer differs from its complete installed model and asset selection",
            ));
        }
        let value = canonical::parse_json(session.transcript().1, 4 * 1024 * 1024)?;
        let kernel: KernelPeer = serde_json::from_value(value)?;
        let history = native.control_history().map_err(error)?;
        if history.packets.len() > 4096 {
            return Err(refused(
                "Root preparation control inventory exceeds fixed credit",
            ));
        }
        let mut packets = Vec::new();
        packets
            .try_reserve_exact(history.packets.len())
            .map_err(error)?;
        for packet in &history.packets {
            packets.push(canonical::content_ref(&packet.bytes, "application/json")?);
        }
        let result = Self {
            owner: launch.owner().clone(),
            incarnation: launch.incarnation().clone(),
            generation: launch.generation(),
            profile: launch.profile().clone(),
            bindings: profile.bindings.clone(),
            boundary: native.boundary().clone(),
            packet: session.packet().0.clone(),
            session: session.transcript().0.clone(),
            token: session.token().clone(),
            source_capture: session.source_capture().cloned(),
            kernel,
            packets,
            closure: authority.evidence().0.clone(),
            outcomes: native.outcomes().len(),
        };
        result.verify_kernel()?;
        Ok(result)
    }

    pub(super) fn verify_kernel(&self) -> Result<(), NodeObservedError> {
        let path = format!("/proc/{}/stat", self.kernel.pid);
        let file = std::fs::File::open(path).map_err(error)?;
        use std::io::Read;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(65_537).map_err(error)?;
        file.take(65_537).read_to_end(&mut bytes).map_err(error)?;
        if bytes.len() > 65_536 {
            return Err(refused(
                "Root current kernel identity exceeds finite read credit",
            ));
        }
        let text = std::str::from_utf8(&bytes).map_err(error)?;
        let end = text
            .rfind(')')
            .ok_or_else(|| refused("Root original kernel identity has no command boundary"))?;
        let columns = text
            .get(end + 2..)
            .ok_or_else(|| refused("Root original kernel identity is incomplete"))?
            .split_whitespace()
            .collect::<Vec<_>>();
        if self.kernel.pid == 0
            || columns.len() < 20
            || columns[0] == "Z"
            || columns[0] == "X"
            || columns[2] != self.kernel.pid.to_string()
            || columns[19] != self.kernel.start_ticks
        {
            return Err(refused(
                "Root actual native peer no longer owns its original kernel group identity",
            ));
        }
        Ok(())
    }

    pub(super) fn verify_current(
        &self,
        native: &ArmRootNativeProcess,
    ) -> Result<(), NodeObservedError> {
        self.verify_kernel()?;
        let launch = native.launch().map_err(error)?;
        let history = native.control_history().map_err(error)?;
        if launch.owner() != &self.owner
            || launch.incarnation() != &self.incarnation
            || launch.generation() != self.generation
            || launch.profile() != &self.profile
            || native.boundary() != &self.boundary
            || !launch.bindings().eq(self
                .bindings
                .iter()
                .map(|(role, content)| (role.as_str(), content)))
            || native.outcomes().len() != self.outcomes
            || history.packets.len() != self.packets.len()
            || !history.sessions.iter().any(|session| {
                session.token == self.token
                    && session.packet == self.packet
                    && session.transcript == self.session
            })
        {
            return Err(refused(
                "Root current preparation differs from its actual enrolled native/control scope",
            ));
        }
        for (packet, reference) in history.packets.iter().zip(&self.packets) {
            reference.verify(&packet.bytes)?;
        }
        Ok(())
    }
}

impl RootPreparedQualification {
    pub(super) fn new(
        profile: &RootWorldProfile,
        graph: &AdmittedGraph,
        native: &ArmRootNativeProcess,
        authority: &ArmRootExactAuthority,
        source: Option<&AuthenticatedArmRootContinuation>,
    ) -> Result<Self, NodeObservedError> {
        let node = Id::new("root")?;
        let descriptor = graph
            .descriptor(&node)
            .ok_or_else(|| refused("Root admitted descriptor is absent"))?;
        let binding = graph
            .binding(&node)
            .ok_or_else(|| refused("Root admitted binding is absent"))?;
        if graph.world_binding_hash() != &profile.scenario.world.identity()?
            || !profile.scenario.descriptors.contains(descriptor)
            || !profile
                .scenario
                .compatibility
                .contains(&binding.compatibility)
            || !graph.selected_extensions().is_empty()
        {
            return Err(refused(
                "Root preparation selects another installed complete world",
            ));
        }
        let peer = RootPeer::measure(profile, native, authority, source)?;
        if binding.compatibility.execution_owner.id != peer.owner
            || binding.authority.incarnation_id != peer.incarnation
            || binding.authority.owner_generation != peer.generation
        {
            return Err(refused(
                "Root actual current native owner differs from the locally prepared binding",
            ));
        }
        Ok(Self {
            world: graph.world_binding_hash().clone(),
            descriptor: descriptor.clone(),
            binding: binding.clone(),
            peer,
        })
    }
}

impl ArmRootPreparationQualification for RootPreparedQualification {
    fn authenticate_preparation(
        &self,
        native: &ArmRootNativeProcess,
        graph: &AdmittedGraph,
        node: &Id,
    ) -> Result<(), OperationFailure> {
        if node.as_str() != "root"
            || graph.world_binding_hash() != &self.world
            || graph.descriptor(node) != Some(&self.descriptor)
            || graph.binding(node) != Some(&self.binding)
        {
            return Err(OperationFailure {
                effects: EffectKnowledge::None,
                reason: "Root actual preparation names another admitted world or original binding"
                    .into(),
            });
        }
        self.peer
            .verify_current(native)
            .map_err(|error| OperationFailure {
                effects: EffectKnowledge::None,
                reason: error.to_string(),
            })
    }
}

// This DTO borrows no authority from its labels. It is read only from the
// transcript supplied by an already authenticated native PreparedSession.
#[derive(Deserialize, Serialize)]
struct KernelPeer {
    pid: u32,
    start_ticks: String,
}

fn error(error: impl std::fmt::Display) -> NodeObservedError {
    refused(&error.to_string())
}
