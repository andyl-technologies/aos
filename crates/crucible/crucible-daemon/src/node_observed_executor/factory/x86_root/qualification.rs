//! Enrolls actual current X86Root preparation beneath the fixed installed world.
//!
//! Construction borrows a genuine opaque authority and Original or Restored
//! session. The retained portable commitment is correlation data only; common
//! conversion still checks the actual peer and its own current authority.

use std::collections::BTreeMap;

use crucible_engine::{
    node_adapters::x86_root::{AuthenticatedX86RootContinuation, X86RootPreparationQualification},
    node_admission::AdmittedGraph,
    node_contract::{EffectKnowledge, OperationFailure},
};
use crucible_node_format::{ContentRef, HashRef, Id, NodeBinding, NodeDescriptor, canonical};
use crucible_node_transport::gem5::{Gem5Boundary, X86RootExactAuthority, X86RootNativeProcess};
use serde::{Deserialize, Serialize};

use super::super::{NodeObservedError, refused};
use super::profile::X86RootWorldProfile;

pub(super) struct X86RootPreparedQualification {
    world: HashRef,
    descriptor: NodeDescriptor,
    binding: NodeBinding,
    peer: X86RootPeer,
}

#[derive(Serialize)]
pub(super) struct X86RootPeer {
    owner: Id,
    incarnation: Id,
    generation: crucible_node_format::U64,
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

impl X86RootPeer {
    pub(super) fn measure(
        profile: &X86RootWorldProfile,
        native: &X86RootNativeProcess,
        authority: &X86RootExactAuthority,
        source: Option<&AuthenticatedX86RootContinuation>,
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
                "X86Root qualified peer differs from its complete installed model and asset selection",
            ));
        }
        let value = canonical::parse_json(session.transcript().1, 4 * 1024 * 1024)?;
        let kernel: KernelPeer = serde_json::from_value(value)?;
        let history = native.control_history().map_err(error)?;
        if history.packets.len() > 4096 {
            return Err(refused(
                "X86Root preparation control inventory exceeds fixed credit",
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
                "X86Root current kernel identity exceeds finite read credit",
            ));
        }
        let text = std::str::from_utf8(&bytes).map_err(error)?;
        let end = text
            .rfind(')')
            .ok_or_else(|| refused("X86Root original kernel identity has no command boundary"))?;
        let columns = text
            .get(end + 2..)
            .ok_or_else(|| refused("X86Root original kernel identity is incomplete"))?
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
                "X86Root actual native peer no longer owns its original kernel group identity",
            ));
        }
        Ok(())
    }

    pub(super) fn verify_current(
        &self,
        native: &X86RootNativeProcess,
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
                "X86Root current preparation differs from its actual enrolled native/control scope",
            ));
        }
        for (packet, reference) in history.packets.iter().zip(&self.packets) {
            reference.verify(&packet.bytes)?;
        }
        Ok(())
    }
}

impl X86RootPreparedQualification {
    pub(super) fn new(
        profile: &X86RootWorldProfile,
        graph: &AdmittedGraph,
        native: &X86RootNativeProcess,
        authority: &X86RootExactAuthority,
        source: Option<&AuthenticatedX86RootContinuation>,
    ) -> Result<Self, NodeObservedError> {
        let node = Id::new("root")?;
        let descriptor = graph
            .descriptor(&node)
            .ok_or_else(|| refused("X86Root admitted descriptor is absent"))?;
        let binding = graph
            .binding(&node)
            .ok_or_else(|| refused("X86Root admitted binding is absent"))?;
        if graph.world_binding_hash() != &profile.scenario.world.identity()?
            || !profile.scenario.descriptors.contains(descriptor)
            || !profile
                .scenario
                .compatibility
                .contains(&binding.compatibility)
            || !graph.selected_extensions().is_empty()
        {
            return Err(refused(
                "X86Root preparation selects another installed complete world",
            ));
        }
        let peer = X86RootPeer::measure(profile, native, authority, source)?;
        if binding.compatibility.execution_owner.id != peer.owner
            || binding.authority.incarnation_id != peer.incarnation
            || binding.authority.owner_generation != peer.generation
        {
            return Err(refused(
                "X86Root actual current native owner differs from the locally prepared binding",
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

impl X86RootPreparationQualification for X86RootPreparedQualification {
    fn authenticate_preparation(
        &self,
        native: &X86RootNativeProcess,
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
                reason:
                    "X86Root actual preparation names another admitted world or original binding"
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
