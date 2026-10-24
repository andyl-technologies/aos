//! Retains three concrete complete sources under one original coordinator-five scope.
//!
//! The source role comes from its private retained model, never a parsed label.
//! Static scope and actual native currentness are distinct reads; neither this
//! roster nor copied installation metadata grants capture or restoration.

use std::rc::Rc;

use crucible_engine::node_adapters::cnp::{
    CnpSemanticInstallation, CnpSemanticSource, PacketCompleteSemanticSource,
    PacketCompleteSourceRole,
};
use crucible_engine::node_contract::OperationFailure;
use crucible_node_transport::reference_packet::coordinator::{
    PACKET_NATIVE5_COORDINATOR_INSTALLATION_BYTES, PacketNative5CoordinatorInstallation,
};

use super::{QualificationError, refused};

/// Retains the same producer, relay and sink sources in original world order.
#[derive(Clone)]
pub struct PacketCompleteRoster {
    pub(super) sources: [Rc<PacketCompleteSemanticSource>; 3],
    pub(super) coordinator: PacketNative5CoordinatorInstallation,
}

impl PacketCompleteRoster {
    /// Authenticates every concrete source's original complete declaration.
    ///
    /// # Errors
    /// Refuses a changed coordinator, reordered model roles, duplicate original
    /// source, foreign creator or exhausted coordinator credit before cloning.
    pub fn new(
        sources: [Rc<PacketCompleteSemanticSource>; 3],
        coordinator: &PacketNative5CoordinatorInstallation,
    ) -> Result<Self, QualificationError> {
        super::super::scope::encoded_size(
            coordinator,
            PACKET_NATIVE5_COORDINATOR_INSTALLATION_BYTES,
        )?;
        for (member, source) in sources.iter().enumerate() {
            source.authenticate_registration().map_err(external)?;
            source
                .authenticate_collecting_world_scope(coordinator)
                .map_err(external)?;
            let selected = source.installation();
            let original = &coordinator.participants[member].realization;
            if original.descriptors.as_slice() != std::slice::from_ref(&selected.descriptor)
                || original.bindings.as_slice() != std::slice::from_ref(&selected.binding)
                || original.owner_bindings.as_slice() != std::slice::from_ref(&selected.owner)
            {
                return Err(refused());
            }
        }
        if sources[0].role() != PacketCompleteSourceRole::Producer
            || sources[1].role() != PacketCompleteSourceRole::Reactive
            || sources[2].role() != PacketCompleteSourceRole::Reactive
            || (0..3).any(|index| {
                sources[..index]
                    .iter()
                    .any(|earlier| Rc::ptr_eq(earlier, &sources[index]))
            })
        {
            return Err(refused());
        }
        Ok(Self {
            sources,
            coordinator: coordinator.clone(),
        })
    }

    /// Borrows immutable original installation metadata for one native member.
    pub fn installation(&self, member: usize) -> Option<&CnpSemanticInstallation> {
        self.sources.get(member).map(|source| source.installation())
    }

    /// Compares the exact original source handles and complete installation.
    ///
    /// This reads immutable identity only and grants no currentness or admission.
    pub fn same_original(&self, other: &Self) -> bool {
        self.coordinator == other.coordinator
            && self
                .sources
                .iter()
                .zip(&other.sources)
                .all(|(left, right)| Rc::ptr_eq(left, right))
    }

    pub(super) fn current_scope(&self) -> Result<(), QualificationError> {
        for source in &self.sources {
            source
                .authenticate_collecting_world_scope(&self.coordinator)
                .map_err(external)?;
        }
        Ok(())
    }

    /// Checks actual current native custody of all three original participants.
    ///
    /// # Errors
    /// Refuses any absent, revoked, copied or foreign native realization.
    pub fn current_native(&self) -> Result<(), OperationFailure> {
        for source in &self.sources {
            source.authenticate_current_native()?;
        }
        Ok(())
    }
}

fn external(error: OperationFailure) -> QualificationError {
    QualificationError::Evidence(error.reason)
}

impl PacketCompleteRoster {
    pub(super) fn charge_retained_storage(
        &self,
        counter: &mut super::retained::Counter,
    ) -> Result<(), QualificationError> {
        let facts =
            crucible_node_transport::retained_metadata::observe_retained_native_coordinator(
                &self.coordinator,
            )
            .map_err(|_| refused())?;
        counter.metadata(&facts)
    }
}
