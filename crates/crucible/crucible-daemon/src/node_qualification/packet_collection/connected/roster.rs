//! Retains three concrete original sources without a vendor authentication hook.

use std::rc::Rc;

use crucible_engine::{
    node_adapters::cnp::{
        CnpSemanticInstallation, CnpSemanticSource, PacketConnectedSemanticSource,
        PacketSemanticSource,
    },
    node_contract::OperationFailure,
};
use crucible_node_transport::reference_packet::coordinator::{
    PACKET_CONNECTED_COORDINATOR_BYTES, PacketConnectedCoordinatorInstallation,
};

use super::{QualificationError, refused};

/// Retains an exact original producer or reactive native source.
///
/// This closed enum supplies no generic callback slot or interchangeable source
/// identity. Copies retain the same original Rc and native current-read witness.
#[derive(Clone)]
pub enum PacketConnectedParticipant {
    /// Retains the existing output-only native producer and its unchanged program.
    Producer(Rc<PacketSemanticSource>),
    /// Retains the connected relay or sink and its original input/output journals.
    Reactive(Rc<PacketConnectedSemanticSource>),
}

impl PacketConnectedParticipant {
    /// Borrows immutable metadata without issuing current native permission.
    pub fn installation(&self) -> &CnpSemanticInstallation {
        match self {
            Self::Producer(source) => source.installation(),
            Self::Reactive(source) => source.installation(),
        }
    }

    pub(super) fn same_original(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Producer(a), Self::Producer(b)) => Rc::ptr_eq(a, b),
            (Self::Reactive(a), Self::Reactive(b)) => Rc::ptr_eq(a, b),
            _ => false,
        }
    }

    pub(super) fn current_native(&self) -> Result<(), OperationFailure> {
        match self {
            Self::Producer(source) => source.authenticate_current_native(),
            Self::Reactive(source) => source.authenticate_current_native(),
        }
    }

    fn collecting_scope(
        &self,
        coordinator: &PacketConnectedCoordinatorInstallation,
    ) -> Result<(), OperationFailure> {
        match self {
            Self::Producer(source) => {
                source.authenticate_collecting_connected_world_scope(coordinator)
            }
            Self::Reactive(source) => source.authenticate_collecting_world_scope(coordinator),
        }
    }
}

/// Retains the complete producer/relay/sink source roster in original world order.
#[derive(Clone)]
pub struct PacketConnectedRoster {
    pub(super) sources: [PacketConnectedParticipant; 3],
    pub(super) coordinator: PacketConnectedCoordinatorInstallation,
}

impl PacketConnectedRoster {
    /// Checks the exact concrete full-world source scope before any peer launch.
    ///
    /// Native realization/current custody remains a later independent check.
    /// Portable installation records cannot create a source or Ready authority.
    ///
    /// # Errors
    /// Refuses a reordered, copied, incomplete or foreign original source roster,
    /// changed coordinator or unsupported producer/relay/sink source roles.
    pub fn new(
        sources: [PacketConnectedParticipant; 3],
        coordinator: &PacketConnectedCoordinatorInstallation,
    ) -> Result<Self, QualificationError> {
        super::super::scope::encoded_size(coordinator, PACKET_CONNECTED_COORDINATOR_BYTES)?;
        if !matches!(sources[0], PacketConnectedParticipant::Producer(_))
            || !matches!(sources[1], PacketConnectedParticipant::Reactive(_))
            || !matches!(sources[2], PacketConnectedParticipant::Reactive(_))
        {
            return Err(refused());
        }
        for source in &sources {
            source
                .collecting_scope(coordinator)
                .map_err(|error| QualificationError::Evidence(error.reason))?;
        }
        if sources[1].same_original(&sources[2]) {
            return Err(refused());
        }
        Ok(Self {
            sources,
            coordinator: coordinator.clone(),
        })
    }

    pub(super) fn same_original(&self, other: &Self) -> bool {
        self.coordinator == other.coordinator
            && self
                .sources
                .iter()
                .zip(&other.sources)
                .all(|(a, b)| a.same_original(b))
    }

    pub(super) fn current_scope(&self) -> Result<(), QualificationError> {
        for source in &self.sources {
            source
                .collecting_scope(&self.coordinator)
                .map_err(|error| QualificationError::Evidence(error.reason))?;
        }
        Ok(())
    }

    /// Checks current native custody of every original participant directly.
    ///
    /// This terminal read dispatches only the concrete source-owned methods; no
    /// arbitrary vendor callback can run after it and supply stale permission.
    ///
    /// # Errors
    /// Refuses any absent, revoked, copied or no-longer-owned native realization.
    pub fn current_native(&self) -> Result<(), OperationFailure> {
        for source in &self.sources {
            source.current_native()?;
        }
        Ok(())
    }
}
