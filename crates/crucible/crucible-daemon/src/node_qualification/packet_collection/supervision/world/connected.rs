//! Reserves three original native peer slots beneath a complete host-owned world.
//!
//! The fourth owner is the actual common scheduler source, not a fourth native
//! process. Portable roster validation supplies correlation only; same-source
//! graph admission, attached host Arm and the full barrier remain mandatory.

use super::{
    ActivationRecord, CnpSemanticProcessSlot, JournalSlot, NativeSlot, PacketPeerJournalSlot,
    PacketWorldHostSupervisor, PacketWorldOriginalReservations, QualificationError, RuntimeLimits,
    U64, WorldNativeSlot,
};
use crucible_engine::node_contract::{RuntimeCustodySupervisor, SavedRuntimeActivation};
use crucible_node_transport::reference_packet::coordinator::PacketConnectedCoordinatorInstallation;

impl PacketWorldHostSupervisor {
    /// Reserves the original three peers and one complete four-owner runtime once.
    ///
    /// No mailbox or world reservation is renewed after failure or reclamation.
    /// The host-owned source remains in that same complete runtime custody slot.
    ///
    /// # Errors
    /// Refuses a foreign/incomplete connected coordinator, changed complete
    /// activation, repeated reservation or exhausted original world capacity.
    pub fn reserve_connected_original(
        &self,
        activation: &ActivationRecord,
        coordinator: &PacketConnectedCoordinatorInstallation,
        limits: RuntimeLimits,
    ) -> Result<PacketWorldOriginalReservations, QualificationError> {
        self.authenticate_selected_origin()?;
        for participant in &coordinator.participants {
            coordinator
                .validate(participant)
                .map_err(|error| QualificationError::Evidence(error.to_string()))?;
        }
        let installed: SavedRuntimeActivation =
            serde_json::from_value(coordinator.template["activation"].clone())
                .map_err(|error| QualificationError::Evidence(error.to_string()))?;
        if activation.generation != installed.generation
            || activation.activation_id != installed.activation_id
            || activation.world_binding_hash != installed.world_binding_hash
            || activation.owners != installed.owners
            || activation.boundary != installed.boundary
            || activation.owners.len() != 4
            || limits.maximum_nodes != 4
            || limits.maximum_owners != 4
            || limits.maximum_operations == 0
            || limits.maximum_operations > 64
            || self.mailboxes.iter().any(|m| m.reserved.get())
        {
            return Err(QualificationError::Refused(
                "packet connected complete world supervision roster",
            ));
        }
        let native: [Box<dyn CnpSemanticProcessSlot>; 3] = std::array::from_fn(|member| {
            Box::new(WorldNativeSlot {
                original: NativeSlot {
                    process: std::process::id(),
                    thread: std::thread::current().id(),
                    mailbox: self.mailboxes[member].clone(),
                    transferred: false,
                },
                identity: U64::new((member as u64) + 1),
            }) as Box<dyn CnpSemanticProcessSlot>
        });
        let journal: [Box<dyn PacketPeerJournalSlot>; 3] = std::array::from_fn(|member| {
            Box::new(JournalSlot {
                mailbox: self.mailboxes[member].clone(),
                transferred: false,
            }) as Box<dyn PacketPeerJournalSlot>
        });
        let runtime = self
            .runtime
            .reserve_world(activation, limits)
            .map_err(|_| QualificationError::Refused("packet whole-world reservation"))?;
        for mailbox in &self.mailboxes {
            mailbox.reserved.set(true);
            mailbox.expected.set(true);
        }
        Ok(PacketWorldOriginalReservations {
            native,
            journal,
            runtime,
        })
    }
}
