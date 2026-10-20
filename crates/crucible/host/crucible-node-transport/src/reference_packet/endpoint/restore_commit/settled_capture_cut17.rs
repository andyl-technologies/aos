//! Refuses active restoration host custody before a settled Capture cut.
//!
//! A successful Commit leaves this capsule allocated. Its transport and proof
//! owners have already moved to the installed connection and immutable journal;
//! the actual released-World witness proves completion independently of slots.

use super::*;
use crate::reference_packet::service::ack_emitter::{
    OriginalRestorationReleaseState, OriginalRestorationReleased,
};

/// Describes only independently retained host owners, never modeled work.
#[derive(Clone, Copy)]
struct FlightSlots17 {
    mapping: bool,
    admission: bool,
    held: bool,
    proof: bool,
    recovered_connection: bool,
    completed: bool,
    proof_allocation: bool,
}
impl FlightSlots17 {
    fn require_completed_owners_data(self) -> Result<(), ProviderError> {
        if !self.mapping
            || !self.held
            || !self.proof_allocation
            || self.admission
            || self.proof
            || self.recovered_connection
            || self.completed
        {
            return Err(refused());
        }
        Ok(())
    }
}

impl<S: ProviderStream> RestoreCommitFlight<S> {
    /// Checks completed host owners independently of native release authority.
    ///
    /// The distinct signed Observe17 lender proves the actual released World,
    /// first observation and latest native checkpoint separately. This pure
    /// subset avoids invoking a legacy canonical verifier before action debit.
    ///
    /// # Errors
    /// Refuses missing/active host fields or another genuine Boot/mapping/hold.
    pub(in crate::reference_packet::endpoint) fn authenticate_observation17_host_owners_data(
        &self,
        boot: &Rc<RefCell<NativeAckBoot>>,
        connection: &Connection<S>,
    ) -> Result<(), ProviderError> {
        FlightSlots17 {
            mapping: self.mapping.is_some(),
            admission: self.admission.is_some(),
            held: self.held.is_some(),
            proof: self.proof.is_some(),
            recovered_connection: self.recovered_connection.is_some(),
            completed: self.completed.is_some(),
            proof_allocation: self.proof_allocation.is_some(),
        }
        .require_completed_owners_data()?;
        let mapping = self.mapping.as_ref().ok_or_else(refused)?;
        self.held
            .as_ref()
            .ok_or_else(refused)?
            .authenticate_settled17_roots_data(boot, mapping)?;
        connection.authenticate_installed_complete_restoration(mapping)
    }

    /// Authenticates a retained completed capsule against the actual released world.
    ///
    /// # Errors
    /// Refuses partial/active host owners, foreign roots, a pending release, or any
    /// actual Control, sent-prefix, acknowledgement, mapping or physical-hold change.
    pub(in crate::reference_packet::endpoint) fn authenticate_completed_settled_capture_cut17_data(
        &self,
        boot: &Rc<RefCell<NativeAckBoot>>,
        connection: &Connection<S>,
        control: &PacketControl,
        records: &[ExchangeRecord],
    ) -> Result<OriginalRestorationReleased, ProviderError> {
        FlightSlots17 {
            mapping: self.mapping.is_some(),
            admission: self.admission.is_some(),
            held: self.held.is_some(),
            proof: self.proof.is_some(),
            recovered_connection: self.recovered_connection.is_some(),
            completed: self.completed.is_some(),
            proof_allocation: self.proof_allocation.is_some(),
        }
        .require_completed_owners_data()?;
        let mapping = self.mapping.as_ref().ok_or_else(refused)?;
        self.held
            .as_ref()
            .ok_or_else(refused)?
            .authenticate_settled17_roots_data(boot, mapping)?;
        connection.authenticate_installed_complete_restoration(mapping)?;
        match NativeAckBoot::original_restoration_release_data(boot, connection, control, records)?
        {
            OriginalRestorationReleaseState::Released(released) => Ok(released),
            OriginalRestorationReleaseState::Pending => Err(refused()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn completed_slots() -> FlightSlots17 {
        FlightSlots17 {
            mapping: true,
            admission: false,
            held: true,
            proof: false,
            recovered_connection: false,
            completed: false,
            proof_allocation: true,
        }
    }

    #[test]
    fn retained_some_completed_capsule_has_no_active_host_owner() {
        let same_some = Some(completed_slots());
        assert!(same_some.is_some());
        assert!(same_some.is_some_and(|slots| slots.require_completed_owners_data().is_ok()));
        // This checks the preliminary slot boundary only. The production helper
        // still requires the actual private released-World witness afterward.
    }

    #[test]
    fn same_some_capsule_refuses_each_independent_active_or_partial_owner() {
        let completed = completed_slots();
        let active = [
            FlightSlots17 {
                mapping: false,
                ..completed
            },
            FlightSlots17 {
                admission: true,
                ..completed
            },
            FlightSlots17 {
                held: false,
                ..completed
            },
            FlightSlots17 {
                proof: true,
                ..completed
            },
            FlightSlots17 {
                recovered_connection: true,
                ..completed
            },
            FlightSlots17 {
                completed: true,
                ..completed
            },
            FlightSlots17 {
                proof_allocation: false,
                ..completed
            },
        ];
        for slots in active {
            let same_some = Some(slots);
            assert!(same_some.is_some());
            assert!(same_some.is_some_and(|slots| slots.require_completed_owners_data().is_err()));
        }
    }
}

/// Names the distinct Observe17 host-slot/root predicate's explicit views.
pub(in crate::reference_packet::endpoint) const fn observation17_host_cut_counter_scratch_data()
-> usize {
    std::mem::size_of::<FlightSlots17>()
        + std::mem::size_of::<&Rc<RefCell<NativeAckBoot>>>()
        + std::mem::size_of::<
            &Rc<RefCell<crate::protocol_snapshot::PreparedArchivedNativeProtocolMapping>>,
        >()
        + std::mem::size_of::<Result<(), ProviderError>>()
}
