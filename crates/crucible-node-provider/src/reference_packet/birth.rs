//! Retains the same original effect socket across actor-construction refusal.

use super::*;

/// Owns the original actor inputs and effect socket after a refused construction.
///
/// No retry or native execution permission follows from this holder. Its owning
/// service keeps it in the original phase until cleanup or an authorized transfer.
pub struct PacketModelBirthFailure<C> {
    pub(super) configuration: C,
    pub(super) effect_socket: UnixDatagram,
    pub(super) error: ProviderError,
}

impl<C> PacketModelBirthFailure<C> {
    /// Borrows the original validation or allocation refusal.
    pub fn error(&self) -> &ProviderError {
        &self.error
    }

    /// Borrows the original configuration without reconstructing it.
    pub fn configuration(&self) -> &C {
        &self.configuration
    }

    /// Borrows the same original effect socket without changing its ownership.
    pub fn effect_socket(&self) -> &UnixDatagram {
        &self.effect_socket
    }

    /// Transfers all original constructor inputs together with their refusal.
    pub fn into_original_parts(self) -> (C, UnixDatagram, ProviderError) {
        (self.configuration, self.effect_socket, self.error)
    }
}

impl PacketProgram {
    // This is the actual empty output bank reserved by new_retained below.
    // The transferred event configuration is counted independently by the caller.
    pub(crate) fn original_initial_reservation_requested_bytes() -> Result<usize, ProviderError> {
        MAXIMUM_EVENTS
            .checked_mul(std::mem::size_of::<PacketPublication>())
            .ok_or(ProviderError::ResourceExhausted(
                "producer birth requested storage",
            ))
    }

    /// Constructs the producer while retaining all original inputs on refusal.
    ///
    /// Validation and finite storage reservation borrow the original inputs before
    /// the socket is transferred. The caller precharges the inline phase holder;
    /// this route allocates no replacement socket or failure wrapper.
    ///
    /// # Errors
    /// Returns the original event population and socket for malformed, duplicate,
    /// overwide or unordered events, or output-bank allocation failure.
    pub fn new_retained(
        events: Vec<PacketEvent>,
        effect_socket: UnixDatagram,
    ) -> Result<Self, PacketModelBirthFailure<Vec<PacketEvent>>> {
        let prepared = (|| {
            if events.is_empty() || events.len() > MAXIMUM_EVENTS {
                return Err(ProviderError::ResourceExhausted("packet native events"));
            }
            let zero = Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl);
            let mut previous = zero;
            for (index, event) in events.iter().enumerate() {
                event.id.validate()?;
                event.evaluation.validate()?;
                event.completion.validate()?;
                if events[..index].iter().any(|prior| prior.id == event.id)
                    || event.evaluation < previous
                    || event.evaluation > event.completion
                    || event.evaluation.phase != Phase::Reaction
                    || event.payload.as_ref().is_some_and(|payload| {
                        payload.as_slice().len() > MAXIMUM_PAYLOAD
                            || event.completion.phase != Phase::Publication
                            || event.completion <= event.evaluation
                    })
                {
                    return Err(ProviderError::Frame("packet native event shape"));
                }
                previous = event.completion;
            }
            let mut outputs = Vec::new();
            outputs
                .try_reserve_exact(MAXIMUM_EVENTS)
                .map_err(|_| ProviderError::ResourceExhausted("packet native output bank"))?;
            Ok((zero, outputs))
        })();
        let (reached, outputs) = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                return Err(PacketModelBirthFailure {
                    configuration: events,
                    effect_socket,
                    error,
                });
            }
        };
        Ok(Self {
            effect_socket,
            events,
            next_event: 0,
            reached,
            gate_closed: true,
            outputs,
            grants: BTreeMap::new(),
            private_mutations: 0,
            packet_effects: 0,
            retired: BTreeMap::new(),
            failed: false,
        })
    }
}

#[cfg(test)]
#[path = "birth_tests.rs"]
mod tests;
