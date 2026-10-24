//! Builds the reactive actor without losing the original socket on refusal.

use super::*;
use crate::reference_packet::PacketModelBirthFailure;

impl PacketConnectedProgram {
    // These are precisely the five empty banks returned by prepared below.
    // Inline Vec headers and the transferred definition belong to caller roots.
    pub(crate) fn original_initial_reservation_requested_bytes() -> Result<usize, ProviderError> {
        let event_slot = std::mem::size_of::<PacketReaction>()
            .checked_add(std::mem::size_of::<PacketDeliveredInput>())
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<PacketPendingPublication>()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<PacketConnectedPublication>()))
            .ok_or(ProviderError::ResourceExhausted(
                "reactive birth requested storage",
            ))?;
        MAXIMUM_EVENTS
            .checked_mul(event_slot)
            .and_then(|bytes| {
                MAXIMUM_BATCHES
                    .checked_mul(std::mem::size_of::<OriginalStage>())
                    .and_then(|stages| bytes.checked_add(stages))
            })
            .ok_or(ProviderError::ResourceExhausted(
                "reactive birth requested storage",
            ))
    }

    /// Constructs the reactive actor while retaining original inputs on refusal.
    ///
    /// All fallible checks and finite bank reservations precede transfer of the
    /// original effect socket. No gate opens and no input is staged or consumed.
    ///
    /// # Errors
    /// Returns the same definition and socket for malformed schema, duplicate or
    /// foreign routes, excessive original bytes or any history-bank allocation failure.
    // The precharged phase keeps the complete original definition and socket
    // inline; refusal must not allocate a box before preserving those owners.
    #[allow(clippy::result_large_err)]
    pub fn new_retained(
        definition: PacketConnectedDefinition,
        effect_socket: UnixDatagram,
    ) -> Result<Self, PacketModelBirthFailure<PacketConnectedDefinition>> {
        let prepared = (|| {
            crate::connection::serialized_credit(&definition, MAXIMUM_RECORD)?;
            if definition.schema != "source-owned.packet-connected-program/4"
                || definition.connections.is_empty()
                || definition.connections.len() > 4
            {
                return Err(ProviderError::Correlation(
                    "packet connected source definition",
                ));
            }
            let node = &definition.connections[0].consumer.node_id;
            for (index, route) in definition.connections.iter().enumerate() {
                route.policy.validate()?;
                if definition.connections[..index]
                    .iter()
                    .any(|prior| prior.id == route.id)
                    || &route.consumer.node_id != node
                    || route.producer == route.consumer
                    || route.delay_ps.get() > 1024
                {
                    return Err(ProviderError::Correlation(
                        "packet connected complete routes",
                    ));
                }
            }
            if definition
                .output
                .as_ref()
                .is_some_and(|output| &output.node_id != node)
            {
                return Err(ProviderError::Correlation("packet connected output owner"));
            }
            Ok((
                reserve(MAXIMUM_EVENTS)?,
                reserve(MAXIMUM_EVENTS)?,
                reserve(MAXIMUM_EVENTS)?,
                reserve(MAXIMUM_EVENTS)?,
                reserve(MAXIMUM_BATCHES)?,
            ))
        })();
        let (reactions, delivered_inputs, publications, outputs, stages) = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                return Err(PacketModelBirthFailure {
                    configuration: definition,
                    effect_socket,
                    error,
                });
            }
        };
        Ok(Self {
            definition,
            native_pid: std::process::id(),
            effect_socket,
            reached: Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl),
            gate_closed: true,
            reactions,
            delivered_inputs,
            publications,
            outputs,
            stages,
            grants: BTreeMap::new(),
            retired: BTreeMap::new(),
            reactions_completed: 0,
            packet_effects: 0,
            failed: false,
        })
    }
}

fn reserve<T>(maximum: usize) -> Result<Vec<T>, ProviderError> {
    let mut bank = Vec::new();
    bank.try_reserve_exact(maximum)
        .map_err(|_| ProviderError::ResourceExhausted("packet connected original actor bank"))?;
    Ok(bank)
}
