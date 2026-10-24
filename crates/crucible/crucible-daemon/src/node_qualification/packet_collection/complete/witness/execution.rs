//! Borrows the original finite oracle scene for collection-only execution gates.

use crucible_node_format::{Phase, Position, U64};
use crucible_node_transport::reference_packet::service::PacketConnectedSourceProgram;

use super::{PacketCompleteNativeOracle, QualificationError, refused};

impl PacketCompleteNativeOracle {
    pub(in super::super) fn execution_schedule(
        &self,
    ) -> &super::super::super::connected::PacketConnectedSchedule {
        &self.schedule
    }

    pub(in super::super) fn authenticate_fixed_execution_data(
        &self,
        world: &crucible_node_format::WorldBinding,
    ) -> Result<(), QualificationError> {
        self.roster.current_scope()?;
        self.preflight()?;
        if world.connections.len() != 2 {
            return Err(refused());
        }
        let PacketConnectedSourceProgram::Producer { program } = &self.programmes[0] else {
            return Err(refused());
        };
        if program.events.len() != 2 {
            return Err(refused());
        }
        let private = &program.events[0];
        let public = &program.events[1];
        if private.evaluation != Position::new(U64::new(4), U64::new(0), Phase::Reaction)
            || private.completion != private.evaluation
            || private.payload.is_some()
            || public.evaluation != Position::new(U64::new(5), U64::new(0), Phase::Reaction)
            || public.completion != Position::new(U64::new(5), U64::new(1), Phase::Publication)
            || public
                .payload
                .as_ref()
                .is_none_or(|bytes| bytes.as_slice() != b"original-producer")
        {
            return Err(refused());
        }
        for member in 1..3 {
            let PacketConnectedSourceProgram::Reactive { program } = &self.programmes[member]
            else {
                return Err(refused());
            };
            let [connection] = program.connections.as_slice() else {
                return Err(refused());
            };
            let installed = &world.connections[member - 1];
            if connection.id != installed.id
                || connection.producer != installed.producer
                || connection.consumer != installed.consumer
                || connection.policy != installed.policy_ref
                || connection.delay_ps != installed.minimum_latency_ps
                || program.output.as_ref()
                    != if member == 1 {
                        Some(&world.connections[1].producer)
                    } else {
                        None
                    }
            {
                return Err(refused());
            }
        }
        self.roster.current_scope()
    }
}
