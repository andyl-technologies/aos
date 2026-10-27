//! Transfers complete current-model DATA into the caller's fresh owned socket.
//!
//! Preparation retains its input before validation. Socket binding moves the
//! already decoded fields and their actual backing; it neither reparses an old
//! model snapshot nor reconstructs native phase, Hold or World permission. The
//! enclosing installer must independently authenticate the archive and keep its
//! genuine physical hold through activation.

use super::{CurrentModel, PacketSettledModel17Data, ProducerState};
use crate::ProviderError;
use crate::reference_packet::{
    PacketProgram, connected::PacketConnectedProgram, service::PacketConnectedSourceProgram,
};
use crate::retained_metadata::{MetadataObserver, requested_metadata_backing_storage_data};
use std::{mem::size_of, os::unix::net::UnixDatagram, thread::ThreadId};

#[path = "adoption18/construction.rs"]
mod construction;
pub use construction::CurrentModel18ConstructionData;

/// Retains exactly one reconstructed program and its actual fresh socket.
pub(crate) enum CurrentModel18Program {
    /// Retains every producer queue, grant and logical cursor.
    Producer(PacketProgram),
    /// Retains every reactive queue, delivery and logical cursor.
    Reactive(PacketConnectedProgram),
}

/// Owns a nonrenewing model transfer and every refused preparation prefix.
pub(crate) struct CurrentModel18Adoption {
    creator: u32,
    thread: ThreadId,
    prepared: bool,
    bound: bool,
    transferred: bool,
    failed: bool,
    model: Option<PacketSettledModel17Data>,
    completed: Option<CurrentModel18Program>,
}

impl CurrentModel18Adoption {
    /// Retains the complete decoded input before checking its actual definition.
    ///
    /// The caller admits validation work and the inline attempt first. Existing
    /// cold-decoder backing remains charged while this attempt owns it. A
    /// missing or refused input leaves this same destination spent; retries
    /// cannot replace its retained model. Failed and incomplete logical originals
    /// remain unchanged; restoring them cannot authorize replay. Preparation
    /// takes no effect socket. The settled17 route keeps its separate predicate.
    ///
    /// # Errors
    /// Refuses an occupied destination, absent input, inconsistent
    /// current history, another model kind or a changed complete definition.
    pub(crate) fn prepare_into(
        model: &mut Option<PacketSettledModel17Data>,
        program: &PacketConnectedSourceProgram,
        output: &mut Option<Self>,
    ) -> Result<(), ProviderError> {
        if output.is_some() {
            return Err(conflict());
        }
        *output = Some(Self {
            creator: std::process::id(),
            thread: std::thread::current().id(),
            prepared: false,
            bound: false,
            transferred: false,
            failed: true,
            model: model.take(),
            completed: None,
        });

        let attempt = output.as_mut().ok_or_else(conflict)?;
        let model = attempt.model.as_ref().ok_or_else(conflict)?;
        model.authenticate_current_data()?;
        model.authenticate_program18_data(program)?;
        attempt.prepared = true;
        attempt.failed = false;
        Ok(())
    }

    /// Binds the original fresh socket after every fallible model check.
    ///
    /// The same decoded vectors and maps move into the program without
    /// allocation, serialization or capacity changes. Captured logical gates
    /// remain unchanged. A reactive program uses the actual new process ID for
    /// future records; its enclosing archive retains historical process DATA.
    /// No native admission, activation or physical Hold follows from this move.
    ///
    /// # Errors
    /// Refuses foreign origin, incomplete/failed preparation, an absent socket,
    /// an already bound attempt or a previously transferred program. Refusal
    /// leaves the caller's socket and every retained model field owned.
    pub(crate) fn bind_effect_socket(
        &mut self,
        socket: &mut Option<UnixDatagram>,
    ) -> Result<(), ProviderError> {
        self.authenticate_origin()?;
        if !self.prepared
            || self.failed
            || self.bound
            || self.transferred
            || self.completed.is_some()
            || socket.is_none()
        {
            return Err(conflict());
        }

        let model = self.model.take().ok_or_else(conflict)?;
        let socket = match socket.take() {
            Some(socket) => socket,
            None => {
                self.model = Some(model);
                return Err(conflict());
            }
        };
        // Every operation after the actual socket transfer is an infallible
        // field move. No parser, allocator, validator or callback runs here.
        self.completed = Some(model.into_program18_data(socket));
        self.bound = true;
        Ok(())
    }

    /// Moves the same completed program once into an empty retained destination.
    ///
    /// # Errors
    /// Refuses foreign origin, incomplete/failed custody, a spent transfer or an
    /// occupied destination without consuming either destination or program.
    pub(crate) fn take_completed_into(
        &mut self,
        output: &mut Option<CurrentModel18Program>,
    ) -> Result<(), ProviderError> {
        self.authenticate_origin()?;
        if !self.prepared
            || self.failed
            || !self.bound
            || self.transferred
            || self.completed.is_none()
            || output.is_some()
        {
            return Err(conflict());
        }
        *output = self.completed.take();
        self.transferred = true;
        Ok(())
    }

    /// Counts this actual inline owner and every retained userspace allocation.
    ///
    /// The independently admitted observer walks the same partial or completed
    /// owner without clearing it. Native socket resources and archive/Control
    /// validation remain separate original obligations, never zero-byte grants.
    ///
    /// # Errors
    /// Refuses foreign origin, metadata/geometry overflow or a total above the
    /// caller's independent restriction while preserving every owning slot.
    pub(crate) fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, ProviderError> {
        self.authenticate_origin()?;
        let mut observer = MetadataObserver::new();
        if let Some(model) = &self.model {
            model.observe_settled_history_metadata_data(&mut observer)?;
        }
        match &self.completed {
            Some(CurrentModel18Program::Producer(program)) => observer.observe(program)?,
            Some(CurrentModel18Program::Reactive(program)) => observer.observe(program)?,
            None => {}
        }
        size_of::<Self>()
            .checked_add(requested_metadata_backing_storage_data(&observer.finish())?)
            .filter(|bytes| *bytes <= maximum)
            .ok_or(ProviderError::ResourceExhausted(
                "current model adoption retained storage",
            ))
    }

    fn authenticate_origin(&self) -> Result<(), ProviderError> {
        if self.creator != std::process::id() || self.thread != std::thread::current().id() {
            return Err(conflict());
        }
        Ok(())
    }
}

impl PacketSettledModel17Data {
    fn authenticate_program18_data(
        &self,
        program: &PacketConnectedSourceProgram,
    ) -> Result<(), ProviderError> {
        match (&self.state, program) {
            (CurrentModel::Producer(state), PacketConnectedSourceProgram::Producer { program })
                if program.schema == "source-owned.packet-program.v1"
                    && state.events == program.events =>
            {
                Ok(())
            }
            (CurrentModel::Reactive(state), PacketConnectedSourceProgram::Reactive { program }) => {
                state.authenticate_definition18_data(program)
            }
            _ => Err(ProviderError::Correlation(
                "current model adoption definition",
            )),
        }
    }

    fn into_program18_data(self, effect_socket: UnixDatagram) -> CurrentModel18Program {
        match self.state {
            CurrentModel::Producer(state) => {
                let ProducerState {
                    events,
                    next_event,
                    reached,
                    gate_closed,
                    outputs,
                    grants,
                    private_mutations,
                    packet_effects,
                    retired,
                    failed,
                } = state;
                CurrentModel18Program::Producer(PacketProgram {
                    effect_socket,
                    events,
                    next_event,
                    reached,
                    gate_closed,
                    outputs,
                    grants,
                    private_mutations,
                    packet_effects,
                    retired,
                    failed,
                })
            }
            CurrentModel::Reactive(state) => {
                CurrentModel18Program::Reactive(state.into_program18_data(effect_socket))
            }
        }
    }
}

fn conflict() -> ProviderError {
    ProviderError::Conflict("current model adoption original slots")
}

#[cfg(test)]
#[path = "adoption18/tests.rs"]
mod tests;
