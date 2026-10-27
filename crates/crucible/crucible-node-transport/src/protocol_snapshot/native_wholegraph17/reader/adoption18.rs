//! Retains the original decoder bank through the distinct18 model transition.
//!
//! The bank moves before validation without moving its large decoder headers.
//! Once its model leaves Control, the private depleted graph cannot escape as
//! a validated17 loan. Raw history, partial children, promotion slots and all
//! remaining Control fields stay owned through success and refusal. This model
//! transition does not authenticate archive ancestry, issue native credit or
//! establish Commit, physical Hold, Arm or World completion.

use super::*;
use crate::reference_packet::continuation_models::settled_reader::adoption18::{
    CurrentModel18Adoption, CurrentModel18Program,
};
use crate::reference_packet::service::PacketConnectedSourceProgram;
use std::{os::unix::net::UnixDatagram, thread::ThreadId};

#[derive(Clone, Copy, Eq, PartialEq)]
enum Stage {
    Preparing,
    Prepared,
    Bound,
    Transferred,
    Failed,
}

/// Owns the same decoder allocation and a nonrenewing current-model transfer.
pub(crate) struct NativeCurrentGraph18ModelAdoption {
    process: u32,
    thread: ThreadId,
    stage: Stage,
    graphs: Vec<Option<NativeCurrentGraph17DecodeAttempt>>,
    model: Option<CurrentModel18Adoption>,
}

impl NativeCurrentGraph18ModelAdoption {
    /// Retains the original heap bank before validating or taking its model.
    ///
    /// The installer first admits this header, model validation and all fixed
    /// controls. The original bank and decoder charges continue through their
    /// moves. Retaining their Vec avoids copying large decoder headers onto the
    /// stack or allocating a replacement bank. No allocating decoder runs here.
    ///
    /// # Errors
    /// Refuses an occupied destination without touching the input. Once the
    /// destination is installed, a missing, multiple, failed or invalid graph,
    /// absent model or different definition leaves that same attempt spent
    /// with every original allocation and initialized child retained.
    pub(crate) fn prepare_into(
        graphs: &mut Vec<Option<NativeCurrentGraph17DecodeAttempt>>,
        program: &PacketConnectedSourceProgram,
        output: &mut Option<Self>,
    ) -> Result<(), ProviderError> {
        if output.is_some() {
            return Err(refused());
        }
        *output = Some(Self {
            process: std::process::id(),
            thread: std::thread::current().id(),
            stage: Stage::Preparing,
            graphs: std::mem::take(graphs),
            model: None,
        });

        let owner = output.as_mut().ok_or_else(refused)?;
        owner.stage = Stage::Failed;
        if owner.graphs.len() != 1 {
            return Err(refused());
        }
        let decoder = owner.graphs[0].as_mut().ok_or_else(refused)?;
        decoder.validate_data()?;
        decoder
            .completed
            .as_mut()
            .ok_or_else(refused)?
            .control
            .prepare_current_model18_into(program, &mut owner.model)?;
        owner.stage = Stage::Prepared;
        Ok(())
    }

    /// Moves the original fresh socket after successful complete model checks.
    ///
    /// The genuine enclosing installer must independently keep its physical
    /// Hold. This field move preserves captured logical gates and grants; it
    /// neither opens that Hold nor authenticates an SDK phase or live World.
    ///
    /// # Errors
    /// Refuses another origin, failed/incomplete preparation, a missing socket
    /// or a repeated binding. Refusal preserves all retained owners and any
    /// caller socket. No fallible operation follows the successful socket move.
    pub(crate) fn bind_effect_socket(
        &mut self,
        socket: &mut Option<UnixDatagram>,
    ) -> Result<(), ProviderError> {
        self.authenticate_origin()?;
        if self.stage != Stage::Prepared {
            return Err(refused());
        }
        self.model
            .as_mut()
            .ok_or_else(refused)?
            .bind_effect_socket(socket)?;
        self.stage = Stage::Bound;
        Ok(())
    }

    /// Transfers the same completed program once while retaining decoder history.
    ///
    /// # Errors
    /// Refuses another origin, an unbound or spent attempt, missing completion
    /// or an occupied output without replacing either retained destination.
    pub(crate) fn take_completed_into(
        &mut self,
        output: &mut Option<CurrentModel18Program>,
    ) -> Result<(), ProviderError> {
        self.authenticate_origin()?;
        if self.stage != Stage::Bound {
            return Err(refused());
        }
        self.model
            .as_mut()
            .ok_or_else(refused)?
            .take_completed_into(output)?;
        self.stage = Stage::Transferred;
        Ok(())
    }

    /// Counts the actual header, decoder bank and every remaining allocation.
    ///
    /// This independently admitted DATA walk accepts failed and depleted
    /// decoder prefixes. The model's backing follows its actual owning slot;
    /// its inline header is already embedded here. Kernel socket resources,
    /// enclosing native owners and compiler frames remain separate terms.
    ///
    /// # Errors
    /// Refuses foreign origin, metadata/layout overflow or a whole retained
    /// demand above the independent requested-storage restriction.
    pub(crate) fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, ProviderError> {
        self.authenticate_origin()?;
        let mut observer = MetadataObserver::new();
        observer.vector::<Option<NativeCurrentGraph17DecodeAttempt>>(self.graphs.capacity())?;
        for decoder in self.graphs.iter().flatten() {
            decoder.observe_capacity_data(&mut observer)?;
        }
        let mut requested = size_of::<Self>()
            .checked_add(requested_metadata_backing_storage_data(&observer.finish())?)
            .ok_or_else(refused)?;
        if let Some(model) = &self.model {
            let backing = model
                .retained_requested_storage_data(usize::MAX)?
                .checked_sub(size_of::<CurrentModel18Adoption>())
                .ok_or_else(refused)?;
            requested = requested.checked_add(backing).ok_or_else(refused)?;
        }
        if requested > maximum {
            return Err(ProviderError::ResourceExhausted(
                "native graph18 model retained storage",
            ));
        }
        Ok(requested)
    }

    /// Returns the inline slot to admit before installing this retained owner.
    pub(crate) const fn inline_header_bytes_data() -> usize {
        size_of::<Option<Self>>()
    }

    /// Names enclosing constructor value moves beside the model's own quote.
    ///
    /// This adds the new owner/Option and moved/default Vec headers. Model
    /// validation, child transfers, dynamic traversal and compiler frames stay
    /// in their independent defining construction terms.
    pub(crate) const fn construction_value_temporary_data() -> usize {
        size_of::<Self>()
            + size_of::<Option<Self>>()
            + size_of::<Vec<Option<NativeCurrentGraph17DecodeAttempt>>>() * 2
    }

    /// Names defining guard, bank, model-transfer and metadata-walk controls.
    ///
    /// Dynamic validation and traversal work, by-value constructor temporaries
    /// and compiler-generated frames need their own independently admitted terms.
    pub(crate) fn counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<&mut Option<Self>>()
            + size_of::<&mut Vec<Option<NativeCurrentGraph17DecodeAttempt>>>()
            + size_of::<&mut NativeCurrentGraph17DecodeAttempt>()
            + size_of::<&mut NativeCurrentGraph17Data>()
            + size_of::<&mut CurrentControl17Data>()
            + size_of::<&PacketConnectedSourceProgram>()
            + size_of::<&mut Option<CurrentModel18Adoption>>()
            + size_of::<&mut Option<CurrentModel18Program>>()
            + size_of::<&mut Option<UnixDatagram>>()
            + size_of::<MetadataObserver<'static>>()
            + size_of::<crate::retained_metadata::RetainedProtocolMetadataFacts>()
            + size_of::<
                std::iter::Flatten<
                    std::slice::Iter<'static, Option<NativeCurrentGraph17DecodeAttempt>>,
                >,
            >()
            + size_of::<Option<&NativeCurrentGraph17DecodeAttempt>>()
            + size_of::<std::thread::Thread>()
            + size_of::<ThreadId>()
            + size_of::<u32>()
            + size_of::<usize>() * 4
            + size_of::<Result<usize, ProviderError>>()
            + size_of::<Result<(), ProviderError>>()
            + NativeCurrentGraph17DecodeAttempt::capacity_counter_scratch_data()
            + PacketSettledModel17Data::adoption18_construction_counter_scratch_data()
    }

    fn authenticate_origin(&self) -> Result<(), ProviderError> {
        if self.process != std::process::id() || self.thread != std::thread::current().id() {
            return Err(refused());
        }
        Ok(())
    }
}

fn refused() -> ProviderError {
    ProviderError::Conflict("original native graph18 model custody")
}

#[cfg(test)]
#[path = "adoption18/tests.rs"]
mod tests;
