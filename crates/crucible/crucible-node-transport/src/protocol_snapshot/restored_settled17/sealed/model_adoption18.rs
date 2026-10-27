//! Retains the complete sealed archive through its distinct18 model transition.
//!
//! The archive enters this opaque owner before validation. Its current decoder
//! bank then moves into the model transition while raw roles, immutable ancestry,
//! before-graph cache and every refused prefix stay here. No depleted archive
//! can escape as a validated17 loan. This ownership transition supplies no
//! Source ancestry, native credit, Commit, physical Hold or activation permit.

use super::*;
use crate::protocol_snapshot::native_wholegraph17::{
    NativeCurrentGraph17Data, NativeCurrentGraph18ModelAdoption,
};
use crate::reference_packet::{
    continuation_models::settled_reader::adoption18::CurrentModel18Program,
    service::PacketConnectedSourceProgram,
};
use std::{os::unix::net::UnixDatagram, thread::ThreadId};

/// Keeps the entire original archive beside its nonrenewing model transition.
pub(crate) struct RestoredSettledNative18ModelAdoption {
    process: u32,
    thread: ThreadId,
    failed: bool,
    archive: Option<SealedHistoricalRestoredSettledNative17>,
    model: Option<NativeCurrentGraph18ModelAdoption>,
}

impl RestoredSettledNative18ModelAdoption {
    /// Retains the whole input before validating or moving its decoder bank.
    ///
    /// The caller independently admits this inline owner, archive validation,
    /// model validation and their constructor controls before entry. Existing
    /// backing keeps its original charge through every move. Model validation
    /// uses its independently admitted temporaries. No decoder, archive copy
    /// or native-effect callback runs here.
    ///
    /// # Errors
    /// Refuses an occupied destination without changing the input. Missing or
    /// incomplete input, invalid graph or a different model definition leaves
    /// this same destination spent with every initialized prefix retained.
    pub(crate) fn prepare_into(
        archive: &mut Option<SealedHistoricalRestoredSettledNative17>,
        program: &PacketConnectedSourceProgram,
        output: &mut Option<Self>,
    ) -> Result<(), ProviderError> {
        if output.is_some() {
            return Err(refused());
        }
        *output = Some(Self {
            process: std::process::id(),
            thread: std::thread::current().id(),
            failed: true,
            archive: archive.take(),
            model: None,
        });

        let owner = output.as_mut().ok_or_else(refused)?;
        let archive = owner.archive.as_mut().ok_or_else(refused)?;
        archive.validated_native_graph_data()?;
        archive
            .decoded
            .native_graph
            .prepare_model18_into(program, &mut owner.model)?;
        owner.failed = false;
        Ok(())
    }

    /// Binds the same fresh socket without releasing an enclosing physical Hold.
    ///
    /// # Errors
    /// Refuses foreign origin, failed preparation, missing model custody or any
    /// underlying socket-binding refusal while preserving all owning slots.
    pub(crate) fn bind_effect_socket(
        &mut self,
        socket: &mut Option<UnixDatagram>,
    ) -> Result<(), ProviderError> {
        self.authenticate_prepared()?;
        self.model
            .as_mut()
            .ok_or_else(refused)?
            .bind_effect_socket(socket)
    }

    /// Transfers the completed program once while retaining the whole archive.
    ///
    /// The genuine installer independently authenticates its original custody,
    /// native phase credit and physical Hold before taking any live program.
    ///
    /// # Errors
    /// Refuses foreign origin, failed or unbound preparation, a spent transfer
    /// or an occupied output without replacing any retained owner.
    pub(crate) fn take_completed_into(
        &mut self,
        output: &mut Option<CurrentModel18Program>,
    ) -> Result<(), ProviderError> {
        self.authenticate_prepared()?;
        self.model
            .as_mut()
            .ok_or_else(refused)?
            .take_completed_into(output)
    }

    /// Counts the actual enclosing header and all independently owned backing.
    ///
    /// Failed and depleted archives use the partial decoder census without a
    /// validated17 loan. The moved bank and model are counted in their actual
    /// destination, whose inline header is already embedded here. Kernel socket
    /// resources and enclosing Source/native owners remain independent terms.
    ///
    /// # Errors
    /// Refuses foreign origin, invalid allocation geometry, checked overflow or
    /// insufficient independent requested-storage credit.
    pub(crate) fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, ProviderError> {
        self.authenticate_origin()?;
        let mut requested = size_of::<Self>();
        if let Some(archive) = &self.archive {
            requested = requested
                .checked_add(
                    archive
                        .decoded
                        .retained_requested_storage_data(usize::MAX)?,
                )
                .ok_or_else(refused)?;
        }
        if let Some(model) = &self.model {
            let backing = model
                .retained_requested_storage_data(usize::MAX)?
                .checked_sub(size_of::<NativeCurrentGraph18ModelAdoption>())
                .ok_or_else(refused)?;
            requested = requested.checked_add(backing).ok_or_else(refused)?;
        }
        if requested > maximum {
            return Err(ProviderError::ResourceExhausted(
                "native archive18 model retained storage",
            ));
        }
        Ok(requested)
    }

    /// Names the actual inline destination admitted before installing this owner.
    pub(crate) const fn inline_header_bytes_data() -> usize {
        size_of::<Option<Self>>()
    }

    /// Names enclosing by-value moves beside the independently quoted child work.
    ///
    /// Dynamic validation and compiler-generated frames remain separate terms.
    pub(crate) const fn construction_value_temporary_data() -> usize {
        size_of::<Self>()
            + size_of::<Option<Self>>()
            + size_of::<SealedHistoricalRestoredSettledNative17>()
            + size_of::<Option<SealedHistoricalRestoredSettledNative17>>()
            + NativeCurrentGraph18ModelAdoption::construction_value_temporary_data()
    }

    /// Names the defining archive, model, origin and requested-storage controls.
    pub(crate) fn counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<&mut Option<Self>>()
            + size_of::<&mut Option<SealedHistoricalRestoredSettledNative17>>()
            + size_of::<&mut SealedHistoricalRestoredSettledNative17>()
            + size_of::<&NativeCurrentGraph17Data>()
            + size_of::<Result<&NativeCurrentGraph17Data, ProviderError>>()
            + size_of::<&mut NativeGraph17DecodeCache>()
            + size_of::<&mut Option<NativeCurrentGraph18ModelAdoption>>()
            + size_of::<&PacketConnectedSourceProgram>()
            + size_of::<&mut Option<UnixDatagram>>()
            + size_of::<&mut Option<CurrentModel18Program>>()
            + size_of::<std::thread::Thread>()
            + size_of::<ThreadId>()
            + size_of::<u32>()
            + size_of::<usize>() * 3
            + size_of::<Result<usize, ProviderError>>()
            + size_of::<Result<(), ProviderError>>()
            + RestoredSettledNative17DecodeAttempt::capacity_counter_scratch_data()
            + NativeCurrentGraph18ModelAdoption::counter_scratch_data()
    }

    fn authenticate_prepared(&self) -> Result<(), ProviderError> {
        self.authenticate_origin()?;
        if self.failed || self.archive.is_none() || self.model.is_none() {
            return Err(refused());
        }
        Ok(())
    }

    fn authenticate_origin(&self) -> Result<(), ProviderError> {
        if self.process != std::process::id() || self.thread != std::thread::current().id() {
            return Err(refused());
        }
        Ok(())
    }
}

fn refused() -> ProviderError {
    ProviderError::Conflict("original native archive18 model custody")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reference_packet::{PacketEvent, PacketProgram};
    use crucible_node_format::{Id, Phase, Position, U64};
    use std::os::fd::AsRawFd;

    fn definition() -> Result<PacketConnectedSourceProgram, ProviderError> {
        let (socket, _peer) = UnixDatagram::pair()?;
        let event = PacketEvent {
            id: Id::new("archive-prefix-event")?,
            evaluation: Position::new(U64::new(1), U64::new(0), Phase::Reaction),
            completion: Position::new(U64::new(2), U64::new(0), Phase::Publication),
            payload: None,
        };
        Ok(PacketConnectedSourceProgram::Producer {
            program: PacketProgram::new(vec![event], socket)?.definition(),
        })
    }

    fn incomplete_archive() -> Result<SealedHistoricalRestoredSettledNative17, ProviderError> {
        let mut decoded = RestoredSettledNative17DecodeAttempt::new();
        let reference = canonical::content_ref(b"{}", "application/json")?;
        assert!(decoded.retain_reference_data(0, &reference, 64).is_err());
        decoded.raw[0]
            .try_reserve_exact(37)
            .map_err(|_| refused())?;
        decoded.raw[0].extend_from_slice(b"partial-native-snapshot");
        Ok(SealedHistoricalRestoredSettledNative17 { decoded })
    }

    #[test]
    fn archive18_model_adoption_keeps_actual_archive_prefix_on_validation_refusal()
    -> Result<(), ProviderError> {
        let archive = incomplete_archive()?;
        let backing = archive
            .decoded
            .retained_requested_storage_data(usize::MAX)?;
        let raw = archive.decoded.raw[0].as_ptr();
        let reference = archive.decoded.references[0].clone();
        let mut input = Some(archive);
        let mut output = None;

        assert!(
            RestoredSettledNative18ModelAdoption::prepare_into(
                &mut input,
                &definition()?,
                &mut output,
            )
            .is_err()
        );

        assert!(input.is_none());
        let owner = output.as_mut().ok_or_else(refused)?;
        assert!(owner.failed);
        assert!(owner.model.is_none());
        let archive = owner.archive.as_ref().ok_or_else(refused)?;
        assert_eq!(archive.decoded.raw[0].as_ptr(), raw);
        assert_eq!(archive.decoded.raw[0], b"partial-native-snapshot");
        assert_eq!(archive.decoded.references[0], reference);
        let requested = size_of::<RestoredSettledNative18ModelAdoption>() + backing;
        assert_eq!(owner.retained_requested_storage_data(requested)?, requested);
        assert!(
            owner
                .retained_requested_storage_data(requested - 1)
                .is_err()
        );

        let (socket, _peer) = UnixDatagram::pair()?;
        let descriptor = socket.as_raw_fd();
        let mut socket = Some(socket);
        assert!(owner.bind_effect_socket(&mut socket).is_err());
        assert_eq!(socket.as_ref().ok_or_else(refused)?.as_raw_fd(), descriptor);
        let mut completed = None;
        assert!(owner.take_completed_into(&mut completed).is_err());
        assert!(completed.is_none());
        assert_eq!(owner.retained_requested_storage_data(requested)?, requested);
        Ok(())
    }

    #[test]
    fn archive18_model_adoption_missing_input_spends_output_and_preserves_replacement()
    -> Result<(), ProviderError> {
        let program = definition()?;
        let mut output = None;
        assert!(
            RestoredSettledNative18ModelAdoption::prepare_into(&mut None, &program, &mut output,)
                .is_err()
        );
        let requested = size_of::<RestoredSettledNative18ModelAdoption>();
        assert_eq!(
            output
                .as_ref()
                .ok_or_else(refused)?
                .retained_requested_storage_data(requested)?,
            requested
        );
        let mut replacement = Some(incomplete_archive()?);
        let raw = replacement.as_ref().ok_or_else(refused)?.decoded.raw[0].as_ptr();

        assert!(
            RestoredSettledNative18ModelAdoption::prepare_into(
                &mut replacement,
                &program,
                &mut output,
            )
            .is_err()
        );

        assert_eq!(
            replacement.as_ref().ok_or_else(refused)?.decoded.raw[0].as_ptr(),
            raw
        );
        let owner = output.as_ref().ok_or_else(refused)?;
        assert!(owner.failed && owner.archive.is_none() && owner.model.is_none());
        assert_eq!(owner.retained_requested_storage_data(requested)?, requested);
        assert!(RestoredSettledNative18ModelAdoption::inline_header_bytes_data() > 0);
        assert!(RestoredSettledNative18ModelAdoption::construction_value_temporary_data() > 0);
        assert!(RestoredSettledNative18ModelAdoption::counter_scratch_data() > 0);
        Ok(())
    }

    #[test]
    fn archive18_model_adoption_moves_failed_actual_cache_without_renewing_its_slot()
    -> Result<(), ProviderError> {
        use crate::protocol_snapshot::native_wholegraph17::NativeCurrentGraph17ReadLimits;

        let mut cache = NativeGraph17DecodeCache::new();
        let limits = NativeCurrentGraph17ReadLimits {
            maximum_requested: 64 * 1024 * 1024,
            maximum_target_requested: 64 * 1024 * 1024,
            maximum_nodes: 64,
            maximum_depth: 64,
        };
        assert!(cache.read_into_data(b"[false]", limits).is_err());
        assert!(cache.as_ref().is_some());
        let backing = cache.retained_requested_storage_data(usize::MAX)?;
        let mut model = None;

        assert!(
            cache
                .prepare_model18_into(&definition()?, &mut model)
                .is_err()
        );

        assert!(cache.as_ref().is_none());
        assert_eq!(cache.retained_requested_storage_data(0)?, 0);
        let owner = model.as_ref().ok_or_else(refused)?;
        let requested = size_of::<NativeCurrentGraph18ModelAdoption>() + backing;
        assert_eq!(owner.retained_requested_storage_data(requested)?, requested);
        assert!(cache.read_into_data(b"[false]", limits).is_err());
        assert_eq!(cache.retained_requested_storage_data(0)?, 0);
        assert_eq!(owner.retained_requested_storage_data(requested)?, requested);
        Ok(())
    }
}
