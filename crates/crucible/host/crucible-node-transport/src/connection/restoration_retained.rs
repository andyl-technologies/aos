//! Counts retained connection owners after selected transfer failure.
//!
//! Creator and actual typed-codec/supervisor identities remain mandatory. Fenced
//! transports and revoked registrations still own their original allocations;
//! these DATA walks neither renew them nor authorize any protocol effect.

use super::*;
use std::mem::size_of;

impl<S: ProviderStream> Connection<S> {
    fn authenticate_original_restoration_codec_data(&self) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        let codec = self
            .native5_codec
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "raw restoration immutable codec absent",
            ))?;
        let installed: Rc<dyn BodySchemaVerifier> = codec.clone();
        if self.packet_schema
            || self.connected_packet_schema
            || !Rc::ptr_eq(&self.schemas, &installed)
        {
            return Err(ProviderError::Correlation(
                "raw restoration verifier identity differs",
            ));
        }
        Ok(())
    }

    pub(crate) fn authenticate_original_restoration_registration_data(
        &self,
        registration: &ConnectionAuthority,
    ) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        if !self.authority.same_registration(registration) {
            return Err(ProviderError::Correlation(
                "raw restoration registration identity differs",
            ));
        }
        Ok(())
    }

    pub(crate) fn observe_original_restoration_metadata(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), ProviderError> {
        self.authenticate_original_restoration_codec_data()?;
        self.authority.observe_retained_metadata(observer)?;
        self.guard.observe_owned_metadata(observer)?;
        let codec = self
            .native5_codec
            .as_ref()
            .ok_or(ProviderError::Correlation("owned protocol codec absent"))?;
        observer.shared_original(
            crate::retained_metadata::aliases::MetadataSharedKind::Codec,
            codec.as_ref(),
        )?;
        codec.observe_retained_metadata(observer)
    }
}

// The closure is never invoked. Its inferred result names every actual borrowed
// field layout without replacing opaque fields by a guessed word count.
fn field_view_bytes<T>(
    _: impl FnOnce(&'static Connection<crate::client::DeadlineStream>) -> T,
) -> usize {
    size_of::<T>()
}

impl Connection<crate::client::DeadlineStream> {
    pub(crate) fn original_restoration_metadata_counter_scratch_data() -> usize {
        field_view_bytes(|connection| {
            let Connection {
                reader,
                authority,
                guard,
                supervisor,
                schemas,
                protocol_owner,
                native5_blobs,
                native5_codec,
                original_restore_inputs,
                original_restore_responses,
                original_complete_restoration,
                original_canonical_ack_admission,
                packet_schema,
                original_frames,
                connected_packet_schema,
                fenced,
                role,
            } = connection;
            (
                reader,
                authority,
                guard,
                supervisor,
                schemas,
                protocol_owner,
                native5_blobs,
                native5_codec,
                original_restore_inputs,
                original_restore_responses,
                original_complete_restoration,
                original_canonical_ack_admission,
                packet_schema,
                original_frames,
                connected_packet_schema,
                fenced,
                role,
            )
        }) + size_of::<Rc<dyn BodySchemaVerifier>>()
            + size_of::<Option<&Rc<Native5CodecOwner>>>()
            + size_of::<&Rc<Native5CodecOwner>>()
            + size_of::<(&OriginalRetainedSupervisor, &Self)>()
            + size_of::<(&OriginalProtocolSupervisor, &Self)>()
            + size_of::<&Rc<dyn ConnectionSupervisor>>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<Result<crate::transport::OriginalFrameReaderFacts, ProviderError>>()
            + size_of::<
                Option<
                    &Rc<
                        std::cell::RefCell<
                            crate::transport::original_frames::OriginalFrameReservation,
                        >,
                    >,
                >,
            >()
            + size_of::<
                Result<
                    &Rc<
                        std::cell::RefCell<
                            crate::transport::original_frames::OriginalFrameReservation,
                        >,
                    >,
                    ProviderError,
                >,
            >()
            + size_of::<
                Result<
                    std::cell::Ref<
                        'static,
                        crate::transport::original_frames::OriginalFrameReservation,
                    >,
                    std::cell::BorrowError,
                >,
            >()
            + size_of::<
                Result<
                    std::cell::Ref<
                        'static,
                        crate::transport::original_frames::OriginalFrameReservation,
                    >,
                    ProviderError,
                >,
            >()
            + size_of::<Result<&Rc<Native5CodecOwner>, ProviderError>>()
            + size_of::<
                std::cell::Ref<
                    'static,
                    crate::transport::original_frames::OriginalFrameReservation,
                >,
            >()
    }

    pub(crate) fn observe_original_restoration_metadata_extras(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), ProviderError> {
        self.authenticate_original_restoration_codec_data()?;
        let Self {
            reader,
            authority: _,
            guard: _,
            supervisor,
            schemas: _,
            protocol_owner,
            native5_blobs,
            native5_codec,
            original_restore_inputs,
            original_restore_responses,
            original_complete_restoration,
            original_canonical_ack_admission,
            packet_schema,
            original_frames,
            connected_packet_schema,
            fenced,
            role,
        } = self;
        if *role != EndpointRole::Controller
            || native5_blobs.is_some()
            || original_restore_inputs.is_some()
            || original_restore_responses.iter().any(Option::is_some)
            || original_complete_restoration.is_some()
            || original_canonical_ack_admission.is_some()
        {
            return Err(ProviderError::Correlation(
                "live host metadata owner family unsupported",
            ));
        }
        observer.shared_original(
            crate::retained_metadata::aliases::MetadataSharedKind::ProtocolOwner,
            protocol_owner.as_ref(),
        )?;
        // The raw identity check established the SAME typed codec allocation.
        // Count the independent erased-schema edge without granting liveness.
        let codec = native5_codec
            .as_ref()
            .ok_or(ProviderError::Correlation("live host codec absent"))?;
        observer.shared_original(
            crate::retained_metadata::aliases::MetadataSharedKind::Codec,
            codec.as_ref(),
        )?;
        codec.observe_retained_metadata(observer)?;
        observer.shared_original(
            crate::retained_metadata::aliases::MetadataSharedKind::HostSupervisor,
            supervisor.as_ref(),
        )?;
        let bank = original_frames
            .as_ref()
            .ok_or(ProviderError::Correlation("live host frame bank absent"))?;
        observer.shared_original(
            crate::retained_metadata::aliases::MetadataSharedKind::FrameBank,
            bank.as_ref(),
        )?;
        bank.try_borrow()
            .map_err(|_| ProviderError::Conflict("live host frame bank borrowed"))?
            .observe_owned11_metadata(observer)?;
        reader.observe_original_host_live_metadata(bank, observer)?;
        observer.observe(packet_schema)?;
        observer.observe(connected_packet_schema)?;
        observer.observe(fenced)
    }
}

#[cfg(all(test, unix))]
impl Connection<crate::client::DeadlineStream> {
    pub(crate) fn fence_restoration_retained_fixture(&mut self) {
        self.contain(ConnectionFailure::Protocol);
    }
}
