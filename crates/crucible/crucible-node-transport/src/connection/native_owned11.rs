//! Captures the actual complete native service through original bounded loans.
//!
//! All mutable/current checks precede registrar and supervisor loans. The same
//! typed views populate precharged rows, quote their complete encoded extent,
//! and encode the final owner without registration callbacks or transport I/O.

use super::*;
use crate::protocol_snapshot::{ProtocolCaptureCut, ProtocolSnapshotReservation};
use crate::retained_metadata::{MetadataObserver, aliases::MetadataSharedKind};
use serde::{Serialize, Serializer};

pub(super) struct NativeCodecView<'a>(pub(super) &'a Native5CodecOwner);

impl Serialize for NativeCodecView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let Native5CodecOwner::NativePacket(policy) = self.0 else {
            return Err(serde::ser::Error::custom(
                "native complete codec role changed",
            ));
        };
        (
            "source-private.native-codec/11",
            policy.borrowed_owned11_protocol_view(),
        )
            .serialize(serializer)
    }
}

pub(super) struct NativeConnectionView<'a>(
    pub(super) &'a Connection<crate::client::DeadlineStream>,
);

impl Serialize for NativeConnectionView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let connection = self.0;
        let codec = connection
            .native5_codec
            .as_ref()
            .ok_or_else(|| serde::ser::Error::custom("native codec absent"))?;
        let frames = connection
            .original_frames
            .as_ref()
            .ok_or_else(|| serde::ser::Error::custom("native literal owner absent"))?;
        let bank = frames
            .try_borrow()
            .map_err(|_| serde::ser::Error::custom("native literal bank borrowed"))?;
        let blobs = connection
            .native5_blobs
            .as_ref()
            .ok_or_else(|| serde::ser::Error::custom("native blob owner absent"))?
            .borrowed_owned11_protocol_view()
            .map_err(serde::ser::Error::custom)?;
        let admission = connection
            .original_native_owned11_admission()
            .map_err(serde::ser::Error::custom)?;
        let token = admission
            .borrowed_owned11_protocol_view(connection)
            .map_err(serde::ser::Error::custom)?;
        // The reader and Connection each own the same bank. Both strong edges
        // are walked; historical reconstruction allocates the shared bank once.
        (
            "source-private.native-connection-complete/11",
            "historical-source-owner",
            connection.authority.historical_owned_view(),
            connection.guard.protocol_view(),
            NativeCodecView(codec),
            NativeCodecView(codec),
            bank.protocol_view_with_encoding(true),
            connection
                .reader
                .original_owned11_facts(frames)
                .map_err(serde::ser::Error::custom)?,
            blobs,
            "source-private.native-supervisor-owner/11",
            connection.packet_schema,
            connection.connected_packet_schema,
            connection.fenced,
            "provider",
            token,
        )
            .serialize(serializer)
    }
}

impl NativeConnectionView<'_> {
    pub(super) fn observe(&self, observer: &mut MetadataObserver) -> Result<(), ProviderError> {
        let connection = self.0;
        observer.shared_original(
            MetadataSharedKind::ProtocolOwner,
            connection.protocol_owner.as_ref(),
        )?;
        connection.authority.observe_retained_metadata(observer)?;
        connection.guard.observe_owned_metadata(observer)?;
        let codec = connection
            .native5_codec
            .as_ref()
            .ok_or(ProviderError::Correlation("native codec absent"))?;
        let Native5CodecOwner::NativePacket(policy) = codec.as_ref() else {
            return Err(ProviderError::Correlation(
                "native complete codec role changed",
            ));
        };
        // The actual erased verifier and typed owner are the same Rc, guarded
        // before entry; both real edges retain full payload correspondence.
        for _ in 0..2 {
            observer.shared_original(MetadataSharedKind::Codec, codec.as_ref())?;
            observer.shared_original(MetadataSharedKind::NativePolicy, policy.as_ref())?;
            policy.observe_owned11_metadata(observer)?;
        }
        let frames = connection
            .original_frames
            .as_ref()
            .ok_or(ProviderError::Correlation("native literal owner absent"))?;
        connection.reader.original_owned11_facts(frames)?;
        let bank = frames
            .try_borrow()
            .map_err(|_| ProviderError::Conflict("native literal bank borrowed"))?;
        for _ in 0..2 {
            observer.shared_original(MetadataSharedKind::FrameBank, frames.as_ref())?;
            bank.observe_owned11_metadata(observer)?;
        }
        connection
            .native5_blobs
            .as_ref()
            .ok_or(ProviderError::Correlation("native blob owner absent"))?
            .borrowed_owned11_protocol_view()?
            .observe_owned11_metadata(observer)?;
        observer.shared_original(
            MetadataSharedKind::NativeSupervisor,
            connection.supervisor.as_ref(),
        )?;
        connection
            .original_native_owned11_admission()?
            .observe_owned11_metadata(connection, observer)
    }
}

impl<S: ProviderStream> Connection<S> {
    pub(crate) fn native_owned11_preflight(
        &mut self,
        cut: ProtocolCaptureCut,
    ) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        if self.role != EndpointRole::Provider {
            return Err(ProviderError::Correlation(
                "native complete capture requires provider",
            ));
        }
        if self.original_complete_restoration.is_some()
            || self.original_restore_inputs.is_some()
            || self.original_restore_responses.iter().any(Option::is_some)
        {
            return Err(ProviderError::Correlation(
                "installed restoration owner requires extended native complete class",
            ));
        }
        self.original_native_owned11_admission()?;
        self.check_authority()?;
        let bank = self
            .original_frames
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "native complete literal bank absent",
            ))?
            .try_borrow()
            .map_err(|_| ProviderError::Conflict("native complete literal bank borrowed"))?;
        if !bank.complete() {
            return Err(ProviderError::Correlation(
                "native complete literal I/O unfinished",
            ));
        }
        self.guard.protocol_cut(cut)
    }
}

impl Connection<crate::client::DeadlineStream> {
    /// Captures the actual service with complete typed owners and original banks.
    ///
    /// # Errors
    /// Refuses foreign/revoked owners, partial cuts, unsupported service roots,
    /// mismatched selected banks or insufficient exact metadata/byte credit.
    pub(crate) fn capture_original_native_owned11(
        &mut self,
        reservation: &mut ProtocolSnapshotReservation,
        blobs: &crate::blob::BlobReceiver,
        cut: ProtocolCaptureCut,
        context: &crate::reference_packet::service::OriginalNativeCaptureContext<'_>,
    ) -> Result<(), ProviderError> {
        self.native_owned11_preflight(cut)?;
        self.preflight_protocol_reservation(reservation)?;
        reservation.validate_source_encoding(self.native5_codec.as_ref(), cut, false)?;
        if !reservation.uses_owned11_encoding()
            || self
                .native5_blobs
                .as_ref()
                .is_none_or(|owner| !blobs.same_protocol_owner(owner))
        {
            return Err(ProviderError::Correlation(
                "native complete bank/blob selection changed",
            ));
        }
        {
            // From this point the service loan holds registrar and supervisor guards.
            // No containment, registration callback or transport operation is called.
            let service = context.borrow_original(self, blobs)?;
            let receiver = blobs.borrowed_owned11_protocol_view(&self.authority)?;
            let connection = NativeConnectionView(self);
            let data = (
                "source-private.native-state/11",
                &connection,
                &receiver,
                &service,
            );
            let quote = reservation.quote_original_native_owned11(&data, |observer| {
                connection.observe(observer)?;
                receiver.observe_owned11_metadata(observer)?;
                service.observe_owned11_metadata(observer)
            })?;
            let limits = self.original_native5_protocol_metadata_limits()?.ok_or(
                ProviderError::Correlation("native complete metadata selection absent"),
            )?;
            let selected_rows = match cut {
                ProtocolCaptureCut::NativeIncomingCapture => limits.native_before_rows,
                ProtocolCaptureCut::HostSettled => limits.native_after_rows,
            };
            if quote.selected_rows as u64 != selected_rows.get() {
                return Err(ProviderError::Correlation(
                    "native complete physical metadata bank differs from source selection",
                ));
            }
            if quote.encoded_extent > reservation.maximum_bytes() {
                return Err(ProviderError::ResourceExhausted(
                    "native complete encoded credit",
                ));
            }
            reservation.bind(
                &self.authority,
                &self.protocol_owner,
                cut,
                service.original_cut(),
            )?;
            reservation.retain_native5_codec(self.native5_codec.as_ref())?;
            reservation.encode_owned11(&data)?;
        }
        self.retain_frozen_protocol_frames(reservation)
    }
}

/// Reports an encoded upper bound for the complete settled native service view.
///
/// Raw incoming ACK and outgoing lifetime bank admission remain separate. This
/// count never predicts a receipt, mutates correlations or creates a snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeOwned11AfterProtocolCapacityFacts {
    pub(crate) current_encoded_bytes: usize,
    pub(crate) frame_bank_views: usize,
    pub(crate) maximum_literal_encoded_bytes: usize,
    pub(crate) maximum_descriptor_encoded_bytes: usize,
    pub(crate) maximum_metadata_growth_bytes: usize,
    pub(crate) maximum_counter_growth_bytes: usize,
    pub(crate) maximum_after_encoded_bytes: usize,
    pub(crate) reserved_after_encoded_bytes: usize,
}

impl Connection<crate::client::DeadlineStream> {
    pub(super) fn preflight_native_owned11_after_protocol_capacity_inner(
        &self,
        reservation: &mut ProtocolSnapshotReservation,
        blobs: &crate::blob::BlobReceiver,
        context: &crate::reference_packet::service::OriginalNativeCaptureContext<'_>,
        prepared: &[Envelope],
    ) -> Result<NativeOwned11AfterProtocolCapacityFacts, ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        self.original_native_owned11_admission()?;
        if self.role != EndpointRole::Provider
            || !reservation.unused_for_after_preflight()
            || !reservation.uses_owned11_encoding()
        {
            return Err(ProviderError::Correlation(
                "native after quote requires unused original owned bank",
            ));
        }
        self.guard.authenticate_prepared_capture_suffix(prepared)?;
        if self
            .native5_blobs
            .as_ref()
            .is_none_or(|owner| !blobs.same_protocol_owner(owner))
        {
            return Err(ProviderError::Correlation(
                "native after quote blob owner changed",
            ));
        }
        reservation.validate_source_encoding(
            self.native5_codec.as_ref(),
            ProtocolCaptureCut::HostSettled,
            false,
        )?;
        let selected_rows = self
            .original_native5_protocol_metadata_limits()?
            .ok_or(ProviderError::Correlation(
                "native after metadata selection absent",
            ))?
            .native_after_rows;
        let bank = self
            .original_frames
            .as_ref()
            .ok_or(ProviderError::Correlation("native after bank absent"))?
            .try_borrow()
            .map_err(|_| ProviderError::Conflict("native after bank borrowed"))?;
        reservation.validate_literal_reservation(&bank)?;
        let (literal_growth, descriptor_growth) = bank.maximum_encoding_growth(true)?;
        let service = context.borrow_original(self, blobs)?;
        let receiver = blobs.borrowed_owned11_protocol_view(&self.authority)?;
        let connection = NativeConnectionView(self);
        let data = (
            "source-private.native-state/11",
            &connection,
            &receiver,
            &service,
        );
        let quote = reservation.quote_original_native_owned11(&data, |observer| {
            connection.observe(observer)?;
            receiver.observe_owned11_metadata(observer)?;
            service.observe_owned11_metadata(observer)
        })?;
        if quote.selected_rows as u64 != selected_rows.get() {
            return Err(ProviderError::Correlation(
                "native after physical metadata bank differs from selected source",
            ));
        }
        // Each recorded FrameBank strong view serializes the actual complete bank.
        // The fixed successful suffix adds only its literal/descriptors and
        // sequence/reader counters: pending Capture and proof maps are removed at
        // settlement. The same blob/policy/bootstrap owners stay borrowed here.
        let maximum_literal_encoded_bytes =
            literal_growth.checked_mul(quote.frame_bank_views).ok_or(
                ProviderError::ResourceExhausted("native after literal bound"),
            )?;
        let maximum_descriptor_encoded_bytes = descriptor_growth
            .checked_mul(quote.frame_bank_views)
            .ok_or(ProviderError::ResourceExhausted(
                "native after descriptor bound",
            ))?;
        // Complete metadata populations are independently bounded by the born
        // rows. A record is at most80 ASCII bytes (two usize decimals<=20), and
        // an alias is at most128 (closed names +bounded index). Charge the entire
        // maximum again, conservatively, instead of crediting current row removal.
        let maximum_metadata_growth_bytes = quote
            .selected_rows
            .checked_mul(80 + 128)
            .and_then(|n| n.checked_add(4))
            .ok_or(ProviderError::ResourceExhausted(
                "native after metadata bound",
            ))?;
        let maximum_counter_growth_bytes = 256usize;
        let maximum_after_encoded_bytes = quote
            .encoded_extent
            .checked_add(maximum_literal_encoded_bytes)
            .and_then(|n| n.checked_add(maximum_descriptor_encoded_bytes))
            .and_then(|n| n.checked_add(maximum_metadata_growth_bytes))
            .and_then(|n| n.checked_add(maximum_counter_growth_bytes))
            .filter(|n| *n <= reservation.maximum_bytes())
            .ok_or(ProviderError::ResourceExhausted(
                "native complete after encoding credit",
            ))?;
        Ok(NativeOwned11AfterProtocolCapacityFacts {
            current_encoded_bytes: quote.encoded_extent,
            frame_bank_views: quote.frame_bank_views,
            maximum_literal_encoded_bytes,
            maximum_descriptor_encoded_bytes,
            maximum_metadata_growth_bytes,
            maximum_counter_growth_bytes,
            maximum_after_encoded_bytes,
            reserved_after_encoded_bytes: reservation.maximum_bytes(),
        })
    }
}

impl<S: ProviderStream> Connection<S> {
    pub(crate) fn prepare_archived_protocol_mapping(
        &mut self,
        input: crate::protocol_snapshot::ArchivedProtocolMappingInput<'_>,
        controller: &Rc<crate::protocol_snapshot::ProtocolCaptureOwner>,
        cut: crate::operational_time::OperationalDeadline,
    ) -> Result<crate::protocol_snapshot::PreparedArchivedProtocolMapping, ProviderError> {
        self.authenticate_native5_source_codec()?;
        if self.role != EndpointRole::Controller {
            return Err(ProviderError::Correlation(
                "archived mapping requires actual controller",
            ));
        }
        self.protocol_capture_preflight(ProtocolCaptureCut::HostSettled)?;
        let codec = self
            .native5_codec
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "archived mapping sealed codec absent",
            ))?;
        if !matches!(
            self.original_native5_capture_profile()?,
            crate::reference_packet::service::PacketNative5CaptureProfile::OwnedProtocol11 { .. }
        ) {
            return Err(ProviderError::Correlation(
                "archived mapping target requires complete owned profile",
            ));
        }
        crate::protocol_snapshot::PreparedArchivedProtocolMapping::prepare(
            input,
            crate::protocol_snapshot::ArchivedProtocolMappingTarget {
                fresh: &self.authority,
                controller_owner: controller,
                connection_owner: &self.protocol_owner,
                codec,
                cut,
            },
        )
    }

    pub(crate) fn authenticate_archived_protocol_mapping(
        &self,
        mapping: &crate::protocol_snapshot::PreparedArchivedProtocolMapping,
        controller: &Rc<crate::protocol_snapshot::ProtocolCaptureOwner>,
        cut: crate::operational_time::OperationalDeadline,
    ) -> Result<(), ProviderError> {
        self.authenticate_native5_source_codec()?;
        mapping.authenticate_target(
            &self.authority,
            controller,
            &self.protocol_owner,
            self.native5_codec.as_ref(),
            cut,
        )
    }
}

impl<S: ProviderStream> Connection<S> {
    pub(crate) fn authenticate_archived_protocol_transfer_mapping(
        &self,
        mapping: &crate::protocol_snapshot::PreparedArchivedProtocolMapping,
        controller: &Rc<crate::protocol_snapshot::ProtocolCaptureOwner>,
    ) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        if self.role != EndpointRole::Controller || self.original_native5_complete_restore_selection()?
            != Some(crate::reference_packet::service::complete_restore::PacketNative5CompleteRestoreSelection::SourceSignedTransfer12) {
            return Err(ProviderError::Correlation("archive transfer source mechanism unselected"));
        }
        mapping.authenticate_registration_target(
            &self.authority,
            controller,
            &self.protocol_owner,
            self.native5_codec.as_ref(),
        )
    }
}

impl Connection<crate::client::DeadlineStream> {
    /// Walks actual native Connection roots before selected restoration begins.
    ///
    /// This measurement is separate from serialization and admission. It must
    /// precede the service registrar/supervisor loan and the boot attempt; those
    /// later owners have independently measured, retained quote terms.
    pub(crate) fn observe_original_restore_connection_metadata(
        &self,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        let Self {
            reader: _,
            authority: _,
            guard: _,
            supervisor: _,
            schemas: _,
            protocol_owner: _,
            native5_blobs: _,
            native5_codec: _,
            original_restore_inputs,
            original_restore_responses,
            original_complete_restoration,
            original_canonical_ack_admission: _,
            packet_schema: _,
            original_frames: _,
            connected_packet_schema: _,
            fenced,
            role,
        } = self;
        if *role != EndpointRole::Provider
            || *fenced
            || original_restore_inputs.is_some()
            || original_complete_restoration.is_some()
            || original_restore_responses.iter().any(Option::is_some)
        {
            return Err(ProviderError::Correlation(
                "restore quote Connection owner phase",
            ));
        }
        NativeConnectionView(self).observe(observer)
    }
}

impl NativeConnectionView<'_> {
    pub(super) fn observe_unique_capture_metadata(
        &self,
        roots: &mut crate::retained_metadata::NativeCaptureMetadataRoots,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        let connection = self.0;
        let Connection {
            reader,
            authority,
            guard,
            supervisor,
            schemas,
            protocol_owner,
            native5_blobs,
            native5_codec,
            original_canonical_ack_admission,
            original_restore_inputs,
            original_restore_responses,
            original_complete_restoration,
            packet_schema: _,
            original_frames,
            connected_packet_schema: _,
            fenced,
            role,
        } = connection;
        if *fenced
            || *role != EndpointRole::Provider
            || original_restore_inputs.is_some()
            || original_complete_restoration.is_some()
            || original_restore_responses.iter().any(Option::is_some)
        {
            return Err(ProviderError::Correlation(
                "native unique Capture SDK phase differs",
            ));
        }
        roots.observe_shared(
            observer,
            MetadataSharedKind::ProtocolOwner,
            protocol_owner.as_ref(),
        )?;
        authority.observe_unique_capture_metadata(roots, observer)?;
        guard.observe_owned_metadata(observer)?;
        let codec = native5_codec
            .as_ref()
            .ok_or(ProviderError::Correlation("native unique codec absent"))?;
        let Native5CodecOwner::NativePacket(policy) = codec.as_ref() else {
            return Err(ProviderError::Correlation(
                "native unique codec role differs",
            ));
        };
        if !std::ptr::addr_eq(Rc::as_ptr(schemas), Rc::as_ptr(policy)) {
            return Err(ProviderError::Correlation(
                "native unique erased policy differs",
            ));
        }
        // The erased verifier is a real separate strong edge to the policy;
        // the codec enum is its own Rc allocation and owns another policy edge.
        roots.observe_shared_edge(observer, MetadataSharedKind::NativePolicy, schemas.as_ref())?;
        if roots.observe_shared(observer, MetadataSharedKind::Codec, codec.as_ref())?
            && roots.observe_shared(observer, MetadataSharedKind::NativePolicy, policy.as_ref())?
        {
            policy.observe_unique_capture_metadata(roots, observer)?;
        }
        let frames = original_frames.as_ref().ok_or(ProviderError::Correlation(
            "native unique frame bank absent",
        ))?;
        let reader_facts = reader.original_owned11_facts(frames)?;
        if reader_facts.failed {
            return Err(ProviderError::Correlation("native unique reader failed"));
        }
        for _ in 0..2 {
            if roots.observe_shared(observer, MetadataSharedKind::FrameBank, frames.as_ref())? {
                frames
                    .try_borrow()
                    .map_err(|_| ProviderError::Conflict("native unique bank borrowed"))?
                    .observe_owned11_metadata(observer)?;
            }
        }
        reader
            .stream_ref()
            .observe_unique_capture_metadata(roots, observer)?;
        native5_blobs
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "native unique blob owner absent",
            ))?
            .borrowed_owned11_protocol_view()?
            .observe_unique_capture_metadata(roots, observer)?;
        roots.observe_shared_edge(
            observer,
            MetadataSharedKind::NativeSupervisor,
            supervisor.as_ref(),
        )?;
        let token = original_canonical_ack_admission
            .as_ref()
            .ok_or(ProviderError::Correlation("native unique ACK token absent"))?;
        token.observe_unique_capture_metadata(connection, roots, observer)
    }
}

impl<S: ProviderStream> Connection<S> {
    pub(crate) fn prepare_original_selected_archived_mapping(
        &mut self,
        input: crate::protocol_snapshot::ArchivedProtocolMappingInput<'_>,
        controller: &Rc<crate::protocol_snapshot::ProtocolCaptureOwner>,
        cut: crate::operational_time::OperationalDeadline,
    ) -> Result<crate::protocol_snapshot::PreparedArchivedProtocolMapping, ProviderError> {
        self.authenticate_native5_source_codec()?;
        if self.role != EndpointRole::Controller {
            return Err(ProviderError::Correlation(
                "archived mapping requires actual controller",
            ));
        }
        self.protocol_capture_preflight(ProtocolCaptureCut::HostSettled)?;
        let codec = self
            .native5_codec
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "archived mapping sealed codec absent",
            ))?;
        if !matches!(
            self.original_native5_capture_profile()?,
            crate::reference_packet::service::PacketNative5CaptureProfile::OwnedProtocol11 { .. }
        ) {
            return Err(ProviderError::Correlation(
                "archived mapping target requires complete owned profile",
            ));
        }
        crate::protocol_snapshot::PreparedArchivedProtocolMapping::prepare_selected(
            input,
            crate::protocol_snapshot::ArchivedProtocolMappingTarget {
                fresh: &self.authority,
                controller_owner: controller,
                connection_owner: &self.protocol_owner,
                codec,
                cut,
            },
        )
    }
}
