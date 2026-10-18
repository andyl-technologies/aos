//! Lends the current concrete Connection17 logical state and real shared edges.
//!
//! This component contains current fields only. Immutable imported ancestry is
//! a separate verified DAG in the enclosing archive. It constructs no stream,
//! registrar, deadline, native token or Capture permit on decode.

use super::*;
use crate::client::DeadlineStream;
use crate::retained_metadata::{MetadataObserver, aliases::MetadataSharedKind};
use crate::transport::original_frames::OriginalFrameReservation;
use serde::{
    Serialize,
    ser::{SerializeSeq, SerializeStruct},
};
use std::{
    cell::{Ref, RefCell},
    mem::size_of,
};

pub(crate) struct ConnectionSettledHistoryData<'a> {
    connection: &'a Connection<DeadlineStream>,
    frames: Ref<'a, OriginalFrameReservation>,
    reader: crate::transport::OriginalFrameReaderFacts,
}

impl Connection<DeadlineStream> {
    pub(crate) fn authenticate_settled_history_supervisor_data<T: ConnectionSupervisor>(
        &self,
        supervisor: &Rc<T>,
    ) -> Result<(), ProviderError> {
        if !std::ptr::addr_eq(Rc::as_ptr(&self.supervisor), Rc::as_ptr(supervisor)) {
            return Err(refused());
        }
        Ok(())
    }

    pub(crate) fn borrowed_settled_history_data(
        &self,
    ) -> Result<ConnectionSettledHistoryData<'_>, ProviderError> {
        let codec = self.native5_codec.as_ref().ok_or_else(refused)?;
        if !std::ptr::addr_eq(Rc::as_ptr(&self.schemas), Rc::as_ptr(codec)) {
            return Err(refused());
        }
        let bank = self.original_frames.as_ref().ok_or_else(refused)?;
        let reader = self.reader.original_owned11_facts(bank)?;
        let frames = bank
            .try_borrow()
            .map_err(|_| ProviderError::Conflict("current17 literal bank borrowed"))?;
        Ok(ConnectionSettledHistoryData {
            connection: self,
            frames,
            reader,
        })
    }

    pub(crate) fn observe_settled_history_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let view = self.borrowed_settled_history_data()?;
        let Self {
            reader,
            authority,
            guard,
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
        authority.observe_retained_metadata(observer)?;
        guard.observe_owned_metadata(observer)?;
        observer.shared_original(MetadataSharedKind::ProtocolOwner, protocol_owner.as_ref())?;
        observer.shared_original(
            match role {
                EndpointRole::Controller => MetadataSharedKind::HostSupervisor,
                EndpointRole::Provider => MetadataSharedKind::NativeSupervisor,
            },
            supervisor.as_ref(),
        )?;
        let codec = native5_codec.as_ref().ok_or_else(refused)?;
        // Both typed codec and erased verifier are the same checked allocation.
        for _ in 0..2 {
            observer.shared_original(MetadataSharedKind::Codec, codec.as_ref())?;
            codec.observe_settled_history_metadata_data(observer)?;
        }
        if let Some(blobs) = native5_blobs {
            blobs
                .borrowed_owned11_protocol_view()?
                .observe_owned11_metadata(observer)?;
        }
        if let Some(inputs) = original_restore_inputs {
            inputs.observe_settled_history_metadata_data(observer)?;
        }
        for response in original_restore_responses.iter().flatten() {
            observer
                .shared_original(MetadataSharedKind::NativeRestoreResponse, response.as_ref())?;
            response
                .try_borrow()
                .map_err(|_| ProviderError::Conflict("current17 response borrowed"))?
                .observe_settled_history_metadata_data(observer)?;
        }
        if let Some(installed) = original_complete_restoration {
            installed.observe_settled_history_metadata_data(observer)?;
        }
        if let Some(admitted) = original_canonical_ack_admission {
            admitted.observe_settled_history_metadata_data(observer)?;
        }
        let bank = original_frames.as_ref().ok_or_else(refused)?;
        observer.shared_original(MetadataSharedKind::FrameBank, bank.as_ref())?;
        view.frames.observe_owned11_metadata(observer)?;
        reader.observe_original_host_live_metadata(bank, observer)?;
        observer.observe(packet_schema)?;
        observer.observe(connected_packet_schema)?;
        observer.observe(fenced)
    }

    pub(crate) fn settled_history_counter_scratch_data() -> usize {
        size_of::<ConnectionSettledHistoryData<'static>>()
            +size_of::<Result<ConnectionSettledHistoryData<'static>,ProviderError>>()
            +size_of::<&Self>()
            +size_of::<Ref<'static,OriginalFrameReservation>>()
            +size_of::<Result<Ref<'static,OriginalFrameReservation>,std::cell::BorrowError>>()
            +size_of::<Result<Ref<'static,OriginalFrameReservation>,ProviderError>>()
            +size_of::<crate::transport::OriginalFrameReaderFacts>()
            +size_of::<Result<crate::transport::OriginalFrameReaderFacts,ProviderError>>()
            +size_of::<Ref<'static,restore_response::AssignedNativeRestoreResponse>>()
            +size_of::<Result<Ref<'static,restore_response::AssignedNativeRestoreResponse>,std::cell::BorrowError>>()
            +size_of::<Result<Ref<'static,restore_response::AssignedNativeRestoreResponse>,ProviderError>>()
            +size_of::<NativeResponses<'static>>()
            +size_of::<std::slice::Iter<'static,Option<Rc<RefCell<restore_response::AssignedNativeRestoreResponse>>>>>()
            +size_of::<std::iter::Flatten<std::slice::Iter<'static,Option<Rc<RefCell<restore_response::AssignedNativeRestoreResponse>>>>>>()
            +size_of::<std::ops::Range<usize>>()
            +size_of::<Result<(),ProviderError>>()
            +size_of::<&mut MetadataObserver<'static>>()
            +ConnectionAuthority::settled_history_counter_scratch_data()
            +Native5CodecOwner::settled_history_counter_scratch_data()
            +restore_inputs::InstalledCompleteRestoreInputs::settled_history_counter_scratch_data()
            +restore_response::AssignedNativeRestoreResponse::settled_history_counter_scratch_data()
            +complete_installation::InstalledNativeCompleteRestoration::settled_history_counter_scratch_data()
            +crate::reference_packet::service::ack_emitter::VerifiedCanonicalAckAdmission::settled_history_counter_scratch_data()
    }
}

struct NativeResponses<'a>(
    &'a [Option<Rc<RefCell<restore_response::AssignedNativeRestoreResponse>>>; 2],
);

impl Serialize for NativeResponses<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(2))?;
        for response in self.0 {
            if let Some(response) = response {
                let response = response.try_borrow().map_err(serde::ser::Error::custom)?;
                sequence.serialize_element(&Some(
                    response
                        .borrowed_settled_history_data()
                        .map_err(serde::ser::Error::custom)?,
                ))?;
            } else {
                sequence.serialize_element(&Option::<()>::None)?;
            }
        }
        sequence.end()
    }
}

impl Serialize for ConnectionSettledHistoryData<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let Connection {
            reader: _,
            authority,
            guard,
            supervisor: _,
            schemas: _,
            protocol_owner: _,
            native5_blobs,
            native5_codec,
            original_restore_inputs,
            original_restore_responses,
            original_complete_restoration,
            original_canonical_ack_admission,
            packet_schema,
            original_frames: _,
            connected_packet_schema,
            fenced,
            role,
        } = self.connection;
        let mut fields = serializer.serialize_struct("CurrentConnection17", 17)?;
        fields.serialize_field("schema", "source-private.connection-restored-settled/17")?;
        fields.serialize_field("authority", &authority.borrowed_settled_history_data())?;
        fields.serialize_field("correlations", &guard.protocol_view())?;
        fields.serialize_field(
            "codec",
            &native5_codec
                .as_ref()
                .map(|codec| codec.settled_history_data()),
        )?;
        fields.serialize_field(
            "blobs",
            &native5_blobs
                .as_ref()
                .map(|blobs| blobs.borrowed_owned11_protocol_view())
                .transpose()
                .map_err(serde::ser::Error::custom)?,
        )?;
        fields.serialize_field(
            "restore_inputs",
            &original_restore_inputs
                .as_ref()
                .map(|value| value.borrowed_settled_history_data())
                .transpose()
                .map_err(serde::ser::Error::custom)?,
        )?;
        fields.serialize_field(
            "restore_responses",
            &NativeResponses(original_restore_responses),
        )?;
        fields.serialize_field(
            "complete_restoration",
            &original_complete_restoration
                .as_ref()
                .map(|value| value.borrowed_settled_history_data())
                .transpose()
                .map_err(serde::ser::Error::custom)?,
        )?;
        fields.serialize_field(
            "canonical_ack_admission",
            &original_canonical_ack_admission
                .as_ref()
                .map(|value| value.borrowed_settled_history_data())
                .transpose()
                .map_err(serde::ser::Error::custom)?,
        )?;
        fields.serialize_field("frames", &self.frames.protocol_view_with_encoding(true))?;
        fields.serialize_field("reader", &self.reader)?;
        fields.serialize_field("packet_schema", packet_schema)?;
        fields.serialize_field("connected_packet_schema", connected_packet_schema)?;
        fields.serialize_field("fenced", fenced)?;
        fields.serialize_field(
            "role",
            &match role {
                EndpointRole::Controller => "controller",
                EndpointRole::Provider => "provider",
            },
        )?;
        fields.serialize_field("protocol_owner_role", "same-current-connection-actor")?;
        fields.serialize_field(
            "supervisor_role",
            &match role {
                EndpointRole::Controller => "actual-retained-host-supervisor",
                EndpointRole::Provider => "actual-native-service-supervisor",
            },
        )?;
        fields.end()
    }
}

fn refused() -> ProviderError {
    ProviderError::Correlation("current17 Connection owner differs")
}

impl Connection<DeadlineStream> {
    pub(crate) fn authenticate_archived_mapping_history_data(
        &self,
        mapping: &crate::protocol_snapshot::PreparedArchivedProtocolMapping,
        controller: &Rc<crate::protocol_snapshot::ProtocolCaptureOwner>,
    ) -> Result<(), ProviderError> {
        mapping.authenticate_history_target_data(
            &self.authority,
            controller,
            &self.protocol_owner,
            self.native5_codec.as_ref(),
        )
    }

    pub(crate) fn authenticate_settled_session_parent_data(
        &self,
        authority: &ConnectionAuthority,
        deadline: &crate::client::ExchangeDeadline,
    ) -> Result<(), ProviderError> {
        if !authority.same_registration(&self.authority) || self.role != EndpointRole::Controller {
            return Err(refused());
        }
        self.reader
            .stream_ref()
            .authenticate_settled_history_deadline_data(deadline)
    }
}
