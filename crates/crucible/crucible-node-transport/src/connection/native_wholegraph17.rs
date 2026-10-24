//! Defines the real native Connection roots before any current17 role edges.
//!
//! The rooted variant changes only explicit wire roles. It authenticates the
//! same concrete codec, literal bank, installed mapping and stream deadline;
//! their complete payloads remain in the enclosing native17 protocol once.

use super::*;
use crate::client::DeadlineStream;
use crate::protocol_snapshot::PreparedArchivedNativeProtocolMapping;
use crate::reference_packet::Native5Policy;
use crate::retained_metadata::{MetadataObserver, aliases::MetadataSharedKind};
use crate::transport::original_frames::OriginalFrameReservation;
use serde::{
    Serialize,
    ser::{SerializeSeq, SerializeStruct},
};
use std::cell::{Ref, RefCell};

pub(crate) struct NativeConnectionPrelude17<'a> {
    connection: &'a Connection<DeadlineStream>,
    policy: &'a Rc<Native5Policy>,
    codec: &'a Rc<Native5CodecOwner>,
    frames: Ref<'a, OriginalFrameReservation>,
    mapping: Ref<'a, PreparedArchivedNativeProtocolMapping>,
}

pub(crate) struct NativeRootedConnection17<'a> {
    connection: &'a Connection<DeadlineStream>,
    reader: crate::transport::OriginalFrameReaderFacts,
}

impl Connection<DeadlineStream> {
    /// Borrows the exact installed native roots after their genuine token check.
    ///
    /// # Errors
    /// Refuses foreign origin, changed real roots or a conflicting mutable loan.
    pub(crate) fn borrowed_native_prelude17_data(
        &self,
    ) -> Result<NativeConnectionPrelude17<'_>, ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        if self.role != EndpointRole::Provider {
            return Err(refused());
        }
        let codec = self.native5_codec.as_ref().ok_or_else(refused)?;
        let Native5CodecOwner::NativePacket(policy) = codec.as_ref() else {
            return Err(refused());
        };
        let installed = self
            .original_complete_restoration
            .as_ref()
            .ok_or_else(refused)?;
        let mapping_owner = installed.borrowed_settled_mapping17_data()?;
        self.authenticate_installed_complete_restoration(mapping_owner)?;
        let mapping = mapping_owner.try_borrow().map_err(|_| refused())?;
        let frames = self
            .original_frames
            .as_ref()
            .ok_or_else(refused)?
            .try_borrow()
            .map_err(|_| refused())?;
        Ok(NativeConnectionPrelude17 {
            connection: self,
            policy,
            codec,
            frames,
            mapping,
        })
    }

    /// Borrows this same native Connection with full shared payloads rooted once.
    ///
    /// # Errors
    /// Refuses the same origins, schema identities or frame loans as the full view.
    pub(crate) fn borrowed_rooted_native17_data(
        &self,
    ) -> Result<NativeRootedConnection17<'_>, ProviderError> {
        self.protocol_owner.ensure_current()?;
        if self.role != EndpointRole::Provider {
            return Err(refused());
        }
        self.borrowed_settled_history_data()?;
        let reader = self
            .reader
            .original_owned11_facts(self.original_frames.as_ref().ok_or_else(refused)?)?;
        Ok(NativeRootedConnection17 {
            connection: self,
            reader,
        })
    }
}

impl NativeConnectionPrelude17<'_> {
    pub(crate) fn actor_data(&self) -> Result<impl Serialize + '_, ProviderError> {
        self.connection.protocol_owner.borrowed_native_root17_data()
    }

    pub(crate) fn codec_data(&self) -> impl Serialize + '_ {
        self.codec.settled_history_data()
    }

    pub(crate) fn frames_data(&self) -> impl Serialize + '_ {
        self.frames.protocol_view_with_encoding(true)
    }

    pub(crate) fn deadline_data(&self) -> &'static str {
        "native-shared-operational-deadline-history-only"
    }

    pub(crate) fn mapping_data(&self) -> Result<impl Serialize + '_, ProviderError> {
        self.mapping.borrowed_current17_data()
    }

    pub(crate) fn policy_data(&self) -> &Rc<Native5Policy> {
        self.policy
    }

    pub(crate) fn connection_data(&self) -> &Connection<DeadlineStream> {
        self.connection
    }

    pub(crate) fn observe_actor_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        observer.shared_original(
            MetadataSharedKind::ProtocolOwner,
            self.connection.protocol_owner.as_ref(),
        )?;
        self.connection
            .protocol_owner
            .observe_native_root17_metadata_data(observer)
    }

    pub(crate) fn observe_codec_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        observer.shared_original(MetadataSharedKind::Codec, self.codec.as_ref())?;
        self.codec.observe_settled_history_metadata_data(observer)
    }

    pub(crate) fn observe_frames_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        observer.shared_original(
            MetadataSharedKind::FrameBank,
            self.connection
                .original_frames
                .as_ref()
                .ok_or_else(refused)?
                .as_ref(),
        )?;
        self.frames.observe_owned11_metadata(observer)
    }

    pub(crate) fn observe_deadline_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        self.connection
            .reader
            .stream_ref()
            .observe_original_host_live_metadata(observer)
    }

    pub(crate) fn observe_mapping_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let installed = self
            .connection
            .original_complete_restoration
            .as_ref()
            .ok_or_else(refused)?;
        observer.shared_original(
            MetadataSharedKind::ArchivedMapping,
            installed.borrowed_settled_mapping17_data()?.as_ref(),
        )?;
        self.mapping.observe_current17_metadata_data(observer)
    }
}

struct RootedResponses17<'a>(
    &'a [Option<Rc<RefCell<restore_response::AssignedNativeRestoreResponse>>>; 2],
);

impl Serialize for RootedResponses17<'_> {
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

impl Serialize for NativeRootedConnection17<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.connection
            .borrowed_settled_history_data()
            .map_err(serde::ser::Error::custom)?;
        let Connection {
            reader: _,
            authority,
            guard,
            supervisor: _,
            schemas: _,
            protocol_owner: _,
            native5_blobs,
            native5_codec: _,
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
        fields.serialize_field("schema", "source-private.native-rooted-connection/17")?;
        fields.serialize_field("authority", &authority.borrowed_settled_history_data())?;
        fields.serialize_field("correlations", &guard.protocol_view())?;
        fields.serialize_field("codec", "native-connection-codec")?;
        fields.serialize_field(
            "blobs",
            &native5_blobs.as_ref().map(|_| "native-blob-ledger"),
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
            &RootedResponses17(original_restore_responses),
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
        fields.serialize_field("frames", "native-connection-frames")?;
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
    ProviderError::Correlation("native17 actual Connection roots unavailable")
}
