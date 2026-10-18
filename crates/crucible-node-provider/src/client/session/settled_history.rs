//! Lends the current Session17 namespace, journals' parent and literal Hello bank.
//!
//! Absolute operational coordinates are never portable; existing cuts retain
//! their real owner association and are represented only as nonrenewable roles.

use super::*;
use crate::{
    connection::OriginalRetainedSupervisor,
    retained_metadata::{MetadataObserver, aliases::MetadataSharedKind},
    transport::original_frames::OriginalFrameReservation,
};
use serde::{Serialize, ser::SerializeStruct};
use std::{cell::Ref, mem::size_of};

pub(in crate::client) struct SessionSettledHistoryData<'a> {
    session: &'a ClientSession,
    connection: crate::connection::ConnectionSettledHistoryData<'a>,
    hello: Option<Ref<'a, OriginalFrameReservation>>,
}

impl ClientSession {
    pub(in crate::client) fn capture_history_encoded_growth_data(
        &self,
    ) -> Result<usize, ProviderError> {
        // Session.sequence is independently encoded as a decimal U64 string.
        self.connection
            .capture_history_encoded_growth_data()?
            .checked_add(22)
            .ok_or(ProviderError::ResourceExhausted(
                "SDK Capture Session encoding",
            ))
    }

    pub(in crate::client) fn capture_history_encoding_counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<Result<usize, ProviderError>>()
            + crate::connection::Connection::<DeadlineStream>::capture_history_encoding_counter_scratch_data()
    }

    fn authenticate_settled_history_parent_data(&self) -> Result<(), ProviderError> {
        if self.original_response_loss.is_some() {
            return Err(ProviderError::Correlation(
                "current17 Session parent or callback differs",
            ));
        }
        // The defining Connection guard checks the actual registration, role
        // and original deadline association together without lending authority.
        self.connection
            .authenticate_settled_session_parent_data(&self.authority, &self.deadline)
    }

    pub(in crate::client) fn authenticate_settled_history_supervisor_data(
        &self,
        supervisor: &OriginalRetainedSupervisor,
    ) -> Result<(), ProviderError> {
        self.authenticate_settled_history_parent_data()?;
        supervisor.authenticate_settled_history_parent_data(&self.connection)
    }

    pub(in crate::client) fn borrowed_settled_history_data(
        &self,
    ) -> Result<SessionSettledHistoryData<'_>, ProviderError> {
        self.authenticate_settled_history_parent_data()?;
        let connection = self.connection.borrowed_settled_history_data()?;
        let hello = self
            .original_ack_hello
            .as_ref()
            .map(|bank| {
                bank.try_borrow()
                    .map_err(|_| ProviderError::Conflict("current17 Hello bank borrowed"))
            })
            .transpose()?;
        Ok(SessionSettledHistoryData {
            session: self,
            connection,
            hello,
        })
    }

    pub(in crate::client) fn observe_settled_history_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        self.authenticate_settled_history_parent_data()?;
        self.connection
            .observe_settled_history_metadata_data(observer)?;
        self.authority.observe_retained_metadata(observer)?;
        self.deadline.observe_owned11_metadata(observer)?;
        observer.observe(&self.sequence)?;
        observer.observe(&self.peer_pid)?;
        observer.observe(&self.peer_executable)?;
        if let Some(hello) = &self.original_ack_hello {
            observer.shared_original(MetadataSharedKind::HelloBank, hello.as_ref())?;
            hello
                .try_borrow()
                .map_err(|_| ProviderError::Conflict("current17 Hello metadata borrowed"))?
                .observe_owned11_metadata(observer)?;
        }
        Ok(())
    }

    pub(in crate::client) fn authenticate_archived_mapping_history_data(
        &self,
        mapping: &crate::protocol_snapshot::PreparedArchivedProtocolMapping,
        controller: &Rc<crate::protocol_snapshot::ProtocolCaptureOwner>,
    ) -> Result<(), ProviderError> {
        self.authenticate_settled_history_parent_data()?;
        self.connection
            .authenticate_archived_mapping_history_data(mapping, controller)
    }

    pub(in crate::client) fn settled_history_counter_scratch_data() -> usize {
        size_of::<SessionSettledHistoryData<'static>>()
            + size_of::<Result<SessionSettledHistoryData<'static>, ProviderError>>()
            + size_of::<Option<Ref<'static, OriginalFrameReservation>>>()
            + size_of::<Result<Option<Ref<'static, OriginalFrameReservation>>, ProviderError>>()
            + size_of::<Ref<'static, OriginalFrameReservation>>()
            + size_of::<Result<Ref<'static, OriginalFrameReservation>, std::cell::BorrowError>>()
            + size_of::<Result<Ref<'static, OriginalFrameReservation>, ProviderError>>()
            + size_of::<&ClientSession>()
            + size_of::<&OriginalRetainedSupervisor>()
            + size_of::<Result<(), ProviderError>>()
            + crate::connection::Connection::<DeadlineStream>::settled_history_counter_scratch_data(
            )
            + ConnectionAuthority::settled_history_counter_scratch_data()
    }
}

impl Serialize for SessionSettledHistoryData<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let ClientSession {
            connection: _,
            authority,
            deadline: _,
            sequence,
            peer_pid,
            peer_executable,
            original_ack_hello: _,
            original_response_loss: _,
        } = self.session;
        let mut fields = serializer.serialize_struct("CurrentSession17", 8)?;
        fields.serialize_field(
            "schema",
            "source-private.client-session-restored-settled/17",
        )?;
        fields.serialize_field("connection", &self.connection)?;
        fields.serialize_field("authority", &authority.borrowed_settled_history_data())?;
        fields.serialize_field("sequence", sequence)?;
        fields.serialize_field("peer_pid", peer_pid)?;
        fields.serialize_field("peer_executable", peer_executable)?;
        fields.serialize_field(
            "hello",
            &self
                .hello
                .as_ref()
                .map(|bank| bank.protocol_view_with_encoding(true)),
        )?;
        fields.serialize_field("operational_cut", "same-stream-historical-nonrenewable-cut")?;
        fields.end()
    }
}
