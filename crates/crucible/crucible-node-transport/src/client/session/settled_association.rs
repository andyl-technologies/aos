//! Compares actual historical SDK graph parents without testing live authority.
//!
//! These checks keep expired/revoked partial owners available to a separately
//! authenticated Source history walk. They acquire no gate, clone no Arc, invoke
//! no policy callback and cannot renew registration or authorize an operation.

use super::*;

impl ClientSession {
    pub(in crate::client) fn authenticate_original_ack_emitter_history_data(
        &self,
        owner: &Rc<crate::protocol_snapshot::ProtocolCaptureOwner>,
        registration: &crate::handshake::RegistrationRead,
        codec: &Rc<crate::connection::Native5CodecOwner>,
    ) -> Result<(), ProviderError> {
        if !registration.same_authority_data(&self.authority) {
            return Err(ProviderError::Correlation(
                "historical ACK Session registrar differs",
            ));
        }
        self.connection
            .authenticate_original_ack_emitter_history_data(owner, registration, codec)
    }

    pub(in crate::client) fn authenticate_source_registrar_history_data(
        &self,
        read: &crate::client::CnpRegistrarRead,
    ) -> Result<(), ProviderError> {
        if !read.same_authority_data(&self.authority) {
            return Err(ProviderError::Correlation(
                "historical Source Session registrar differs",
            ));
        }
        self.connection
            .authenticate_source_registrar_history_data(read)
    }

    pub(in crate::client) fn source_registrar_history_counter_scratch_data() -> usize {
        use std::mem::size_of;
        size_of::<&ClientSession>()
            + size_of::<&Rc<crate::protocol_snapshot::ProtocolCaptureOwner>>()
            + size_of::<&crate::handshake::RegistrationRead>()
            + size_of::<&crate::client::CnpRegistrarRead>()
            + size_of::<&crate::handshake::ConnectionAuthority>()
            + size_of::<&Rc<crate::connection::Native5CodecOwner>>()
            + size_of::<Option<&Rc<crate::connection::Native5CodecOwner>>>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<bool>()
            + crate::client::CnpRegistrarRead::settled_history_counter_scratch_data()
            + Connection::<DeadlineStream>::source_registrar_history_counter_scratch_data()
    }
}
