//! Lends raw session ownership for the dedicated retained Transfer12 branch.
//!
//! Same-registration and known supervisor associations survive fencing. These
//! checks copy no owner, renew no deadline and grant no live effect authority.

use super::*;
use crate::connection::{OriginalProtocolSupervisor, OriginalRetainedSupervisor};
use std::mem::size_of;

fn field_view_bytes<T>(_: impl FnOnce(&'static ClientSession) -> T) -> usize {
    size_of::<T>()
}

impl ClientSession {
    pub(in crate::client) fn original_restoration_metadata_counter_scratch_data() -> usize {
        field_view_bytes(|session| {
            let ClientSession {
                connection,
                authority,
                deadline,
                bootstrap_hello_cut: _,
                sequence,
                peer_pid,
                peer_executable,
                original_ack_hello,
                original_response_loss,
            } = session;
            (
                connection,
                authority,
                deadline,
                sequence,
                peer_pid,
                peer_executable,
                original_ack_hello,
                original_response_loss,
            )
        }) + Connection::<DeadlineStream>::original_restoration_metadata_counter_scratch_data()
            + size_of::<Result<(), ProviderError>>()
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
            + size_of::<
                std::cell::Ref<
                    'static,
                    crate::transport::original_frames::OriginalFrameReservation,
                >,
            >()
    }

    fn authenticate_original_restoration_registration_data(&self) -> Result<(), ProviderError> {
        if self.original_response_loss.is_some() {
            return Err(ProviderError::Correlation(
                "raw restoration mutable loss callback unsupported",
            ));
        }
        self.connection
            .authenticate_original_restoration_registration_data(&self.authority)
    }

    pub(in crate::client) fn authenticate_original_retained_supervisor_data(
        &self,
        owner: &OriginalRetainedSupervisor,
    ) -> Result<(), ProviderError> {
        self.authenticate_original_restoration_registration_data()?;
        owner.authenticate_original_connection_data(&self.connection)
    }

    pub(in crate::client) fn authenticate_original_protocol_supervisor_data(
        &self,
        witness: &OriginalProtocolSupervisor,
    ) -> Result<(), ProviderError> {
        self.authenticate_original_restoration_registration_data()?;
        witness.authenticate_original_connection_data(&self.connection)
    }

    pub(in crate::client) fn observe_original_restoration_metadata(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), ProviderError> {
        if self.original_response_loss.is_some() {
            return Err(ProviderError::Correlation(
                "owned protocol mutable callback",
            ));
        }
        self.authenticate_original_restoration_registration_data()?;
        self.connection
            .observe_original_restoration_metadata(observer)?;
        self.authority.observe_retained_metadata(observer)?;
        observer.observe(&self.sequence)?;
        observer.observe(&self.peer_pid)?;
        observer.observe(&self.peer_executable)?;
        // The actual Hello literal bank is encoded separately with full byte and
        // descriptor capacities; this metadata walk charges its shared header.
        if let Some(bank) = &self.original_ack_hello {
            observer.shared_original(
                crate::retained_metadata::aliases::MetadataSharedKind::HelloBank,
                bank.as_ref(),
            )?;
        }
        Ok(())
    }

    pub(in crate::client) fn observe_original_restoration_metadata_extras(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), ProviderError> {
        let Self {
            connection,
            authority: _,
            deadline,
            bootstrap_hello_cut: _,
            sequence: _,
            peer_pid: _,
            peer_executable: _,
            original_ack_hello,
            original_response_loss,
        } = self;
        if original_response_loss.is_some() {
            return Err(ProviderError::Correlation(
                "live host metadata mutable loss callback",
            ));
        }
        self.authenticate_original_restoration_registration_data()?;
        connection.observe_original_restoration_metadata_extras(observer)?;
        deadline.observe_owned11_metadata(observer)?;
        if let Some(bank) = original_ack_hello {
            // The existing tuple metadata already counts this Session Rc edge.
            // This additive live walk includes its actual bytes/descriptors.
            bank.try_borrow()
                .map_err(|_| ProviderError::Conflict("live host Hello bank borrowed"))?
                .observe_owned11_metadata(observer)?;
        }
        Ok(())
    }
}

#[cfg(all(test, unix))]
impl ClientSession {
    /// Builds actual local owners for raw census controls, without native authority.
    pub(in crate::client) fn restoration_retained_fixture() -> (
        Handshake,
        Self,
        OriginalRetainedSupervisor,
        OriginalProtocolSupervisor,
        std::os::unix::net::UnixStream,
    ) {
        // Raw census needs the real base codec owner, not ACK-specific metadata.
        let (handshake, authority, selection, coordinator) =
            crate::reference_packet::coordinator::original_native5_controller_scope();
        let (stream, peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let (stream, deadline) = DeadlineStream::new(stream, Duration::from_secs(30)).unwrap();
        let (operational, owner) = OriginalRetainedSupervisor::reserve().unwrap();
        let mut connection = Connection::new(
            stream,
            authority.clone(),
            operational,
            Rc::new(FixtureSchemas),
            crate::connection::EndpointRole::Controller,
        )
        .unwrap();
        let mut bank = Some(
            crate::transport::original_frames::OriginalFrameReservation::reserve(1024 * 1024, 64)
                .unwrap(),
        );
        connection
            .install_native5_controller_codec(&mut bank, selection, coordinator)
            .unwrap();
        let witness = connection.retain_original_protocol_supervisor().unwrap();
        let bootstrap_hello_cut = bootstrap_cut::OriginalBootstrapHelloCut::capture(&deadline);
        let session = Self {
            connection,
            authority,
            deadline,
            bootstrap_hello_cut,
            sequence: U64::new(2),
            peer_pid: std::process::id(),
            peer_executable: canonical::content_ref(
                b"fixture executable",
                "application/octet-stream",
            )
            .unwrap(),
            original_ack_hello: None,
            original_response_loss: None,
        };
        (handshake, session, owner, witness, peer)
    }

    pub(in crate::client) fn fence_restoration_retained_fixture(&mut self) {
        self.connection.fence_restoration_retained_fixture();
    }
}

#[cfg(all(test, unix))]
struct FixtureSchemas;

#[cfg(all(test, unix))]
impl BodySchemaVerifier for FixtureSchemas {
    fn verify(
        &self,
        _: &ConnectionAuthority,
        _: &Envelope,
        _: &ReceivedBody,
    ) -> Result<(), ProviderError> {
        Err(ProviderError::Correlation(
            "raw census fixture has no effect verifier",
        ))
    }
}
