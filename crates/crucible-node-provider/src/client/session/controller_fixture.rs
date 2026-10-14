//! Constructs a socket-only controller model from an original inert SDK lease.
//!
//! No Child, peer measurement, Hello transport or native authority is claimed.
//! The source-only test fixture keeps the real connection gate and epoch so
//! construction refusal and moves can be checked without semantic operations.

use super::*;

impl ClientSession {
    /// Builds an inert socket-only session beneath an original model SDK lease.
    ///
    /// # Errors
    /// Returns socket, finite deadline or original registration refusal.
    pub(in crate::client) fn controller_fixture(
        authority: ConnectionAuthority,
        supervisor: Rc<dyn ConnectionSupervisor>,
        schemas: Rc<dyn BodySchemaVerifier>,
    ) -> Result<(Self, std::os::unix::net::UnixStream), ProviderError> {
        let (stream, peer) = std::os::unix::net::UnixStream::pair()?;
        let deadline = ExchangeDeadline::start(Duration::from_secs(30))?;
        let writer = DeadlineStream::with_deadline(stream, deadline.clone())?;
        let connection = Connection::new(
            writer,
            authority.clone(),
            supervisor,
            schemas,
            EndpointRole::Controller,
        )?;
        Ok((
            Self {
                connection,
                authority,
                deadline,
                sequence: U64::new(2),
                peer_pid: std::process::id(),
                peer_executable: canonical::content_ref(
                    b"inert controller model",
                    "application/octet-stream",
                )?,
                original_ack_hello: None,
                original_response_loss: None,
            },
            peer,
        ))
    }
    /// Retains two literal data-model Hello frames for historical decoder controls.
    ///
    /// This fixture does not claim actual Hello negotiation, a Child or source
    /// admission. It leaves the production original-journal path unchanged.
    pub(in crate::client) fn seed_owned11_model_hello(&mut self) -> Result<(), ProviderError> {
        use crate::transport::original_frames::{FrameDirection, OriginalFrameReservation};
        let mut bank = OriginalFrameReservation::reserve(16384, 4)?;
        for direction in [FrameDirection::Outgoing, FrameDirection::Incoming] {
            let bytes = b"{}";
            let slot = bank.begin(direction, 64)?;
            let length = u32::try_from(bytes.len())
                .map_err(|_| ProviderError::Frame("model Hello length"))?;
            bank.append(slot, &length.to_be_bytes())?;
            bank.append(slot, bytes)?;
            if direction == FrameDirection::Outgoing {
                bank.advance(slot, bytes.len() + 4)?;
            }
            bank.finish(slot)?;
        }
        self.original_ack_hello = Some(Rc::new(std::cell::RefCell::new(bank)));
        Ok(())
    }
}
