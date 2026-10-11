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
                original_response_loss: None,
            },
            peer,
        ))
    }
}
