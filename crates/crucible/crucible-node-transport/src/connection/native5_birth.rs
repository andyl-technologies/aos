//! Owning complete-source connection births without implicit transport release.
//!
//! Refusals retain the original socket, registrar and callbacks. These helpers
//! install framing only; the actual source must separately install its sealed
//! codec and retain Hello, private launch and native process custody.

use std::any::Any;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::rc::Rc;

use crucible_node_format::Validate;

use super::{BodySchemaVerifier, Connection, ConnectionSupervisor, EndpointRole, ProviderStream};
use crate::ProviderError;
use crate::handshake::ConnectionAuthority;
use crate::session::CorrelationGuard;
use crate::transport::FrameReader;

/// Retains every original input to a complete native connection constructor.
///
/// An ordinary refusal performs no transport I/O or supervisor callback. A
/// callback unwind poisons this original birth permanently and retains its
/// payload; retry cannot renew registration or replace original owners.
pub struct Native5ConnectionBirth<S: ProviderStream> {
    stream: S,
    protocol_owner: Rc<crate::protocol_snapshot::ProtocolCaptureOwner>,
    authority: ConnectionAuthority,
    supervisor: Rc<dyn ConnectionSupervisor>,
    schemas: Rc<dyn BodySchemaVerifier>,
    unwind_payload: Option<Box<dyn Any + Send>>,
}

/// Returns the failed birth with its original socket and callback owners intact.
pub struct Native5ConnectionBirthRefusal<S: ProviderStream> {
    original: Native5ConnectionBirth<S>,
    error: ProviderError,
}

impl<S: ProviderStream> Native5ConnectionBirthRefusal<S> {
    /// Borrows the refusal without extracting or releasing original owners.
    pub fn error(&self) -> &ProviderError {
        &self.error
    }

    /// Transfers the same original birth to its owning service phase capsule.
    pub fn into_original(self) -> Native5ConnectionBirth<S> {
        self.original
    }
}

impl<S: ProviderStream> Native5ConnectionBirth<S> {
    /// Borrows the retained original transport without performing I/O.
    pub fn stream(&self) -> &S {
        &self.stream
    }

    /// Borrows the same registrar authority supplied to the original attempt.
    pub fn authority(&self) -> &ConnectionAuthority {
        &self.authority
    }

    /// Reports whether an unwind permanently prevents further birth attempts.
    pub fn is_poisoned(&self) -> bool {
        self.unwind_payload.is_some()
    }

    /// Retries validation with the same socket, authority and callback owners.
    ///
    /// This performs no reads, writes, fencing or supervisor callbacks. It does
    /// not authenticate a native-five codec, capture, or restoration permission.
    ///
    /// # Errors
    /// Retains every original input on revoked authority, invalid framing credit
    /// or a prior/current unwind. A poisoned birth refuses before validation.
    pub fn retry(self) -> Result<Connection<S>, Box<Native5ConnectionBirthRefusal<S>>> {
        let mut original = self;
        if let Err(error) = original.protocol_owner.ensure_current() {
            return Err(Box::new(Native5ConnectionBirthRefusal { original, error }));
        }
        if original.is_poisoned() {
            return Err(Box::new(Native5ConnectionBirthRefusal {
                original,
                error: ProviderError::Correlation("complete native connection birth poisoned"),
            }));
        }

        let prepared = catch_unwind(AssertUnwindSafe(|| {
            original.authority.with_live(|| {
                let limits = original.authority.limits();
                limits.validate()?;
                let guard = CorrelationGuard::new(
                    original.authority.session_id().clone(),
                    original.authority.incarnation_id().clone(),
                    super::allowance(limits.requests.get())?,
                    original.authority.envelope_extensions().clone(),
                )?;
                Ok((
                    guard,
                    super::allowance(limits.frame_bytes.get())?,
                    super::allowance(limits.nesting.get())?,
                ))
            })
        }));
        let (guard, maximum_bytes, maximum_nesting) = match prepared {
            Ok(Ok(prepared)) => prepared,
            Ok(Err(error)) => {
                return Err(Box::new(Native5ConnectionBirthRefusal { original, error }));
            }
            Err(payload) => {
                original.unwind_payload = Some(payload);
                return Err(Box::new(Native5ConnectionBirthRefusal {
                    original,
                    error: ProviderError::Correlation("complete native connection birth unwound"),
                }));
            }
        };

        let Native5ConnectionBirth {
            stream,
            protocol_owner,
            authority,
            supervisor,
            schemas,
            unwind_payload,
        } = original;
        let reader = match FrameReader::with_limits_owned(stream, maximum_bytes, maximum_nesting) {
            Ok(reader) => reader,
            Err((stream, error)) => {
                return Err(Box::new(Native5ConnectionBirthRefusal {
                    original: Native5ConnectionBirth {
                        stream,
                        protocol_owner,
                        authority,
                        supervisor,
                        schemas,
                        unwind_payload,
                    },
                    error,
                }));
            }
        };
        Ok(Connection {
            reader,
            authority,
            guard,
            supervisor,
            schemas,
            protocol_owner,
            native5_blobs: None,
            native5_codec: None,
            original_canonical_ack_admission: None,
            original_restore_inputs: None,
            original_restore_responses: [None, None],
            original_complete_restoration: None,
            packet_schema: false,
            original_frames: None,
            connected_packet_schema: false,
            fenced: false,
            role: EndpointRole::Provider,
        })
    }
}

impl<S: ProviderStream> Connection<S> {
    /// Prepares native framing while retaining every constructor input on refusal.
    ///
    /// The service retains its Hello and native owners separately. Unlike an
    /// incident on an established connection, this refusal neither invokes
    /// arbitrary fencing callbacks nor releases the original socket.
    ///
    /// # Errors
    /// Returns an owning refusal on revoked authority, invalid negotiated credit
    /// or constructor unwind. Success grants framing only, not codec selection.
    pub fn new_native5_owned(
        stream: S,
        authority: ConnectionAuthority,
        supervisor: Rc<dyn ConnectionSupervisor>,
        schemas: Rc<dyn BodySchemaVerifier>,
    ) -> Result<Self, Box<Native5ConnectionBirthRefusal<S>>> {
        Native5ConnectionBirth {
            stream,
            protocol_owner: Rc::new(crate::protocol_snapshot::ProtocolCaptureOwner::new()),
            authority,
            supervisor,
            schemas,
            unwind_payload: None,
        }
        .retry()
    }
}

#[cfg(all(test, unix))]
// Owning fixture invariants deliberately panic when their original lease differs.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    struct Supervisor;
    impl ConnectionSupervisor for Supervisor {
        fn quarantine(&self, _: super::super::ConnectionIncident) {}
    }
    struct Schemas;
    impl BodySchemaVerifier for Schemas {
        fn verify(
            &self,
            _: &ConnectionAuthority,
            _: &crate::envelope::Envelope,
            _: &super::super::ReceivedBody,
        ) -> Result<(), ProviderError> {
            Err(ProviderError::Correlation(
                "uninstalled birth fixture codec",
            ))
        }
    }

    #[test]
    fn native5_connection_birth_success_keeps_original_actor_lease() {
        let (_handshake, authority) = crate::handshake::tests::controller_authority(true).unwrap();
        let (stream, _peer) = UnixStream::pair().unwrap();
        let protocol_owner = Rc::new(crate::protocol_snapshot::ProtocolCaptureOwner::new());
        let original_owner = protocol_owner.clone();
        let birth = Native5ConnectionBirth {
            stream,
            protocol_owner,
            authority,
            supervisor: Rc::new(Supervisor),
            schemas: Rc::new(Schemas),
            unwind_payload: None,
        };
        let connection = match birth.retry() {
            Ok(connection) => connection,
            Err(_) => panic!("current original framing refused"),
        };
        assert!(Rc::ptr_eq(&connection.protocol_owner, &original_owner));
        connection.protocol_owner.ensure_current().unwrap();
    }
}
