//! Holds complete-source byte owners beside the same actual native endpoint.
//!
//! The owning constructor preserves original Hello and precharges protocol
//! snapshots before the first control frame. It does not issue a native capture;
//! the original ticket, unchanged full cut and complete prefix settlement remain
//! independent prerequisites.

use super::super::service::PacketNative5StorageLimits;
use super::*;
use crate::{
    native_hello::OriginalNativeHelloJournal, protocol_snapshot::ProtocolSnapshotReservation,
};

pub(super) struct CompleteEndpointState {
    pub(super) creator: u32,
    pub(super) thread: std::thread::ThreadId,
    pub(super) storage: PacketNative5StorageLimits,
    pub(super) hello: OriginalNativeHelloJournal,
    pub(super) before: Option<ProtocolSnapshotReservation>,
    pub(super) after: Option<ProtocolSnapshotReservation>,
}

impl CompleteEndpointState {
    pub(super) fn ensure_origin(&self) -> Result<(), ProviderError> {
        if self.creator != std::process::id() {
            return Err(ProviderError::Correlation(
                "native5 endpoint foreign creator",
            ));
        }
        if self.thread != std::thread::current().id() {
            return Err(ProviderError::Correlation(
                "native5 endpoint foreign thread",
            ));
        }
        Ok(())
    }

    fn preflight_birth(&self, authority: &ConnectionAuthority) -> Result<(), ProviderError> {
        self.ensure_origin()?;
        self.storage.validate(&authority.limits())?;
        let maximum_hello = usize::try_from(self.storage.hello_bytes.get())
            .map_err(|_| ProviderError::ResourceExhausted("native5 Hello allocation credit"))?;
        if self.hello.allocated_bytes() > maximum_hello {
            return Err(ProviderError::ResourceExhausted(
                "native5 actual Hello allocation",
            ));
        }
        let hello_view_credit = maximum_hello
            .checked_mul(4)
            .and_then(|bytes| bytes.checked_add(8192))
            .ok_or(ProviderError::ResourceExhausted(
                "native5 Hello codec extent",
            ))?;
        serialized_credit(&self.hello.protocol_view(), hello_view_credit)?;
        let before = self.before.as_ref().ok_or(ProviderError::Correlation(
            "native5 initial snapshot slot absent",
        ))?;
        let after = self.after.as_ref().ok_or(ProviderError::Correlation(
            "native5 initial settlement slot absent",
        ))?;
        before
            .allocated_bytes()
            .checked_add(after.allocated_bytes())
            .ok_or(ProviderError::ResourceExhausted(
                "native5 actual snapshot capacity overflow",
            ))?;
        authority.ensure_live()
    }
}

impl<S: ProviderStream> PacketEndpoint<S> {
    /// Takes complete native source owners on the same unused archived connection.
    ///
    /// Actual selected allocations precede control input. The enclosing source
    /// factory separately charges both endpoints and whole-world peak geometry;
    /// this constructor cannot manufacture that admission from portable limits.
    ///
    /// # Errors
    /// Returns the original connection/native owner on legacy construction,
    /// invalid finite storage, absent codec bank or failed original blob binding.
    pub fn new_complete(
        mut connection: Connection<S>,
        native: PacketControl,
        policy: Rc<dyn PacketEndpointPolicy>,
        supervisor: Rc<dyn BlobSupervisor>,
        storage: PacketNative5StorageLimits,
        hello: OriginalNativeHelloJournal,
    ) -> Result<Self, Box<PacketEndpointRefusal<S>>> {
        let prepare = || -> Result<CompleteEndpointState, ProviderError> {
            let authority = connection.provider_authority()?;
            storage.validate(&authority.limits())?;
            native.authenticate_complete_birth()?;
            let maximum = usize::try_from(storage.protocol_snapshot_bytes.get())
                .map_err(|_| ProviderError::ResourceExhausted("native5 protocol snapshot bytes"))?;
            let before = ProtocolSnapshotReservation::reserve(maximum)?;
            let after = ProtocolSnapshotReservation::reserve(maximum)?;
            Ok(CompleteEndpointState {
                creator: std::process::id(),
                thread: std::thread::current().id(),
                storage: storage.clone(),
                hello,
                before: Some(before),
                after: Some(after),
            })
        };
        let state = match prepare() {
            Ok(state) => state,
            Err(error) => {
                return Err(Box::new(PacketEndpointRefusal {
                    connection,
                    native,
                    error,
                }));
            }
        };
        let validate = connection
            .provider_authority()
            .and_then(|authority| state.preflight_birth(authority));
        if let Err(error) = validate {
            return Err(Box::new(PacketEndpointRefusal {
                connection,
                native,
                error,
            }));
        }
        let mut endpoint = Self::new(connection, native, policy, supervisor)?;
        endpoint.complete = Some(state);
        Ok(endpoint)
    }
}
