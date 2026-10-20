//! Retains only the two actual Hello literals needed by historical ACK proof.

use crate::ProviderError;
use crate::connection::native17_borrowed_bytes::Bytes17;
use crate::protocol_snapshot::owned11::typed::{Ledger, invalid};
use crate::retained_metadata::MetadataObserver;

/// Owns exact selected frame bytes without reconstructing their old frame bank.
#[derive(Default)]
pub(super) struct NativeHello17Data {
    started: bool,
    request: Vec<u8>,
    response: Vec<u8>,
}

impl NativeHello17Data {
    pub(super) fn preflight_data(
        request: Bytes17<'_>,
        response: Bytes17<'_>,
        ledger: &mut Ledger<'_, '_, '_>,
    ) -> Result<(), ProviderError> {
        ledger.native17_target_vector_data::<u8>(request.len())?;
        ledger.native17_target_vector_data::<u8>(response.len())
    }

    pub(super) fn read_into_data(
        &mut self,
        request: Bytes17<'_>,
        response: Bytes17<'_>,
        ledger: &mut Ledger<'_, '_, '_>,
    ) -> Result<(), ProviderError> {
        if self.started {
            return Err(invalid());
        }
        self.started = true;
        Self::preflight_data(request, response, ledger)?;
        copy_into(request, &mut self.request)?;
        copy_into(response, &mut self.response)
    }

    pub(super) fn request_data(&self) -> &[u8] {
        &self.request
    }

    pub(super) fn response_data(&self) -> &[u8] {
        &self.response
    }

    pub(super) fn observe_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        observer.vector::<u8>(self.request.capacity())?;
        observer.vector::<u8>(self.response.capacity())
    }
}

fn copy_into(source: Bytes17<'_>, destination: &mut Vec<u8>) -> Result<(), ProviderError> {
    destination
        .try_reserve_exact(source.len())
        .map_err(|_| invalid())?;
    if destination.capacity() != source.len() {
        return Err(invalid());
    }
    destination.resize(source.len(), 0);
    source.copy(0, destination)
}
