//! Fallible bounded writers for pending network checkpoint CBOR.

use std::io::{self, Write};

use super::{
    BackendNetworkOutputCodecError, HARD_BACKEND_NETWORK_CHECKPOINT_BYTES, backend_network_resource,
};

pub(super) struct BackendNetworkCheckpointCountingWriter {
    pub(super) length: u64,
    pub(super) configured: usize,
    pub(super) failure: Option<BackendNetworkOutputCodecError>,
}

impl BackendNetworkCheckpointCountingWriter {
    pub(super) const fn new(configured: usize) -> Self {
        Self {
            length: 0,
            configured,
            failure: None,
        }
    }
}

impl Write for BackendNetworkCheckpointCountingWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let current = usize::try_from(self.length).unwrap_or(usize::MAX);
        let total = current.checked_add(buffer.len()).ok_or_else(|| {
            let error = backend_network_resource(
                "encoded frame",
                current,
                buffer.len(),
                self.configured,
                HARD_BACKEND_NETWORK_CHECKPOINT_BYTES,
            );
            self.failure = Some(error);
            io::Error::other("pending network frame checkpoint length overflow")
        })?;
        if total > self.configured || total > HARD_BACKEND_NETWORK_CHECKPOINT_BYTES {
            self.failure = Some(backend_network_resource(
                "encoded frame",
                current,
                buffer.len(),
                self.configured,
                HARD_BACKEND_NETWORK_CHECKPOINT_BYTES,
            ));
            return Err(io::Error::other(
                "pending network frame checkpoint exceeds its bound",
            ));
        }
        self.length = u64::try_from(total).unwrap_or(u64::MAX);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) struct BackendNetworkCheckpointReservedWriter<'a> {
    pub(super) bytes: &'a mut Vec<u8>,
    pub(super) reservation: usize,
    pub(super) configured: usize,
    pub(super) failure: Option<BackendNetworkOutputCodecError>,
}

impl<'a> BackendNetworkCheckpointReservedWriter<'a> {
    pub(super) fn new(bytes: &'a mut Vec<u8>, reservation: usize, configured: usize) -> Self {
        Self {
            bytes,
            reservation,
            configured,
            failure: None,
        }
    }
}

impl Write for BackendNetworkCheckpointReservedWriter<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let current = self.bytes.len();
        let total = current.checked_add(buffer.len()).ok_or_else(|| {
            let error = backend_network_resource(
                "encoded frame",
                current,
                buffer.len(),
                self.configured,
                HARD_BACKEND_NETWORK_CHECKPOINT_BYTES,
            );
            self.failure = Some(error);
            io::Error::other("pending network frame checkpoint length overflow")
        })?;
        if total > self.reservation
            || buffer.len() > self.bytes.capacity().saturating_sub(self.bytes.len())
        {
            self.failure = Some(backend_network_resource(
                "encoded frame",
                current,
                buffer.len(),
                self.configured,
                HARD_BACKEND_NETWORK_CHECKPOINT_BYTES,
            ));
            return Err(io::Error::other(
                "pending network frame checkpoint exceeded its reservation",
            ));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
