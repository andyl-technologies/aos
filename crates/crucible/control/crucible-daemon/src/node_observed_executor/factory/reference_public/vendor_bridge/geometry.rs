//! Counts borrowed preparation records before retaining their serialized bodies.

use std::io::{self, Write};

use crucible_node_transport::ProviderError;
use serde::Serialize;

pub(super) fn bounded(value: &impl Serialize, maximum: usize) -> Result<(), ProviderError> {
    serde_json::to_writer(Credit(maximum), value)
        .map_err(crucible_node_format::ContractError::from)?;
    Ok(())
}

struct Credit(usize);

impl Write for Credit {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self.0.checked_sub(bytes.len()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::OutOfMemory,
                "ordinary preparation metadata credit",
            )
        })?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
