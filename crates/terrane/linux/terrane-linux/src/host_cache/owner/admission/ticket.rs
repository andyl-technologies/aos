//! Receives the actual completion of a successfully queued chunk admission.
//!
//! A ticket acknowledges queue submission only. Native files and producer
//! funding remain owned by the physical worker if the ticket is dropped.

use super::{NativeChunkAdmission, NativeChunkAdmissionError};
use std::io;
use tokio::sync::oneshot;

/// Retains the reply channel for one genuinely queued native chunk command.
///
/// Possession grants neither native backing nor a consumer lease. Only actual
/// worker completion can return an admission receipt. Dropping the ticket does
/// not cancel an accepted command or relinquish its physical resources.
pub struct NativeChunkAdmissionTicket {
    receive: oneshot::Receiver<io::Result<NativeChunkAdmission>>,
}

impl NativeChunkAdmissionTicket {
    /// Receives the actual physical worker's admission outcome.
    ///
    /// # Errors
    /// Returns the accepted command's verification, capacity or physical error,
    /// or an accepted failure if its worker terminates without replying.
    pub async fn finish(self) -> Result<NativeChunkAdmission, NativeChunkAdmissionError> {
        self.receive
            .await
            .map_err(|_| {
                NativeChunkAdmissionError::Accepted(io::Error::other(
                    "admission worker terminated before reply",
                ))
            })?
            .map_err(NativeChunkAdmissionError::Accepted)
    }

    /// Retains only the original channel created for this submitted command.
    pub(super) fn new(receive: oneshot::Receiver<io::Result<NativeChunkAdmission>>) -> Self {
        Self { receive }
    }
}
