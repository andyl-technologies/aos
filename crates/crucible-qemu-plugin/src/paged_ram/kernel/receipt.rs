//! Retains consumed Linux fault-message bytes through projection and settlement.
//!
//! The paid fault-work body owns this buffer before the kernel read. Decoding
//! borrows it; malformed positive reads never become an empty event or release
//! the consumed receipt. This local custody does not issue a PageIn operation.
//!
//! SPDX-License-Identifier: GPL-2.0-or-later

use super::{FaultEvent, io};

/// Keeps the actual read disposition and fixed kernel message together.
#[derive(Default)]
pub(crate) struct FaultReceipt {
    message: [u8; 32],
    count: usize,
}

impl FaultReceipt {
    /// Reads into retained storage and projects an event without consuming it.
    ///
    /// # Errors
    /// Refuses replacement of consumed bytes, hard read failures, short messages,
    /// unknown event kinds or unsupported fault flags.
    pub(crate) fn read_with(
        &mut self,
        read: impl FnOnce(&mut [u8; 32]) -> io::Result<usize>,
    ) -> io::Result<Option<FaultEvent>> {
        if self.retained() {
            return Err(io::Error::other("kernel fault receipt remains unsettled"));
        }
        let count = match read(&mut self.message) {
            Ok(count) => count,
            Err(error) => {
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) {
                    return Ok(None);
                }
                return Err(error);
            }
        };
        self.count = count;

        if count != self.message.len() || self.message[0] != 0x12 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected userfaultfd event",
            ));
        }
        let flags = u64::from_ne_bytes(
            self.message[8..16]
                .try_into()
                .map_err(|_| io::Error::other("invalid fixed-size fault flags"))?,
        );
        if flags & !3 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "unsupported fault flags",
            ));
        }

        Ok(Some(FaultEvent {
            address: u64::from_ne_bytes(
                self.message[16..24]
                    .try_into()
                    .map_err(|_| io::Error::other("invalid fixed-size fault address"))?,
            ),
            thread_id: u32::from_ne_bytes(
                self.message[24..28]
                    .try_into()
                    .map_err(|_| io::Error::other("invalid fixed-size fault thread"))?,
            ),
            write: flags & 1 != 0,
            write_protected: flags & 2 != 0,
        }))
    }

    /// Reports consumed bytes even when their event could not be interpreted.
    pub(crate) fn retained(&self) -> bool {
        self.count != 0
    }

    /// Clears the receipt only after its original operation completed.
    pub(crate) fn clear_after_settlement(&mut self) {
        *self = Self::default();
    }
}
