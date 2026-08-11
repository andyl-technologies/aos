//! Allocation-free callback metadata for exact white-box instruction coordinates.
//!
//! QEMU invokes a translation-block entry callback before each instrumented
//! instruction callback. This module packs the translated instruction count and
//! doorbell index into callback userdata, then combines that fixed location with
//! the cached entry icount without allocating on the callback path.

use std::os::raw::c_void;

use super::LiveWhiteboxError;

/// Fixed instruction location encoded directly in QEMU callback userdata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct LiveWhiteboxInstructionLocation {
    tb_insns: u32,
    index: u32,
}

impl LiveWhiteboxInstructionLocation {
    pub(super) fn new(tb_insns: usize, index: usize) -> Result<Self, LiveWhiteboxError> {
        if usize::BITS < 64 || index >= tb_insns {
            return Err(LiveWhiteboxError::InstructionLocationOverflow { tb_insns, index });
        }
        let tb_insns = u32::try_from(tb_insns).map_err(|_source| {
            LiveWhiteboxError::InstructionLocationOverflow { tb_insns, index }
        })?;
        let index = u32::try_from(index).map_err(|_source| {
            LiveWhiteboxError::InstructionLocationOverflow {
                tb_insns: tb_insns as usize,
                index,
            }
        })?;
        Ok(Self { tb_insns, index })
    }

    pub(super) fn into_userdata(self) -> *mut c_void {
        let encoded = (u64::from(self.tb_insns) << 32) | u64::from(self.index + 1);
        encoded as usize as *mut c_void
    }

    pub(super) fn tb_userdata(self) -> *mut c_void {
        self.tb_insns as usize as *mut c_void
    }

    pub(super) fn tb_insns_from_userdata(userdata: *mut c_void) -> Result<u32, LiveWhiteboxError> {
        let tb_insns = userdata as usize;
        let tb_insns = u32::try_from(tb_insns).map_err(|_source| {
            LiveWhiteboxError::InstructionLocationOverflow { tb_insns, index: 0 }
        })?;
        if tb_insns == 0 {
            return Err(LiveWhiteboxError::InstructionLocationOverflow {
                tb_insns: 0,
                index: 0,
            });
        }
        Ok(tb_insns)
    }

    pub(super) fn from_userdata(userdata: *mut c_void) -> Result<Self, LiveWhiteboxError> {
        let encoded = userdata as usize as u64;
        let tb_insns = (encoded >> 32) as u32;
        let encoded_index = encoded as u32;
        if tb_insns == 0 || encoded_index == 0 || encoded_index > tb_insns {
            return Err(LiveWhiteboxError::InstructionLocationOverflow {
                tb_insns: tb_insns as usize,
                index: encoded_index.saturating_sub(1) as usize,
            });
        }
        Ok(Self {
            tb_insns,
            index: encoded_index - 1,
        })
    }

    pub(super) fn current_icount(
        self,
        entry: LiveWhiteboxTbEntry,
    ) -> Result<u64, LiveWhiteboxError> {
        if entry.tb_insns != self.tb_insns {
            return Err(LiveWhiteboxError::IcountObservation);
        }
        entry
            .icount
            .checked_add(u64::from(self.index))
            .ok_or(LiveWhiteboxError::IcountObservation)
    }
}

/// Exact coordinate captured at the current translation block's entry.
#[derive(Clone, Copy, Default)]
pub(super) struct LiveWhiteboxTbEntry {
    pub(super) tb_insns: u32,
    pub(super) icount: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instruction_location_round_trips_without_callback_allocation() {
        let location = LiveWhiteboxInstructionLocation::new(9, 4)
            .expect("test instruction location should fit callback userdata");

        assert_eq!(
            LiveWhiteboxInstructionLocation::from_userdata(location.into_userdata())
                .expect("encoded instruction location should decode"),
            location
        );
        assert_eq!(
            location
                .current_icount(LiveWhiteboxTbEntry {
                    tb_insns: 9,
                    icount: 100,
                })
                .expect("entry coordinate should resolve"),
            104
        );
    }

    #[test]
    fn instruction_location_rejects_missing_metadata_and_failed_observation() {
        assert!(matches!(
            LiveWhiteboxInstructionLocation::from_userdata(std::ptr::null_mut()),
            Err(LiveWhiteboxError::InstructionLocationOverflow { .. })
        ));
        let location = LiveWhiteboxInstructionLocation::new(9, 4)
            .expect("test instruction location should fit callback userdata");
        assert!(matches!(
            location.current_icount(LiveWhiteboxTbEntry {
                tb_insns: 8,
                icount: 100,
            }),
            Err(LiveWhiteboxError::IcountObservation)
        ));
        assert!(matches!(
            LiveWhiteboxInstructionLocation::tb_insns_from_userdata(std::ptr::null_mut()),
            Err(LiveWhiteboxError::InstructionLocationOverflow { .. })
        ));
    }
}
