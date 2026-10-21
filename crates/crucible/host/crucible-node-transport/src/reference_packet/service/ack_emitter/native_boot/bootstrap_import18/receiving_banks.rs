//! Retains seven distinct empty receive banks before private body parsing.
//!
//! These are the physical headers for the new ordered input roster. Empty
//! storage creates no Prepare token, reference binding, reservation, completed
//! upload or native installation. Bank backing remains a later independently
//! admitted construction under the same original escrow.

use super::*;
use crate::reference_packet::service::complete_restore::import18::PacketNativeImport18InputRole;

struct InputBank {
    role: PacketNativeImport18InputRole,
    bytes: Vec<u8>,
    transfer: [u8; 128],
    transfer_length: usize,
    received: usize,
    begun: bool,
    finished: bool,
}

impl InputBank {
    fn empty(role: PacketNativeImport18InputRole) -> Self {
        Self {
            role,
            bytes: Vec::new(),
            transfer: [0; 128],
            transfer_length: 0,
            received: 0,
            begun: false,
            finished: false,
        }
    }
}

/// Owns physical headers without interpreting them as authenticated input custody.
pub(super) struct OriginalImport18ReceivingBanks {
    banks: [InputBank; 7],
}

impl OriginalImport18ReceivingBanks {
    pub(super) fn empty() -> Self {
        Self {
            banks: PacketNativeImport18InputRole::ALL.map(InputBank::empty),
        }
    }

    /// Counts actual backing only; the enclosing raw owner counts these headers.
    pub(super) fn retained_backing_data(&self) -> Result<usize, ProviderError> {
        self.banks.iter().try_fold(0usize, |total, bank| {
            total
                .checked_add(bank.bytes.capacity())
                .ok_or_else(exhausted)
        })
    }

    pub(super) const fn construction_transient_data() -> usize {
        size_of::<Self>() * 2
            + size_of::<[InputBank; 7]>() * 2
            + size_of::<InputBank>() * 2
            + size_of::<Vec<u8>>()
            + size_of::<[u8; 128]>()
    }

    pub(super) fn counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<&InputBank>()
            + size_of::<PacketNativeImport18InputRole>()
            + size_of::<[PacketNativeImport18InputRole; 7]>()
            + size_of::<std::array::IntoIter<PacketNativeImport18InputRole, 7>>()
            + size_of::<std::slice::Iter<'static, InputBank>>()
            + size_of::<Option<usize>>()
            + size_of::<Result<usize, ProviderError>>()
            + size_of::<usize>() * 3
    }

    #[cfg(test)]
    pub(super) fn is_empty_data(&self) -> bool {
        self.banks.iter().enumerate().all(|(ordinal, bank)| {
            bank.role.ordinal_data() == ordinal
                && bank.bytes.is_empty()
                && bank.bytes.capacity() == 0
                && bank.transfer == [0; 128]
                && bank.transfer_length == 0
                && bank.received == 0
                && !bank.begun
                && !bank.finished
        })
    }
}
