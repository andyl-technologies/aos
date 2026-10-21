//! Retains seven distinct empty receive banks before private body parsing.
//!
//! The original bootstrap owns these headers before its first read. A separate
//! admitted Prepare must supply the actual seven references before reservation;
//! no announcement or empty bank creates that permission. The private storage
//! and transfer primitives retain partial references, allocations and bytes on
//! refusal. Their completion lends DATA only, without installing native state.

use super::*;
use crate::reference_packet::service::complete_restore::import18::PacketNativeImport18InputRole;
use crucible_node_format::{ContentRef, HashRef};

#[path = "receiving_banks/storage.rs"]
mod storage;
#[path = "receiving_banks/transfer.rs"]
mod transfer;

#[derive(Clone, Copy, Eq, PartialEq)]
enum ReceivePhase {
    Empty,
    Reserving,
    Receiving,
    Complete,
    Failed,
}

struct InputBank {
    role: PacketNativeImport18InputRole,
    reference: Option<ContentRef>,
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
            reference: None,
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
    next_input: usize,
    phase: ReceivePhase,
}

impl OriginalImport18ReceivingBanks {
    pub(super) fn empty() -> Self {
        Self {
            banks: PacketNativeImport18InputRole::ALL.map(InputBank::empty),
            next_input: 0,
            phase: ReceivePhase::Empty,
        }
    }

    /// Counts actual backing only; the enclosing raw owner counts these headers.
    pub(super) fn retained_backing_data(&self) -> Result<usize, ProviderError> {
        let Self {
            banks,
            next_input: _,
            phase: _,
        } = self;
        banks.iter().try_fold(0usize, |total, bank| {
            let InputBank {
                role: _,
                reference,
                bytes,
                transfer: _,
                transfer_length: _,
                received: _,
                begun: _,
                finished: _,
            } = bank;
            let total = total.checked_add(bytes.capacity()).ok_or_else(exhausted)?;
            let Some(reference) = reference else {
                return Ok(total);
            };
            storage::reference_strings(reference)
                .into_iter()
                .try_fold(total, |sum, string| {
                    sum.checked_add(string.capacity()).ok_or_else(exhausted)
                })
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
            + size_of::<&[InputBank; 7]>()
            + size_of::<&InputBank>()
            + size_of::<&Vec<u8>>()
            + size_of::<&Option<ContentRef>>()
            + size_of::<PacketNativeImport18InputRole>()
            + size_of::<[PacketNativeImport18InputRole; 7]>()
            + size_of::<std::array::IntoIter<PacketNativeImport18InputRole, 7>>()
            + size_of::<std::slice::Iter<'static, InputBank>>()
            + size_of::<&ContentRef>()
            + size_of::<Option<&ContentRef>>()
            + size_of::<[&String; 4]>()
            + size_of::<std::array::IntoIter<&String, 4>>()
            + size_of::<&String>()
            + size_of::<ReceivePhase>()
            + size_of::<Option<usize>>()
            + size_of::<Result<usize, ProviderError>>()
            + size_of::<usize>() * 3
    }

    /// Names future completed loans separately from initial empty-bank work.
    pub(super) fn completed_loan_counter_scratch_data() -> usize {
        Self::counter_scratch_data() + transfer::counter_scratch_data()
    }

    #[cfg(test)]
    pub(super) fn is_empty_data(&self) -> bool {
        self.phase == ReceivePhase::Empty
            && self.next_input == 0
            && self.banks.iter().enumerate().all(|(ordinal, bank)| {
                bank.role.ordinal_data() == ordinal
                    && bank.reference.is_none()
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

fn unavailable() -> ProviderError {
    ProviderError::Correlation("original import18 receiving banks")
}

#[cfg(test)]
#[path = "receiving_banks/tests.rs"]
mod tests;
