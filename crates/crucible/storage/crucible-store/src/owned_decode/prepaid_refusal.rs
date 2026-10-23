//! Prepays fixed account diagnostics independently of the account they report.
//!
//! Errors retain this separate holder and its original loan. The holder never
//! retains an Account, so a sticky error inside that Account cannot form a cycle.

use super::ownership::TerminalOwner;
use super::{AccountingRefusal, AdmissionSource, DecodeAdmissionError, ResourceLoan};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum AccountRefusal {
    Poisoned,
    Exhausted,
    ScratchInvariant,
}

struct RefusalStorage {
    poisoned: AccountingRefusal,
    exhausted: AccountingRefusal,
    scratch_invariant: AccountingRefusal,
    // TerminalOwner frees this storage's shared header before returning credit.
    _credit: ResourceLoan,
}

#[derive(Clone)]
pub(super) struct PrepaidRefusals {
    storage: TerminalOwner<RefusalStorage>,
}

impl PrepaidRefusals {
    pub(super) const fn peak_bytes() -> u64 {
        // This concrete record contains pointer-aligned fields. The two atomic
        // counts precede it; construction/extraction may overlap its allocation.
        (2 * std::mem::size_of::<usize>()
            + 2 * std::mem::size_of::<RefusalStorage>()
            + std::mem::size_of::<Self>()
            + std::mem::size_of::<DecodeAdmissionError>()) as u64
    }

    pub(super) fn new(credit: ResourceLoan) -> Self {
        Self {
            storage: TerminalOwner::new(RefusalStorage {
                poisoned: AccountingRefusal("decoded metadata account is poisoned"),
                exhausted: AccountingRefusal("decoded metadata allowance exhausted"),
                scratch_invariant: AccountingRefusal("decoded scratch accounting invariant failed"),
                _credit: credit,
            }),
        }
    }

    pub(super) fn error(&self, refusal: AccountRefusal) -> DecodeAdmissionError {
        DecodeAdmissionError {
            source: AdmissionSource::Account {
                retained: self.clone(),
                refusal,
            },
        }
    }

    pub(super) fn source(&self, refusal: AccountRefusal) -> &AccountingRefusal {
        match refusal {
            AccountRefusal::Poisoned => &self.storage.poisoned,
            AccountRefusal::Exhausted => &self.storage.exhausted,
            AccountRefusal::ScratchInvariant => &self.storage.scratch_invariant,
        }
    }

    pub(super) fn shares_owner(&self, other: &Self) -> bool {
        self.storage.shares_owner(&other.storage)
    }
}

#[cfg(test)]
pub(super) const fn allocation_bytes_for_test() -> usize {
    2 * std::mem::size_of::<usize>() + std::mem::size_of::<RefusalStorage>()
}
