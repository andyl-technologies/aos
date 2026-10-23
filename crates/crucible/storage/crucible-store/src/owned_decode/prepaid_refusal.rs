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
    ArrayOverflow,
    ScratchArrayOverflow,
    VectorOverflow,
    BtreeOverflow,
    TreeNodeOverflow,
}

impl AccountRefusal {
    pub(super) fn diagnostic(self) -> AccountingRefusal {
        AccountingRefusal(match self {
            Self::Poisoned => "decoded metadata account is poisoned",
            Self::Exhausted => "decoded metadata allowance exhausted",
            Self::ScratchInvariant => "decoded scratch accounting invariant failed",
            Self::ArrayOverflow => "decoded array size overflow",
            Self::ScratchArrayOverflow => "decoded scratch array size overflow",
            Self::VectorOverflow => "decoded vector size overflow",
            Self::BtreeOverflow => "decoded B-tree size overflow",
            Self::TreeNodeOverflow => "decoded tree node size overflow",
        })
    }
}

struct RefusalStorage {
    poisoned: AccountingRefusal,
    exhausted: AccountingRefusal,
    scratch_invariant: AccountingRefusal,
    array_overflow: AccountingRefusal,
    scratch_array_overflow: AccountingRefusal,
    vector_overflow: AccountingRefusal,
    btree_overflow: AccountingRefusal,
    tree_node_overflow: AccountingRefusal,
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
                poisoned: AccountRefusal::Poisoned.diagnostic(),
                exhausted: AccountRefusal::Exhausted.diagnostic(),
                scratch_invariant: AccountRefusal::ScratchInvariant.diagnostic(),
                array_overflow: AccountRefusal::ArrayOverflow.diagnostic(),
                scratch_array_overflow: AccountRefusal::ScratchArrayOverflow.diagnostic(),
                vector_overflow: AccountRefusal::VectorOverflow.diagnostic(),
                btree_overflow: AccountRefusal::BtreeOverflow.diagnostic(),
                tree_node_overflow: AccountRefusal::TreeNodeOverflow.diagnostic(),
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
            AccountRefusal::ArrayOverflow => &self.storage.array_overflow,
            AccountRefusal::ScratchArrayOverflow => &self.storage.scratch_array_overflow,
            AccountRefusal::VectorOverflow => &self.storage.vector_overflow,
            AccountRefusal::BtreeOverflow => &self.storage.btree_overflow,
            AccountRefusal::TreeNodeOverflow => &self.storage.tree_node_overflow,
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
