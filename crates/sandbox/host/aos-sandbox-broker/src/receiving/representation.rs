//! Restrictive representation debits on the captured service's sole ledger.
//!
//! A debit cannot issue an operation loan, perform IO, replace an original, or
//! establish positive disposal. Role-private stages retain those obligations.

use aos_sandbox_model::{AccountingError, ResourceVector};
use aos_sandbox_model::component_receiving::ComponentServiceReceivingLedgerV1;

/// Performs nonauthorizing checked representation arithmetic only.
///
/// Implementations supply no receiving authority. Private role entries must
/// separately join their actual captured original before native operations.
#[doc(hidden)]
pub trait RepresentationDemandDebitV1 {
    /// Debits every dimension monotonically and retains the first refusal.
    ///
    /// # Errors
    /// Borrows the original arithmetic refusal; no later debit can reopen it.
    fn reserve(&mut self, demand: ResourceVector) -> Result<(), &AccountingError>;

    /// Borrows the earliest arithmetic refusal.
    fn failure(&self) -> Option<&AccountingError>;

    /// Returns passive cumulative usage DATA.
    fn charged(&self) -> ResourceVector;

    /// Computes passive remaining representation DATA.
    ///
    /// # Errors
    /// Returns the existing checked subtraction or sticky refusal.
    fn remaining(&self) -> Result<ResourceVector, AccountingError>;
}

impl RepresentationDemandDebitV1 for ComponentServiceReceivingLedgerV1 {
    fn reserve(&mut self, demand: ResourceVector) -> Result<(), &AccountingError> {
        ComponentServiceReceivingLedgerV1::reserve(self, demand)
    }

    fn failure(&self) -> Option<&AccountingError> {
        ComponentServiceReceivingLedgerV1::failure(self)
    }

    fn charged(&self) -> ResourceVector {
        ComponentServiceReceivingLedgerV1::charged(self)
    }

    fn remaining(&self) -> Result<ResourceVector, AccountingError> {
        ComponentServiceReceivingLedgerV1::remaining(self)
    }
}

/// Retains the sole ledger within one genuine fixed-service capture.
///
/// No public constructor, account extraction, credit or replacement method is
/// available. Its only mutating operation is a restrictive DATA debit. Borrowing
/// this field neither bypasses a role's private admission nor authorizes IO.
#[doc(hidden)]
pub struct FixedServiceRepresentationOriginalV1 {
    ledger: ComponentServiceReceivingLedgerV1,
}

impl FixedServiceRepresentationOriginalV1 {
    pub(crate) const fn new(ceiling: ResourceVector) -> Self {
        Self { ledger: ComponentServiceReceivingLedgerV1::new(ceiling) }
    }
}

impl RepresentationDemandDebitV1 for FixedServiceRepresentationOriginalV1 {
    fn reserve(&mut self, demand: ResourceVector) -> Result<(), &AccountingError> {
        self.ledger.reserve(demand)
    }

    fn failure(&self) -> Option<&AccountingError> {
        self.ledger.failure()
    }

    fn charged(&self) -> ResourceVector {
        self.ledger.charged()
    }

    fn remaining(&self) -> Result<ResourceVector, AccountingError> {
        self.ledger.remaining()
    }
}

/// Keeps the actual debit original in its capture without a take/replace port.
///
/// Borrowers can restrict representation use but cannot extract a Core account,
/// transfer the debit into a role owner, install a new ceiling, or reset it.
#[doc(hidden)]
pub struct FixedServiceRepresentationSlotV1 {
    original: Option<FixedServiceRepresentationOriginalV1>,
}

impl FixedServiceRepresentationSlotV1 {
    pub(crate) const fn empty() -> Self { Self { original: None } }

    pub(crate) fn install_once(&mut self, ceiling: ResourceVector) -> bool {
        if self.original.is_some() { return false; }
        self.original = Some(FixedServiceRepresentationOriginalV1::new(ceiling));
        true
    }

    /// Borrows passive arithmetic state without exposing an account.
    pub fn as_ref(&self) -> Option<&FixedServiceRepresentationOriginalV1> { self.original.as_ref() }

    /// Borrows only the restrictive DATA debit interface on this same original.
    pub fn as_mut(&mut self) -> Option<&mut FixedServiceRepresentationOriginalV1> { self.original.as_mut() }
}
