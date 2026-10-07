//! Exclusively occupied provider diagnostic storage with retained original credit.
//!
//! This storage grants no namespace, I/O, or supervision authority. Providers
//! construct it only after admitting its complete peak in their real resident
//! and metadata accounts. A checked-out permit keeps that credit and the
//! original service alive until the returned source has actually closed.

use std::error::Error;
use std::fmt;
use std::sync::Arc;

use super::StoreError;

/// Closed classification of an originally funded provider refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderFailureKind {
    /// An original service resource reservation refused capacity.
    Resources,
    /// Original operational supervision refused the work.
    Supervision,
    /// Original physical quota or namespace authentication refused the work.
    PhysicalQuota,
}

/// Exclusive diagnostic occupancy in an already admitted provider service.
///
/// This interface grants no namespace, I/O, resource or supervision authority.
/// Implementations retain their original constructor credit and expose only
/// the occupancy state shared by guards of that same service.
pub trait ProviderDiagnosticStorage: Send + Sync {
    /// Occupies the service's precharged diagnostic storage without allocation.
    ///
    /// # Errors
    /// Refuses already occupied storage before a new source is constructed.
    fn try_occupy(&self) -> Result<(), StoreError>;

    /// Releases occupancy after every covered diagnostic source has closed.
    fn release(&self);
}

/// Exclusive custody for one already-funded provider diagnostic.
///
/// It cannot be cloned to authorize independent error bodies. The original
/// provider checks still run after checkout under their unchanged supervision.
#[must_use = "the permit must outlive every diagnostic allocation it covers"]
pub struct ProviderDiagnosticPermit {
    storage: Arc<dyn ProviderDiagnosticStorage>,
}

impl ProviderDiagnosticPermit {
    /// Retains the issuing provider while occupying its admitted storage.
    ///
    /// The storage interface supplies no provider permissions or new credit.
    /// Guard dispatch passes its own retained issuer, never a caller's permit.
    ///
    /// # Errors
    /// Refuses occupied storage inline, without allocating a source or receipt.
    pub fn checkout(storage: Arc<dyn ProviderDiagnosticStorage>) -> Result<Self, StoreError> {
        storage.try_occupy()?;
        Ok(Self { storage })
    }

    /// Moves an originally funded boxed source into retained error custody.
    ///
    /// This performs no allocation or new reservation. The source and every
    /// owning payload must have been funded before they were created; the
    /// permit does not retroactively fund an incoming unowned failure.
    pub fn retain(
        self,
        kind: ProviderFailureKind,
        // crucible-lint: allow erased-error -- the paid portable storage boundary preserves its concrete daemon cause without a CAS dependency on Linux resource implementation types.
        source: Box<dyn Error + Send + Sync>,
    ) -> ProviderDiagnosticError {
        ProviderDiagnosticError {
            kind,
            source,
            _permit: self,
        }
    }
}

impl fmt::Debug for ProviderDiagnosticPermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProviderDiagnosticPermit { original_custody: retained }")
    }
}

impl Drop for ProviderDiagnosticPermit {
    fn drop(&mut self) {
        // This permit lives INLINE after the source box in the carrier below.
        // The source box is deallocated before another checkout can succeed.
        // The issuing Arc stays live through release, then closes normally.
        self.storage.release();
    }
}

/// A typed provider cause whose original slot remains occupied through close.
pub struct ProviderDiagnosticError {
    kind: ProviderFailureKind,
    // crucible-lint: allow erased-error -- the original funded cause remains typed through Error::source; this portable storage carrier acquires no I/O authority.
    source: Box<dyn Error + Send + Sync>,
    // Last: boxed source destruction and deallocation precede slot reuse.
    _permit: ProviderDiagnosticPermit,
}

impl ProviderDiagnosticError {
    /// Returns the original closed refusal category without detaching custody.
    pub const fn kind(&self) -> ProviderFailureKind {
        self.kind
    }
}

impl fmt::Debug for ProviderDiagnosticError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderDiagnosticError")
            .field("kind", &self.kind)
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for ProviderDiagnosticError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.source.as_ref(), formatter)
    }
}

impl Error for ProviderDiagnosticError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}
