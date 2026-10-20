//! Reports fixed native owner geometry without private types or authority.
//!
//! The upper transport supplies these three independently requested components
//! from the actual CompleteBirth owners and original acknowledgement banks.
//! This record has no provenance seal, allocation grant, Source, native member,
//! digest or readiness. Its public numbers do not authenticate a constructor.

/// Separates the actual native shared owners, phase owners and context banks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeBirthFixedOwnerLayoutData {
    /// Reports the defining shared native constructor-owner allocations.
    pub shared_headers_bytes: usize,
    /// Reports the independently retained native phase/failure owner headers.
    pub phase_headers_bytes: usize,
    /// Reports the original acknowledgement context banks' bounded total.
    pub context_bank_bytes: usize,
}
