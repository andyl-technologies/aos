//! Optional synchronous observations of actual issuer signature operations.
//!
//! Events expose no payload, key material, signature or permission. Observers
//! must be bounded, non-panicking and synchronous; they must not select inputs
//! or replace an authority result. Ordinary entrypoints attach no observer.

/// Identifies the actual issuer signature purpose being measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseSignatureKind {
    /// Signs the epoch lease after its first durable issuance acknowledgment.
    Lease,
    /// Signs the independently correlated issuer control reply.
    Reply,
}

/// Identifies a boundary immediately surrounding the Ed25519 signing call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseSignatureBoundary {
    /// The validated, serialized message is ready for signing.
    Started,
    /// The actual synchronous signature operation returned.
    Completed,
}

/// Reports an actual signing boundary without conveying signing authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseSignatureObservation {
    /// Exact signature purpose selected by the existing signing path.
    pub kind: LeaseSignatureKind,
    /// Boundary immediately before or after the actual signing call.
    pub boundary: LeaseSignatureBoundary,
}
