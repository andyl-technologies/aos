//! Owns disclosure-scoped storage and admission from specification 24.
//!
//! The canonical domain ordering comes from `terrane_core::properties`.
//! Guard-issued access binds a request to one trusted root and one domain;
//! backends receive that binding rather than a capability token. Separate
//! backend instances prevent cross-domain dedup shortcuts and pack sharing.

mod access;
mod admission;
mod deletion;
#[cfg(feature = "std")]
mod namespaces;
mod storage;

#[cfg(test)]
mod tests;

#[cfg(all(test, feature = "tokio", unix))]
mod native_tests;

pub use access::{DomainAccess, DomainBinding};
pub use admission::{DomainAdmission, DomainRecord, DomainReference};
pub use deletion::{
    DomainAdminRequest, DomainDeletionAudit, DomainDeletionBackend, DomainDeletionEvent,
    DomainDeletionPlan,
};
#[cfg(feature = "std")]
pub use namespaces::{
    ConfiguredDomainRoute, DomainAuditRoute, DomainFsBinding, DomainNamespace, DomainNamespaces,
};
pub use storage::{DomainDisclosure, DomainStore};

use terrane_core::identity::{Identity, IdentityKind, TERRANE_V1};
use terrane_core::properties::Domain;

use crate::store::{InvalidReason, StoreErrorKind, StoreFailure};

/// Names the exact authoritative administrative head for a canonical domain.
///
/// The suffix is the registered policy identity digest of the domain label's
/// canonical CBOR text value. Signed audit payloads independently bind the
/// domain and ref; this name alone does not establish administrative authority.
///
/// # Errors
///
/// Returns `Invalid(MalformedRequest)` for an invalid label or identity failure.
pub fn control_ref_name(domain: &str) -> Result<String, StoreFailure> {
    Domain::parse(domain)
        .map_err(|_| StoreFailure::new(StoreErrorKind::Invalid(InvalidReason::MalformedRequest)))?;
    let mut encoded = Vec::new();
    terrane_core::cbor::write_text(&mut encoded, domain);
    let identity = TERRANE_V1
        .calculate(IdentityKind::Policy, &encoded)
        .map_err(|error| {
            StoreFailure::with_source(
                StoreErrorKind::Invalid(InvalidReason::MalformedRequest),
                error,
            )
        })?;
    let digest: String = identity
        .digest()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();

    Ok(format!("refs/heads/domain-deletions/{digest}"))
}

/// Returns the canonical text representation of a disclosure domain.
#[must_use]
pub fn label(domain: Domain<'_>) -> String {
    match domain {
        Domain::Public => "public".to_owned(),
        Domain::Tenant(name) => format!("tenant:{name}"),
        Domain::Group(name) => format!("group:{name}"),
        Domain::Private(name) => format!("private:{name}"),
    }
}

/// Supplies the private default for a root without an inherited domain.
///
/// The identity profile and kind distinguish equal digest bytes belonging to
/// different identity spaces. Local-user defaults may be supplied explicitly
/// by the trusted root policy resolver instead (DOM-1).
#[must_use]
pub fn private_default(root: &Identity) -> String {
    let digest: String = root
        .digest()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("private:{}:{:?}:{digest}", root.profile(), root.kind())
}
