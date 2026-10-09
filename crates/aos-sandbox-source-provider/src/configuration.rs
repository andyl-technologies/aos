//! Authenticated catalog-publication projection used by provider bootstrap.
//!
//! The security crate mints this opaque value only after verifying exact
//! canonical publication bytes against freshly revalidated protected trust.

pub use aos_sandbox_source_provider_security::VerifiedCatalogPublicationV1;
