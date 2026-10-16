//! Owns Linux project-quota inspection and host-only provisioning.
//!
//! Quota charges include kernel reservations; they are not physical allocation.
//! Linux checks the current caller's privilege even for retained descriptors.

mod native;
pub use native::{NativeProject, NativeQuota, provision_project, synchronized_allocated_bytes};

mod wire;
pub use wire::{QuotaObservation, QuotaQuery, QuotaRoot};

mod broker;
mod socket;
pub use broker::{
    ConfiguredOwner, ConfiguredRoot, HostQuotaBroker, HostQuotaClient, ROOT_LABELS,
    VerifiedQuotaObservation,
};
pub use native::filesystem_uuid;
pub use native::open_host_path;

/// Validates the registered disclosure-domain label used by host configuration.
///
/// # Errors
/// Returns an error for an unknown domain kind, empty identifier or oversized label.
pub fn validate_domain_label(domain: &str) -> std::io::Result<()> {
    if domain.len() > 256 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "domain label too long",
        ));
    }
    terrane_core::properties::Domain::parse(domain)
        .map(|_| ())
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid disclosure domain",
            )
        })
}

mod guard;
pub use guard::DomainProvisioningGuard;

mod namespace;
pub use namespace::require_host_root_namespace_boundary;
