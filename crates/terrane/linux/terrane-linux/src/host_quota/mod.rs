//! Owns Linux project-quota inspection and host-only provisioning.
//!
//! Quota charges include kernel reservations; they are not physical allocation.
//! Linux checks the current caller's privilege even for retained descriptors.

/// Retains fresh-bucket observations for administrative native enrollment.
pub mod initial_enrollment;

mod native;
pub use native::{NativeProject, NativeQuota, provision_project, synchronized_allocated_bytes};

mod wire;
pub use wire::{QuotaObservation, QuotaQuery, QuotaRoot};

mod broker;
mod socket;
pub use broker::{
    ConfiguredOwner, ConfiguredRoot, ConfiguredScaffold, HostQuotaBroker, HostQuotaClient,
    ROOT_LABELS, VerifiedQuotaObservation,
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
    terrane_format::properties::Domain::parse(domain)
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

mod custody;
pub use custody::{
    DirectoryChild, directory_children, open_directory_child, set_directory_custody,
};

pub use native::require_unused_project;

mod claim;
pub use claim::{MAX_PROJECT_CLAIM_BYTES, RetainedProjectClaim, project_claim_name};
