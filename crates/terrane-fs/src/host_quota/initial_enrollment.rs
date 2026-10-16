//! Owns native first-enrollment scaffolding and creator-backed metadata changes.
//!
//! Administrative operations must retain the actual creator receipt, original
//! exclusions and protected project claim. This declaration grants no setter,
//! custody, accounting or completed-enrollment authority.

/// Requires actual host UID zero in the initial host user namespace.
///
/// Administrative enrollment calls this before registry writes or scaffold
/// creation. Success establishes this immediate process precondition only;
/// creator evidence, exclusion and durable claims remain separate obligations.
///
/// # Errors
/// Refuses a noninitial user namespace, another effective user identity or
/// failure to inspect the actual native namespace boundary.
pub fn require_initial_host_root() -> std::io::Result<()> {
    super::require_host_root_namespace_boundary()?;
    if !rustix::process::geteuid().is_root() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "initial enrollment requires actual host UID zero",
        ));
    }
    Ok(())
}
