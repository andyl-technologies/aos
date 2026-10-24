//! Binds the original Rust worker request to the guarded launch environment.
//!
//! The supported Linux launch clears its inherited environment and installs
//! the fixed callback diagnostic input and its existing optional canonical
//! stage-token passthrough. Neither can change Rust or loader configuration.
//! The matched Rust source consequently requests its Linux default. This request is not the pthread allocation size:
//! TLS, guard pages, stack-cache reuse and retained allocations need their own
//! source-qualified footprint under the same process owner.

/// Names the existing request without supplying an allocation allowance.
pub(crate) struct GuardedWorkerStackProfile;

impl GuardedWorkerStackProfile {
    // Both production environment variants preserve the original Linux default.
    // Rejecting other entries also excludes loader and glibc tunable overrides.
    pub(crate) fn for_environment(environment: &[(&str, &str)]) -> Option<Self> {
        match environment {
            [] | [("CRUCIBLE_CONTROL_CALLBACK_WITNESS", "1")] => Some(Self),
            _ => None,
        }
    }

    #[cfg(any(test, feature = "private-measurement-domain"))]
    pub(crate) const fn original_request_bytes(&self) -> usize {
        2 * 1024 * 1024
    }
}

#[cfg(test)]
mod tests {
    use super::GuardedWorkerStackProfile;

    #[test]
    fn existing_production_environments_preserve_the_original_request() {
        for environment in [&[][..], &[("CRUCIBLE_CONTROL_CALLBACK_WITNESS", "1")][..]] {
            let profile = GuardedWorkerStackProfile::for_environment(environment).unwrap();

            assert_eq!(profile.original_request_bytes(), 2 * 1024 * 1024);
        }
    }

    #[test]
    fn unknown_stack_or_loader_environment_is_rejected() {
        for environment in [
            &[("RUST_MIN_STACK", "2097152")][..],
            &[("LD_PRELOAD", "/unknown/plugin.so")][..],
            &[("GLIBC_TUNABLES", "glibc.pthread.stack_cache_size=0")][..],
            &[("CRUCIBLE_CONTROL_CALLBACK_WITNESS", "0")][..],
        ] {
            assert!(GuardedWorkerStackProfile::for_environment(environment).is_none());
        }
    }
}
