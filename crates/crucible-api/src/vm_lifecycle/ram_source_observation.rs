//! Test-only observation of an authenticated, leased native RAM source.
//!
//! A decorator can hold a genuine page completion while independent control
//! changes its original operational authority. It cannot replace the root or
//! manufacture source admission; normal source proof and boundary checks remain
//! authoritative before any response reaches the faulting native process.

use std::sync::Arc;

use crucible_qemu::ram_source::{QemuRamBacking, QemuRamSourceError};

use super::{LifecycleApiError, ProductionVmLifecycleConfig, loop_factory_error};

/// Observes a genuine leased RAM backing in native test-support builds.
///
/// Implementations retain the supplied backing and forward its immutable root
/// reference unchanged. Any gate, proof storage or diagnostic allocation must
/// retain its own loan from the original admitted resource owner. Page reads
/// preserve the caller's operational boundary and return its real page proof.
pub trait ProductionRamSourceDecorator: Send + Sync {
    /// Wraps a backing after checkpoint authentication and before source launch.
    ///
    /// # Errors
    /// Refuses unavailable original resource credit or invalid observer setup.
    fn decorate(
        &self,
        backing: Arc<dyn QemuRamBacking>,
    ) -> Result<Arc<dyn QemuRamBacking>, QemuRamSourceError>;
}

impl ProductionVmLifecycleConfig {
    /// Authorizes an explicitly selected native fault-worker fixture mutation.
    ///
    /// The nonce is attached only to the cold launch that receives an actual
    /// RAM registration. It supplies no resource or process authority, and a
    /// forked child receives no inherited mutation entitlement.
    ///
    /// # Errors
    /// Refuses the all-zero nonce. Native launch also refuses absent genuine
    /// RAM registration before emitting the entitlement to the plugin.
    pub fn with_fault_actor_test_entitlement_for_test(
        mut self,
        entitlement: [u8; 32],
    ) -> Result<Self, crucible_protocol::ram_control::RamControlError> {
        if entitlement == [0; 32] {
            return Err(crucible_protocol::ram_control::RamControlError::AuthorityMismatch);
        }
        self.fault_actor_test_entitlement = Some(entitlement);
        Ok(self)
    }

    /// Observes authenticated native page reads without replacing their authority.
    ///
    /// This test-support hook does not admit a root, process or Service. Native
    /// construction first authenticates the checkpoint, then checks that the
    /// decorator retained its exact root reference and storage identity. Source
    /// requests still use the original cap, namespace and proof verification.
    #[must_use]
    pub fn with_ram_source_decorator_for_test(
        mut self,
        decorator: Arc<dyn ProductionRamSourceDecorator>,
    ) -> Self {
        self.ram_source_decorator = Some(decorator);
        self
    }
}

pub(super) fn decorate_authenticated_backing(
    backing: Arc<dyn QemuRamBacking>,
    decorator: Option<&dyn ProductionRamSourceDecorator>,
) -> Result<Arc<dyn QemuRamBacking>, LifecycleApiError> {
    let Some(decorator) = decorator else {
        return Ok(backing);
    };
    let observed = decorator.decorate(Arc::clone(&backing)).map_err(|error| {
        loop_factory_error(format!("observe authenticated RAM source: {error}"))
    })?;
    if observed.root_object_id() != backing.root_object_id()
        || !std::ptr::eq(observed.root_record(), backing.root_record())
    {
        return Err(loop_factory_error(
            "RAM source observer replaced its authenticated root authority",
        ));
    }
    Ok(observed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_qemu::ram_source::QemuRamSourceError;

    #[test]
    fn fault_worker_fixture_requires_an_explicit_nonzero_entitlement() {
        let config =
            ProductionVmLifecycleConfig::for_artifact_authentication("qemu", "plugin", "run-state");
        assert!(config.fault_actor_test_entitlement.is_none());
        assert!(matches!(
            config.with_fault_actor_test_entitlement_for_test([0; 32]),
            Err(crucible_protocol::ram_control::RamControlError::AuthorityMismatch)
        ));
        let config =
            ProductionVmLifecycleConfig::for_artifact_authentication("qemu", "plugin", "run-state")
                .with_fault_actor_test_entitlement_for_test([9; 32])
                .unwrap_or_else(|source| panic!("explicit fault worker fixture: {source}"));
        assert_eq!(config.fault_actor_test_entitlement, Some([9; 32]));
    }

    struct ForwardingBacking(Arc<dyn QemuRamBacking>);

    impl QemuRamBacking for ForwardingBacking {
        fn root_object_id(&self) -> &str {
            self.0.root_object_id()
        }

        fn root_record(&self) -> &crucible_ram::RootRecord {
            self.0.root_record()
        }

        fn read_page_with_proof(
            &self,
            region: &str,
            page: u64,
            boundary: &mut dyn FnMut() -> Result<
                (),
                crucible_qemu::ram_source::QemuRamReadBoundaryError,
            >,
        ) -> Result<(Vec<u8>, crucible_ram::PageProof), QemuRamSourceError> {
            self.0.read_page_with_proof(region, page, boundary)
        }
    }

    struct ForwardingDecorator;

    impl ProductionRamSourceDecorator for ForwardingDecorator {
        fn decorate(
            &self,
            backing: Arc<dyn QemuRamBacking>,
        ) -> Result<Arc<dyn QemuRamBacking>, QemuRamSourceError> {
            Ok(Arc::new(ForwardingBacking(backing)))
        }
    }

    struct ReplacingDecorator(Arc<dyn QemuRamBacking>);

    impl ProductionRamSourceDecorator for ReplacingDecorator {
        fn decorate(
            &self,
            _backing: Arc<dyn QemuRamBacking>,
        ) -> Result<Arc<dyn QemuRamBacking>, QemuRamSourceError> {
            Ok(Arc::clone(&self.0))
        }
    }

    fn fixture_backing(directory: &std::path::Path) -> Arc<dyn QemuRamBacking> {
        let fixture = super::super::checkpoint_store::test_support::
            build_exact_ram_production_checkpoint_codec_fixture(directory)
                .unwrap_or_else(|error| panic!("authenticated leased fixture: {error}"));
        Arc::new(fixture.closure().ram_sources()[0].clone())
    }

    #[test]
    fn observer_forwards_the_actual_root_and_original_page_boundary() {
        let _scope = crucible::test_support::fixture_decode_scope(256 * 1024 * 1024)
            .unwrap_or_else(|error| panic!("finite API component authority: {error}"));

        let directory =
            tempfile::tempdir().unwrap_or_else(|error| panic!("fixture directory: {error}"));
        let backing = fixture_backing(directory.path());
        let observed =
            decorate_authenticated_backing(Arc::clone(&backing), Some(&ForwardingDecorator))
                .unwrap_or_else(|error| panic!("forwarding genuine backing: {error}"));
        assert!(std::ptr::eq(observed.root_record(), backing.root_record()));

        let region = &backing.root_record().topology().regions()[0];
        let mut checked_original_boundary = false;
        let result = observed.read_page_with_proof(region.id(), 0, &mut || {
            checked_original_boundary = true;
            Err(crucible_qemu::ram_source::QemuRamReadBoundaryError::Canceled)
        });

        assert!(checked_original_boundary);
        assert!(matches!(result, Err(QemuRamSourceError::Canceled)));
    }

    #[test]
    fn observer_cannot_substitute_an_independently_leased_root() {
        let _scope = crucible::test_support::fixture_decode_scope(256 * 1024 * 1024)
            .unwrap_or_else(|error| panic!("finite API component authority: {error}"));

        let original =
            tempfile::tempdir().unwrap_or_else(|error| panic!("original directory: {error}"));
        let other = tempfile::tempdir().unwrap_or_else(|error| panic!("other directory: {error}"));
        let backing = fixture_backing(original.path());
        let replacement = fixture_backing(other.path());
        assert!(!std::ptr::eq(
            backing.root_record(),
            replacement.root_record()
        ));

        let result =
            decorate_authenticated_backing(backing, Some(&ReplacingDecorator(replacement)));

        assert!(result.is_err());
    }
}
