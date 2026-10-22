//! Host-I/O runtime construction and slot-access errors.

use crucible_qemu_shmem::{MappedSetupRegionAccessError, SetupRegionMapError};
use thiserror::Error;

use crate::QemuAsyncDriverRuntimeError;

/// Maps a node-slot access failure to a runtime await error.
pub(super) fn map_slot_error(source: MappedSetupRegionAccessError) -> QemuAsyncDriverRuntimeError {
    QemuAsyncDriverRuntimeError::mapped_region_access("poll advance completion", source)
}

/// Error building a [`super::QemuLiveHostIoRuntime`].
#[derive(Debug, Error)]
pub enum QemuLiveHostIoRuntimeError {
    /// The shared-memory region could not be mapped.
    #[error("map shared-memory region failed: {source}")]
    MapRegion {
        /// Underlying mapping error.
        source: SetupRegionMapError,
    },
    /// The plugin wake eventfd could not be cloned.
    #[error("clone plugin wake eventfd failed: {source}")]
    CloneWakeFd {
        /// Underlying descriptor clone error.
        source: std::io::Error,
    },
    /// The node's fixed network rings could not be bound.
    #[error("bind host-I/O network rings failed: {source}")]
    NetworkRing {
        /// Invalid node identity, ring direction, or mapped geometry.
        source: MappedSetupRegionAccessError,
    },
    /// The configured poll interval was zero.
    #[error("host-I/O runtime poll interval must be nonzero")]
    ZeroPollInterval,
    /// More than one console stream was attached to one node runtime.
    #[error("QEMU host-I/O runtime already has a console stream")]
    DuplicateConsole,
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crucible_host_resources::host_supervision::{
        HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
    };
    use crucible_host_resources::test_support::TestAllocationObserver;
    use std::io::Write;
    use std::os::fd::AsFd;

    #[test]
    fn actual_mapped_refusal_retains_typed_cause_and_independent_post_without_allocation()
    -> Result<(), Box<dyn std::error::Error>> {
        let allocation = crucible_qemu_shmem::RegionAllocation::new_model(
            crucible_qemu_shmem::RegionConfig::new(1, 4),
        )?;
        let length = allocation.layout().region_size;
        let mut file = std::fs::File::from(crate::spawn::memfd_region(length)?);
        file.write_all(&allocation.setup_region_bytes()?)?;
        let mapping = crucible_qemu_shmem::mmap_setup_region(file.as_fd(), length)?;
        let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;
        let original = supervisor.begin(HostOperationClass::Quantum)?;
        supervisor.cancel()?;
        let post = original
            .wait_slice()
            .expect_err("actual Original is canceled");

        let ((source, error), counts) = TestAllocationObserver::count(|| {
            let source = match mapping.node_slot(u32::MAX) {
                Err(source) => source,
                Ok(_) => panic!("actual mapping cannot contain the foreign node"),
            };
            let error = map_slot_error(source.clone()).with_operational_supervision_post(post);
            (source, error)
        });

        assert_eq!(counts.allocations, 0);
        assert_eq!(counts.reallocations, 0);
        assert!(!counts.overflow);
        assert_eq!(error.mapped_region_access_source(), Some(&source));
        assert_eq!(error.operational_supervision_post(), Some(post));
        assert!(error.message.is_empty());
        assert_eq!(
            std::error::Error::source(&error)
                .and_then(|cause| cause.downcast_ref::<MappedSetupRegionAccessError>()),
            Some(&source),
        );
        assert_eq!(
            error.to_string(),
            format!(
                "poll advance completion failed: {source}; independent host operation postcheck failed: {post}"
            ),
        );
        Ok(())
    }
}
