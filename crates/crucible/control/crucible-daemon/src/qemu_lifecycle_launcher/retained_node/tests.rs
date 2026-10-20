//! Exercises real local owners without creating a Source or launching a child.

use super::*;
use std::os::unix::fs::FileExt;

struct UnexecutedGuard {
    cancellation: ExecutionCancellation,
}

impl crate::QemuAttemptOperationalBoundary for UnexecutedGuard {
    fn resource_limits(&self) -> crucible_campaign::AttemptResourceLimits {
        crucible_campaign::AttemptResourceLimits::new(1, 64 * 1024 * 1024, 128 * 1024 * 1024, 8)
            .expect("same component registry limits")
    }

    fn cancellation(&self) -> &ExecutionCancellation {
        &self.cancellation
    }

    fn check_operational_boundary(&mut self) -> Result<(), QemuVmRealizationError> {
        panic!("descriptor controls cannot execute a guest")
    }

    fn charge_execution_quantum(&mut self) -> Result<(), QemuVmRealizationError> {
        panic!("descriptor controls cannot execute a guest")
    }
}

impl crate::QemuAttemptResourceGuard for UnexecutedGuard {
    fn finish(&mut self) -> Result<(), crate::QemuAttemptResourceGuardCleanupFailure> {
        Ok(())
    }

    fn quarantine(&mut self) {
        // This component guard has no native allocation or process to return.
    }
}

struct Fixture {
    owner: QemuAttemptGenerationResourceOwner<UnexecutedGuard>,
    preparation: RetainedFreshPreparation,
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let node = crucible_engine::NodeId {
            name: String::from("descriptor-only"),
        };
        let storage = crate::QemuAttemptGenerationStorage::prepare(std::iter::once(&node))?;
        let mut owner = QemuAttemptGenerationResourceOwner::new(
            UnexecutedGuard {
                cancellation: ExecutionCancellation::default(),
            },
            storage,
        );
        let lease = owner.register_generation(ProductionVmNodeGeneration::new(node, 1)?)?;
        let directory = tempfile::tempdir()?;
        std::fs::write(
            directory
                .path()
                .join(crucible_qemu_host::DEFAULT_VMSTATE_FILE_NAME),
            b"same pinned VMState",
        )?;
        std::fs::write(
            directory
                .path()
                .join(crucible_qemu_host::DEFAULT_ROOT_OVERLAY_FILE_NAME),
            b"",
        )?;
        let contract = QemuChildProcessContract::from_unvalidated_test_descriptors(
            tempfile::tempfile()?.into(),
            rustix::event::eventfd(0, rustix::event::EventfdFlags::CLOEXEC)?,
            u32::MAX,
            u64::MAX,
            u64::MAX,
        );
        let prepared = QemuPreparedRunDirectory::open_for_test_requirements(
            crucible_qemu_host::QemuLaunchResourceRequirements::from_vm_shape(1, 1, true),
            directory.path(),
            &contract,
        )?;
        assert!(contract.issued_helper_receiver().is_none());
        let mut preparation =
            RetainedFreshPreparation::new(lease, prepared, std::sync::Weak::new());
        // An adversarial nonissued input can only exercise refusal. No helper,
        // Native admission or cleanup is invoked under this component contract.
        preparation.contract = Some(contract);
        Ok(Self {
            owner,
            preparation,
            _directory: directory,
        })
    }

    fn assert_same_owners(&self) -> Result<(), Box<dyn std::error::Error>> {
        let preparation = &self.preparation;
        assert_eq!(
            preparation
                .lease
                .as_ref()
                .expect("same lease")
                .identity()
                .generation(),
            1,
        );
        assert!(preparation.contract.is_some());
        assert!(matches!(preparation.body, FreshPreparationBody::Empty));
        let mut contents = [0; b"same pinned VMState".len()];
        preparation
            .directory()?
            .open_vmstate_for_hot_fork()?
            .read_exact_at(&mut contents, 0)?;
        assert_eq!(&contents, b"same pinned VMState");
        Ok(())
    }

    fn dispose_unexecuted(mut self) -> Result<(), Box<dyn std::error::Error>> {
        // The test created no helper/native call. Dispose its actual descriptors
        // before using the real local registry's exact no-process return.
        drop(self.preparation.contract.take());
        drop(self.preparation.directory.take());
        self.preparation
            .lease
            .as_mut()
            .expect("same lease")
            .abort_without_process()?;
        self.preparation.lease = None;
        self.owner.finish()?;
        Ok(())
    }
}

#[test]
fn incomplete_transfer_restores_the_same_local_generation_and_directory()
-> Result<(), Box<dyn std::error::Error>> {
    let Fixture {
        owner,
        preparation,
        _directory,
    } = Fixture::new()?;
    let preparation = match preparation.into_prepared() {
        Ok(_) => panic!("missing real Node cannot become a prepared generation"),
        Err(preparation) => preparation,
    };
    let fixture = Fixture {
        owner,
        preparation,
        _directory,
    };
    fixture.assert_same_owners()?;
    fixture.dispose_unexecuted()
}

#[test]
fn uncertain_native_entry_and_unauthenticated_return_never_dispose_local_owners()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::new()?;
    for progress in [
        NativeLaunchProgress::Entered,
        NativeLaunchProgress::Returned,
    ] {
        fixture.preparation.native = progress;
        assert!(matches!(
            fixture.preparation.finish(),
            Err(crate::ProductionVmConstructionCleanupError::Retained(
                "fresh native entry has no authenticated returned failure",
            ))
        ));
        assert!(fixture.preparation.native == progress);
        fixture.assert_same_owners()?;
    }
    fixture.dispose_unexecuted()
}

#[test]
fn physical_owner_drop_unwind_keeps_the_actual_return_guard_unresolved()
-> Result<(), Box<dyn std::error::Error>> {
    struct UncertainOwner;

    impl Drop for UncertainOwner {
        fn drop(&mut self) {
            panic!("physical owner destruction interrupted")
        }
    }

    let mut fixture = Fixture::new()?;
    // This invokes only the production progress guard, not an issued Source
    // poll. A normal negative keeps the same retry state; an actual destructor
    // unwind must leave it irrevocably rejecting before any later observation.
    fixture.preparation.native = NativeLaunchProgress::AuthenticatedFailure;
    assert!(!fixture.preparation.native.observe_physical_return(|| false));
    assert!(fixture.preparation.native == NativeLaunchProgress::AuthenticatedFailure);

    let first = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        fixture.preparation.native.observe_physical_return(|| {
            drop(Some(UncertainOwner));
            true
        })
    }));
    let first = first.expect_err("actual destructor panic must remain outward");
    assert_eq!(
        first.downcast_ref::<&str>(),
        Some(&"physical owner destruction interrupted"),
    );
    assert!(fixture.preparation.native == NativeLaunchProgress::Unresolved);
    for _ in 0..2 {
        assert!(matches!(
            fixture.preparation.finish(),
            Err(crate::ProductionVmConstructionCleanupError::Retained(
                "fresh native entry has no authenticated returned failure",
            ))
        ));
        assert!(fixture.preparation.native == NativeLaunchProgress::Unresolved);
        fixture.assert_same_owners()?;
    }
    fixture.dispose_unexecuted()
}
