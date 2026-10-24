//! Preserves actual negative custody fixtures and their independent observations.
//!
//! Component launchers refuse execution. Retry controls retain the same body,
//! initiating cause and real file owners through canonical queued destruction.

use super::super::{Companion, Contract};

pub(super) const CONTROLS: &[(&str, usize)] = &[
    (
        r###"impl ProductionVmNodeLauncher for RetainedLauncher {
    fn take_construction_custody(&mut self) -> Option<Box<ProductionVmConstructionCustody>> {
        self.custody.take()
    }

    fn begin_execution_quantum(&mut self) -> Result<(), LifecycleApiError> {
        Err(LifecycleApiError::ConstructionCustodyUnavailable)
    }

    fn check_operational_boundary(&mut self) -> Result<(), LifecycleApiError> {
        Err(LifecycleApiError::ConstructionCustodyUnavailable)
    }

    fn launch_fresh(
        &mut self,
        _: ProductionVmNodeLaunchRequest<'_>,
        _: &Path,
        _: &Path,
    ) -> Result<ProductionVmNodeLaunch, LifecycleApiError> {
        Err(LifecycleApiError::ConstructionCustodyUnavailable)
    }

    fn launch_restored(
        &mut self,
        _: ProductionVmNodeLaunchRequest<'_>,
        _: ProductionVmExactNodeRestoreAdmission,
    ) -> Result<ProductionVmNodeLaunch, LifecycleApiError> {
        Err(LifecycleApiError::ConstructionCustodyUnavailable)
    }

    fn replay_candidate(&self) -> Result<Box<dyn ProductionVmNodeLauncher>, LifecycleApiError> {
        Err(LifecycleApiError::ConstructionCustodyUnavailable)
    }

    fn finish(&mut self) -> Result<(), crate::ProductionVmConstructionCleanupError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(failure) = self.retained_failure.as_ref() {
            return failure.retry_cleanup();
        }
        if let Some(failure) = self.raw_failure.take() {
            return Err(failure.into());
        }
        if self.refuse_once.swap(false, Ordering::SeqCst) {
            Err((LifecycleApiError::ConstructionCustodyUnavailable).into())
        } else {
            Ok(())
        }
    }
}"###,
        1,
    ),
    (
        r###"impl crucible_control_api::ProductionVmCleanupOwner for RetainedLauncher {
    type Failure = crate::ProductionVmConstructionCleanupError;
    type PostBody = crate::ProductionVmConstructionPostBody;

    fn take_post_body(&mut self) -> Result<Option<Self::PostBody>, Self::Failure> {
        // This component launcher owns no native World or Service return.
        Ok(None)
    }

    fn retry_cleanup(&mut self) -> Result<(), crate::ProductionVmConstructionCleanupError> {
        ProductionVmNodeLauncher::finish(self)
    }
}"###,
        1,
    ),
    (
        r###"fn absent_storage_keeps_same_launcher_and_first_cause_through_retry() {
    let (launcher, calls, drops) = launcher(None);
    let failure = with_inputs(launcher, None, None, None, Vec::new()).unwrap_err();
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(drops.load(Ordering::SeqCst), 0);

    assert!(failure.retry_cleanup().is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    assert_eq!(
        failure.first(),
        Some(&LifecycleApiError::ConstructionCustodyUnavailable)
    );

    failure.retry_cleanup().unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    assert_eq!(
        failure.first(),
        Some(&LifecycleApiError::ConstructionCustodyUnavailable)
    );
    drop(failure);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}"###,
        1,
    ),
    (
        r###"fn rejected_assembly_returns_the_same_partial_owner_without_new_storage() {
    let (launcher, calls, drops) = launcher(Some(Box::new(ProductionVmConstructionCustody::new())));
    let mut custody = with_inputs(launcher, None, None, None, Vec::new()).unwrap();
    let address = (&*custody as *const ProductionVmConstructionCustody) as usize;
    let first = custody.complete_with(Err).unwrap_err();
    let failure = custody.into_failure(first.clone());
    let custody = failure.into_custody().unwrap();
    assert_eq!(
        (&*custody as *const ProductionVmConstructionCustody) as usize,
        address
    );

    assert!(custody.retry_cleanup().is_err());
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    custody.retry_cleanup().unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    assert_eq!(custody.first.as_ref(), Some(&first));
    custody.retry_cleanup().unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    drop(custody);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}"###,
        1,
    ),
    (
        r###"fn component_error_extraction_preserves_the_same_body_without_publication() {
    let _scope = crucible_engine::test_support::fixture_decode_scope(1024 * 1024).unwrap();
    let carrier = ProductionVmConstructionCustody::prepare_component().unwrap();
    let address = std::ptr::from_ref(&*carrier);
    let (launcher, calls, drops) = launcher(Some(carrier));
    let custody = with_inputs(launcher, None, None, None, Vec::new()).unwrap();
    let mut failure = custody.into_failure(LifecycleApiError::LoopFactory {
        message: String::from("actual component admission refusal"),
    });

    let first = failure.take_component_first_error().unwrap();
    assert!(matches!(first, LifecycleApiError::LoopFactory { message }
        if message == "actual component admission refusal"));
    assert!(failure.take_component_first_error().is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    let custody = failure.into_custody().unwrap();
    assert_eq!(std::ptr::from_ref(&*custody), address);
    assert!(custody.first.is_none());
    #[cfg(target_os = "linux")]
    assert!(custody.reservation.is_none());

    assert!(custody.retry_cleanup().is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    custody.retry_cleanup().unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    drop(custody);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}"###,
        1,
    ),
    (
        r###"fn borrowed_preparation_keeps_the_same_carrier_and_owner_after_validation_refuses() {
    let source = crucible_engine::crash_restart_scenario().unwrap().scenario;
    let other = ScenarioDef::from_canonical_material(
        "crucible.test.borrowed-construction",
        "different-scenario",
    );
    let config = ProductionVmLifecycleConfig::new("qemu", "plugin", "kernel", "root", "state");

    for exposure in [
        construction::ExactRestoreExposure::Released,
        construction::ExactRestoreExposure::AwaitingOwnershipCommit,
    ] {
        let mut custody = Box::new(ProductionVmConstructionCustody::new());
        let carrier_address = std::ptr::from_ref(&*custody);
        let (input, calls, drops) = launcher(None);
        let launcher_address = std::ptr::from_ref(&*input);
        let mut input = Some(input);
        custody.install_inputs(&mut input, &mut None).unwrap();
        assert!(input.is_none());

        let first =
            construction::prepare_from_custody(&other, &source, &config, &mut custody, exposure)
                .unwrap_err();

        assert_eq!(std::ptr::from_ref(&*custody), carrier_address);
        let retained = custody
            .partial_mut()
            .unwrap()
            .node_launcher
            .as_ref()
            .unwrap();
        assert!(std::ptr::addr_eq(
            std::ptr::from_ref(&**retained),
            launcher_address,
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        assert!(first.to_string().contains("requested scenario"));

        let failure = custody.into_failure(first.clone());
        assert!(failure.retry_cleanup().is_err());
        failure.retry_cleanup().unwrap();
        assert_eq!(failure.first_error(), Some(&first));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        drop(failure);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }
}"###,
        1,
    ),
    (
        r###"fn borrowed_preparation_refuses_physically_closed_custody_before_any_new_effect() {
    let source = crucible_engine::crash_restart_scenario().unwrap().scenario;
    let config = ProductionVmLifecycleConfig::new("qemu", "plugin", "kernel", "root", "state");
    let mut custody = Box::new(ProductionVmConstructionCustody::new());
    let (input, calls, drops) = launcher(None);
    let mut input = Some(input);
    custody.install_inputs(&mut input, &mut None).unwrap();
    assert!(custody.retry_cleanup().is_err());
    custody.retry_cleanup().unwrap();
    assert!(custody.physically_closed.load(Ordering::Acquire));
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    let result = construction::prepare_from_custody(
        &source.scenario_def(),
        &source,
        &config,
        &mut custody,
        construction::ExactRestoreExposure::Released,
    );

    assert_eq!(
        result,
        Err(LifecycleApiError::ConstructionCustodyUnavailable)
    );
    assert!(custody.partial_mut().unwrap().retained_config.is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    drop(custody);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}"###,
        1,
    ),
    (
        r###"fn retained_fork_validation_failure_stays_in_the_original_carrier() {
    let source = crucible_engine::crash_restart_scenario().unwrap().scenario;
    let other = ScenarioDef::from_canonical_material(
        "crucible.test.borrowed-fork-construction",
        "different-scenario",
    );
    let (_, mut world) =
        crate::vm_lifecycle::production_permanently_failed_loop_for_test().unwrap();
    let mut continuation = Some(world.capture_hot_fork_world_continuation().unwrap());
    let configuration = continuation.as_ref().unwrap().configuration().id();
    let (input, calls, drops) = launcher(None);
    let launcher_address = std::ptr::from_ref(&*input);
    let mut input = Some(input);
    let mut adoptions = Vec::with_capacity(7);
    let adoption_buffer = adoptions.as_ptr();
    let adoption_capacity = adoptions.capacity();
    let mut custody = Box::new(ProductionVmConstructionCustody::new());
    let carrier_address = std::ptr::from_ref(&*custody);
    custody
        .install_hot_fork_inputs(&mut input, &mut continuation, &mut adoptions)
        .unwrap();

    let first = prepare_retained_hot_fork_construction(
        &other,
        &source,
        &mut custody,
        PathBuf::from("unused-fork-state"),
    )
    .unwrap_err();

    assert!(first.to_string().contains("requested scenario"));
    assert!(input.is_none());
    assert!(continuation.is_none());
    assert_eq!(adoptions.capacity(), 0);
    assert_eq!(std::ptr::from_ref(&*custody), carrier_address);
    let partial = custody.partial_mut().unwrap();
    assert!(std::ptr::addr_eq(
        std::ptr::from_ref(&**partial.node_launcher.as_ref().unwrap()),
        launcher_address,
    ));
    assert_eq!(
        partial
            .hot_fork_continuation
            .as_ref()
            .unwrap()
            .configuration()
            .id(),
        configuration
    );
    assert_eq!(partial.hot_fork_adoptions.as_ptr(), adoption_buffer);
    assert_eq!(partial.hot_fork_adoptions.capacity(), adoption_capacity);
    assert!(partial.restore_checkpoint.is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(drops.load(Ordering::SeqCst), 0);

    let failure = custody.into_failure(first.clone());
    assert!(failure.retry_cleanup().is_err());
    failure.retry_cleanup().unwrap();
    assert_eq!(failure.first_error(), Some(&first));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    drop(failure);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}"###,
        1,
    ),
    (
        r###"fn rejected_two_body_cleanup_keeps_both_leaves_through_actual_queued_destruction() {
    // Local launchers own real files but refuse all execution operations. This
    // exercises existing carrier/cell custody, not Main or native admission.
    let (existing_launcher, existing_calls, existing_drops, existing_cause) =
        raw_launcher("existing carrier", None);
    let mut existing = Box::new(ProductionVmConstructionCustody::new());
    existing.first = Some(LifecycleApiError::ConstructionCustodyUnavailable);
    existing.partial_mut().unwrap().node_launcher = Some(existing_launcher);
    let (incoming_launcher, incoming_calls, incoming_drops, incoming_cause) =
        raw_launcher("incoming partial", Some(existing));
    let failure = with_inputs(incoming_launcher, None, None, None, Vec::new()).unwrap_err();
    let wrapper_calls = Arc::new(AtomicUsize::new(0));
    let wrapper_drops = Arc::new(AtomicUsize::new(0));
    let wrapper = Box::new(RetainedLauncher {
        calls: Arc::clone(&wrapper_calls),
        drops: Arc::clone(&wrapper_drops),
        refuse_once: AtomicBool::new(false),
        custody: None,
        raw_failure: None,
        retained_failure: Some(failure),
    });

    let history = crate::lifecycle_cleanup::component_owner_history_for_test(wrapper, || {
        assert_eq!(incoming_calls.load(Ordering::SeqCst), 1);
        assert_eq!(existing_calls.load(Ordering::SeqCst), 1);
        assert_eq!(incoming_drops.load(Ordering::SeqCst), 0);
        assert_eq!(existing_drops.load(Ordering::SeqCst), 0);
        assert!(incoming_cause.is_open());
        assert!(existing_cause.is_open());
    });

    assert_eq!(wrapper_calls.load(Ordering::SeqCst), 2);
    assert_eq!(wrapper_drops.load(Ordering::SeqCst), 1);
    assert_eq!(incoming_calls.load(Ordering::SeqCst), 2);
    assert_eq!(existing_calls.load(Ordering::SeqCst), 2);
    assert_eq!(incoming_drops.load(Ordering::SeqCst), 1);
    assert_eq!(existing_drops.load(Ordering::SeqCst), 1);
    let ProductionVmConstructionCleanupError::GuardPair {
        first: Some(ProductionVmCleanupEarlierFailure::Poisoned),
        first_guard,
        second_guard,
    } = &history
    else {
        panic!("both independently owned bodies must retain their actual leaves: {history:?}");
    };
    incoming_cause.assert_same_leaf(first_guard);
    existing_cause.assert_same_leaf(second_guard);
    drop(history);
    assert!(!incoming_cause.is_open());
    assert!(!existing_cause.is_open());
}"###,
        1,
    ),
    (
        r###"fn component_carrier_requires_existing_metadata_admission() {
    assert!(crucible_engine::owned_decode::current_custody().is_none());
    assert!(ProductionVmConstructionCustody::prepare_component().is_err());

    let _scope = crucible_engine::test_support::fixture_decode_scope(1024 * 1024).unwrap();
    let carrier = ProductionVmConstructionCustody::prepare_component().unwrap();
    assert!(carrier.component_funding.is_some());
    #[cfg(target_os = "linux")]
    assert!(carrier.reservation.is_none());
}"###,
        1,
    ),
    (
        r###"fn component_error_extraction_refuses_an_ordinary_carrier() {
    let (launcher, calls, drops) = launcher(Some(Box::new(ProductionVmConstructionCustody::new())));
    let custody = with_inputs(launcher, None, None, None, Vec::new()).unwrap();
    let mut failure = custody.into_failure(LifecycleApiError::ConstructionCustodyUnavailable);

    assert!(failure.take_component_first_error().is_none());
    assert_eq!(
        failure.first_error(),
        Some(&LifecycleApiError::ConstructionCustodyUnavailable)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    drop(failure);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}"###,
        1,
    ),
];

pub(super) const CONTRACT: Contract = Contract {
    package: "crucible-daemon",
    target: "src/vm_lifecycle/construction/custody/tests",
    required: CONTROLS,
    expressions: &[
        ("failure.retry_cleanup()", 7),
        ("custody.retry_cleanup()", 7),
    ],
    identifiers: &[
        ("retry_cleanup", 15),
        ("absent_storage_keeps_same_launcher_and_first_cause_through_retry", 1),
    ],
    companions: &[
        Companion {
            path: "crates/crucible/crucible-daemon/src/vm_lifecycle/construction/custody.rs",
            required: super::construction_custody::BODY,
        },
        super::super::production_publication::CONSTRUCTOR_RESERVATION,
        super::super::production_publication::CONSTRUCTOR_QUEUE,
        super::super::production_publication::CONSTRUCTOR_DRIVER,
        super::super::production_publication::CONSTRUCTOR_QUEUED_OWNER,
        super::super::production_publication::ROLE_REPORTS,
    ],
};
