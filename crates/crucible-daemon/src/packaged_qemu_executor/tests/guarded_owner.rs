//! Component tests for immutable guarded authority and production refusal.
//!
//! These exercise genuine configured actor ownership and admission boundaries;
//! they do not qualify a native guest or an operator-installed quota filesystem.

use super::*;

#[test]
fn deferred_guarded_admission_refuses_until_the_exact_closed_basis_is_bound() {
    let repository = repository_with_campaigns(&[("packaged", b"shared", "qemu-test")]);
    let admission = PackagedAttemptAdmission::default();
    let request = controlled_submit_request(DaemonEpoch::from_bytes([0x61; 16]).expect("epoch"));
    assert_eq!(
        admission.validate(&request),
        Err(ExecutorRejection::Unauthorized)
    );

    let admitted_profile = profile();
    let scenarios = BTreeSet::from([scenario_artifact()]);
    admission
        .bind(
            repository.clone(),
            admitted_profile.clone(),
            scenarios.clone(),
        )
        .expect("bind exact closed basis");
    admission
        .bind(repository.clone(), admitted_profile, scenarios.clone())
        .expect("repeat identical authority");

    let different_profile = ExecutorCompatibilityProfile::new(
        "crucible-test",
        "different-qemu",
        BTreeMap::from([(String::from("control"), 1)]),
        1,
        1,
    )
    .expect("different compatibility");
    assert!(
        admission
            .bind(repository.clone(), different_profile, scenarios.clone())
            .is_err()
    );
    assert!(
        admission
            .bind(repository.clone(), profile(), BTreeSet::new())
            .is_err()
    );
    let different_repository = repository_with_campaigns(&[("packaged", b"shared", "qemu-test")]);
    assert!(
        admission
            .bind(different_repository, profile(), scenarios)
            .is_err()
    );
    let retained = admission
        .get()
        .expect("original authority survives all refusals");
    assert!(Arc::ptr_eq(&retained.repository, &repository));
    assert_eq!(retained.profile, profile());
    assert_eq!(retained.scenarios, BTreeSet::from([scenario_artifact()]));
}

#[test]
fn guarded_owner_refuses_missing_main_before_any_namespace_publication() {
    let directory = tempfile::TempDir::new().expect("directory");
    let config = config(&directory, 1);
    let run_state = config.lifecycle.run_state_root().to_owned();
    let ledger_root = config.ledger_root().to_owned();
    let catalog_root = config
        .ram_catalog()
        .expect("authored catalog")
        .root()
        .to_owned();
    let result = guarded::GuardedCampaignOwner::open(config);

    assert!(matches!(
        result,
        Err(PackagedQemuExecutorError::MissingNormalProcessOwner)
    ));
    assert!(!ledger_root.exists());
    assert!(!catalog_root.exists());
    assert!(!run_state.join("guarded-campaign").exists());
}

#[cfg(target_os = "linux")]
// crucible-lint: allow rust-allow -- the genuine Main quota control waits for authenticated producer admission rather than a component Main substitute.
#[allow(
    dead_code,
    reason = "The authentic normal Main quota fixture remains unqualified."
)]
fn genuine_guarded_owner_refuses_uninstalled_quota_before_publication(
    config: PackagedQemuExecutorConfig,
) {
    config
        .normal_executor
        .as_ref()
        .expect("actual normal Main")
        .check()
        .expect("unchanged Main authority");
    let run_state = config.lifecycle.run_state_root().to_owned();
    let ledger_root = config.ledger_root().to_owned();
    let catalog_root = config
        .ram_catalog()
        .expect("authored catalog")
        .root()
        .to_owned();

    let result = guarded::GuardedCampaignOwner::open(config);

    let Err(PackagedQemuExecutorError::RegistryQuota(
        crucible_linux_resource::LinuxProjectQuotaError::Io {
            operation,
            path,
            source,
        },
    )) = result
    else {
        panic!("uninstalled genuine Main quota must refuse before publication");
    };
    assert_eq!(operation, "open-physical-quota-root");
    assert_eq!(path, ledger_root);
    assert_eq!(source.kind(), std::io::ErrorKind::NotFound);
    assert!(!ledger_root.exists());
    assert!(!catalog_root.exists());
    assert!(!run_state.join("guarded-campaign").exists());
}

#[cfg(target_os = "linux")]
// crucible-lint: allow rust-allow -- this lifecycle control awaits a genuine Main Source fixture; no scripted or scalar authority issues the opaque target permit.
#[allow(
    dead_code,
    reason = "The authentic standalone normal Main Source fixture remains unqualified."
)]
fn genuine_standalone_main_retirement_retains_busy_custody_and_closes_once(
    mut owner: guarded::GuardedCampaignOwner,
    mut source: crate::vm_lifecycle::ProductionVmHotForkSourceWorld,
    target_resources: AttemptResourceLimits,
) {
    owner
        .inner
        .config
        .normal_executor
        .as_ref()
        .expect("actual normal Main")
        .check()
        .expect("unchanged Main authority");
    let original_owner = Arc::as_ptr(&owner.inner);
    let peer = owner.clone();
    assert!(matches!(
        owner.try_retire().unwrap_err().first_error(),
        guarded::GuardedCampaignOwnerRetirementCause::SharedOwner
    ));
    assert_eq!(Arc::as_ptr(&owner.inner), original_owner);
    drop(peer);
    let weak = Arc::downgrade(&owner.inner);
    assert!(matches!(
        owner.try_retire().unwrap_err().first_error(),
        guarded::GuardedCampaignOwnerRetirementCause::SharedOwner
    ));
    assert_eq!(Arc::as_ptr(&owner.inner), original_owner);
    drop(weak);
    owner
        .inner
        .actor
        .with_supervisor(|_| Ok(()))
        .expect("clone destruction keeps the same Main admission live");
    let host_alias = owner.inner.host.clone();
    assert!(owner.try_retire().is_err());
    assert_eq!(Arc::as_ptr(&owner.inner), original_owner);
    drop(host_alias);

    let preparation = source.prepare_fork_target().expect("genuine Source permit");
    let (permit, mut target_cleanup) = match preparation {
        crucible_qemu::QemuForkTargetPreparation::Ready { permit, cleanup } => (permit, cleanup),
        crucible_qemu::QemuForkTargetPreparation::Retained { first, .. } => {
            panic!("genuine Target landing refused: {first}");
        }
    };
    let inner = Arc::get_mut(&mut owner.inner).expect("same exclusive owner");
    let mut target = inner
        .host
        .begin_fork_target(permit, target_resources)
        .expect("actual same-family Target and paid Main dispatcher");
    assert!(owner.try_retire().is_err());
    assert_eq!(Arc::as_ptr(&owner.inner), original_owner);
    assert!(source.fork_target_is_owned());
    target.finish().expect("actual Target job cleanup");
    drop(target);
    target_cleanup
        .try_finish()
        .expect("exact Target role return");
    assert!(target_cleanup.is_physically_returned());
    assert!(owner.try_retire().is_err());
    assert_eq!(Arc::as_ptr(&owner.inner), original_owner);
    source.retire().expect("actual Source cleanup");
    drop(source);

    owner
        .try_retire()
        .expect("actual standalone Main terminal retirement");
    assert_eq!(Arc::as_ptr(&owner.inner), original_owner);
    assert!(owner.inner.actor.with_supervisor(|_| Ok(())).is_err());
    owner
        .try_retire()
        .expect("same completed physical retirement");
    assert_eq!(Arc::as_ptr(&owner.inner), original_owner);
}

#[cfg(target_os = "linux")]
// crucible-lint: allow rust-allow -- this deterministic final-release control requires an authenticated Main owner and exercises its actual facade Drop path.
#[allow(
    dead_code,
    reason = "The authentic standalone Main final-release fixture remains unqualified."
)]
fn genuine_concurrent_final_releases_retain_the_same_uncertain_owner(
    mut owner: guarded::GuardedCampaignOwner,
) {
    owner
        .inner
        .config
        .normal_executor
        .as_ref()
        .expect("actual normal Main")
        .check()
        .expect("unchanged Main authority");
    owner
        .install_final_release_barrier(Arc::new(std::sync::Barrier::new(2)))
        .expect("exclusive authentic fixture before release");
    let weak = Arc::downgrade(&owner.inner);
    let peer = owner.clone();

    let first = thread::spawn(move || drop(owner));
    let second = thread::spawn(move || drop(peer));
    first.join().expect("first real facade release");
    second.join().expect("second real facade release");

    // The barrier holds both real Drop bodies before either field can drop.
    // The retained weak alias forces native exclusivity refusal: exactly one
    // final-release selection must keep the entire same allocation alive.
    let retained = weak
        .upgrade()
        .expect("same complete failure owner retained");
    assert!(retained.facades.is_quarantined());
    assert!(std::ptr::eq(Arc::as_ptr(&retained), weak.as_ptr()));
}

#[cfg(target_os = "linux")]
// crucible-lint: allow rust-allow -- actual poisoned factory custody must retain its genuine Main owner, not a component success substitute.
#[allow(
    dead_code,
    reason = "The authentic standalone Main poison fixture remains unqualified."
)]
fn genuine_poisoned_factory_retains_the_same_final_owner(mut owner: guarded::GuardedCampaignOwner) {
    owner
        .inner
        .config
        .normal_executor
        .as_ref()
        .expect("actual normal Main")
        .check()
        .expect("unchanged Main authority");
    owner.inner.host.poison_custody_for_test();
    assert!(owner.try_retire().is_err());
    let weak = Arc::downgrade(&owner.inner);

    drop(owner);

    let retained = weak.upgrade().expect("actual poisoned owner retained");
    assert!(retained.facades.is_quarantined());
}

#[cfg(target_os = "linux")]
// crucible-lint: allow rust-allow -- corrupted facade accounting is tested only as a refusal on the real retained Main owner.
#[allow(
    dead_code,
    reason = "The authentic standalone Main counter fixture remains unqualified."
)]
fn genuine_corrupt_final_release_accounting_retains_the_same_owner(
    owner: guarded::GuardedCampaignOwner,
) {
    owner
        .inner
        .config
        .normal_executor
        .as_ref()
        .expect("actual normal Main")
        .check()
        .expect("unchanged Main authority");
    let weak = Arc::downgrade(&owner.inner);
    owner.corrupt_final_release_record_for_test();

    drop(owner);

    let retained = weak.upgrade().expect("underflow keeps actual owner");
    assert!(retained.facades.is_quarantined());
}

#[cfg(target_os = "linux")]
// crucible-lint: allow rust-allow -- counter overflow is a negative custody control on the authentic Main owner and creates no native authority.
#[allow(
    dead_code,
    reason = "The authentic standalone Main overflow fixture remains unqualified."
)]
fn genuine_clone_record_overflow_seals_the_same_retained_owner(
    mut owner: guarded::GuardedCampaignOwner,
) {
    owner
        .inner
        .config
        .normal_executor
        .as_ref()
        .expect("actual normal Main")
        .check()
        .expect("unchanged Main authority");
    let weak = Arc::downgrade(&owner.inner);
    owner.exhaust_final_clone_record_for_test();

    let mut sealed = owner.clone();

    assert!(matches!(
        owner.try_retire().unwrap_err().first_error(),
        guarded::GuardedCampaignOwnerRetirementCause::UncertainOwner
    ));
    assert!(matches!(
        sealed.try_retire().unwrap_err().first_error(),
        guarded::GuardedCampaignOwnerRetirementCause::UncertainOwner
    ));
    assert!(Arc::ptr_eq(&owner.inner, &sealed.inner));
    drop(owner);
    drop(sealed);
    assert!(
        weak.upgrade()
            .expect("overflow retains the entire same owner")
            .facades
            .is_quarantined()
    );
}
