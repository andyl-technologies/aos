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
fn guarded_owner_refuses_uninstalled_physical_quota_before_campaign_publication() {
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

    let error = result.err().expect("uninstalled ledger quota must refuse");
    let PackagedQemuExecutorError::RegistryQuota(
        crucible_linux_resource::LinuxProjectQuotaError::Io {
            operation,
            path,
            source,
        },
    ) = error
    else {
        panic!("the original registry quota must refuse first: {error:?}");
    };
    assert_eq!(operation, "open-physical-quota-root");
    assert_eq!(path, ledger_root);
    assert_eq!(source.kind(), std::io::ErrorKind::NotFound);
    assert!(!ledger_root.exists());
    assert!(!catalog_root.exists());
    assert!(!run_state.join("guarded-campaign").exists());
}
