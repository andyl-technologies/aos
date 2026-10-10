//! Component proof of post-admission asset projection and original-credit custody.
//!
//! The fixture retains the real prepared actor and Directory ledger. It does
//! not qualify Linux quota enforcement, native launch, or guest execution.

use super::*;
use crate::packaged_qemu_executor::preparation::prepare_component_runtime;

#[test]
fn lifecycle_assets_require_installed_catalog_scope_and_retain_original_credit() {
    // An isolated thread cannot inherit another fixture's decoder scope.
    thread::spawn(|| {
        let directory = tempfile::TempDir::new().expect("component directory");
        let mut config = config(&directory, 1);
        let lifecycle = ProductionVmLifecycleConfig::new(
            "selected-qemu",
            "selected-plugin",
            "selected-kernel",
            "selected-root",
            directory.path().join("selected-run-state"),
        );
        let original = config.lifecycle.clone();
        let assignment = config.assignment_resources();
        let template = config.retained_template_resources();
        let semantic_limits = config.assignment_limits();

        assert!(crucible::owned_decode::current_budget().is_none());
        assert!(matches!(
            install_lifecycle_assets(&mut config, &lifecycle),
            Err(PackagedQemuExecutorError::LifecycleConfiguration(
                crucible_api::vm_lifecycle::ProductionVmLifecycleConfigCloneError::MissingAdmission
            ))
        ));
        assert!(Arc::ptr_eq(&config.lifecycle, &original));
        assert_eq!(config.assignment_resources(), assignment);
        assert_eq!(config.retained_template_resources(), template);

        let repository = repository_with_campaigns(&[("packaged", b"shared", "qemu-test")]);
        let basis = authenticate_packaged_campaigns(&repository, &config.campaigns, false)
            .expect("campaign admission");
        let prepared = prepare_component_runtime(
            &repository,
            Arc::new(DirectoryBlobBackend::new(
                "asset-projection-checkpoints",
                directory.path().join("checkpoints"),
            )),
            &basis,
            &config,
        )
        .expect("same actual component actor and catalog account");
        let before = prepared
            .actor
            .with_supervisor(|actor| {
                actor
                    .host_resource_availability()
                    .ok_or(crucible_api::host_operational::HostOperationalError::Unavailable)
            })
            .expect("original complete capacity");
        let decoding = crucible::owned_decode::DecodeBudget::for_store(
            prepared
                .checkpoints
                .metadata_resource_authority()
                .expect("original admitted checkpoint namespace"),
        )
        .expect("catalog metadata account");

        {
            let _scope = decoding.enter();
            install_lifecycle_assets(&mut config, &lifecycle)
                .expect("asset projection after original catalog admission");
            decoding.check().expect("original credit remains valid");
        }

        assert!(crucible::owned_decode::current_budget().is_none());
        assert_eq!(config.lifecycle.executable(), lifecycle.executable());
        assert_eq!(config.lifecycle.plugin(), lifecycle.plugin());
        assert_eq!(
            config.lifecycle.run_state_root(),
            original.run_state_root().join("equivalence")
        );
        assert!(Arc::ptr_eq(
            config
                .lifecycle
                .ram_catalog_provider()
                .expect("retained provider"),
            original.ram_catalog_provider().expect("original provider")
        ));
        assert_eq!(config.assignment_resources(), assignment);
        assert_eq!(config.retained_template_resources(), template);
        assert_eq!(config.assignment_limits(), semantic_limits);
        assert_eq!(
            prepared
                .actor
                .with_supervisor(|actor| {
                    actor
                        .host_resource_availability()
                        .ok_or(crucible_api::host_operational::HostOperationalError::Unavailable)
                })
                .expect("same complete capacity after asset projection"),
            before
        );

        // The returned model owns the child loan after its producer scope ends.
        let scope = config
            .lifecycle
            .enter_input_custody()
            .expect("asset copy retains original metadata custody");
        let copy = config
            .lifecycle
            .try_clone_admitted()
            .expect("retained original authority permits another admitted copy");
        drop(copy);
        drop(scope);
        assert!(crucible::owned_decode::current_budget().is_none());
    })
    .join()
    .expect("asset projection component thread");
}
