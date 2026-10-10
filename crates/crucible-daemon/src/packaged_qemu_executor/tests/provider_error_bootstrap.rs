//! Original catalog bootstrap refusal before registry or diagnostic admission.

#![cfg(test)]
// crucible-lint: allow panic-shortcut -- the fixture localizes unexpected admission before the original supervisor refusal.
#![allow(clippy::expect_used)]

use super::*;

#[test]
fn catalog_supervisor_refusal_preserves_exact_inline_cause_before_registry_access() {
    let _scope = crate::exact_checkpoint_store::test_support::fixture_decode_scope();
    let directory = tempfile::tempdir().expect("contained component configuration");
    let mut config = config(&directory, 1)
        .with_ram_catalog(fixture_ram_catalog_config(&directory))
        .expect("finite original catalog contract");
    // Inject an invalid original roster at the actual bootstrap boundary. The
    // detached registry has no admission, so reaching it would produce a
    // different error; no filesystem or project-quota qualification is claimed.
    config.host_operation_budgets = Some(crucible_api::host_operational::HostOperationBudgets {
        classes: [crucible_api::host_operational::HostOperationBudget::finite(Duration::ZERO);
            crucible_linux_resource::host_supervision::HOST_OPERATION_CLASS_COUNT],
    });
    let registry = crate::HostOperationalRegistry::default();

    let error = super::super::ram_catalog::admit_catalog_service(&config, &registry)
        .expect_err("original supervisor refuses before any registry or slot admission");

    assert!(matches!(
        error,
        PackagedQemuExecutorError::ProviderServiceAdmission(
            crate::ProviderServiceAdmissionError::Supervision(
                crucible_linux_resource::host_supervision::HostSupervisionError::InvalidBudget
            )
        )
    ));
}
