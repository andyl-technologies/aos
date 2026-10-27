//! Checks original quota supervision before any namespace effect.

use super::*;

#[test]
fn canceled_project_admission_never_calls_the_backing_effect_boundary() {
    let duration = std::time::Duration::from_secs(60);
    let supervisor = HostOperationSupervisor::new(
        crate::host_supervision::HostOperationBudgets {
            classes: [crate::host_supervision::HostOperationBudget::finite(duration);
                crate::host_supervision::HOST_OPERATION_CLASS_COUNT],
        },
        Some(duration),
    )
    .unwrap_or_else(|error| panic!("authored original fixture roster: {error}"));
    supervisor
        .cancel()
        .unwrap_or_else(|error| panic!("cancel original fixture owner: {error}"));
    let mut admitted = false;
    let result = SupervisedProjectQuotaBinding::bind_existing_admitted(
        Path::new("/aos-quota-admission-must-remain-unopened"),
        701,
        16 << 20,
        16,
        supervisor,
        &mut |_| {
            admitted = true;
            Ok(())
        },
    );

    assert!(matches!(
        result,
        Err(SupervisedProjectQuotaError::Supervision(_))
    ));
    assert!(!admitted);
}

#[test]
fn persistent_binding_uses_the_original_guard_before_namespace_access() {
    let supervisor = HostOperationSupervisor::new(
        crate::host_supervision::HostOperationBudgets::default(),
        None,
    )
    .unwrap_or_else(|error| panic!("finite component roster: {error}"));
    let operation = supervisor
        .begin_work(HostOperationClass::Preparation, 16)
        .unwrap_or_else(|error| panic!("original preparation scope: {error}"));
    let directory =
        tempfile::tempdir().unwrap_or_else(|error| panic!("owned component namespace: {error}"));
    let absent = directory.path().join("must-remain-unopened");
    supervisor
        .cancel()
        .unwrap_or_else(|error| panic!("cancel original scope: {error}"));

    let error = SupervisedProjectQuotaBinding::bind_existing_under(
        &absent,
        701,
        16 << 20,
        16,
        supervisor,
        &operation,
    )
    .err()
    .unwrap_or_else(|| panic!("canceled original scope must refuse"));

    assert!(matches!(error, SupervisedProjectQuotaError::Supervision(_)));
    assert!(!absent.exists());
}

#[test]
fn audit_retains_first_actual_refusal_without_masking_independent_kernel_errors() {
    let supervisor = HostOperationSupervisor::new(
        crate::host_supervision::HostOperationBudgets::default(),
        None,
    )
    .unwrap();
    let operation = supervisor
        .begin_work(HostOperationClass::Preparation, 16)
        .unwrap();
    let audit = SupervisedAudit {
        operation: &operation,
        first: Cell::new(None),
    };

    audit.progress(1).unwrap();
    assert!(audit.progress(0).is_err());
    supervisor.cancel().unwrap();
    assert!(audit.check().is_err());

    assert!(matches!(
        audit.result::<()>(Err(QuotaAuditRefusal.into())),
        Err(SupervisedProjectQuotaError::Supervision(
            HostSupervisionError::ProgressRegressed
        )),
    ));
    assert!(matches!(
        audit.result::<()>(Err(LinuxProjectQuotaError::InvalidLimits)),
        Err(SupervisedProjectQuotaError::Quota(
            LinuxProjectQuotaError::InvalidLimits
        )),
    ));
}
