//! Binds Main publication and retirement to its actual saved executor owner.

use super::super::Contract;

pub(super) const MAIN_ATTACHED: Contract = Contract {
    package: "crucible-daemon",
    target: "src/campaign_process/attached_retirement",
    required: &[
        (r#".begin("#, 0),
        (r#"HostOperationSupervisor::new("#, 0),
        (r#"Instant::now("#, 0),
        (r#".begin(HostOperationClass::"#, 0),
        (r#".begin_original_cleanup_control("#, 0),
        (r#".is_none_or(|actual| !Arc::ptr_eq(actual, main))"#, 1),
        (
            r#"actor.attached_started.swap(true, std::sync::atomic::Ordering::AcqRel)"#,
            1,
        ),
        (
            r#"*slot = Some(RetainedExecutorConstruction::Attached(body));"#,
            1,
        ),
        (r#"let original = match main.retained_cleanup()"#, 1),
        (
            r#"let Some(RetainedExecutorConstruction::Attached(body)) = slot.as_mut()"#,
            2,
        ),
        (
            r#"if !body.physically_retired() { return Err(retained_attached_report(main)); }"#,
            1,
        ),
        (
            r#"let returned = slot.take(); drop(slot); drop(returned);"#,
            1,
        ),
        (r#"self.first.get_or_init(|| first);"#, 1),
        (r#"let work = body.retry(main, original)"#, 1),
    ],
    expressions: &[
        (r#"retry_attached_retirement_original(main, &original)"#, 1),
        (r#"retry(main, original)"#, 1),
    ],
    identifiers: &[
        ("retry_attached_retirement", 1),
        ("retry_attached_retirement_original", 2),
        ("retry", 1),
    ],
    companions: &[super::ORIGINAL, super::ATTACHED_BODY],
};

pub(super) const MAIN_CONSTRUCTION: Contract = Contract {
    package: "crucible-daemon",
    target: "src/campaign_process/retained_construction",
    required: &[
        (r#".begin("#, 0),
        (r#"HostOperationSupervisor::new("#, 0),
        (r#"Instant::now("#, 0),
        (r#".begin(HostOperationClass::"#, 0),
        (r#".begin_original_cleanup_control("#, 0),
        (
            r#"let Some(owner) = slot.take() else { return Err(self); }; retain_executor_construction(main, owner, self.source)"#,
            1,
        ),
        (r#".is_some_and(|admitted| Arc::ptr_eq(admitted, main))"#, 1),
        (
            r#"let original = main.retained_cleanup().map_err(RetainedExecutorRetirementError::Admission)?;"#,
            1,
        ),
        (r#"original.wait_slice()?;"#, 1),
        (
            r#"let controls = super::try_retire_executor_controls(main, &original).err(); let post = original.wait_slice().err();"#,
            1,
        ),
        (r#"work.err(), controls, post,"#, 1),
        (r#"return super::retry_attached_retirement(main)"#, 1),
    ],
    expressions: &[(r#"super::retry_attached_retirement(main)"#, 1)],
    identifiers: &[
        ("retry_retention", 1),
        ("retry_retained_executor_construction", 1),
        ("retry_attached_retirement", 1),
    ],
    companions: &[
        super::ORIGINAL,
        super::ATTACHED_BODY,
        super::PACKAGED_BODY,
        super::CONSTRUCTION_FINISH,
    ],
};

pub(super) const MAIN_EXPORT: Contract = Contract {
    package: "crucible-daemon",
    target: "src/campaign_process",
    required: &[
        (r#".begin("#, 0),
        (r#"HostOperationSupervisor::new("#, 0),
        (r#"Instant::now("#, 0),
        (r#".begin(HostOperationClass::"#, 0),
        (r#".begin_original_cleanup_control("#, 0),
        (r#"pub(crate) use attached_retirement::{"#, 1),
        (r#"retry_attached_retirement, verify_attached_start,"#, 1),
    ],
    expressions: &[],
    identifiers: &[("retry_attached_retirement", 1)],
    companions: &[super::MAIN_ATTACHMENT],
};

pub(super) const ATTACHED: Contract = Contract {
    package: "crucible-daemon",
    target: "src/packaged_qemu_executor/attached_retirement",
    required: &[
        (r#".begin("#, 0),
        (r#"HostOperationSupervisor::new("#, 0),
        (r#"Instant::now("#, 0),
        (r#".begin(HostOperationClass::"#, 0),
        (r#".begin_original_cleanup_control("#, 0),
        (r#"if !self.service_returned"#, 2),
        (
            r#"self.service_returned = self.completion.0.try_lock().is_ok_and(|done| *done);"#,
            1,
        ),
        (r#"if self.dispatcher_closed { return Ok(()); }"#, 1),
        (r#"self.post.get_or_insert(post);"#, 4),
        (
            r#"let materializer = self.materializer.try_retire_original(original).err();"#,
            1,
        ),
        (r#"self.source_closed = true;"#, 1),
        (r#"let Self::RetirementCustody { owner, .. } = self"#, 1),
        (r#"body.mark_service_returned();"#, 1),
        (r#"*slot = Some(body);"#, 1),
        (
            r#"crate::campaign_process::retry_attached_retirement(&thread_main)"#,
            1,
        ),
    ],
    expressions: &[
        (
            r#"fn retry(
        &mut self,
        main: &Arc<AuthenticatedNativeSlotPurpose>,
        original: &HostOperationGuard,
    )"#,
            1,
        ),
        (
            r#"crate::campaign_process::retry_attached_retirement(&thread_main)"#,
            1,
        ),
    ],
    identifiers: &[
        ("retry", 1),
        ("retry_attached_retirement", 1),
        ("retry_retirement_retention", 1),
    ],
    companions: &[super::ORIGINAL, super::MAIN_ATTACHMENT, super::DISPATCHER],
};

pub(super) const PACKAGED: Contract = Contract {
    package: "crucible-daemon",
    target: "src/packaged_qemu_executor/original_retirement",
    required: &[
        (r#".begin("#, 0),
        (r#"HostOperationSupervisor::new("#, 0),
        (r#"Instant::now("#, 0),
        (r#".begin(HostOperationClass::"#, 0),
        (r#".begin_original_cleanup_control("#, 0),
        (r#"original.wait_slice()?;"#, 1),
        (
            r#"let workers = self.service.try_retire_original(original).err();"#,
            1,
        ),
        (r#"if self.service.physically_retired()"#, 2),
        (r#"self.source_physically_retired = true;"#, 1),
        (r#"let workers = workers.or(service_retry);"#, 1),
        (r#"post: dispatch.post,"#, 1),
    ],
    expressions: &[],
    identifiers: &[("service_retry", 2)],
    companions: &[super::ORIGINAL, super::SERVICE, super::DISPATCHER],
};
