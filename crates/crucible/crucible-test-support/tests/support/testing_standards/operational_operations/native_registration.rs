//! Binds native registration polling to the same startup Original and borrower.
//!
//! The finite loop is one exact expression so inserting a nested unobserved
//! delay cannot retain a match. These source checks issue no native authority.

use super::{Companion, Contract};

const REGISTRATION_WAIT: &str = r#"loop {
    let waiting = self.native.with_control(false, |control| {
        let slice = control.check_original(&mut wait_slice)?;
        self.native.check_readiness(control)?;
        let state = control.lock();
        if state.failure.is_some() {
            drop(state);
            return Err(Self::failed(control));
        }
        let registered = state.registered;
        drop(state);
        if registered {
            check_worker_identity(control)?;
            control.check_original(&mut wait_slice)?;
            Ok(None)
        } else {
            Ok(Some(slice))
        }
    })?;
    let Some(slice) = waiting else {
        return Ok(());
    };
    std::thread::sleep(slice.min(std::time::Duration::from_millis(10)));
}"#;

#[path = "native_registration/required_workers.rs"]
mod required_workers;

pub(super) const REQUIRED_WORKER_CONTRACTS: &[Contract] = &[required_workers::CONTRACT];

const ORIGINAL_SETUP: Companion = Companion {
    path: "crates/crucible/crucible-qemu-plugin/src/setup.rs",
    required: &[
        (
            r#"pub(crate) fn original_startup_slice(&self,) -> Result<std::time::Duration, crate::StartupSourceError> {
self.original_startup()?.wait_slice() }"#,
            1,
        ),
        (
            r#"fn original_startup(
    &self,
) -> Result<&crate::startup_source::InstallerStartupSource, crate::StartupSourceError> {
    self.startup_source.as_ref().ok_or(crate::StartupSourceError::Ownership {
        reason: "initial installer Source is absent",
    })
}"#,
            1,
        ),
    ],
};
const ORIGINAL_SLICE: Companion = Companion {
    path: "crates/crucible/crucible-qemu-plugin/src/startup_source.rs",
    required: &[
        (
            r#"pub(crate) fn wait_slice(&self) -> Result<Duration, StartupSourceError> {
    let api = self.live_api()?;
    let mut bounded_ns = 0;
    self.accept_status((api.query_slice)(self.plugin_id, &mut bounded_ns))?;
    if bounded_ns == 0 {
        self.invalid_slice.store(true, Ordering::Release);
        return Err(StartupSourceError::Ownership {
            reason: "native returned an empty successful observation slice",
        });
    }
    Ok(Duration::from_nanos(bounded_ns))
}"#,
            1,
        ),
        (r#"Ok(Duration::from_nanos(bounded_ns))"#, 1),
    ],
};

pub(super) const CONTRACTS: &[Contract] = &[Contract {
    package: "crucible-qemu-plugin",
    target: "src/runtime/live_callbacks/fingerprint_worker/native",
    required: &[
        (
            r#"pub(in crate::runtime::live_callbacks) fn wait_registered(
    &self,
    mut wait_slice: impl FnMut() -> Result<std::time::Duration, crate::StartupSourceError>,
) -> Result<(), LiveVcpuTimeCallbackError> {
    loop {"#,
            1,
        ),
        (
            r#"let worker = self.unattached.as_ref().ok_or_else(|| status_error(-libc::ESTALE))?;
worker.wait_registered(wait_slice)?;
self.registered.store(true, Ordering::Release);
Ok(())"#,
            1,
        ),
        (
            r#"let status = self.observe()?;
let first = [
    status.first_status, status.post_status, status.create_status,
    status.mask_restore_status, status.attr_destroy_status, status.control_lifetime_status,
].into_iter().find(|status| *status != 0);"#,
            1,
        ),
        (
            r#"if status.born != 1 || status.initialized != 1 || status.closing != 0
    || status.entry_returned != 0 || status.control_lifetime_uncertain != 0"#,
            2,
        ),
        (
            r#"let snapshot = context.quiescence.identity_snapshot().map_err(|source| {
    control.refuse(FingerprintWorkerCause::Registration(source));
    LiveFingerprintDigestWorker::failed(control)
})?;"#,
            1,
        ),
        (
            r#"if snapshot.process_id != u64::from(std::process::id())
    || snapshot.membership_generation == 0
    || snapshot.worker_mask & WORKER_FINGERPRINT == 0
    || snapshot.thread_ids[index] == 0"#,
            1,
        ),
        (r#"Instant::now("#, 0),
        (r#"HostOperationSupervisor::new("#, 0),
        (r#"SourceOperationClass::"#, 0),
    ],
    expressions: &[(REGISTRATION_WAIT, 1)],
    identifiers: &[],
    companions: &[
        Companion {
            path: "crates/crucible/crucible-qemu-plugin/src/runtime.rs",
            required: &[
                (
                    r#"let birth_post = state.setup.check_runtime_installation(); state.fingerprint_worker_owner.record_installation_post(birth_post);
birth?; birth_post.map_err(|source| LiveVcpuTimeCallbackError::CallbackChildStorage { source })?;
state.fingerprint_worker_owner.wait_registered(|| state.setup.original_startup_slice())?;"#,
                    1,
                ),
                (
                    r#".wait_fingerprint_registered(|| state.setup.original_startup_slice())"#,
                    1,
                ),
            ],
        },
        ORIGINAL_SETUP,
        ORIGINAL_SLICE,
        Companion {
            path: "crates/crucible/crucible-qemu-plugin/src/runtime/live_callbacks/fingerprint_worker.rs",
            required: &[(
                r#"fn check_original(
    self: &Arc<Self>,
    wait_slice: &mut impl FnMut() -> Result<std::time::Duration, crate::StartupSourceError>,
) -> Result<std::time::Duration, LiveVcpuTimeCallbackError> {
    wait_slice().map_err(|source| {
        let mut state = self.lock();
        if state.failure.is_none() {
            state.failure = Some(FingerprintWorkerCause::Supervision);
        }
        if state.supervision_failure.is_none() {
            state.supervision_failure = Some(source);
        }
        drop(state);
        self.available.notify_all();
        self.capacity.notify_all();
        LiveFingerprintDigestWorker::failed(self)
    })
}"#,
                1,
            )],
        },
        Companion {
            path: "crates/crucible/crucible-qemu-plugin/src/runtime/live_callbacks/fingerprint_worker/native/scope.rs",
            required: &[
                (
                    r#"F: for<'a> FnOnce(&'a Arc<FingerprintWorkerControl>,) -> Result<R, LiveVcpuTimeCallbackError>,
R: Copy + 'static,"#,
                    1,
                ),
                (
                    r#"let use_control = if terminal { self.api.control_retire } else { self.api.control_use };
let outcome = native_scope::with_control(action, retain_module_error, retain_module_panic, |input| {
    use_control(self.id, self.pointer(), input)
});
let status = outcome.status;
let Some(output) = outcome.output else {
    return Err(status_error(if status != 0 { status } else { -libc::EPROTO }));
};"#,
                    1,
                ),
                (
                    r#"(Ok(output), 0) => Ok(output), (Ok(_), status) => Err(status_error(status)), (Err(error), 0) => Err(error),"#,
                    1,
                ),
                (
                    r#"source.control.record_native_failure("control scope return", status);
Err(LiveVcpuTimeCallbackError::FingerprintWorkerControlScope { source, native_status: status, })"#,
                    1,
                ),
                (
                    r#"if !control.native.as_ref().is_some_and(|context| context.handle.id == id && context.handle.pointer() == worker) {
    return -libc::EPERM;
}
unsafe { native_scope::dispatch(owner, input) }"#,
                    1,
                ),
                (
                    r#"if state.module_action_failure.is_none() { state.module_action_failure = Some(error); }"#,
                    1,
                ),
            ],
        },
        Companion {
            path: "crates/crucible/crucible-qemu-plugin/src/runtime/native_worker/scope.rs",
            required: &[
                (
                    r#"F: for<'a> FnOnce(&'a Arc<B>) -> Result<R, E>,
R: Copy + 'static,
E: 'static,
RetainError: Fn(&Arc<B>, E) -> E,
RetainPanic: Fn(&Arc<B>, Box<dyn Any + Send>),"#,
                    2,
                ),
                (
                    r#"let mut input: ScopedInput<B, F, R, E, RetainError, RetainPanic> = ScopedInput {
    body: PhantomData,
    action: Some(action),
    retain_error,
    retain_panic,
    output: MaybeUninit::uninit(),
    completed: false,
};"#,
                    1,
                ),
                (
                    r#"let input = unsafe { &mut *input.cast::<ScopedInput<B, F, R, E, RetainError, RetainPanic>>() };"#,
                    1,
                ),
                (
                    r#"let mut header = InputHeader {
    invoke: invoke::<B, F, R, E, RetainError, RetainPanic>,
    payload: std::ptr::from_mut(&mut input).cast(),
};
let status = enter(std::ptr::from_mut(&mut header).cast());
let output = if input.completed {
    Some(unsafe { input.output.assume_init() })
} else {
    None
};
ScopeOutcome { output, status }"#,
                    1,
                ),
                (
                    r#"let control = ManuallyDrop::new(unsafe { Arc::from_raw(owner.cast::<B>()) });"#,
                    1,
                ),
                (
                    r#"let Some(action) = input.action.take() else { return -libc::EALREADY; };"#,
                    1,
                ),
                (
                    r#"match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| action(&control))) {
    Ok(output) => {
        let output = output.map_err(|error| (input.retain_error)(&control, error));
        input.output.write(output);
        input.completed = true;
        0
    }
    Err(payload) => {
        (input.retain_panic)(&control, payload);
        -libc::EFAULT
    }
}"#,
                    1,
                ),
                (
                    r#"let input = unsafe { &mut *input.cast::<InputHeader>() };
unsafe { (input.invoke)(owner, input.payload) }"#,
                    1,
                ),
            ],
        },
    ],
}];

#[test]
fn registration_wait_rejects_unchecked_repetition_and_foreign_borrows()
-> Result<(), Box<dyn std::error::Error>> {
    let root = crate::workspace_root();
    let contract = &CONTRACTS[0];
    let path = crate::workspace::package_path(&root.join("crates"), contract.package)
        .join(format!("{}.rs", contract.target));
    let code = crate::scrub_comments_and_strings(&std::fs::read_to_string(path)?);
    let evidence = super::read_companions(contract)?;
    assert!(crate::flaky_escape_failures(contract.package, contract.target, &code,).is_empty());

    let rejects = |changed: &str, companions: &[String]| {
        let masked = super::mask_contract(contract, changed, companions);
        assert_eq!(masked, changed, "changed registration still matched");
        assert!(!crate::flaky_escape_failures("unreviewed", "unreviewed", &masked,).is_empty());
    };
    for (needle, replacement) in [
        (
            "let slice = control.check_original(&mut wait_slice)?;",
            "let slice = unobserved_slice;",
        ),
        ("self.native.check_readiness(control)?;", ""),
        ("if state.failure.is_some()", "if false"),
        (
            "let registered = state.registered; drop(state);",
            "let registered = state.registered;",
        ),
        (
            "self.native.with_control(false, |control|",
            "self.native.with_control(true, |control|",
        ),
        (
            "check_worker_identity(control)?; control.check_original(&mut wait_slice)?;",
            "control.check_original(&mut wait_slice)?; check_worker_identity(control)?;",
        ),
        (
            "check_worker_identity(control)?; control.check_original(&mut wait_slice)?;",
            "check_worker_identity(control)?;",
        ),
        (
            "std::thread::sleep(slice.min(std::time::Duration::from_millis(10)));",
            "std::thread::sleep(std::time::Duration::from_millis(10));",
        ),
        (
            "std::thread::sleep(slice.min(std::time::Duration::from_millis(10)));",
            "loop { std::thread::sleep(slice.min(std::time::Duration::from_millis(10))); }",
        ),
    ] {
        let changed_loop = super::replace_one_obligation(
            REGISTRATION_WAIT,
            &super::source_pattern(needle),
            replacement,
        );
        assert_ne!(
            changed_loop, REGISTRATION_WAIT,
            "registration mutation was not applied: {needle}"
        );
        let changed = super::replace_one_obligation(
            &code,
            &super::source_pattern(REGISTRATION_WAIT),
            &changed_loop,
        );
        rejects(&changed, &evidence);
    }

    for (index, needle, replacement) in [
        (
            0,
            "wait_registered(|| state.setup.original_startup_slice())",
            "wait_registered(|| renewed_original.wait_slice())",
        ),
        (
            1,
            "self.original_startup()?.wait_slice()",
            "renewed_original.wait_slice()",
        ),
        (
            2,
            "self.accept_status((api.query_slice)(self.plugin_id, &mut bounded_ns))?;",
            "bounded_ns = renewed_slice;",
        ),
        (
            3,
            "state.supervision_failure = Some(source);",
            "drop(source);",
        ),
        (4, "R: Copy + 'static,", "R: 'static,"),
        (
            5,
            "ManuallyDrop::new(unsafe { Arc::from_raw(owner.cast::<B>()) })",
            "unsafe { Arc::from_raw(owner.cast::<B>()) }",
        ),
        (
            4,
            "Err(LiveVcpuTimeCallbackError::FingerprintWorkerControlScope { source, native_status: status, })",
            "Err(status_error(status))",
        ),
        (
            4,
            "state.module_action_failure = Some(error);",
            "drop(error);",
        ),
        (
            4,
            "use_control(self.id, self.pointer(), input)",
            "self.api.control_retire(self.id, self.pointer(), input)",
        ),
        (4, "let status = outcome.status;", "let status = 0;"),
        (5, "R: Copy + 'static,", "R: 'static,"),
        (5, "E: 'static,", ""),
        (
            5,
            "input.output.write(output); input.completed = true;",
            "input.completed = true; input.output.write(output);",
        ),
        (5, "(input.retain_error)(&control, error)", "error"),
        (
            5,
            "(input.retain_panic)(&control, payload);",
            "drop(payload);",
        ),
    ] {
        let mut changed = evidence.clone();
        changed[index] = super::replace_one_obligation(
            &crate::scrub_comments_and_strings(&changed[index]),
            &super::source_pattern(needle),
            replacement,
        );
        assert_ne!(
            changed[index],
            crate::scrub_comments_and_strings(&evidence[index])
        );
        rejects(&code, &changed);
    }
    Ok(())
}
