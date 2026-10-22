//! Exercises the actual native measurement and its original terminal custody.
//!
//! Every case uses the real inherited socket and admitted SDK from the policy
//! fixture. Admission callbacks remain test models, not genuine Source credit.

use super::super::super::bootstrap_kernel::{self, OriginalImport18BootstrapKernelAdmission};
use super::*;
use crucible_node_format::U64;
use std::cell::Cell;

struct Admission<'a> {
    case: &'a str,
    before: usize,
    calls: Cell<usize>,
}

impl OriginalImport18BootstrapKernelAdmission for Admission<'_> {
    fn construct_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        row: [usize; 3],
    ) -> Result<(), ProviderError> {
        self.calls.set(self.calls.get() + 1);
        assert_eq!(original.retained_requested_bytes().unwrap(), self.before);
        assert_eq!(
            row,
            bootstrap_kernel::construction_data(original.bounds.requested_peak).unwrap()
        );
        assert_eq!(original.bootstrap_kernel.row, Some(row));
        if self.case.ends_with("construct_refused") {
            return Err(ProviderError::ResourceExhausted("kernel admission model"));
        }
        if self.case.ends_with("construct_expired") {
            std::thread::sleep(Duration::from_secs(5));
        }
        Ok(())
    }

    fn finish_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        actual: usize,
    ) -> Result<(), ProviderError> {
        self.calls.set(self.calls.get() + 1);
        assert!(original.bootstrap_kernel.executable.is_some());
        assert_eq!(
            actual,
            original.bootstrap_kernel.retained_backing_data().unwrap()
        );
        assert_eq!(
            actual,
            bootstrap_kernel::construction_data(usize::MAX).unwrap()[0]
        );
        assert_eq!(
            original.retained_requested_bytes().unwrap(),
            self.before + actual
        );
        if self.case.ends_with("finish_refused") {
            return Err(ProviderError::ResourceExhausted("kernel census model"));
        }
        if self.case.ends_with("finish_expired") {
            std::thread::sleep(Duration::from_secs(5));
        }
        Ok(())
    }
}

pub(super) fn assert_missing_policy(original: &mut OriginalImport18RawBootstrap) {
    let before = original.retained_requested_bytes().unwrap();
    let admission = Admission {
        case: "missing_policy",
        before,
        calls: Cell::new(0),
    };
    assert!(
        original
            .construct_bootstrap_kernel_data(&admission)
            .is_err()
    );
    assert!(
        original
            .construct_bootstrap_kernel_data(&admission)
            .is_err()
    );
    assert_eq!(admission.calls.get(), 0);
    assert!(original.bootstrap_kernel.started);
    assert!(original.bootstrap_kernel.executable.is_none());
    assert!(!original.bootstrap_kernel.complete);
    assert_eq!(original.retained_requested_bytes().unwrap(), before);
    assert!(
        original
            .with_bootstrap_kernel_wire_data(|_| Ok(()))
            .is_err()
    );
    assert!(original.with_hello_authority_data(|_| Ok(())).is_err());
}

pub(super) fn assert_child(case: &str, original: &mut OriginalImport18RawBootstrap) {
    let before = original.retained_requested_bytes().unwrap();
    let raw_pointers = original.bodies.each_ref().map(Vec::as_ptr);
    let launch_pointer = std::rc::Rc::as_ptr(original.parsed.shared_launch_data().unwrap());
    let sdk_pointer = original
        .hello_registrar
        .retained_authority_fixture_data()
        .map(std::ptr::from_ref);
    assert!(
        original
            .with_bootstrap_kernel_wire_data(|_| Ok(()))
            .is_err()
    );
    let admission = Admission {
        case,
        before,
        calls: Cell::new(0),
    };
    let prior_cut = original.cut;
    if case.ends_with("substituted_cut") {
        original.cut = OperationalDeadline::after(Duration::from_secs(3)).unwrap();
    }
    let result = original.construct_bootstrap_kernel_data(&admission);
    let completed = ![
        "construct_refused",
        "construct_expired",
        "finish_refused",
        "finish_expired",
        "substituted_cut",
    ]
    .into_iter()
    .any(|suffix| case.ends_with(suffix));
    assert_eq!(result.is_ok(), completed, "{case}: {result:?}");
    assert_eq!(original.bootstrap_kernel.complete, completed);

    if completed {
        original
            .with_bootstrap_kernel_wire_data(|view| {
                let value = serde_json::to_value(view).unwrap();
                let expected = measure_original_restore_current_executable().unwrap();
                let launch = original.typed_bodies_data()?.launch.launch_data();
                assert_eq!(
                    value["schema"],
                    json!("source-owned.packet-canonical-ack-kernel-binding/5")
                );
                assert_eq!(value["controller"]["pid"], json!(launch.controller_pid));
                assert_eq!(value["controller"]["uid"], json!(launch.controller_uid));
                assert_eq!(
                    value["controller"]["executable"],
                    json!(launch.controller_executable)
                );
                assert_eq!(
                    value["native"]["pid"],
                    json!(U64::new(u64::from(std::process::id())))
                );
                assert_eq!(
                    value["native"]["uid"],
                    json!(U64::new(u64::from(rustix::process::geteuid().as_raw())))
                );
                assert_eq!(value["native"]["executable"], json!(expected));
                Ok(())
            })
            .unwrap();
        assert_eq!(admission.calls.get(), 2);
        if case.ends_with("callback_refused") {
            assert!(
                original
                    .with_bootstrap_kernel_wire_data::<()>(|_| Err(ProviderError::Conflict(
                        "kernel callback model"
                    )))
                    .is_err()
            );
            original
                .with_bootstrap_kernel_wire_data(|_| Ok(()))
                .unwrap();
        }
        if case.ends_with("loan_expired") {
            assert!(
                original
                    .with_bootstrap_kernel_wire_data(|_| {
                        std::thread::sleep(Duration::from_secs(5));
                        Ok(())
                    })
                    .is_err()
            );
        }
        if case.ends_with("later_contained") {
            original.hello_registrar.contain_admission_data().unwrap();
            assert!(
                original
                    .with_bootstrap_kernel_wire_data(|_| Ok(()))
                    .is_err()
            );
        }
    } else {
        assert!(
            original
                .with_bootstrap_kernel_wire_data(|_| Ok(()))
                .is_err()
        );
        assert!(original.with_hello_authority_data(|_| Ok(())).is_err());
    }
    original.cut = prior_cut;
    let calls = admission.calls.get();
    assert!(
        original
            .construct_bootstrap_kernel_data(&admission)
            .is_err()
    );
    assert_eq!(admission.calls.get(), calls);
    assert_eq!(original.bodies.each_ref().map(Vec::as_ptr), raw_pointers);
    assert_eq!(
        std::rc::Rc::as_ptr(original.parsed.shared_launch_data().unwrap()),
        launch_pointer
    );
    assert_eq!(
        original
            .hello_registrar
            .retained_authority_fixture_data()
            .map(std::ptr::from_ref),
        sdk_pointer
    );
    assert_eq!(
        original.retained_requested_bytes().unwrap(),
        before + original.bootstrap_kernel.retained_backing_data().unwrap()
    );
    assert!(original.inputs.is_empty_data());
}
