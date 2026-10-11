//! Data-only admitted quantum accounting and legacy error compatibility tests.

#![cfg(test)]
// crucible-lint: allow panic-shortcut -- fixture setup and accounting invariants intentionally panic.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crate::QemuExecutionQuantumCounter;
use crucible_qemu::QemuVmRealizationError;

fn resources(quanta: u64) -> AttemptResourceLimits {
    AttemptResourceLimits::new(1, 4096, 0, quanta).expect("nonzero fixture limits")
}

#[test]
fn charges_exact_ceiling_and_retains_counter_after_refusal() {
    let mut counter = AttemptExecutionQuantumCounter::new(resources(2));
    assert_eq!((counter.ceiling(), counter.charged()), (2, 0));

    counter.charge().expect("first admitted quantum");
    counter.charge().expect("second admitted quantum");
    let spent = counter;
    let error = counter.charge().expect_err("ceiling is spent");

    assert_eq!(counter, spent);
    assert_eq!(error.ceiling(), 2);
    assert_eq!(error.to_string(), "execution quantum ceiling is exhausted");
    assert_eq!(counter.charge(), Err(error));
    assert_eq!(counter, spent);
}

#[test]
fn independent_attempts_do_not_share_accounting() {
    let mut first = AttemptExecutionQuantumCounter::new(resources(1));
    let mut second = AttemptExecutionQuantumCounter::new(resources(3));

    first.charge().expect("first attempt quantum");
    assert!(first.charge().is_err());
    second.charge().expect("separate attempt quantum");

    assert_eq!((first.ceiling(), first.charged()), (1, 1));
    assert_eq!((second.ceiling(), second.charged()), (3, 1));
}

#[test]
fn terminal_u64_charge_cannot_overflow() {
    let mut counter = AttemptExecutionQuantumCounter {
        ceiling: u64::MAX,
        charged: u64::MAX - 1,
    };

    counter.charge().expect("final representable quantum");
    let spent = counter;
    let error = counter.charge().expect_err("exact terminal ceiling");

    assert_eq!(counter.charged(), u64::MAX);
    assert_eq!(error.ceiling(), u64::MAX);
    assert_eq!(counter, spent);
}

#[test]
fn legacy_qemu_counter_keeps_nominal_error_and_debug_fields() {
    const LIMITS: AttemptResourceLimits = match AttemptResourceLimits::new(1, 4096, 0, 1) {
        Ok(resources) => resources,
        Err(_) => panic!("nonzero constant fixture limits"),
    };
    const INITIAL: QemuExecutionQuantumCounter = QemuExecutionQuantumCounter::new(LIMITS);
    let mut legacy = INITIAL;

    legacy.charge().expect("legacy admitted quantum");
    let spent = legacy;
    let failure = legacy.charge().expect_err("legacy ceiling is spent");

    assert!(matches!(
        failure,
        QemuVmRealizationError::Executor {
            operation: "charge QEMU execution quantum",
            ref message,
        } if message == "execution quantum ceiling is exhausted"
    ));
    assert_eq!(legacy, spent);
    assert_eq!(
        format!("{legacy:?}"),
        "QemuExecutionQuantumCounter { ceiling: 1, charged: 1 }"
    );
}
