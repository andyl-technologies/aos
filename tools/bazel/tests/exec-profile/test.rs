//! Checks independent execution and target compiler profiles through real actions.

#[test]
fn generator_uses_execution_profile() {
    assert_eq!(
        env!("AOS_EXEC_DEBUG_ASSERTIONS"),
        env!("EXPECTED_EXEC_CHECKS")
    );
    assert_eq!(
        env!("AOS_EXEC_OVERFLOW_CHECKS"),
        env!("EXPECTED_EXEC_CHECKS")
    );
}

#[test]
fn procedural_macro_uses_execution_profile() {
    assert_eq!(
        profile_macro::execution_debug_assertions!(),
        env!("EXPECTED_EXEC_CHECKS") == "true",
    );
}

#[test]
fn target_uses_independent_profile() {
    let expected = env!("EXPECTED_TARGET_CHECKS") == "true";
    assert_eq!(cfg!(debug_assertions), expected);

    std::panic::set_hook(Box::new(|_| {}));
    let value = std::hint::black_box(u8::MAX);
    assert_eq!(std::panic::catch_unwind(|| value + 1).is_err(), expected);
}
