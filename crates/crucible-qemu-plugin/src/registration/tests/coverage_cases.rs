//! Coverage-disabled registration cases.

use super::*;

#[test]
fn registration_coverage_off_installs_no_callback_without_capability() {
    let mut sequence = PluginRegistrationSequence::new();
    record_steps_through_wake_fd(&mut sequence);
    let args = registration_args("simfd=3,slot=0,coverage=off");

    let capabilities = sequence
        .register_callbacks_for_test(
            &args,
            Some(registration_test_deadline),
            Some(registration_test_direct_advance),
            CoverageCapabilities::none(),
        )
        .unwrap_or_else(|error| panic!("coverage off should not need TCG exec: {error}"));

    assert_eq!(
        capabilities.coverage_registration_plan(),
        CoverageRegistrationPlan::Disabled
    );
    assert!(
        !capabilities
            .coverage_registration_plan()
            .installs_callback()
    );
    assert_eq!(capabilities.coverage_callback(), None);
}
