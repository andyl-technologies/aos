//! Live runtime coverage ownership cases.

use super::*;

#[test]
fn install_coverage_on_owns_callback_model_registration() {
    let _runtime_state = isolate_runtime_state_for_test();
    let _callback_model_guard = isolate_coverage_callback_model_for_test();
    CALLBACK_MODEL_REGISTERED_PLUGIN_ID.store(0, Ordering::SeqCst);
    let fixture = LiveInstallFixture::new();
    let host = fixture.spawn_host(SETUP_ACK_STATUS_READY);
    let mut capabilities = test_capabilities();
    capabilities.basic_block_coverage = Some(coverage_callback_model_apis());
    let mut reservation =
        reserve_runtime().unwrap_or_else(|error| panic!("test runtime should reserve: {error}"));

    let runtime = install_live_runtime(
        0xC0E0,
        fixture.coverage_args(),
        test_state(),
        capabilities,
        &SuccessfulCallbackRegistrar,
        &mut reservation,
    )
    .unwrap_or_else(|error| panic!("coverage callback model should install: {error}"));

    assert_eq!(
        CALLBACK_MODEL_REGISTERED_PLUGIN_ID.load(Ordering::SeqCst),
        0xC0E0
    );
    assert!(runtime._callbacks.coverage_is_registered_for_test());
    drop(runtime);
    join_host(host);
}
