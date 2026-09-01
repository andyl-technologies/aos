//! Test-only ownership for the published app-random restore continuation.

use super::*;

pub(in crate::runtime) struct TestLiveAppRandomRestoreOwner {
    state: Box<LiveAppRandomState>,
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl TestLiveAppRandomRestoreOwner {
    pub(in crate::runtime) fn set_draws(&mut self, draws: u64) {
        self.state.set_draws_for_test(draws);
    }

    pub(in crate::runtime) fn draws(&self) -> u64 {
        self.state.draws_for_test()
    }
}

impl Drop for TestLiveAppRandomRestoreOwner {
    fn drop(&mut self) {
        let state = std::ptr::from_mut(self.state.as_mut());
        let cleared = LIVE_APP_RANDOM_STATE.compare_exchange(
            state,
            std::ptr::null_mut(),
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        assert!(cleared.is_ok(), "test app-random restore owner changed");
    }
}

pub(in crate::runtime) fn install_app_random_restore_state_for_test(
    config: &PluginAppRandomConfig,
) -> TestLiveAppRandomRestoreOwner {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let lock = LOCK
        .lock()
        .unwrap_or_else(|error| panic!("app-random restore test lock poisoned: {error}"));
    let doorbell = PluginWhiteboxDoorbell::from_abi(
        PluginSwitch::On,
        WHITEBOX_DOORBELL_X86_64_ABI,
        MAX_FRAME_DATA,
    );
    let capability = doorbell
        .require_guest_input_capability(WhiteboxDoorbellCapabilities::bidirectional())
        .unwrap_or_else(|error| panic!("test app-random capability should build: {error}"));
    let mut state = Box::new(LiveAppRandomState::new(config, capability));
    let pointer = std::ptr::from_mut(state.as_mut());
    LIVE_APP_RANDOM_STATE
        .compare_exchange(
            std::ptr::null_mut(),
            pointer,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .unwrap_or_else(|_existing| panic!("test app-random restore owner must be exclusive"));
    TestLiveAppRandomRestoreOwner { state, _lock: lock }
}
