//! Basic-block coverage callback and ownership tests.

use super::*;

use std::sync::atomic::{AtomicU64, AtomicUsize};

mod live_callback_cases;

static CALLBACK_MODEL_TRANSLATION_PLUGIN_ID: AtomicU64 = AtomicU64::new(0);
static CALLBACK_MODEL_TRANSLATION_CALLBACK: AtomicUsize = AtomicUsize::new(0);
static CALLBACK_MODEL_EXEC_CALLBACK: AtomicUsize = AtomicUsize::new(0);
static CALLBACK_MODEL_FLUSH_PLUGIN_ID: AtomicU64 = AtomicU64::new(0);
static CALLBACK_MODEL_FLUSH_CALLBACK: AtomicUsize = AtomicUsize::new(0);
static CALLBACK_MODEL_EXEC_FLAGS: AtomicUsize = AtomicUsize::new(usize::MAX);
static CALLBACK_MODEL_EXEC_USERDATA: AtomicUsize = AtomicUsize::new(0);
static CALLBACK_MODEL_ICOUNT: AtomicU64 = AtomicU64::new(0);
static CALLBACK_MODEL_TB_INSNS: AtomicU64 = AtomicU64::new(0);
static CALLBACK_MODEL_SCOREBOARD_SIZE: AtomicUsize = AtomicUsize::new(0);
static CALLBACK_MODEL_SEEN_OFFSET: AtomicUsize = AtomicUsize::new(usize::MAX);
static CALLBACK_MODEL_SEEN_VCPU: AtomicUsize = AtomicUsize::new(usize::MAX);
static CALLBACK_MODEL_SEEN_VALUE: AtomicU64 = AtomicU64::new(0);

struct TestInsn {
    size: usize,
}

struct TestTb {
    guest_pc: u64,
    insns: Vec<TestInsn>,
}

fn coverage_callback(coverage: PluginCoverage) -> CoverageCallback {
    let plan = coverage
        .registration_plan(test_coverage_capabilities())
        .unwrap_or_else(|error| panic!("enabled coverage should register: {error}"));
    plan.require_callback()
        .unwrap_or_else(|error| panic!("enabled coverage should expose callback: {error}"))
}

#[test]
fn coverage_registration_off_mode_installs_no_callback_and_ignores_map_config() {
    let coverage = PluginCoverage::new(PluginSwitch::Off, 0);

    let plan = match coverage.registration_plan(CoverageCapabilities::none()) {
        Ok(plan) => plan,
        Err(error) => panic!("off-mode should not validate coverage config: {error}"),
    };

    assert_eq!(plan, CoverageRegistrationPlan::Disabled);
    assert!(!plan.installs_callback());
    assert!(plan.hot_path_has_zero_coverage_overhead());
    assert_eq!(
        plan.require_callback(),
        Err(CoverageError::CallbackWhileDisabled)
    );
}

#[test]
fn coverage_registration_on_mode_requires_basic_block_callback_capability() {
    let coverage = PluginCoverage::new(PluginSwitch::On, 1024);

    assert_eq!(
        coverage.registration_plan(CoverageCapabilities::none()),
        Err(CoverageError::CapabilityUnavailable {
            symbol: QEMU_PLUGIN_REGISTER_VCPU_TB_TRANS_CB_SYMBOL,
        })
    );
    let plan = coverage
        .registration_plan(test_coverage_capabilities())
        .unwrap_or_else(|error| panic!("coverage registration should succeed: {error}"));
    assert_eq!(
        plan,
        CoverageRegistrationPlan::Install { map_entries: 1024 }
    );
    assert_eq!(
        plan.require_callback()
            .unwrap_or_else(|error| panic!("enabled plan should expose callback: {error}"))
            .map_entries(),
        1024
    );
}

#[test]
fn coverage_registration_rejects_invalid_enabled_map_size() {
    assert_eq!(
        PluginCoverage::new(PluginSwitch::On, 0).registration_plan(test_coverage_capabilities()),
        Err(CoverageError::InvalidMapEntries { entries: 0 })
    );
    assert_eq!(
        PluginCoverage::new(PluginSwitch::On, 1000).registration_plan(test_coverage_capabilities()),
        Err(CoverageError::InvalidMapEntries { entries: 1000 })
    );
}

#[test]
fn coverage_exec_callback_folds_basic_block_pc_and_records_observation() {
    let callback = coverage_callback(PluginCoverage::new(PluginSwitch::On, 1024));
    let mut map =
        CoverageMap::new(1024).unwrap_or_else(|error| panic!("coverage map should build: {error}"));
    let mut sink = RecordingCoverageSink::default();
    let event = CoverageBlockEvent::new(77, 2, 0x4010, 16);
    let expected_index = fold_basic_block_pc(0x4010, 1024);

    let observation = match handle_coverage_exec_callback(&callback, &mut map, &mut sink, event) {
        Ok(observation) => observation,
        Err(error) => panic!("coverage event should record: {error}"),
    };

    assert_eq!(observation.current_icount(), 77);
    assert_eq!(observation.vcpu_index(), 2);
    assert_eq!(observation.guest_pc(), 0x4010);
    assert_eq!(observation.block_len(), 16);
    assert_eq!(observation.map_index(), expected_index);
    assert!(observation.was_new());
    assert_eq!(map.entries()[expected_index], 1);
    assert_eq!(sink.observations, vec![observation]);
}

#[test]
fn coverage_exec_callback_uses_saturating_counters_without_new_signal_on_repeat() {
    let callback = coverage_callback(PluginCoverage::new(PluginSwitch::On, 16));
    let mut map =
        CoverageMap::new(16).unwrap_or_else(|error| panic!("coverage map should build: {error}"));
    let mut sink = RecordingCoverageSink::default();
    let event = CoverageBlockEvent::new(77, 0, 0x4010, 8);
    let index = fold_basic_block_pc(0x4010, 16);

    let first = callback
        .record_basic_block(&mut map, &mut sink, event)
        .unwrap_or_else(|error| panic!("first coverage event should record: {error}"));
    let second = callback
        .record_basic_block(&mut map, &mut sink, event)
        .unwrap_or_else(|error| panic!("second coverage event should record: {error}"));

    assert!(first.was_new());
    assert!(!second.was_new());
    assert_eq!(map.entries()[index], 2);
    assert_eq!(sink.observations, vec![first, second]);
}

#[test]
fn live_coverage_sink_retains_each_novelty_without_silent_eviction() {
    let header = RingHeader::new();
    let mut entries = vec![CoverageEntry::default(); 1];
    let mut sink = callback_model_shmem_producer(&header, &mut entries);
    let repeat = CoverageObservation {
        current_icount: 1,
        vcpu_index: 0,
        guest_pc: 0x1000,
        block_len: 4,
        map_index: 0,
        was_new: false,
    };
    sink.record_coverage(&repeat)
        .unwrap_or_else(|error| panic!("repeat coverage should be coalesced: {error}"));
    assert!(
        sink.drain()
            .unwrap_or_else(|error| panic!("repeat coverage drain should succeed: {error}"))
            .is_empty()
    );

    let first = CoverageObservation {
        was_new: true,
        ..repeat
    };
    sink.record_coverage(&first)
        .unwrap_or_else(|error| panic!("novel coverage should be retained: {error}"));
    let second = CoverageObservation {
        current_icount: 2,
        guest_pc: 0x2000,
        map_index: 1,
        ..first
    };
    let error = match sink.record_coverage(&second) {
        Ok(()) => panic!("full novelty sink must fail instead of evicting"),
        Err(error) => error,
    };
    assert!(error.message().contains("full"));
    assert_eq!(
        sink.drain()
            .unwrap_or_else(|error| panic!("novel coverage should drain: {error}")),
        vec![first]
    );
}

#[test]
fn coverage_disabled_plan_cannot_build_hot_callback_and_does_not_touch_map() {
    let coverage = PluginCoverage::new(PluginSwitch::Off, 16);
    let plan = coverage
        .registration_plan(test_coverage_capabilities())
        .unwrap_or_else(|error| panic!("off-mode coverage should not validate caps: {error}"));
    let map =
        CoverageMap::new(16).unwrap_or_else(|error| panic!("coverage map should build: {error}"));
    let sink = RecordingCoverageSink::default();

    assert_eq!(
        plan.require_callback(),
        Err(CoverageError::CallbackWhileDisabled)
    );
    assert!(map.entries().iter().all(|entry| *entry == 0));
    assert!(sink.observations.is_empty());
}

#[test]
fn coverage_exec_callback_rejects_wrong_map_size_before_recording() {
    let callback = coverage_callback(PluginCoverage::new(PluginSwitch::On, 32));
    let mut map =
        CoverageMap::new(16).unwrap_or_else(|error| panic!("coverage map should build: {error}"));
    let mut sink = RecordingCoverageSink::default();

    assert_eq!(
        callback.record_basic_block(
            &mut map,
            &mut sink,
            CoverageBlockEvent::new(1, 0, 0x4010, 8),
        ),
        Err(CoverageError::MapSizeMismatch {
            expected: 32,
            actual: 16,
        })
    );
    assert!(map.entries().iter().all(|entry| *entry == 0));
    assert!(sink.observations.is_empty());
}

fn test_coverage_capabilities() -> CoverageCapabilities {
    CoverageCapabilities::basic_blocks(QemuBasicBlockCoverageApis::new(
        test_register_tb_trans_cb,
        test_register_tb_exec_cond_cb,
        test_tb_vaddr,
        test_tb_n_insns,
        test_tb_get_insn,
        test_insn_size,
        test_icount_at_tb_entry,
        test_register_flush_cb,
        test_scoreboard_new,
        test_scoreboard_free,
        test_u64_set,
    ))
}

extern "C" fn test_register_tb_trans_cb(
    _plugin_id: QemuPluginId,
    _callback: Option<QemuVcpuTbTransCbFn>,
) {
}

extern "C" fn test_register_tb_exec_cond_cb(
    _tb: *mut QemuPluginTb,
    _callback: Option<QemuVcpuTbExecCbFn>,
    _flags: c_int,
    _condition: c_int,
    _entry: QemuPluginU64,
    _immediate: u64,
    _userdata: *mut c_void,
) {
}

extern "C" fn test_tb_vaddr(_tb: *const QemuPluginTb) -> u64 {
    0
}

extern "C" fn test_tb_n_insns(_tb: *const QemuPluginTb) -> usize {
    0
}

extern "C" fn test_tb_get_insn(_tb: *const QemuPluginTb, _index: usize) -> *mut QemuPluginInsn {
    std::ptr::null_mut()
}

extern "C" fn test_insn_size(_insn: *const QemuPluginInsn) -> usize {
    0
}

extern "C" fn test_icount_at_tb_entry(_tb_insns: u64, entry_icount: *mut u64) -> c_int {
    if entry_icount.is_null() {
        return -1;
    }
    // SAFETY: this test stub just validated the caller-provided output.
    unsafe { *entry_icount = 0 };
    0
}

extern "C" fn test_register_flush_cb(_plugin_id: QemuPluginId, _callback: QemuPluginSimpleCbFn) {}

extern "C" fn test_scoreboard_new(_element_size: usize) -> *mut QemuPluginScoreboard {
    std::ptr::NonNull::dangling().as_ptr()
}

extern "C" fn test_scoreboard_free(_score: *mut QemuPluginScoreboard) {}

extern "C" fn test_u64_set(_entry: QemuPluginU64, _vcpu_index: c_uint, _value: u64) {}

#[test]
fn coverage_exec_callback_rejects_zero_length_basic_block() {
    let callback = coverage_callback(PluginCoverage::new(PluginSwitch::On, 16));
    let mut map =
        CoverageMap::new(16).unwrap_or_else(|error| panic!("coverage map should build: {error}"));
    let mut sink = RecordingCoverageSink::default();

    assert_eq!(
        callback.record_basic_block(
            &mut map,
            &mut sink,
            CoverageBlockEvent::new(1, 0, 0x4010, 0),
        ),
        Err(CoverageError::InvalidBlockLength { block_len: 0 })
    );
    assert!(map.entries().iter().all(|entry| *entry == 0));
    assert!(sink.observations.is_empty());
}

#[test]
fn coverage_exec_callback_exports_protocol_basic_block_observation() {
    let callback = coverage_callback(PluginCoverage::new(PluginSwitch::On, 1024));
    let mut map =
        CoverageMap::new(1024).unwrap_or_else(|error| panic!("coverage map should build: {error}"));
    let mut sink = RecordingCoverageSink::default();

    let plugin_observation = handle_coverage_exec_callback(
        &callback,
        &mut map,
        &mut sink,
        CoverageBlockEvent::new(77, 2, 0x4010, 16),
    )
    .unwrap_or_else(|error| panic!("plugin callback should record coverage: {error}"));
    let protocol_observation = plugin_observation
        .to_protocol_observation()
        .unwrap_or_else(|error| panic!("plugin observation should export to protocol: {error}"));

    assert_eq!(protocol_observation.current_icount(), 77);
    assert_eq!(protocol_observation.vcpu_index(), 2);
    assert_eq!(protocol_observation.guest_pc(), 0x4010);
    assert_eq!(protocol_observation.block_len(), 16);
    assert_eq!(
        protocol_observation.map_index(),
        fold_basic_block_pc(0x4010, 1024) as u64
    );
    assert!(protocol_observation.was_new());
}

#[test]
fn coverage_flush_reclaims_metadata_before_retranslation() {
    let _callback_model_guard = crate::runtime::isolate_coverage_callback_model_for_test();
    CALLBACK_MODEL_TRANSLATION_CALLBACK.store(0, Ordering::SeqCst);
    CALLBACK_MODEL_EXEC_CALLBACK.store(0, Ordering::SeqCst);
    CALLBACK_MODEL_FLUSH_CALLBACK.store(0, Ordering::SeqCst);
    CALLBACK_MODEL_ICOUNT.store(125, Ordering::SeqCst);
    let callback = coverage_callback(PluginCoverage::new(PluginSwitch::On, 16));
    let coverage_header = RingHeader::new();
    let mut coverage_entries = vec![CoverageEntry::default(); 16];
    let output = callback_model_shmem_producer(&coverage_header, &mut coverage_entries);
    let mut owner = LiveBasicBlockCoverage::register(
        0xC0DE,
        callback,
        callback_model_apis(),
        output,
        Arc::new(LiveCallbackQuiescence::new()),
    )
    .unwrap_or_else(|error| panic!("coverage callback model should register: {error}"));
    let translate_address = CALLBACK_MODEL_TRANSLATION_CALLBACK.load(Ordering::SeqCst);
    let flush_address = CALLBACK_MODEL_FLUSH_CALLBACK.load(Ordering::SeqCst);
    assert_ne!(translate_address, 0);
    assert_ne!(flush_address, 0);
    // SAFETY: the registration stubs store callbacks with these exact ABI
    // types in their integer slots.
    let translate = unsafe { std::mem::transmute::<usize, QemuVcpuTbTransCbFn>(translate_address) };
    // SAFETY: see the callback registration invariant above.
    let flush = unsafe { std::mem::transmute::<usize, QemuPluginSimpleCbFn>(flush_address) };

    let mut first_tb = TestTb {
        guest_pc: 0x5000,
        insns: vec![TestInsn { size: 4 }],
    };
    translate(
        0xC0DE,
        std::ptr::from_mut(&mut first_tb).cast::<QemuPluginTb>(),
    );
    assert_eq!(owner.translated_block_count(), 1);

    // This models QEMU's documented ordering: generated callbacks have
    // already been destroyed before the plugin flush callback fires.
    flush(0xC0DE);
    assert_eq!(owner.translated_block_count(), 0);

    let mut second_tb = TestTb {
        guest_pc: 0x6000,
        insns: vec![TestInsn { size: 2 }, TestInsn { size: 3 }],
    };
    translate(
        0xC0DE,
        std::ptr::from_mut(&mut second_tb).cast::<QemuPluginTb>(),
    );
    assert_eq!(owner.translated_block_count(), 1);
    let execute_address = CALLBACK_MODEL_EXEC_CALLBACK.load(Ordering::SeqCst);
    let userdata = CALLBACK_MODEL_EXEC_USERDATA.load(Ordering::SeqCst);
    assert_ne!(execute_address, 0);
    // SAFETY: the execution-registration stub stores exactly this callback
    // ABI, and only the post-flush callback is invoked here.
    let execute = unsafe { std::mem::transmute::<usize, QemuVcpuTbExecCbFn>(execute_address) };
    execute(1, userdata as *mut c_void);

    let observations = owner.drain_observations();
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].current_icount(), 125);
    assert_eq!(observations[0].guest_pc(), 0x6000);
    assert_eq!(observations[0].block_len(), 5);
}

#[test]
fn coverage_callbacks_reject_work_after_quiescence_without_freeing_metadata() {
    let _callback_model_guard = crate::runtime::isolate_coverage_callback_model_for_test();
    CALLBACK_MODEL_TRANSLATION_CALLBACK.store(0, Ordering::SeqCst);
    CALLBACK_MODEL_EXEC_CALLBACK.store(0, Ordering::SeqCst);
    CALLBACK_MODEL_FLUSH_CALLBACK.store(0, Ordering::SeqCst);
    CALLBACK_MODEL_ICOUNT.store(150, Ordering::SeqCst);
    let callback = coverage_callback(PluginCoverage::new(PluginSwitch::On, 16));
    let coverage_header = RingHeader::new();
    let mut coverage_entries = vec![CoverageEntry::default(); 16];
    let output = callback_model_shmem_producer(&coverage_header, &mut coverage_entries);
    let quiescence = Arc::new(LiveCallbackQuiescence::new());
    let mut owner = LiveBasicBlockCoverage::register(
        0xC0DE,
        callback,
        callback_model_apis(),
        output,
        Arc::clone(&quiescence),
    )
    .unwrap_or_else(|error| panic!("coverage callback model should register: {error}"));
    let translate_address = CALLBACK_MODEL_TRANSLATION_CALLBACK.load(Ordering::SeqCst);
    let flush_address = CALLBACK_MODEL_FLUSH_CALLBACK.load(Ordering::SeqCst);
    let translate =
        // SAFETY: the registration stub stored this exact translation callback ABI.
        unsafe { std::mem::transmute::<usize, QemuVcpuTbTransCbFn>(translate_address) };
    let flush =
        // SAFETY: the registration stub stored this exact simple callback ABI.
        unsafe { std::mem::transmute::<usize, QemuPluginSimpleCbFn>(flush_address) };
    let mut first_tb = TestTb {
        guest_pc: 0x7000,
        insns: vec![TestInsn { size: 4 }],
    };
    translate(
        0xC0DE,
        std::ptr::from_mut(&mut first_tb).cast::<QemuPluginTb>(),
    );
    assert_eq!(owner.translated_block_count(), 1);
    let execute_address = CALLBACK_MODEL_EXEC_CALLBACK.load(Ordering::SeqCst);
    let userdata = CALLBACK_MODEL_EXEC_USERDATA.load(Ordering::SeqCst);
    let execute =
        // SAFETY: the translation callback registered this exact execution callback ABI.
        unsafe { std::mem::transmute::<usize, QemuVcpuTbExecCbFn>(execute_address) };

    quiescence.close();
    execute(0, userdata as *mut c_void);
    flush(0xC0DE);
    let mut late_tb = TestTb {
        guest_pc: 0x7100,
        insns: vec![TestInsn { size: 4 }],
    };
    translate(
        0xC0DE,
        std::ptr::from_mut(&mut late_tb).cast::<QemuPluginTb>(),
    );

    assert!(owner.drain_observations().is_empty());
    assert_eq!(owner.translated_block_count(), 1);
    assert!(!LIVE_COVERAGE_STATE.load(Ordering::Acquire).is_null());
    drop(owner);
    assert!(LIVE_COVERAGE_STATE.load(Ordering::Acquire).is_null());
}

#[test]
fn coverage_owner_unpublishes_callbacks_before_state_is_freed_and_can_reinstall() {
    let _callback_model_guard = crate::runtime::isolate_coverage_callback_model_for_test();
    CALLBACK_MODEL_TRANSLATION_CALLBACK.store(0, Ordering::SeqCst);
    CALLBACK_MODEL_FLUSH_CALLBACK.store(0, Ordering::SeqCst);
    let callback = coverage_callback(PluginCoverage::new(PluginSwitch::On, 16));
    let first_header = RingHeader::new();
    let mut first_entries = vec![CoverageEntry::default(); 16];
    let first_output = callback_model_shmem_producer(&first_header, &mut first_entries);
    let first_owner = LiveBasicBlockCoverage::register(
        0xC0DE,
        callback,
        callback_model_apis(),
        first_output,
        Arc::new(LiveCallbackQuiescence::new()),
    )
    .unwrap_or_else(|error| panic!("first coverage owner should register: {error}"));
    let translate_address = CALLBACK_MODEL_TRANSLATION_CALLBACK.load(Ordering::SeqCst);
    let flush_address = CALLBACK_MODEL_FLUSH_CALLBACK.load(Ordering::SeqCst);
    assert_ne!(translate_address, 0);
    assert_ne!(flush_address, 0);
    drop(first_owner);
    assert!(LIVE_COVERAGE_STATE.load(Ordering::Acquire).is_null());

    // QEMU removes dynamic TB callbacks before releasing the process owner.
    // Plugin-wide translation/flush callbacks can still race with teardown;
    // both observe the null published owner and return without dereference.
    let mut stale_tb = TestTb {
        guest_pc: 0x7000,
        insns: vec![TestInsn { size: 4 }],
    };
    let stale_translate =
        // SAFETY: the registration stubs stored callbacks with these exact ABI
        // types and the nonnull TB handle remains live for this invocation.
        unsafe { std::mem::transmute::<usize, QemuVcpuTbTransCbFn>(translate_address) };
    let stale_flush =
        // SAFETY: the flush callback address has the declared simple-callback ABI.
        unsafe { std::mem::transmute::<usize, QemuPluginSimpleCbFn>(flush_address) };
    stale_translate(
        0xC0DE,
        std::ptr::from_mut(&mut stale_tb).cast::<QemuPluginTb>(),
    );
    stale_flush(0xC0DE);

    let second_header = RingHeader::new();
    let mut second_entries = vec![CoverageEntry::default(); 16];
    let second_output = callback_model_shmem_producer(&second_header, &mut second_entries);
    let second_owner = LiveBasicBlockCoverage::register(
        0xC0DE,
        callback,
        callback_model_apis(),
        second_output,
        Arc::new(LiveCallbackQuiescence::new()),
    )
    .unwrap_or_else(|error| panic!("coverage owner should reinstall after teardown: {error}"));
    drop(second_owner);
    assert!(LIVE_COVERAGE_STATE.load(Ordering::Acquire).is_null());
}

fn callback_model_apis() -> QemuBasicBlockCoverageApis {
    QemuBasicBlockCoverageApis::new(
        callback_model_register_tb_trans_cb,
        callback_model_register_tb_exec_cond_cb,
        callback_model_tb_vaddr,
        callback_model_tb_n_insns,
        callback_model_tb_get_insn,
        callback_model_insn_size,
        callback_model_icount_at_tb_entry,
        callback_model_register_flush_cb,
        callback_model_scoreboard_new,
        callback_model_scoreboard_free,
        callback_model_u64_set,
    )
}

fn callback_model_shmem_producer(
    header: &RingHeader,
    entries: &mut [CoverageEntry],
) -> LiveCoverageShmemProducer {
    // SAFETY: every caller declares the header and backing vector before the
    // producer/owner and retains both until that owner is dropped.
    unsafe {
        LiveCoverageShmemProducer::from_raw_parts(
            std::ptr::from_ref(header),
            entries.as_mut_ptr(),
            entries.len(),
        )
    }
}

extern "C" fn callback_model_register_tb_trans_cb(
    plugin_id: QemuPluginId,
    callback: Option<QemuVcpuTbTransCbFn>,
) {
    CALLBACK_MODEL_TRANSLATION_PLUGIN_ID.store(plugin_id, Ordering::SeqCst);
    CALLBACK_MODEL_TRANSLATION_CALLBACK.store(
        callback.map_or(0, |callback| callback as usize),
        Ordering::SeqCst,
    );
}

extern "C" fn callback_model_register_tb_exec_cond_cb(
    _tb: *mut QemuPluginTb,
    callback: Option<QemuVcpuTbExecCbFn>,
    flags: c_int,
    condition: c_int,
    _entry: QemuPluginU64,
    immediate: u64,
    userdata: *mut c_void,
) {
    assert_eq!(condition, QEMU_PLUGIN_COND_EQ);
    assert_eq!(immediate, 0);
    CALLBACK_MODEL_EXEC_CALLBACK.store(
        callback.map_or(0, |callback| callback as usize),
        Ordering::SeqCst,
    );
    CALLBACK_MODEL_EXEC_FLAGS.store(flags as usize, Ordering::SeqCst);
    CALLBACK_MODEL_EXEC_USERDATA.store(userdata as usize, Ordering::SeqCst);
}

extern "C" fn callback_model_scoreboard_new(element_size: usize) -> *mut QemuPluginScoreboard {
    CALLBACK_MODEL_SCOREBOARD_SIZE.store(element_size, Ordering::SeqCst);
    std::ptr::NonNull::dangling().as_ptr()
}

extern "C" fn callback_model_scoreboard_new_failure(
    _element_size: usize,
) -> *mut QemuPluginScoreboard {
    std::ptr::null_mut()
}

extern "C" fn callback_model_scoreboard_free(_score: *mut QemuPluginScoreboard) {}

extern "C" fn callback_model_u64_set(entry: QemuPluginU64, vcpu_index: c_uint, value: u64) {
    CALLBACK_MODEL_SEEN_OFFSET.store(entry.offset, Ordering::SeqCst);
    CALLBACK_MODEL_SEEN_VCPU.store(vcpu_index as usize, Ordering::SeqCst);
    CALLBACK_MODEL_SEEN_VALUE.store(value, Ordering::SeqCst);
}

extern "C" fn callback_model_register_flush_cb(
    plugin_id: QemuPluginId,
    callback: QemuPluginSimpleCbFn,
) {
    CALLBACK_MODEL_FLUSH_PLUGIN_ID.store(plugin_id, Ordering::SeqCst);
    CALLBACK_MODEL_FLUSH_CALLBACK.store(callback as usize, Ordering::SeqCst);
}

extern "C" fn callback_model_tb_vaddr(tb: *const QemuPluginTb) -> u64 {
    // SAFETY: the callback ABI model passes a `TestTb` cast to the opaque
    // QEMU handle for the duration of the callback.
    unsafe { &*tb.cast::<TestTb>() }.guest_pc
}

extern "C" fn callback_model_tb_n_insns(tb: *const QemuPluginTb) -> usize {
    // SAFETY: the callback ABI model passes a `TestTb` cast to the opaque
    // QEMU handle for the duration of the callback.
    unsafe { &*tb.cast::<TestTb>() }.insns.len()
}

extern "C" fn callback_model_tb_get_insn(
    tb: *const QemuPluginTb,
    index: usize,
) -> *mut QemuPluginInsn {
    // SAFETY: the callback ABI model passes a valid `TestTb`; `index` comes
    // from the length returned by `callback_model_tb_n_insns`.
    let tb = unsafe { &*tb.cast::<TestTb>() };
    tb.insns.get(index).map_or(std::ptr::null_mut(), |insn| {
        std::ptr::from_ref(insn).cast_mut().cast::<QemuPluginInsn>()
    })
}

extern "C" fn callback_model_insn_size(insn: *const QemuPluginInsn) -> usize {
    // SAFETY: `callback_model_tb_get_insn` returns only pointers to valid
    // `TestInsn` values retained by the test translation block.
    unsafe { &*insn.cast::<TestInsn>() }.size
}

extern "C" fn callback_model_icount_at_tb_entry(tb_insns: u64, entry_icount: *mut u64) -> c_int {
    if entry_icount.is_null() {
        return -1;
    }
    CALLBACK_MODEL_TB_INSNS.store(tb_insns, Ordering::SeqCst);
    // SAFETY: this callback model just validated the output pointer supplied
    // by the production callback body.
    unsafe { *entry_icount = CALLBACK_MODEL_ICOUNT.load(Ordering::SeqCst) };
    0
}

#[derive(Default)]
struct RecordingCoverageSink {
    observations: Vec<CoverageObservation>,
}

impl CoverageSink for RecordingCoverageSink {
    fn record_coverage(
        &mut self,
        observation: &CoverageObservation,
    ) -> Result<(), CoverageSinkError> {
        self.observations.push(*observation);
        Ok(())
    }
}
