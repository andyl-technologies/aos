//! Live coverage callback ABI and allocation cases.

use super::*;

#[test]
fn coverage_callback_abi_model_captures_block_pc_length_and_exact_entry_icount() {
    let _callback_model_guard = crate::runtime::isolate_coverage_callback_model_for_test();
    CALLBACK_MODEL_TRANSLATION_CALLBACK.store(0, Ordering::SeqCst);
    CALLBACK_MODEL_EXEC_CALLBACK.store(0, Ordering::SeqCst);
    CALLBACK_MODEL_FLUSH_CALLBACK.store(0, Ordering::SeqCst);
    CALLBACK_MODEL_ICOUNT.store(91, Ordering::SeqCst);
    CALLBACK_MODEL_TB_INSNS.store(0, Ordering::SeqCst);
    CALLBACK_MODEL_SCOREBOARD_SIZE.store(0, Ordering::SeqCst);
    CALLBACK_MODEL_SEEN_OFFSET.store(usize::MAX, Ordering::SeqCst);
    CALLBACK_MODEL_SEEN_VCPU.store(usize::MAX, Ordering::SeqCst);
    CALLBACK_MODEL_SEEN_VALUE.store(0, Ordering::SeqCst);
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
    let plugin_id = CALLBACK_MODEL_TRANSLATION_PLUGIN_ID.load(Ordering::SeqCst);
    let translate_address = CALLBACK_MODEL_TRANSLATION_CALLBACK.swap(0, Ordering::SeqCst);
    assert_ne!(translate_address, 0);
    let translate =
        // SAFETY: the registration stub stores exactly one
        // `QemuVcpuTbTransCbFn` address in this integer slot.
        unsafe { std::mem::transmute::<usize, QemuVcpuTbTransCbFn>(translate_address) };
    assert_eq!(plugin_id, 0xC0DE);
    assert_eq!(
        CALLBACK_MODEL_FLUSH_PLUGIN_ID.load(Ordering::SeqCst),
        0xC0DE
    );
    assert_ne!(CALLBACK_MODEL_FLUSH_CALLBACK.load(Ordering::SeqCst), 0);
    assert_eq!(
        CALLBACK_MODEL_SCOREBOARD_SIZE.load(Ordering::SeqCst),
        16 * std::mem::size_of::<u64>()
    );

    let mut tb = TestTb {
        guest_pc: 0x4010,
        insns: vec![
            TestInsn { size: 2 },
            TestInsn { size: 3 },
            TestInsn { size: 5 },
        ],
    };
    translate(
        plugin_id,
        std::ptr::from_mut(&mut tb).cast::<QemuPluginTb>(),
    );
    let execute_address = CALLBACK_MODEL_EXEC_CALLBACK.swap(0, Ordering::SeqCst);
    assert_ne!(execute_address, 0);
    // SAFETY: the execution-registration stub stores exactly one
    // `QemuVcpuTbExecCbFn` address in this integer slot.
    let execute = unsafe { std::mem::transmute::<usize, QemuVcpuTbExecCbFn>(execute_address) };
    let flags = CALLBACK_MODEL_EXEC_FLAGS.load(Ordering::SeqCst) as c_int;
    let userdata = CALLBACK_MODEL_EXEC_USERDATA.load(Ordering::SeqCst);
    assert_eq!(flags, QEMU_PLUGIN_CB_NO_REGS);
    assert_eq!(owner.translated_block_count(), 1);

    execute(2, userdata as *mut c_void);
    assert_eq!(CALLBACK_MODEL_TB_INSNS.load(Ordering::SeqCst), 3);
    assert_eq!(
        CALLBACK_MODEL_SEEN_OFFSET.load(Ordering::SeqCst),
        fold_basic_block_pc(0x4010, 16) * std::mem::size_of::<u64>()
    );
    assert_eq!(CALLBACK_MODEL_SEEN_VCPU.load(Ordering::SeqCst), 2);
    assert_eq!(CALLBACK_MODEL_SEEN_VALUE.load(Ordering::SeqCst), 1);
    let observations = owner.drain_observations();
    assert_eq!(observations.len(), 1);
    let observation = observations[0];
    assert_eq!(observation.current_icount(), 91);
    assert_eq!(observation.vcpu_index(), 2);
    assert_eq!(observation.guest_pc(), 0x4010);
    assert_eq!(observation.block_len(), 10);
    assert_eq!(observation.map_index(), fold_basic_block_pc(0x4010, 16));
    assert!(observation.was_new());
    assert_eq!(owner.map_entries()[fold_basic_block_pc(0x4010, 16)], 1);
}

#[test]
fn coverage_callback_owner_fails_loudly_when_novelty_scoreboard_allocation_fails() {
    let _callback_model_guard = crate::runtime::isolate_coverage_callback_model_for_test();
    let callback = coverage_callback(PluginCoverage::new(PluginSwitch::On, 16));
    let coverage_header = RingHeader::new();
    let mut coverage_entries = vec![CoverageEntry::default(); 16];
    let output = callback_model_shmem_producer(&coverage_header, &mut coverage_entries);
    let mut apis = callback_model_apis();
    apis.scoreboard_new = callback_model_scoreboard_new_failure;

    let error = match LiveBasicBlockCoverage::register(
        0xC0DE,
        callback,
        apis,
        output,
        Arc::new(LiveCallbackQuiescence::new()),
    ) {
        Ok(_owner) => panic!("null novelty scoreboard should reject coverage registration"),
        Err(error) => error,
    };

    assert_eq!(
        error,
        CoverageError::NoveltyScoreboardAllocation {
            scoreboard_size: 16 * std::mem::size_of::<u64>(),
        }
    );
    assert!(LIVE_COVERAGE_STATE.load(Ordering::Acquire).is_null());
}
