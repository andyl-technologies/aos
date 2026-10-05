//! Live whitebox runtime regression tests.

use std::cell::Cell;
use std::sync::atomic::{AtomicBool, Ordering};

use super::*;

#[test]
fn selectable_pre_instruction_tick_preserves_fractional_phase() -> Result<(), LiveWhiteboxError> {
    assert_eq!(pre_instruction_tick_ps(100, 110, 5_537)?, 5_037);
    assert_eq!(pre_instruction_tick_ps(100, 110, 1_000_537)?, 1_000_037);
    assert!(pre_instruction_tick_ps(111, 110, 5_537).is_err());
    assert!(pre_instruction_tick_ps(100, 110, 499).is_err());
    assert!(pre_instruction_tick_ps(0, u64::MAX, u64::MAX).is_err());
    Ok(())
}

static REGISTER_ZERO_READ: AtomicBool = AtomicBool::new(false);
static REGISTER_BYTES: [u8; 8] = 0x1122_3344_5566_7788_u64.to_le_bytes();

extern "C" fn byte_array_new() -> *mut api::GByteArray {
    Box::into_raw(Box::new(api::GByteArray {
        data: REGISTER_BYTES.as_ptr().cast_mut(),
        len: 0,
    }))
}

extern "C" fn read_register_zero(
    handle: *mut QemuPluginRegister,
    array: *mut api::GByteArray,
) -> bool {
    if !handle.is_null() {
        return false;
    }
    let Some(mut array) = NonNull::new(array) else {
        return false;
    };
    // SAFETY: `byte_array_new` returns an owned, live array allocation to this
    // synchronous fake, which mutates only its length field.
    unsafe { array.as_mut() }.len = REGISTER_BYTES.len() as c_uint;
    REGISTER_ZERO_READ.store(true, Ordering::Release);
    true
}

extern "C" fn byte_array_free(array: *mut api::GByteArray, _free_segment: bool) -> *mut u8 {
    let Some(array) = NonNull::new(array) else {
        return std::ptr::null_mut();
    };
    // SAFETY: the reader frees exactly the allocation returned by
    // `byte_array_new`, after the synchronous fake read has completed.
    let array = unsafe { Box::from_raw(array.as_ptr()) };
    array.data
}

#[test]
fn register_zero_handle_is_present_and_read_unchanged() -> Result<(), LiveWhiteboxError> {
    REGISTER_ZERO_READ.store(false, Ordering::Release);
    let descriptors = [
        QemuPluginRegDescriptor {
            handle: std::ptr::null_mut(),
            name: c"x0".as_ptr(),
            feature: c"org.gnu.gdb.aarch64.core".as_ptr(),
            _is_readonly: false,
        },
        QemuPluginRegDescriptor {
            handle: 2_usize as *mut QemuPluginRegister,
            name: c"x1".as_ptr(),
            feature: c"org.gnu.gdb.aarch64.core".as_ptr(),
            _is_readonly: false,
        },
    ];
    let registers = required_registers(QemuPluginTargetArchitecture::Aarch64, &descriptors);
    let Some(pointer) = registers.pointer else {
        panic!("the zero-valued x0 handle must remain present");
    };
    assert!(pointer.as_ptr().is_null());
    assert!(registers.complete(QemuPluginTargetArchitecture::Aarch64));

    let reader = LiveRegisterReader {
        read_register: read_register_zero,
        byte_array_new,
        byte_array_free,
    };
    assert_eq!(reader.read_u64(pointer)?, 0x1122_3344_5566_7788);
    assert!(REGISTER_ZERO_READ.load(Ordering::Acquire));
    Ok(())
}

thread_local! {
    static PC_READS: Cell<usize> = const { Cell::new(0) };
}

extern "C" fn read_pc(handle: *mut QemuPluginRegister, array: *mut api::GByteArray) -> bool {
    PC_READS.set(PC_READS.get() + 1);
    read_register_zero(handle, array)
}

extern "C" fn reject_pc(_handle: *mut QemuPluginRegister, _array: *mut api::GByteArray) -> bool {
    PC_READS.set(PC_READS.get() + 1);
    false
}

fn late_failure() -> LiveWhiteboxError {
    LiveWhiteboxError::LateSelectableRegistration {
        source: Box::new(crate::SelectableCatalogError::RegistrationAfterFreeze),
        selectable_id: "flight.ready".to_owned(),
        sequence: 1,
        previous_sequence: Some(1),
        completed_sequence: Some(2),
        raw_icount: 100,
        logical_ps: 5_037,
        vcpu_index: 0,
        process_id: std::process::id(),
        guest_pc: None,
    }
}

#[test]
fn optional_pc_descriptor_keeps_original_required_register_admission() {
    for (architecture, pointer, length, pc) in [
        (QemuPluginTargetArchitecture::X86_64, c"rax", c"rcx", c"rip"),
        (QemuPluginTargetArchitecture::Aarch64, c"x0", c"x1", c"pc"),
    ] {
        let descriptors = [pointer, length, pc].map(|name| QemuPluginRegDescriptor {
            handle: std::ptr::null_mut(),
            name: name.as_ptr(),
            feature: std::ptr::null(),
            _is_readonly: false,
        });

        let original = required_registers(architecture, &descriptors[..2]);
        assert!(original.complete(architecture));
        assert!(original.instruction_pointer.is_none());
        let observed = required_registers(architecture, &descriptors);
        assert!(observed.complete(architecture));
        assert!(observed.instruction_pointer.is_some());
        assert!(!required_registers(architecture, &descriptors[2..]).complete(architecture));
    }
}

#[test]
fn unavailable_pc_keeps_original_late_refusal_and_context() {
    PC_READS.set(0);
    let reader = LiveRegisterReader {
        read_register: reject_pc,
        byte_array_new,
        byte_array_free,
    };
    let original = late_failure().to_string();
    let absent =
        with_selectable_failure_pc(late_failure(), LiveWhiteboxRegisters::default(), reader);

    assert_eq!(absent.to_string(), original);
    assert_eq!(PC_READS.get(), 0);
    let failed = with_selectable_failure_pc(
        late_failure(),
        LiveWhiteboxRegisters {
            instruction_pointer: Some(LiveWhiteboxRegisterHandle(std::ptr::null_mut())),
            ..LiveWhiteboxRegisters::default()
        },
        reader,
    );
    assert_eq!(failed.to_string(), original);
    assert_eq!(PC_READS.get(), 1);
    assert!(original.contains("guest_pc=unavailable"));
}

#[test]
fn failure_only_pc_read_retains_exact_original_register_value() {
    PC_READS.set(0);
    let reader = LiveRegisterReader {
        read_register: read_pc,
        byte_array_new,
        byte_array_free,
    };
    let registers = LiveWhiteboxRegisters {
        instruction_pointer: Some(LiveWhiteboxRegisterHandle(std::ptr::null_mut())),
        ..LiveWhiteboxRegisters::default()
    };
    let failure = with_selectable_failure_pc(late_failure(), registers, reader);

    assert!(matches!(
        failure,
        LiveWhiteboxError::LateSelectableRegistration {
            guest_pc: Some(0x1122_3344_5566_7788),
            ..
        }
    ));
    assert!(failure.to_string().contains("guest_pc=0x1122334455667788"));
    assert_eq!(PC_READS.get(), 1);

    let original = LiveWhiteboxError::Callback {
        message: "original selectable decode refusal".to_owned(),
    };
    let original_display = original.to_string();
    let unchanged = with_selectable_failure_pc(original, registers, reader);
    assert_eq!(unchanged.to_string(), original_display);
    assert_eq!(PC_READS.get(), 1);
}

#[test]
fn maximum_legal_late_registration_fatal_line_is_bounded() -> Result<(), Box<dyn std::error::Error>>
{
    let registration = crucible_protocol::SelectableRegister::new(
        u64::MAX,
        "x".repeat(crucible_protocol::SELECTABLE_IDENTIFIER_MAX_BYTES),
        vec![1],
        vec![1],
        vec!["readiness".to_owned()],
    )?;
    let failure = LiveWhiteboxError::LateSelectableRegistration {
        source: Box::new(crate::SelectableCatalogError::RegistrationAfterFreeze),
        selectable_id: registration.selectable_id().to_owned(),
        sequence: registration.sequence(),
        previous_sequence: Some(u64::MAX),
        completed_sequence: Some(u64::MAX),
        raw_icount: u64::MAX,
        logical_ps: u64::MAX,
        vcpu_index: u32::MAX,
        process_id: u32::MAX,
        guest_pc: Some(u64::MAX),
    };
    let line = format!("crucible-qemu-plugin: live white-box callback failed: {failure}\n");

    assert!(line.is_ascii());
    assert_eq!(line.lines().count(), 1);
    assert!(line.len() <= 512, "{} bytes", line.len());
    assert!(line.contains(registration.selectable_id()));
    Ok(())
}

#[test]
fn two_markers_without_fault_keep_raw_identity_and_zero_logical_bias() {
    let markers = [(8, 9), (19, 21)];
    let tick_scale = crucible_shmem::TICKS_PER_INSTRUCTION;

    for (marker_raw, observed_raw) in markers {
        let observed_tick = observed_raw * tick_scale;
        let marker = WhiteboxDoorbellTrapEvent::from_register_pointer_length(
            0,
            marker_raw,
            GuestMemoryRange::new(GuestMemoryAddressSpace::Virtual, 0, 0),
        );

        assert_eq!(
            marker_logical_offset(observed_raw, observed_tick)
                .unwrap_or_else(|error| panic!("unbiased marker tick should resolve: {error}")),
            0
        );
        assert_eq!(marker.current_icount(), marker_raw);
    }
}

#[test]
fn fault_advance_changes_only_logical_bias_after_marker_instruction() {
    let first_marker = 8;
    let second_marker = 19;
    let fault_advance_ticks = 7;
    let tick_scale = crucible_shmem::TICKS_PER_INSTRUCTION;

    let first_observed_raw = first_marker + 1;
    let first_tick = first_observed_raw * tick_scale;
    assert_eq!(
        marker_logical_offset(first_observed_raw, first_tick)
            .unwrap_or_else(|error| panic!("first marker bias should resolve: {error}")),
        0
    );

    let second_observed_raw = second_marker + 2;
    let second_tick = second_observed_raw * tick_scale + fault_advance_ticks;
    assert_eq!(
        marker_logical_offset(second_observed_raw, second_tick)
            .unwrap_or_else(|error| panic!("advanced marker bias should resolve: {error}")),
        fault_advance_ticks
    );
    assert_eq!(tick_scale, 50);
}
