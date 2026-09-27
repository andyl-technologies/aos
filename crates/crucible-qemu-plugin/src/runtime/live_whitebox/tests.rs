//! Live whitebox runtime regression tests.

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
