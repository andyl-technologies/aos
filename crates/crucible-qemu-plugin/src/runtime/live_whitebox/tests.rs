//! Live whitebox runtime regression tests.

use std::sync::atomic::{AtomicBool, Ordering};

use super::*;

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
    let first_marker = 8;
    let second_marker = 19;

    for marker_raw in [first_marker, second_marker] {
        let observed_tick = marker_raw * crucible_shmem::TICKS_PER_INSTRUCTION;
        let marker = WhiteboxDoorbellTrapEvent::from_register_pointer_length(
            0,
            marker_raw,
            GuestMemoryRange::new(GuestMemoryAddressSpace::Virtual, 0, 0),
        );

        assert_eq!(marker_logical_offset(marker_raw, observed_tick).unwrap(), 0);
        assert_eq!(marker.current_icount(), marker_raw);
    }
}

#[test]
fn fault_advance_changes_only_logical_bias_after_marker_instruction() {
    let first_marker = 8;
    let second_marker = 19;
    let fault_advance_ticks = 7;
    let tick_scale = crucible_shmem::TICKS_PER_INSTRUCTION;

    let first_tick = first_marker * tick_scale;
    assert_eq!(marker_logical_offset(first_marker, first_tick).unwrap(), 0);

    let second_tick = second_marker * tick_scale + fault_advance_ticks;
    assert_eq!(
        marker_logical_offset(second_marker, second_tick).unwrap(),
        fault_advance_ticks
    );
    assert_eq!(tick_scale, 50);
}
