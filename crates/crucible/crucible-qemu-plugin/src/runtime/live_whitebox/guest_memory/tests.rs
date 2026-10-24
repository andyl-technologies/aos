//! Exercises native buffer ownership with the real read and Drop adapters.

use std::cell::RefCell;

use super::*;

#[derive(Default)]
struct Fixture {
    payload: Vec<u8>,
    allocate: bool,
    read_ok: bool,
    null_data: bool,
    reported_len: Option<u32>,
    allocations: usize,
    reads: usize,
    frees: usize,
    free_segments: bool,
    address: u64,
    length: usize,
}

thread_local! {
    static FIXTURE: RefCell<Fixture> = RefCell::new(Fixture::default());
}

fn configure(payload: Vec<u8>) {
    FIXTURE.with_borrow_mut(|state| {
        *state = Fixture {
            payload,
            allocate: true,
            read_ok: true,
            ..Fixture::default()
        };
    });
}

extern "C" fn new() -> *mut GByteArray {
    FIXTURE.with_borrow_mut(|state| {
        state.allocations += 1;
        if !state.allocate {
            return std::ptr::null_mut();
        }
        Box::into_raw(Box::new(GByteArray {
            data: std::ptr::null_mut(),
            len: 0,
        }))
    })
}

extern "C" fn read(address: u64, array: *mut GByteArray, length: usize) -> bool {
    FIXTURE.with_borrow_mut(|state| {
        state.reads += 1;
        state.address = address;
        state.length = length;
        if !state.read_ok {
            return false;
        }
        let data = if state.null_data || state.payload.is_empty() {
            std::ptr::null_mut()
        } else {
            state.payload.as_mut_ptr()
        };
        let len = state.reported_len.unwrap_or(state.payload.len() as u32);
        // SAFETY: the adapter passes the live Box created by this test's new.
        unsafe {
            *array = GByteArray { data, len };
        }
        true
    })
}

extern "C" fn free(array: *mut GByteArray, free_segments: bool) -> *mut u8 {
    FIXTURE.with_borrow_mut(|state| {
        state.frees += 1;
        state.free_segments = free_segments;
    });
    // SAFETY: Drop returns the same Box exactly once, including read failures.
    unsafe {
        drop(Box::from_raw(array));
    }
    std::ptr::null_mut()
}

fn snapshot(length: usize) -> Result<LiveGuestMemoryBuffer, GuestMemoryReadError> {
    read_guest_buffer(
        GuestMemoryRange::new(GuestMemoryAddressSpace::Virtual, 0x1234, length),
        new,
        read,
        free,
    )
}

#[test]
fn borrowed_native_payload_retains_original_address_until_exact_scope_return() {
    configure(vec![0x5a; 4096]);

    let buffer = snapshot(4096).unwrap();

    assert_eq!(buffer.bytes(), &[0x5a; 4096]);
    FIXTURE.with_borrow(|state| {
        assert_eq!(buffer.bytes().as_ptr(), state.payload.as_ptr());
        assert_eq!((state.allocations, state.reads, state.frees), (1, 1, 0));
        assert_eq!((state.address, state.length), (0x1234, 4096));
    });

    drop(buffer);

    FIXTURE.with_borrow(|state| {
        assert_eq!(state.frees, 1);
        assert!(state.free_segments);
    });
}

#[test]
fn native_read_refusals_return_only_born_arrays_once_and_keep_static_diagnostics() {
    configure(vec![1]);
    let physical = read_guest_buffer(
        GuestMemoryRange::new(GuestMemoryAddressSpace::Physical, 0x1234, 1),
        new,
        read,
        free,
    )
    .err()
    .unwrap();
    assert_eq!(
        physical.message(),
        "live white-box adapter requires a virtual payload range"
    );
    FIXTURE
        .with_borrow(|state| assert_eq!((state.allocations, state.reads, state.frees), (0, 0, 0)));

    configure(vec![1]);
    FIXTURE.with_borrow_mut(|state| state.allocate = false);
    let allocation = snapshot(1).err().unwrap();
    assert_eq!(allocation.message(), "GLib byte-array allocation failed");
    FIXTURE
        .with_borrow(|state| assert_eq!((state.allocations, state.reads, state.frees), (1, 0, 0)));

    configure(vec![1]);
    FIXTURE.with_borrow_mut(|state| state.read_ok = false);
    let failure = snapshot(1).err().unwrap();
    let retained = failure.clone();
    assert_eq!(failure.message(), "qemu_plugin_read_memory_vaddr failed");
    assert_eq!(retained.message().as_ptr(), failure.message().as_ptr());
    assert_eq!(
        failure.to_string(),
        "guest-memory read failed: qemu_plugin_read_memory_vaddr failed"
    );
    FIXTURE
        .with_borrow(|state| assert_eq!((state.allocations, state.reads, state.frees), (1, 1, 1)));
}

#[test]
fn native_buffer_shape_refusal_precedes_slice_borrow_and_empty_null_data_is_valid() {
    for (null_data, reported_len) in [(true, None), (false, Some(2)), (false, Some(0))] {
        configure(vec![1]);
        FIXTURE.with_borrow_mut(|state| {
            state.null_data = null_data;
            state.reported_len = reported_len;
        });

        let failure = snapshot(1).err().unwrap();

        assert_eq!(
            failure.message(),
            "qemu_plugin_read_memory_vaddr returned an invalid byte array"
        );
        FIXTURE.with_borrow(|state| {
            assert_eq!((state.allocations, state.reads, state.frees), (1, 1, 1))
        });
    }

    configure(Vec::new());

    let empty = snapshot(0).unwrap();
    assert!(empty.bytes().is_empty());
    drop(empty);

    FIXTURE
        .with_borrow(|state| assert_eq!((state.allocations, state.reads, state.frees), (1, 1, 1)));
    let owned = GuestMemoryReadError::new(String::from("owned backend diagnostic"));
    assert_eq!(owned.message(), "owned backend diagnostic");
}
