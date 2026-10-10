//! Checks exact token custody and no-ack cleanup of the native capture claim.

// SPDX-License-Identifier: GPL-2.0-or-later

use super::*;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, AtomicUsize, Ordering};

static SERIAL: Mutex<()> = Mutex::new(());
static INVALID_HEADER: AtomicBool = AtomicBool::new(false);
static CLEANUP_STATUS: AtomicI32 = AtomicI32::new(0);
static CLOSES: AtomicUsize = AtomicUsize::new(0);
static COMMITS: AtomicUsize = AtomicUsize::new(0);
static CLOSED_TOKEN: AtomicU64 = AtomicU64::new(0);
static CLOSED_GENERATION: AtomicU64 = AtomicU64::new(0);

extern "C" fn begin(_full: u32, _token: u64, header: *mut CaptureHeader) -> c_int {
    // SAFETY: CaptureClaim lends initialized, exclusive output storage for
    // this synchronous callback; no pointer is retained.
    unsafe {
        header.write(CaptureHeader {
            schema: CAPTURE_SCHEMA,
            region_count: u32::from(!INVALID_HEADER.load(Ordering::Relaxed)),
            topology_generation: 1,
            capture_generation: 27,
            metadata_budget_bytes: 1024,
        });
    }
    0
}

extern "C" fn finish(generation: u64, token: u64, commit: u32) -> c_int {
    if commit != 0 {
        COMMITS.fetch_add(1, Ordering::Relaxed);
        return -libc::EPERM;
    }
    CLOSED_TOKEN.store(token, Ordering::Relaxed);
    CLOSED_GENERATION.store(generation, Ordering::Relaxed);
    CLOSES.fetch_add(1, Ordering::Relaxed);
    CLEANUP_STATUS.load(Ordering::Relaxed)
}

fn fixture() -> NativeApis {
    INVALID_HEADER.store(false, Ordering::Relaxed);
    CLEANUP_STATUS.store(0, Ordering::Relaxed);
    CLOSES.store(0, Ordering::Relaxed);
    COMMITS.store(0, Ordering::Relaxed);
    CLOSED_TOKEN.store(0, Ordering::Relaxed);
    CLOSED_GENERATION.store(0, Ordering::Relaxed);
    NativeApis {
        begin,
        finish,
        ..super::tests::apis()
    }
}

#[test]
fn explicit_no_ack_close_retains_token_and_reports_cleanup_refusal_once() {
    let _serial = SERIAL.lock().unwrap();
    let apis = fixture();
    let mut claim = CaptureClaim::begin(apis, false, 53).unwrap();
    CLEANUP_STATUS.store(-libc::ESTALE, Ordering::Relaxed);

    assert_eq!(claim.close_without_ack(), Some(-libc::ESTALE));
    assert_eq!(claim.close_without_ack(), None);
    drop(claim);

    assert_eq!(CLOSES.load(Ordering::Relaxed), 1);
    assert_eq!(COMMITS.load(Ordering::Relaxed), 0);
    assert_eq!(CLOSED_TOKEN.load(Ordering::Relaxed), 53);
    assert_eq!(CLOSED_GENERATION.load(Ordering::Relaxed), 27);
}

#[test]
fn commit_refusal_preserves_first_error_and_closes_same_claim() {
    let _serial = SERIAL.lock().unwrap();
    let apis = fixture();
    let claim = CaptureClaim::begin(apis, false, 53).unwrap();
    CLEANUP_STATUS.store(-libc::ESTALE, Ordering::Relaxed);

    let error = claim.commit().unwrap_err();

    assert!(matches!(error, RamError::Native { status, .. } if status == -libc::EPERM));
    assert_eq!(CLOSES.load(Ordering::Relaxed), 1);
    assert_eq!(COMMITS.load(Ordering::Relaxed), 1);
    assert_eq!(CLOSED_TOKEN.load(Ordering::Relaxed), 53);
}

#[test]
fn unwind_closes_same_token_without_ack() {
    let _serial = SERIAL.lock().unwrap();
    let apis = fixture();

    let result = std::panic::catch_unwind(|| {
        let _claim = CaptureClaim::begin(apis, false, 53).unwrap();
        panic!("capture work failed");
    });

    assert!(result.is_err());
    assert_eq!(CLOSES.load(Ordering::Relaxed), 1);
    assert_eq!(COMMITS.load(Ordering::Relaxed), 0);
    assert_eq!(CLOSED_TOKEN.load(Ordering::Relaxed), 53);
}

#[test]
fn malformed_header_closes_original_claim_before_returning_refusal() {
    let _serial = SERIAL.lock().unwrap();
    let apis = fixture();
    INVALID_HEADER.store(true, Ordering::Relaxed);

    assert!(CaptureClaim::begin(apis, false, 53).is_err());

    assert_eq!(CLOSES.load(Ordering::Relaxed), 1);
    assert_eq!(COMMITS.load(Ordering::Relaxed), 0);
    assert_eq!(CLOSED_TOKEN.load(Ordering::Relaxed), 53);
}
