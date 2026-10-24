//! Refusal and revocation controls for the actual semantic callback entry points.
//!
//! These controls issue no native root, owned epoch or effect permission. They
//! exercise invalid callback storage and the real Rust TLS revocation path.

// SPDX-License-Identifier: GPL-2.0-or-later

use super::*;

#[test]
fn prepare_clears_original_output_before_missing_userdata_refusal() {
    let mut output = std::ptr::dangling_mut::<c_void>();

    // SAFETY: Output names writable aligned storage; null userdata must be
    // refused before dereference and no source handle is supplied.
    let result = unsafe { (OPS.prepare)(std::ptr::null(), &mut output, std::ptr::null_mut()) };

    assert_eq!(result, -libc::EINVAL);
    assert!(output.is_null());
}

#[test]
fn null_callback_arguments_never_install_scope_or_return_a_command() {
    SCOPED_CONTEXT.with(|scope| scope.set(None));

    // SAFETY: Each callback must reject null userdata before dereference;
    // prepare/getter must also reject missing writable output storage.
    unsafe {
        assert_eq!(
            (OPS.prepare)(std::ptr::null(), std::ptr::null_mut(), std::ptr::null_mut()),
            -libc::EINVAL
        );
        assert_eq!(
            (OPS.validate_held)(std::ptr::null(), std::ptr::null_mut(), std::ptr::null_mut()),
            -libc::EINVAL
        );
        assert_eq!(
            (OPS.begin)(
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null_mut()
            ),
            -libc::EINVAL
        );
        assert_eq!(
            get_command(
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut()
            ),
            -libc::EINVAL
        );
    }

    assert!(SCOPED_CONTEXT.with(Cell::get).is_none());
}

#[test]
fn end_revokes_staged_tls_before_missing_userdata_refusal() {
    // This test-only TLS sentinel grants no native scope. It proves that even
    // a malformed end cannot leave previously staged Rust state installed.
    SCOPED_CONTEXT.with(|scope| {
        scope.set(Some(ScopedContext {
            owner: 1,
            root: 2,
            epoch: 3,
            cut: 4,
            prospective: NativeEffectContext::default(),
        }))
    });

    // SAFETY: Missing userdata is rejected without dereference; end must first
    // clear the same-thread TLS state regardless of the supplied handles.
    let result = unsafe {
        (OPS.end)(
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null_mut(),
        )
    };

    assert_eq!(result, -libc::EINVAL);
    assert!(SCOPED_CONTEXT.with(Cell::get).is_none());
}

#[test]
fn command_getter_zeros_complete_output_before_missing_userdata_refusal() {
    let getter: command::OriginalCommandGetter = get_command;
    let mut output = NativeEffectCommand {
        version: 1,
        size: 224,
        kind: 1,
        reserved: 0,
        sequence: 7,
        scope: [1; 32],
        effect_preparation: [2; 32],
        grant_digest: [3; 32],
        command_digest: [4; 32],
        owned_epoch: std::ptr::dangling_mut(),
        start: NativeEffectPosition {
            time_ps: 1,
            microstep: 2,
            phase: 3,
            reserved: 0,
        },
        limit: NativeEffectPosition {
            time_ps: 4,
            microstep: 5,
            phase: 0,
            reserved: 0,
        },
        maximum_callbacks: 1,
        budget_reserved: 0,
        maximum_service_span: 1,
    };

    // SAFETY: Output is complete aligned native224 storage; null userdata must
    // be refused after zeroing, before any opaque handle or owner dereference.
    let result = unsafe { getter(std::ptr::null_mut(), &mut output, std::ptr::null_mut()) };

    assert_eq!(result, -libc::EINVAL);
    assert_eq!(output.version, 0);
    assert_eq!(output.sequence, 0);
    assert_eq!(output.scope, [0; 32]);
    assert_eq!(output.grant_digest, [0; 32]);
    assert_eq!(output.start, NativeEffectPosition::default());
    assert_eq!(output.limit, NativeEffectPosition::default());
    assert!(output.owned_epoch.is_null());
}
