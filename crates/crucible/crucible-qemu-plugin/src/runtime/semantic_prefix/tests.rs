//! Refusal and revocation controls for the separate controller-nine semantic callback entry points.
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

#[test]
fn prefix_policy_keeps_the_exact_unchanged_ancestor_extent() {
    use std::mem::{offset_of, size_of};

    assert_eq!(size_of::<AncestorEffectPolicy>(), 200);
    assert_eq!(size_of::<PrefixPolicy>(), 280);
    assert_eq!(offset_of!(PrefixPolicy, original_effect), 8);
    assert_eq!(offset_of!(PrefixPolicy, prefix_preparation_commitment), 208);
    assert_eq!(offset_of!(PrefixPolicy, prefix_policy_digest), 240);
    assert_eq!(offset_of!(PrefixPolicy, controller_edition), 272);
    assert_eq!(offset_of!(PrefixPolicy, maximum_prefixes), 276);
}

#[test]
// crucible-lint: allow panic-shortcut -- This control deliberately poisons the actual mutex and asserts retained bytes after refusal.
// crucible-lint: allow rust-allow -- Unwrap is confined to this assertion and deliberate-poison test.
#[allow(clippy::unwrap_used)]
fn held_and_poisoned_original_journals_have_distinct_refusals_without_consumption() {
    let original = (vec![1u8, 2, 3], 7u64);
    let journal = Mutex::new(original.clone());
    let held = journal.lock().unwrap();

    assert!(matches!(try_callback_journal(&journal), Err(code) if code == -libc::EAGAIN));
    assert_eq!(*held, original);
    drop(held);
    assert_eq!(*try_callback_journal(&journal).unwrap(), original);

    let result = std::panic::catch_unwind(|| {
        let _original_guard = journal.lock().unwrap();
        panic!("deliberate original journal poison control");
    });

    assert!(result.is_err());
    assert!(matches!(try_callback_journal(&journal), Err(code) if code == -libc::EOWNERDEAD));
    assert_eq!(*journal.lock().unwrap_err().into_inner(), original);
    assert!(SCOPED_CONTEXT.with(Cell::get).is_none());
}
