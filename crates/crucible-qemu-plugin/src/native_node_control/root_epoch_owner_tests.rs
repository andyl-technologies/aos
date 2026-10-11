//! Dormant ABI tests with real native transport and model-only initialization.

// crucible-lint: allow panic-shortcut -- Test-only assertions panic on an unmet custody or codec invariant.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use crucible_protocol::node_control::{NativeChannel, NativeControlEdition};

use super::*;
use crate::native_node_control::administrative_inbox::NativeAdministrativeInbox;
use crate::native_node_control::preparation_fifo::tests::{initializer, mapped};
use crate::native_node_control::preparation_transport::NativePreparationTransportCredit;
use crate::runtime::callback_quiescence::LiveCallbackQuiescence;
use crate::runtime::native_run_control::{NativeRunControlCustody, test_running_pair};
use crate::runtime::worker_quiescence::{WORKER_RUN_CONTROL, WORKER_TEARDOWN};

#[test]
fn busy_and_completed_transport_keep_null_epoch_and_same_original_holds() {
    let region = mapped(1);
    let initialization = initializer(true);
    let (_host, native) =
        NativeChannel::supervised_pair_for_edition(NativeControlEdition::Administration).unwrap();
    let mut endpoint = Some(native);
    let inbox = Arc::new(
        NativeAdministrativeInbox::from_pinned_endpoint(
            &mut endpoint,
            initialization.scope,
            false,
            8,
            65536,
        )
        .unwrap(),
    );
    let (_run_host, original_run) = test_running_pair();
    let prepared = NativeRunControlCustody::prepare(original_run);
    prepared.status.unwrap();
    let workers = Arc::clone(inbox.modeled_workers());
    let _reader = workers.idle(WORKER_RUN_CONTROL);
    let _teardown = workers.idle(WORKER_TEARDOWN);
    let callbacks = Arc::new(LiveCallbackQuiescence::new());
    let transport = NativePreparationTransportCustody::new(
        initialization,
        Arc::clone(&callbacks),
        Arc::clone(&workers),
        &region,
        Arc::clone(&inbox),
        prepared.owner,
        NativePreparationTransportCredit {
            fifo_bytes: 64 * 1024 * 1024,
            inbox_bytes: 65536,
        },
    )
    .unwrap();
    let owner = DormantRootEpochOwner::pin(transport);
    let root_cookie = 1_u8;
    let foreign_cookie = 2_u8;
    let root = std::ptr::from_ref(&root_cookie).cast::<NativeSourceRootSeal>();
    let foreign = std::ptr::from_ref(&foreign_cookie).cast::<NativeSourceRootSeal>();
    let userdata = owner.as_ref().userdata();
    let (acquire, begin, end) = DormantRootEpochOwner::callbacks();
    let mut output = userdata;
    let busy = inbox.test_hold_mailbox();

    // SAFETY: These calls use live pinned userdata and valid writable output.
    // Cookies model only pointer correlation, never a genuine native RootSeal.
    assert_eq!(
        // SAFETY: Live test storage is retained; opaque correlation cookies are never dereferenced.
        unsafe { acquire(root, &mut output, userdata) },
        -libc::EAGAIN
    );
    assert!(output.is_null());
    assert!(!owner.state.lock().unwrap().transport_retained);
    assert!(callbacks.enter().is_none());
    assert!(workers.snapshot().held);
    drop(busy);

    output = userdata;
    // SAFETY: The original pinned owner, root cookie and output remain live.
    assert_eq!(
        // SAFETY: Live test storage is retained; opaque correlation cookies are never dereferenced.
        unsafe { acquire(root, &mut output, userdata) },
        -libc::EAGAIN
    );
    assert!(output.is_null());
    assert!(owner.state.lock().unwrap().transport_retained);
    output = userdata;
    // SAFETY: The foreign cookie is a valid correlation test pointer only.
    assert_eq!(
        // SAFETY: Live test storage is retained; opaque correlation cookies are never dereferenced.
        unsafe { acquire(foreign, &mut output, userdata) },
        -libc::ESTALE
    );
    assert!(output.is_null());
    assert!(owner.state.lock().unwrap().transport_retained);

    let cut = std::ptr::from_ref(&foreign_cookie).cast::<NativeSourceEffectCut>();
    // SAFETY: Live cookies are never dereferenced. No epoch was issued.
    assert_eq!(
        // SAFETY: Live test storage is retained; opaque correlation cookies are never dereferenced.
        unsafe { begin(root, userdata, cut, userdata) },
        -libc::ESTALE
    );
    // SAFETY: Ending an unissued epoch cannot grant or release admission.
    assert_eq!(unsafe { end(root, userdata, cut, userdata) }, -libc::ESTALE);
    assert!(callbacks.enter().is_none());
    assert!(workers.snapshot().held);

    // Busy callback userdata never waits under the native BQL seam.
    let locked = owner.state.lock().unwrap();
    output = userdata;
    // SAFETY: Original pointers remain live while the actual mutex is busy.
    assert_eq!(
        // SAFETY: Live test storage is retained; opaque correlation cookies are never dereferenced.
        unsafe { acquire(root, &mut output, userdata) },
        -libc::EAGAIN
    );
    assert!(output.is_null());
    drop(locked);
}

#[test]
fn absent_userdata_clears_output_and_never_resolves_an_implicit_native_fallback() {
    let mut output = std::ptr::dangling_mut::<c_void>();
    // SAFETY: Valid output is provided; null userdata is refused before dereference.
    assert_eq!(
        // SAFETY: Live test storage is retained; opaque correlation cookies are never dereferenced.
        unsafe { acquire(std::ptr::null(), &mut output, std::ptr::null_mut()) },
        -libc::EINVAL
    );
    assert!(output.is_null());
    assert!(super::super::root_epoch_abi::resolve_register_root_epoch().is_none());
    assert_eq!(
        super::super::root_epoch_abi::RESOURCE_NATIVE_ROOT_EPOCH,
        1 << 20
    );
    assert_eq!(
        super::super::root_epoch_abi::CALLBACK_NATIVE_ROOT_EPOCH,
        1 << 17
    );
    assert_eq!(
        std::mem::size_of::<super::super::root_epoch_abi::NativeRootEpochManifest>(),
        264
    );
}
