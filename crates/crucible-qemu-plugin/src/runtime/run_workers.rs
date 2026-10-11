//! Startup of the original RUN and teardown workers after mapped boot release.
//!
//! This module owns thread creation and source-root RUN custody installation.
//! It preserves the original endpoint, typed lifecycle and worker gates; failed
//! irreversible startup uses the mandatory runtime fatal policy. Registration,
//! worker creation and retained socket prefixes do not grant native permission.

use std::os::unix::net::UnixStream;
use std::sync::Arc;

use super::teardown_channel::{TeardownReceiver, TeardownSender};

use crucible_protocol::ControlLifecycleStream;

use super::{
    PluginArgs, PluginRuntimeInstallError, PostRegistrationFatalPolicy, QemuRequestShutdownFn,
    RequiredOwnedCallbacksRegistered, native_run_control, run_control_reader,
    run_runtime_thread_fail_loud, run_teardown_worker,
};

/// Starts the two original workers in their existing order after RUN entry.
///
/// Startup failure retains irreversible runtime ownership and invokes the
/// mandatory fatal policy; this function never substitutes worker admission.
pub(super) fn start<F: PostRegistrationFatalPolicy>(
    args: &PluginArgs,
    callbacks_registered: &RequiredOwnedCallbacksRegistered,
    control_stream: ControlLifecycleStream<UnixStream>,
    teardown_receiver: TeardownReceiver,
    teardown_sender: &TeardownSender,
    request_shutdown: QemuRequestShutdownFn,
    fatal_policy: &F,
) -> (std::thread::JoinHandle<()>, std::thread::JoinHandle<()>) {
    let teardown_handle = match callbacks_registered.control_teardown_handle(args.slot()) {
        Ok(handle) => handle,
        Err(error) => fatal_policy.terminate(error),
    };
    let teardown_workers = callbacks_registered.worker_quiescence();
    let teardown_worker = match std::thread::Builder::new()
        .name(String::from("crucible-teardown"))
        .spawn(move || {
            run_runtime_thread_fail_loud("teardown worker", || {
                run_teardown_worker(
                    teardown_receiver,
                    teardown_handle,
                    request_shutdown,
                    teardown_workers,
                );
            });
        }) {
        Ok(worker) => worker,
        Err(source) => {
            fatal_policy.terminate(PluginRuntimeInstallError::TeardownWorkerSpawn { source })
        }
    };

    let reader_sender = teardown_sender.clone();
    let control_workers = callbacks_registered.worker_quiescence();
    enum RunControlOwner {
        FixedRoot(Arc<native_run_control::NativeRunControlCustody>),
        Legacy(ControlLifecycleStream<UnixStream>),
    }

    let control_owner = if let Some(owner) = crate::native_node_control::registered_owner()
        && owner.registered_root_commitment().is_some()
    {
        let preparation = native_run_control::NativeRunControlCustody::prepare(control_stream);
        if owner
            .install_root_run_control(Arc::clone(&preparation.owner), &control_workers)
            .is_err()
        {
            fatal_policy.terminate(PluginRuntimeInstallError::RootRunControl {
                source: std::io::Error::other("original ROOT RUN owner could not be retained"),
            });
        }
        if let Err(error) = preparation.status {
            fatal_policy.terminate(PluginRuntimeInstallError::RootRunControl {
                source: std::io::Error::other(error),
            });
        }
        RunControlOwner::FixedRoot(preparation.owner)
    } else {
        RunControlOwner::Legacy(control_stream)
    };

    let control_reader = match std::thread::Builder::new()
        .name(String::from("crucible-run-control"))
        .spawn(move || {
            run_runtime_thread_fail_loud("RUN control reader", || {
                let _delivered = match control_owner {
                    RunControlOwner::FixedRoot(custody) => {
                        native_run_control::run_reader(custody, reader_sender, control_workers)
                    }
                    RunControlOwner::Legacy(control) => {
                        run_control_reader(control, reader_sender, control_workers)
                    }
                };
            });
        }) {
        Ok(reader) => reader,
        Err(source) => {
            fatal_policy.terminate(PluginRuntimeInstallError::ControlWorkerSpawn { source })
        }
    };

    (control_reader, teardown_worker)
}
