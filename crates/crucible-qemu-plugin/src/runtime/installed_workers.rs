//! Startup of the existing installed RUN and teardown workers.
//!
//! The ordinary path preserves its original sockets and admission gates. The
//! explicit local-owner path retains those same allocations before publication
//! and source self-enrollment. Neither worker startup nor source registration
//! grants execution, root closure or capture authority.

use std::os::unix::net::UnixStream;
use std::sync::Arc;

use super::teardown_channel::{TeardownReceiver, TeardownSender};

use crucible_protocol::ControlLifecycleStream;

use super::installed_endpoint_owner;
use super::installed_teardown::{self, run_installed_teardown_worker};
use super::native_run_control;
use super::{
    PluginArgs, PluginRuntimeInstallError, PostRegistrationFatalPolicy, QemuRequestShutdownFn,
    RequiredOwnedCallbacksRegistered, emit_control_worker_diagnostic, run_control_reader,
    run_runtime_thread_fail_loud, run_teardown_worker,
};

/// Starts each original worker once, after installation's manifest and RUN barrier.
///
/// Irreversible failure retains original runtime custody and uses the mandatory
/// process fatal policy. The installer never waits for source worker enrollment.
pub(super) fn start<F: PostRegistrationFatalPolicy>(
    args: &PluginArgs,
    callbacks_registered: &RequiredOwnedCallbacksRegistered,
    control_stream: ControlLifecycleStream<UnixStream>,
    teardown_receiver: TeardownReceiver,
    teardown_sender: &TeardownSender,
    request_shutdown: QemuRequestShutdownFn,
    fatal_policy: &F,
) -> (std::thread::JoinHandle<()>, std::thread::JoinHandle<()>) {
    if !args
        .native_node_control()
        .is_some_and(|config| config.endpoint_owner_version().is_some())
    {
        return super::run_workers::start(
            args,
            callbacks_registered,
            control_stream,
            teardown_receiver,
            teardown_sender,
            request_shutdown,
            fatal_policy,
        );
    }

    let teardown_handle = match callbacks_registered.control_teardown_handle(args.slot()) {
        Ok(handle) => handle,
        Err(error) => fatal_policy.terminate(error),
    };
    let teardown_workers = callbacks_registered.worker_quiescence();
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
    let endpoint_selected = args
        .native_node_control()
        .is_some_and(|config| config.endpoint_owner_version().is_some());
    let (teardown_mailbox, legacy_teardown_receiver) = if endpoint_selected {
        (
            Some(installed_teardown::InstalledTeardownMailbox::new(
                teardown_receiver,
            )),
            None,
        )
    } else {
        (None, Some(teardown_receiver))
    };
    let installed_endpoint = if let Some(mailbox) = &teardown_mailbox {
        let RunControlOwner::FixedRoot(run) = &control_owner else {
            fatal_policy.terminate(PluginRuntimeInstallError::InstalledEndpointOwner {
                status: -libc::ESTALE,
            });
        };
        match installed_endpoint_owner::InstalledEndpointCustody::install(
            callbacks_registered.state.as_ref().get_ref(),
            Arc::clone(run),
            Arc::clone(mailbox),
        ) {
            Ok(owner) => Some(owner),
            Err(status) => {
                fatal_policy.terminate(PluginRuntimeInstallError::InstalledEndpointOwner { status })
            }
        }
    } else {
        None
    };
    if let (Some(endpoint), Some(effect)) = (
        &installed_endpoint,
        crate::native_node_control::registered_owner().and_then(|owner| owner.effect.as_ref()),
    ) && effect
        .install(
            callbacks_registered.state.as_ref().get_ref(),
            Arc::clone(endpoint),
        )
        .is_err()
    {
        fatal_policy.terminate(PluginRuntimeInstallError::InstalledEndpointOwner {
            status: -libc::ESTALE,
        });
    }
    if let (Some(endpoint), Some(prefix)) = (
        &installed_endpoint,
        crate::native_node_control::registered_owner().and_then(|owner| owner.prefix.as_ref()),
    ) && prefix
        .install(
            callbacks_registered.state.as_ref().get_ref(),
            Arc::clone(endpoint),
        )
        .is_err()
    {
        fatal_policy.terminate(PluginRuntimeInstallError::InstalledEndpointOwner {
            status: -libc::ESTALE,
        });
    }

    let teardown_endpoint = installed_endpoint.as_ref().map(Arc::clone);
    let teardown_worker = match std::thread::Builder::new()
        .name(String::from("crucible-teardown"))
        .spawn(move || {
            run_runtime_thread_fail_loud("teardown worker", || {
                if let (Some(mailbox), Some(endpoint)) = (teardown_mailbox, teardown_endpoint) {
                    run_installed_teardown_worker(
                        mailbox,
                        endpoint,
                        teardown_handle,
                        request_shutdown,
                        teardown_workers,
                    );
                } else if let Some(receiver) = legacy_teardown_receiver {
                    run_teardown_worker(
                        receiver,
                        teardown_handle,
                        request_shutdown,
                        teardown_workers,
                    );
                }
            });
        }) {
        Ok(worker) => worker,
        Err(source) => {
            fatal_policy.terminate(PluginRuntimeInstallError::TeardownWorkerSpawn { source })
        }
    };
    let control_reader = match std::thread::Builder::new()
        .name(String::from("crucible-run-control"))
        .spawn(move || {
            run_runtime_thread_fail_loud("RUN control reader", || {
                let _delivered = match control_owner {
                    RunControlOwner::FixedRoot(custody) => {
                        if let Some(endpoint) = &installed_endpoint {
                            while !endpoint.enroll_run().unwrap_or_else(|status| {
                                emit_control_worker_diagnostic(&format!(
                                    "original RUN enrollment refused: {status}"
                                ));
                                std::process::abort();
                            }) {
                                std::thread::yield_now();
                            }
                        }
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
