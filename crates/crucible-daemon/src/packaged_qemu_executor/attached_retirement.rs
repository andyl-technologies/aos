//! Keeps active attached retirement custody in the existing permanent Main.
//!
//! The service thread borrows no actor cell while serving. Only its bounded
//! retirement steps use the cell; failed spawn and panic leave these same
//! owners reachable through Main's saved Cleanup route.

use super::*;
use crucible_linux_resource::host_services::process_birth::AuthenticatedNativeSlotPurpose;
use crucible_linux_resource::host_supervision::HostOperationGuard;

/// Keeps the existing attached retirement owners reachable from their Main.
pub struct RetainedAttachedRetirement {
    materializer: PackagedExactPinMaterializerOwner,
    source: Option<Box<dyn PackagedQemuHotForkSourceOwner>>,
    host: Option<SharedQemuAttemptHostResourceFactory<LinuxQemuAttemptHostResourceFactory>>,
    queue: Option<Arc<crate::lifecycle_cleanup::LifecycleCleanupQueue>>,
    completion: Arc<(Mutex<bool>, Condvar)>,
    post: Option<crucible_linux_resource::host_supervision::HostSupervisionError>,
    service_returned: bool,
    source_closed: bool,
    dispatcher_closed: bool,
}

impl std::fmt::Debug for RetainedAttachedRetirement {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RetainedAttachedRetirement")
            .field("service_returned", &self.service_returned)
            .field("source_closed", &self.source_closed)
            .field("dispatcher_closed", &self.dispatcher_closed)
            .finish_non_exhaustive()
    }
}

impl RetainedAttachedRetirement {
    pub(crate) fn mark_service_returned(&mut self) {
        self.service_returned = true;
    }

    pub(crate) fn post_refusal(
        &self,
    ) -> Option<crucible_linux_resource::host_supervision::HostSupervisionError> {
        self.post
    }

    pub(crate) fn physically_retired(&self) -> bool {
        self.dispatcher_closed
    }

    pub(crate) fn retry(
        &mut self,
        main: &Arc<AuthenticatedNativeSlotPurpose>,
        original: &HostOperationGuard,
    ) -> Result<(), PackagedQemuExecutorJoinError> {
        if !self.service_returned {
            // A panic or failed post-service marker cannot hide actual thread
            // exit. The same completion header is retained, never synthesized.
            self.service_returned = self.completion.0.try_lock().is_ok_and(|done| *done);
            if !self.service_returned {
                return Err(PackagedQemuExecutorJoinError::AttachedPending);
            }
        }
        if self.dispatcher_closed {
            return Ok(());
        }
        let mut first = crate::campaign_process::try_retire_executor_controls(main, original).err();
        if let Some(post) = first.as_ref().and_then(|error| error.original_post()) {
            self.post.get_or_insert(post);
        }
        if first
            .as_ref()
            .is_some_and(|error| !error.physically_closed())
        {
            return Err(PackagedQemuExecutorJoinError::MainControls(
                first
                    .take()
                    .ok_or(PackagedQemuExecutorJoinError::AttachedPending)?,
            ));
        }
        // All actual W bodies are gone before stopping checkpoint materialization.
        let materializer = self.materializer.try_retire_original(original);
        let source = if self.source_closed {
            Ok(())
        } else {
            self.source
                .as_ref()
                .map(|source| source.orderly_shutdown())
                .unwrap_or(Ok(()))
        };
        if source.is_ok() {
            self.source_closed = true;
        }
        let after = crate::campaign_process::try_retire_executor_controls(main, original);
        let controls_closed = after
            .as_ref()
            .err()
            .is_none_or(|error| error.physically_closed());
        if let Err(error) = after {
            first.get_or_insert(error);
        }
        let lifecycle = self
            .queue
            .as_ref()
            .map(|queue| {
                let work = queue.retry_pending();
                let empty = queue.verify_empty();
                work.and(empty)
            })
            .unwrap_or(Ok(()));
        if let Err(post) = original.wait_slice() {
            self.post.get_or_insert(post);
        }
        let ready = self.materializer.physically_retired()
            && self.source_closed
            && controls_closed
            && lifecycle.is_ok();
        // Preserve initiating component errors while still checking all peers.
        let report =
            materializer
                .map_err(PackagedQemuExecutorJoinError::ExactPinMaterializerRetirement)
                .and(source.map_err(|error| {
                    PackagedQemuExecutorJoinError::HotForkSources(Box::new(error))
                }))
                .and(lifecycle.map_err(PackagedQemuExecutorJoinError::LifecycleCleanup))
                .and(first.map_or(Ok(()), |error| {
                    Err(PackagedQemuExecutorJoinError::MainControls(error))
                }));
        if !ready {
            return report.and(Err(PackagedQemuExecutorJoinError::AttachedPending));
        }
        original
            .wait_slice()
            .map_err(|error| PackagedQemuExecutorJoinError::MainOriginal(error))?;
        let dispatcher = self
            .host
            .as_ref()
            .ok_or(PackagedQemuExecutorJoinError::OwnerUnavailable)?
            .finish_target_dispatcher()
            .map_err(PackagedQemuExecutorJoinError::TargetDispatcher);
        if dispatcher.is_ok() {
            self.dispatcher_closed = true;
        }
        let post = original.wait_slice();
        if let Err(error) = post {
            self.post.get_or_insert(error);
        }
        report.and(dispatcher).and(
            post.map(|_| ())
                .map_err(PackagedQemuExecutorJoinError::MainOriginal),
        )
    }
}

impl AttachedPackagedQemuExecutor {
    pub(super) fn start_main(
        service: PackagedQemuExecutor,
        main: Arc<AuthenticatedNativeSlotPurpose>,
    ) -> Result<Self, PackagedQemuExecutorStartError> {
        let PackagedQemuExecutor {
            guarded_state,
            host_operational_registry,
            repository_identity,
            admitted_scenarios,
            endpoint,
            service,
            exact_pin_materializer,
            operational_status,
            hot_fork_owner,
            hot_fork_retention,
            campaign_debug,
            original_physically_retired: _,
            source_physically_retired: _,
        } = service;
        let shutdown = service.shutdown_handle();
        let completion = Arc::new((Mutex::new(false), Condvar::new()));
        let body = RetainedAttachedRetirement {
            materializer: exact_pin_materializer,
            source: hot_fork_owner,
            host: guarded_state.host.clone(),
            queue: guarded_state.lifecycle_cleanup.clone(),
            completion: Arc::clone(&completion),
            post: None,
            service_returned: false,
            source_closed: false,
            dispatcher_closed: false,
        };
        crate::campaign_process::install_attached_retirement(&main, body).map_err(
            |(owner, reason)| PackagedQemuExecutorStartError::RetirementCustody {
                reason,
                owner: Mutex::new(Some(owner)),
            },
        )?;
        if let Err(first) = crate::campaign_process::verify_attached_start(&main) {
            // Custody cannot be revoked by this admission refusal. No service
            // thread was created; disposing its unserved listener requests the
            // same anchored workers to stop while Main keeps materialization.
            drop(service);
            match completion.0.lock() {
                Ok(mut done) => *done = true,
                Err(poison) => *poison.into_inner() = true,
            }
            completion.1.notify_all();
            let mark = crate::campaign_process::mark_attached_returned(&main, Some(first));
            return Err(PackagedQemuExecutorStartError::Retained {
                report: match mark {
                    Ok(()) => crate::campaign_process::retained_attached_report(&main),
                    Err(error) => error,
                },
            });
        }
        let thread_completion = Arc::clone(&completion);
        let thread_main = Arc::clone(&main);
        let thread = thread::Builder::new()
            .name(String::from("crucible-packaged-qemu-executor"))
            .spawn(move || {
                let _completion = PackagedQemuExecutorCompletionGuard(thread_completion);
                // Main owns the materializer and native aliases before this call;
                // its cell is not locked during listener/worker execution.
                let result = service.serve();
                let report = match result {
                    Ok(report) => {
                        crate::campaign_process::mark_attached_returned(&thread_main, None)?;
                        Some(report)
                    }
                    Err(error) => {
                        crate::campaign_process::mark_attached_returned(
                            &thread_main,
                            Some(PackagedQemuExecutorJoinError::Service(error)),
                        )?;
                        None
                    }
                };
                crate::campaign_process::retry_attached_retirement(&thread_main)?;
                report.ok_or(PackagedQemuExecutorJoinError::OwnerUnavailable)
            });
        let thread = match thread {
            Ok(thread) => thread,
            Err(error) => {
                // Failed spawn has returned after disposing its service closure.
                match completion.0.lock() {
                    Ok(mut done) => *done = true,
                    Err(poison) => *poison.into_inner() = true,
                }
                completion.1.notify_all();
                // Failed spawn drops only the service closure. Its W directory
                // and this exact materializer/native body already belong to Main.
                let mark = crate::campaign_process::mark_attached_returned(
                    &main,
                    Some(PackagedQemuExecutorJoinError::OwnerSpawn(error)),
                );
                let report = match mark {
                    Ok(()) => crate::campaign_process::retained_attached_report(&main),
                    Err(report) => report,
                };
                return Err(PackagedQemuExecutorStartError::Retained { report });
            }
        };
        Ok(Self {
            guarded_state,
            host_operational_registry,
            repository_identity,
            admitted_scenarios,
            endpoint,
            operational_status,
            hot_fork_retention,
            campaign_debug,
            shutdown,
            completion,
            thread: Some(thread),
        })
    }
}

impl PackagedQemuExecutorStartError {
    /// Retries only publication of the same preexisting failed-start body.
    ///
    /// No service thread is created, and no Original is entered by this handoff.
    ///
    /// # Errors
    /// Preserves the same owner in this error if its Main cell remains occupied,
    /// poisoned or foreign. The body is never replaced or silently discarded.
    pub(crate) fn retry_retirement_retention(
        &mut self,
        main: &Arc<AuthenticatedNativeSlotPurpose>,
    ) -> Result<(), &'static str> {
        let Self::RetirementCustody { owner, .. } = self else {
            return Err("start failure has no returned custody body");
        };
        let slot = owner.get_mut().map_err(|_| "start custody is poisoned")?;
        let Some(mut body) = slot.take() else {
            return Ok(());
        };
        // This error is returned only before spawn. Its unserved service has
        // already dropped; the same W directory still owns every worker.
        body.mark_service_returned();
        match crate::campaign_process::install_attached_retirement(main, body) {
            Ok(()) => Ok(()),
            Err((body, reason)) => {
                *slot = Some(body);
                Err(reason)
            }
        }
    }
}
