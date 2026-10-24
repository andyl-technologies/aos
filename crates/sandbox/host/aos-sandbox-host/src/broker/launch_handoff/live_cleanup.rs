//! Lends the actual resident Launch to finite fresh cleanup work.
//!
//! The native graph remains owned and financially charged while current
//! Control pays new reads and effects. No old request or deadline is renewed.

use super::*;

/// Borrows the actual resident native Launch and its completed Capture owner.
///
/// The closed constructor checks the retained native graph. This is neither a
/// reconstructed Launch nor authorization to reuse its original request/D.
pub(crate) struct HostLiveCleanupParentV1<'source> {
    source: &'source HostLaunchOriginalV2,
    capture: Option<(
        crate::plan::HostExecutionRequestBindingV2,
        crate::plan::HostExecutionRequestBindingV2,
    )>,
}

/// Retains the same actual resident Launch across a cold financial exchange.
pub(crate) struct HostLiveCleanupOwnerV1 {
    source: Arc<Mutex<HostLaunchOriginalV2>>,
}

impl HostLiveCleanupOwnerV1 {
    pub(in crate::broker) fn new_v1(source: Arc<Mutex<HostLaunchOriginalV2>>) -> Self {
        Self { source }
    }

    /// Lends current Control while retaining this exact resident native graph.
    ///
    /// # Errors
    /// Refuses a changed/borrowed graph, closed Control or insufficient funding.
    pub(crate) fn begin_inventory_v1<'original>(
        &self,
        control: &'original mut crate::plan::HostComponentControlStartupV2,
        complete: ResourceVector,
        selected: &mut bool,
    ) -> Result<crate::plan::HostControlPreparationReceivingV5<'original>> {
        let held = self
            .source
            .lock()
            .map_err(|_| HostError::AgentLaunchQuarantined)?;
        control.begin_live_native_inventory_entry_v1(
            complete,
            selected,
            &held.borrow_live_cleanup_parent_v1()?,
        )
    }
}

impl HostLiveCleanupParentV1<'_> {
    /// Returns comparison DATA from the actual typed resident Launch namespace.
    ///
    /// # Errors
    /// Refuses missing or inconsistent native Launch association.
    pub(crate) fn namespace_scope_v1(
        &self,
    ) -> Result<aos_sandbox_protocol::host_stopped_namespace::HostLaunchNamespaceDataV1> {
        let (boot, fence, anchor) = self.source.namespace_scope_v4.ok_or(HostError::Fence(
            "resident cleanup lacks its actual Launch namespace",
        ))?;
        aos_sandbox_protocol::host_stopped_namespace::HostLaunchNamespaceDataV1::from_data_v1(
            boot,
            fence,
            anchor,
            self.source.request,
        )
        .map_err(Into::into)
    }

    /// Returns the original finite financial bindings without renewing them.
    pub(crate) fn original_bindings_v1(
        &self,
    ) -> (
        crate::plan::HostExecutionRequestBindingV2,
        Option<(
            crate::plan::HostExecutionRequestBindingV2,
            crate::plan::HostExecutionRequestBindingV2,
        )>,
    ) {
        let (id, session, signed) = self.source.request;
        (
            crate::plan::HostExecutionRequestBindingV2 {
                id,
                session,
                signed,
            },
            self.capture,
        )
    }

    /// Borrows the genuine earlier acquisition-disposal native original.
    ///
    /// # Errors
    /// Refuses a missing resident original; DATA cannot replace it.
    pub(crate) fn resident_native_v1(&self) -> Result<&HostLaunchResidentNativeV4> {
        self.source
            .resident_native
            .as_ref()
            .ok_or(HostError::AgentLaunchQuarantined)
    }
}

impl HostLaunchOriginalV2 {
    /// Borrows an idle native Launch and optional wholly completed Capture.
    ///
    /// # Errors
    /// Refuses failed, incomplete, aliased or independently occupied originals.
    pub(in crate::broker) fn borrow_live_cleanup_parent_v1(
        &self,
    ) -> Result<HostLiveCleanupParentV1<'_>> {
        if !self.authenticated_sent
            || self.first.is_some()
            || self.resident_stop.is_some()
            || self.next_execution.is_some()
            || self.stop_admission.is_some()
            || !self
                .resident_native
                .as_ref()
                .is_some_and(|native| native.request_identity_v4() == self.request)
        {
            return Err(HostError::Fence(
                "cleanup lacks the genuine idle resident Launch",
            ));
        }
        let capture = match self.capture.as_ref() {
            Some(capture) => {
                if capture.monitor_failed_data_v5() {
                    return Err(HostError::Fence(
                        "ambiguous Capture cannot lend live cleanup",
                    ));
                }
                let actual = capture.stage_for_terminal_disposal_v3();
                if Arc::strong_count(actual) != 1 {
                    return Err(HostError::Fence(
                        "cleanup Capture has another native borrower",
                    ));
                }
                let stage = actual
                    .lock()
                    .map_err(|_| HostError::Fence("cleanup Capture owner is poisoned"))?;
                stage.require_terminal_storage_disposal_v3()?;
                Some(capture.terminal_bindings_v3()?)
            }
            None => None,
        };
        Ok(HostLiveCleanupParentV1 {
            source: self,
            capture,
        })
    }
}

impl<C: HostCatalog, S: HostStateStore, W: HostWorker> HostBroker<C, S, W> {
    /// Selects only the actual retained Launch with its exact runtime owners.
    ///
    /// # Errors
    /// Refuses unrelated or incomplete native custody and mismatched runtime.
    pub(in crate::broker) fn live_cleanup_source_v1(
        &self,
    ) -> Result<Option<Arc<Mutex<HostLaunchOriginalV2>>>> {
        let Some(source) = self.launch_original.as_ref() else {
            return Ok(None);
        };
        if self.active_accepted_authorization.is_some()
            || self.argument_stages.iter().any(Option::is_some)
            || self.active_argument_writes.is_some()
            || self.active_launch_writes.is_some()
            || self.live_agent.is_some()
            || self.runtime_pins.len() != 1
            || self.observed_leaders.len() != 1
            || !self.live_limit_attempts.is_empty()
            || !self.fuse_workers.is_empty()
        {
            return Err(HostError::Fence(
                "live cleanup has unrelated native custody",
            ));
        }
        let held = source
            .lock()
            .map_err(|_| HostError::Fence("resident cleanup Launch is poisoned"))?;
        let parent = held.borrow_live_cleanup_parent_v1()?;
        let scope = parent.namespace_scope_v1()?;
        let (runtime, pins) = self
            .runtime_pins
            .first_key_value()
            .ok_or(HostError::AgentLaunchQuarantined)?;
        if *runtime != crate::worker::HostRuntimeIdentity::from(scope.fence_v1())
            || !self
                .observed_leaders
                .get(runtime)
                .is_some_and(|leader| leader.handle() == pins.supervisor.handle())
        {
            return Err(HostError::Fence(
                "live cleanup runtime owners differ from resident Launch",
            ));
        }
        Ok(Some(Arc::clone(source)))
    }
}
