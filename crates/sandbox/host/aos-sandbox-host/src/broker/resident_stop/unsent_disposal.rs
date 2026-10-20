//! Disposes a genuinely completed resident Stop whose response was not Sent.
//!
//! Current Control pays the new history comparison and both real Source
//! bookends. The old positive native graph then follows the same physical
//! owning-drop path as ordinary Stop. No effect, deadline, receipt or old
//! authenticated outcome is renewed, and fresh Host3 census remains required.

use super::*;

pub(super) struct UnsentStopDisposalOriginalV1 {
    before: Option<Result<()>>,
    history: Option<Result<()>>,
    after: Option<Result<()>>,
    source_disposal: Option<Result<()>>,
}

impl UnsentStopDisposalOriginalV1 {
    fn new() -> Self {
        Self {
            before: None,
            history: None,
            after: None,
            source_disposal: None,
        }
    }

    pub(super) fn require_positive_v1(&self) -> Result<()> {
        if !matches!(self.before, Some(Ok(())))
            || !matches!(self.history, Some(Ok(())))
            || !matches!(self.after, Some(Ok(())))
            || !matches!(self.source_disposal, Some(Ok(())))
        {
            return Err(HostError::Fence(
                "unsent Stop disposal retains an incomplete paid interval",
            ));
        }
        Ok(())
    }

    pub(super) fn failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        error(&self.before)
            .or_else(|| error(&self.history))
            .or_else(|| error(&self.after))
            .or_else(|| error(&self.source_disposal))
    }

    pub(super) fn format_failure_v1(
        &self,
        component: &crate::plan::HostComponentControlStartupV2,
        formatter: &mut std::fmt::Formatter<'_>,
    ) -> Option<std::fmt::Result> {
        if matches!(self.before, Some(Err(_))) {
            return Some(std::fmt::Display::fmt(component.failure(), formatter));
        }
        if let Some(Err(cause)) = self.history.as_ref() {
            return Some(std::fmt::Display::fmt(cause, formatter));
        }
        if matches!(self.after, Some(Err(_))) || matches!(self.source_disposal, Some(Err(_))) {
            return Some(std::fmt::Display::fmt(component.failure(), formatter));
        }
        None
    }
}

impl<C: HostCatalog, S: HostStateStore, W: HostWorker> HostBroker<C, S, W> {
    pub(crate) async fn retire_completed_unsent_stopped_agent_v1(
        &mut self,
        incoming: &mut Option<HostAgentLiveSessionV1>,
    ) -> Result<bool> {
        let Some(source) = self.launch_original.as_ref().cloned() else {
            return Ok(false);
        };
        let stop = {
            let source = source
                .lock()
                .map_err(|_| HostError::Fence("unsent Stop Launch is poisoned"))?;
            let Some(stop) = source.resident_stop.as_ref().cloned() else {
                return Ok(false);
            };
            stop
        };
        let authenticated = stop.lock()
            .map_err(|_| HostError::Fence("unsent Stop original is poisoned"))?
            .authenticated_sent;
        if authenticated {
            // The already-authenticated owning callback may itself have been
            // interrupted before Services moved the actual Agent. Resume that
            // existing physical closure; it creates no new observation answer.
            drop(stop);
            drop(source);
            return self.retire_authenticated_stopped_agent_v4(incoming);
        }
        {
            let original = stop
                .lock()
                .map_err(|_| HostError::Fence("unsent Stop original is poisoned"))?;
            if original.unsent_disposal.is_some()
                || original.disposal_error.is_some()
                || original.capture_stage.is_some()
                || original.capture_first.is_some()
                || original.retained_agent.is_some()
                || !matches!(original.sdk_terminal, Some(Ok(())))
                || original.native_completed.is_none()
            {
                return Err(HostError::Fence(
                    "unsent Stop lacks a wholly positive native owner",
                ));
            }
            original.require_terminal_positive_v4()?;
        }

        let component = self
            .component_control
            .as_ref()
            .cloned()
            .ok_or(HostError::Fence("unsent Stop actual Control is absent"))?;
        let mut component = component
            .lock()
            .map_err(|_| HostError::Fence("unsent Stop actual Control is poisoned"))?;
        let mut original = stop
            .lock()
            .map_err(|_| HostError::Fence("unsent Stop original is poisoned"))?;
        let launch = original.source_launch;
        let launch_binding = crate::plan::HostExecutionRequestBindingV2 {
            id: launch.0,
            session: launch.1,
            signed: launch.2,
        };
        // Reuse the complete protected-history invoice, including the canonical
        // MAC traversal and model overlaps. These are conservative paid bounds;
        // no snapshot IO or native census is substituted by the in-memory read.
        let extra = std::mem::size_of::<UnsentStopDisposalOriginalV1>()
            .checked_mul(2)
            .and_then(|bytes| {
                bytes.checked_add(std::mem::size_of::<sha2::Sha256>().checked_mul(2)?)
            })
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(HostError::ResourceExhausted)?;
        let complete = self
            .state
            .native_inventory_history_receiving_demand_v6()
            .ok_or(HostError::ResourceExhausted)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, extra))
            .map_err(|_| HostError::ResourceExhausted)?;
        let mut receiving = component.begin_unsent_stop_disposal_v1(
            launch_binding,
            original
                .native_completed
                .as_ref()
                .ok_or(HostError::AgentLaunchQuarantined)?,
            complete,
        )?;
        original.unsent_disposal = Some(UnsentStopDisposalOriginalV1::new());
        let before = receiving.observe_before_once_v5().await;
        let before_positive = before.is_ok();
        original
            .unsent_disposal
            .as_mut()
            .ok_or(HostError::AgentLaunchQuarantined)?
            .before = Some(before);
        if before_positive {
            let history = self.require_unsent_stop_history_v1(&source, &original);
            original
                .unsent_disposal
                .as_mut()
                .ok_or(HostError::AgentLaunchQuarantined)?
                .history = Some(history);
        }
        // Always reach the independently paid Source after, including on a
        // failed before or MAC/history comparison. Failed native owners stay.
        let after = receiving.observe_after_once_v5().await;
        original
            .unsent_disposal
            .as_mut()
            .ok_or(HostError::AgentLaunchQuarantined)?
            .after = Some(after);
        let positive = original.unsent_disposal.as_ref().is_some_and(|attempt| {
            matches!(attempt.before, Some(Ok(())))
                && matches!(attempt.history, Some(Ok(())))
                && matches!(attempt.after, Some(Ok(())))
        });
        if positive {
            let disposed = receiving.dispose_positive_once_v5();
            original
                .unsent_disposal
                .as_mut()
                .ok_or(HostError::AgentLaunchQuarantined)?
                .source_disposal = Some(disposed);
        }
        original
            .unsent_disposal
            .as_ref()
            .ok_or(HostError::AgentLaunchQuarantined)?
            .require_positive_v1()?;
        drop(receiving);
        drop(original);
        drop(component);
        // The local Arc clones must leave before the same exclusive native
        // disposer verifies and physically drops its unique old graph.
        drop(stop);
        drop(source);
        self.retire_stopped_agent_with_failure_v1(
            incoming,
            StopDisposalPurposeV1::UnsentNativePositive,
        )
    }

    fn require_unsent_stop_history_v1(
        &self,
        source: &Arc<Mutex<HostLaunchOriginalV2>>,
        original: &HostResidentStopOriginalV4,
    ) -> Result<()> {
        let source = source
            .lock()
            .map_err(|_| HostError::Fence("unsent Stop Launch is poisoned"))?;
        let stage = original
            .stage
            .lock()
            .map_err(|_| HostError::Fence("unsent Stop Stage is poisoned"))?;
        source.require_unsent_stop_launch_v1(original.source_launch)?;
        if stage.first.is_some()
            || stage.primary.is_some()
            || !matches!(stage.before, Some(Ok(())))
            || !matches!(stage.after, Some(Ok(())))
            || !matches!(stage.native_finish, Some(Ok(())))
        {
            return Err(HostError::Fence(
                "unsent Stop differs from its positive native Stage",
            ));
        }
        let effect = self
            .state
            .effect(&stage.request.0)
            .ok_or(HostError::Fence("unsent Stop has no durable effect"))?;
        let effect = self.authority.open_effect(&stage.request.0, effect)?;
        if effect.status() != aos_sandbox_broker::BrokerEffectStatusV1::Complete
            || effect.transport_request_digest().as_bytes() != &stage.transport_body_digest_v1()
        {
            return Err(HostError::Fence(
                "unsent Stop differs from its exact durable Complete",
            ));
        }
        let (boot, fence, anchor) = source.namespace_scope_v4.ok_or(HostError::Fence(
            "unsent Stop lacks the actual old namespace",
        ))?;
        let scope =
            aos_sandbox_protocol::host_stopped_namespace::HostStoppedNamespaceDataV4::from_data_v4(
                boot,
                fence,
                anchor,
                source.request,
                stage.request,
            )?;
        self.state
            .historical_namespace_candidate_v7(&self.authority)?
            .require_completed_resident_stop_v1(&scope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_history_and_later_after_failure_never_replace_the_first_cause() {
        let mut original = UnsentStopDisposalOriginalV1::new();
        original.before = Some(Err(HostError::Fence("original before failure")));
        original.after = Some(Err(HostError::Fence(
            "later independently owed after failure",
        )));

        assert!(original.require_positive_v1().is_err());
        assert_eq!(
            original.failure_v1().unwrap().to_string(),
            HostError::Fence("original before failure").to_string(),
        );
        assert!(original.history.is_none());
        assert!(original.source_disposal.is_none());
    }
}
