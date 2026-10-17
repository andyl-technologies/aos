//! Closed admitted copies and linear merges of scheduler output event storage.

use super::*;
use crate::EngineError;
use event_log::owned_copy::{
    copy_entries_admitted, copy_scheduled, copy_scheduler_node, copy_string, copy_vec,
    reserve_array,
};

impl SchedulerEventLogAppend {
    /// Copies its fields under an independent child of the retained original account.
    ///
    /// # Errors
    /// Refuses original admission or allocation failure before publishing a copy.
    pub fn try_clone_admitted(&self) -> Result<Self, EngineError> {
        let _original = self.event_log_custody.enter_decode_scope();
        let input = crate::owned_decode::require_current_custody().map_err(admission)?;
        let bank = crate::owned_decode::require_current_child_budget().map_err(admission)?;
        let _scope = bank.enter();
        Ok(Self {
            entries: copy_entries_admitted(&self.entries)?,
            segment_bytes: copy_vec(&self.segment_bytes)?,
            segment_text: copy_string(&self.segment_text)?,
            segment_hash: self.segment_hash,
            offset: self.offset,
            event_log_custody: EventLogOutputCustody::from_budget(&bank, input)?
                .combine(&self.event_log_custody)?,
        })
    }
}

impl QuantumOutcome {
    pub(crate) fn into_shared_admitted(self) -> Result<Arc<Self>, EngineError> {
        let _scope = self.event_log_custody.enter_decode_scope();
        crate::owned_decode::charge_bytes(
            (std::mem::size_of::<Self>() + 2 * std::mem::size_of::<usize>()) as u64,
        )
        .map_err(admission)?;
        Ok(Arc::new(self))
    }

    /// Copies concrete owned fields under the retained original resource authority.
    ///
    /// # Errors
    /// Refuses original admission or allocation failure before publishing a copy.
    pub fn try_clone_admitted(&self) -> Result<Self, EngineError> {
        let _original = self.event_log_custody.enter_decode_scope();
        let input = crate::owned_decode::require_current_custody().map_err(admission)?;
        let bank = crate::owned_decode::require_current_child_budget().map_err(admission)?;
        let _scope = bank.enter();
        let mut resolved_events = reserve_array(self.resolved_events.len())?;
        for event in &self.resolved_events {
            resolved_events.push(copy_scheduled(event)?);
        }
        let mut decisions = reserve_array(self.decisions.len())?;
        for decision in &self.decisions {
            decisions.push(decision.try_clone_admitted()?);
        }
        let mut discovered_choices = reserve_array(self.discovered_choices.len())?;
        for choice in &self.discovered_choices {
            discovered_choices.push(choice.clone_admitted().map_err(|source| match source {
                crucible_campaign::CampaignCodecError::DecodeAdmission(source) => admission(source),
                source => admission(crate::owned_decode::DecodeAdmissionError::new(source)),
            })?);
        }
        Ok(Self {
            configuration: self.configuration.try_clone_admitted()?,
            frontier: self.frontier,
            advanced_node: self
                .advanced_node
                .as_ref()
                .map(copy_scheduler_node)
                .transpose()?,
            resolved_events,
            decisions,
            discovered_choices,
            event_log_entries: copy_entries_admitted(&self.event_log_entries)?,
            event_log_segment_bytes: copy_vec(&self.event_log_segment_bytes)?,
            event_log_segment_text: copy_string(&self.event_log_segment_text)?,
            event_log_segment_hash: self.event_log_segment_hash,
            event_log_offset: self.event_log_offset,
            scheduler_quiescence: self
                .scheduler_quiescence
                .as_ref()
                .map(copy_quiescence)
                .transpose()?,
            event_log_custody: EventLogOutputCustody::from_budget(&bank, input)?
                .combine(&self.event_log_custody)?,
        })
    }

    /// Moves an admitted append into this output after reserving its entry table.
    ///
    /// # Errors
    /// Refuses original admission before changing event entries or segment fields.
    pub fn merge_event_log_append(
        &mut self,
        append: SchedulerEventLogAppend,
    ) -> Result<(), EngineError> {
        let custody = self.event_log_custody.combine(&append.event_log_custody)?;
        // Capacity growth survives a later refusal, so publish only operational
        // custody before reserving. Semantic fields remain unchanged on refusal.
        self.event_log_custody = custody;
        self.event_log_custody
            .reserve_entries(&mut self.event_log_entries, append.entries.len())?;
        self.event_log_entries.extend(append.entries);
        self.event_log_segment_bytes = append.segment_bytes;
        self.event_log_segment_text = append.segment_text;
        self.event_log_segment_hash = append.segment_hash;
        self.event_log_offset = append.offset;
        Ok(())
    }
}

fn admission(source: crate::owned_decode::DecodeAdmissionError) -> EngineError {
    EngineError::ArtifactDecodeAdmission { source }
}

fn copy_quiescence(source: &SchedulerQuiescence) -> Result<SchedulerQuiescence, EngineError> {
    use SchedulerQuiescenceBlocker as B;
    let mut blockers = reserve_array(source.blockers.len())?;
    for blocker in &source.blockers {
        blockers.push(match blocker {
            B::RunnableNode { node } => B::RunnableNode {
                node: copy_scheduler_node(node)?,
            },
            B::ActiveVcpu { node, vcpu } => B::ActiveVcpu {
                node: copy_scheduler_node(node)?,
                vcpu: *vcpu,
            },
            B::PendingVcpuTimer {
                node,
                vcpu,
                deadline,
            } => B::PendingVcpuTimer {
                node: copy_scheduler_node(node)?,
                vcpu: *vcpu,
                deadline: *deadline,
            },
            B::PendingVcpuInput { node, vcpu } => B::PendingVcpuInput {
                node: copy_scheduler_node(node)?,
                vcpu: *vcpu,
            },
            B::PendingEvent { key } => B::PendingEvent {
                key: copy_key(key)?,
            },
            B::PendingPreemption { decision } => B::PendingPreemption {
                decision: PreemptionDecision {
                    node: event_log::owned_copy::copy_node(&decision.node)?,
                    at: decision.at,
                    kind: decision.kind.clone(),
                },
            },
            B::DeviceCompletionInFlight { target } => B::DeviceCompletionInFlight {
                target: event_log::owned_copy::copy_node(target)?,
            },
            B::PendingExactLocalEvent { node, event } => B::PendingExactLocalEvent {
                node: copy_scheduler_node(node)?,
                event: match event {
                    ExactLocalEvent::IoCompletion {
                        virtual_time,
                        sub_node,
                    } => ExactLocalEvent::IoCompletion {
                        virtual_time: *virtual_time,
                        sub_node: copy_scheduler_node(sub_node)?,
                    },
                    _ => event.clone(),
                },
            },
            // These closed variants contain only integer coordinates and unit enums.
            B::PendingGlobalEvaluation { .. }
            | B::PendingControl { .. }
            | B::PendingTopologyChange { .. } => blocker.clone(),
        });
    }
    Ok(SchedulerQuiescence { blockers })
}

fn copy_key(source: &ScheduledEventKey) -> Result<ScheduledEventKey, EngineError> {
    Ok(ScheduledEventKey {
        timeline: SharedTimelineKey {
            virtual_time: source.timeline.virtual_time,
            node: copy_scheduler_node(&source.timeline.node)?,
            sequence: source.timeline.sequence,
        },
        producer: copy_scheduler_node(&source.producer)?,
    })
}
