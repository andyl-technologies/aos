//! Revalidates the live resources behind an interrupted transaction's receipts.
//!
//! The restoration stack retains independent repair intents while preserving
//! the primary dispatch. Earlier prerequisites can be restored after another
//! reboot without forgetting a suspended repair's original journal sequence.

use anyhow::{Result, ensure};
use aos_ability_plan::module_graph::{CheckedModuleGraph, Handler, Lifetime};

use super::{Activation, ActivationAdapter, Boundary, CancellationToken, Event, Observation};

impl Activation {
    pub(super) fn restore_completed_prefix(
        &mut self,
        graph: &CheckedModuleGraph,
        adapter: &mut impl ActivationAdapter,
        cancellation: &CancellationToken,
    ) -> Result<()> {
        // Iteration bounds both stack depth and work by the checked graph. A
        // saved later repair remains suspended until its predecessors are live.
        for id in &graph.graph().order {
            if !self.state.transaction_results.contains_key(id) {
                break;
            }
            let effect = &graph.graph().nodes[id];
            if effect.lifetime == Lifetime::Transaction
                || !matches!(effect.handler, Handler::Process { .. })
            {
                continue;
            }
            ensure!(
                !cancellation.is_cancelled(),
                "activation restoration cancelled"
            );
            let invocation = self.state.retained[id].invocation.clone();
            let sequence = if self
                .state
                .restoration
                .last()
                .is_some_and(|saved| saved.id == *id)
            {
                *self
                    .restoration_sequences
                    .last()
                    .ok_or_else(|| anyhow::anyhow!("restoration has no durable intent sequence"))?
            } else {
                self.journal.ensure_capacity(
                    self.state.restoration.len() + usize::from(self.state.pending.is_some()) + 3,
                )?;
                self.record(Event::RestorationStarted {
                    invocation: Box::new(invocation.clone()),
                })?
            };
            // Nested repairs may consume the space a suspended intent reserved.
            // Reserve all outstanding outcomes and commit before observing or
            // dispatching, including when this exact intent is being resumed.
            self.journal.ensure_capacity(
                self.state.restoration.len() + usize::from(self.state.pending.is_some()) + 1,
            )?;
            self.boundary(
                &invocation,
                sequence,
                Boundary::IntentDurable,
                adapter,
                cancellation,
            )?;
            let outputs = match self.observe(&invocation, sequence, adapter, cancellation)? {
                Observation::Current(outputs) => outputs,
                Observation::RetrySafe | Observation::Absent => {
                    self.invoke(&invocation, sequence, adapter, cancellation)?
                }
                Observation::Indeterminate => {
                    anyhow::bail!(
                        "completed effect {} cannot be restored safely",
                        invocation.id
                    )
                }
            };
            // Replay checks canonical equality against the original result,
            // including when a handler returned otherwise well-typed drift.
            self.record(Event::RestorationFinished { outputs })?;
            self.boundary(
                &invocation,
                sequence,
                Boundary::OutcomeDurable,
                adapter,
                cancellation,
            )?;
        }
        ensure!(
            self.state.restoration.is_empty(),
            "unresolved restoration stack"
        );
        Ok(())
    }
}
