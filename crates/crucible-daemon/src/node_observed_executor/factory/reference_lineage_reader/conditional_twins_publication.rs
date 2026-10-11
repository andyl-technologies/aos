//! Publishes actual fresh preparations with the complete authenticated source cut.
//!
//! The signed source pin remains owned by this publisher. A typed source runtime
//! reference and its exact Scheduler1 accompany actual fresh readiness; an empty
//! initial coordinator can never replace the preserved original state.

#![cfg(test)]

use crate::node_observed_executor::StoredWorldActivationPublisher;
use crucible::{
    node_contract::{
        ActivationPublisher, ActivationRecord, PreparedWorldPublication, PublicationStatus,
        RuntimeError, SavedRuntimeActivation, ValidatedNodePreparation,
    },
    node_scheduling::{InputPayload, SchedulingSnapshot},
    node_state::PinnedOriginalLineageSource,
};
use crucible_node_contract::{ContentRef, canonical};
use serde::Serialize;
use std::rc::Rc;

pub(super) struct TwinsPublisher {
    stored: Option<StoredWorldActivationPublisher>,
    source: Rc<PinnedOriginalLineageSource>,
    target: ActivationRecord,
    preparations: Option<Vec<ValidatedNodePreparation>>,
    coordinator: Option<InputPayload>,
    attempted: bool,
}

impl TwinsPublisher {
    pub(super) fn new(
        stored: StoredWorldActivationPublisher,
        source: Rc<PinnedOriginalLineageSource>,
        target: ActivationRecord,
    ) -> Self {
        Self {
            stored: Some(stored),
            source,
            target,
            preparations: None,
            coordinator: None,
            attempted: false,
        }
    }
}

impl ActivationPublisher for TwinsPublisher {
    fn prepare_coordinator(
        &mut self,
        record: &ActivationRecord,
        nodes: &[ValidatedNodePreparation],
    ) -> Result<InputPayload, RuntimeError> {
        if record != &self.target
            || nodes.len() != 3
            || self.preparations.as_ref().is_some_and(|old| old != nodes)
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        if !self.attempted {
            self.attempted = true;
            #[derive(Serialize)]
            struct RestoredPublication<'a> {
                format: &'static str,
                source_archive: &'a ContentRef,
                source_runtime: &'a ContentRef,
                source_activation: &'a SavedRuntimeActivation,
                original_scheduler: &'a SchedulingSnapshot,
                target: SavedRuntimeActivation,
                node_preparations: &'a [ValidatedNodePreparation],
            }
            let publication = RestoredPublication {
                format: "crucible/coordinator-original-lineage-restored/7",
                source_archive: self.source.source_artifact(),
                source_runtime: self.source.runtime_reference(),
                source_activation: &self.source.runtime().source_activation,
                original_scheduler: self.source.scheduling(),
                target: SavedRuntimeActivation::from(record),
                node_preparations: nodes,
            };
            // Charge the whole borrowed coordinator before source metadata copies.
            let mut count = Count {
                remaining: 16 * 1024 * 1024,
            };
            serde_json::to_writer(&mut count, &publication)
                .map_err(|_| RuntimeError::ResourceLimit)?;
            let value =
                serde_json::to_value(publication).map_err(|_| RuntimeError::InvalidReceipt)?;
            let bytes =
                canonical::canonical_json(&value).map_err(|_| RuntimeError::InvalidReceipt)?;
            let reference = canonical::content_ref(&bytes, "application/json")
                .map_err(|_| RuntimeError::InvalidReceipt)?;
            self.coordinator = Some(InputPayload { reference, bytes });
            let mut preparations = Vec::new();
            preparations
                .try_reserve_exact(3)
                .map_err(|_| RuntimeError::ResourceLimit)?;
            preparations.extend_from_slice(nodes);
            self.preparations = Some(preparations);
            let stored = self.stored.take().ok_or(RuntimeError::PublicationFailed)?;
            self.stored = Some(
                stored
                    .with_prepared_coordinator(
                        record.clone(),
                        self.preparations
                            .as_ref()
                            .ok_or(RuntimeError::InvalidReceipt)?
                            .clone(),
                        self.coordinator
                            .as_ref()
                            .ok_or(RuntimeError::InvalidReceipt)?
                            .clone(),
                    )
                    .map_err(|_| RuntimeError::PublicationFailed)?,
            );
        }
        self.stored
            .as_mut()
            .ok_or(RuntimeError::PublicationFailed)?
            .prepare_coordinator(record, nodes)
    }

    fn publish_complete(
        &mut self,
        record: &ActivationRecord,
        prepared: &PreparedWorldPublication,
    ) -> PublicationStatus {
        self.stored
            .as_mut()
            .map_or(PublicationStatus::NotCommitted, |stored| {
                stored.publish_complete(record, prepared)
            })
    }

    fn reconcile_complete(
        &mut self,
        record: &ActivationRecord,
        prepared: &PreparedWorldPublication,
    ) -> PublicationStatus {
        self.stored
            .as_mut()
            .map_or(PublicationStatus::Unknown, |stored| {
                stored.reconcile_complete(record, prepared)
            })
    }

    fn publish(&mut self, _: &ActivationRecord) -> PublicationStatus {
        PublicationStatus::NotCommitted
    }

    fn reconcile(&mut self, _: &ActivationRecord) -> PublicationStatus {
        PublicationStatus::Unknown
    }
}

struct Count {
    remaining: usize,
}

impl std::io::Write for Count {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.remaining = self.remaining.checked_sub(bytes.len()).ok_or_else(|| {
            std::io::Error::other("complete restored coordinator credit exhausted")
        })?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
