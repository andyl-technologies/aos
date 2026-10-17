//! Durable fresh publication of the authenticated original replay continuation.
//!
//! Original scheduler/runtime custody stays explicitly labeled as source state.
//! Fresh readiness comes from actual runtime-validated model preparations after
//! complete restore verification; no initial empty coordinator is substituted.

use crucible::node_contract::{
    ActivationPublisher, PreparedWorldPublication, PublicationStatus, RuntimeError,
    ValidatedNodePreparation,
};

use super::*;

pub(super) struct ReplayRestoredPublisher {
    stored: Option<StoredWorldActivationPublisher>,
    source: serde_json::Value,
    target: ActivationRecord,
    nodes: Option<Vec<ValidatedNodePreparation>>,
}

impl ReplayRestoredPublisher {
    pub(super) fn new(
        stored: StoredWorldActivationPublisher,
        source: serde_json::Value,
        target: ActivationRecord,
    ) -> Self {
        Self {
            stored: Some(stored),
            source,
            target,
            nodes: None,
        }
    }
}

impl ActivationPublisher for ReplayRestoredPublisher {
    fn prepare_coordinator(
        &mut self,
        record: &ActivationRecord,
        nodes: &[ValidatedNodePreparation],
    ) -> Result<InputPayload, RuntimeError> {
        if record != &self.target
            || self
                .nodes
                .as_ref()
                .is_some_and(|original| original != nodes)
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.nodes.is_none() {
            #[derive(serde::Serialize)]
            struct Publication<'a> {
                schema: &'static str,
                target: crucible::node_contract::SavedRuntimeActivation,
                original: &'a serde_json::Value,
                node_preparations: &'a [ValidatedNodePreparation],
            }
            // Serialize a borrowed view to the counting sink before allocating
            // the canonical object or duplicating any source custody bodies.
            let object = bounded_value(&Publication {
                schema: "crucible/coordinator-restored-replay/1",
                target: crucible::node_contract::SavedRuntimeActivation::from(record),
                original: &self.source,
                node_preparations: nodes,
            })?;
            let bytes =
                canonical::canonical_json(&object).map_err(|_| RuntimeError::InvalidReceipt)?;
            let reference = canonical::content_ref(&bytes, "application/json")
                .map_err(|_| RuntimeError::InvalidReceipt)?;
            let stored = self.stored.take().ok_or(RuntimeError::PublicationFailed)?;
            self.stored = Some(
                stored
                    .with_prepared_coordinator(
                        record.clone(),
                        nodes.to_vec(),
                        InputPayload { reference, bytes },
                    )
                    .map_err(|_| RuntimeError::PublicationFailed)?,
            );
            self.nodes = Some(nodes.to_vec());
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

pub(super) fn bounded_value<T: serde::Serialize>(
    value: &T,
) -> Result<serde_json::Value, RuntimeError> {
    let mut writer = Count {
        remaining: 16 * 1024 * 1024,
    };
    serde_json::to_writer(&mut writer, value).map_err(|_| RuntimeError::ResourceLimit)?;
    serde_json::to_value(value).map_err(|_| RuntimeError::InvalidReceipt)
}

struct Count {
    remaining: usize,
}
impl std::io::Write for Count {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.remaining = self
            .remaining
            .checked_sub(bytes.len())
            .ok_or_else(|| std::io::Error::other("restored coordinator credit exhausted"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
