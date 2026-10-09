//! Complete owner readiness and durable world publication authority.

use std::{collections::BTreeSet, rc::Rc};

use crucible_node_contract::{HashRef, Id, Position, U64};

use super::{OwnerIdentity, PreparedWorldPublication, RuntimeError, ValidatedNodePreparation};
use crate::node_scheduling::InputPayload;

/// Defines one complete world generation prepared for initial or restored work.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivationRecord {
    /// New world generation distinct from discarded or source generations.
    pub generation: U64,
    /// Original activation identity retained across uncertain publication.
    pub activation_id: Id,
    /// Complete immutable admitted world binding identity.
    pub world_binding_hash: HashRef,
    /// Complete immutable owner incarnation roster.
    pub owners: Vec<OwnerIdentity>,
    /// Validated initial or preserved cut coordinate.
    pub boundary: Position,
}

/// Reports the durable publisher's actual disposition of the original record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicationStatus {
    /// The complete original record is durably committed.
    Committed,
    /// The publisher positively establishes that no activation was committed.
    NotCommitted,
    /// Publication may have committed and requires reconciliation.
    Unknown,
}

/// Publishes and reconciles complete world generations under trusted local custody.
///
/// Implementations are a trusted storage boundary: `Committed` means the exact
/// supplied record is durable and recoverable. A transport acknowledgement or
/// an externally supplied record identifier is insufficient. Implementations
/// must recover the same result for retries without publishing another world.
pub trait ActivationPublisher {
    /// Attempts durable publication of this exact complete generation.
    fn publish(&mut self, record: &ActivationRecord) -> PublicationStatus;

    /// Resolves uncertain publication of the same original generation.
    fn reconcile(&mut self, record: &ActivationRecord) -> PublicationStatus;

    /// Reads the actual complete prepared coordinator object before publication.
    ///
    /// Implementations must bind the complete routing, clock, scheduling, input
    /// and operation state to this exact generation and original preparations.
    /// An activation record alone is insufficient. Restored worlds require their
    /// authenticated original coordinator custody, not an empty initial ledger.
    /// The runtime retains the first object across uncertain publication.
    ///
    /// # Errors
    /// Refuses unsupported complete state, incomplete custody or a changed world.
    fn prepare_coordinator(
        &mut self,
        _record: &ActivationRecord,
        _nodes: &[ValidatedNodePreparation],
    ) -> Result<InputPayload, RuntimeError> {
        Err(RuntimeError::PublicationFailed)
    }

    /// Durably publishes the exact complete coordinator and original owner records.
    ///
    /// The default refuses: scalar publication cannot acknowledge this contract.
    fn publish_complete(
        &mut self,
        _record: &ActivationRecord,
        _prepared: &PreparedWorldPublication,
    ) -> PublicationStatus {
        PublicationStatus::NotCommitted
    }

    /// Reconciles the same original complete object after uncertain publication.
    fn reconcile_complete(
        &mut self,
        _record: &ActivationRecord,
        _prepared: &PreparedWorldPublication,
    ) -> PublicationStatus {
        PublicationStatus::Unknown
    }
}

/// Carries authenticated local authority for a durably published complete world.
///
/// This value cannot be constructed from a generation string or a ready token.
/// It is usable only with the runtime that validated readiness and publication.
#[derive(Clone, Debug)]
pub struct WorldActivation {
    pub(crate) authority: Rc<()>,
    pub(crate) record: ActivationRecord,
    pub(crate) nodes: Rc<[ValidatedNodePreparation]>,
    pub(crate) preparation: Option<Rc<PreparedWorldPublication>>,
}

impl WorldActivation {
    /// Returns the complete committed world generation record.
    pub fn record(&self) -> &ActivationRecord {
        &self.record
    }

    /// Borrows the original independently validated closed-gate preparations.
    ///
    /// These historical records do not establish current physical suspension.
    pub fn node_preparations(&self) -> &[ValidatedNodePreparation] {
        &self.nodes
    }

    /// Borrows complete original public owner records when the world supports them.
    pub fn prepared_owners(&self) -> Option<&[crucible_node_contract::PreparedOwner]> {
        self.preparation
            .as_ref()
            .map(|value| value.prepared_owners())
    }

    /// Borrows the complete coordinator object acknowledged by durable publication.
    pub fn coordinator_snapshot(&self) -> Option<&InputPayload> {
        self.preparation
            .as_ref()
            .map(|value| value.coordinator_snapshot())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BarrierState {
    Preparing,
    PublicationUnknown,
    Published,
    Abandoned,
}

pub(crate) struct ActivationBarrier {
    record: ActivationRecord,
    ready: BTreeSet<OwnerIdentity>,
    state: BarrierState,
    last_publication: Option<PublicationStatus>,
    nodes: Rc<[ValidatedNodePreparation]>,
    preparation: Option<Rc<PreparedWorldPublication>>,
}

impl ActivationBarrier {
    pub(crate) fn new(record: ActivationRecord) -> Result<Self, RuntimeError> {
        let unique: BTreeSet<_> = record.owners.iter().cloned().collect();
        if record.generation.get() == 0
            || record.owners.is_empty()
            || record
                .owners
                .iter()
                .any(|owner| owner.generation.get() == 0)
            || unique.len() != record.owners.len()
        {
            return Err(RuntimeError::InvalidRoute);
        }

        Ok(Self {
            record,
            ready: BTreeSet::new(),
            state: BarrierState::Preparing,
            last_publication: None,
            nodes: Rc::from([]),
            preparation: None,
        })
    }

    pub(crate) fn record(&self) -> &ActivationRecord {
        &self.record
    }

    pub(crate) fn prepared_nodes(&self) -> Result<&[ValidatedNodePreparation], RuntimeError> {
        if self.state != BarrierState::Preparing || self.ready.len() != self.record.owners.len() {
            return Err(RuntimeError::NotActivated);
        }
        Ok(&self.nodes)
    }

    pub(crate) fn publication_status_or_not_attempted(&self) -> Option<PublicationStatus> {
        self.last_publication
    }

    pub(crate) fn retained_nodes(&self) -> Rc<[ValidatedNodePreparation]> {
        Rc::clone(&self.nodes)
    }

    pub(crate) fn retained_preparation(&self) -> Option<Rc<PreparedWorldPublication>> {
        self.preparation.as_ref().map(Rc::clone)
    }

    pub(crate) fn reconcile_contained(
        &mut self,
        record: &ActivationRecord,
        publisher: &mut dyn ActivationPublisher,
    ) -> Result<PublicationStatus, RuntimeError> {
        if self.record != *record || self.state != BarrierState::PublicationUnknown {
            return Err(RuntimeError::ForeignAuthority);
        }
        let status = match &self.preparation {
            Some(prepared) => publisher.reconcile_complete(&self.record, prepared),
            None => publisher.reconcile(&self.record),
        };
        self.last_publication = Some(status);
        self.state = match status {
            PublicationStatus::Committed => BarrierState::Published,
            PublicationStatus::NotCommitted => BarrierState::Abandoned,
            PublicationStatus::Unknown => BarrierState::PublicationUnknown,
        };
        Ok(status)
    }

    pub(crate) fn can_arm(&self) -> bool {
        self.state == BarrierState::Preparing
    }

    pub(crate) fn abandon(&mut self, nodes: Vec<ValidatedNodePreparation>) {
        self.ready.clear();
        if self.nodes.is_empty() {
            self.nodes = nodes.into();
        }
        self.state = BarrierState::Abandoned;
    }

    pub(crate) fn ready(
        &mut self,
        nodes: Vec<ValidatedNodePreparation>,
    ) -> Result<(), RuntimeError> {
        if self.state != BarrierState::Preparing
            || nodes
                .iter()
                .flat_map(|node| &node.readiness.owners)
                .any(|owner| !self.record.owners.contains(owner))
        {
            return Err(RuntimeError::ForeignAuthority);
        }

        if !self.nodes.is_empty() && self.nodes.as_ref() != nodes {
            return Err(RuntimeError::InvalidReceipt);
        }

        self.ready = nodes
            .iter()
            .flat_map(|node| node.readiness.owners.iter().cloned())
            .collect();
        self.nodes = nodes.into();
        Ok(())
    }

    pub(crate) fn publish(
        &mut self,
        authority: &Rc<()>,
        publisher: &mut dyn ActivationPublisher,
    ) -> Result<WorldActivation, RuntimeError> {
        if self.state == BarrierState::Published {
            return Ok(self.activation(authority));
        }
        if self.state != BarrierState::Preparing || self.ready.len() != self.record.owners.len() {
            return Err(RuntimeError::NotActivated);
        }

        let has_public_mapping = self.nodes.iter().any(|node| node.prepared_owners.is_some());
        let status = if has_public_mapping {
            if self.preparation.is_none() {
                let mut owners = std::collections::BTreeMap::new();
                for node in self.nodes.iter() {
                    let records = node
                        .prepared_owners
                        .as_ref()
                        .ok_or(RuntimeError::InvalidReceipt)?;
                    for owner in records {
                        if owners
                            .get(&owner.owner_id)
                            .is_some_and(|original| original != owner)
                        {
                            return Err(RuntimeError::InvalidReceipt);
                        }
                        owners.insert(owner.owner_id.clone(), owner.clone());
                    }
                }
                if owners.len() != self.record.owners.len() {
                    return Err(RuntimeError::InvalidReceipt);
                }
                let prepared = PreparedWorldPublication {
                    nodes: Rc::clone(&self.nodes),
                    owners: owners.into_values().collect(),
                    coordinator: publisher.prepare_coordinator(&self.record, &self.nodes)?,
                };
                prepared.validate_coordinator()?;
                self.preparation = Some(Rc::new(prepared));
            }
            let prepared = self
                .preparation
                .as_ref()
                .ok_or(RuntimeError::PublicationFailed)?;
            // A trusted publisher may commit and then unwind. Supervision must
            // retain the original uncertain attempt before entering that effect.
            self.last_publication = Some(PublicationStatus::Unknown);
            self.state = BarrierState::PublicationUnknown;
            publisher.publish_complete(&self.record, prepared)
        } else {
            self.last_publication = Some(PublicationStatus::Unknown);
            self.state = BarrierState::PublicationUnknown;
            publisher.publish(&self.record)
        };
        self.accept_publication(authority, status)
    }

    pub(crate) fn reconcile(
        &mut self,
        authority: &Rc<()>,
        publisher: &mut dyn ActivationPublisher,
    ) -> Result<WorldActivation, RuntimeError> {
        if self.state != BarrierState::PublicationUnknown {
            return Err(RuntimeError::PublicationFailed);
        }

        let status = match &self.preparation {
            Some(prepared) => publisher.reconcile_complete(&self.record, prepared),
            None => publisher.reconcile(&self.record),
        };
        self.accept_publication(authority, status)
    }

    fn accept_publication(
        &mut self,
        authority: &Rc<()>,
        status: PublicationStatus,
    ) -> Result<WorldActivation, RuntimeError> {
        self.last_publication = Some(status);
        match status {
            PublicationStatus::Committed => {
                self.state = BarrierState::Published;
                Ok(self.activation(authority))
            }
            PublicationStatus::NotCommitted => {
                self.state = BarrierState::Abandoned;
                Err(RuntimeError::PublicationFailed)
            }
            PublicationStatus::Unknown => {
                self.state = BarrierState::PublicationUnknown;
                Err(RuntimeError::PublicationFailed)
            }
        }
    }

    pub(crate) fn activation(&self, authority: &Rc<()>) -> WorldActivation {
        WorldActivation {
            authority: Rc::clone(authority),
            record: self.record.clone(),
            nodes: Rc::clone(&self.nodes),
            preparation: self.preparation.as_ref().map(Rc::clone),
        }
    }
}

#[cfg(test)]
#[path = "activation_tests.rs"]
mod tests;
