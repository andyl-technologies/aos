//! Complete owner readiness and durable world publication authority.

use std::{collections::BTreeSet, rc::Rc};

use crucible_node_contract::{HashRef, Id, Position, U64};

use super::{OwnerIdentity, RuntimeError};

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
}

/// Carries authenticated local authority for a durably published complete world.
///
/// This value cannot be constructed from a generation string or a ready token.
/// It is usable only with the runtime that validated readiness and publication.
#[derive(Clone, Debug)]
pub struct WorldActivation {
    pub(crate) authority: Rc<()>,
    pub(crate) record: ActivationRecord,
}

impl WorldActivation {
    /// Returns the complete committed world generation record.
    pub fn record(&self) -> &ActivationRecord {
        &self.record
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
        })
    }

    pub(crate) fn record(&self) -> &ActivationRecord {
        &self.record
    }

    pub(crate) fn publication_status_or_not_attempted(&self) -> Option<PublicationStatus> {
        self.last_publication
    }

    pub(crate) fn abandon(&mut self) {
        self.ready.clear();
        self.state = BarrierState::Abandoned;
    }

    pub(crate) fn ready(&mut self, owners: &[OwnerIdentity]) -> Result<(), RuntimeError> {
        if self.state != BarrierState::Preparing
            || owners
                .iter()
                .any(|owner| !self.record.owners.contains(owner))
        {
            return Err(RuntimeError::ForeignAuthority);
        }

        self.ready.extend(owners.iter().cloned());
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

        self.accept_publication(authority, publisher.publish(&self.record))
    }

    pub(crate) fn reconcile(
        &mut self,
        authority: &Rc<()>,
        publisher: &mut dyn ActivationPublisher,
    ) -> Result<WorldActivation, RuntimeError> {
        if self.state != BarrierState::PublicationUnknown {
            return Err(RuntimeError::PublicationFailed);
        }

        self.accept_publication(authority, publisher.reconcile(&self.record))
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

    fn activation(&self, authority: &Rc<()>) -> WorldActivation {
        WorldActivation {
            authority: Rc::clone(authority),
            record: self.record.clone(),
        }
    }
}
