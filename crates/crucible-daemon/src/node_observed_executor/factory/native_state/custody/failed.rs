//! Authenticates no-archive original histories against the same reclaimed capsule.
//!
//! The constructor is restricted to the independently installed four-owner
//! factory. Its caller must reopen the complete original source and history
//! roots and authenticate the actual retained Host/runtime before this native
//! conjunction. It never accepts a caller-created capture or signed DTO alone.

use crucible::node_contract::{ActivationRecord, SavedRuntimeActivation};
use crucible_node_contract::ContentRef;

use super::{Entry, NativeCustodyError, RetirementRecords};

pub(in crate::node_observed_executor::factory::native_state) struct FailedHistoryReferences {
    pub(in crate::node_observed_executor::factory::native_state) metadata: ContentRef,
    pub(in crate::node_observed_executor::factory::native_state) native: ContentRef,
    pub(in crate::node_observed_executor::factory::native_state) acknowledgements: ContentRef,
}

/// Holds installed source-qualified original history, independently of a native proof.
pub(in crate::node_observed_executor::factory::native_state) struct AuthenticatedFailedSupervision {
    activation: SavedRuntimeActivation,
    source: ContentRef,
    history: FailedHistoryReferences,
}

impl AuthenticatedFailedSupervision {
    pub(in crate::node_observed_executor::factory::native_state) fn from_original(
        activation: &ActivationRecord,
        source: ContentRef,
        history: FailedHistoryReferences,
    ) -> Result<Self, NativeCustodyError> {
        if activation.owners.len() != 4 {
            return Err(NativeCustodyError::Refused(
                "failed supervisor requires all four original owners",
            ));
        }
        Ok(Self {
            activation: activation.into(),
            source,
            history,
        })
    }

    pub(super) fn same_original(&self, other: &Self) -> bool {
        self.activation == other.activation
            && self.source == other.source
            && self.history.metadata == other.history.metadata
            && self.history.native == other.history.native
            && self.history.acknowledgements == other.history.acknowledgements
    }

    pub(super) fn validate_entry(&self, original: &mut Entry) -> Result<(), NativeCustodyError> {
        let fail = || {
            NativeCustodyError::Refused(
                "same original failed supervisor history or release proof differs",
            )
        };
        if original.in_flight
            || original.scope.publication != crucible::node_state::PublicationKnowledge::Committed
            || SavedRuntimeActivation::from(&original.scope.activation) != self.activation
            || !original.failure.is_empty()
        {
            return Err(fail());
        }
        let custody = original.custody.as_mut().ok_or_else(fail)?;
        if custody.launch.owner != original.scope.owner.owner
            || custody.launch.incarnation != original.scope.owner.incarnation
            || custody.launch.generation != original.scope.owner.generation
        {
            return Err(fail());
        }
        custody
            .authenticate_original_retirement_histories(
                &self.history.native,
                &self.history.acknowledgements,
            )
            .map_err(|_| fail())?;
        let (reference, body) = original.proof.as_ref().ok_or_else(fail)?;
        reference.verify(body).map_err(|_| fail())?;
        let proof = custody
            .poll_reclamation()
            .map_err(|_| fail())?
            .ok_or_else(fail)?;
        if proof.owner() != &original.scope.owner.owner
            || proof.incarnation() != &original.scope.owner.incarnation
            || proof.generation() != original.scope.owner.generation
            || proof.evidence() != (reference, body.as_slice())
        {
            return Err(fail());
        }
        Ok(())
    }
}

pub(super) struct FailedSupervisedEntry {
    pub(super) original: Entry,
    pub(super) source: AuthenticatedFailedSupervision,
}

/// Records actual supervisor safe-release; no data constructor or serializer exists.
pub(in crate::node_observed_executor::factory::native_state) struct NativeFailedRelease {
    activation: SavedRuntimeActivation,
    source: ContentRef,
    metadata: ContentRef,
}

impl NativeFailedRelease {
    pub(in crate::node_observed_executor::factory::native_state) fn matches(
        &self,
        activation: &ActivationRecord,
        source: &ContentRef,
        metadata: &ContentRef,
    ) -> bool {
        self.activation == activation.into() && &self.source == source && &self.metadata == metadata
    }
}

impl super::Gem5CustodyQueue {
    pub(in super::super) fn supervise_failed_original(
        &self,
        target: &ActivationRecord,
        source: &mut Option<AuthenticatedFailedSupervision>,
    ) -> Result<(), NativeCustodyError> {
        let mut registry = self.owner.shared.lock();
        if let Some(held) = registry
            .failed_supervised
            .iter()
            .flatten()
            .find(|entry| &entry.original.scope.activation == target)
        {
            return if source
                .as_ref()
                .is_some_and(|source| source.same_original(&held.source))
            {
                Ok(())
            } else {
                Err(NativeCustodyError::Refused(
                    "original failed supervisor source differs",
                ))
            };
        }
        let index = registry
            .slots
            .iter()
            .position(|entry| {
                entry
                    .as_ref()
                    .is_some_and(|entry| &entry.scope.activation == target)
            })
            .ok_or(NativeCustodyError::Refused(
                "original failed capsule absent",
            ))?;
        if registry.supervised[index].is_some() || registry.failed_supervised[index].is_some() {
            return Err(NativeCustodyError::Refused(
                "matching supervisor slot occupied",
            ));
        }
        source
            .as_ref()
            .ok_or(NativeCustodyError::Refused(
                "qualified original failed source absent",
            ))?
            .validate_entry(
                registry.slots[index]
                    .as_mut()
                    .ok_or(NativeCustodyError::Refused("original failed entry absent"))?,
            )?;

        // Matching preallocated slots share the same original eight-owner credit.
        // Fallible validation precedes taking either entire original value.
        let authenticated = source.take().ok_or(NativeCustodyError::Refused(
            "original failed source disappeared",
        ))?;
        let Some(original) = registry.slots[index].take() else {
            *source = Some(authenticated);
            return Err(NativeCustodyError::Refused(
                "original failed capsule disappeared",
            ));
        };
        registry.failed_supervised[index] = Some(FailedSupervisedEntry {
            original,
            source: authenticated,
        });
        Ok(())
    }

    pub(in super::super) fn failed_retirement_records(
        &self,
        target: &ActivationRecord,
        source: &AuthenticatedFailedSupervision,
    ) -> Result<Option<RetirementRecords>, NativeCustodyError> {
        let mut registry = self.owner.shared.lock();
        let held = registry
            .failed_supervised
            .iter_mut()
            .flatten()
            .find(|entry| &entry.original.scope.activation == target)
            .ok_or(NativeCustodyError::Refused(
                "failed original supervisor absent",
            ))?;
        if !source.same_original(&held.source) {
            return Err(NativeCustodyError::Refused(
                "failed original durable source differs",
            ));
        }
        if held.original.proof.is_none() || held.original.in_flight {
            return Ok(None);
        }
        source.validate_entry(&mut held.original)?;
        let native = held
            .original
            .custody
            .as_ref()
            .ok_or(NativeCustodyError::Refused(
                "failed original native custody absent",
            ))?;
        let shutdown = native
            .original_retirement_shutdown_record(64 * 1024)
            .map_err(|_| NativeCustodyError::Refused("actual original Shutdown history differs"))?;
        let (reference, bytes) =
            held.original
                .proof
                .as_ref()
                .ok_or(NativeCustodyError::Refused(
                    "actual original reaping proof absent",
                ))?;
        if bytes.len() > 64 * 1024 {
            return Err(NativeCustodyError::Refused(
                "original reaping proof exceeds credit",
            ));
        }
        let mut body = Vec::new();
        body.try_reserve_exact(bytes.len())?;
        body.extend_from_slice(bytes);
        let mut records = Vec::new();
        records.try_reserve_exact(2)?;
        records.push(shutdown);
        records.push((reference.clone(), body));
        Ok(Some(records))
    }

    pub(in super::super) fn release_failed_supervised(
        &self,
        target: &ActivationRecord,
        reopened: &AuthenticatedFailedSupervision,
    ) -> Result<NativeFailedRelease, NativeCustodyError> {
        let mut registry = self.owner.shared.lock();
        let index = registry
            .failed_supervised
            .iter()
            .position(|entry| {
                entry
                    .as_ref()
                    .is_some_and(|entry| &entry.original.scope.activation == target)
            })
            .ok_or(NativeCustodyError::Refused(
                "same failed supervisor capsule absent",
            ))?;
        let held =
            registry.failed_supervised[index]
                .as_mut()
                .ok_or(NativeCustodyError::Refused(
                    "same failed supervisor entry absent",
                ))?;
        if !reopened.same_original(&held.source) {
            return Err(NativeCustodyError::Refused(
                "fresh complete failed source differs",
            ));
        }
        reopened.validate_entry(&mut held.original)?;
        let released = NativeFailedRelease {
            activation: reopened.activation.clone(),
            source: reopened.source.clone(),
            metadata: reopened.history.metadata.clone(),
        };
        // Only this actual post-validation take releases native credit. The
        // caller still holds the original full runtime/Host/data capsule.
        let original = registry.failed_supervised[index].take();
        drop(registry);
        drop(original);
        self.owner.shared.changed.notify_one();
        Ok(released)
    }
}
