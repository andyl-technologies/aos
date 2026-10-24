//! Joins the complete retained Network histories without allocating a census.
//!
//! A false result is retained resource history, never evidence of absence.
//! Mandatory initialization heads are checked through their existing codecs.
//! Native writer observations are owned separately and bookend this full fold.

use super::*;
use super::callsite::NetworkServiceDomainCallsiteV4;
use crate::journal::{Journal, JournalError};
use crate::journal::FixedServiceInventoryJournalCurrentnessOriginalV2 as Writer;

#[derive(Debug, thiserror::Error)]
#[error("the complete retained Network inventory history is incomplete")]
pub(super) struct HistoryClosed;

/// Keeps each actual protected owner's independent whole-history result.
#[derive(Default)]
pub(super) struct HistoryOriginal {
    creation: Option<std::result::Result<bool, crate::NetworkStateError>>,
    lifecycle: Option<std::result::Result<bool, crate::NetworkLifecycleStateError>>,
    preparation: Option<std::result::Result<bool, crate::NetworkPreparationCatalogError>>,
    namespaces: Option<std::result::Result<bool, crate::NetworkNamespaceCatalogError>>,
    entered: bool,
    repeated: bool,
}

impl HistoryOriginal {
    pub(super) fn observe_once(&mut self, sources: &NetworkServiceDomainCallsiteV4<'_>)
        -> std::result::Result<bool, HistoryClosed>
    {
        if self.entered {
            self.repeated = true;
            return Err(HistoryClosed);
        }
        self.entered = true;
        // Every owned journal is inspected, including retired, old-boot,
        // allocation and authority rows. No output-row filter is reused here.
        self.creation = Some(sources.coordinator.inventory_creation_history_empty_v2(
            sources.preparations.inventory_policy_v2(),
        ));
        self.lifecycle = Some(sources.coordinator.inventory_lifecycle_state_v2()
            .inventory_no_resource_history_v2());
        self.preparation = Some(sources.preparations.inventory_no_resource_history_v2());
        self.namespaces = Some(sources.namespaces.inventory_no_resource_history_v2());
        self.complete()
    }

    pub(super) fn complete(&self) -> std::result::Result<bool, HistoryClosed> {
        if self.repeated {
            return Err(HistoryClosed);
        }
        let creation = self.creation.as_ref().and_then(|value| value.as_ref().ok()).ok_or(HistoryClosed)?;
        let lifecycle = self.lifecycle.as_ref().and_then(|value| value.as_ref().ok()).ok_or(HistoryClosed)?;
        let preparation = self.preparation.as_ref().and_then(|value| value.as_ref().ok()).ok_or(HistoryClosed)?;
        let namespaces = self.namespaces.as_ref().and_then(|value| value.as_ref().ok()).ok_or(HistoryClosed)?;
        Ok(*creation && *lifecycle && *preparation && *namespaces)
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        fn cause<T, E: Error + 'static>(value: &Option<std::result::Result<T, E>>)
            -> Option<&(dyn Error + 'static)>
        {
            value.as_ref()?.as_ref().err().map(|cause| cause as _)
        }
        cause(&self.creation).or_else(|| cause(&self.lifecycle))
            .or_else(|| cause(&self.preparation)).or_else(|| cause(&self.namespaces))
            .or_else(|| self.repeated.then_some(&HistoryClosed as &(dyn Error + 'static)))
    }
}

impl NetworkServiceDomainCallsiteV4<'_> {
    pub(super) fn inventory_history_receiving_demand_v2(&self)
        -> std::result::Result<ResourceVector, JournalError>
    {
        let history = self.coordinator.inventory_creation_state_v2().inventory_history_memory_v2()
            .and_then(|bytes| bytes.checked_add(self.coordinator.inventory_lifecycle_state_v2()
                .inventory_history_memory_v2()?))
            .and_then(|bytes| bytes.checked_add(self.preparations.inventory_history_memory_v2()?))
            .and_then(|bytes| bytes.checked_add(self.namespaces.inventory_history_memory_v2()?))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<HistoryOriginal>().checked_mul(4)?))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(JournalError::JournalTooLarge)?;
        self.creation_original.inventory_currentness_demand_v2()?
            .checked_add(self.lifecycle_original.inventory_currentness_demand_v2()?)?
            .checked_add(self.preparation_original.inventory_currentness_demand_v2()?)?
            .checked_add(self.namespace_original.inventory_currentness_demand_v2()?)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, history))
            .map_err(Into::into)
    }

    fn inventory_journals_v2(&self) -> [&Journal; 4] {
        [
            self.coordinator.inventory_creation_state_v2().inventory_journal_v2(),
            self.coordinator.inventory_lifecycle_state_v2().inventory_journal_v2(),
            self.preparations.inventory_journal_v2(),
            self.namespaces.inventory_journal_v2(),
        ]
    }

    pub(super) fn inventory_native_before_v2(&self, originals: &mut [Writer; 4],
        results: &mut [Option<std::result::Result<(), JournalError>>; 4],
    ) {
        let journals = self.inventory_journals_v2();
        results[0] = Some(self.creation_original.inventory_currentness_before_v2(journals[0], &mut originals[0]));
        results[1] = Some(self.lifecycle_original.inventory_currentness_before_v2(journals[1], &mut originals[1]));
        results[2] = Some(self.preparation_original.inventory_currentness_before_v2(journals[2], &mut originals[2]));
        results[3] = Some(self.namespace_original.inventory_currentness_before_v2(journals[3], &mut originals[3]));
    }

    pub(super) fn inventory_native_after_owed_v2(&self, originals: &mut [Writer; 4],
        results: &mut [Option<std::result::Result<(), JournalError>>; 4],
    ) {
        let journals = self.inventory_journals_v2();
        // Each actual held writer has its own prepaid destination. A failure
        // in another writer or the domain body cannot suppress a later post.
        results[0] = Some(self.creation_original.inventory_currentness_after_owed_v2(journals[0], &mut originals[0]));
        results[1] = Some(self.lifecycle_original.inventory_currentness_after_owed_v2(journals[1], &mut originals[1]));
        results[2] = Some(self.preparation_original.inventory_currentness_after_owed_v2(journals[2], &mut originals[2]));
        results[3] = Some(self.namespace_original.inventory_currentness_after_owed_v2(journals[3], &mut originals[3]));
    }
}
