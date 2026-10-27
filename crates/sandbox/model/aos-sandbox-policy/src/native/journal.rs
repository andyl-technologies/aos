//! Keeps a genuine Root coordinator and its completed semantic history together.
//!
//! Fixed construction alone creates this owner. Role publication/currentness
//! operations stay private to the Policy native modules; no mutable writer,
//! native parts or arbitrary transaction port is exposed to a caller.

mod legacy_read;
pub(super) mod append_stage;
mod native_interval;
mod opening;
mod ordinary;
pub(in crate::native) use ordinary::RootPolicyOrdinaryOpeningOriginalV1;
mod q04_readback;
mod serving;
pub(in crate::native) mod names;

pub(in crate::native) use legacy_read::PolicyLegacyDesiredReadV1;


use std::error::Error;
use std::sync::Arc;

use aos_sandbox_broker::canonical_journal::coordinator::{
    CanonicalCoordinatorReadV1, CanonicalWriterReadViewV1,
};
use aos_sandbox_broker::canonical_journal::{CanonicalOrdinaryHeldJournalV1, RecoveryReport};
use aos_sandbox_broker::receiving::{RootCoordinatorWriterV1, RootJournalFinancialOriginalV1};
use aos_sandbox_model::RecordNamespace;
use aos_sandbox_ledger_replay::cold::ColdReplayRemainderDataV1;

pub use opening::{RootPolicyJournalConstructionOriginalV1, RootPolicyJournalPurposeV1};
pub use q04_readback::Q04ReadbackFailureV1;
pub use native_interval::PolicyNativePostFailureOriginalV1;
pub use serving::RootPolicyJournalServingIdentityV1;

use super::PolicyNativeJournalErrorV1;

pub(super) struct PolicyJournalInstanceV1;

// Both variants own actual native storage. An ordinary opening is a distinct
// fixed-path acquisition, never the fallback for missing selected finance.
pub(super) enum PolicyJournalStorageV1 {
    Selected {
        writer: RootCoordinatorWriterV1<()>,
        financial: RootJournalFinancialOriginalV1,
    },
    Ordinary {
        writer: CanonicalOrdinaryHeldJournalV1<(), PolicyJournalInstanceV1>,
    },
}

/// Retains one actual fixed Root journal, full cold history and same payer.
///
/// A native opening transfers its same coordinator only after full semantic
/// COMMIT/prefix checks, tail and independent fixed-name posts. The identity is
/// private comparison storage; it creates neither a role grant nor currentness.
pub struct RootPolicyJournalV1 {
    pub(super) storage: PolicyJournalStorageV1,
    pub(super) instance: Arc<PolicyJournalInstanceV1>,
    pub(super) history: ColdReplayRemainderDataV1,
    report: RecoveryReport,
    pub(super) captured_native_bytes: u64,
    q04_current: q04_readback::Q04ReadbackCustodyV1,
    native_interval: Option<Arc<native_interval::PolicyNativeIntervalOriginalV1>>,
}

impl RootPolicyJournalV1 {
    pub(in crate::native) fn ensure_healthy(&self) -> Result<(), PolicyNativeJournalErrorV1> {
        self.require_healthy_native()
    }

    pub(in crate::native) fn ensure_protected_authority(&self) -> Result<(), PolicyNativeJournalErrorV1> {
        self.require_healthy_native()?;
        if self.read_view().protected_view().is_none() {
            return Err(PolicyNativeJournalErrorV1::boundary());
        }
        Ok(())
    }

    pub(in crate::native) fn historical_read_view_v1(&self)
        -> aos_sandbox_protocol::domain_ledger::readonly::HistoricalLedgerReadViewV1<'_>
    {
        self.read_view().historical_view()
    }

    pub(in crate::native) fn snapshot_sequence(&self) -> u64 {
        self.read_view().next_sequence()
    }

    /// Borrows an existing committed value as passive historical DATA.
    ///
    /// This performs no native observation and certifies neither role authority
    /// nor currentness. Genuine role methods separately retain their exact
    /// currentness, payment and final mutation crossings.
    #[must_use]
    pub fn get(&self, namespace: RecordNamespace, key: &[u8]) -> Option<&[u8]> {
        self.read_view().historical_view().get(namespace, key)
    }

    /// Copies the actual native next sequence without granting a fresh cut.
    #[must_use]
    pub fn next_sequence(&self) -> u64 {
        self.read_view().next_sequence()
    }

    /// Copies the actual fixed native limits as passive configuration DATA.
    #[must_use]
    pub fn limits(&self) -> aos_sandbox_protocol::domain_ledger::transaction::JournalLimits {
        self.read_view().limits()
    }

    /// Borrows committed rows in one namespace as passive historical DATA.
    ///
    /// The ordered borrowed view is stable only for this immutable borrow. It
    /// grants no currentness, same-payer admission or mutation authority.
    pub fn records(&self, namespace: RecordNamespace) -> impl Iterator<Item = (&[u8], &[u8])> + Clone {
        self.read_view().historical_view().records(namespace)
    }

    /// Borrows every materialized row, including other generic namespaces.
    ///
    /// No family whitelist or fixed-recipe shortcut replaces the complete map.
    pub fn all_records(&self) -> impl Iterator<Item = (RecordNamespace, &[u8], &[u8])> + Clone {
        self.read_view().historical_view().all_records()
    }

    // This excludes the shared financial marker. Startup's independent post
    // must resolve its actual IO cause before falling back to that marker.
    pub(in crate::native) fn concrete_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.retained_append_failure_v1()
            .or_else(|| self.q04_current.failure())
            .or_else(|| match &self.storage {
                PolicyJournalStorageV1::Selected { writer, .. } => writer.concrete_failure_v1(),
                PolicyJournalStorageV1::Ordinary { .. } => None,
            })
    }

    /// Borrows the actual retained native cause before a later coarse refusal.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.concrete_failure_v1().or_else(|| match &self.storage {
            PolicyJournalStorageV1::Selected { financial, .. } => financial.failure_v1(),
            PolicyJournalStorageV1::Ordinary { .. } => None,
        })
    }

    // This is the original concrete selected-writer lane. Financial and
    // invocation-wide refusal belong to their actual receiving frontier.
    // Current's bare-writer phase has not entered q04_current. This narrow
    // query is not an exhaustive diagnostic for later Q04/readback purposes;
    // those retain the existing broader failure() and their own result owners.
    pub(in crate::native) fn retained_selected_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        if let Some(cause) = self.retained_append_failure_v1() {
            return Some(cause);
        }
        match &self.storage {
            PolicyJournalStorageV1::Selected { writer, .. } => writer.concrete_failure_v1(),
            PolicyJournalStorageV1::Ordinary { .. } => None,
        }
    }

    /// Copies the completed opening report without claiming a live role cut.
    #[must_use]
    pub const fn recovery_report(&self) -> RecoveryReport {
        self.report
    }

    // The complete read view stays inside the native role implementation. Its
    // actual Root cursor/samplers keep the original invocation fence over IO.
    pub(super) fn read_view(&self) -> CanonicalWriterReadViewV1<'_, ()> {
        match &self.storage {
            PolicyJournalStorageV1::Selected { writer, .. } => writer.coordinator_read_view(),
            PolicyJournalStorageV1::Ordinary { writer } => writer.read_view_v1(),
        }
    }

    pub(super) fn require_native_original(&self) -> Result<(), PolicyNativeJournalErrorV1> {
        match &self.storage {
            PolicyJournalStorageV1::Selected { writer, financial } => financial
                .require_writer_v1(writer)
                .map_err(|_| PolicyNativeJournalErrorV1::Financial(financial.clone())),
            PolicyJournalStorageV1::Ordinary { writer } => {
                if writer.is_read_only_v1() {
                    return Err(PolicyNativeJournalErrorV1::boundary());
                }
                self.require_healthy_native()
            }
        }
    }

    // Actual role owners supply their full co-resident observation/model demand
    // before growth. Ordinary custody keeps its existing allocation policy; it
    // is a genuine separate physical branch, never absent selected finance.
    pub(super) fn admit_role_observation_v1(
        &self,
        demand: aos_sandbox_model::ResourceVector,
    ) -> Result<(), PolicyNativeJournalErrorV1> {
        match &self.storage {
            PolicyJournalStorageV1::Selected { writer, financial } => financial
                .debit_v1(writer, demand)
                .map_err(|_| PolicyNativeJournalErrorV1::Financial(financial.clone())),
            // Ordinary receiving has no separate financial admission. Native
            // health remains at its original observation/append frontier.
            PolicyJournalStorageV1::Ordinary { .. } => Ok(()),
        }
    }

    pub(super) fn require_healthy_native(&self) -> Result<(), PolicyNativeJournalErrorV1> {
        match &self.storage {
            PolicyJournalStorageV1::Selected { writer, .. } => {
                if writer.has_native_uncertainty_v1() {
                    return Err(PolicyNativeJournalErrorV1::Mechanical(
                        aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1::Poisoned,
                    ));
                }
                if writer.is_closed_or_poisoned_v1() {
                    return Err(PolicyNativeJournalErrorV1::boundary());
                }
            }
            PolicyJournalStorageV1::Ordinary { writer } => {
                if writer.read_view_v1().is_poisoned() {
                    return Err(PolicyNativeJournalErrorV1::Mechanical(
                        aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1::Poisoned,
                    ));
                }
            }
        }
        Ok(())
    }
}
