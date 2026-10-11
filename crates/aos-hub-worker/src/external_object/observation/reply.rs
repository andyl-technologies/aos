//! Exact original-request reply binding for shared guarded HEAD execution.

use anyhow::{ensure, Result};
use aos_hub_core::storage_authority::{
    external_object::observation::{
        semantic::SemanticExternalObservationReply, ExternalObservationOutcome,
        ExternalObservationReply,
    },
    external_object::ExternalObjectRequest,
    lease::LeaseCohort,
};
use aos_hub_core::storage_work::{StorageBindingSnapshot, StorageWorkKey};

/// Selects the exact authenticated original request for a guarded HEAD reply.
pub(in crate::external_object) enum ReplyBinding<'a> {
    /// Preserves the existing token-bearing route's original byte commitment.
    Existing(&'a [u8]),
    /// Binds the semantic route and its independently selected exact read cohort.
    Semantic {
        bytes: &'a [u8],
        cohort: &'a LeaseCohort,
    },
}

impl ReplyBinding<'_> {
    /// Checks semantic application and snapshot time immediately before Begin.
    ///
    /// # Errors
    /// Returns an error when either original permission is future or expired.
    pub(in crate::external_object) fn check_begin_time(
        &self,
        work: &ExternalObjectRequest,
        snapshot: &StorageBindingSnapshot,
        now: i64,
    ) -> Result<()> {
        if matches!(self, Self::Semantic { .. }) {
            for (issued, expires) in [
                (work.plan.issued_at, work.plan.expires_at),
                (snapshot.issued_at, snapshot.expires_at),
            ] {
                ensure!(
                    issued <= now.saturating_add(5) && now <= expires,
                    "semantic permission expired before Begin"
                );
            }
        }
        Ok(())
    }

    /// Requires the semantic profile's entire independently configured read cohort.
    ///
    /// # Errors
    /// Returns an error when the selected cohort differs from that profile.
    pub(in crate::external_object) fn validate_cohort(&self, selected: &LeaseCohort) -> Result<()> {
        if let Self::Semantic { cohort, .. } = self {
            ensure!(
                *cohort == selected,
                "semantic read cohort differs from selected profile"
            );
        }
        Ok(())
    }

    /// Signs the typed outcome for the caller's exact original request bytes.
    ///
    /// # Errors
    /// Returns an error for malformed context, outcome or reply encoding bounds.
    pub(in crate::external_object) fn sign(
        &self,
        key: &StorageWorkKey,
        outcome: ExternalObservationOutcome,
    ) -> Result<(Vec<u8>, String)> {
        match self {
            Self::Existing(bytes) => {
                ExternalObservationReply::new(bytes, outcome)?.sign(key, bytes)
            }
            Self::Semantic { bytes, .. } => {
                SemanticExternalObservationReply::new(bytes, outcome)?.sign(key, bytes)
            }
        }
    }
}
