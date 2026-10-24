//! Dispatches Policy's real private physical stages to the sole native engines.
//!
//! Only the actual fixed Root coordinator or genuine ordinary held storage can
//! enter this enum. Root failure extraction parks the same failed native prefix;
//! ordinary temporaries retain their existing error/disposal semantics. These
//! sibling-private primitives are used by the actual typed append schedule, not
//! a public transaction port or a replacement role/funding gate.

use aos_sandbox_broker::canonical_journal::append_stages::CanonicalAppendPublishedDataV1;
use aos_sandbox_broker::canonical_journal::coordinator::{
    CanonicalCoordinatorAppendDataV1, CanonicalCoordinatorAppendV1,
};
use aos_sandbox_broker::canonical_journal::{
    CanonicalJournalMechanicalErrorV1, CanonicalOrdinaryAppendStageV1,
};
use aos_sandbox_broker::receiving::RootPreparedAppendV1;
use aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction;

use super::super::PolicyNativeJournalErrorV1 as JournalError;
use super::PolicyJournalStorageV1;

pub(in crate::native) enum PolicyAppendStageV1<'transaction> {
    Ordinary(Option<CanonicalOrdinaryAppendStageV1<'transaction>>),
    #[cfg(target_os = "linux")]
    Root(Option<RootPreparedAppendV1>),
}

impl PolicyAppendStageV1<'_> {
    pub(in crate::native) fn projected_materialized_bytes(&self) -> Option<usize> {
        match self {
            Self::Ordinary(stage) => stage.as_ref()?.projected_materialized_bytes(),
            #[cfg(target_os = "linux")]
            Self::Root(stage) => stage.as_ref()?.projected_materialized_bytes(),
        }
    }

    // Ordinary temporaries retire immediately. Root stages move into their
    // same permanent sink before an error reaches the actual role caller.
    fn take_failure(&mut self) -> JournalError {
        match self {
            Self::Ordinary(stage) => {
                let Some(mut stage) = stage.take() else {
                    return JournalError::boundary();
                };
                stage
                    .take_ordinary_error_v1()
                    .ok()
                    .flatten()
                    .map(CanonicalJournalMechanicalErrorV1::from)
                    .map(JournalError::from)
                    .unwrap_or(JournalError::boundary())
            }
            #[cfg(target_os = "linux")]
            Self::Root(stage) => stage
                .take()
                .map(|stage| JournalError::RootAppend(stage.into_failure_original_v1()))
                .unwrap_or(JournalError::boundary()),
        }
    }
}

impl PolicyJournalStorageV1 {
    pub(in crate::native) fn prepare_append<'transaction>(
        &mut self,
        transaction: &'transaction JournalTransaction,
    ) -> Result<PolicyAppendStageV1<'transaction>, JournalError> {
        let mut stage = match self {
            Self::Ordinary { writer } => PolicyAppendStageV1::Ordinary(Some(
                writer
                    .prepare_append_once(transaction)
                    .map_err(|_| JournalError::boundary())?,
            )),
            #[cfg(target_os = "linux")]
            Self::Selected { writer, .. } => PolicyAppendStageV1::Root(Some(
                writer
                    .prepare_append_once(transaction)
                    .map_err(JournalError::Root)?,
            )),
        };
        if stage.projected_materialized_bytes().is_none() {
            return Err(stage.take_failure());
        }
        Ok(stage)
    }

    pub(in crate::native) fn append_coordinates(
        &mut self,
        stage: &mut PolicyAppendStageV1<'_>,
    ) -> Result<(u64, u64), JournalError> {
        let result = match (self, &mut *stage) {
            (Self::Ordinary { writer }, PolicyAppendStageV1::Ordinary(Some(stage))) => {
                writer.append_coordinates_once(stage).map_err(|_| ())
            }
            #[cfg(target_os = "linux")]
            (Self::Selected { writer, .. }, PolicyAppendStageV1::Root(Some(stage))) => {
                writer.append_coordinates_once(stage).map_err(|_| ())
            }
            _ => Err(()),
        };
        match result {
            Ok(value) => Ok(value),
            Err(()) => Err(stage.take_failure()),
        }
    }

    pub(in crate::native) fn expected_append_length(
        &mut self,
        stage: &mut PolicyAppendStageV1<'_>,
    ) -> Result<u64, JournalError> {
        let result = match (self, &mut *stage) {
            (Self::Ordinary { writer }, PolicyAppendStageV1::Ordinary(Some(stage))) => {
                writer.expected_append_length_once(stage).map_err(|_| ())
            }
            #[cfg(target_os = "linux")]
            (Self::Selected { writer, .. }, PolicyAppendStageV1::Root(Some(stage))) => {
                writer.expected_append_length_once(stage).map_err(|_| ())
            }
            _ => Err(()),
        };
        match result {
            Ok(value) => Ok(value),
            Err(()) => Err(stage.take_failure()),
        }
    }

    pub(in crate::native) fn append_prepared(
        &mut self,
        stage: &mut PolicyAppendStageV1<'_>,
    ) -> Result<u64, JournalError> {
        let result = match (self, &mut *stage) {
            (Self::Ordinary { writer }, PolicyAppendStageV1::Ordinary(Some(stage))) => {
                writer.append_prepared_once(stage).map_err(|_| ())
            }
            #[cfg(target_os = "linux")]
            (Self::Selected { writer, .. }, PolicyAppendStageV1::Root(Some(stage))) => {
                writer.append_prepared_once(stage).map_err(|_| ())
            }
            _ => Err(()),
        };
        match result {
            Ok(value) => Ok(value),
            Err(()) => Err(stage.take_failure()),
        }
    }

    pub(in crate::native) fn apply_next_record(
        &mut self,
        stage: &mut PolicyAppendStageV1<'_>,
    ) -> Result<bool, JournalError> {
        let result = match (self, &mut *stage) {
            (Self::Ordinary { writer }, PolicyAppendStageV1::Ordinary(Some(stage))) => {
                writer.apply_next_record_once(stage).map_err(|_| ())
            }
            #[cfg(target_os = "linux")]
            (Self::Selected { writer, .. }, PolicyAppendStageV1::Root(Some(stage))) => {
                writer.apply_next_record_once(stage).map_err(|_| ())
            }
            _ => Err(()),
        };
        match result {
            Ok(value) => Ok(value),
            Err(()) => Err(stage.take_failure()),
        }
    }

    pub(in crate::native) fn publish_append(
        &mut self,
        stage: &mut PolicyAppendStageV1<'_>,
    ) -> Result<CanonicalAppendPublishedDataV1, JournalError> {
        let result = match (self, &mut *stage) {
            (Self::Ordinary { writer }, PolicyAppendStageV1::Ordinary(Some(stage))) => {
                writer.publish_append_once(stage).map_err(|_| ())
            }
            #[cfg(target_os = "linux")]
            (Self::Selected { writer, .. }, PolicyAppendStageV1::Root(Some(stage))) => {
                writer.publish_append_once(stage).map_err(|_| ())
            }
            _ => Err(()),
        };
        match result {
            Ok(value) => Ok(value),
            Err(()) => Err(stage.take_failure()),
        }
    }

    pub(in crate::native) fn finish_append_after_posts(
        &mut self,
        stage: &mut PolicyAppendStageV1<'_>,
    ) -> Result<(), JournalError> {
        let result = match (self, &mut *stage) {
            (Self::Ordinary { writer }, PolicyAppendStageV1::Ordinary(Some(stage))) => {
                writer.finish_append_after_posts_once(stage).map_err(|_| ())
            }
            #[cfg(target_os = "linux")]
            (Self::Selected { writer, .. }, PolicyAppendStageV1::Root(Some(stage))) => {
                writer.finish_append_after_posts_once(stage).map_err(|_| ())
            }
            _ => Err(()),
        };
        match result {
            Ok(value) => Ok(value),
            Err(()) => Err(stage.take_failure()),
        }
    }
}
