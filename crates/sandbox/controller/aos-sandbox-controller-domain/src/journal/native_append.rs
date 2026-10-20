//! Dispatches the sole upper append schedule to its actual native owner.
//!
//! The common ordinary stage retains borrowed or captured DATA. Selected
//! stages own their prepaid copy and park unfinished work in the same sink.
//! Every semantic and final-crossing gate stays at its original upper callsite.

use aos_sandbox_broker::canonical_journal::CanonicalOrdinaryAppendStageV1;
use aos_sandbox_broker::canonical_journal::append_stages::CanonicalAppendPublishedDataV1;
use aos_sandbox_broker::canonical_journal::coordinator::{
    CanonicalCoordinatorAppendDataV1, CanonicalCoordinatorAppendV1,
};
use aos_sandbox_broker::controller_receiving::bank_launch::ControllerPreparedAppendV1;
use aos_sandbox_broker::receiving::RootPreparedAppendV1;
use aos_sandbox_broker::source_receiving::SourcePreparedAppendV1;

use super::native_backing::JournalNativeBackingV1;
use super::*;

pub(super) enum JournalAppendStageV1<'transaction> {
    Ordinary(Option<CanonicalOrdinaryAppendStageV1<'transaction>>),
    #[cfg(target_os = "linux")]
    Controller(Option<ControllerPreparedAppendV1>),
    #[cfg(target_os = "linux")]
    Root(Option<RootPreparedAppendV1>),
    #[cfg(target_os = "linux")]
    Source(Option<SourcePreparedAppendV1>),
}

impl JournalAppendStageV1<'_> {
    pub(super) fn projected_materialized_bytes(&self) -> Option<usize> {
        match self {
            Self::Ordinary(stage) => stage.as_ref()?.projected_materialized_bytes(),
            #[cfg(target_os = "linux")]
            Self::Controller(stage) => stage.as_ref()?.projected_materialized_bytes().ok(),
            #[cfg(target_os = "linux")]
            Self::Root(stage) => stage.as_ref()?.projected_materialized_bytes(),
            #[cfg(target_os = "linux")]
            Self::Source(stage) => stage.as_ref()?.projected_materialized_bytes(),
        }
    }

    // Ordinary temporaries retire immediately; captured and selected bodies
    // move into their same permanent sinks before an error reaches upper code.
    fn take_failure(&mut self) -> JournalError {
        match self {
            Self::Ordinary(stage) => {
                let Some(mut stage) = stage.take() else {
                    return JournalError::ProtectedBoundary;
                };
                // The captured extractor leaves a borrowed body untouched.
                #[cfg(target_os = "linux")]
                if let Ok(original) = stage.take_captured_failure_v1() {
                    return JournalError::CapturedAppendOriginal(original);
                }
                stage.take_ordinary_error_v1()
                    .ok()
                    .flatten()
                    .map(CanonicalJournalMechanicalErrorV1::from)
                    .map(JournalError::from)
                    .unwrap_or(JournalError::ProtectedBoundary)
            }
            #[cfg(target_os = "linux")]
            Self::Controller(stage) => stage.take()
                .map(|stage| JournalError::ControllerAppendOriginal(stage.into_failure_original_v1()))
                .unwrap_or(JournalError::ProtectedBoundary),
            #[cfg(target_os = "linux")]
            Self::Root(stage) => stage.take()
                .map(|stage| JournalError::RootAppendOriginal(stage.into_failure_original_v1()))
                .unwrap_or(JournalError::ProtectedBoundary),
            #[cfg(target_os = "linux")]
            Self::Source(stage) => stage.take()
                .map(|stage| JournalError::SourceAppendOriginal(stage.into_failure_original_v1()))
                .unwrap_or(JournalError::ProtectedBoundary),
        }
    }
}

impl JournalNativeBackingV1 {
    pub(super) fn prepare_append<'transaction>(
        &mut self,
        transaction: &'transaction JournalTransaction,
    ) -> Result<JournalAppendStageV1<'transaction>, JournalError> {
        let mut stage = match self {
            Self::Ordinary(ordinary) => {
                #[cfg(target_os = "linux")]
                if let Some(owner) = ordinary.captured_append.as_ref() {
                    owner.require_delete_append_window_v1(transaction)?;
                    let stage = ordinary.held.prepare_captured_append_v1(
                        owner.data_custody_v1(),
                        transaction,
                    ).map_err(|_| JournalError::ProtectedBoundary)?;
                    let mut stage = JournalAppendStageV1::Ordinary(Some(stage));
                    if stage.projected_materialized_bytes().is_none() {
                        return Err(stage.take_failure());
                    }
                    return Ok(stage);
                }
                JournalAppendStageV1::Ordinary(Some(
                    ordinary.held.prepare_append_once(transaction)
                        .map_err(|_| JournalError::ProtectedBoundary)?,
                ))
            },
            #[cfg(target_os = "linux")]
            Self::Controller(writer) => JournalAppendStageV1::Controller(Some(
                writer.prepare_append_once(transaction).map_err(JournalError::ControllerNative)?,
            )),
            #[cfg(target_os = "linux")]
            Self::Root(writer) => JournalAppendStageV1::Root(Some(
                writer.prepare_append_once(transaction).map_err(JournalError::RootNative)?,
            )),
            #[cfg(target_os = "linux")]
            Self::Source(writer) => JournalAppendStageV1::Source(Some(
                writer.prepare_append_once(transaction).map_err(JournalError::SourceNative)?,
            )),
        };
        if stage.projected_materialized_bytes().is_none() {
            return Err(stage.take_failure());
        }
        Ok(stage)
    }

    pub(super) fn append_coordinates(
        &mut self,
        stage: &mut JournalAppendStageV1<'_>,
    ) -> Result<(u64, u64), JournalError> {
        let result = match (self, &mut *stage) {
            (Self::Ordinary(ordinary), JournalAppendStageV1::Ordinary(Some(stage))) =>
                ordinary.held.append_coordinates_once(stage).map_err(|_| ()),
            #[cfg(target_os = "linux")]
            (Self::Controller(writer), JournalAppendStageV1::Controller(Some(stage))) =>
                writer.append_coordinates_once(stage).map_err(|_| ()),
            #[cfg(target_os = "linux")]
            (Self::Root(writer), JournalAppendStageV1::Root(Some(stage))) =>
                writer.append_coordinates_once(stage).map_err(|_| ()),
            #[cfg(target_os = "linux")]
            (Self::Source(writer), JournalAppendStageV1::Source(Some(stage))) =>
                writer.append_coordinates_once(stage).map_err(|_| ()),
            _ => Err(()),
        };
        match result {
            Ok(value) => Ok(value),
            Err(()) => Err(stage.take_failure()),
        }
    }

    pub(super) fn expected_append_length(
        &mut self,
        stage: &mut JournalAppendStageV1<'_>,
    ) -> Result<u64, JournalError> {
        let result = match (self, &mut *stage) {
            (Self::Ordinary(ordinary), JournalAppendStageV1::Ordinary(Some(stage))) =>
                ordinary.held.expected_append_length_once(stage).map_err(|_| ()),
            #[cfg(target_os = "linux")]
            (Self::Controller(writer), JournalAppendStageV1::Controller(Some(stage))) =>
                writer.expected_append_length_once(stage).map_err(|_| ()),
            #[cfg(target_os = "linux")]
            (Self::Root(writer), JournalAppendStageV1::Root(Some(stage))) =>
                writer.expected_append_length_once(stage).map_err(|_| ()),
            #[cfg(target_os = "linux")]
            (Self::Source(writer), JournalAppendStageV1::Source(Some(stage))) =>
                writer.expected_append_length_once(stage).map_err(|_| ()),
            _ => Err(()),
        };
        match result {
            Ok(value) => Ok(value),
            Err(()) => Err(stage.take_failure()),
        }
    }

    pub(super) fn append_prepared(
        &mut self,
        stage: &mut JournalAppendStageV1<'_>,
    ) -> Result<u64, JournalError> {
        let result = match (self, &mut *stage) {
            (Self::Ordinary(ordinary), JournalAppendStageV1::Ordinary(Some(stage))) =>
                ordinary.held.append_prepared_once(stage).map_err(|_| ()),
            #[cfg(target_os = "linux")]
            (Self::Controller(writer), JournalAppendStageV1::Controller(Some(stage))) =>
                writer.append_prepared_once(stage).map_err(|_| ()),
            #[cfg(target_os = "linux")]
            (Self::Root(writer), JournalAppendStageV1::Root(Some(stage))) =>
                writer.append_prepared_once(stage).map_err(|_| ()),
            #[cfg(target_os = "linux")]
            (Self::Source(writer), JournalAppendStageV1::Source(Some(stage))) =>
                writer.append_prepared_once(stage).map_err(|_| ()),
            _ => Err(()),
        };
        match result {
            Ok(value) => Ok(value),
            Err(()) => Err(stage.take_failure()),
        }
    }

    pub(super) fn apply_next_record(
        &mut self,
        stage: &mut JournalAppendStageV1<'_>,
    ) -> Result<bool, JournalError> {
        let result = match (self, &mut *stage) {
            (Self::Ordinary(ordinary), JournalAppendStageV1::Ordinary(Some(stage))) =>
                ordinary.held.apply_next_record_once(stage).map_err(|_| ()),
            #[cfg(target_os = "linux")]
            (Self::Controller(writer), JournalAppendStageV1::Controller(Some(stage))) =>
                writer.apply_next_record_once(stage).map_err(|_| ()),
            #[cfg(target_os = "linux")]
            (Self::Root(writer), JournalAppendStageV1::Root(Some(stage))) =>
                writer.apply_next_record_once(stage).map_err(|_| ()),
            #[cfg(target_os = "linux")]
            (Self::Source(writer), JournalAppendStageV1::Source(Some(stage))) =>
                writer.apply_next_record_once(stage).map_err(|_| ()),
            _ => Err(()),
        };
        match result {
            Ok(value) => Ok(value),
            Err(()) => Err(stage.take_failure()),
        }
    }

    pub(super) fn publish_append(
        &mut self,
        stage: &mut JournalAppendStageV1<'_>,
    ) -> Result<CanonicalAppendPublishedDataV1, JournalError> {
        let result = match (self, &mut *stage) {
            (Self::Ordinary(ordinary), JournalAppendStageV1::Ordinary(Some(stage))) =>
                ordinary.held.publish_append_once(stage).map_err(|_| ()),
            #[cfg(target_os = "linux")]
            (Self::Controller(writer), JournalAppendStageV1::Controller(Some(stage))) =>
                writer.publish_append_once(stage).map_err(|_| ()),
            #[cfg(target_os = "linux")]
            (Self::Root(writer), JournalAppendStageV1::Root(Some(stage))) =>
                writer.publish_append_once(stage).map_err(|_| ()),
            #[cfg(target_os = "linux")]
            (Self::Source(writer), JournalAppendStageV1::Source(Some(stage))) =>
                writer.publish_append_once(stage).map_err(|_| ()),
            _ => Err(()),
        };
        match result {
            Ok(value) => Ok(value),
            Err(()) => Err(stage.take_failure()),
        }
    }

    pub(super) fn finish_append_after_posts(
        &mut self,
        stage: &mut JournalAppendStageV1<'_>,
    ) -> Result<(), JournalError> {
        let result = match (self, &mut *stage) {
            (Self::Ordinary(ordinary), JournalAppendStageV1::Ordinary(Some(stage))) =>
                ordinary.held.finish_append_after_posts_once(stage).map_err(|_| ()),
            #[cfg(target_os = "linux")]
            (Self::Controller(writer), JournalAppendStageV1::Controller(Some(stage))) =>
                writer.finish_append_after_posts_once(stage).map_err(|_| ()),
            #[cfg(target_os = "linux")]
            (Self::Root(writer), JournalAppendStageV1::Root(Some(stage))) =>
                writer.finish_append_after_posts_once(stage).map_err(|_| ()),
            #[cfg(target_os = "linux")]
            (Self::Source(writer), JournalAppendStageV1::Source(Some(stage))) =>
                writer.finish_append_after_posts_once(stage).map_err(|_| ()),
            _ => Err(()),
        };
        match result {
            Ok(value) => Ok(value),
            Err(()) => Err(stage.take_failure()),
        }
    }
}
