//! Drives full Domain Session semantics on Network's actual fixed native capture.
//!
//! The same genuine Network opening loan prepays this owner, captured extent
//! and full semantic recipe. No path, file, replay callback, successful marker
//! or imported map can replace that borrowed original. The shared cold Session
//! engine subsequently consumes this exact private Journal.

use std::error::Error;

use aos_sandbox_broker::canonical_journal::coordinator::indexed_replay::CanonicalIndexedReplayErrorV1;
use aos_sandbox_broker::canonical_journal::network_opening::NetworkBrokerSessionCapturedJournalOpenV4;
use aos_sandbox_broker::canonical_journal::{
    CanonicalJournalInstanceDataV1, CanonicalOrdinaryHeldJournalV1,
    CanonicalOrdinaryOpeningOriginalsV1, NativeJournalDataErrorV1,
    RecoveryReport as NativeRecoveryReport,
};
use aos_sandbox_broker::receiving::NetworkServiceSessionOpeningLoanV4;
use aos_sandbox_core::{ResourceDimension as D, ResourceVector};

use aos_sandbox_ledger_replay::cold::ColdReplayOriginalV1;

use super::native_backing::Selection;
use super::native_interval::captured::CapturedAppendOwnerV1;
use super::semantic_remainder::{ColdSemanticRemainderOriginalV1, DomainSemanticRemainderDataV1};
use super::*;

type Semantic = ColdReplayOriginalV1<CanonicalIndexedReplayErrorV1>;

/// Retains full Session semantics around the same paid Network native opening.
///
/// Creating this empty destination performs no native operation. Its Journal
/// constructor is private and accepts only its own completed semantic remainder
/// and the same fixed capture's mechanical move.
pub struct NetworkSessionSemanticReplayOriginalV1 {
    semantic: Semantic,
    conversion: ColdSemanticRemainderOriginalV1,
    converted: Option<DomainSemanticRemainderDataV1>,
    opened: Option<(
        CanonicalOrdinaryHeldJournalV1<Selection, JournalAuthorityInstance>,
        NativeRecoveryReport,
    )>,
    captured: Option<CapturedAppendOwnerV1>,
    journal: Option<(Journal, RecoveryReport)>,
    native: Option<Result<(), NativeJournalDataErrorV1>>,
    body: Option<Result<(), JournalError>>,
    native_selected: bool,
    entered: bool,
    replay_started: bool,
    capture: Option<CanonicalJournalInstanceDataV1<()>>,
    reentry: Option<JournalError>,
}

impl NetworkSessionSemanticReplayOriginalV1 {
    /// Creates vacant semantic destinations without a writer or financial grant.
    #[must_use]
    pub fn new() -> Self {
        Self {
            semantic: Semantic::new(),
            conversion: ColdSemanticRemainderOriginalV1::new(),
            converted: None,
            opened: None,
            captured: None,
            journal: None,
            native: None,
            body: None,
            native_selected: false,
            entered: false,
            replay_started: false,
            capture: None,
            reentry: None,
        }
    }

    /// Prices the actual receiver, constructor and retained semantic headers.
    ///
    /// The genuine caller adds actual-prefix replay and Session schema demand
    /// before allocating this owner. This amount provides no funding by itself.
    ///
    /// # Errors
    /// Preserves checked representation and canonical supplier failures.
    pub fn receiving_demand_v1() -> Result<ResourceVector, JournalError> {
        // The fixed Network opening already pays unit held carriers. This
        // caller replaces that part with its actual selection/payload geometry,
        // while preserving the distinct early capture and late Domain marker.
        let common_unit =
            CanonicalOrdinaryOpeningOriginalsV1::<()>::receiving_payload_construction_bytes_v1::<(), ()>(
            )
            .ok_or(JournalError::JournalTooLarge)?;
        let common_domain =
            CanonicalOrdinaryOpeningOriginalsV1::<()>::receiving_payload_construction_bytes_v1::<
                Selection,
                JournalAuthorityInstance,
            >()
            .ok_or(JournalError::JournalTooLarge)?;
        let typed_delta = common_domain
            .checked_sub(common_unit)
            .ok_or(JournalError::JournalTooLarge)?;
        let memory = std::mem::size_of::<Self>()
            .checked_mul(2)
            .and_then(|bytes| {
                bytes.checked_add(Journal::ordinary_materialization_receiving_bytes_v1()?)
            })
            .and_then(|bytes| bytes.checked_add(typed_delta))
            .and_then(|bytes| {
                bytes.checked_add(
                CanonicalJournalInstanceDataV1::<JournalAuthorityInstance>::
                    payload_allocation_receiving_bytes_v1()?
            )
            })
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(JournalError::JournalTooLarge)?;
        Semantic::fixed_demand_v1()?
            .checked_add(ColdSemanticRemainderOriginalV1::receiving_demand_v1()?)?
            .checked_add(
                super::native_interval::captured::CapturedAppendOwnerV1::construction_demand_v1()
                    .ok_or(JournalError::JournalTooLarge)?,
            )?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, memory))
            .map_err(Into::into)
    }

    /// Prices the shared staged parser, key validator and actual resident index.
    ///
    /// This replaces the old native replay term for Network Session only;
    /// Domain's complete semantic models and Session schema remain additional.
    /// The same actual loan admits this amount before parser/index growth.
    ///
    /// # Errors
    /// Refuses missing captured extent or checked native/index geometry.
    pub fn native_receiving_demand_v1(
        opening: &NetworkBrokerSessionCapturedJournalOpenV4,
    ) -> Result<ResourceVector, JournalError> {
        let extent = opening
            .captured_extent()
            .copied()
            .ok_or(JournalError::ProtectedBoundary)?;
        let native = extent
            .dominant_native_receiving_demand_v1()
            .map_err(|cause| {
                JournalError::from(CanonicalJournalMechanicalErrorV1::from_ordinary_native_v1(
                    cause,
                ))
            })?;
        let codec = extent
            .dominant_semantic_receiving_demand_v1()
            .map_err(|cause| {
                JournalError::from(CanonicalJournalMechanicalErrorV1::from_ordinary_native_v1(
                    cause,
                ))
            })?;
        let index = aos_sandbox_broker::canonical_journal::coordinator::indexed_replay::
            CanonicalReplayIndexOriginalsV1::dynamic_demand_v1(extent)
            .map_err(|_| JournalError::JournalTooLarge)?;
        native
            .checked_add(codec)?
            .checked_add(index)
            .map_err(Into::into)
    }

    /// Replays the same fixed capture under its actual current Session lender.
    ///
    /// Independent owed native names run on every entered replay return. Tail
    /// repair and transfer occur only after the full semantic engine succeeds.
    pub fn observe_once(
        &mut self,
        opening: &mut NetworkBrokerSessionCapturedJournalOpenV4,
        loan: &mut NetworkServiceSessionOpeningLoanV4<'_>,
    ) {
        if self.entered {
            self.reentry.get_or_insert(JournalError::ProtectedBoundary);
            return;
        }
        self.entered = true;
        self.body = Some((|| {
            loan.require_network_session_opening_current_v4()
                .map_err(|_| JournalError::ProtectedBoundary)?;
            let extent = opening
                .captured_extent()
                .copied()
                .ok_or(JournalError::ProtectedBoundary)?;
            let limits = extent.limits();
            self.capture = opening.capture_identity_data_v1();
            if self.capture.is_none() {
                return Err(JournalError::ProtectedBoundary);
            }
            self.replay_started = true;
            let outcome = match opening.begin_replay_once() {
                Ok((identity, mut cursor)) => self
                    .semantic
                    .observe_indexed_once(&mut cursor, identity, limits)
                    .map_err(|_| JournalError::ProtectedBoundary),
                Err(cause) => {
                    self.native = Some(Err(cause));
                    Err(JournalError::ProtectedBoundary)
                }
            };
            // Select the original cause before the independent after can fail.
            self.native_selected = opening.failure().is_some();
            outcome?;
            self.native = Some(opening.finish_tail_once());
            if !matches!(self.native, Some(Ok(()))) {
                self.native_selected = opening.failure().is_some();
                return Err(JournalError::ProtectedBoundary);
            }
            Ok(())
        })());
        if self.replay_started {
            opening.observe_after_owed_once();
        }
    }

    /// Moves the actual completed full-semantic Journal once to the cold engine.
    #[must_use]
    pub fn take_opened_once(
        &mut self,
        opening: &mut NetworkBrokerSessionCapturedJournalOpenV4,
    ) -> Option<Journal> {
        if self.journal.is_none() {
            if !matches!(self.body, Some(Ok(())))
                || self.reentry.is_some()
                || !self
                    .capture
                    .as_ref()
                    .is_some_and(|identity| opening.same_capture_data_v1(identity))
                || opening.failure().is_some()
            {
                return None;
            }
            if self.converted.is_none() {
                if !self.conversion.entered() {
                    self.conversion
                        .observe_once(&mut self.semantic.take_remainder_once());
                }
                if !self.conversion.ready() {
                    return None;
                }
                self.converted = self.conversion.take_once();
            }
            self.converted.as_ref()?;

            if self.opened.is_none() {
                if self.captured.is_none() {
                    opening.prepare_held_transfer_once_v1()?;
                    // Native final checks and traversal retirement precede
                    // these same two captured-owner allocations. The distinct
                    // late Domain identity follows only after they are resident.
                    self.captured = Some(CapturedAppendOwnerV1::new(
                        "/var/lib/aos/sandbox-network/broker-session",
                        "session.journal",
                        0,
                    ));
                }
                self.opened = Some(
                    opening.take_prepared_held_with_independent_late_payload_once_v1(
                        runtime_deployment_history::OriginalCompactionSelectionV1::capture(
                            std::path::Path::new("/var/lib/aos/sandbox-network/broker-session"),
                            "session.journal",
                        ),
                        JournalAuthorityInstance,
                    )?,
                );
            }
            self.journal = Journal::from_actual_ordinary_held_v1(
                &mut self.opened,
                &mut self.converted,
                &mut self.captured,
            );
        }
        self.journal.take().map(|(journal, _)| journal)
    }

    /// Selects only a retained native cause owned by the borrowed capture.
    #[must_use]
    pub fn external_native_failure_selected_v1(
        &self,
        opening: &NetworkBrokerSessionCapturedJournalOpenV4,
    ) -> bool {
        self.native_selected || (matches!(self.body, Some(Ok(()))) && opening.failure().is_some())
    }

    /// Borrows this receiver's original semantic or local stopping cause.
    #[must_use]
    pub fn local_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.semantic
            .failure()
            .or_else(|| self.native.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.body.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.reentry.as_ref().map(|cause| cause as _))
            .or_else(|| self.conversion.failure())
    }

    /// Borrows the original selected cause before any later owed native failure.
    #[must_use]
    pub fn failure<'owner>(
        &'owner self,
        opening: &'owner NetworkBrokerSessionCapturedJournalOpenV4,
    ) -> Option<&'owner (dyn Error + 'static)> {
        if self.native_selected {
            opening.failure().or_else(|| self.semantic.failure())
        } else {
            self.semantic
                .failure()
                .or_else(|| self.native.as_ref()?.as_ref().err().map(|cause| cause as _))
                .or_else(|| self.body.as_ref()?.as_ref().err().map(|cause| cause as _))
                .or_else(|| self.reentry.as_ref().map(|cause| cause as _))
                .or_else(|| self.conversion.failure())
                .or_else(|| opening.failure())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retained_body_cause_precedes_later_capture_refusal_and_blocks_transfer() {
        let mut receiver = NetworkSessionSemanticReplayOriginalV1::new();
        let original = std::io::Error::other(std::io::Error::from_raw_os_error(9));
        let inner = original.get_ref().unwrap() as *const (dyn Error + Send + Sync);
        receiver.body = Some(Err(JournalError::Io(original)));
        let mut capture = NetworkBrokerSessionCapturedJournalOpenV4::new();

        // An out-of-order owed-after entry creates a later capture refusal
        // without any IO or a supplied financial/native positive marker.
        capture.observe_after_owed_once();
        assert!(capture.failure().is_some());
        let actual = receiver
            .failure(&capture)
            .unwrap()
            .downcast_ref::<JournalError>()
            .unwrap();
        let JournalError::Io(actual) = actual else {
            panic!("the first actual body error must remain selected");
        };

        assert!(std::ptr::addr_eq(
            inner,
            actual.get_ref().unwrap() as *const (dyn Error + Send + Sync)
        ));
        assert_eq!(
            actual
                .get_ref()
                .unwrap()
                .downcast_ref::<std::io::Error>()
                .unwrap()
                .raw_os_error(),
            Some(9)
        );
        assert!(receiver.take_opened_once(&mut capture).is_none());
    }

    #[test]
    fn an_unobserved_native_capture_cannot_supply_a_semantic_journal() {
        let mut receiver = NetworkSessionSemanticReplayOriginalV1::new();
        let mut capture = NetworkBrokerSessionCapturedJournalOpenV4::new();

        assert!(receiver.take_opened_once(&mut capture).is_none());
        assert!(capture.capture_identity_data_v1().is_none());
        assert!(receiver.journal.is_none());
    }
}
