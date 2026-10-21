//! Borrows one real Current replay while its same Audit stays immutable.
//!
//! The suffix and physical accepted observer are constructed at their original
//! frontier. A fresh actual Initial/L check follows that constructor and precedes
//! the native cursor. The body always retains its prefix post and tail outcome.

use aos_sandbox_protocol::domain_ledger::create_storage_history::native_suffix::controller::ControllerHistoryNativeSuffixV1;

use super::super::readonly_receiving::RootCurrentReadonlyReceivingContextV1;
use super::prepared::RootInitialControllerReadonlyPreparedBorrowV1;
use super::*;
use crate::native::readonly::RootCurrentReplayFieldsBorrowV1;
use crate::native::startup::RootStartupControllerPeerOriginalV1;

/// Borrows Initial's actual disjoint replay fields and live receiving context.
///
/// Private fields come only from the same prepared Controller owner. This loan
/// owns no cloned Audit, caller-supplied successful admission or replacement file.
pub struct RootInitialControllerReadonlyReplayBorrowV1<'turn, 'startup> {
    replay: RootCurrentReplayFieldsBorrowV1<'turn>,
    receiving: RootCurrentReadonlyReceivingContextV1<'turn, 'turn, 'turn>,
    semantic: &'turn RootInitialStageOriginalV1,
    open: &'turn RootInitialOpenPreparedOriginalV1,
    producer: &'turn RootStartupControllerPeerOriginalV1<'startup>,
    ran: bool,
    primary: &'turn mut Slot<(), E>,
}

impl<'scope, 'startup, 'inputs>
    RootInitialControllerReadonlyPreparedBorrowV1<'scope, 'startup, 'inputs>
{
    /// Constructs the exact suffix and physical observer before the live EOF gate.
    ///
    /// # Errors
    /// Retains semantic-stage, repeat, expected-recipe, suffix or original-row refusal.
    pub fn borrow_replay_once_v1(
        &mut self,
    ) -> Result<RootInitialControllerReadonlyReplayBorrowV1<'_, 'startup>, E> {
        macro_rules! retain_primary {
            ($expression:expr) => {
                match $expression {
                    Ok(value) => value,
                    Err(_) => {
                        self.state.primary.get_or_insert(Err(E::Incomplete));
                        return Err(E::Incomplete);
                    }
                }
            };
        }
        retain_primary!(self.state.semantic.require_complete_v1());
        if self.state.replay_borrowed || self.state.closed {
            self.state.closed = true;
            return Err(E::Incomplete);
        }
        self.state.replay_borrowed = true;
        let (replay, receiving) = match self.purpose {
            RootControllerPurposeBorrowV1::Initial => {
                let [first, second, ..] = &mut self.state.previous_progress;
                let suffix = ControllerHistoryNativeSuffixV1::new(
                    [
                        retain_primary!(positive(&self.state.previous_expected[0])),
                        retain_primary!(positive(&self.state.previous_expected[1])),
                        retain_primary!(positive(&self.state.expected)),
                    ],
                    [first, second, &mut self.state.suffix_progress],
                    &mut self.state.suffix_active,
                    retain_primary!(positive(&self.state.history_geometry)).positions,
                );
                let suffix = match suffix {
                    Ok(suffix) => {
                        self.state.suffix_construction = Some(Ok(()));
                        suffix
                    }
                    Err(cause) => {
                        self.state.suffix_construction = Some(Err(cause));
                        self.state.primary.get_or_insert(Err(E::Incomplete));
                        return Err(E::Incomplete);
                    }
                };
                let (original, admission) = retain_primary!(
                    crate::controller_history_data::decode_replay_original_v1(self.bundle)
                );
                let (replay, audit) = self.state.reader.borrow_current_replay_fields_v1();
                let receiving = self.state.receiving.replay_v1(
                    audit,
                    suffix,
                    original,
                    admission,
                    &mut self.state.accepted_native,
                );
                (replay, receiving)
            }
            RootControllerPurposeBorrowV1::Reserved { received, .. } => {
                let expected = retain_primary!(received.expected_v1());
                let tail = retain_primary!(received.positions_v1());
                let initial = retain_primary!(positive(&self.state.history_geometry)).positions;
                if initial[3] != tail[0] {
                    self.state.primary.get_or_insert(Err(E::Incomplete));
                    return Err(E::Incomplete);
                }
                let positions = [
                    initial[0], initial[1], initial[2], initial[3], tail[1], tail[2], tail[3],
                ];
                let [p0, p1, p2, p3, p4, ..] = &mut self.state.previous_progress;
                let suffix = ControllerHistoryNativeSuffixV1::<6>::new_reserved(
                    [
                        retain_primary!(positive(&self.state.previous_expected[0])),
                        retain_primary!(positive(&self.state.previous_expected[1])),
                        retain_primary!(positive(&self.state.expected)),
                        expected[0],
                        expected[1],
                        expected[2],
                    ],
                    [p0, p1, p2, p3, p4, &mut self.state.suffix_progress],
                    &mut self.state.suffix_active,
                    positions,
                );
                let suffix = match suffix {
                    Ok(suffix) => {
                        self.state.suffix_construction = Some(Ok(()));
                        suffix
                    }
                    Err(cause) => {
                        self.state.suffix_construction = Some(Err(cause));
                        self.state.primary.get_or_insert(Err(E::Incomplete));
                        return Err(E::Incomplete);
                    }
                };
                let (original, admission) = retain_primary!(
                    crate::controller_history_data::decode_replay_original_v1(self.bundle)
                );
                let (replay, audit) = self.state.reader.borrow_current_replay_fields_v1();
                let reserved = retain_primary!(
                    retain_primary!(received.receipt_v1(self.bundle.lane)).body(self.bundle.lane)
                );
                let receiving = self.state.receiving.replay_reserved_v1(
                    audit,
                    suffix,
                    original,
                    admission,
                    reserved,
                    &mut self.state.accepted_native,
                );
                (replay, receiving)
            }
            RootControllerPurposeBorrowV1::Signed { received, .. } => {
                let expected = retain_primary!(received.expected_v1());
                let tail = retain_primary!(received.positions_v1());
                let initial = retain_primary!(positive(&self.state.history_geometry)).positions;
                let later = retain_primary!(self.state.signed_suffix.positions_v1());
                if initial[3] != tail[0] || tail[3] != later[0] {
                    self.state.primary.get_or_insert(Err(E::Incomplete)); return Err(E::Incomplete);
                }
                let positions = [initial[0],initial[1],initial[2],initial[3],tail[1],tail[2],tail[3],later[1]];
                let [p0,p1,p2,p3,p4,p5,..] = &mut self.state.previous_progress;
                let suffix = ControllerHistoryNativeSuffixV1::<7>::new_signed(
                    [retain_primary!(positive(&self.state.previous_expected[0])),
                     retain_primary!(positive(&self.state.previous_expected[1])),
                     retain_primary!(positive(&self.state.expected)),expected[0],expected[1],expected[2],
                     retain_primary!(self.state.signed_suffix.expected_v1())],
                    [p0,p1,p2,p3,p4,p5,&mut self.state.suffix_progress], &mut self.state.suffix_active, positions);
                let suffix = match suffix {
                    Ok(suffix) => { self.state.suffix_construction = Some(Ok(())); suffix }
                    Err(cause) => { self.state.suffix_construction = Some(Err(cause));
                        self.state.primary.get_or_insert(Err(E::Incomplete)); return Err(E::Incomplete); }
                };
                let (original, admission) = retain_primary!(crate::controller_history_data::decode_replay_original_v1(self.bundle));
                let (replay, audit) = self.state.reader.borrow_current_replay_fields_v1();
                let reserved = retain_primary!(retain_primary!(received.receipt_v1(self.bundle.lane)).body(self.bundle.lane));
                let receiving = self.state.receiving.replay_signed_v1(
                    audit, suffix, original, admission, reserved, &mut self.state.accepted_native,
                );
                (replay, receiving)
            }
            RootControllerPurposeBorrowV1::Outcome { received, .. } => {
                let expected = retain_primary!(received.expected_v1());
                let tail = retain_primary!(received.positions_v1());
                let initial = retain_primary!(positive(&self.state.history_geometry)).positions;
                let continuation = retain_primary!(self.state.outcome_suffix.expected_v1());
                let later = retain_primary!(self.state.outcome_suffix.positions_v1());
                if initial[3] != tail[0] || tail[3] != later[0] {
                    self.state.primary.get_or_insert(Err(E::Incomplete)); return Err(E::Incomplete);
                }
                let positions = [initial[0],initial[1],initial[2],initial[3],tail[1],tail[2],tail[3],later[1],later[2],later[3],later[4]];
                let [p0,p1,p2,p3,p4,p5,p6,p7,p8,..] = &mut self.state.previous_progress;
                let suffix = ControllerHistoryNativeSuffixV1::<10>::new_outcome(
                    [retain_primary!(positive(&self.state.previous_expected[0])),
                     retain_primary!(positive(&self.state.previous_expected[1])),
                     retain_primary!(positive(&self.state.expected)),expected[0],expected[1],expected[2],
                     continuation[0],continuation[1],continuation[2],continuation[3]],
                    [p0,p1,p2,p3,p4,p5,p6,p7,p8,&mut self.state.suffix_progress], &mut self.state.suffix_active, positions);
                let suffix = match suffix {
                    Ok(suffix) => { self.state.suffix_construction = Some(Ok(())); suffix }
                    Err(cause) => { self.state.suffix_construction = Some(Err(cause));
                        self.state.primary.get_or_insert(Err(E::Incomplete)); return Err(E::Incomplete); }
                };
                let (original, admission) = retain_primary!(crate::controller_history_data::decode_replay_original_v1(self.bundle));
                let (replay, audit) = self.state.reader.borrow_current_replay_fields_v1();
                let reserved = retain_primary!(retain_primary!(received.receipt_v1(self.bundle.lane)).body(self.bundle.lane));
                let receiving = self.state.receiving.replay_outcome_v1(
                    audit, suffix, original, admission, reserved, &mut self.state.accepted_native,
                );
                (replay, receiving)
            }
            RootControllerPurposeBorrowV1::Closed { received, outcome, .. } => {
                let expected = retain_primary!(received.expected_v1());
                let tail = retain_primary!(received.positions_v1());
                let initial = retain_primary!(positive(&self.state.history_geometry)).positions;
                let prior = retain_primary!(retain_primary!(outcome.completed_controller_v1()).outcome_suffix_v1());
                let continuation = retain_primary!(prior.expected_v1());
                let later = retain_primary!(prior.positions_v1());
                let final_pairs = retain_primary!(self.state.closed_suffix.expected_v1());
                let closing = retain_primary!(self.state.closed_suffix.positions_v1());
                if initial[3] != tail[0] || tail[3] != later[0] || later[4] != closing[0] {
                    self.state.primary.get_or_insert(Err(E::Incomplete)); return Err(E::Incomplete);
                }
                let positions = [initial[0],initial[1],initial[2],initial[3],tail[1],tail[2],tail[3],later[1],later[2],later[3],later[4],closing[1],closing[2]];
                let [p0,p1,p2,p3,p4,p5,p6,p7,p8,p9,p10] = &mut self.state.previous_progress;
                let binding = retain_primary!(aos_sandbox_protocol::domain_ledger::resource_bank::CreateStorageUseBindingV1::decode(
                    retain_primary!(retain_primary!(received.receipt_v1(self.bundle.lane)).body(self.bundle.lane)).binding,
                ).map_err(|_| E::Incomplete));
                let suffix = ControllerHistoryNativeSuffixV1::<12>::new_closed(
                    [retain_primary!(positive(&self.state.previous_expected[0])),
                     retain_primary!(positive(&self.state.previous_expected[1])),
                     retain_primary!(positive(&self.state.expected)),expected[0],expected[1],expected[2],
                     continuation[0],continuation[1],continuation[2],continuation[3],final_pairs[0],final_pairs[1]],
                    [p0,p1,p2,p3,p4,p5,p6,p7,p8,p9,p10,&mut self.state.suffix_progress], &mut self.state.suffix_active, positions, binding);
                let suffix = match suffix {
                    Ok(suffix) => { self.state.suffix_construction = Some(Ok(())); suffix }
                    Err(cause) => { self.state.suffix_construction = Some(Err(cause));
                        self.state.primary.get_or_insert(Err(E::Incomplete)); return Err(E::Incomplete); }
                };
                let (original, admission) = retain_primary!(crate::controller_history_data::decode_replay_original_v1(self.bundle));
                let (replay, audit) = self.state.reader.borrow_current_replay_fields_v1();
                let reserved = retain_primary!(retain_primary!(received.receipt_v1(self.bundle.lane)).body(self.bundle.lane));
                let receiving = self.state.receiving.replay_closed_v1(
                    audit, suffix, original, admission, reserved, &mut self.state.accepted_native,
                );
                (replay, receiving)
            }
        };
        Ok(RootInitialControllerReadonlyReplayBorrowV1 {
            replay,
            receiving,
            semantic: &self.state.semantic,
            open: self.open,
            producer: &self.originals.peer,
            ran: false,
            primary: &mut self.state.primary,
        })
    }
}

impl RootInitialControllerReadonlyReplayBorrowV1<'_, '_> {
    /// Borrows the first retained cause from this actual replay and context.
    ///
    /// An actual context refusal precedes its mapped reader marker. Otherwise
    /// the same cursor/Cold/prefix/tail originals keep their original priority.
    /// No observation, result adoption or programme reborrow occurs.
    #[must_use]
    pub fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        let context = self.receiving.failure_v1();
        if context.is_some() {
            context
        } else {
            self.replay.failure_v1().or_else(|| cause(self.primary))
        }
    }

    /// Repeats the actual semantic-stage receiver check before the native cursor.
    ///
    /// The caller still invokes `replay_once_v1` after this admission refuses:
    /// that same entered body owes the independent retained prefix observation.
    ///
    /// # Errors
    /// Retains genuine predecessor, same-Initial, repeated or semantic-stage refusal.
    pub fn admit_captured_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        if self.ran {
            self.replay.refuse_reentry_once_v1();
            initial.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        }
        let mut predecessor = match self.producer.borrow_current_writers_predecessor_v1(initial) {
            Ok(predecessor) => predecessor,
            Err(error) => {
                self.receiving
                    .park_captured_live_predecessor_refusal_v1(error);
                initial.latch_root_refusal_v1();
                return Err(RootObservationErrorV1::Service);
            }
        };
        let (initial, financial) = predecessor.split_initial_v1();
        self.receiving.admit_captured_live_once_v1(
            initial,
            self.open,
            self.semantic,
            financial,
            exclusion,
        )
    }

    /// Parks an upper lock/borrow refusal without suppressing the owed prefix post.
    pub fn refuse_captured_entry_once_v1(&mut self) {
        self.receiving.refuse_captured_live_entry_once_v1();
    }

    /// Runs the same actual Current COMMIT/EOF engine and independent prefix post.
    ///
    /// # Errors
    /// Retains captured-end admission, native parser, semantic, accepted-history,
    /// suffix, prefix-post or tail refusal. No Common fallback is available.
    pub fn replay_once_v1(&mut self) -> Result<(), E> {
        if self.ran {
            self.replay.refuse_reentry_once_v1();
            return Err(E::Incomplete);
        }
        self.ran = true;
        if !self.replay.replay_once_v1(&mut self.receiving) {
            self.primary.get_or_insert(Err(E::Incomplete));
            return Err(E::Incomplete);
        }
        let result = self.replay.require_complete_v1().map_err(E::from);
        if result.is_err() {
            self.primary.get_or_insert(Err(E::Incomplete));
        }
        result
    }
}
