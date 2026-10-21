//! Joins the same late Controller model to its accepted history and compilation.
//!
//! Initial archive observation follows every entered replay outcome before any
//! model query. The later row recipes are historical comparisons; actual held
//! custody remains on this same purpose, through its independent owed posts.

use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    RecordEnvelopeV1, controller_intent::ControllerIntentBodyDataV1,
};

use super::prepared::RootInitialControllerReadonlyPreparedBorrowV1;
use super::*;

impl RootInitialControllerReadonlyPreparedBorrowV1<'_, '_, '_> {
    /// Materializes the same replay and runs its original accepted/compiler checks.
    ///
    /// Call this after dropping the replay borrower, including on its returned
    /// error: the entered replay still owes its initial archived-name observation.
    ///
    /// # Errors
    /// Retains native replay, model/archive, exact cut, history, acceptance,
    /// Authority parent, publisher/compiler or independent Storage refusal.
    pub fn finish_replay_and_models_once_v1(&mut self) -> Result<(), E> {
        if self.state.model_compared || self.state.closed {
            self.state.closed = true;
            return Err(E::Incomplete);
        }
        if !self
            .state
            .reader
            .finish_current_replay_model_once_v1(&mut self.state.model)
        {
            self.state.primary.get_or_insert(Err(E::Incomplete));
            return Err(E::Incomplete);
        }
        self.state.model_compared = true;
        let result = self.compare_models_inner();
        if result.is_err() {
            self.state.primary.get_or_insert(Err(E::Incomplete));
        } else {
            self.state.primary.get_or_insert(Ok(()));
        }
        result
    }

    fn compare_models_inner(&mut self) -> Result<(), E> {
        if self.state.reader.failure().is_some() {
            return Err(E::Incomplete);
        }
        self.state.model.require_complete_v1()?;
        self.state.native_binding = Some(match self.purpose {
            RootControllerPurposeBorrowV1::Initial | RootControllerPurposeBorrowV1::Reserved { .. } => {

            self.state.model.require_current_controller_native_cut_v1(
                self.state.reader.current_audit_original_v1(),
                match self.purpose {
                    RootControllerPurposeBorrowV1::Initial => self.receipt.names,
                    RootControllerPurposeBorrowV1::Reserved { received, .. } => {
                        received
                            .receipt_v1(self.bundle.lane)
                            .map_err(|_| E::Incomplete)?
                            .names
                    }
                    _ => return Err(E::Incomplete),
                },
                match self.purpose {
                    RootControllerPurposeBorrowV1::Initial => self.receipt.after_next,
                    RootControllerPurposeBorrowV1::Reserved { received, .. } => {
                        received
                            .receipt_v1(self.bundle.lane)
                            .map_err(|_| E::Incomplete)?
                            .after_next
                    }
                    _ => return Err(E::Incomplete),
                },
                self.purpose.after_end_v1(self.bundle.lane, self.receipt, self.state)?,
            )
            }
            RootControllerPurposeBorrowV1::Signed { received, .. } => {
                let names = received.receipt_v1(self.bundle.lane).map_err(|_| E::Incomplete)?.names;
                let position = self.state.signed_suffix.positions_v1()?[1];
                self.state.model.require_current_controller_native_cut_v1(
                    self.state.reader.current_audit_original_v1(), names, position.0, position.1,
                )
            }
            RootControllerPurposeBorrowV1::Outcome { input, .. } => {
                let receipt = input.recorded_receipt_v1(self.bundle.lane).map_err(|_| E::Incomplete)?;
                self.state.model.require_current_controller_native_cut_v1(
                    self.state.reader.current_audit_original_v1(), receipt.names, receipt.after_next, receipt.after_end,
                )
            }
            RootControllerPurposeBorrowV1::Closed { input, .. } => {
                let receipt = input.controller_receipt_v1(self.bundle.lane).map_err(|_| E::Incomplete)?;
                self.state.model.require_current_controller_native_cut_v1(
                    self.state.reader.current_audit_original_v1(), receipt.names, receipt.after_next, receipt.after_end,
                )
            }
        });
        positive(&self.state.native_binding)?;
        // This second framing call remains at the old post-materialization
        // frontier. The earlier cached framing spans all receiving intervals.
        let raw = self.ready.raw_ready_bytes_v1()?;
        let bundle =
            ReadyBundleDataV1::borrow_field_framing_data_v1(raw).map_err(|_| E::Incomplete)?;
        self.state.history_binding = Some(match self.purpose {
            RootControllerPurposeBorrowV1::Initial => {
                crate::controller_history_data::require_bundle_history_data_v1(
                    self.state.model.raw_state_v1()?,
                    bundle.lane,
                    bundle.intent_record,
                    bundle.assignment_planned,
                    self.receipt,
                )
                .map_err(ReadError::from)
            }
            RootControllerPurposeBorrowV1::Reserved { received, .. } => {
                let expected = received.expected_v1().map_err(|_| E::Incomplete)?;
                let receipt = received
                    .receipt_v1(bundle.lane)
                    .map_err(|_| E::Incomplete)?;
                let [record, _] = expected[0].records() else {
                    return Err(E::Incomplete);
                };
                crate::controller_history_data::require_lane_history_data_v1(
                    self.state.model.raw_state_v1()?,
                    bundle.lane,
                    [
                        (
                            KeyV1::new(bundle.lane, OwnerV1::Controller, 1),
                            bundle.intent_record,
                        ),
                        (
                            KeyV1::new(bundle.lane, OwnerV1::Controller, 2),
                            bundle.assignment_planned,
                        ),
                        (
                            KeyV1::new(bundle.lane, OwnerV1::Controller, 3),
                            self.receipt.record.as_slice(),
                        ),
                        (
                            KeyV1::new(bundle.lane, OwnerV1::Controller, 4),
                            record.value().ok_or(E::Incomplete)?,
                        ),
                        (
                            KeyV1::new(bundle.lane, OwnerV1::Controller, 5),
                            receipt.record.as_slice(),
                        ),
                        (
                            KeyV1::new(bundle.lane, OwnerV1::Controller, 0),
                            receipt.latest_head.as_slice(),
                        ),
                    ],
                )
                .map_err(ReadError::from)
            }
            RootControllerPurposeBorrowV1::Signed { received, .. } => {
                self.state.model.require_healthy_v1()?;
                let expected = received.expected_v1().map_err(|_| E::Incomplete)?;
                let receipt = received.receipt_v1(bundle.lane).map_err(|_| E::Incomplete)?;
                let [validated, _] = expected[0].records() else { return Err(E::Incomplete); };
                let [signed, head] = self.state.signed_suffix.expected_v1()?.records() else { return Err(E::Incomplete); };
                crate::controller_history_data::require_lane_history_data_v1(
                    self.state.model.raw_state_v1()?, bundle.lane, [
                        (KeyV1::new(bundle.lane, OwnerV1::Controller, 1), bundle.intent_record),
                        (KeyV1::new(bundle.lane, OwnerV1::Controller, 2), bundle.assignment_planned),
                        (KeyV1::new(bundle.lane, OwnerV1::Controller, 3), self.receipt.record.as_slice()),
                        (KeyV1::new(bundle.lane, OwnerV1::Controller, 4), validated.value().ok_or(E::Incomplete)?),
                        (KeyV1::new(bundle.lane, OwnerV1::Controller, 5), receipt.record.as_slice()),
                        (KeyV1::new(bundle.lane, OwnerV1::Controller, 6), signed.value().ok_or(E::Incomplete)?),
                        (KeyV1::new(bundle.lane, OwnerV1::Controller, 0), head.value().ok_or(E::Incomplete)?),
                    ],
                ).map_err(ReadError::from)
            }
            RootControllerPurposeBorrowV1::Outcome { input, .. } => {
                self.state.model.require_healthy_v1()?;
                crate::controller_history_data::require_continuation_history_data_v1(
                    self.state.model.raw_state_v1()?, bundle.lane,
                    input.recorded_receipt_v1(bundle.lane).map_err(|_| E::Incomplete)?,
                    self.state.outcome_suffix.expected_v1()?,
                ).map_err(ReadError::from)
            }
            RootControllerPurposeBorrowV1::Closed { outcome, input, .. } => {
                let prior = outcome.completed_controller_v1().map_err(|_| E::Incomplete)?.outcome_suffix_v1()?.expected_v1()?;
                let tail = self.state.closed_suffix.expected_v1()?;
                self.state.model.require_healthy_v1()?;
                crate::controller_history_data::require_continuation_history_data_v1(
                    self.state.model.raw_state_v1()?, bundle.lane,
                    input.controller_receipt_v1(bundle.lane).map_err(|_| E::Incomplete)?,
                    [prior[0],prior[1],prior[2],prior[3],tail[1]],
                ).map_err(ReadError::from)
            }
        });
        positive(&self.state.history_binding)?;
        self.state.model.require_healthy_v1()?;
        let key = KeyV1::new(bundle.lane, OwnerV1::Controller, 1).map_err(|_| E::Incomplete)?;
        let phase = PhaseV1::new(OwnerV1::Controller, 1).map_err(|_| E::Incomplete)?;
        let intent = RecordEnvelopeV1::decode(bundle.intent_record, key, phase)
            .map_err(|_| E::Incomplete)?;
        let original =
            ControllerIntentBodyDataV1::decode(intent.body()).map_err(|_| E::Incomplete)?;
        self.state
            .accepted_create
            .observe_once(self.state.model.raw_state_v1()?, original);
        self.state
            .accepted_create
            .require_complete()
            .map_err(|_| E::Incomplete)?;
        self.state
            .accepted_native
            .require_complete()
            .map_err(|_| E::Incomplete)?;
        let identity = self
            .state
            .accepted_create
            .identity_v1()
            .map_err(|_| E::Incomplete)?;
        let root_final = self
            .state
            .accepted_create
            .root_final_v1()
            .map_err(|_| E::Incomplete)?;
        let (authority, _) = self
            .writers
            .opened_pair_view_v1()
            .map_err(|_| E::Incomplete)?;
        self.state.root_parent_result = Some(self.state.root_parent.observe_original_parent_once(
            authority.historical_read_view_v1().materialized_state_v1(),
            identity,
            root_final,
        ));
        positive(&self.state.root_parent_result)?;
        let (_, policy) = self
            .writers
            .opened_pair_view_v1()
            .map_err(|_| E::Incomplete)?;
        let source_fields = self.source.fields_v1().map_err(|_| E::Incomplete)?;
        let cache_body = self.cache.verified_body_v1()?;
        let manifest = self
            .ownership
            .completed_manifest_v1()
            .map_err(|_| E::Incomplete)?;
        let now = positive(&self.state.before_sample)?.wall_seconds();
        self.state.compiled.observe_once(
            &self.state.model,
            policy,
            self.policy_data,
            source_fields,
            cache_body,
            bundle,
            identity,
            manifest,
            now,
        );
        self.state
            .compiled
            .require_complete()
            .map_err(|_| E::Incomplete)?;
        let candidate = self
            .state
            .compiled
            .candidate_v1()
            .map_err(|_| E::Incomplete)?;
        let body = self.open.body_v1()?;
        self.state.storage_inventory.observe_once(
            bundle,
            manifest,
            candidate,
            *positive(&self.state.before_sample)?,
            aos_sandbox_protocol::PeerCredentials {
                uid: body.controller_uid,
                gid: body.controller_gid,
                pid: Some(body.controller_pid),
            },
            self.ownership
                .completed_response_v1()
                .map_err(|_| E::Incomplete)?
                .value()
                .ok_or(E::Incomplete)?,
            self.state
                .compiled
                .expires_at_v1()
                .map_err(|_| E::Incomplete)?,
            body.cutoff,
        );
        if self.state.storage_inventory.failure().is_some() {
            Err(E::Incomplete)
        } else {
            Ok(())
        }
    }
}
