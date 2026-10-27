//! Runs genuine administrative recapture after separate full settled admission.
//!
//! Independent current checkpoint construction and a whole-owner observation
//! precede the mutable Runtime loan for owner callbacks and persistence.
//! A failed admission or Capture retains the Window's spent original and every
//! actual Source/native partial. No stored checkpoint creates Capture rights.

use super::*;
use crate::node_adapters::cnp::PacketCompleteOriginalHostSdk;
use crate::node_admission::{CompleteOriginalRestorationWindow, InstalledConformancePlan};
use crate::node_state::{NativeArchiveRecord, StateError};
use crucible_node_transport::reference_packet::service::PacketNative5SourceLaunch;

#[path = "restored_capture/scope.rs"]
mod scope;
pub use scope::RestoredCollectingCaptureScope17;

impl ConformanceRuntime {
    /// Captures a settled restored World through genuine owner reservations.
    ///
    /// This path requires explicit settled codecs installed before launch, real
    /// current Source proofs, actual mutable-owner census and the independently
    /// admitted archive geometry. Immutable first lineage remains separate from
    /// new operation history. Native effects still require real Capture tickets.
    ///
    /// # Errors
    /// Refuses unsupported or foreign owners, unsettled operations/inspections,
    /// exhausted limits, incomplete admission, changed current proofs or failed
    /// capture/persistence. The same failed attempt and custody remain retained.
    pub fn capture_complete_restored_lineage(
        &mut self,
        window: &Rc<CompleteOriginalRestorationWindow>,
        plan: &InstalledConformancePlan,
        sdks: [&PacketCompleteOriginalHostSdk; 3],
        launches: &[PacketNative5SourceLaunch; 3],
        raw5: [&[u8]; 3],
        request: CollectingOriginalLineageCaptureRequest<'_>,
    ) -> Result<NativeArchiveRecord, StateError> {
        self.authenticate_complete_original_restoration_origin()
            .map_err(crate::node_state::schema)?;
        let world = self
            .activation
            .as_ref()
            .ok_or_else(|| crate::node_state::schema(RuntimeError::NotActivated))?
            .clone();
        let host = Rc::clone(
            self.exact_inputs
                .as_ref()
                .ok_or_else(|| crate::node_state::schema(RuntimeError::UnsupportedFacet))?,
        );
        let (maximum, _) = window
            .current_observation_policy_data()
            .map_err(crate::node_state::schema)?;
        let limits = request.archive.original_restored_capture_limits_data();
        let maximum_record_bytes = limits
            .state
            .maximum_record_bytes
            .min(limits.native.maximum_record_bytes);
        let row = self
            .runtime
            .original_restored_capture_runtime_construction_data(
                &world,
                request.cut,
                request.ordinal,
                maximum_record_bytes,
                maximum,
            )
            .map_err(crate::node_state::schema)?;
        let boundary = self
            .runtime
            .original_restored_coordinator_capture_boundary_data(
                &world,
                request.cut,
                request.ordinal,
                &host,
                maximum,
            )
            .map_err(crate::node_state::schema)?;
        let CollectingOriginalLineageCaptureRequest {
            archive,
            cut,
            ordinal,
            capture_id,
            requirements,
            immutable,
            factory,
            lineage_limits,
        } = request;
        window
            .retain_restored_capture_preparation_data(
                self,
                &self.runtime,
                plan,
                &world,
                capture_id,
                cut,
                ordinal,
                row,
                boundary,
            )
            .map_err(crate::node_state::schema)?;
        // The passive stage uses only current originating owners and registered
        // identities. Its complete work is retained before a whole observer or
        // full Source validator may allocate a fresh validation bank.
        for selected in 0..3 {
            let node = window
                .restored_capture_node_data(selected)
                .map_err(crate::node_state::schema)?;
            let work = window
                .with_pending_restored_capture_request_data(|request| {
                    self.runtime.quote_original_restored_capture_prequote_data(
                        node,
                        &launches[selected],
                        raw5[selected],
                        request,
                        maximum,
                    )
                })
                .map_err(crate::node_state::schema)?;
            window
                .retain_restored_capture_prequote_data(selected, work)
                .map_err(crate::node_state::schema)?;
        }
        window
            .recheck_original_transaction_inputs_data(
                plan,
                sdks,
                launches,
                raw5,
                self,
                world.record(),
            )
            .map_err(crate::node_state::schema)?;

        // Every reservation retains its actual owners and invalidates the
        // whole observation. Reobserve before another Source may reserve.
        for selected in 0..3 {
            let node = window
                .restored_capture_node_data(selected)
                .map_err(crate::node_state::schema)?;
            window
                .with_pending_restored_capture_request_data(|request| {
                    self.runtime
                        .reserve_original_restored_capture_counting_banks_data(
                            node,
                            &launches[selected],
                            raw5[selected],
                            request,
                            maximum,
                        )
                })
                .map_err(crate::node_state::schema)?;
            window
                .recheck_original_transaction_inputs_data(
                    plan,
                    sdks,
                    launches,
                    raw5,
                    self,
                    world.record(),
                )
                .map_err(crate::node_state::schema)?;
        }

        for selected in 0..3 {
            let node = window
                .restored_capture_node_data(selected)
                .map_err(crate::node_state::schema)?;
            let row = window
                .with_pending_restored_capture_request_data(|request| {
                    self.runtime
                        .quote_original_restored_capture_construction_data(
                            node,
                            &launches[selected],
                            raw5[selected],
                            request,
                            maximum,
                        )
                })
                .map_err(crate::node_state::schema)?;
            window
                .retain_restored_capture_quote_data(selected, row)
                .map_err(crate::node_state::schema)?;
            window
                .recheck_original_transaction_inputs_data(
                    plan,
                    sdks,
                    launches,
                    raw5,
                    self,
                    world.record(),
                )
                .map_err(crate::node_state::schema)?;
        }
        let slot = window
            .append_restored_capture_after_census_data()
            .map_err(crate::node_state::schema)?;
        let attempt_guard = window
            .retain_restored_capture_attempt_guard_data(slot)
            .map_err(crate::node_state::schema)?;
        window
            .recheck_original_transaction_inputs_data(
                plan,
                sdks,
                launches,
                raw5,
                self,
                world.record(),
            )
            .map_err(crate::node_state::schema)?;
        window
            .construct_restored_capture_checkpoint_data(
                slot,
                &self.runtime,
                &world,
                &host,
                lineage_limits,
                maximum_record_bytes,
            )
            .map_err(crate::node_state::schema)?;
        window
            .recheck_original_transaction_inputs_data(
                plan,
                sdks,
                launches,
                raw5,
                self,
                world.record(),
            )
            .map_err(crate::node_state::schema)?;
        let capture_id = window
            .admitted_restored_capture_id_data(slot)
            .map_err(crate::node_state::schema)?;

        // Existing archive machinery constructs and retains the actual runtime
        // snapshot, canonical object, four owner tickets and partial captures.
        // A selected Node additionally requires the admitted Window claim; the
        // ordinary entry alone cannot select or enable the settled codec.
        let captured = self.capture_complete_original_lineage_with_prepared_data(
            CollectingOriginalLineageCaptureRequest {
                archive,
                cut,
                ordinal,
                capture_id,
                requirements,
                immutable,
                factory,
                lineage_limits,
            },
            Some(
                |runtime: &NodeRuntime,
                 host: &crate::node_contract::HostSchedulingSource,
                 runtime_object: &crate::node_scheduling::InputPayload,
                 scheduling_object: &crate::node_scheduling::InputPayload| {
                    window.join_restored_capture_writer_objects_data(
                        slot,
                        runtime,
                        &world,
                        host,
                        runtime_object,
                        scheduling_object,
                    )
                },
            ),
        )?;
        let world = self
            .activation
            .as_ref()
            .ok_or_else(|| crate::node_state::schema(RuntimeError::NotActivated))?;
        window
            .recheck_original_transaction_inputs_data(
                plan,
                sdks,
                launches,
                raw5,
                self,
                world.record(),
            )
            .map_err(crate::node_state::schema)?;
        window
            .complete_restored_capture_archive_data(slot)
            .map_err(crate::node_state::schema)?;
        window
            .recheck_original_transaction_inputs_data(
                plan,
                sdks,
                launches,
                raw5,
                self,
                world.record(),
            )
            .map_err(crate::node_state::schema)?;
        attempt_guard
            .complete_data()
            .map_err(crate::node_state::schema)?;
        Ok(captured)
    }
}
