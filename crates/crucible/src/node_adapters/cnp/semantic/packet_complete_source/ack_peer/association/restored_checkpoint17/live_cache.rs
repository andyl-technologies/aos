//! Lends live completed caches beneath the exact same armed Source read.
//!
//! The successful private constructors already authenticated the Source key,
//! complete native proof and literal SDK pair before freezing their typed
//! caches. This path borrows those same live owners; it neither redecodes them
//! nor accepts historical DATA as a completion. Currentness still belongs to
//! the actual read token, immutable actor and unique saved Session frontier.

use super::*;
use crate::node_adapters::cnp::semantic::process::{
    FreshCurrentScratch, OriginalFreshQueryReadCall,
};
use crucible_node_provider::reference_packet::service::complete_restore::activation::PacketRestorationActivationScope;
use crucible_node_provider::{ProviderError, envelope::Envelope};
use std::mem::size_of;

/// Borrows actual completed-cache geometry without claiming native currentness.
///
/// These private frozen owners and SDK cuts can be counted before allocating
/// native read scratch. The result supplies DATA only: the actual effect must
/// acquire the independently funded original read and compare its complete
/// correspondence again. Historical DATA never constructs these live owners.
pub(in crate::node_adapters::cnp::semantic) struct OriginalCompletedCheckpoint17GeometryData<'a> {
    scope: &'a PacketRestorationActivationScope,
    scope_binding: [u8; 32],
    first_observation: &'a ContentRef,
    first_frontier: U64,
    record: &'a PacketNativeRestoredRecord,
    underlying: &'a PacketNative5UnderlyingRecord,
    measurement: &'a ContentRef,
    frontier: U64,
}

impl OriginalCompletedCheckpoint17GeometryData<'_> {
    /// Borrows the actual current-generation first SDK scope.
    pub(in crate::node_adapters::cnp::semantic) fn scope_data(
        &self,
    ) -> &PacketRestorationActivationScope {
        self.scope
    }

    /// Returns the private first-owner scope commitment established at completion.
    pub(in crate::node_adapters::cnp::semantic) fn scope_binding_data(&self) -> [u8; 32] {
        self.scope_binding
    }

    /// Borrows the genuine first observation as immutable ancestry.
    pub(in crate::node_adapters::cnp::semantic) fn first_observation_data(&self) -> &ContentRef {
        self.first_observation
    }

    /// Returns the first owner's saved SDK cut independently of the latest cut.
    pub(in crate::node_adapters::cnp::semantic) const fn first_completed_frontier_data(
        &self,
    ) -> U64 {
        self.first_frontier
    }

    /// Borrows the same live completed restored record.
    pub(in crate::node_adapters::cnp::semantic) fn record_data(
        &self,
    ) -> &PacketNativeRestoredRecord {
        self.record
    }

    /// Borrows its same retained complete native model.
    pub(in crate::node_adapters::cnp::semantic) fn underlying_data(
        &self,
    ) -> &PacketNative5UnderlyingRecord {
        self.underlying
    }

    /// Borrows the actual complete current restored proof identity.
    pub(in crate::node_adapters::cnp::semantic) fn measurement_data(&self) -> &ContentRef {
        self.measurement
    }

    /// Returns the actual saved SDK cut after complete proof receipt.
    pub(in crate::node_adapters::cnp::semantic) const fn completed_frontier_data(&self) -> U64 {
        self.frontier
    }
}

/// Borrows the same completed geometry under its actual armed Source read.
///
/// This type has no constructor outside the token-checked defining callback.
pub(in crate::node_adapters::cnp::semantic) struct OriginalLiveCompletedCheckpoint17Data<'a> {
    geometry: OriginalCompletedCheckpoint17GeometryData<'a>,
}

impl OriginalLiveCompletedCheckpoint17Data<'_> {
    /// Borrows the actual current-generation first SDK scope.
    pub(in crate::node_adapters::cnp::semantic) fn scope_data(
        &self,
    ) -> &PacketRestorationActivationScope {
        self.geometry.scope_data()
    }

    /// Returns the genuine immutable first-owner scope commitment.
    pub(in crate::node_adapters::cnp::semantic) fn scope_binding_data(&self) -> [u8; 32] {
        self.geometry.scope_binding_data()
    }

    /// Borrows actual immutable first ancestry, independently of the current cut.
    pub(in crate::node_adapters::cnp::semantic) fn first_observation_data(&self) -> &ContentRef {
        self.geometry.first_observation_data()
    }

    /// Returns immutable first ancestry's actual saved SDK cut.
    pub(in crate::node_adapters::cnp::semantic) const fn first_completed_frontier_data(
        &self,
    ) -> U64 {
        self.geometry.first_completed_frontier_data()
    }

    /// Borrows the actual current live restored record.
    pub(in crate::node_adapters::cnp::semantic) fn record_data(
        &self,
    ) -> &PacketNativeRestoredRecord {
        self.geometry.record_data()
    }

    /// Borrows its same retained native model.
    pub(in crate::node_adapters::cnp::semantic) fn underlying_data(
        &self,
    ) -> &PacketNative5UnderlyingRecord {
        self.geometry.underlying_data()
    }

    /// Borrows the actual current complete proof identity.
    pub(in crate::node_adapters::cnp::semantic) fn measurement_data(&self) -> &ContentRef {
        self.geometry.measurement_data()
    }

    /// Returns the SDK's actual saved completed frontier.
    pub(in crate::node_adapters::cnp::semantic) fn completed_frontier_data(&self) -> U64 {
        self.geometry.completed_frontier_data()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CacheFamily {
    First,
    Producer,
    Recurring,
    Input,
    Capture,
    SignedObservation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CacheCandidate {
    family: CacheFamily,
    frontier: U64,
}

fn select_data(candidates: &[Option<CacheCandidate>; 6]) -> Result<CacheCandidate, RuntimeError> {
    let mut selected: Option<CacheCandidate> = None;
    for (index, entry) in candidates.iter().enumerate() {
        let Some(candidate) = *entry else {
            continue;
        };
        if candidate.frontier.get() == 0 {
            return Err(RuntimeError::InvalidReceipt);
        }
        for previous in candidates[..index].iter().flatten() {
            if previous.frontier == candidate.frontier {
                return Err(RuntimeError::InvalidReceipt);
            }
        }
        if selected.is_none_or(|previous| previous.frontier < candidate.frontier) {
            selected = Some(candidate);
        }
    }
    selected.ok_or(RuntimeError::OwnerUnavailable)
}

fn authenticate_scope_data(
    source: &PacketCompleteSemanticSource,
    world: &WorldActivation,
    scope: &PacketRestorationActivationScope,
    record: &PacketNativeRestoredRecord,
) -> Result<(), RuntimeError> {
    authenticate_world_record_data(source, record, world)?;
    let target = &scope.target;
    let restoration = &scope.restoration;
    let receipt = &record.native_receipt;
    if target.activation != world.record().activation_id
        || target.generation != world.record().generation
        || record.physical_gate_held
        || record.captured_owner_state != restoration.captured_owner_state
        || record.captured_journal != restoration.captured_journal
        || record.mapping != restoration.mapping
        || record.restore_commit != restoration.commit_request
        || record.restore_response != restoration.commit_response
        || record.context_digest != restoration.context_digest
        || receipt.native_pid != target.native_pid
        || receipt.session != target.session
        || receipt.incarnation != target.incarnation
        || receipt.node != target.node
        || receipt.owner != target.owner
        || receipt.owner_generation != target.owner_generation
        || receipt.binding_hash != target.binding_hash
        || receipt.world != target.world
    {
        return Err(RuntimeError::ForeignAuthority);
    }
    Ok(())
}

fn authenticate_cached_model_data(
    controller: &CnpController,
    emitter: &crucible_node_provider::client::OriginalCanonicalBlobAckEmitter,
    record: &PacketNativeRestoredRecord,
    underlying: &PacketNative5UnderlyingRecord,
    measurement: &ContentRef,
) -> Result<(), RuntimeError> {
    let original = &record.native_receipt.original;
    let matches = match underlying {
        PacketNative5UnderlyingRecord::Producer(model) => {
            model.native_pid == record.native_receipt.native_pid && model.original == *original
        }
        PacketNative5UnderlyingRecord::Reactive(model) => {
            model.native_pid == record.native_receipt.native_pid && model.original == *original
        }
    };
    // The defining SDK lender rehashes both immutable ContentStore banks using
    // stack-only normative blob framing. No HashRef, DOM or decoded model is
    // reconstructed; genuine private completion already bound the typed caches.
    if !matches
        || measurement == &record.native_receipt.native_record
        || controller
            .original_completed_checkpoint17_content_cache_data(emitter, measurement)
            .map_err(|_| RuntimeError::InvalidReceipt)?
            .is_empty()
        || controller
            .original_completed_checkpoint17_content_cache_data(
                emitter,
                &record.native_receipt.native_record,
            )
            .map_err(|_| RuntimeError::InvalidReceipt)?
            .is_empty()
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    Ok(())
}

impl PacketCompleteSemanticSource {
    /// Lends current completed custody beneath the exact actual native read.
    ///
    /// The DATA borrower cannot construct this token-qualified view. The same
    /// Source-held native read remains armed before and after the callback; the
    /// caller independently completes its original sticky terminal fence.
    ///
    /// # Errors
    /// Refuses another Source/read/controller/World, revoked or busy custody,
    /// any DATA/current SDK mismatch or a failing callback/currentness fence.
    pub(in crate::node_adapters::cnp::semantic) fn with_latest_original_live_checkpoint17_cache_data<
        R,
    >(
        &self,
        controller: &CnpController,
        world: &WorldActivation,
        call: &OriginalFreshQueryReadCall<'_>,
        scratch: &mut FreshCurrentScratch,
        inspect: impl for<'loan> FnOnce(
            OriginalLiveCompletedCheckpoint17Data<'loan>,
        ) -> Result<R, RuntimeError>,
    ) -> Result<R, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        let association = self
            .ack_peer_association
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let original = association.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        original.authenticate_transfer_ready_data()?;
        let native = original
            .native
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        call.authenticate_original_source_read17_data(native, scratch)?;
        let result =
            self.with_latest_original_checkpoint17_geometry_data(controller, world, |geometry| {
                inspect(OriginalLiveCompletedCheckpoint17Data { geometry })
            });
        // A refusal may follow partially executed caller work. Repeat the actual
        // read and Source fence on both outcomes before returning its result.
        call.authenticate_original_source_read17_data(native, scratch)?;
        self.storage_origin_with_error::<RuntimeError>()?;
        result
    }

    /// Borrows exact private completed owners for an independently funded quote.
    ///
    /// This walks no native read and allocates no scratch/DTO/canonical bank.
    /// Current SDK custody and frozen Source provenance bind correspondence,
    /// while native currentness and all effect authority remain separate.
    ///
    /// # Errors
    /// Refuses foreign/busy/failed/inflight owner custody, changed SDK pairs or
    /// saved cuts, differing World/full references, duplicate latest cuts,
    /// a changed completed Capture bridge or a failing DATA callback.
    pub(in crate::node_adapters::cnp::semantic) fn with_latest_original_checkpoint17_geometry_data<
        R,
    >(
        &self,
        controller: &CnpController,
        world: &WorldActivation,
        inspect: impl for<'loan> FnOnce(
            OriginalCompletedCheckpoint17GeometryData<'loan>,
        ) -> Result<R, RuntimeError>,
    ) -> Result<R, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        let association = self
            .ack_peer_association
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let original = association.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        original.authenticate_transfer_ready_data()?;
        let birth = self
            .ack_peer_birth
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        birth
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .original_fresh_query_key_data()?;
        let emitter = original
            .emitter
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        emitter
            .authenticate_original(controller)
            .map_err(|_| RuntimeError::ForeignAuthority)?;

        let first = self.original_first_observation_checkpoint_frontier17_data(controller)?;
        let candidates = [
            first.map(|frontier| CacheCandidate {
                family: CacheFamily::First,
                frontier,
            }),
            self.original_producer_checkpoint_frontier17_data()?
                .map(|frontier| CacheCandidate {
                    family: CacheFamily::Producer,
                    frontier,
                }),
            self.original_current_observation_checkpoint_frontier17_data()?
                .map(|frontier| CacheCandidate {
                    family: CacheFamily::Recurring,
                    frontier,
                }),
            self.original_input_reactive_checkpoint_frontier17_data()?
                .map(|frontier| CacheCandidate {
                    family: CacheFamily::Input,
                    frontier,
                }),
            self.original_restored_capture_checkpoint_frontier_data()?
                .map(|frontier| CacheCandidate {
                    family: CacheFamily::Capture,
                    frontier,
                }),
            self.original_signed_observation17_completed_cache_frontier_data()?
                .map(|frontier| CacheCandidate {
                    family: CacheFamily::SignedObservation,
                    frontier,
                }),
        ];
        let selected = select_data(&candidates)?;
        let first_frontier = first.ok_or(RuntimeError::OwnerUnavailable)?;
        let result = self.with_original_first_completed_cache17_data(
            controller,
            first_frontier,
            false,
            |scope, first_record, _, first_measurement, _, scope_binding| {
                authenticate_scope_data(self, world, scope, first_record)?;
                let lend = |record: &PacketNativeRestoredRecord,
                            underlying: &PacketNative5UnderlyingRecord,
                            measurement: &ContentRef,
                            frontier: U64| {
                    if frontier != selected.frontier {
                        return Err(RuntimeError::InvalidReceipt);
                    }
                    authenticate_scope_data(self, world, scope, record)?;
                    authenticate_cached_model_data(
                        controller,
                        emitter,
                        record,
                        underlying,
                        measurement,
                    )?;
                    inspect(OriginalCompletedCheckpoint17GeometryData {
                        scope,
                        scope_binding,
                        first_observation: first_measurement,
                        first_frontier,
                        record,
                        underlying,
                        measurement,
                        frontier,
                    })
                };
                match selected.family {
                    CacheFamily::First => self.with_original_first_completed_cache17_data(
                        controller,
                        selected.frontier,
                        true,
                        |_, record, underlying, measurement, frontier, _| {
                            lend(record, underlying, measurement, frontier)
                        },
                    ),
                    CacheFamily::Producer => self.with_original_producer_completed_cache17_data(
                        controller,
                        world,
                        selected.frontier,
                        true,
                        lend,
                    ),
                    CacheFamily::Recurring => self.with_original_recurring_completed_cache17_data(
                        controller,
                        selected.frontier,
                        true,
                        lend,
                    ),
                    CacheFamily::Input => self.with_original_input_completed_cache17_data(
                        controller,
                        selected.frontier,
                        true,
                        lend,
                    ),
                    CacheFamily::SignedObservation => self
                        .with_original_signed_observation17_completed_cache_data(
                            controller,
                            selected.frontier,
                            true,
                            lend,
                        ),
                    CacheFamily::Capture => self
                        .with_original_frozen_restored_capture_checkpoint17_cache_data(
                            controller,
                            world,
                            |measurement, model, prefix_frontier, final_frontier| {
                                if final_frontier != selected.frontier {
                                    return Err(RuntimeError::InvalidReceipt);
                                }
                                self.with_original_retained_completed_checkpoint17_cache_data(
                                    controller,
                                    world,
                                    measurement,
                                    model,
                                    prefix_frontier,
                                    |record, underlying| {
                                        lend(record, underlying, measurement, final_frontier)
                                    },
                                )
                            },
                        ),
                }
            },
        );
        self.storage_origin_with_error::<RuntimeError>()?;
        result
    }

    /// Lends the exact frozen pre-Capture origin without claiming its currency.
    ///
    /// The surrounding genuine Capture bridge separately authenticates its
    /// current final SDK cut. Its pre-upload prefix was uniquely latest before
    /// that suffix, so the same frozen origin remains latest within its family
    /// while that final cut stays current. Older nonlatest family cuts refuse;
    /// they never trigger a validator fallback or historical-to-live promotion.
    ///
    /// # Errors
    /// Refuses missing/duplicate origin cuts, failed/inflight custody, another
    /// Source/controller/World, full-reference mismatch, changed actual SDK
    /// membership/content or a failing borrowed DATA callback.
    pub(in crate::node_adapters::cnp::semantic) fn with_original_retained_completed_checkpoint17_cache_data<
        R,
    >(
        &self,
        controller: &CnpController,
        world: &WorldActivation,
        measurement: &ContentRef,
        model: &ContentRef,
        frontier: U64,
        inspect: impl FnOnce(
            &PacketNativeRestoredRecord,
            &PacketNative5UnderlyingRecord,
        ) -> Result<R, RuntimeError>,
    ) -> Result<R, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        let first = self.original_first_observation_checkpoint_frontier17_data(controller)?;
        let candidates = [
            first.map(|frontier| CacheCandidate {
                family: CacheFamily::First,
                frontier,
            }),
            self.original_producer_checkpoint_frontier17_data()?
                .map(|frontier| CacheCandidate {
                    family: CacheFamily::Producer,
                    frontier,
                }),
            self.original_current_observation_checkpoint_frontier17_data()?
                .map(|frontier| CacheCandidate {
                    family: CacheFamily::Recurring,
                    frontier,
                }),
            self.original_input_reactive_checkpoint_frontier17_data()?
                .map(|frontier| CacheCandidate {
                    family: CacheFamily::Input,
                    frontier,
                }),
            self.original_signed_observation17_completed_cache_frontier_data()?
                .map(|frontier| CacheCandidate {
                    family: CacheFamily::SignedObservation,
                    frontier,
                }),
            None,
        ];
        // Reuse the complete duplicate/zero audit, then select only this exact
        // retained cut. Selecting a newer candidate is not a fallback option.
        select_data(&candidates)?;
        let mut selected = None;
        for candidate in candidates.iter().flatten() {
            if candidate.frontier == frontier {
                if selected.is_some() {
                    return Err(RuntimeError::InvalidReceipt);
                }
                selected = Some(*candidate);
            }
        }
        let selected = selected.ok_or(RuntimeError::OwnerUnavailable)?;
        let association = self
            .ack_peer_association
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let original = association.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        original.authenticate_transfer_ready_data()?;
        let emitter = original
            .emitter
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let result = self.with_original_first_completed_cache17_data(
            controller,
            first.ok_or(RuntimeError::OwnerUnavailable)?,
            false,
            |scope, first_record, _, _, _, _| {
                authenticate_scope_data(self, world, scope, first_record)?;
                let lend = |record: &PacketNativeRestoredRecord,
                            underlying: &PacketNative5UnderlyingRecord,
                            actual_measurement: &ContentRef,
                            actual_frontier: U64| {
                    if actual_frontier != frontier
                        || actual_measurement != measurement
                        || &record.native_receipt.native_record != model
                    {
                        return Err(RuntimeError::InvalidReceipt);
                    }
                    authenticate_scope_data(self, world, scope, record)?;
                    authenticate_cached_model_data(
                        controller,
                        emitter,
                        record,
                        underlying,
                        actual_measurement,
                    )?;
                    inspect(record, underlying)
                };
                match selected.family {
                    CacheFamily::First => self.with_original_first_completed_cache17_data(
                        controller,
                        frontier,
                        false,
                        |_, record, underlying, measurement, frontier, _| {
                            lend(record, underlying, measurement, frontier)
                        },
                    ),
                    CacheFamily::Producer => self.with_original_producer_completed_cache17_data(
                        controller, world, frontier, false, lend,
                    ),
                    CacheFamily::Recurring => self.with_original_recurring_completed_cache17_data(
                        controller, frontier, false, lend,
                    ),
                    CacheFamily::Input => self.with_original_input_completed_cache17_data(
                        controller, frontier, false, lend,
                    ),
                    CacheFamily::SignedObservation => self
                        .with_original_signed_observation17_completed_cache_data(
                            controller, frontier, false, lend,
                        ),
                    CacheFamily::Capture => Err(RuntimeError::UnsupportedFacet),
                }
            },
        );
        self.storage_origin_with_error::<RuntimeError>()?;
        result
    }

    /// Names the fixed borrowed views; this path creates no new retained cache.
    pub(in crate::node_adapters::cnp::semantic) fn original_live_checkpoint17_cache_counter_scratch_data()
    -> usize {
        CnpSemanticSourceRead::original_fresh_query_call_scratch_data()
            + Self::original_first_completed_cache17_counter_scratch_data() * 2
            + Self::original_producer_completed_cache17_counter_scratch_data()
            + Self::original_recurring_completed_cache17_counter_scratch_data()
            + Self::original_input_completed_cache17_counter_scratch_data()
            + Self::original_signed_observation17_completed_cache_counter_scratch_data()
            + Self::original_frozen_restored_capture_checkpoint17_cache_counter_scratch_data()
            + size_of::<std::cell::Ref<'static, Option<OriginalAckPeerAssociation>>>()
            + size_of::<std::cell::Ref<'static, Option<crate::node_adapters::cnp::semantic::packet_complete_source::ack_peer::OriginalAckPeerBirth>>>()
            + size_of::<Result<std::cell::Ref<'static, Option<OriginalAckPeerAssociation>>, std::cell::BorrowError>>()
            + CnpController::original_completed_checkpoint17_content_cache_counter_scratch_data()
            + CnpController::original_completed_restoration_checkpoint17_cache_counter_scratch_data()
            + crucible_node_provider::client::OriginalRestoredSuffixHostAttempt::completed_checkpoint17_cache_counter_scratch_data()
            + size_of::<OriginalLiveCompletedCheckpoint17Data<'static>>()
            + size_of::<OriginalCompletedCheckpoint17GeometryData<'static>>()
            + size_of::<Result<(), RuntimeError>>() + size_of::<Result<(), ProviderError>>()
            + 2 * size_of::<[Option<CacheCandidate>; 6]>()
            + size_of::<Option<CacheCandidate>>()
            + size_of::<std::iter::Flatten<std::slice::Iter<'static, Option<CacheCandidate>>>>() + size_of::<CacheCandidate>()
            + size_of::<Option<CacheCandidate>>() + size_of::<Result<CacheCandidate, RuntimeError>>()
            + size_of::<std::iter::Enumerate<std::slice::Iter<'static, Option<CacheCandidate>>>>()
            + size_of::<std::iter::Flatten<std::slice::Iter<'static, Option<CacheCandidate>>>>()
            + size_of::<[usize; 4]>() + size_of::<&PacketRestorationActivationScope>()
            + size_of::<&PacketNativeRestoredRecord>() + size_of::<&PacketNative5UnderlyingRecord>()
            + size_of::<&ContentRef>() * 4 + size_of::<&Envelope>()
            + size_of::<[u8; 32]>() + size_of::<U64>()
    }
}

// crucible-lint: allow panic-shortcut -- these finite cut comparisons create no live owner or authority.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_nonmaximum_duplicate_saved_cut_refuses_the_entire_live_selection() {
        let values = [
            Some(CacheCandidate {
                family: CacheFamily::First,
                frontier: U64::new(100),
            }),
            Some(CacheCandidate {
                family: CacheFamily::Producer,
                frontier: U64::new(8),
            }),
            Some(CacheCandidate {
                family: CacheFamily::Recurring,
                frontier: U64::new(8),
            }),
            None,
            None,
            None,
        ];
        assert!(matches!(
            select_data(&values),
            Err(RuntimeError::InvalidReceipt)
        ));
    }

    #[test]
    fn every_pair_of_distinct_families_rejects_a_shared_completed_frontier() {
        let families = [
            CacheFamily::First,
            CacheFamily::Producer,
            CacheFamily::Recurring,
            CacheFamily::Input,
            CacheFamily::Capture,
            CacheFamily::SignedObservation,
        ];
        for left in 0..families.len() {
            for right in left + 1..families.len() {
                let mut values: [Option<CacheCandidate>; 6] = std::array::from_fn(|index| {
                    Some(CacheCandidate {
                        family: families[index],
                        frontier: U64::new(100 + index as u64),
                    })
                });
                values[left].as_mut().unwrap().frontier = U64::new(8);
                values[right].as_mut().unwrap().frontier = U64::new(8);
                assert!(matches!(
                    select_data(&values),
                    Err(RuntimeError::InvalidReceipt)
                ));
            }
        }
    }

    #[test]
    fn unique_newest_cut_wins_independently_of_immutable_first_ancestry() {
        let values = [
            Some(CacheCandidate {
                family: CacheFamily::First,
                frontier: U64::new(8),
            }),
            None,
            None,
            None,
            None,
            Some(CacheCandidate {
                family: CacheFamily::SignedObservation,
                frontier: U64::new(100),
            }),
        ];
        let selected = select_data(&values).unwrap();
        assert_eq!(selected.family, CacheFamily::SignedObservation);
        assert_eq!(selected.frontier, U64::new(100));
    }
}
