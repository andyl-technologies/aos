//! Verifies Root's own fresh Source pending observation under the actual D flight.
//!
//! The same fixed Source socket transport serves existing Source17 and this
//! distinct purpose. Root retains its own pin verification, exact complete
//! pending cut, paired clocks and independent Root/Controller native posts.
//! None of these comparison results accepts six owners or grants lifecycle
//! disposition; every reached original remains with the enclosing D receiver.

use aos_sandbox_policy::native::{RootFinalityReadOriginalV1 as Target, RootFinalityReadKindV1 as Kind};
use crate::journal::historical_observation::root_readonly_error_v1 as project_read;
mod predecessor;
pub(crate) use predecessor::RootDeleteSourcePredecessorPhaseV2;

use super::{
    RootDeleteChallengeOriginalsV1, RootDeleteControllerCurrentOriginalV1, RootDeleteErrorV1,
};
use crate::controller_resource_reservation::{ResourceReservationErrorV1, RootDeleteChunkPostsV1};
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::journal::JournalError;
use crate::normal_root::{NormalRootStartupErrorV1, RootPolicyAcceptedFlightV1};
use crate::policy_compiler::RetainedKernelPairedClockAttemptV1;
use crate::policy_compiler::RootCreateStorageCurrentErrorV1;
use aos_sandbox_broker::source_signer_transport::RootSourceSignerTransportOriginalsV1;
use aos_sandbox_broker::source_signer_transport::RootSourceTransportClosedV1;
use aos_sandbox_model::{RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::delete_root::{
    source_current::{
        SOURCE_DELETE_CURRENT_BODY_BYTES_V1, SOURCE_DELETE_CURRENT_QUERY_BYTES_V1,
        SOURCE_DELETE_CURRENT_REPLY_BYTES_V1, SOURCE_DELETE_CURRENT_REPLY_MAGIC_V1,
        SOURCE_DELETE_CURRENT_SIGNATURE_DOMAIN_V1, SourceDeleteCurrentDataErrorV1,
        SourceDeleteCurrentQueryDataV1, SourceDeleteCurrentReplyDataV1,
        SourceDeleteCurrentReplyFieldsV1,
    },
    transport::DeleteRootOpenDataV2,
};
use ed25519_dalek::Signature;
use std::error::Error;

#[derive(Clone, Copy)]
enum First {
    Permit,
    Arm,
    ClockBefore,
    Before,
    Query,
    Profile,
    Transport,
    Framing,
    Decode,
    Pin,
    Signature,
    Correlation,
    Native,
    Predecessor,
    PredecessorPermit(usize),
    PredecessorPost,
    PredecessorBinding,
    PredecessorRetirement,
    After,
    ClockAfter,
    Freshness,
    FinalAssociation,
    Reentry,
}

pub(crate) struct RootDeleteSourceCurrentOriginalV1 {
    permit: Option<Result<(), ResourceReservationErrorV1>>,
    final_pass: bool,
    final_association: Option<Result<(), SourceDeleteCurrentDataErrorV1>>,
    posts: RootDeleteChunkPostsV1,
    arm: Option<Result<(), NormalRootStartupErrorV1>>,
    before: Option<Result<(), NormalRootStartupErrorV1>>,
    after: Option<Result<(), NormalRootStartupErrorV1>>,
    before_original: RetainedKernelPairedClockAttemptV1,
    before_clock: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    before_binding: Option<Result<(), JournalError>>,
    after_original: RetainedKernelPairedClockAttemptV1,
    after_clock: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    after_binding: Option<Result<(), JournalError>>,
    source_query: Option<Result<SourceDeleteCurrentQueryDataV1, NormalRootStartupErrorV1>>,
    query:
        Option<Result<[u8; SOURCE_DELETE_CURRENT_QUERY_BYTES_V1], SourceDeleteCurrentDataErrorV1>>,
    profile: Option<Result<(), NormalRootStartupErrorV1>>,
    transport: RootSourceSignerTransportOriginalsV1<
        SOURCE_DELETE_CURRENT_QUERY_BYTES_V1,
        SOURCE_DELETE_CURRENT_REPLY_BYTES_V1,
    >,
    exchanged: Option<Result<(), RootSourceTransportClosedV1>>,
    framing: Option<Result<(), SourceDeleteCurrentDataErrorV1>>,
    reply: Option<Result<SourceDeleteCurrentReplyDataV1, SourceDeleteCurrentDataErrorV1>>,
    pin: Option<Result<(), RootCreateStorageCurrentErrorV1>>,
    signature: Option<Result<(), ed25519_dalek::SignatureError>>,
    correlation: Option<Result<(), SourceDeleteCurrentDataErrorV1>>,
    native: Option<Result<(), SourceDeleteCurrentDataErrorV1>>,
    predecessor: Option<Target>,
    predecessor_retirement: Option<Result<(), JournalError>>,
    predecessor_capture: Option<Result<(), JournalError>>,
    predecessor_native: Option<Result<ResourceVector, JournalError>>,
    predecessor_semantic: Option<Result<ResourceVector, JournalError>>,
    predecessor_phase: Option<RootDeleteSourcePredecessorPhaseV2>,
    predecessor_permits: [Option<Result<(), ResourceReservationErrorV1>>; 2],
    predecessor_binding: Option<Result<(), SourceDeleteCurrentDataErrorV1>>,
    predecessor_graph_entry: Option<Result<(), Vec<aos_sandbox_ledger_replay::delete_graph::DeleteGraphCapabilityDataV2>>>,
    freshness: Option<Result<(), SourceDeleteCurrentDataErrorV1>>,
    entered: bool,
    native_entered: bool,
    complete: bool,
    first: Option<First>,
    closed: Option<RootDeleteErrorV1>,
}

impl Default for RootDeleteSourceCurrentOriginalV1 {
    fn default() -> Self {
        Self {
            permit: None,
            final_pass: false,
            final_association: None,
            posts: Default::default(),
            arm: None,
            before: None,
            after: None,
            before_original: Default::default(),
            before_clock: None,
            before_binding: None,
            after_original: Default::default(),
            after_clock: None,
            after_binding: None,
            source_query: None,
            query: None,
            profile: None,
            transport: Default::default(),
            exchanged: None,
            framing: None,
            reply: None,
            pin: None,
            signature: None,
            correlation: None,
            native: None,
            predecessor: Some(Target::new(Kind::Source)),
            predecessor_retirement: None,
            predecessor_capture: None, predecessor_native: None, predecessor_semantic: None,
            predecessor_phase: None, predecessor_permits: [None, None], predecessor_binding: None,
            predecessor_graph_entry: None,
            freshness: None,
            entered: false,
            native_entered: false,
            complete: false,
            first: None,
            closed: None,
        }
    }
}

impl RootDeleteSourceCurrentOriginalV1 {
    pub(super) fn observe_final_once_v2(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        challenge: &RootDeleteChallengeOriginalsV1,
        controller: &mut RootDeleteControllerCurrentOriginalV1,
        initial_controller: &RootDeleteControllerCurrentOriginalV1,
        initial: &Self,
        open: DeleteRootOpenDataV2,
    ) -> Result<(), RootDeleteErrorV1> {
        if self.entered || self.final_pass || self.first.is_some() {
            self.closed.get_or_insert(RootDeleteErrorV1::Original);
            self.first.get_or_insert(First::Reentry);
            return Err(RootDeleteErrorV1::Original);
        }
        controller.require_fresh_controller_v2(initial_controller)?;
        initial.verified_fields_v1()?;
        self.final_pass = true;
        self.observe_once_v1(flight, challenge, controller, open)?;
        self.final_association = Some((|| {
            let old = initial.verified_fields_v1().map_err(|_| SourceDeleteCurrentDataErrorV1::Native)?;
            let now = self.verified_fields_v1().map_err(|_| SourceDeleteCurrentDataErrorV1::Native)?;
            if now.generation != old.generation || now.names != old.names
                || now.next != old.next || now.end != old.end
                || now.pending_native != old.pending_native
                || now.tree_generation != old.tree_generation
                || now.tree_commitment != old.tree_commitment
                || now.tree_head != old.tree_head || now.lineage_head != old.lineage_head
            {
                return Err(SourceDeleteCurrentDataErrorV1::Association);
            }
            Ok(())
        })());
        if !matches!(self.final_association, Some(Ok(()))) {
            self.first = Some(First::FinalAssociation);
            return Err(RootDeleteErrorV1::Opening);
        }
        Ok(())
    }

    pub(crate) fn is_final_read_v2(&self) -> bool { self.final_pass }

    pub(crate) fn final_predecessor_phase_v2(&self)
        -> Result<RootDeleteSourcePredecessorPhaseV2, ResourceReservationErrorV1>
    {
        self.predecessor_receiving_demand_v2()?;
        if !self.final_pass { return Err(ResourceReservationErrorV1::Conflict); }
        self.predecessor_phase.ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(super) fn observe_once_v1(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        challenge: &RootDeleteChallengeOriginalsV1,
        controller: &mut RootDeleteControllerCurrentOriginalV1,
        open: DeleteRootOpenDataV2,
    ) -> Result<(), RootDeleteErrorV1> {
        if self.entered || self.closed.is_some() {
            self.first.get_or_insert(First::Reentry);
            self.closed.get_or_insert(RootDeleteErrorV1::Original);
            return Err(RootDeleteErrorV1::Original);
        }
        self.entered = true;
        let primary = self.observe_inner(flight, challenge, controller, open);
        // Native name/mount/metadata afters remain independently owed even
        // when capture, semantic admission or the primary Source query failed.
        if let Some(predecessor) = self.predecessor.as_mut() {
            predecessor.finish_post_once();
            if predecessor.post_failure().is_some() {
                self.first.get_or_insert(First::PredecessorPost);
            }
        }
        if primary.is_ok() && self.first.is_none() {
            self.finish_predecessor_binding_v2();
        }
        if self.native_entered {
            // The whole distinct before/after roster was funded before arm.
            // No primary failure may suppress its independently owed afters.
            self.after = Some(self.posts.observe_after_once_v1(flight, challenge));
            if !matches!(self.after, Some(Ok(()))) {
                self.first.get_or_insert(First::After);
            }
            self.after_clock = Some(self.after_original.observe_once(None));
            self.after_binding = Some((|| {
                let before = *positive(&self.before_clock)?;
                let after = *positive(&self.after_clock)?;
                before
                    .validate_later_sample(after)
                    .map_err(|_| JournalError::ProtectedBoundary)?;
                challenge.require_current_clock_v1(after)
            })());
            if !matches!(self.after_binding, Some(Ok(()))) {
                self.first.get_or_insert(First::ClockAfter);
            }
            if matches!(self.reply, Some(Ok(_))) {
                self.freshness = Some((|| {
                    let before = *positive(&self.before_clock)
                        .map_err(|_| SourceDeleteCurrentDataErrorV1::Clock)?;
                    let after = *positive(&self.after_clock)
                        .map_err(|_| SourceDeleteCurrentDataErrorV1::Clock)?;
                    let fields = positive(&self.reply)
                        .map_err(|_| SourceDeleteCurrentDataErrorV1::Clock)?
                        .fields;
                    require_fresh_interval_v1(before, after, fields)
                })());
                if !matches!(self.freshness, Some(Ok(()))) {
                    self.first.get_or_insert(First::Freshness);
                }
            }
        }
        if primary.is_err() || self.first.is_some() || self.failure().is_some() {
            return Err(RootDeleteErrorV1::Opening);
        }
        self.predecessor_retirement = Some(self.retire_predecessor_once_v2());
        if !matches!(self.predecessor_retirement, Some(Ok(()))) {
            self.first = Some(First::PredecessorRetirement);
            return Err(RootDeleteErrorV1::Opening);
        }
        self.complete = true;
        Ok(())
    }

    fn observe_inner(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        challenge: &RootDeleteChallengeOriginalsV1,
        controller: &mut RootDeleteControllerCurrentOriginalV1,
        open: DeleteRootOpenDataV2,
    ) -> Result<(), RootDeleteErrorV1> {
        self.permit = Some(flight.admit_delete_source_current_v1(challenge, controller, self));
        self.require(matches!(self.permit, Some(Ok(()))), First::Permit)?;
        self.native_entered = true;
        self.arm = Some(flight.arm_delete_chunk_posts_once_v1(challenge, &mut self.posts));
        self.require(matches!(self.arm, Some(Ok(()))), First::Arm)?;
        self.before_clock = Some(self.before_original.observe_once(None));
        self.before_binding = Some(
            positive(&self.before_clock)
                .and_then(|clock| challenge.require_current_clock_v1(*clock)),
        );
        self.before = Some(self.posts.observe_before_once_v1(flight, challenge));
        self.require(
            matches!(self.before_binding, Some(Ok(()))),
            First::ClockBefore,
        )?;
        self.require(matches!(self.before, Some(Ok(()))), First::Before)?;
        self.source_query = Some(challenge.source_query_v1());
        self.require(matches!(self.source_query, Some(Ok(_))), First::Query)?;
        let query = *positive(&self.source_query).map_err(|_| RootDeleteErrorV1::Opening)?;
        self.query = Some(query.encode());
        self.require(matches!(self.query, Some(Ok(_))), First::Query)?;
        let (uid, gid, controller_uid) = match flight.delete_cut_startup_v1() {
            Ok(startup) => {
                let ids = startup
                    .native_startup_original_v1()
                    .fields()
                    .profile
                    .identities;
                self.profile = Some(Ok(()));
                (ids[3], ids[1], ids[0])
            }
            Err(cause) => {
                self.profile = Some(Err(cause));
                self.first = Some(First::Profile);
                return Err(RootDeleteErrorV1::Opening);
            }
        };
        let request = positive(&self.query).map_err(|_| RootDeleteErrorV1::Opening)?;
        self.exchanged = Some(self.transport.run_once_v1(uid, gid, request, query.cutoff));
        self.require(matches!(self.exchanged, Some(Ok(()))), First::Transport)?;
        self.framing = Some(
            if self.transport.frame_v1()[..8] == *SOURCE_DELETE_CURRENT_REPLY_MAGIC_V1 {
                Ok(())
            } else {
                Err(SourceDeleteCurrentDataErrorV1::Format)
            },
        );
        self.require(matches!(self.framing, Some(Ok(()))), First::Framing)?;
        self.reply = Some(SourceDeleteCurrentReplyDataV1::decode(
            &self.transport.frame_v1()[8..],
        ));
        self.require(matches!(self.reply, Some(Ok(_))), First::Decode)?;
        let reply = *positive(&self.reply).map_err(|_| RootDeleteErrorV1::Opening)?;
        let signer = match flight.delete_source_signer_pin_v1() {
            Ok(signer) => {
                self.pin = Some(Ok(()));
                signer
            }
            Err(cause) => {
                self.pin = Some(Err(cause));
                self.first = Some(First::Pin);
                return Err(RootDeleteErrorV1::Opening);
            }
        };
        self.signature = Some(verify_source_signature_v1(
            self.transport.frame_v1(),
            reply.signature,
            signer,
        ));
        self.require(matches!(self.signature, Some(Ok(()))), First::Signature)?;
        self.correlation = Some(reply.fields.require_query(query, signer.generation()));
        self.require(matches!(self.correlation, Some(Ok(()))), First::Correlation)?;
        // The Source query contains no Controller native coordinate. This is
        // the independent signed native64 joined to the actual intrinsic C17
        // pending fence conveyed in the same canonical opening.
        self.native = Some(require_pending_native_v1(reply.fields, open));
        self.require(matches!(self.native, Some(Ok(()))), First::Native)?;
        self.observe_predecessor_v2(flight, challenge, controller, query, reply.fields, controller_uid)
    }

    fn require(&mut self, positive: bool, stage: First) -> Result<(), RootDeleteErrorV1> {
        if positive {
            Ok(())
        } else {
            self.first.get_or_insert(stage);
            Err(RootDeleteErrorV1::Opening)
        }
    }

    pub(crate) fn receiving_demand_v1(&self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        if !self.entered || self.permit.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.receiving_recipe_v1()
    }

    pub(crate) fn retained_receiving_demand_v1(&self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        self.verified_fields_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        self.retained_predecessor_shape_v2(self.receiving_recipe_v1()?)
    }

    fn receiving_recipe_v1(&self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        let invalid = || ResourceReservationErrorV1::EnrollmentUnavailable;
        let pair = RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()
            .ok_or_else(invalid)?;
        let message = aos_sandbox_protocol::domain_ledger::delete_root::source_current::SOURCE_DELETE_CURRENT_SIGNATURE_MESSAGE_MAXIMUM_BYTES_V3;
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(3)
            .and_then(|bytes| bytes.checked_add(pair.checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(message))
            // Same bounded native pathname/error backing as the actual old
            // Source17 transport supplier, now serving this distinct purpose.
            .and_then(|bytes| bytes.checked_add(30 * 256))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(invalid)?;
        let clock_names = RetainedKernelPairedClockAttemptV1::receiving_metadata_cells_v1()
            .and_then(|cells| cells.checked_mul(2))
            .and_then(|cells| cells.checked_add(6))
            .and_then(|cells| u64::try_from(cells).ok())
            .ok_or_else(invalid)?;
        let prefix = super::reader::fixed_demand_v1(Kind::Source)
            .map_err(|_| invalid())?;
        let prefix = if self.predecessor.as_ref().is_some_and(Target::native_prefixes_retired_data_v2) {
            prefix.with(D::OpenFiles, 0)
        } else { prefix };
        RootDeleteChunkPostsV1::fixed_demand_v1()?.checked_add(prefix)?
            .checked_add(
                ResourceVector::ZERO
                    .with(D::MemoryBytes, bytes)
                    // Two actual fixed three-path metadata observation rosters.
                    .with(D::MetadataEntries, clock_names)
                    .with(
                        D::OpenFiles,
                        1 + 2 * RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1
                            as u64,
                    )
                    .with(
                        D::NetworkBytes,
                        (SOURCE_DELETE_CURRENT_QUERY_BYTES_V1
                            + SOURCE_DELETE_CURRENT_REPLY_BYTES_V1
                            + 1) as u64,
                    )
                    .with(D::OutputBytes, SOURCE_DELETE_CURRENT_QUERY_BYTES_V1 as u64),
            )
            .map_err(Into::into)
    }

    pub(crate) fn verified_fields_v1(
        &self,
    ) -> Result<&SourceDeleteCurrentReplyFieldsV1, RootDeleteErrorV1> {
        if !self.complete || self.first.is_some() || self.closed.is_some() {
            return Err(RootDeleteErrorV1::Original);
        }
        self.reply
            .as_ref()
            .and_then(|reply| reply.as_ref().ok())
            .map(|reply| &reply.fields)
            .ok_or(RootDeleteErrorV1::Original)
    }

    pub(super) fn financial_failure_is_selected_v1(&self) -> bool {
        matches!(self.first, Some(First::Permit | First::PredecessorPermit(_)))
            || matches!(self.first, Some(First::Arm)) && self.posts.funding_failed_v1()
    }

    pub(super) fn property_failure_view_v1(
        &self,
    ) -> Option<aos_systemd_client::FixedPid1PropertyFailureViewV1<'_>> {
        match self.first? {
            First::Before | First::After => self.posts.property_failure_view_v1(self.failure()?),
            _ => None,
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::Permit => cause(&self.permit),
            First::Arm | First::Before => self
                .posts
                .before_failure_v1()
                .or_else(|| cause(&self.arm))
                .or_else(|| cause(&self.before)),
            First::After => self.posts.after_failure_v1().or_else(|| cause(&self.after)),
            First::ClockBefore => self
                .before_original
                .failure()
                .or_else(|| cause(&self.before_clock))
                .or_else(|| cause(&self.before_binding)),
            First::ClockAfter => self
                .after_original
                .failure()
                .or_else(|| cause(&self.after_clock))
                .or_else(|| cause(&self.after_binding)),
            First::Query => cause(&self.source_query).or_else(|| cause(&self.query)),
            First::Profile => cause(&self.profile),
            First::Transport => self.transport.failure().or_else(|| cause(&self.exchanged)),
            First::Framing => cause(&self.framing),
            First::Decode => cause(&self.reply),
            First::Pin => cause(&self.pin),
            First::Signature => cause(&self.signature),
            First::Correlation => cause(&self.correlation),
            First::Native => cause(&self.native),
            First::Predecessor => self.predecessor.as_ref().and_then(|original| original.failure())
                .or_else(|| cause(&self.predecessor_capture))
                .or_else(|| cause(&self.predecessor_native))
                .or_else(|| cause(&self.predecessor_semantic)),
            First::PredecessorPermit(index) => cause(&self.predecessor_permits[index]),
            First::PredecessorPost => self.predecessor.as_ref().and_then(|original| original.post_failure()),
            First::PredecessorBinding => cause(&self.predecessor_binding),
            First::PredecessorRetirement => self.predecessor.as_ref().and_then(|original| original.failure())
                .or_else(|| cause(&self.predecessor_retirement)),
            First::FinalAssociation => cause(&self.final_association),
            First::Freshness => cause(&self.freshness),
            First::Reentry => self.closed.as_ref().map(|cause| cause as _),
        }
    }
}

fn require_pending_native_v1(
    reply: SourceDeleteCurrentReplyFieldsV1,
    open: DeleteRootOpenDataV2,
) -> Result<(), SourceDeleteCurrentDataErrorV1> {
    if reply.pending_native == open.source_pending {
        Ok(())
    } else {
        Err(SourceDeleteCurrentDataErrorV1::Native)
    }
}

pub(super) fn require_fresh_interval_v1(
    before: RawPairedClockSample,
    after: RawPairedClockSample,
    reply: SourceDeleteCurrentReplyFieldsV1,
) -> Result<(), SourceDeleteCurrentDataErrorV1> {
    before
        .validate_later_sample(after)
        .map_err(|_| SourceDeleteCurrentDataErrorV1::Clock)?;
    // Signed Source clock DATA has its own purpose provenance. Keep the actual
    // native Root samples unchanged and compare the same-boot numerical bracket.
    if reply.boot != before.host_boot_id()
        || reply.boot != after.host_boot_id()
        || reply.boottime_nanoseconds < before.boottime_nanoseconds()
        || reply.boottime_nanoseconds > after.boottime_nanoseconds()
        || reply.wall_seconds < before.wall_seconds()
        || reply.wall_seconds > after.wall_seconds()
    {
        return Err(SourceDeleteCurrentDataErrorV1::Clock);
    }
    Ok(())
}

fn verify_source_signature_v1(
    frame: &[u8; SOURCE_DELETE_CURRENT_REPLY_BYTES_V1],
    signature: [u8; 64],
    signer: &crate::policy_compiler::PinnedSourceHoldReadbackSignerV1,
) -> Result<(), ed25519_dalek::SignatureError> {
    verify_source_signature_for_purpose_v3(frame, signature, signer,
        aos_sandbox_protocol::domain_ledger::delete_root::source_current::SourceDeleteCurrentPurposeDataV3::Planned)
}

pub(super) fn verify_source_signature_for_purpose_v3(
    frame: &[u8; SOURCE_DELETE_CURRENT_REPLY_BYTES_V1], signature: [u8;64],
    signer: &crate::policy_compiler::PinnedSourceHoldReadbackSignerV1,
    purpose: aos_sandbox_protocol::domain_ledger::delete_root::source_current::SourceDeleteCurrentPurposeDataV3,
) -> Result<(), ed25519_dalek::SignatureError> {
    use aos_sandbox_protocol::domain_ledger::delete_root::source_current::SOURCE_DELETE_CURRENT_SIGNATURE_MESSAGE_MAXIMUM_BYTES_V3;
    let domain = purpose.signature_domain_v3();
    let mut message = [0; SOURCE_DELETE_CURRENT_SIGNATURE_MESSAGE_MAXIMUM_BYTES_V3];
    message[..domain.len()].copy_from_slice(domain);
    message[domain.len()..domain.len()+SOURCE_DELETE_CURRENT_BODY_BYTES_V1]
        .copy_from_slice(&frame[8..8+SOURCE_DELETE_CURRENT_BODY_BYTES_V1]);
    signer.verifying_key().verify_strict(&message[..domain.len()+SOURCE_DELETE_CURRENT_BODY_BYTES_V1], &Signature::from_bytes(&signature))
}

fn positive<T, E>(slot: &Option<Result<T, E>>) -> Result<&T, JournalError> {
    slot.as_ref()
        .and_then(|value| value.as_ref().ok())
        .ok_or(JournalError::ProtectedBoundary)
}

fn cause<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_model::RawClockProvenance;
    use aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1;
    use ed25519_dalek::{Signer as _, SigningKey};

    fn clock(wall: i64, seconds: u64) -> RawPairedClockSample {
        RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted([1; 16]).unwrap(),
            [2; 16],
            wall,
            seconds * 1_000_000_000,
        )
        .unwrap()
    }

    fn fields() -> SourceDeleteCurrentReplyFieldsV1 {
        SourceDeleteCurrentReplyFieldsV1 {
            generation: 1,
            query: [3; 32],
            boot: [2; 16],
            wall_seconds: 101,
            boottime_nanoseconds: 11_000_000_000,
            names: ProtectedJournalNamesV1::from_historical_fields((1, 2), (3, 4), (5, 6)),
            next: 8,
            end: 4096,
            pending_native: [7; 64],
            batch: [8; 32],
            project: [9; 16],
            operation: [10; 16],
            tree_generation: 1,
            tree_commitment: [11; 32],
            tree_head: [12; 32],
            lineage_head: [13; 32],
        }
    }

    #[test]
    fn signature_uses_own_pin_and_every_raw_body_byte() {
        let key = SigningKey::from_bytes(&[17; 32]);
        let foreign = SigningKey::from_bytes(&[18; 32]);
        let pin = |key: &SigningKey| {
            let credential =
                crate::policy_compiler::encode_source_hold_readback_signer_credential_v1(
                    1,
                    &key.verifying_key(),
                )
                .unwrap();
            crate::policy_compiler::PinnedSourceHoldReadbackSignerV1::decode(&credential).unwrap()
        };
        let own_pin = pin(&key);
        let foreign_pin = pin(&foreign);
        // This exercises only the signature boundary. It creates no native
        // Source/D owner, accepted query, or lifecycle state from these bytes.
        let mut frame = [0; SOURCE_DELETE_CURRENT_REPLY_BYTES_V1];
        frame[..8].copy_from_slice(SOURCE_DELETE_CURRENT_REPLY_MAGIC_V1);
        frame[8..8 + SOURCE_DELETE_CURRENT_BODY_BYTES_V1].fill(3);
        let mut message = Vec::from(SOURCE_DELETE_CURRENT_SIGNATURE_DOMAIN_V1);
        message.extend_from_slice(&frame[8..8 + SOURCE_DELETE_CURRENT_BODY_BYTES_V1]);
        let signature = key.sign(&message).to_bytes();

        assert!(verify_source_signature_v1(&frame, signature, &own_pin).is_ok());
        assert!(verify_source_signature_v1(&frame, signature, &foreign_pin).is_err());
        for offset in [8, 8 + 24, 8 + 152, 8 + 215, 8 + 352, 8 + 383] {
            frame[offset] ^= 1;
            assert!(verify_source_signature_v1(&frame, signature, &own_pin).is_err());
            frame[offset] ^= 1;
        }
    }

    #[test]
    fn controller_committed_signature_is_separated_from_the_original_planned_domain() {
        use aos_sandbox_protocol::domain_ledger::delete_root::source_current::SourceDeleteCurrentPurposeDataV3 as P;
        let key = SigningKey::from_bytes(&[17;32]);
        let credential = crate::policy_compiler::encode_source_hold_readback_signer_credential_v1(
            1, &key.verifying_key()).unwrap();
        let pin = crate::policy_compiler::PinnedSourceHoldReadbackSignerV1::decode(&credential).unwrap();
        let mut frame = [0; SOURCE_DELETE_CURRENT_REPLY_BYTES_V1];
        frame[..8].copy_from_slice(P::ControllerCommitted.reply_magic_v3());
        frame[8..8 + SOURCE_DELETE_CURRENT_BODY_BYTES_V1].fill(3);
        let mut message = Vec::from(P::ControllerCommitted.signature_domain_v3());
        message.extend_from_slice(&frame[8..8 + SOURCE_DELETE_CURRENT_BODY_BYTES_V1]);
        let signature = key.sign(&message).to_bytes();
        assert!(verify_source_signature_for_purpose_v3(&frame, signature, &pin, P::ControllerCommitted).is_ok());
        assert!(verify_source_signature_v1(&frame, signature, &pin).is_err());
        frame[8 + 152] ^= 1;
        assert!(verify_source_signature_for_purpose_v3(&frame, signature, &pin, P::ControllerCommitted).is_err());
    }

    #[test]
    fn native_join_checks_all_coordinates_and_signed_clock_is_bracketed() {
        let reply = fields();
        let open = DeleteRootOpenDataV2 {
            project: reply.project,
            operation: reply.operation,
            batch: reply.batch,
            batch_bytes: 640,
            authorization_clock: clock(100, 10),
            authorization_expires: 150,
            source_pending: reply.pending_native,
        };
        assert!(require_pending_native_v1(reply, open).is_ok());
        for offset in [0, 15, 16, 47, 48, 55, 56, 63] {
            let mut changed = reply;
            changed.pending_native[offset] ^= 1;
            assert_eq!(
                require_pending_native_v1(changed, open),
                Err(SourceDeleteCurrentDataErrorV1::Native)
            );
        }

        let before = clock(100, 10);
        let after = clock(102, 12);
        assert!(require_fresh_interval_v1(before, after, reply).is_ok());
        let mut early = reply;
        early.boottime_nanoseconds = 9_999_999_999;
        assert!(require_fresh_interval_v1(before, after, early).is_err());
        let mut late = reply;
        late.boottime_nanoseconds = 12_000_000_001;
        assert!(require_fresh_interval_v1(before, after, late).is_err());
        let mut other_boot = reply;
        other_boot.boot[0] ^= 1;
        assert!(require_fresh_interval_v1(before, after, other_boot).is_err());
    }
}
