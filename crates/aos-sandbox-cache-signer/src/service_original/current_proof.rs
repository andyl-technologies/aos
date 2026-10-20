//! Builds and signs only this private F owner's fully observed current packet.
//!
//! The packet remains private until the same request/Root/F posts complete.
//! No caller can supply a snapshot, signing preimage, key, budget or completed
//! marker. Both contacted peers receive this exact one resident packet.

use std::error::Error;

use aos_sandbox_core::{AccountingError, ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    HistoryErrorV1,
    cache_held::{
        CacheHeldReceiptDataV1,
        current_proof::{
            CACHE_CURRENT_PROOF_BODY_BYTES_V1, CACHE_CURRENT_PROOF_PACKET_BYTES_V1,
            CACHE_CURRENT_PROOF_PREIMAGE_BYTES_V1, CacheCurrentProofBodyDataV1,
            current_cache_proof_preimage_v1,
        },
    },
    root_open::{ROOT_HELLO_FRAME_BYTES_V1, RootHelloDataV1},
};
use ed25519_dalek::{Signature, Signer as _, SigningKey};

use aos_sandbox_ledger_replay::cache_current::CacheCurrentModelErrorV1;
use super::reply::CacheReplyOriginalV1;
use super::{
    CachePurposeReceivingV1, CacheSignerReceivingClosedV1 as Closed, Common, First, StageOriginals,
    admit_stage, cause, observe_original, sample_pair_demand,
};
use crate::cache_signer_credential::CacheSignerCredentialErrorV2;

#[derive(Clone, Copy)]
enum Failure {
    Order,
    Funding,
    Before,
    Body,
    Encode,
    Correlation,
    Key,
    After,
    Deadline,
    ReplyFunding,
    ReplyBefore,
    RootReply,
    ControllerReply,
    RootSettlement,
    ReplyAfter,
    ReplyDeadline,
}

pub(super) struct CacheCurrentProofOriginalV1 {
    signing: StageOriginals,
    body: Option<Result<CacheCurrentProofBodyDataV1, CacheCurrentModelErrorV1>>,
    encoded: Option<Result<[u8; CACHE_CURRENT_PROOF_BODY_BYTES_V1], HistoryErrorV1>>,
    correlation: Option<Result<(), HistoryErrorV1>>,
    key: Option<Result<SigningKey, CacheSignerCredentialErrorV2>>,
    preimage: Option<[u8; CACHE_CURRENT_PROOF_PREIMAGE_BYTES_V1]>,
    signature: Option<Signature>,
    packet: Option<[u8; CACHE_CURRENT_PROOF_PACKET_BYTES_V1]>,
    clock: Option<rustix::time::Timespec>,
    deadline: Option<
        Result<
            rustix::time::Timespec,
            aos_sandbox_broker::cache_signer_connection::CacheSignerConnectionClosedV1,
        >,
    >,
    replies: StageOriginals,
    root_reply: CacheReplyOriginalV1,
    root_result: Option<Result<(), Closed>>,
    controller_reply: CacheReplyOriginalV1,
    controller_result: Option<Result<(), Closed>>,
    reply_clock: Option<rustix::time::Timespec>,
    reply_deadline: Option<
        Result<
            rustix::time::Timespec,
            aos_sandbox_broker::cache_signer_connection::CacheSignerConnectionClosedV1,
        >,
    >,
    first: Option<Failure>,
}

impl CacheCurrentProofOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            signing: Default::default(),
            body: None,
            encoded: None,
            correlation: None,
            key: None,
            preimage: None,
            signature: None,
            packet: None,
            clock: None,
            deadline: None,
            replies: Default::default(),
            root_reply: Default::default(),
            root_result: None,
            controller_reply: Default::default(),
            controller_result: None,
            reply_clock: None,
            reply_deadline: None,
            first: None,
        }
    }

    fn signing_demand_v1() -> Result<ResourceVector, AccountingError> {
        let overflow = AccountingError::ArithmeticOverflow {
            dimension: D::MemoryBytes,
        };
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(CACHE_CURRENT_PROOF_BODY_BYTES_V1.checked_mul(2)?))
            .and_then(|bytes| {
                bytes.checked_add(CACHE_CURRENT_PROOF_PREIMAGE_BYTES_V1.checked_mul(2)?)
            })
            .and_then(|bytes| {
                bytes.checked_add(CACHE_CURRENT_PROOF_PACKET_BYTES_V1.checked_mul(2)?)
            })
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(overflow)?;
        ResourceVector::ZERO
            .with(D::MemoryBytes, bytes)
            .checked_add(sample_pair_demand()?)
    }

    pub(super) fn is_complete_v1(&self) -> bool {
        self.first.is_none()
            && self.packet.is_some()
            && self.signing.complete()
            && self.replies.complete()
            && matches!(self.root_result, Some(Ok(())))
            && matches!(self.controller_result, Some(Ok(())))
            && matches!(self.reply_deadline, Some(Ok(_)))
    }

    pub(super) fn can_retire_positive_native_v1(&self) -> bool {
        self.is_complete_v1()
            && self.signing.can_retire_positive_samples()
            && self.replies.can_retire_positive_samples()
    }

    pub(super) fn retire_positive_native_once_v1(&mut self) -> Result<(), Closed> {
        if !self.can_retire_positive_native_v1() {
            return Err(Closed);
        }
        self.signing.retire_positive_samples()?;
        self.replies.retire_positive_samples()?;
        drop(self.key.take());
        Ok(())
    }

    pub(super) fn failure<'a>(&'a self, common: &'a Common) -> Option<&'a (dyn Error + 'static)> {
        match self.first? {
            Failure::Order => Some(&Closed),
            Failure::Funding => self.signing.funding_failure(common),
            Failure::Before => self
                .signing
                .before
                .failure()
                .or_else(|| cause(&self.signing.before_result)),
            Failure::Body => cause(&self.body),
            Failure::Encode => cause(&self.encoded),
            Failure::Correlation => cause(&self.correlation),
            Failure::Key => cause(&self.key),
            Failure::After => self
                .signing
                .after
                .failure()
                .or_else(|| cause(&self.signing.after_result)),
            Failure::Deadline => cause(&self.deadline),
            Failure::ReplyFunding => self.replies.funding_failure(common),
            Failure::ReplyBefore => self
                .replies
                .before
                .failure()
                .or_else(|| cause(&self.replies.before_result)),
            Failure::RootReply => self
                .root_reply
                .failure()
                .or_else(|| cause(&self.root_result)),
            Failure::ControllerReply => self
                .controller_reply
                .failure()
                .or_else(|| cause(&self.controller_result)),
            Failure::ReplyAfter => self
                .replies
                .after
                .failure()
                .or_else(|| cause(&self.replies.after_result)),
            Failure::ReplyDeadline => cause(&self.reply_deadline),
            Failure::RootSettlement => Some(&Closed),
        }
    }
}

impl CachePurposeReceivingV1<'_> {
    // This entry itself drives the entire actual observation/signature body.
    // Every entered outer post remains owed even after a body or debit failure.
    pub(super) fn serve_current_purpose_once(&mut self) -> Result<(), Closed> {
        if self.original.first.is_none() {
            let _ = self.capture_root_request_once();
        }
        if self.original.first.is_none() {
            let _ = self.begin_current_root_purpose_once();
        }
        if self.original.first.is_none() {
            let _ = self.join_current_controller_once();
        }
        if self
            .original
            .current_journals
            .as_ref()
            .is_some_and(|owner| owner.owes_after_v1())
        {
            let _ = self.finish_current_journals_once();
        }
        if self
            .original
            .current_objects
            .as_ref()
            .is_some_and(|owner| owner.owes_after_v1())
        {
            let _ = self.finish_current_objects_once();
        }
        if self.original.current_clock_stage.before_result.is_some()
            && self.original.current_clock_after.is_none()
        {
            let _ = self.finish_current_clock_once();
        }
        if self.original.first.is_none() {
            let _ = self.sign_current_observation_once();
        }
        if self.original.purpose_stage.before_result.is_some()
            && self.original.purpose_stage.after_result.is_none()
        {
            let _ = self.finish_current_root_purpose_once();
        }
        if self.original.first.is_none() {
            let _ = self.send_current_observation_once();
        }
        if self.original.first.is_some() {
            Err(Closed)
        } else {
            Ok(())
        }
    }

    fn sign_current_observation_once(&mut self) -> Result<(), Closed> {
        if self.original.first.is_some()
            || self.original.current_proof.is_some()
            || !self.original.join_stage.native_retired
            || !matches!(self.original.current_clock_after, Some(Ok(())))
            || !self
                .original
                .current_journals
                .as_ref()
                .is_some_and(|owner| owner.native_leaves_are_retired_v1())
        {
            return Err(self.fail(First::Closed));
        }
        let challenge = *self.original.root_challenge.data()?;
        let sample = self
            .original
            .current_clock
            .as_ref()
            .ok_or(Closed)?
            .completed_sample_v1()?;
        let generation = self.credential()?.generation();
        let resident = self.current_observation_resident_files_v1()?;
        self.original.current_proof = Some(CacheCurrentProofOriginalV1::new());
        let proof = self.original.current_proof.as_mut().ok_or(Closed)?;
        proof.signing.demand = Some(CacheCurrentProofOriginalV1::signing_demand_v1());
        if admit_stage(&mut self.startup.common, &mut proof.signing, resident).is_err() {
            proof.first.get_or_insert(Failure::Funding);
            return Err(self.fail(First::CurrentProof));
        }
        proof.signing.before_result = Some(observe_original(
            &mut self.startup.common,
            &mut proof.signing.before,
        ));
        if !matches!(proof.signing.before_result, Some(Ok(()))) {
            proof.first.get_or_insert(Failure::Before);
        }
        if proof.first.is_none() {
            proof.body = Some((|| {
                let families = self
                    .original
                    .current_models
                    .as_ref()
                    .ok_or(CacheCurrentModelErrorV1::Changed)?
                    .data_v1()
                    .map_err(|_| CacheCurrentModelErrorV1::Changed)?;
                let snapshot = families.observed_snapshot_v1(
                    self.original
                        .current_journals
                        .as_ref()
                        .ok_or(CacheCurrentModelErrorV1::Changed)?,
                    self.original
                        .current_objects
                        .as_ref()
                        .ok_or(CacheCurrentModelErrorV1::Changed)?,
                    sample,
                )?;
                Ok(CacheCurrentProofBodyDataV1 {
                    lane: challenge.root.open.lane,
                    root_open_checksum: challenge.root_checksum,
                    root_nonce: challenge.root.root_nonce,
                    ready: challenge.root.open.ready,
                    cache_held_checksum: challenge.held_checksum,
                    signer_generation: generation,
                    sample,
                    snapshot,
                })
            })());
            if !matches!(proof.body, Some(Ok(_))) {
                proof.first.get_or_insert(Failure::Body);
            }
        }
        if let Some(Ok(body)) = proof.body {
            proof.encoded = Some(body.encode());
            if !matches!(proof.encoded, Some(Ok(_))) {
                proof.first.get_or_insert(Failure::Encode);
            }
            proof.correlation = Some((|| {
                let raw = self
                    .original
                    .root_request
                    .as_ref()
                    .ok_or(HistoryErrorV1::Correlation)?
                    .bytes()
                    .map_err(|_| HistoryErrorV1::Correlation)?;
                let hello: &[u8; ROOT_HELLO_FRAME_BYTES_V1] = raw[8..8 + ROOT_HELLO_FRAME_BYTES_V1]
                    .try_into()
                    .map_err(|_| HistoryErrorV1::Extent)?;
                let hello = RootHelloDataV1::decode(hello, challenge.root.open)?;
                let held = CacheHeldReceiptDataV1::decode(
                    &raw[8 + ROOT_HELLO_FRAME_BYTES_V1..],
                    challenge.root.open.lane,
                )?;
                body.compare_root_hello_data(hello)?;
                body.compare_held_data(held)
            })());
            if !matches!(proof.correlation, Some(Ok(()))) {
                proof.first.get_or_insert(Failure::Correlation);
            }
        }
        if proof.first.is_none() {
            proof.key = Some(match self.startup.credentials.credential() {
                Ok(credential) => credential.signing_key(),
                Err(_) => Err(crate::cache_signer_credential::CacheSignerCredentialErrorV2),
            });
            if !matches!(proof.key, Some(Ok(_))) {
                proof.first.get_or_insert(Failure::Key);
            }
        }
        if proof.first.is_none() {
            let body = proof
                .encoded
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(Closed)?;
            proof.preimage = Some(current_cache_proof_preimage_v1(body));
            let key = proof
                .key
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(Closed)?;
            proof.signature = Some(key.sign(proof.preimage.as_ref().ok_or(Closed)?));
            let mut packet = [0; CACHE_CURRENT_PROOF_PACKET_BYTES_V1];
            packet[..CACHE_CURRENT_PROOF_BODY_BYTES_V1].copy_from_slice(body);
            packet[CACHE_CURRENT_PROOF_BODY_BYTES_V1..]
                .copy_from_slice(&proof.signature.as_ref().ok_or(Closed)?.to_bytes());
            proof.packet = Some(packet);
        }
        proof.signing.after_result = Some(observe_original(
            &mut self.startup.common,
            &mut proof.signing.after,
        ));
        if !matches!(proof.signing.after_result, Some(Ok(()))) {
            proof.first.get_or_insert(Failure::After);
        }
        let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
        proof.clock = Some(now);
        proof.deadline = Some(
            aos_sandbox_broker::cache_signer_connection::deadline_timeout_v1(now, challenge.cutoff),
        );
        if !matches!(proof.deadline, Some(Ok(_))) {
            proof.first.get_or_insert(Failure::Deadline);
        }
        if proof.first.is_some() {
            return Err(self.fail(First::CurrentProof));
        }
        Ok(())
    }

    fn current_observation_resident_files_v1(&self) -> Result<u64, Closed> {
        // Whole native/clock/object/signing observations remain resident through
        // reply and all independent posts. No later positive drop is credited.
        let clock = self
            .original
            .current_clock_stage
            .demand
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(Closed)?;
        let objects = self
            .original
            .current_objects
            .as_ref()
            .ok_or(Closed)?
            .resident_file_bound_v1()?;
        self.current_purpose_resident_files_v1()?
            .checked_add(clock.get(D::OpenFiles))
            .and_then(|files| files.checked_add(objects))
            .and_then(|files| files.checked_add(sample_pair_demand().ok()?.get(D::OpenFiles)))
            .ok_or(Closed)
    }

    fn send_current_observation_once(&mut self) -> Result<(), Closed> {
        if self.original.first.is_some()
            || !self.original.purpose_stage.complete()
            || !matches!(self.original.root_finish, Some(Ok(())))
            || !matches!(self.original.root_request_finish, Some(Ok(())))
            || !matches!(self.original.controller_request_finish, Some(Ok(())))
            || !matches!(self.original.purpose_after_deadline, Some(Ok(_)))
        {
            return Err(self.fail(First::Closed));
        }
        let cutoff = self.original.root_challenge.data()?.cutoff;
        let resident = self
            .current_observation_resident_files_v1()?
            .checked_add(sample_pair_demand().map_err(|_| Closed)?.get(D::OpenFiles))
            .ok_or(Closed)?;
        let proof = self.original.current_proof.as_mut().ok_or(Closed)?;
        if proof.first.is_some()
            || proof.packet.is_none()
            || !proof.signing.complete()
            || proof.replies.demand.is_some()
        {
            return Err(self.fail(First::Closed));
        }
        proof.replies.demand = Some((|| {
            let overflow = AccountingError::ArithmeticOverflow {
                dimension: D::MemoryBytes,
            };
            let one = CacheReplyOriginalV1::receiving_demand_v1().ok_or(overflow)?;
            one.checked_add(one)?
                .checked_add(sample_pair_demand()?)?
                .checked_add(
                    ResourceVector::ZERO
                        .with(
                            D::NetworkBytes,
                            (CACHE_CURRENT_PROOF_PACKET_BYTES_V1 * 2) as u64,
                        )
                        .with(
                            D::OutputBytes,
                            (CACHE_CURRENT_PROOF_PACKET_BYTES_V1 * 2) as u64,
                        ),
                )
        })());
        if admit_stage(&mut self.startup.common, &mut proof.replies, resident).is_err() {
            proof.first.get_or_insert(Failure::ReplyFunding);
            return Err(self.fail(First::CurrentProof));
        }
        proof.replies.before_result = Some(observe_original(
            &mut self.startup.common,
            &mut proof.replies.before,
        ));
        if !matches!(proof.replies.before_result, Some(Ok(()))) {
            proof.first.get_or_insert(Failure::ReplyBefore);
        }
        if proof.first.is_none() {
            proof.root_result = Some(
                proof.root_reply.send_once(
                    self.original
                        .root_request
                        .as_ref()
                        .ok_or(Closed)?
                        .stream()?,
                    proof.packet.as_ref().ok_or(Closed)?,
                    cutoff,
                ),
            );
            if !matches!(proof.root_result, Some(Ok(()))) {
                proof.first.get_or_insert(Failure::RootReply);
            }
        }
        if proof.first.is_none() {
            proof.controller_result = Some(
                proof.controller_reply.send_once(
                    self.original
                        .controller_request
                        .as_ref()
                        .ok_or(Closed)?
                        .stream()?,
                    proof.packet.as_ref().ok_or(Closed)?,
                    cutoff,
                ),
            );
            if !matches!(proof.controller_result, Some(Ok(()))) {
                proof.first.get_or_insert(Failure::ControllerReply);
            }
        }
        if proof.first.is_none() {
            // This closes the actual Root property/native reservoir after both
            // sends and before the reply stage's independently owed F post.
            self.original.root_settlement = Some(
                self.original
                    .root_interval
                    .as_mut()
                    .ok_or(Closed)?
                    .settle_native_once(cutoff),
            );
            if !matches!(self.original.root_settlement, Some(Ok(()))) {
                proof.first.get_or_insert(Failure::RootSettlement);
                self.original.first.get_or_insert(First::RootSettlement);
            }
        }
        proof.replies.after_result = Some(observe_original(
            &mut self.startup.common,
            &mut proof.replies.after,
        ));
        if !matches!(proof.replies.after_result, Some(Ok(()))) {
            proof.first.get_or_insert(Failure::ReplyAfter);
        }
        let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
        proof.reply_clock = Some(now);
        proof.reply_deadline =
            Some(aos_sandbox_broker::cache_signer_connection::deadline_timeout_v1(now, cutoff));
        if !matches!(proof.reply_deadline, Some(Ok(_))) {
            proof.first.get_or_insert(Failure::ReplyDeadline);
        }
        if proof.first.is_some() {
            return Err(self.fail(First::CurrentProof));
        }
        Ok(())
    }
}
