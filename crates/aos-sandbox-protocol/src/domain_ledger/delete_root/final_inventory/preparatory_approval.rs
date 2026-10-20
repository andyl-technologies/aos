//! Binds preparatory desired-state acceptance to the exact signed cleanup draft.
//!
//! ```text
//! AOSDPA03 | version3/reserved | open32 | challenge32 | fresh-frame32 |
//! exact-draft-and-signature32 | actual-Root-paired-clock48
//! ```
//!
//! The full frame already commits every fresh-six descriptor. Its redundant
//! hash slot therefore names the exact concrete draft and verified signature.
//! This DATA never creates a native borrower, dispatch permission, destruction
//! result or final D disposition. The prior unshipped final-only purpose has no
//! decoder or compatibility path.

use super::{DeleteRootFreshFrameDataV2, initial_ack_commitment_data_v2};
use super::super::{initial_inventory::DeleteRootInitialAckDataV3,
    transport::{DeleteRootChallengeDataV2, DeleteRootWireErrorV2, array, decode_clock,
        encode_clock, header_v3, encode_header_v3},
    resource_exchange::{DeleteRootResourceContextDataV2, DeleteRootResourceDraftDataV2,
        DeleteRootResourceSignedDataV2, DeleteRootResourceWireErrorV2}};
use aos_sandbox_core::RawPairedClockSample;
use super::super::resource_exchange::DeleteRootResourcePurposeDataV3 as Purpose;
use super::super::preparation_current::DeleteRootPreparationCurrentDataV3;

/// Gives the exact finite concrete preparatory acceptance frame extent.
pub const DELETE_ROOT_PREPARATORY_APPROVAL_BYTES_V3: usize = 192;

/// Carries nonauthorizing comparison DATA for the concrete preparatory approval.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeleteRootPreparatoryApprovalDataV3 {
    /// Commits the complete original pending opening.
    pub open: [u8; 32],
    /// Commits the unchanged challenge on that original socket.
    pub challenge: [u8; 32],
    /// Commits the full late fresh-six and Controller comparison frame.
    pub frame: [u8; 32],
    /// Commits the exact unsigned draft and returned canonical signature.
    pub preparation: [u8; 32],
    /// Gives the genuine Root preparatory sender's completed native sample.
    pub clock: RawPairedClockSample,
}

impl DeleteRootPreparatoryApprovalDataV3 {
    /// Encodes only this distinct concrete preparatory purpose.
    ///
    /// # Errors
    /// Rejects a zero identity or invalid clock representation.
    pub fn encode_v3(self) -> Result<[u8; DELETE_ROOT_PREPARATORY_APPROVAL_BYTES_V3], DeleteRootWireErrorV2> {
        self.encode_for_purpose_v3(Purpose::Preparation26)
    }

    /// Encodes the finite same-flight purpose with a distinct strict header.
    ///
    /// # Errors
    /// Rejects the same invalid identities and clocks as the preparatory codec.
    pub fn encode_for_purpose_v3(self, purpose: Purpose)
        -> Result<[u8; DELETE_ROOT_PREPARATORY_APPROVAL_BYTES_V3], DeleteRootWireErrorV2> {
        self.require_canonical_v3()?;
        let mut bytes = [0; DELETE_ROOT_PREPARATORY_APPROVAL_BYTES_V3];
        encode_header_v3(&mut bytes, approval_magic_v3(purpose));
        for (index, digest) in [self.open, self.challenge, self.frame, self.preparation].iter().enumerate() {
            bytes[16 + index * 32..48 + index * 32].copy_from_slice(digest);
        }
        encode_clock(&mut bytes, 144, self.clock);
        Ok(bytes)
    }

    /// Decodes exactly this purpose, without accepting initial or old final ACKs.
    ///
    /// # Errors
    /// Rejects another purpose/version, reserved bytes, trailing data or zero fields.
    pub fn decode_v3(bytes: &[u8]) -> Result<Self, DeleteRootWireErrorV2> {
        Self::decode_for_purpose_v3(bytes, Purpose::Preparation26)
    }

    /// Decodes only the exact finite purpose supplied by its genuine caller.
    ///
    /// # Errors
    /// Rejects another purpose or the same malformed fields as the strict codec.
    pub fn decode_for_purpose_v3(bytes: &[u8], purpose: Purpose) -> Result<Self, DeleteRootWireErrorV2> {
        header_v3(bytes, DELETE_ROOT_PREPARATORY_APPROVAL_BYTES_V3, approval_magic_v3(purpose))?;
        let value = Self { open: array(bytes, 16)?, challenge: array(bytes, 48)?,
            frame: array(bytes, 80)?, preparation: array(bytes, 112)?, clock: decode_clock(bytes, 144)? };
        value.require_canonical_v3()?;
        Ok(value)
    }

    /// Compares the complete frame and its exact concrete signed preparation.
    ///
    /// # Errors
    /// Rejects another frame, fresh six, draft, signature, regressed clock or
    /// the actual Root-issued signed-policy expiry.
    pub fn require_resources_v3(self, frame: DeleteRootFreshFrameDataV2,
        draft: DeleteRootResourceDraftDataV2<'_>, signed: DeleteRootResourceSignedDataV2<'_>,
    ) -> Result<(), DeleteRootResourceWireErrorV2> {
        self.require_resources_inner_v3(frame, draft, signed, PredecessorV4::Preparation)
    }

    fn require_resources_inner_v3(self, frame: DeleteRootFreshFrameDataV2,
        draft: DeleteRootResourceDraftDataV2<'_>, signed: DeleteRootResourceSignedDataV2<'_>,
        current: PredecessorV4,
    ) -> Result<(), DeleteRootResourceWireErrorV2> {
        self.require_canonical_v3()?;
        let purpose = match current {
            PredecessorV4::Preparation => Purpose::Preparation26,
            PredecessorV4::Apply(..) => Purpose::Apply7,
            PredecessorV4::Network(..) => Purpose::Network9,
            PredecessorV4::Mount(..) => Purpose::MountReap62,
        };
        let context = DeleteRootResourceContextDataV2::decode_for_purpose_v3(draft.context, purpose)?;
        let expected_frame = match current {
            PredecessorV4::Preparation => { context.require_frame_v2(frame, context.lease)?; frame.digest_v2()? }
            PredecessorV4::Apply(current, prior_draft) => {
                context.require_preparation_current_v3(frame, current, prior_draft, context.lease)?;
                current.commitment_v3().map_err(|_| DeleteRootWireErrorV2::Association)?
            }
            PredecessorV4::Network(prior, prior26) => {
                context.require_network_predecessor_v4(frame, prior, prior26, context.lease)?;
                prior.commitment_v4()?
            }
            PredecessorV4::Mount(current, approved9) => {
                context.require_cleanup_current_v4(frame, current, approved9, context.lease)?;
                current.commitment_v4().map_err(|_| DeleteRootWireErrorV2::Association)?
            }
        };
        if self.open != frame.open || self.challenge != frame.challenge
            || self.frame != expected_frame
            || self.preparation != signed.acceptance_commitment_for_purpose_v3(draft, purpose)? {
            return Err(DeleteRootWireErrorV2::Association.into());
        }
        context.clock.validate_later_sample(self.clock).map_err(|_| DeleteRootWireErrorV2::Clock)?;
        if self.clock.wall_seconds() >= context.policy_expires_seconds { return Err(DeleteRootWireErrorV2::Clock.into()); }
        Ok(())
    }

    /// Compares the full same-flight conjunction under the unchanged horizon.
    ///
    /// # Errors
    /// Rejects another initial ACK/challenge, changed signed resources, a
    /// regressed clock, or the original Root or fresh Cache cutoff.
    pub fn require_exchange_v3(self, frame: DeleteRootFreshFrameDataV2,
        challenge: DeleteRootChallengeDataV2, initial: DeleteRootInitialAckDataV3,
        draft: DeleteRootResourceDraftDataV2<'_>, signed: DeleteRootResourceSignedDataV2<'_>,
    ) -> Result<(), DeleteRootResourceWireErrorV2> {
        self.require_resources_v3(frame, draft, signed)?;
        self.require_original_exchange_v3(frame, challenge, initial)
    }

    /// Compares a concrete Apply7 approval with its complete actual post26 predecessor.
    ///
    /// This pure comparison requires the exact prior26 draft and retains every
    /// original challenge, initial-ACK, Cache cutoff and clock predicate.
    ///
    /// # Errors
    /// Rejects another predecessor, purpose, signed plan, horizon or clock.
    pub fn require_apply_exchange_v3(self, frame: DeleteRootFreshFrameDataV2,
        challenge: DeleteRootChallengeDataV2, initial: DeleteRootInitialAckDataV3,
        current: DeleteRootPreparationCurrentDataV3, prior_draft: [u8; 32],
        draft: DeleteRootResourceDraftDataV2<'_>, signed: DeleteRootResourceSignedDataV2<'_>,
    ) -> Result<(), DeleteRootResourceWireErrorV2> {
        self.require_resources_inner_v3(frame, draft, signed, PredecessorV4::Apply(current, prior_draft))?;
        self.require_original_exchange_v3(frame, challenge, initial)
    }

    /// Compares Network9 approval with actual7 approval and the same original D.
    ///
    /// # Errors
    /// Rejects another purpose, full predecessor, signed9 plan or original horizon.
    pub fn require_network_exchange_v4(self, frame: DeleteRootFreshFrameDataV2,
        challenge: DeleteRootChallengeDataV2, initial: DeleteRootInitialAckDataV3,
        predecessor: super::super::resource_exchange::DeleteRootNetworkPredecessorDataV4,
        prior26_draft: [u8; 32], draft: DeleteRootResourceDraftDataV2<'_>,
        signed: DeleteRootResourceSignedDataV2<'_>,
    ) -> Result<(), DeleteRootResourceWireErrorV2> {
        self.require_resources_inner_v3(frame, draft, signed, PredecessorV4::Network(predecessor, prior26_draft))?;
        self.require_original_exchange_v3(frame, challenge, initial)
    }

    /// Compares Mount62 approval with the completed same-D cleanup conjunction.
    ///
    /// # Errors
    /// Rejects another strict9 approval, original challenge, fresh Host receipt,
    /// signed Mount draft or unchanged authorization horizon.
    pub fn require_mount_exchange_v4(self, frame: DeleteRootFreshFrameDataV2,
        challenge: DeleteRootChallengeDataV2, initial: DeleteRootInitialAckDataV3,
        current: super::super::cleanup_current::DeleteRootCleanupCurrentDataV4,
        approved9: DeleteRootPreparatoryApprovalDataV3,
        draft: DeleteRootResourceDraftDataV2<'_>, signed: DeleteRootResourceSignedDataV2<'_>,
    ) -> Result<(), DeleteRootResourceWireErrorV2> {
        if current.challenge != challenge.source.nonce {
            return Err(DeleteRootWireErrorV2::Association.into());
        }
        self.require_resources_inner_v3(frame, draft, signed, PredecessorV4::Mount(current, approved9))?;
        self.require_original_exchange_v3(frame, challenge, initial)
    }

    fn require_original_exchange_v3(self, frame: DeleteRootFreshFrameDataV2,
        challenge: DeleteRootChallengeDataV2, initial: DeleteRootInitialAckDataV3,
    ) -> Result<(), DeleteRootResourceWireErrorV2> {
        if initial.open != frame.open || initial.challenge != frame.challenge
            || self.challenge != challenge.digest_v2()?
            || frame.initial_ack != initial_ack_commitment_data_v2(&initial.encode_v3()?) {
            return Err(DeleteRootWireErrorV2::Association.into());
        }
        initial.clock.validate_later_sample(self.clock).map_err(|_| DeleteRootWireErrorV2::Clock)?;
        challenge.clock.validate_later_sample(self.clock).map_err(|_| DeleteRootWireErrorV2::Clock)?;
        if self.clock.boottime_nanoseconds() >= challenge.source.cutoff
            || self.clock.boottime_nanoseconds() >= frame.cache_cutoff { return Err(DeleteRootWireErrorV2::Clock.into()); }
        Ok(())
    }

    fn require_canonical_v3(self) -> Result<(), DeleteRootWireErrorV2> {
        if [self.open, self.challenge, self.frame, self.preparation].into_iter().any(|digest| digest == [0; 32])
            || self.clock.boottime_nanoseconds() == 0 { return Err(DeleteRootWireErrorV2::Format); }
        Ok(())
    }
}

fn approval_magic_v3(purpose: Purpose) -> &'static [u8; 8] {
    match purpose { Purpose::Preparation26 => b"AOSDPA03", Purpose::Apply7 => b"AOSDAA03", Purpose::Network9 => b"AOSDNA04", Purpose::MountReap62 => b"AOSDMA04" }
}

#[derive(Clone, Copy)]
enum PredecessorV4 {
    Preparation,
    Apply(DeleteRootPreparationCurrentDataV3, [u8; 32]),
    Network(super::super::resource_exchange::DeleteRootNetworkPredecessorDataV4, [u8; 32]),
    Mount(super::super::cleanup_current::DeleteRootCleanupCurrentDataV4, DeleteRootPreparatoryApprovalDataV3),
}
