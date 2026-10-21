//! Checks existing Controller successor signature DATA without native custody.
//!
//! The complete signed observation is compared once. Its decoded fields never
//! create a Controller, Source or Root loan or renew the original signed D.
//!
//! ```text
//! AOSCSO02/03[2560] or AOSCSO04/05[2736]
//! nonce | signer | role UIDs | names | approval | Begin | optional settled tuple
//! ```

use aos_sandbox_model::ObjectDigest;
use aos_sandbox_ledger_replay::data::{digest_at, take};
use aos_sandbox_ledger_replay::replay::phase_records::{
    ControllerFirstSourceSuccessorAnchoredV2, ControllerFirstSourceSuccessorBeginV2,
    ControllerFirstSourceSuccessorCompleteV2, SourceFirstSuccessorAckV2,
    SourceFirstSuccessorReceiptV2,
};
use aos_sandbox_ledger_replay::successor::SourceSuccessorApprovalDataV2;
use aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1;
use ed25519_dalek::Signature;

/// Preserves a refused canonical successor comparison without native authority.
#[derive(Debug, thiserror::Error)]
pub enum ControllerSuccessorReadbackDataErrorV1 {
    /// The fixed packet or saved canonical association is malformed.
    #[error("invalid Source genesis record or exact owner join")]
    NonCanonical,
    /// Independently decoded complete records have different original bindings.
    #[error("Source genesis project or flight conflicts with retained state")]
    Conflict,
    /// The independently pinned signature or original clock comparison changed.
    #[error("Source genesis owner or credential is not current")]
    Stale,
    /// The original signed clock interval no longer admits new work.
    #[error("new Source genesis admission is unavailable")]
    AdmissionClosed,
    /// The sole canonical approval or phase-record decoder refused its DATA.
    #[error(transparent)]
    Source(#[from] aos_sandbox_ledger_replay::data::SourceSuccessorDataErrorV2),
    /// The original protected physical-name DATA decoder refused its bytes.
    #[error(transparent)]
    Mechanical(#[from] aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1),
}

const CONTROLLER_OBSERVATION_BYTES: usize = 2560;
const RESOURCE_CONTROLLER_OBSERVATION_BYTES: usize = 2736;
const OBSERVATION_MAGIC: &[u8; 8] = b"AOSCSO02";
const OBSERVATION_DOMAIN: &[u8] =
    b"aos.sandbox.source-first-successor.controller-held-observation.signature.v2\0";

/// Selects an existing signed comparison purpose without admitting a role.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum ControllerSuccessorSignatureRecipeV3 {
    /// Selects the existing strict successor signature grammar as DATA.
    StrictV2,
    /// Selects the existing mixed successor signature grammar as DATA.
    MixedV3,
}

impl ControllerSuccessorSignatureRecipeV3 {
    /// Returns the fixed magic of the selected comparison grammar.
    pub const fn magic(self, resource: bool) -> &'static [u8; 8] {
        match (self, resource) {
            (Self::StrictV2, false) => OBSERVATION_MAGIC,
            (Self::MixedV3, false) => b"AOSCSO03",
            (Self::StrictV2, true) => b"AOSCSO04",
            (Self::MixedV3, true) => b"AOSCSO05",
        }
    }

    /// Returns the version byte of the selected comparison grammar.
    pub const fn version(self, resource: bool) -> u8 {
        match (self, resource) {
            (Self::StrictV2, false) => 2,
            (Self::MixedV3, false) => 3,
            (Self::StrictV2, true) => 4,
            (Self::MixedV3, true) => 5,
        }
    }

    /// Returns the existing signature domain for comparison DATA.
    pub const fn domain(self, resource: bool) -> &'static [u8] {
        match (self, resource) {
            (Self::StrictV2, false) => OBSERVATION_DOMAIN,
            (Self::MixedV3, false) => {
                b"aos.sandbox.source-first-successor.controller-held-observation.signature.v3\0"
            }
            (Self::StrictV2, true) => {
                b"aos.sandbox.source-first-successor.controller-held-observation.signature.v4\0"
            }
            (Self::MixedV3, true) => {
                b"aos.sandbox.source-first-successor.controller-held-observation.signature.v5\0"
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ControllerObservationPhaseV2 {
    Before,
    Prepared,
    Completed,
}

pub(crate) struct VerifiedControllerFirstSuccessorObservationV2 {
    pub(crate) phase: ControllerObservationPhaseV2,
    pub(crate) packet: SourceSuccessorApprovalDataV2,
    pub(crate) begin: ControllerFirstSourceSuccessorBeginV2,
    pub(crate) root_intent: Option<ObjectDigest>,
    pub(crate) receipt: Option<SourceFirstSuccessorReceiptV2>,
    pub(crate) anchored: Option<ControllerFirstSourceSuccessorAnchoredV2>,
    pub(crate) complete: Option<ControllerFirstSourceSuccessorCompleteV2>,
    pub(crate) ack: Option<SourceFirstSuccessorAckV2>,
    pub(crate) source_names: ProtectedJournalNamesV1,
    pub(crate) source_sequence: u64,
}

// Comparison DATA only. The common parser is private; this wrapper does not
// export a strict-v2 live Controller/Source/Root loan or mutation entrypoint.
pub(crate) struct VerifiedControllerFirstSuccessorObservationV3 {
    pub(crate) data: VerifiedControllerFirstSuccessorObservationV2,
}

pub(crate) fn verify_controller_first_successor_readback_v2(
    bytes: &[u8],
    pin: &crate::controller_readback::PinnedControllerHoldSignerV1,
    nonce: [u8; 16],
    controller_uid: u32,
    source_uid: u32,
) -> Result<VerifiedControllerFirstSuccessorObservationV2, ControllerSuccessorReadbackDataErrorV1> {
    verify_controller_successor_with_recipe(
        bytes,
        pin,
        nonce,
        controller_uid,
        source_uid,
        ControllerSuccessorSignatureRecipeV3::StrictV2,
    )
}

pub(crate) fn verify_controller_project_successor_readback_v3(
    bytes: &[u8],
    pin: &crate::controller_readback::PinnedControllerHoldSignerV1,
    nonce: [u8; 16],
    controller_uid: u32,
    source_uid: u32,
) -> Result<VerifiedControllerFirstSuccessorObservationV3, ControllerSuccessorReadbackDataErrorV1> {
    verify_controller_successor_with_recipe(
        bytes,
        pin,
        nonce,
        controller_uid,
        source_uid,
        ControllerSuccessorSignatureRecipeV3::MixedV3,
    )
    .map(|data| VerifiedControllerFirstSuccessorObservationV3 { data })
}

fn verify_controller_successor_with_recipe(
    bytes: &[u8],
    pin: &crate::controller_readback::PinnedControllerHoldSignerV1,
    nonce: [u8; 16],
    controller_uid: u32,
    source_uid: u32,
    recipe: ControllerSuccessorSignatureRecipeV3,
) -> Result<VerifiedControllerFirstSuccessorObservationV2, ControllerSuccessorReadbackDataErrorV1> {
    let resource = bytes.len() == RESOURCE_CONTROLLER_OBSERVATION_BYTES;
    if !matches!(
        bytes.len(),
        CONTROLLER_OBSERVATION_BYTES | RESOURCE_CONTROLLER_OBSERVATION_BYTES
    ) || nonce == [0; 16]
        || bytes.get(..8) != Some(recipe.magic(resource).as_slice())
        || bytes[8..11] != [0, recipe.version(resource), 1]
        || bytes[12..16] != [0; 4]
        || bytes[16..32] != nonce
        || u64::from_be_bytes(take(bytes, 32)?) != pin.generation()
        || u32::from_be_bytes(take(bytes, 40)?) != controller_uid
        || u32::from_be_bytes(take(bytes, 44)?) != source_uid
    {
        return Err(ControllerSuccessorReadbackDataErrorV1::NonCanonical);
    }
    let body_bytes = bytes.len() - 64;
    let tail = body_bytes - 1144;
    let begin_offset = tail - 296;
    pin.verifying_key()
        .verify_strict(
            &[recipe.domain(resource), &bytes[..body_bytes]].concat(),
            &Signature::from_bytes(&take(bytes, body_bytes)?),
        )
        .map_err(|_| ControllerSuccessorReadbackDataErrorV1::Stale)?;
    let phase = match bytes[11] {
        1 => ControllerObservationPhaseV2::Before,
        2 => ControllerObservationPhaseV2::Prepared,
        3 => ControllerObservationPhaseV2::Completed,
        _ => return Err(ControllerSuccessorReadbackDataErrorV1::NonCanonical),
    };
    let packet = SourceSuccessorApprovalDataV2::from_record_bytes(&bytes[160..begin_offset])?;
    if packet.has_resource_authorization() != resource {
        return Err(ControllerSuccessorReadbackDataErrorV1::NonCanonical);
    }
    let begin = ControllerFirstSourceSuccessorBeginV2::decode(&bytes[begin_offset..tail])
        .map_err(ControllerSuccessorReadbackDataErrorV1::from)?;
    let names = ProtectedJournalNamesV1::from_bytes(&take::<48>(bytes, 64)?)
        .map_err(aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1::from)?;
    let source_names = ProtectedJournalNamesV1::from_bytes(&take::<48>(bytes, 112)?)
        .map_err(aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1::from)?;
    if names == source_names
        || begin.approval() != packet.digest()
        || begin.source_uid() != source_uid
        || begin.predecessor_floor() != digest_at(packet.body(), 144)
        || begin.genesis_complete() != digest_at(packet.body(), 176)
        || begin.old_tree_head() != packet.old_tree_head()
        || begin.old_lineage_head() != packet.old_lineage_head()
        || begin.next_tree_commit() != packet.next_tree_commit()
    {
        return Err(ControllerSuccessorReadbackDataErrorV1::Conflict);
    }
    let (root_intent, receipt, anchored, complete, ack) = if phase
        == ControllerObservationPhaseV2::Before
    {
        if bytes[tail..body_bytes] != [0; 1144] || source_names != begin.source_names() {
            return Err(ControllerSuccessorReadbackDataErrorV1::NonCanonical);
        }
        (None, None, None, None, None)
    } else {
        let receipt = SourceFirstSuccessorReceiptV2::decode(&bytes[tail + 32..tail + 568])
            .map_err(ControllerSuccessorReadbackDataErrorV1::from)?;
        let anchored = (bytes[tail + 568..tail + 712] != [0; 144])
            .then(|| {
                ControllerFirstSourceSuccessorAnchoredV2::decode(&bytes[tail + 568..tail + 712])
                    .map_err(ControllerSuccessorReadbackDataErrorV1::from)
            })
            .transpose()?;
        let complete = (bytes[tail + 712..tail + 952] != [0; 240])
            .then(|| {
                ControllerFirstSourceSuccessorCompleteV2::decode(&bytes[tail + 712..tail + 952])
                    .map_err(ControllerSuccessorReadbackDataErrorV1::from)
            })
            .transpose()?;
        let ack = (bytes[tail + 952..body_bytes] != [0; 192])
            .then(|| {
                SourceFirstSuccessorAckV2::decode(&bytes[tail + 952..body_bytes])
                    .map_err(ControllerSuccessorReadbackDataErrorV1::from)
            })
            .transpose()?;
        if receipt.approval() != packet.digest()
            || receipt.begin() != begin.digest()
            || receipt.root_intent() != digest_at(bytes, tail)
            || receipt.source_names() != begin.source_names()
            || (ack.is_none() && source_names != receipt.source_names())
        {
            return Err(ControllerSuccessorReadbackDataErrorV1::Conflict);
        }
        if let Some(anchored) = &anchored {
            if anchored.approval() != packet.digest() || anchored.receipt() != receipt.digest() {
                return Err(ControllerSuccessorReadbackDataErrorV1::Conflict);
            }
        }
        if let Some(ack) = &ack {
            let anchored = anchored
                .as_ref()
                .ok_or(ControllerSuccessorReadbackDataErrorV1::Conflict)?;
            if ack.receipt() != receipt.digest()
                || ack.root_floor() != anchored.floor()
                || ack.controller_anchored() != anchored.digest()
                || ack.project() != receipt.project()
                || ack.instance() != receipt.instance()
            {
                return Err(ControllerSuccessorReadbackDataErrorV1::Conflict);
            }
        }
        if let Some(complete) = &complete {
            let ack = ack
                .as_ref()
                .ok_or(ControllerSuccessorReadbackDataErrorV1::Conflict)?;
            let anchored = anchored
                .as_ref()
                .ok_or(ControllerSuccessorReadbackDataErrorV1::Conflict)?;
            if complete.approval() != packet.digest()
                || complete.receipt() != receipt.digest()
                || complete.floor() != anchored.floor()
                || complete.ack() != ack.digest()
                || complete.begin() != begin.digest()
                || complete.anchored() != anchored.digest()
            {
                return Err(ControllerSuccessorReadbackDataErrorV1::Conflict);
            }
        }
        if (phase == ControllerObservationPhaseV2::Completed) != complete.is_some() {
            return Err(ControllerSuccessorReadbackDataErrorV1::NonCanonical);
        }
        (
            Some(receipt.root_intent()),
            Some(receipt),
            anchored,
            complete,
            ack,
        )
    };
    Ok(VerifiedControllerFirstSuccessorObservationV2 {
        phase,
        packet,
        begin,
        root_intent,
        receipt,
        anchored,
        complete,
        ack,
        source_names,
        source_sequence: u64::from_be_bytes(take(bytes, 56)?),
    })
}

/// Compares an independently supplied raw pair with the unchanged signed interval.
///
/// # Errors
/// Refuses a different boot, time reversal, drift or expired original interval.
pub fn require_approval_clock(
    packet: &SourceSuccessorApprovalDataV2,
    clock: aos_sandbox_model::RawPairedClockSample,
) -> Result<(), ControllerSuccessorReadbackDataErrorV1> {
    let issued = packet.issued_wall()?;
    let expires = packet.expires_wall()?;
    let issued_boottime = packet.issued_boottime()?;
    let wall = u64::try_from(clock.wall_seconds())
        .map_err(|_| ControllerSuccessorReadbackDataErrorV1::Stale)?;
    let boot_deadline = issued_boottime
        .checked_add(
            expires
                .checked_sub(issued)
                .ok_or(ControllerSuccessorReadbackDataErrorV1::NonCanonical)?
                .checked_mul(1_000_000_000)
                .ok_or(ControllerSuccessorReadbackDataErrorV1::NonCanonical)?,
        )
        .ok_or(ControllerSuccessorReadbackDataErrorV1::NonCanonical)?;
    if packet.boot()? != clock.host_boot_id()
        || wall < issued
        || wall >= expires
        || clock.boottime_nanoseconds() < issued_boottime
        || clock.boottime_nanoseconds() >= boot_deadline
    {
        return Err(ControllerSuccessorReadbackDataErrorV1::AdmissionClosed);
    }
    let original = aos_sandbox_model::RawPairedClockSample::new_untrusted(
        clock.provenance(),
        packet.boot()?,
        i64::try_from(issued).map_err(|_| ControllerSuccessorReadbackDataErrorV1::NonCanonical)?,
        issued_boottime,
    )
    .map_err(|_| ControllerSuccessorReadbackDataErrorV1::NonCanonical)?;
    original
        .validate_later_sample(clock)
        .map_err(|_| ControllerSuccessorReadbackDataErrorV1::Stale)?;
    Ok(())
}
