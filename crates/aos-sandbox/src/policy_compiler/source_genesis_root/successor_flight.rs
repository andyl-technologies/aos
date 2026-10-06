//! Closed successor-purpose loans from the original normal Root flight.
//!
//! The shared connection engine keeps the original description, peer, image,
//! policy and finite custody clock. Only receipt on that stream constructs
//! Prepared, Anchored or Completed. Persisted admission identity never follows
//! a new recovery flight's observation nonce or custody deadline.

use aos_sandbox_core::ObjectDigest;

use crate::hierarchy::genesis_profile::{SourceGenesisErrorV1, take};

use super::flight::OriginalRootGenesisFlightV1;
use super::successor_consumer::{HeldControllerFirstSourceSuccessorV2, HeldControllerProjectSuccessorV3, ControllerSuccessorOwnerViewV3};
use super::successor_records::{RootFirstSourceSuccessorFloorV2, RootFirstSourceSuccessorIntentV2};
use super::wire::{RootFirstSourceSuccessorFrameKindV2 as Phase, FirstSuccessorWireRecipeV3,
    decode_root_first_source_successor_frame_v2, decode_root_project_source_successor_frame_v3};

pub(super) struct OriginalRootFirstSourceSuccessorFlightV2<'flight> {
    origin: &'flight OriginalRootGenesisFlightV1<'flight>,
    recipe: FirstSuccessorWireRecipeV3,
}

impl<'flight> OriginalRootFirstSourceSuccessorFlightV2<'flight> {
    pub(super) fn from_original(origin: &'flight OriginalRootGenesisFlightV1<'flight>) -> Result<Self, SourceGenesisErrorV1> {
        origin.recheck()?;
        Ok(Self { origin, recipe: FirstSuccessorWireRecipeV3::StrictV2 })
    }

    pub(super) fn recheck(&self) -> Result<(), SourceGenesisErrorV1> {
        self.origin.recheck()?;
        self.origin.first_successor_clock().map(|_| ())
    }

    pub(super) fn nonce(&self) -> [u8; 16] { self.origin.nonce() }

    pub(super) fn source_uid(&self) -> Result<u32, SourceGenesisErrorV1> { self.origin.first_successor_source_uid() }

    pub(super) fn signing_boundary_clock(&self) -> Result<aos_sandbox_core::RawPairedClockSample, SourceGenesisErrorV1> {
        self.origin.first_successor_clock()
    }

    pub(super) fn observe_original_clock(&self) -> Result<aos_sandbox_core::RawPairedClockSample, SourceGenesisErrorV1> {
        self.origin.observe_first_successor_clock()
    }

    pub(super) fn prepared(
        &'flight self,
        frame: &[u8],
        controller: &HeldControllerFirstSourceSuccessorV2<'_>,
    ) -> Result<HeldRootFirstSourceSuccessorIntentV2<'flight>, SourceGenesisErrorV1> {
        self.prepared_with_recipe_v3(frame, ControllerSuccessorOwnerViewV3::Strict(controller))
    }

    fn decode<'frame>(&self, frame: &'frame [u8], phase: Phase) -> Result<&'frame [u8], SourceGenesisErrorV1> {
        match self.recipe {
            FirstSuccessorWireRecipeV3::StrictV2 => decode_root_first_source_successor_frame_v2(frame, phase, self.nonce()),
            FirstSuccessorWireRecipeV3::MixedV3 => decode_root_project_source_successor_frame_v3(frame, phase, self.nonce()),
        }
    }

    fn prepared_with_recipe_v3(
        &'flight self, frame: &[u8], controller: ControllerSuccessorOwnerViewV3<'_, '_>,
    ) -> Result<HeldRootFirstSourceSuccessorIntentV2<'flight>, SourceGenesisErrorV1> {
        self.recheck()?;
        controller.recheck()?;
        let record = RootFirstSourceSuccessorIntentV2::decode(
            self.decode(frame, Phase::Prepared)?,
        )?;
        if record.approval_packet() != controller.packet() || record.begin() != controller.begin().digest()
            || record.source_uid() != self.source_uid()? || record.source_uid() != controller.source_uid()
            || record.source_names() != controller.begin().source_names()
        {
            return Err(SourceGenesisErrorV1::Conflict);
        }
        let held = HeldRootFirstSourceSuccessorIntentV2 { origin: self, record };
        held.recheck()?;
        Ok(held)
    }

    pub(super) fn anchored(
        &'flight self,
        frame: &[u8],
        prepared: &HeldRootFirstSourceSuccessorIntentV2<'_>,
    ) -> Result<RootFirstSourceSuccessorFloorProofV2<'flight>, SourceGenesisErrorV1> {
        self.recheck()?;
        prepared.recheck()?;
        let floor = RootFirstSourceSuccessorFloorV2::decode(
            self.decode(frame, Phase::Anchored)?,
        )?;
        super::successor_owner::require_receipt_intent(floor.receipt(), prepared.record())?;
        if floor.roles() != prepared.record().roles() || floor.approval() != prepared.record().approval()
            || floor.predecessor_floor() != prepared.record().predecessor_floor()
            || !std::ptr::eq(self, prepared.origin)
        {
            return Err(SourceGenesisErrorV1::Conflict);
        }
        let proof = RootFirstSourceSuccessorFloorProofV2 { origin: self, floor, original: prepared.record().clone() };
        proof.recheck()?;
        Ok(proof)
    }

    pub(super) fn completed<'completed>(
        &self,
        frame: &[u8],
        floor: &'completed RootFirstSourceSuccessorFloorProofV2<'flight>,
        controller: &HeldControllerFirstSourceSuccessorV2<'_>,
    ) -> Result<CompletedRootFirstSourceSuccessorFloorV2<'completed, 'flight>, SourceGenesisErrorV1> {
        self.completed_with_recipe_v3(frame, floor, ControllerSuccessorOwnerViewV3::Strict(controller))
    }

    fn completed_with_recipe_v3<'completed>(
        &self, frame: &[u8], floor: &'completed RootFirstSourceSuccessorFloorProofV2<'flight>,
        controller: ControllerSuccessorOwnerViewV3<'_, '_>,
    ) -> Result<CompletedRootFirstSourceSuccessorFloorV2<'completed, 'flight>, SourceGenesisErrorV1> {
        self.recheck()?;
        floor.recheck()?;
        controller.recheck()?;
        if !std::ptr::eq(self, floor.origin) { return Err(SourceGenesisErrorV1::Conflict); }
        let payload = self.decode(frame, Phase::Completed)?;
        let complete = controller.complete().ok_or(SourceGenesisErrorV1::Conflict)?;
        if payload[..32] != floor.floor.digest().as_bytes()[..]
            || payload[32..64] != complete.digest().as_bytes()[..]
            || payload[64..96] != complete.ack().as_bytes()[..]
        {
            return Err(SourceGenesisErrorV1::Conflict);
        }
        Ok(CompletedRootFirstSourceSuccessorFloorV2 {
            proof: floor, controller_complete: complete.digest(), source_ack: complete.ack(),
        })
    }
}

pub(super) struct OriginalRootProjectSuccessorFlightV3<'flight> {
    common: OriginalRootFirstSourceSuccessorFlightV2<'flight>,
}

#[derive(Clone, Copy)]
pub(super) enum RootSuccessorFlightViewV3<'loan, 'flight> {
    Strict(&'loan OriginalRootFirstSourceSuccessorFlightV2<'flight>),
    Mixed(&'loan OriginalRootProjectSuccessorFlightV3<'flight>),
}

impl<'loan, 'flight> RootSuccessorFlightViewV3<'loan, 'flight> {
    fn data(&self) -> &OriginalRootFirstSourceSuccessorFlightV2<'flight> {
        match self { Self::Strict(flight) => flight, Self::Mixed(flight) => &flight.common }
    }

    pub(super) fn recheck(&self) -> Result<(), SourceGenesisErrorV1> { self.data().recheck() }
    pub(super) fn nonce(&self) -> [u8; 16] { self.data().nonce() }
    pub(super) fn source_uid(&self) -> Result<u32, SourceGenesisErrorV1> { self.data().source_uid() }
    pub(super) fn signing_boundary_clock(&self) -> Result<aos_sandbox_core::RawPairedClockSample, SourceGenesisErrorV1> { self.data().signing_boundary_clock() }
    pub(super) fn observe_original_clock(&self) -> Result<aos_sandbox_core::RawPairedClockSample, SourceGenesisErrorV1> { self.data().observe_original_clock() }
}

impl<'flight> OriginalRootProjectSuccessorFlightV3<'flight> {
    pub(super) fn from_original(origin: &'flight OriginalRootGenesisFlightV1<'flight>) -> Result<Self, SourceGenesisErrorV1> {
        origin.recheck()?;
        Ok(Self { common: OriginalRootFirstSourceSuccessorFlightV2 { origin, recipe: FirstSuccessorWireRecipeV3::MixedV3 } })
    }

    pub(super) fn recheck(&self) -> Result<(), SourceGenesisErrorV1> { self.common.recheck() }
    pub(super) fn nonce(&self) -> [u8; 16] { self.common.nonce() }
    pub(super) fn source_uid(&self) -> Result<u32, SourceGenesisErrorV1> { self.common.source_uid() }
    pub(super) fn signing_boundary_clock(&self) -> Result<aos_sandbox_core::RawPairedClockSample, SourceGenesisErrorV1> { self.common.signing_boundary_clock() }
    pub(super) fn observe_original_clock(&self) -> Result<aos_sandbox_core::RawPairedClockSample, SourceGenesisErrorV1> { self.common.observe_original_clock() }

    pub(super) fn prepared(
        &'flight self, frame: &[u8], controller: &HeldControllerProjectSuccessorV3<'_>,
    ) -> Result<HeldRootProjectSuccessorIntentV3<'flight>, SourceGenesisErrorV1> {
        self.common.prepared_with_recipe_v3(frame, ControllerSuccessorOwnerViewV3::Mixed(controller))
            .map(|common| HeldRootProjectSuccessorIntentV3 { common })
    }

    pub(super) fn anchored(
        &'flight self, frame: &[u8], prepared: &HeldRootProjectSuccessorIntentV3<'_>,
    ) -> Result<RootProjectSuccessorFloorProofV3<'flight>, SourceGenesisErrorV1> {
        self.common.anchored(frame, &prepared.common).map(|common| RootProjectSuccessorFloorProofV3 { common })
    }

    pub(super) fn completed<'completed>(
        &self, frame: &[u8], floor: &'completed RootProjectSuccessorFloorProofV3<'flight>,
        controller: &HeldControllerProjectSuccessorV3<'_>,
    ) -> Result<CompletedRootProjectSuccessorFloorV3<'completed, 'flight>, SourceGenesisErrorV1> {
        self.common.completed_with_recipe_v3(frame, &floor.common, ControllerSuccessorOwnerViewV3::Mixed(controller))
            .map(|common| CompletedRootProjectSuccessorFloorV3 { common })
    }
}

/// Retains the selected durable intent under its genuine mixed original flight.
pub struct HeldRootProjectSuccessorIntentV3<'flight> {
    common: HeldRootFirstSourceSuccessorIntentV2<'flight>,
}

impl HeldRootProjectSuccessorIntentV3<'_> {
    /// Borrows immutable original admission DATA without renewing its bound.
    pub fn record(&self) -> &RootFirstSourceSuccessorIntentV2 { self.common.record() }
    /// Returns the independently authenticated configured Source UID.
    pub fn source_uid(&self) -> u32 { self.common.source_uid() }
    /// Rechecks the same original peer, endpoint, policy and custody cut.
    ///
    /// # Errors
    /// Rejects any lost original custody or changed selected Source identity.
    pub fn recheck(&self) -> Result<(), SourceGenesisErrorV1> { self.common.recheck() }
    /// Checks the original nonrenewable signed new-append admission.
    ///
    /// # Errors
    /// Rejects original expiry, boot discontinuity or persisted deadline.
    pub fn recheck_current_admission(&self) -> Result<(), SourceGenesisErrorV1> { self.common.recheck_current_admission() }
}

#[derive(Clone, Copy)]
pub(crate) enum RootSuccessorIntentViewV3<'loan, 'flight> {
    Strict(&'loan HeldRootFirstSourceSuccessorIntentV2<'flight>),
    Mixed(&'loan HeldRootProjectSuccessorIntentV3<'flight>),
}

impl<'loan, 'flight> RootSuccessorIntentViewV3<'loan, 'flight> {
    fn data(&self) -> &HeldRootFirstSourceSuccessorIntentV2<'flight> {
        match self { Self::Strict(owner) => owner, Self::Mixed(owner) => &owner.common }
    }

    pub(crate) fn record(&self) -> &RootFirstSourceSuccessorIntentV2 { self.data().record() }
    pub(crate) fn source_uid(&self) -> u32 { self.data().source_uid() }
    pub(crate) fn recheck(&self) -> Result<(), SourceGenesisErrorV1> { self.data().recheck() }
    pub(crate) fn recheck_current_admission(&self) -> Result<(), SourceGenesisErrorV1> { self.data().recheck_current_admission() }
    pub(crate) fn current_admission_clock(&self) -> Result<aos_sandbox_core::RawPairedClockSample, SourceGenesisErrorV1> { self.data().current_admission_clock() }
    pub(crate) fn observe_original_clock(&self) -> Result<aos_sandbox_core::RawPairedClockSample, SourceGenesisErrorV1> { self.data().observe_original_clock() }
}

/// Retains the selected actual floor and its original immutable archive join.
pub struct RootProjectSuccessorFloorProofV3<'flight> {
    common: RootFirstSourceSuccessorFloorProofV2<'flight>,
}

impl RootProjectSuccessorFloorProofV3<'_> {
    /// Borrows the exact selected logical floor DATA.
    pub fn floor(&self) -> &RootFirstSourceSuccessorFloorV2 { self.common.floor() }
    /// Borrows the persisted original admission DATA.
    pub fn original_intent(&self) -> &RootFirstSourceSuccessorIntentV2 { self.common.original_intent() }
    /// Returns the independently authenticated Source UID.
    pub fn source_uid(&self) -> u32 { self.common.source_uid() }
    /// Rechecks genuine original custody and the whole receipt/archive join.
    ///
    /// # Errors
    /// Rejects changed custody, peer or original receipt/intent bindings.
    pub fn recheck(&self) -> Result<(), SourceGenesisErrorV1> { self.common.recheck() }
    pub(crate) fn observe_original_clock(&self) -> Result<aos_sandbox_core::RawPairedClockSample, SourceGenesisErrorV1> { self.common.observe_original_clock() }
}

#[derive(Clone, Copy)]
pub(crate) enum RootSuccessorFloorViewV3<'loan, 'flight> {
    Strict(&'loan RootFirstSourceSuccessorFloorProofV2<'flight>),
    Mixed(&'loan RootProjectSuccessorFloorProofV3<'flight>),
}

impl<'loan, 'flight> RootSuccessorFloorViewV3<'loan, 'flight> {
    fn data(&self) -> &RootFirstSourceSuccessorFloorProofV2<'flight> {
        match self { Self::Strict(owner) => owner, Self::Mixed(owner) => &owner.common }
    }

    pub(crate) fn floor(&self) -> &RootFirstSourceSuccessorFloorV2 { self.data().floor() }
    pub(crate) fn original_intent(&self) -> &RootFirstSourceSuccessorIntentV2 { self.data().original_intent() }
    pub(crate) fn source_uid(&self) -> u32 { self.data().source_uid() }
    pub(crate) fn recheck(&self) -> Result<(), SourceGenesisErrorV1> { self.data().recheck() }
    pub(crate) fn observe_original_clock(&self) -> Result<aos_sandbox_core::RawPairedClockSample, SourceGenesisErrorV1> { self.data().observe_original_clock() }
}

pub(in crate::policy_compiler) struct CompletedRootProjectSuccessorFloorV3<'completed, 'flight> {
    common: CompletedRootFirstSourceSuccessorFloorV2<'completed, 'flight>,
}

impl CompletedRootProjectSuccessorFloorV3<'_, '_> {
    pub(in crate::policy_compiler) fn recheck(&self) -> Result<(), SourceGenesisErrorV1> { self.common.recheck() }
    pub(in crate::policy_compiler) fn floor(&self) -> &RootFirstSourceSuccessorFloorV2 { self.common.floor() }
    pub(in crate::policy_compiler) fn source_uid(&self) -> u32 { self.common.source_uid() }
    pub(in crate::policy_compiler) fn controller_complete(&self) -> ObjectDigest { self.common.controller_complete() }
    pub(in crate::policy_compiler) fn source_ack(&self) -> ObjectDigest { self.common.source_ack() }
    pub(super) fn finish_payload(&self) -> [u8; 96] { self.common.finish_payload() }
}

/// Borrows exact durable Prepared DATA from its original Root connection.
pub struct HeldRootFirstSourceSuccessorIntentV2<'flight> {
    origin: &'flight OriginalRootFirstSourceSuccessorFlightV2<'flight>,
    record: RootFirstSourceSuccessorIntentV2,
}

impl HeldRootFirstSourceSuccessorIntentV2<'_> {
    /// Borrows the original immutable admission intent.
    pub const fn record(&self) -> &RootFirstSourceSuccessorIntentV2 { &self.record }

    /// Returns the actual configured Source UID of the still-held Root peer.
    pub fn source_uid(&self) -> u32 { self.record.source_uid() }

    /// Rechecks original endpoint, description, peer, policy and custody clock.
    ///
    /// # Errors
    /// Rejects lost original custody or a foreign selected Source identity.
    pub fn recheck(&self) -> Result<(), SourceGenesisErrorV1> {
        self.origin.recheck()?;
        if self.origin.source_uid()? != self.record.source_uid() { return Err(SourceGenesisErrorV1::Stale); }
        Ok(())
    }

    /// Separately checks the persisted, nonrenewable new-append admission bound.
    ///
    /// # Errors
    /// Rejects original approval expiry, boot discontinuity or persisted D.
    pub fn recheck_current_admission(&self) -> Result<(), SourceGenesisErrorV1> {
        self.recheck()?;
        self.current_admission_clock().map(|_| ())
    }

    // Only a genuine original loan reaches this pure final crossing sample.
    // All slow owner/location work must precede it in the native caller.
    pub(crate) fn current_admission_clock(&self) -> Result<aos_sandbox_core::RawPairedClockSample, SourceGenesisErrorV1> {
        let clock = self.observe_original_clock()?;
        super::successor_consumer::require_approval_clock(self.record.approval_packet(), clock)?;
        if clock.host_boot_id() != self.record.boot()
            || clock.boottime_nanoseconds() >= self.record.boottime_deadline()
            || u64::try_from(clock.wall_seconds()).map_err(|_| SourceGenesisErrorV1::AdmissionClosed)? >= self.record.expires_wall()
        {
            return Err(SourceGenesisErrorV1::AdmissionClosed);
        }
        Ok(clock)
    }

    pub(crate) fn observe_original_clock(&self) -> Result<aos_sandbox_core::RawPairedClockSample, SourceGenesisErrorV1> {
        self.origin.observe_original_clock()
    }
}

/// Borrows the exact successor floor and original archived intent on one stream.
pub struct RootFirstSourceSuccessorFloorProofV2<'flight> {
    origin: &'flight OriginalRootFirstSourceSuccessorFlightV2<'flight>,
    floor: RootFirstSourceSuccessorFloorV2,
    original: RootFirstSourceSuccessorIntentV2,
}

impl RootFirstSourceSuccessorFloorProofV2<'_> {
    /// Borrows the logical floor; its wire width does not discard the archive.
    pub const fn floor(&self) -> &RootFirstSourceSuccessorFloorV2 { &self.floor }

    /// Borrows the immutable original intent retained in the physical archive.
    pub const fn original_intent(&self) -> &RootFirstSourceSuccessorIntentV2 { &self.original }

    /// Returns the actual Root peer's selected Source UID.
    pub fn source_uid(&self) -> u32 { self.original.source_uid() }

    /// Rechecks genuine original Root custody and the complete archive join.
    ///
    /// # Errors
    /// Rejects changed peer, custody deadline or original receipt/intent joins.
    pub fn recheck(&self) -> Result<(), SourceGenesisErrorV1> {
        self.origin.recheck()?;
        super::successor_owner::require_receipt_intent(self.floor.receipt(), &self.original)?;
        if self.origin.source_uid()? != self.original.source_uid() { return Err(SourceGenesisErrorV1::Stale); }
        Ok(())
    }

    pub(crate) fn observe_original_clock(&self) -> Result<aos_sandbox_core::RawPairedClockSample, SourceGenesisErrorV1> {
        self.origin.observe_original_clock()
    }
}

pub(in crate::policy_compiler) struct CompletedRootFirstSourceSuccessorFloorV2<'completed, 'flight> {
    proof: &'completed RootFirstSourceSuccessorFloorProofV2<'flight>,
    controller_complete: ObjectDigest,
    source_ack: ObjectDigest,
}

impl CompletedRootFirstSourceSuccessorFloorV2<'_, '_> {
    pub(in crate::policy_compiler) fn recheck(&self) -> Result<(), SourceGenesisErrorV1> { self.proof.recheck() }
    pub(in crate::policy_compiler) fn floor(&self) -> &RootFirstSourceSuccessorFloorV2 { self.proof.floor() }
    pub(in crate::policy_compiler) fn source_uid(&self) -> u32 { self.proof.source_uid() }
    pub(in crate::policy_compiler) fn controller_complete(&self) -> ObjectDigest { self.controller_complete }
    pub(in crate::policy_compiler) fn source_ack(&self) -> ObjectDigest { self.source_ack }
    pub(super) fn finish_payload(&self) -> [u8; 96] {
        let mut payload = [0; 96];
        payload[..32].copy_from_slice(self.floor().digest().as_bytes());
        payload[32..64].copy_from_slice(self.controller_complete.as_bytes());
        payload[64..].copy_from_slice(self.source_ack.as_bytes());
        payload
    }
}
