//! Resident issuance on the original completed generation-one Root flight.
//!
//! The state borrows the actual Controller and Source writers, selected
//! profile and parked credential owner. Its raw/adopted/validated descriptions
//! remain resident across every failed crossing. Only this implementation can
//! mark success, after exact durable delivery and SAME-flight Finish.

use std::os::fd::OwnedFd;

use aos_sandbox_core::{DesiredGeneration, RawPairedClockSample};
use aos_sandbox_linux::unix_stream::RetainedUnixStream;
use ed25519_dalek::SigningKey;

use crate::Journal;
use crate::hierarchy::codec::tree_commitment_v1;
use crate::hierarchy::controller_genesis::{
    HeldControllerSourceGenesisV1, hold_existing_completed_source_genesis_v2,
};
use crate::hierarchy::genesis_profile::{SourceGenesisErrorV1, take};
use crate::hierarchy::model::SandboxTreeRecordV1;
use crate::hierarchy::protected_journal::{
    RetainedTreeInventoryDataV1, retained_tree_inventory_data_v1,
};
use crate::hierarchy::source_genesis::observe_retained_source_genesis_v1;
use crate::hierarchy::source_successor::{
    BODY_BYTES, SourceSuccessorApprovalDataV2, SourceSuccessorIntentDataV2,
};
use crate::journal::controller_source_successor_issuance::PublicationCustodyV2;
use crate::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1;
use crate::normal_root::{
    ProductionControllerNormalRootProfileV1, SourceSuccessorCredentialCustodyV2,
    SourceSuccessorCredentialErrorV2,
};

use super::controller_readback::{
    sign_controller_source_genesis_completion_readback_v1,
    sign_controller_source_genesis_readback_v1,
};
use super::flight::{
    CompletedRootSourceGenesisFloorV1, OriginalRootGenesisFlightV1, OriginalRootGenesisReplyV1,
};
use super::wire::RootSourceGenesisFrameKindV1 as WirePhase;

/// Identifies the first failed original issuance boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceSuccessorIssuancePhaseV2 {
    /// Genuine credential/Controller signer admission has not completed.
    Admission,
    /// The original Root connection or its received completion failed.
    Root,
    /// Actual current context derivation or immutable saved replay failed.
    Derivation,
    /// Complete native preflight or atomic Controller retention failed.
    Retention,
    /// Fixed no-replace publication or exact delivery readback failed.
    Delivery,
    /// Final current checks or SAME-flight Finish failed.
    Finish,
    /// An armed attempt unwound or was abandoned.
    Abandoned,
}

#[derive(Debug, thiserror::Error)]
enum IssuerCause {
    #[error(transparent)]
    Owner(#[from] SourceGenesisErrorV1),
    #[error(transparent)]
    Credential(#[from] SourceSuccessorCredentialErrorV2),
}

/// Parks one original issuer attempt over the SAME genuine resident writers.
///
/// Parking establishes negative custody only, not eligibility or authority.
/// The installed executor supplies its own actual Source field and Journal;
/// there is no decoded-data, supplied-FD or scalar-current-head constructor.
/// Dropping an unfinished attempt aborts before its resource fields drop.
#[must_use = "the resident issuer must be completed or deliberately terminated"]
pub struct OriginalSourceSuccessorInvocationV2<'writers, 'profile, 'credentials> {
    journal: &'writers mut Journal,
    source: Option<&'writers mut ProtectedSourceDomainJournalOwnerV1>,
    profile: &'profile ProductionControllerNormalRootProfileV1,
    credentials: &'credentials mut SourceSuccessorCredentialCustodyV2<'profile>,
    raw: Option<OwnedFd>,
    adopted: Option<RetainedUnixStream>,
    flight: Option<OriginalRootGenesisFlightV1<'profile>>,
    publication: PublicationCustodyV2,
    phase: SourceSuccessorIssuancePhaseV2,
    first_cause: Option<(SourceSuccessorIssuancePhaseV2, IssuerCause)>,
    cleanup_debt: Option<SourceGenesisErrorV1>,
    completed: Option<SourceSuccessorApprovalDataV2>,
    started: bool,
    armed: bool,
}

/// Retains first cause and all original issuer custody until process termination.
///
/// This failure cannot be retried, decoded or converted to a current floor.
/// An abandoned failure aborts; the installed caller must deliberately consume
/// it while the enclosing Controller and credential resources are resident.
#[must_use = "the failed original administrative invocation must terminate"]
pub struct FailedOriginalSourceSuccessorInvocationV2<'writers, 'profile, 'credentials> {
    original: OriginalSourceSuccessorInvocationV2<'writers, 'profile, 'credentials>,
}

// Only this owner composition can construct the cut. Its fields borrow the
// real originals, not a snapshot/permit or caller-supplied currentness check.
pub(crate) struct SourceSuccessorSigningCutV2<'cut, 'controller, 'source, 'completed, 'flight> {
    controller: &'cut HeldControllerSourceGenesisV1<'controller>,
    inventory: &'cut RetainedTreeInventoryDataV1<'source>,
    completed: &'cut CompletedRootSourceGenesisFloorV1<'completed, 'flight>,
}

impl SourceSuccessorSigningCutV2<'_, '_, '_, '_, '_> {
    pub(crate) fn recheck_before_signature(
        &self,
        prepared: &[u8; BODY_BYTES],
        intent: SourceSuccessorIntentDataV2,
        issuer_generation: u64,
    ) -> Result<(), SourceGenesisErrorV1> {
        let derivation_clock = self.completed.signing_boundary_clock()?;
        let current = derive_body(
            self.controller,
            self.inventory,
            self.completed,
            intent,
            issuer_generation,
            derivation_clock,
        )?;

        self.inventory.recheck().map_err(SourceGenesisErrorV1::from)?;
        self.controller.recheck()?;

        // The last pair follows the expensive context and original-flight
        // observations. Expiry/continuity checks are pure; crypto follows this
        // method without another profile, descriptor or owner observation.
        let clock = self.completed.signing_boundary_clock()?;
        require_body_context(prepared, &current, clock)
    }
}

impl<'writers, 'profile, 'credentials>
    OriginalSourceSuccessorInvocationV2<'writers, 'profile, 'credentials>
{
    /// Parks the production executor's real writers before fallible checks.
    ///
    /// No packet, epoch, Root connection or signing effect occurs here.
    pub fn park(
        journal: &'writers mut Journal,
        source: &'writers mut ProtectedSourceDomainJournalOwnerV1,
        profile: &'profile ProductionControllerNormalRootProfileV1,
        credentials: &'credentials mut SourceSuccessorCredentialCustodyV2<'profile>,
    ) -> Self {
        Self::park_inner(journal, Some(source), profile, credentials)
    }

    fn park_inner(
        journal: &'writers mut Journal,
        source: Option<&'writers mut ProtectedSourceDomainJournalOwnerV1>,
        profile: &'profile ProductionControllerNormalRootProfileV1,
        credentials: &'credentials mut SourceSuccessorCredentialCustodyV2<'profile>,
    ) -> Self {
        Self {
            journal,
            source,
            profile,
            credentials,
            raw: None,
            adopted: None,
            flight: None,
            publication: PublicationCustodyV2::new(),
            phase: SourceSuccessorIssuancePhaseV2::Admission,
            first_cause: None,
            cleanup_debt: None,
            completed: None,
            started: false,
            armed: true,
        }
    }

    /// Runs the exact owner composition inside the existing fixed signer loan.
    ///
    /// Errors are latched on this resident attempt, not returned as a lossy
    /// ordinary Result. Calling twice irreversibly fails the same invocation.
    pub fn run_with_controller_signer(&mut self, generation: u64, signer: &SigningKey) {
        if self.started || self.first_cause.is_some() {
            self.fail(SourceGenesisErrorV1::Conflict.into());
            return;
        }
        self.started = true;
        match self.run(generation, signer) {
            Ok(packet) => self.completed = Some(packet),
            Err(cause) => self.fail(cause),
        }
    }

    /// Latches failure of the unchanged fixed Controller signer admission.
    ///
    /// This is a destructive negative operation, not an admission constructor.
    pub fn fail_controller_signer_admission(&mut self, cause: std::io::Error) {
        self.fail(SourceGenesisErrorV1::Transport(cause).into());
    }

    /// Returns only completed public DATA or the retaining terminal failure.
    ///
    /// # Errors
    /// Returns a must-use failed original owner for every incomplete or failed
    /// invocation. Only successful internal Finish can disarm the Drop fence.
    pub fn into_outcome(
        mut self,
    ) -> Result<
        SourceSuccessorApprovalDataV2,
        FailedOriginalSourceSuccessorInvocationV2<'writers, 'profile, 'credentials>,
    > {
        if self.first_cause.is_none() {
            if let Some(packet) = self.completed.take() {
                self.armed = false;
                return Ok(packet);
            }
            self.fail(SourceGenesisErrorV1::AdmissionClosed.into());
        }
        Err(FailedOriginalSourceSuccessorInvocationV2 { original: self })
    }

    fn fail(&mut self, cause: IssuerCause) {
        if self.first_cause.is_none() {
            self.first_cause = Some((self.phase, cause));
        }
        self.completed = None;
        self.credentials.end_failed();

        if self.cleanup_debt.is_none() {
            let result = if let Some(flight) = &self.flight {
                flight.end_failed()
            } else if let Some(raw) = &self.raw {
                rustix::net::shutdown(raw, rustix::net::Shutdown::Both)
                    .map_err(|error| SourceGenesisErrorV1::Transport(std::io::Error::from(error)))
            } else {
                Ok(())
            };
            self.cleanup_debt = result.err();
        }
    }

    fn run(
        &mut self,
        generation: u64,
        signer: &SigningKey,
    ) -> Result<SourceSuccessorApprovalDataV2, IssuerCause> {
        self.credentials.recheck()?;
        let intent = self.credentials.intent()?;
        let source = self.source.as_deref_mut()
            .ok_or(SourceGenesisErrorV1::AdmissionClosed)?;
        source.require_fixed_named_writer_v1().map_err(SourceGenesisErrorV1::from)?;
        let controller = hold_existing_completed_source_genesis_v2(self.journal, intent.project())?;
        let inventory = retained_tree_inventory_data_v1(source).map_err(SourceGenesisErrorV1::from)?;
        let acknowledged = observe_retained_source_genesis_v1(
            &inventory, controller.uid(), intent.project(),
        )?;
        controller.recheck_completed_source_ack(&acknowledged)?;

        self.phase = SourceSuccessorIssuancePhaseV2::Root;
        OriginalRootGenesisFlightV1::connect_parked(
            self.profile, &mut self.raw, &mut self.adopted, &mut self.flight,
        )?;
        let flight = self.flight.as_ref().ok_or(SourceGenesisErrorV1::Stale)?;
        let prepare = sign_controller_source_genesis_readback_v1(
            &controller, &acknowledged, flight.nonce(), generation, signer,
        )?;
        flight.send_phase(WirePhase::Prepare, &prepare)?;
        let floor = match flight.receive_reply(&controller)? {
            OriginalRootGenesisReplyV1::Anchored(floor) => floor,
            OriginalRootGenesisReplyV1::Prepared(_) => {
                return Err(SourceGenesisErrorV1::AdmissionClosed.into());
            }
        };
        let complete = sign_controller_source_genesis_completion_readback_v1(
            &controller, &acknowledged, flight.nonce(), generation, signer,
        )?;
        flight.send_phase(WirePhase::Complete, &complete)?;
        let completed = flight.receive_completed(&floor)?;
        super::super::public_create_source::consume_completed_gen1_ancestry_v1(
            &controller, &acknowledged, &inventory, &completed,
        )?;

        self.phase = SourceSuccessorIssuancePhaseV2::Derivation;
        let clock = flight.issuance_clock()?;
        let issuer_generation = self.credentials.issuer_generation()?;
        let body = derive_body(
            &controller, &inventory, &completed, intent, issuer_generation, clock,
        )?;
        let packet = if let Some(saved) = controller.retained_successor_approval_v2()? {
            self.credentials.verify_saved(&saved)?;
            require_saved_context(&saved, &body, clock)?;
            saved
        } else {
            let signing_cut = SourceSuccessorSigningCutV2 {
                controller: &controller,
                inventory: &inventory,
                completed: &completed,
            };
            self.credentials.sign_approval(&body, &signing_cut)?
        };
        recheck_current_context(
            &controller, &inventory, &completed, flight, self.credentials, &packet,
        )?;

        self.phase = SourceSuccessorIssuancePhaseV2::Retention;
        controller.preflight_successor_issuance_v2(&packet)?;
        recheck_current_context(
            &controller, &inventory, &completed, flight, self.credentials, &packet,
        )?;
        controller.save_successor_issuance_v2(&packet)?;
        recheck_current_context(
            &controller, &inventory, &completed, flight, self.credentials, &packet,
        )?;

        self.phase = SourceSuccessorIssuancePhaseV2::Delivery;
        controller.publish_successor_issuance_v2(&packet, &mut self.publication)?;
        recheck_current_context(
            &controller, &inventory, &completed, flight, self.credentials, &packet,
        )?;
        controller.complete_successor_delivery_v2(&packet, &mut self.publication)?;

        self.phase = SourceSuccessorIssuancePhaseV2::Finish;
        recheck_current_context(
            &controller, &inventory, &completed, flight, self.credentials, &packet,
        )?;
        flight.finish(completed)?;
        Ok(packet)
    }
}

impl FailedOriginalSourceSuccessorInvocationV2<'_, '_, '_> {
    /// Borrows the first typed phase/cause, never a cleanup replacement.
    pub fn first_cause(
        &self,
    ) -> Option<(SourceSuccessorIssuancePhaseV2, &(dyn std::error::Error + 'static))> {
        self.original.first_cause.as_ref().map(|(phase, cause)| {
            let source: &(dyn std::error::Error + 'static) = match cause {
                IssuerCause::Owner(cause) => cause,
                IssuerCause::Credential(cause) => cause,
            };
            (*phase, source)
        })
    }

    /// Borrows separately retained shutdown debt without changing first cause.
    pub fn cleanup_debt(&self) -> Option<&SourceGenesisErrorV1> {
        self.original.cleanup_debt.as_ref()
    }

    /// Deliberately terminates while all original writer/carrier borrows remain.
    pub fn terminate_failed(self) -> ! {
        std::process::exit(1)
    }
}

impl Drop for OriginalSourceSuccessorInvocationV2<'_, '_, '_> {
    fn drop(&mut self) {
        if self.armed {
            // No allocation, panic or ordinary field drop precedes the fence.
            if self.first_cause.is_none() {
                self.phase = SourceSuccessorIssuancePhaseV2::Abandoned;
                self.first_cause = Some((self.phase, SourceGenesisErrorV1::AdmissionClosed.into()));
            }
            self.credentials.end_failed();
            if let Some(raw) = &self.raw {
                let _ = rustix::net::shutdown(raw, rustix::net::Shutdown::Both);
            }
            std::process::abort();
        }
    }
}

pub(crate) fn unavailable<'writers, 'profile, 'credentials>(
    journal: &'writers mut Journal,
    profile: &'profile ProductionControllerNormalRootProfileV1,
    credentials: &'credentials mut SourceSuccessorCredentialCustodyV2<'profile>,
) -> FailedOriginalSourceSuccessorInvocationV2<'writers, 'profile, 'credentials> {
    let mut original = OriginalSourceSuccessorInvocationV2::park_inner(
        journal, None, profile, credentials,
    );
    original.fail(SourceGenesisErrorV1::AdmissionClosed.into());
    FailedOriginalSourceSuccessorInvocationV2 { original }
}

fn derive_body(
    controller: &HeldControllerSourceGenesisV1<'_>,
    inventory: &RetainedTreeInventoryDataV1<'_>,
    completed: &CompletedRootSourceGenesisFloorV1<'_, '_>,
    intent: SourceSuccessorIntentDataV2,
    issuer_generation: u64,
    clock: RawPairedClockSample,
) -> Result<[u8; BODY_BYTES], SourceGenesisErrorV1> {
    completed.recheck()?;
    let floor = completed.floor();
    let (tree, tree_head, lineage_head) = inventory.trees()?
        .find(|(tree, _, _)| tree.project() == intent.project())
        .ok_or(SourceGenesisErrorV1::Stale)?;
    if tree.tree_generation().get() != 1
        || tree.records().next().is_some()
        || tree.tombstones().next().is_some()
        || tree_head != floor.tree_head()
        || lineage_head != floor.lineage_head()
        || floor.project() != intent.project()
    {
        return Err(SourceGenesisErrorV1::Stale);
    }
    let (
        publisher_generation, publisher_head, publisher_revision,
        authorization_head, limits, authorization,
    ) = controller.current_successor_authorization_v2()?;
    if limits != tree.limits() {
        return Err(SourceGenesisErrorV1::Conflict);
    }
    let record = SandboxTreeRecordV1::new(
        intent.project(), intent.sandbox(), None, DesiredGeneration::new(1), None,
    )
        .map_err(|_| SourceGenesisErrorV1::NonCanonical)?;
    let next = tree.insert(record, tree.tree_generation(), None)
        .map_err(|_| SourceGenesisErrorV1::NonCanonical)?;
    let epoch = controller.acceptance().seed_claims()?.epoch().checked_add(1)
        .ok_or(SourceGenesisErrorV1::NonCanonical)?;
    let issued = u64::try_from(clock.wall_seconds()).map_err(|_| SourceGenesisErrorV1::AdmissionClosed)?;
    let expires = issued.checked_add(u64::from(intent.validity_seconds()))
        .ok_or(SourceGenesisErrorV1::NonCanonical)?;

    let mut body = [0; BODY_BYTES];
    body[..16].copy_from_slice(b"AOSCSA02\0\x02\0\0\0\0\0\0");
    body[16..24].copy_from_slice(&issuer_generation.to_be_bytes());
    body[24..32].copy_from_slice(&epoch.to_be_bytes());
    body[32..64].copy_from_slice(&floor.instance());
    body[64..80].copy_from_slice(intent.project().as_bytes());
    body[80..96].copy_from_slice(&intent.request());
    body[96..112].copy_from_slice(intent.sandbox().as_bytes());
    body[112..144].copy_from_slice(floor.roles().as_bytes());
    body[144..176].copy_from_slice(floor.digest().as_bytes());
    body[176..208].copy_from_slice(controller.completed_record_commitment_v2()?.as_bytes());
    body[208..216].copy_from_slice(&publisher_generation.to_be_bytes());
    body[216..248].copy_from_slice(publisher_head.as_bytes());
    body[248..280].copy_from_slice(publisher_revision.as_bytes());
    body[280..312].copy_from_slice(authorization_head.as_bytes());
    body[312..536].copy_from_slice(&authorization);
    body[536..568].copy_from_slice(tree_head.as_bytes());
    body[568..600].copy_from_slice(lineage_head.as_bytes());
    body[600..632].copy_from_slice(
        tree_commitment_v1(tree).map_err(|_| SourceGenesisErrorV1::NonCanonical)?.as_bytes(),
    );
    body[632..640].copy_from_slice(&1_u64.to_be_bytes());
    body[640..648].copy_from_slice(&next.tree_generation().get().to_be_bytes());
    let ceilings = [
        limits.maximum_project_roots(),
        limits.maximum_project_sandboxes(),
        limits.maximum_project_live_sandboxes(),
        limits.maximum_depth(),
        limits.maximum_children_per_parent(),
        limits.maximum_descendants(),
        limits.maximum_live_descendants(),
    ];
    for (index, ceiling) in ceilings.into_iter().enumerate() {
        let ceiling = u32::try_from(ceiling)
            .map_err(|_| SourceGenesisErrorV1::NonCanonical)?;
        body[648 + index * 4..652 + index * 4].copy_from_slice(&ceiling.to_be_bytes());
    }
    body[680..712].copy_from_slice(
        tree_commitment_v1(&next).map_err(|_| SourceGenesisErrorV1::NonCanonical)?.as_bytes(),
    );
    body[712..728].copy_from_slice(&clock.host_boot_id());
    body[728..736].copy_from_slice(&clock.boottime_nanoseconds().to_be_bytes());
    body[736..744].copy_from_slice(&issued.to_be_bytes());
    body[744..752].copy_from_slice(&expires.to_be_bytes());
    body[752..832].copy_from_slice(intent.as_bytes());
    crate::hierarchy::source_successor::validate_body(&body)?;
    controller.recheck()?;
    completed.recheck()?;
    Ok(body)
}

fn require_saved_context(
    packet: &SourceSuccessorApprovalDataV2,
    current: &[u8],
    clock: RawPairedClockSample,
) -> Result<(), SourceGenesisErrorV1> {
    require_body_context(packet.body(), current, clock)
}

fn require_body_context(
    saved: &[u8],
    current: &[u8],
    clock: RawPairedClockSample,
) -> Result<(), SourceGenesisErrorV1> {
    let current_wall = u64::try_from(clock.wall_seconds())
        .map_err(|_| SourceGenesisErrorV1::AdmissionClosed)?;
    if saved.len() != BODY_BYTES
        || current.len() != BODY_BYTES
        || saved[..712] != current[..712]
        || saved[752..] != current[752..]
        || saved[712..728] != clock.host_boot_id()
        || u64::from_be_bytes(take(saved, 744)?) <= current_wall
    {
        return Err(SourceGenesisErrorV1::Stale);
    }
    // The prepared/saved original pair is comparison DATA, not a clock loan.
    // Only the same original flight supplies the independently obtained later
    // sample; construction here cannot revive an owner or renew its deadline.
    let original = RawPairedClockSample::new_untrusted(
        clock.provenance(), take(saved, 712)?,
        i64::try_from(u64::from_be_bytes(take(saved, 736)?)).map_err(|_| SourceGenesisErrorV1::NonCanonical)?,
        u64::from_be_bytes(take(saved, 728)?),
    ).map_err(|_| SourceGenesisErrorV1::NonCanonical)?;
    original.validate_later_sample(clock).map_err(|_| SourceGenesisErrorV1::AdmissionClosed)
}

fn recheck_current_context(
    controller: &HeldControllerSourceGenesisV1<'_>,
    inventory: &RetainedTreeInventoryDataV1<'_>,
    completed: &CompletedRootSourceGenesisFloorV1<'_, '_>,
    flight: &OriginalRootGenesisFlightV1<'_>,
    credentials: &mut SourceSuccessorCredentialCustodyV2<'_>,
    packet: &SourceSuccessorApprovalDataV2,
) -> Result<(), IssuerCause> {
    credentials.recheck()?;
    let clock = flight.issuance_clock()?;
    let current = derive_body(
        controller,
        inventory,
        completed,
        credentials.intent()?,
        credentials.issuer_generation()?,
        clock,
    )?;
    require_saved_context(packet, &current, clock)?;
    credentials.verify_saved(packet)?;
    completed.recheck().map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_core::RawClockProvenance;
    use crate::hierarchy::source_successor::tests::approval_fixture;

    fn clock(boot: u8, wall: i64, boottime: u64) -> RawPairedClockSample {
        RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted([1; 16]).unwrap(),
            [boot; 16], wall, boottime,
        ).unwrap()
    }

    #[test]
    fn saved_reexecution_uses_immutable_context_and_never_renews_expiry() {
        let (packet, _) = approval_fixture();
        let current = take::<BODY_BYTES>(packet.body(), 0).unwrap();

        assert!(require_saved_context(&packet, &current, clock(12, 1_000, 1_000_000_000)).is_ok());
        assert!(require_saved_context(&packet, &current, clock(12, 1_001, 2_000_000_000)).is_ok());
        assert!(require_saved_context(&packet, &current, clock(12, 1_300, 301_000_000_000)).is_err());
        assert_eq!(&packet.body()[744..752], &1_300_u64.to_be_bytes());
    }

    #[test]
    fn saved_reexecution_rejects_every_current_owner_head_and_intent_substitution() {
        let (packet, _) = approval_fixture();
        let now = clock(12, 1_001, 2_000_000_000);

        for offset in [
            16, 24, 32, 64, 80, 96, 112, 144, 176, 208, 216, 248, 280,
            312, 536, 568, 600, 632, 640, 648, 680, 752,
        ] {
            let mut current = take::<BODY_BYTES>(packet.body(), 0).unwrap();
            current[offset] ^= 1;
            assert!(require_saved_context(&packet, &current, now).is_err(), "{offset}");
        }
    }

    #[test]
    fn saved_reexecution_rejects_boot_wall_boottime_rollback_and_clock_divergence() {
        let (packet, _) = approval_fixture();
        for changed in [
            clock(13, 1_001, 2_000_000_000),
            clock(12, 999, 2_000_000_000),
            clock(12, 1_001, 999_999_999),
            clock(12, 1_100, 2_000_000_000),
        ] {
            assert!(require_saved_context(&packet, packet.body(), changed).is_err());
        }
    }

    #[test]
    fn prepared_body_expiry_uses_the_last_pair_after_owner_observations() {
        let (packet, _) = approval_fixture();
        let prepared = packet.body();
        let early = clock(12, 1_000, 1_000_000_000);
        let after_observations = clock(12, 1_300, 301_000_000_000);

        assert!(require_body_context(prepared, prepared, early).is_ok());
        assert!(require_body_context(prepared, prepared, after_observations).is_err());
        assert_eq!(&prepared[744..752], &1_300_u64.to_be_bytes());
    }

    #[test]
    fn prepared_body_refuses_width_and_unsigned_owner_context_substitutions() {
        let (packet, _) = approval_fixture();
        let prepared = packet.body();
        let now = clock(12, 1_001, 2_000_000_000);
        let mut oversized = prepared.to_vec();
        oversized.push(0);

        assert!(require_body_context(&prepared[..BODY_BYTES - 1], prepared, now).is_err());
        assert!(require_body_context(&oversized, prepared, now).is_err());

        for offset in [32, 144, 176, 536, 568, 680, 752] {
            let mut current = take::<BODY_BYTES>(prepared, 0).unwrap();
            current[offset] ^= 1;

            assert!(require_body_context(prepared, &current, now).is_err(), "{offset}");
        }
    }
}
