//! Original-session remote catalog selection for dormant native Acquire V3.
//!
//! The pending owner retains namespace-40 planning custody across nonblocking
//! catalog control I/O. Only an answer received from that same original peer,
//! joined to an independently verified publication and exact `AOSPCZ01` row,
//! can reach the private signer. No namespace-41 owner or row revision is
//! reconstructed here. Provider admission and native outcome gates remain
//! separate, closed prerequisites.

use aos_sandbox_core::{RawClockProvenance, RawPairedClockSample};
use aos_sandbox_source_provider_protocol::native_held_completion::witness::{
    NativeHeldByteWitnessV1, NativeHeldGenerationClaimV1, RootNativeHeldWitnessV1,
};
use aos_sandbox_source_provider_protocol::{
    ACQUIRE_SOURCE_REQUEST_VERSION_V2, CatalogCurrentnessQueryV1, NativeAcquireCatalogBindingV3,
    ProviderHeldSnapshotCatalogV1, SignedCatalogCurrentnessV1, SourceResourceV1,
    ZfsHeldSnapshotProofV1,
};

use super::*;
use crate::handshake::root_mount::AuthenticatedRootMountCatalogCurrentnessV1;
use crate::{RevalidatedProviderConfigurationV1, VerifiedCatalogPublicationV1};

#[path = "native_catalog/outcome.rs"]
mod outcome;

pub(super) mod custody;

pub(super) use outcome::NativeAcquireOutcomeCustodyV3;
pub(super) use outcome::require_native_completion_barrier;
pub(super) use outcome::retain_original_outcome_owner;

/// Retains one original native query, protected plan, and absolute deadline.
///
/// This move-only value has no public constructor or claim projection. Pending
/// progress must use the same current session and protected Mount writer.
#[must_use = "continue the same original flight or abandon its preparation"]
pub struct PendingNativeMountAcquireV3 {
    retained_plan: Option<CurrentMountProviderSessionPlanV2>,
    retained_draft: Option<AcquireSourceRequestV1>,
    retained_deadline: Option<OriginalNativeDeadlineV3>,
    preparation: Option<NativeAcquirePreparationV3>,
    retained_currentness: Option<NativeAcquireCurrentnessGuardV3>,
    retained_prepared: Option<PreparedMountProviderRequestV2>,
    retained_signed_request: Option<Vec<u8>>,
    retained_signed: Option<SignedSourceProviderRequestV1>,
    signature_attempted: bool,
    failed: core::cell::Cell<bool>,
}

struct NativeAcquirePreparationV3 {
    plan: CurrentMountProviderSessionPlanV2,
    request: AcquireSourceRequestV1,
    publication: VerifiedCatalogPublicationV1,
    catalog: ProviderHeldSnapshotCatalogV1,
    selection_key: Option<Vec<u8>>,
    query: Option<CatalogCurrentnessQueryV1>,
    mount_head_minimum: (u64, ObjectDigest),
    socket_cookie: std::num::NonZeroU64,
    deadline: OriginalNativeDeadlineV3,
    proof: Option<AuthenticatedRootMountCatalogCurrentnessV1>,
}

/// Retains genuine received-sender custody through reservation, send, and outcome.
pub(super) struct NativeAcquireCurrentnessGuardV3 {
    preparation: NativeAcquirePreparationV3,
    binding_digest: ObjectDigest,
    resource: SourceResourceV1,
    snapshot: ZfsHeldSnapshotProofV1,
    trust: (u64, ObjectDigest),
    revocation: (u64, ObjectDigest),
}

impl NativeAcquireCurrentnessGuardV3 {
    pub(super) const fn original_planning_snapshot(
        &self,
    ) -> &aos_sandbox::ProtectedJournalSnapshot {
        &self.preparation.plan.journal_snapshot
    }

    fn proof(
        &self,
    ) -> Result<&AuthenticatedRootMountCatalogCurrentnessV1, SourceProviderSecurityError> {
        self.preparation
            .proof
            .as_ref()
            .ok_or(SourceProviderSecurityError::SessionContinuity)
    }

    pub(super) fn original_root_witness(
        &self,
        records: [NativeHeldByteWitnessV1; 4],
        journal_sequence: u64,
    ) -> Result<RootNativeHeldWitnessV1, SourceProviderSecurityError> {
        let claim = |(generation, digest)| NativeHeldGenerationClaimV1 { generation, digest };
        let proof = self.proof()?;

        Ok(RootNativeHeldWitnessV1 {
            local_socket_cookie: proof.socket_cookie.get(),
            journal_sequence,
            planning_sequence: self.original_planning_snapshot().sequence(),
            trust: claim(self.trust),
            revocation: claim(self.revocation),
            provider_head: claim(proof.head()),
            provider_floor: claim(proof.floor()),
            publication: proof.publication_digest(),
            records,
        })
    }
}

struct OriginalNativeDeadlineV3 {
    // The original bracket is never refreshed during pending progress.
    initial: OriginalNativeClockBracketV3,
    // This exact whole-second bound is written into the signed native request.
    expires_seconds: i64,
    // The finalized signed expiry conservatively bounds this absolute I/O cutoff.
    boottime_deadline: u64,
}

// The wall observation lies between these BOOTTIME reads under one boot-ID
// sandwich. The before-read limits local expiry; the after-read conservatively
// projects the Mount cutoff into wall time and anchors later paired comparisons.
struct OriginalNativeClockBracketV3 {
    boottime_before: u64,
    paired: RawPairedClockSample,
}

impl OriginalNativeClockBracketV3 {
    fn new(
        boottime_before: u64,
        paired: RawPairedClockSample,
    ) -> Result<Self, SourceProviderSecurityError> {
        if boottime_before > paired.boottime_nanoseconds() {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        Ok(Self {
            boottime_before,
            paired,
        })
    }
}

impl core::fmt::Debug for PendingNativeMountAcquireV3 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("PendingNativeMountAcquireV3([original pending custody])")
    }
}

impl CurrentRootMountSourceProviderSessionV1 {
    /// Begins an original-session catalog challenge for native Acquire V3.
    ///
    /// The V2 draft supplies only the already-planned common request data.
    /// Canonical publication and catalog bytes are untrusted input until their
    /// independent signature, protected floors, and exact selection are joined.
    /// An empty Mount graph permits a publication-floor challenge, not fresh
    /// authorization. Both the signed expiry and local I/O fence intersect the
    /// original live Mount cutoff using one bracketed paired sample. This method
    /// performs at most one bounded progress step.
    ///
    /// # Errors
    ///
    /// Poisons the session for stale planning custody, an overlapping query,
    /// nonnative draft, invalid publication/selection, or expired original time.
    #[allow(clippy::too_many_arguments)]
    pub fn begin_native_acquire_v3(
        &mut self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        plan: CurrentMountProviderSessionPlanV2,
        request: AcquireSourceRequestV1,
        live_mount_request: &aos_sandbox_protocol::LiveValidatedAcquireMountSourceRequest,
        canonical_publication: &[u8],
        canonical_catalog: &[u8],
        selection_key: Option<Vec<u8>>,
    ) -> Result<PendingNativeMountAcquireV3, SourceProviderSecurityError> {
        let mut retained = None;
        self.begin_original_native_acquire_retaining_v5(
            journal,
            plan,
            request,
            live_mount_request,
            canonical_publication,
            canonical_catalog,
            selection_key,
            &mut retained,
        )?;
        retained.ok_or(SourceProviderSecurityError::SessionContinuity)
    }

    /// Begins the SAME catalog exchange while parking original custody first.
    ///
    /// # Errors
    /// Retains any actual plan, paired deadline and pending exchange on failure;
    /// callers must not replace the owner or restart a poisoned original flight.
    #[allow(clippy::too_many_arguments)]
    #[doc(hidden)]
    pub fn begin_original_native_acquire_retaining_v5(
        &mut self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        plan: CurrentMountProviderSessionPlanV2,
        request: AcquireSourceRequestV1,
        live_mount_request: &aos_sandbox_protocol::LiveValidatedAcquireMountSourceRequest,
        canonical_publication: &[u8],
        canonical_catalog: &[u8],
        selection_key: Option<Vec<u8>>,
        retained: &mut Option<PendingNativeMountAcquireV3>,
    ) -> Result<(), SourceProviderSecurityError> {
        let mut plan_slot = Some(plan);
        let mut request_slot = Some(request);
        self.begin_original_native_acquire_from_parked_v5(
            journal,
            &mut plan_slot,
            &mut request_slot,
            live_mount_request,
            canonical_publication,
            canonical_catalog,
            selection_key,
            retained,
        )
    }

    /// Begins the original challenge without consuming the caller's parked inputs.
    ///
    /// # Errors
    ///
    /// Retains both inputs, pending custody and the actual Session on refusal or
    /// unwind. A failed flight cannot be restarted using the same slots.
    #[allow(clippy::too_many_arguments)]
    #[doc(hidden)]
    pub fn begin_original_native_acquire_from_parked_v5(
        &mut self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        plan_slot: &mut Option<CurrentMountProviderSessionPlanV2>,
        request_slot: &mut Option<AcquireSourceRequestV1>,
        live_mount_request: &aos_sandbox_protocol::LiveValidatedAcquireMountSourceRequest,
        canonical_publication: &[u8],
        canonical_catalog: &[u8],
        selection_key: Option<Vec<u8>>,
        retained: &mut Option<PendingNativeMountAcquireV3>,
    ) -> Result<(), SourceProviderSecurityError> {
        OriginalBoundaryV5::new(self, retained).run(|owner, retained| {
            if retained.is_some() || plan_slot.is_none() || request_slot.is_none() {
                return Err(SourceProviderSecurityError::SessionContinuity);
            }

            **retained = Some(PendingNativeMountAcquireV3 {
                retained_plan: plan_slot.take(),
                retained_draft: request_slot.take(),
                retained_deadline: None,
                preparation: None,
                retained_currentness: None,
                retained_prepared: None,
                retained_signed_request: None,
                retained_signed: None,
                signature_attempted: false,
                failed: core::cell::Cell::new(false),
            });
            let pending = retained
                .as_mut()
                .ok_or(SourceProviderSecurityError::SessionContinuity)?;
            let plan = pending
                .retained_plan
                .as_ref()
                .ok_or(SourceProviderSecurityError::SessionContinuity)?;
            let request = pending
                .retained_draft
                .as_ref()
                .ok_or(SourceProviderSecurityError::SessionContinuity)?;
            owner.validate_current_mount_plan(journal, plan)?;
            let mount = live_mount_request.request();
            if owner.has_pending_control_exchange()
                || request.acquisition_version() != ACQUIRE_SOURCE_REQUEST_VERSION_V2
                || request.kernel_coupled()
                || request.session_binding() != plan.session.session_binding
                || request.sequence() != plan.current_request_sequence
                || request.node_id() != plan.session.node_id
                || request.boot_id() != plan.session.root_boot_id
                || request.deadline_seconds() > plan.session.current_valid_until_seconds
                || request.prospective_apply_template() != mount.prospective_mount_template()
                || request.prospective_apply_template_digest()
                    != mount.prospective_mount_template_digest()
                || request.binding() != mount.source_binding().canonical_bytes()
                || request.source_use()
                    != aos_sandbox_source_provider_protocol::SourceUseV1::MountCreate
                || request.requested_bounds()
                    != (
                        mount.requested_lease_seconds(),
                        mount.recursive(),
                        mount.requested_maximum_submounts(),
                        mount.kernel_coupled(),
                    )
            {
                return Err(owner.poison(SourceProviderSecurityError::SessionContinuity));
            }
            let deadline = OriginalNativeDeadlineV3::capture(
                request.deadline_seconds(),
                plan.session.root_boot_id,
                mount.header().deadline_boottime_nanoseconds(),
            )
            .map_err(|error| owner.poison(error))?;
            pending.retained_deadline = Some(deadline);
            let deadline = pending
                .retained_deadline
                .as_ref()
                .ok_or(SourceProviderSecurityError::SessionContinuity)?;
            let request = bound_native_draft_deadline(request.clone(), deadline)
                .map_err(|error| owner.poison(error))?;
            let configuration = RevalidatedProviderConfigurationV1::capture_root_mount(
                &mut owner.custody,
                deadline.initial.paired.wall_seconds(),
            )
            .map_err(|error| owner.poison(error))?;
            let publication = crate::verify_catalog_publication(&configuration, canonical_publication)
                .map_err(|error| owner.poison(error))?;
            let catalog = ProviderHeldSnapshotCatalogV1::from_canonical_bytes(canonical_catalog)
                .map_err(|_| owner.poison(SourceProviderSecurityError::SessionContinuity))?;
            require_publication_scope(&publication, &configuration, &plan.session)
                .map_err(|error| owner.poison(error))?;
            select_catalog_claim(&catalog, &publication, request.binding_digest())
                .map_err(|error| owner.poison(error))?;

            let graph = validated_mount_state(journal).map_err(|error| owner.poison(error))?;
            let bounds = catalog_floor::remote_catalog_bounds(
                &graph,
                &plan.session,
                publication.catalog_floor(),
            )
            .map_err(|error| owner.poison(error))?;
            catalog_floor::validate_mount_floor(
                journal,
                &graph,
                &plan.session,
                &bounds.query_floor,
                selection_key.as_deref(),
            )
            .map_err(|error| owner.poison(error))?;
            let socket_cookie = owner.carrier.socket().peer().socket_cookie();
            // Park the actual plan and paired clock BEFORE catalog IO. Even a
            // poisoned post-IO check leaves this same original owner in the flight.
            match (pending.retained_plan.take(), pending.retained_deadline.take()) {
                (Some(plan), Some(deadline)) => {
                    pending.preparation = Some(NativeAcquirePreparationV3 {
                        plan,
                        request,
                        publication,
                        catalog,
                        selection_key,
                        query: None,
                        mount_head_minimum: bounds.head_minimum,
                        socket_cookie,
                        deadline,
                        proof: None,
                    });
                }
                (plan, deadline) => {
                    pending.retained_plan = plan;
                    pending.retained_deadline = deadline;
                    return Err(SourceProviderSecurityError::SessionContinuity);
                }
            }
            let preparation = pending
                .preparation
                .as_mut()
                .ok_or(SourceProviderSecurityError::SessionContinuity)?;
            owner.advance_catalog_currentness_retaining_v5(
                &bounds.query_floor,
                || preparation.deadline.require_current(kernel_clock()?),
                &mut preparation.proof,
            )?;
            preparation.query = Some(match &preparation.proof {
                Some(proof) => proof.query.clone(),
                None => owner
                    .catalog_exchange
                    .as_ref()
                    .ok_or(SourceProviderSecurityError::SessionContinuity)?
                    .query
                    .clone(),
            });
            owner.require_original_native_deadline_v3(&preparation.deadline)?;
            owner.validate_current_mount_plan(journal, &preparation.plan)?;
            Ok(())
        })
    }

    /// Advances and signs one exact original native Acquire V3 preparation.
    ///
    /// `None` retains the same challenge, plan, peer, and deadline; it never
    /// generates a replacement nonce. Success consumes that preparation once.
    /// The returned request still requires protected reservation before send.
    ///
    /// # Errors
    ///
    /// Poisons the session for stale/superseded query custody, changed boot or
    /// time, mismatched catalog artifacts, stale Mount state, or signing failure.
    pub fn prepare_native_acquire_v3(
        &mut self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        pending: &mut PendingNativeMountAcquireV3,
    ) -> Result<Option<PreparedMountProviderRequestV2>, SourceProviderSecurityError> {
        let mut prepared = None;
        if self.prepare_original_native_acquire_retaining_v5(journal, pending, &mut prepared)? {
            Ok(prepared)
        } else {
            Ok(None)
        }
    }

    /// Advances the same preparation and parks its signed output before postchecks.
    ///
    /// # Errors
    ///
    /// Retains the complete pending and prepared owners on any refusal or unwind.
    /// A completed or failed preparation cannot sign or transfer a second time.
    #[doc(hidden)]
    pub fn prepare_original_native_acquire_retaining_v5(
        &mut self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        pending: &mut PendingNativeMountAcquireV3,
        prepared_slot: &mut Option<PreparedMountProviderRequestV2>,
    ) -> Result<bool, SourceProviderSecurityError> {
        OriginalBoundaryV5::new(self, pending).run(|owner, pending| {
            let pending = &mut **pending;
            if pending.failed.get()
                || pending.signature_attempted
                || prepared_slot.is_some()
                || pending.retained_prepared.is_some()
                || pending.retained_currentness.is_some()
            {
                return Err(SourceProviderSecurityError::SessionContinuity);
            }
            let preparation = pending.preparation.as_mut()
                .ok_or(SourceProviderSecurityError::SessionContinuity)?;
            owner.validate_current_mount_plan(journal, &preparation.plan)?;
            owner.require_original_native_deadline_v3(&preparation.deadline)?;
            if preparation.socket_cookie != owner.carrier.socket().peer().socket_cookie() {
                return Err(owner.poison(SourceProviderSecurityError::SessionContinuity));
            }

            if preparation.proof.is_none() {
                let query = preparation.query.as_ref()
                    .ok_or(SourceProviderSecurityError::SessionContinuity)?;
                if !original_query_is_pending(
                    query,
                    owner.catalog_exchange.as_ref().map(|exchange| &exchange.query),
                    owner.session.binding(),
                    owner.catalog_sequence,
                ) {
                    return Err(owner.poison(SourceProviderSecurityError::SessionContinuity));
                }
                let minimum = ProviderCatalogFloorV1::new(
                    preparation.plan.session.authority_trust[1].authority.authority_id(),
                    preparation.plan.session.resource_namespace_digest,
                    query.minimum().0,
                    query.minimum().1,
                )
                .map_err(|_| owner.poison(SourceProviderSecurityError::SessionContinuity))?;
                owner.advance_catalog_currentness_retaining_v5(
                    &minimum,
                    || preparation.deadline.require_current(kernel_clock()?),
                    &mut preparation.proof,
                )?;
                owner.require_original_native_deadline_v3(&preparation.deadline)?;
                if preparation.proof.is_none() {
                    return Ok(false);
                }
            }

            // Derive only DATA while the actual plan, deadline and packet are
            // still parked together. No original custody is split for signing.
            owner.validate_current_mount_plan(journal, &preparation.plan)?;
            let proof = preparation.proof.as_ref()
                .ok_or(SourceProviderSecurityError::SessionContinuity)?;
            if Some(&proof.query) != preparation.query.as_ref()
                || proof.socket_cookie != preparation.socket_cookie
            {
                return Err(owner.poison(SourceProviderSecurityError::SessionContinuity));
            }
            let (resource, snapshot) = select_catalog_claim(
                &preparation.catalog,
                &preparation.publication,
                preparation.request.binding_digest(),
            ).map_err(|error| owner.poison(error))?;
            let binding = join_current_catalog_claims(
                &proof.signed,
                &proof.query,
                &preparation.publication,
                preparation.mount_head_minimum,
            )
            .map_err(|error| owner.poison(error))?;
            let request = AcquireSourceRequestV1::new_native_v3(
                preparation.request.clone(),
                binding,
            )
            .map_err(|_| owner.poison(SourceProviderSecurityError::SessionContinuity))?;
            let session = preparation.plan.session.retained_data_copy();
            let request_sequence = preparation.plan.current_request_sequence;
            let response_sequence = preparation.plan.current_response_sequence;
            let binding_digest = preparation.request.binding_digest();
            let trust = (session.trust_generation, session.trust_digest);
            let revocation = (session.revocation_generation, session.revocation_digest);
            let head_commitment = proof.head_commitment();
            let graph = validated_mount_state(journal).map_err(|error| owner.poison(error))?;
            let catalog_floor = ProviderCatalogFloorV1::new(
                preparation.publication.provider().authority_id(),
                preparation.publication.resource_namespace_digest(),
                proof.floor().0,
                proof.floor().1,
            ).map_err(|_| owner.poison(SourceProviderSecurityError::SessionContinuity))?;
            let selection_floor = catalog_floor::validate_mount_floor(
                journal,
                &graph,
                &session,
                &catalog_floor,
                preparation.selection_key.as_deref(),
            ).map_err(|error| owner.poison(error))?;
            let normalized = NormalizedAcquisitionIntentV2::from_original_acquire_request(
                &request,
                session.authority_trust[1].authority.clone(),
                session.authority_trust[0].authority.clone(),
                session.node_id,
                session.root_boot_id,
                session.route_id,
                session.route_generation,
                session.route_digest,
                session.resource_namespace_digest,
                session.revocation_generation,
                session.revocation_digest,
            ).map_err(|_| owner.poison(SourceProviderSecurityError::SessionContinuity))?;

            // Only direct moves separate the original preparation and guard.
            pending.retained_currentness = pending.preparation.take().map(|preparation| {
                NativeAcquireCurrentnessGuardV3 {
                    preparation,
                    binding_digest,
                    resource,
                    snapshot,
                    trust,
                    revocation,
                }
            });
            let guard = pending.retained_currentness.as_ref()
                .ok_or(SourceProviderSecurityError::SessionContinuity)?;
            owner.require_native_acquire_currentness_v3(guard)?;
            owner.prepare_acquire_from_catalog_retaining(
                session,
                request_sequence,
                response_sequence,
                request,
                normalized,
                catalog_floor,
                selection_floor,
                head_commitment,
                &mut pending.retained_signed_request,
                &mut pending.retained_signed,
                &mut pending.signature_attempted,
                &mut pending.retained_prepared,
            )?;
            let prepared = pending.retained_prepared.as_mut()
                .ok_or(SourceProviderSecurityError::SessionContinuity)?;
            prepared.native_currentness = pending.retained_currentness.take();
            let guard = prepared.native_currentness.as_ref()
                .ok_or(SourceProviderSecurityError::SessionContinuity)?;
            owner.require_native_acquire_currentness_v3(guard)?;
            journal.validate_mount_source_acquisition_snapshot(
                guard.original_planning_snapshot(),
            ).map_err(|_| owner.poison(SourceProviderSecurityError::SessionContinuity))?;

            *prepared_slot = pending.retained_prepared.take();
            Ok(true)
        })
    }

    /// Rechecks original native preparation immediately before Mount commit.
    ///
    /// # Errors
    ///
    /// Poisons the session if this is not native preparation, its original
    /// namespace-40 snapshot changed, or sender/catalog/time custody is stale.
    #[doc(hidden)]
    pub fn revalidate_native_acquire_preparation_v3(
        &mut self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        prepared: &PreparedMountProviderRequestV2,
    ) -> Result<(), SourceProviderSecurityError> {
        OriginalBoundaryV5::new(self, ()).run(|owner, _| {
            let guard = prepared
                .native_currentness
                .as_ref()
                .ok_or_else(|| owner.poison(SourceProviderSecurityError::SessionContinuity))?;
            journal
                .validate_mount_source_acquisition_snapshot(guard.original_planning_snapshot())
                .map_err(|_| owner.poison(SourceProviderSecurityError::SessionContinuity))?;
            owner.require_native_acquire_currentness_v3(guard)
        })
    }

    /// Rechecks the original native sender and exact committed Mount readback.
    ///
    /// The reservation stays with its caller on failure. This check provides
    /// no send permit; the actual atomic-send path rechecks it again.
    ///
    /// # Errors
    ///
    /// Poisons the session for missing native custody, changed reservation
    /// records/snapshot, or expired/changed original sender/catalog/time.
    #[doc(hidden)]
    pub fn revalidate_native_acquire_reservation_v3(
        &mut self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        reservation: &ReservedMountProviderRequestV2,
    ) -> Result<(), SourceProviderSecurityError> {
        self.revalidate_native_acquire_reservation_with_view(journal, reservation)
    }

    pub(super) fn revalidate_native_acquire_reservation_with_view(
        &mut self,
        journal: &impl MountSourceAcquisitionJournalViewV2,
        reservation: &ReservedMountProviderRequestV2,
    ) -> Result<(), SourceProviderSecurityError> {
        OriginalBoundaryV5::new(self, reservation).run(|owner, reservation| {
            let reservation = &**reservation;
            let guard = reservation
                .prepared
                .native_currentness
                .as_ref()
                .ok_or_else(|| owner.poison(SourceProviderSecurityError::SessionContinuity))?;
            reservation
                .prepared
                .validate_protected_reservation(
                    journal,
                    &reservation.reservation_snapshot,
                    &reservation.attempt_key,
                    &reservation.attempt_record,
                    &reservation.head_key,
                    &reservation.head_record,
                )
                .map_err(|error| owner.poison(error))?;
            owner.require_native_acquire_currentness_v3(guard)
        })
    }

    /// Confirms exact native reservation records without losing preparation on failure.
    ///
    /// Only the original preparation supplies received-sender and signing
    /// custody. Record coordinates merely locate its exact protected readback;
    /// neither records nor a refreshed snapshot manufacture preparation.
    ///
    /// # Errors
    ///
    /// Poisons the session and returns the original preparation with the error
    /// if the snapshot, typed reservation, or native preparation is invalid.
    #[allow(clippy::too_many_arguments)]
    #[doc(hidden)]
    pub fn confirm_native_acquire_reservation_v3(
        &mut self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        prepared: PreparedMountProviderRequestV2,
        attempt_key: Vec<u8>,
        attempt_record: Vec<u8>,
        head_key: Vec<u8>,
        head_record: Vec<u8>,
    ) -> Result<
        ReservedMountProviderRequestV2,
        (PreparedMountProviderRequestV2, SourceProviderSecurityError),
    > {
        self.confirm_native_acquire_reservation_with_view(
            journal,
            prepared,
            attempt_key,
            attempt_record,
            head_key,
            head_record,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn confirm_native_acquire_reservation_with_view(
        &mut self,
        journal: &impl MountSourceAcquisitionJournalViewV2,
        prepared: PreparedMountProviderRequestV2,
        attempt_key: Vec<u8>,
        attempt_record: Vec<u8>,
        head_key: Vec<u8>,
        head_record: Vec<u8>,
    ) -> Result<
        ReservedMountProviderRequestV2,
        (PreparedMountProviderRequestV2, SourceProviderSecurityError),
    > {
        let validation = OriginalBoundaryV5::new(self, ()).run(|owner, _| {
            owner.validate_native_reservation_confirmation_v5(
                journal,
                &prepared,
                &attempt_key,
                &attempt_record,
                &head_key,
                &head_record,
            )
        });
        match validation {
            Ok((snapshot, session_id, attempt_id)) => Ok(prepared.bind_reserved(
                snapshot,
                attempt_key,
                attempt_record,
                head_key,
                head_record,
                session_id,
                attempt_id,
            )),
            Err(error) => Err((prepared, error)),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn confirm_native_reservation_retaining_with_view_v5(
        &mut self,
        journal: &impl MountSourceAcquisitionJournalViewV2,
        prepared: &mut Option<PreparedMountProviderRequestV2>,
        attempt_key: Vec<u8>,
        attempt_record: Vec<u8>,
        head_key: Vec<u8>,
        head_record: Vec<u8>,
        reserved: &mut Option<ReservedMountProviderRequestV2>,
    ) -> Result<(), SourceProviderSecurityError> {
        OriginalBoundaryV5::new(self, reserved).run(|owner, reserved| {
            if reserved.is_some() {
                return Err(SourceProviderSecurityError::SessionContinuity);
            }
            let current = prepared.as_ref()
                .ok_or(SourceProviderSecurityError::SessionContinuity)?;
            let (snapshot, session_id, attempt_id) =
                owner.validate_native_reservation_confirmation_v5(
                    journal,
                    current,
                    &attempt_key,
                    &attempt_record,
                    &head_key,
                    &head_record,
                )?;

            **reserved = prepared.take().map(|prepared| {
                prepared.bind_reserved(
                    snapshot,
                    attempt_key,
                    attempt_record,
                    head_key,
                    head_record,
                    session_id,
                    attempt_id,
                )
            });
            Ok(())
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn validate_native_reservation_confirmation_v5(
        &mut self,
        journal: &impl MountSourceAcquisitionJournalViewV2,
        prepared: &PreparedMountProviderRequestV2,
        attempt_key: &[u8],
        attempt_record: &[u8],
        head_key: &[u8],
        head_record: &[u8],
    ) -> Result<
        (aos_sandbox::ProtectedJournalSnapshot, [u8; 32], [u8; 32]),
        SourceProviderSecurityError,
    > {
        let guard = prepared.native_currentness.as_ref()
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let proof = guard.proof()?;
        if proof.query.session_binding() != self.session.binding()
            || proof.socket_cookie != self.carrier.socket().peer().socket_cookie()
            || !proof.execution().has_same_execution(&self.provider_execution)
        {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        let snapshot = journal.capture_snapshot()
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        prepared.validate_protected_reservation(
            journal,
            &snapshot,
            attempt_key,
            attempt_record,
            head_key,
            head_record,
        )?;
        let attempt = match aos_sandbox_protocol::mount_source_acquisition_state::decode_mount_source_state_record_v2(
            attempt_key, attempt_record,
        ) {
            Ok(aos_sandbox_protocol::mount_source_acquisition_state::StoredRecordV2::ProviderQueryAttempt { value }) => value,
            _ => return Err(SourceProviderSecurityError::SessionContinuity),
        };
        Ok((snapshot, attempt.session_id, attempt.attempt_id))
    }

    /// Fail-stops the original session after an indeterminate native commit.
    ///
    /// This revokes original signing/send custody without clearing durable
    /// state, adopting a row, creating a reservation, or renewing any deadline.
    #[doc(hidden)]
    pub fn invalidate_native_acquire_commit_v3(&mut self) {
        self.poison(SourceProviderSecurityError::SessionContinuity);
    }

    pub(super) fn require_native_acquire_currentness_v3(
        &mut self,
        guard: &NativeAcquireCurrentnessGuardV3,
    ) -> Result<(), SourceProviderSecurityError> {
        OriginalBoundaryV5::new(self, ()).run(|owner, _| {
            let preparation = &guard.preparation;
            let proof = guard.proof().map_err(|error| owner.poison(error))?;
            proof
                .require_packet_consistency()
                .map_err(|error| owner.poison(error))?;

            owner.revalidate()?;
            let now = kernel_clock().map_err(|error| owner.poison(error))?;
            preparation
                .deadline
                .require_current(now)
                .map_err(|error| owner.poison(error))?;
            if !original_query_is_latest(
                &proof.query,
                owner.session.binding(),
                owner.catalog_sequence,
                owner.has_pending_control_exchange(),
            ) || proof.socket_cookie != owner.carrier.socket().peer().socket_cookie()
                || !proof
                    .execution()
                    .has_same_execution(&owner.provider_execution)
                || proof.execution().boot_id() != now.host_boot_id()
            {
                return Err(owner.poison(SourceProviderSecurityError::SessionContinuity));
            }
            proof
                .execution()
                .revalidate(owner.carrier.socket().peer())
                .map_err(|error| owner.poison(error))?;
            let configuration = RevalidatedProviderConfigurationV1::capture_root_mount(
                &mut owner.custody,
                now.wall_seconds(),
            )
            .map_err(|error| owner.poison(error))?;
            if configuration.trust_head() != guard.trust
                || configuration.revocation_head() != guard.revocation
            {
                return Err(owner.poison(SourceProviderSecurityError::SessionContinuity));
            }
            let publication = crate::verify_catalog_publication(
                &configuration,
                preparation.publication.canonical_publication(),
            )
            .map_err(|error| owner.poison(error))?;
            if publication.provider() != configuration.provider()
                || publication.resource_namespace_digest() != configuration.resource_namespace_digest()
                || join_current_catalog_claims(
                    &proof.signed,
                    &proof.query,
                    &publication,
                    preparation.mount_head_minimum,
                )
                .is_err()
                || select_catalog_claim(&preparation.catalog, &publication, guard.binding_digest)
                    != Ok((guard.resource.clone(), guard.snapshot.clone()))
            {
                return Err(owner.poison(SourceProviderSecurityError::SessionContinuity));
            }
            let (signer, public_key) = {
                let inner = owner.custody.inner();
                let signer = inner.provider_authority().traffic_signer().clone();
                let public_key = inner
                    .trust()
                    .keys()
                    .iter()
                    .find(|key| {
                        key.signer() == &signer
                            && key.state() == SourceProviderKeyTrustStateV1::Eligible
                    })
                    .map(|key| *key.public_key());
                (signer, public_key)
            };
            let public_key = public_key
                .ok_or_else(|| owner.poison(SourceProviderSecurityError::SessionContinuity))?;
            proof
                .signed
                .verify_for_query(&proof.query, &signer, &public_key)
                .map_err(|_| owner.poison(SourceProviderSecurityError::SessionContinuity))?;
            owner.revalidate()?;
            proof
                .execution()
                .revalidate(owner.carrier.socket().peer())
                .map_err(|error| owner.poison(error))?;
            owner.require_original_native_deadline_v3(&preparation.deadline)
        })
    }

    // Clock observation failure is also a loss of original currentness. In
    // particular, postcommit callers must retain custody under a poisoned
    // session rather than treating an unreadable clock as a retryable cut.
    fn require_original_native_deadline_v3(
        &mut self,
        deadline: &OriginalNativeDeadlineV3,
    ) -> Result<(), SourceProviderSecurityError> {
        let now = kernel_clock().map_err(|error| self.poison(error))?;
        deadline
            .require_current(now)
            .map_err(|error| self.poison(error))
    }
}

fn original_query_is_latest(
    query: &CatalogCurrentnessQueryV1,
    session: ObjectDigest,
    sequence: u64,
    overlapping: bool,
) -> bool {
    !overlapping && query.session_binding() == session && query.sequence() == sequence
}

fn original_query_is_pending(
    query: &CatalogCurrentnessQueryV1,
    current: Option<&CatalogCurrentnessQueryV1>,
    session: ObjectDigest,
    completed_sequence: u64,
) -> bool {
    current == Some(query)
        && query.session_binding() == session
        && completed_sequence.checked_add(1) == Some(query.sequence())
}

fn require_publication_scope(
    publication: &VerifiedCatalogPublicationV1,
    configuration: &RevalidatedProviderConfigurationV1,
    session: &MountProviderSessionProjectionV2,
) -> Result<(), SourceProviderSecurityError> {
    if publication.provider() != &session.authority_trust[1].authority
        || publication.resource_namespace_digest() != session.resource_namespace_digest
        || configuration.trust_head() != (session.trust_generation, session.trust_digest)
        || configuration.revocation_head()
            != (session.revocation_generation, session.revocation_digest)
    {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    Ok(())
}

fn select_catalog_claim(
    catalog: &ProviderHeldSnapshotCatalogV1,
    publication: &VerifiedCatalogPublicationV1,
    binding_digest: ObjectDigest,
) -> Result<(SourceResourceV1, ZfsHeldSnapshotProofV1), SourceProviderSecurityError> {
    let head = publication.catalog_head();
    catalog
        .select_under_head(
            head.0,
            head.1,
            publication.resource_namespace_digest(),
            binding_digest,
        )
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)
}

fn join_current_catalog_claims(
    signed: &SignedCatalogCurrentnessV1,
    query: &CatalogCurrentnessQueryV1,
    publication: &VerifiedCatalogPublicationV1,
    mount_head_minimum: (u64, ObjectDigest),
) -> Result<NativeAcquireCatalogBindingV3, SourceProviderSecurityError> {
    joined_binding(
        signed,
        query,
        publication.resource_namespace_digest(),
        publication.catalog_head(),
        publication.catalog_floor(),
        publication.canonical_publication(),
        mount_head_minimum,
    )
}

// Pure claim equality only. Callers must first retain actual signed-response
// sender custody and independently authenticate the complete publication.
fn joined_binding(
    signed: &SignedCatalogCurrentnessV1,
    query: &CatalogCurrentnessQueryV1,
    namespace: ObjectDigest,
    publication_head: (u64, ObjectDigest),
    publication_floor: (u64, ObjectDigest),
    publication: &[u8],
    mount_head_minimum: (u64, ObjectDigest),
) -> Result<NativeAcquireCatalogBindingV3, SourceProviderSecurityError> {
    let publication_digest = ObjectDigest::from_bytes(Sha256::digest(publication).into());
    if signed.head() != publication_head
        || signed.floor() != publication_floor
        || signed.publication_digest() != publication_digest
        || !catalog_floor::floor_at_least(signed.floor(), query.minimum())
        || !catalog_floor::floor_at_least(signed.head(), mount_head_minimum)
    {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    NativeAcquireCatalogBindingV3::new(
        namespace,
        signed.head().0,
        signed.head().1,
        signed.floor().0,
        signed.floor().1,
        signed.head_commitment(),
        publication_digest,
    )
    .map_err(|_| SourceProviderSecurityError::SessionContinuity)
}

// Reconstructs only the native draft's deadline, preserving every original
// identity and semantic field before normalization and signing. A local-only
// BOOTTIME fence would not constrain a Provider effect after successful send.
fn bound_native_draft_deadline(
    request: AcquireSourceRequestV1,
    deadline: &OriginalNativeDeadlineV3,
) -> Result<AcquireSourceRequestV1, SourceProviderSecurityError> {
    if request.acquisition_version() != ACQUIRE_SOURCE_REQUEST_VERSION_V2
        || request.kernel_coupled()
        || request.boot_id() != deadline.initial.paired.host_boot_id()
        || deadline.expires_seconds > request.deadline_seconds()
    {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    AcquireSourceRequestV1::new_v2(
        request.session_binding(),
        request.sequence(),
        request.request_id(),
        request.acquisition_sequence(),
        request.prospective_apply_template().to_vec(),
        request.prospective_apply_template_digest(),
        request.source_use(),
        request.node_id(),
        request.boot_id(),
        request.holder_authority_id(),
        request.holder_generation(),
        request.holder_authority_digest(),
        request.binding().to_vec(),
        request.binding_digest(),
        deadline.expires_seconds,
        request.requested_lease_seconds(),
        request.revocation_digest(),
        request.recursive(),
        request.requested_maximum_submounts(),
        request.kernel_coupled(),
    )
    .map_err(|_| SourceProviderSecurityError::SessionContinuity)
}

impl OriginalNativeDeadlineV3 {
    fn capture(
        expires_seconds: i64,
        boot: [u8; 16],
        mount_deadline: u64,
    ) -> Result<Self, SourceProviderSecurityError> {
        let initial = kernel_initial_clock()?;
        if initial.paired.host_boot_id() != boot {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        Self::from_bracket(initial, expires_seconds, mount_deadline)
    }

    fn from_bracket(
        initial: OriginalNativeClockBracketV3,
        expires_seconds: i64,
        mount_deadline: u64,
    ) -> Result<Self, SourceProviderSecurityError> {
        let paired = initial.paired;

        // Round the Mount's remaining interval down and use the lower observed
        // wall second. The signed remote expiry cannot outlive its original
        // BOOTTIME cutoff; a subsecond-only interval is not representable.
        let mount_remaining_seconds = mount_deadline
            .checked_sub(paired.boottime_nanoseconds())
            .map(|nanoseconds| nanoseconds / 1_000_000_000)
            .filter(|seconds| *seconds > 0)
            .and_then(|seconds| i64::try_from(seconds).ok())
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let mount_expires_seconds = paired
            .wall_seconds()
            .checked_add(mount_remaining_seconds)
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let expires_seconds = expires_seconds.min(mount_expires_seconds);

        let boottime_deadline = conservative_boot_ceiling(&initial, expires_seconds)?;
        let deadline = Self {
            initial,
            expires_seconds,
            boottime_deadline: boottime_deadline.min(mount_deadline),
        };
        deadline.require_current(paired)?;
        Ok(deadline)
    }

    #[cfg(test)]
    fn from_sample(
        initial: RawPairedClockSample,
        expires_seconds: i64,
        mount_deadline: u64,
    ) -> Result<Self, SourceProviderSecurityError> {
        // Equal-edge DATA preserves existing single-point regression vectors;
        // production capture always observes the actual before/after bracket.
        Self::from_bracket(
            OriginalNativeClockBracketV3::new(initial.boottime_nanoseconds(), initial)?,
            expires_seconds,
            mount_deadline,
        )
    }

    fn require_current(
        &self,
        later: RawPairedClockSample,
    ) -> Result<(), SourceProviderSecurityError> {
        self.initial
            .paired
            .validate_later_sample(later)
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        if later.wall_seconds() >= self.expires_seconds
            || later.boottime_nanoseconds() >= self.boottime_deadline
        {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        Ok(())
    }
}

/// Derives a conservative BOOTTIME ceiling from the unchanged original bracket.
fn conservative_boot_ceiling(
    initial: &OriginalNativeClockBracketV3,
    expires_seconds: i64,
) -> Result<u64, SourceProviderSecurityError> {
    // Removing the omitted wall fraction rejects a wall-before-BOOTTIME sample
    // that straddles the finalized expiry within the paired-clock tolerance.
    // Anchor the ceiling to the before-read, not a delayed after-read.
    let remaining = expires_seconds
        .checked_sub(initial.paired.wall_seconds())
        .and_then(|seconds| seconds.checked_sub(1))
        .and_then(|seconds| u64::try_from(seconds).ok())
        .filter(|seconds| *seconds > 0)
        .and_then(|seconds| seconds.checked_mul(1_000_000_000))
        .ok_or(SourceProviderSecurityError::SessionContinuity)?;
    initial
        .boottime_before
        .checked_add(remaining)
        .ok_or(SourceProviderSecurityError::SessionContinuity)
}

pub(crate) fn kernel_clock() -> Result<RawPairedClockSample, SourceProviderSecurityError> {
    let boot = aos_sandbox_linux::boot::KernelBootId::current()
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?
        .into_bytes();
    // Later pairs observe wall first; their BOOTTIME endpoint still enforces
    // the retained absolute cutoff if scheduling delays the second read.
    let wall = rustix::time::clock_gettime(rustix::time::ClockId::Realtime).tv_sec;
    kernel_clock_after_wall(boot, wall)
}

fn kernel_initial_clock() -> Result<OriginalNativeClockBracketV3, SourceProviderSecurityError> {
    let boot = aos_sandbox_linux::boot::KernelBootId::current()
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?
        .into_bytes();
    let boottime_before = kernel_boottime_nanoseconds()?;
    let wall = rustix::time::clock_gettime(rustix::time::ClockId::Realtime).tv_sec;
    let paired = kernel_clock_after_wall(boot, wall)?;
    OriginalNativeClockBracketV3::new(boottime_before, paired)
}

fn kernel_clock_after_wall(
    boot: [u8; 16],
    wall: i64,
) -> Result<RawPairedClockSample, SourceProviderSecurityError> {
    let nanoseconds = kernel_boottime_nanoseconds()?;
    let after = aos_sandbox_linux::boot::KernelBootId::current()
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?
        .into_bytes();
    if boot != after {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    RawPairedClockSample::new_untrusted(
        RawClockProvenance::new_untrusted(*b"aos-kernel-clock")
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?,
        boot,
        wall,
        nanoseconds,
    )
    .map_err(|_| SourceProviderSecurityError::SessionContinuity)
}

fn kernel_boottime_nanoseconds() -> Result<u64, SourceProviderSecurityError> {
    let boottime = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    u64::try_from(boottime.tv_sec)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1_000_000_000))
        .and_then(|seconds| {
            u64::try_from(boottime.tv_nsec)
                .ok()
                .and_then(|fraction| seconds.checked_add(fraction))
        })
        .ok_or(SourceProviderSecurityError::SessionContinuity)
}

#[cfg(test)]
mod tests {
    // These exercise DATA joins and clock policy, not installed session,
    // protected-plan, received-sender, signing, or reservation constructors.
    use super::*;
    use aos_sandbox_source_provider_protocol::{
        ProviderHeldSnapshotRowV1, SignedSourceProviderRequestV1, SourceProviderKeyUsageV1,
        SourceUseV1, decode_acquire_request, digest_logical_binding_bytes,
        prospective_mount_apply_template_digest_v1, source_provider_acquire_intent_digest_v1,
        verify_request,
    };
    use ed25519_dalek::SigningKey;

    fn digest(byte: u8) -> ObjectDigest {
        ObjectDigest::from_bytes([byte; 32])
    }

    fn query(sequence: u64, nonce: u8) -> CatalogCurrentnessQueryV1 {
        CatalogCurrentnessQueryV1::new(digest(1), [nonce; 32], sequence, 4, digest(4)).unwrap()
    }

    pub(super) fn clock(wall: i64, seconds: u64, boot: u8) -> RawPairedClockSample {
        RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted(*b"aos-kernel-clock").unwrap(),
            [boot; 16],
            wall,
            seconds * 1_000_000_000,
        )
        .unwrap()
    }

    #[test]
    fn consumed_currentness_requires_original_latest_query() {
        let query = query(3, 2);
        assert!(original_query_is_latest(&query, digest(1), 3, false));
        assert!(!original_query_is_latest(&query, digest(9), 3, false));
        assert!(!original_query_is_latest(&query, digest(1), 4, false));
        assert!(!original_query_is_latest(&query, digest(1), 2, false));
        assert!(!original_query_is_latest(&query, digest(1), 3, true));
    }

    #[test]
    fn pending_currentness_never_renews_absent_or_substituted_query() {
        let original = query(3, 2);
        assert!(original_query_is_pending(
            &original,
            Some(&original),
            digest(1),
            2
        ));
        assert!(!original_query_is_pending(&original, None, digest(1), 2));
        assert!(!original_query_is_pending(
            &original,
            Some(&query(3, 9)),
            digest(1),
            2
        ));
        assert!(!original_query_is_pending(
            &original,
            Some(&query(4, 2)),
            digest(1),
            2
        ));
        assert!(!original_query_is_pending(
            &original,
            Some(&original),
            digest(9),
            2
        ));
        assert!(!original_query_is_pending(
            &original,
            Some(&original),
            digest(1),
            3
        ));
        let different_floor =
            CatalogCurrentnessQueryV1::new(digest(1), [2; 32], 3, 5, digest(5)).unwrap();
        assert!(!original_query_is_pending(
            &original,
            Some(&different_floor),
            digest(1),
            2
        ));
    }

    #[test]
    fn data_join_preserves_exact_signed_head_floor_and_complete_publication_hash() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let signer = SourceProviderSigningKeyV1::new(
            [1; 16],
            1,
            digest(2),
            [3; 16],
            1,
            ObjectDigest::from_bytes(Sha256::digest(key.verifying_key().as_bytes()).into()),
            SourceProviderKeyUsageV1::ProviderOutcome,
        )
        .unwrap();
        let query = query(3, 2);
        // This arbitrary artifact tests equality only; it is never decoded as
        // an authenticated publication or passed to a production owner.
        let publication = [8; 520];
        let hash = ObjectDigest::from_bytes(Sha256::digest(publication).into());
        let signed = SignedCatalogCurrentnessV1::sign(
            &query,
            (5, digest(5)),
            (4, digest(4)),
            digest(6),
            hash,
            signer.clone(),
            &key,
        )
        .unwrap();
        signed
            .verify_for_query(&query, &signer, key.verifying_key().as_bytes())
            .unwrap();
        let binding = joined_binding(
            &signed,
            &query,
            digest(9),
            (5, digest(5)),
            (4, digest(4)),
            &publication,
            (5, digest(5)),
        )
        .unwrap();
        assert_eq!(binding.resource_namespace_digest(), digest(9));
        assert_eq!(binding.head(), (5, digest(5)));
        assert_eq!(binding.floor(), (4, digest(4)));
        assert_eq!(binding.current_head_commitment(), digest(6));
        assert_eq!(binding.canonical_publication_digest(), hash);

        for (head, floor, bytes) in [
            ((6, digest(6)), (4, digest(4)), publication),
            ((5, digest(7)), (4, digest(4)), publication),
            ((5, digest(5)), (3, digest(3)), publication),
            ((5, digest(5)), (4, digest(7)), publication),
            ((5, digest(5)), (4, digest(4)), [9; 520]),
        ] {
            assert!(
                joined_binding(
                    &signed,
                    &query,
                    digest(9),
                    head,
                    floor,
                    &bytes,
                    (5, digest(5))
                )
                .is_err()
            );
        }
        assert!(
            signed
                .verify_for_query(
                    &super::tests::query(3, 9),
                    &signer,
                    key.verifying_key().as_bytes()
                )
                .is_err()
        );
    }

    #[test]
    fn protected_head_bound_allows_newer_head_with_unchanged_lower_gc_floor() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let signer = SourceProviderSigningKeyV1::new(
            [1; 16],
            1,
            digest(2),
            [3; 16],
            1,
            ObjectDigest::from_bytes(Sha256::digest(key.verifying_key().as_bytes()).into()),
            SourceProviderKeyUsageV1::ProviderOutcome,
        )
        .unwrap();
        let challenge = query(3, 2);
        let publication = [8; 520];
        let hash = ObjectDigest::from_bytes(Sha256::digest(publication).into());
        // Wire minimum remains 4; the separately protected Mount head is 5.
        // V1's existing dual head/GC validation is deliberately unchanged.
        for (head, admitted) in [
            ((6, digest(6)), true),
            ((4, digest(4)), false),
            ((5, digest(7)), false),
        ] {
            let signed = SignedCatalogCurrentnessV1::sign(
                &challenge,
                head,
                (4, digest(4)),
                digest(6),
                hash,
                signer.clone(),
                &key,
            )
            .unwrap();
            signed
                .verify_for_query(&challenge, &signer, key.verifying_key().as_bytes())
                .unwrap();
            let joined = joined_binding(
                &signed,
                &challenge,
                digest(9),
                head,
                (4, digest(4)),
                &publication,
                (5, digest(5)),
            );
            assert_eq!(joined.is_ok(), admitted);
            if let Ok(binding) = joined {
                assert_eq!(binding.head(), (6, digest(6)));
                assert_eq!(binding.floor(), (4, digest(4)));
            }
        }
    }

    #[test]
    fn native_row_data_requires_exact_namespace_head_and_original_logical_binding() {
        let snapshot = ZfsHeldSnapshotProofV1::new(
            [1; 32],
            1,
            2,
            3,
            4,
            [5; 16],
            6,
            digest(7),
            digest(8),
            digest(9),
        )
        .unwrap();
        let row = ProviderHeldSnapshotRowV1::new(
            digest(2),
            [3; 32],
            4,
            digest(5),
            6,
            digest(7),
            snapshot.clone(),
        )
        .unwrap();
        let catalog = ProviderHeldSnapshotCatalogV1::new(8, digest(9), vec![row]).unwrap();
        let catalog =
            ProviderHeldSnapshotCatalogV1::from_canonical_bytes(&catalog.to_canonical_bytes())
                .unwrap();
        let (resource, selected) = catalog
            .select_under_head(8, catalog.digest(), digest(9), digest(2))
            .unwrap();
        assert_eq!(selected, snapshot);
        assert_eq!(resource.resource_namespace_digest(), digest(9));
        assert!(
            catalog
                .select_under_head(8, catalog.digest(), digest(8), digest(2))
                .is_err()
        );
        assert!(
            catalog
                .select_under_head(9, catalog.digest(), digest(9), digest(2))
                .is_err()
        );
        assert!(
            catalog
                .select_under_head(8, digest(8), digest(9), digest(2))
                .is_err()
        );
        assert!(
            catalog
                .select_under_head(8, catalog.digest(), digest(9), digest(8))
                .is_err()
        );
    }

    #[test]
    fn original_deadline_rejects_boot_rollback_drift_and_expiry_without_refresh() {
        let initial = clock(100, 200, 1);
        let deadline = OriginalNativeDeadlineV3::from_sample(initial, 110, u64::MAX).unwrap();
        assert_eq!(deadline.boottime_deadline, 209_000_000_000);
        assert!(deadline.require_current(clock(108, 208, 1)).is_ok());
        assert!(deadline.require_current(clock(109, 209, 1)).is_err());
        assert!(deadline.require_current(clock(110, 208, 1)).is_err());
        assert!(deadline.require_current(clock(101, 201, 2)).is_err());
        assert!(deadline.require_current(clock(99, 201, 1)).is_err());
        assert!(deadline.require_current(clock(101, 199, 1)).is_err());
        assert!(deadline.require_current(clock(104, 201, 1)).is_err());
        assert!(OriginalNativeDeadlineV3::from_sample(initial, 101, u64::MAX).is_err());

        // The original Mount BOOTTIME header can only shorten this fence.
        let deadline =
            OriginalNativeDeadlineV3::from_sample(initial, 110, 203_000_000_000).unwrap();
        assert!(deadline.require_current(clock(101, 201, 1)).is_ok());
        assert!(deadline.require_current(clock(102, 202, 1)).is_err());
        assert!(deadline.require_current(clock(103, 203, 1)).is_err());
    }

    #[test]
    fn signed_wall_bound_intersects_original_mount_cutoff_without_rounding_up() {
        let initial = clock(100, 200, 1);
        for (request_expiry, mount_cutoff, signed_expiry, io_cutoff) in [
            (700, 205_000_000_000, 105, 204_000_000_000),
            (700, 205_999_999_999, 105, 204_000_000_000),
            (104, 205_000_000_000, 104, 203_000_000_000),
        ] {
            let deadline =
                OriginalNativeDeadlineV3::from_sample(initial, request_expiry, mount_cutoff)
                    .unwrap();
            assert_eq!(deadline.expires_seconds, signed_expiry);
            assert_eq!(deadline.boottime_deadline, io_cutoff);
            assert!(deadline.require_current(clock(101, 201, 1)).is_ok());
            assert_eq!(deadline.expires_seconds, signed_expiry);
        }
        for mount_cutoff in [
            199_999_999_999,
            200_000_000_000,
            200_999_999_999,
            201_000_000_000,
            201_999_999_999,
        ] {
            assert!(OriginalNativeDeadlineV3::from_sample(initial, 700, mount_cutoff).is_err());
        }
        let deadline =
            OriginalNativeDeadlineV3::from_sample(initial, 700, 205_000_000_000).unwrap();
        assert!(deadline.require_current(clock(105, 204, 1)).is_err());
        assert!(deadline.require_current(clock(104, 205, 1)).is_err());
    }

    #[test]
    fn finalized_signed_expiry_rejects_a_tolerated_straddling_clock_pair() {
        let initial = clock(100, 200, 1);
        let deadline =
            OriginalNativeDeadlineV3::from_sample(initial, 700, 205_000_000_000).unwrap();
        let straddling = RawPairedClockSample::new_untrusted(
            initial.provenance(),
            initial.host_boot_id(),
            104,
            204_100_000_000,
        )
        .unwrap();

        assert!(initial.validate_later_sample(straddling).is_ok());
        assert_eq!(deadline.expires_seconds, 105);
        assert_eq!(deadline.boottime_deadline, 204_000_000_000);
        assert!(deadline.require_current(clock(103, 203, 1)).is_ok());
        assert!(deadline.require_current(straddling).is_err());
    }

    #[test]
    fn original_clock_bracket_prevents_initial_latency_from_extending_expiry() {
        let paired = clock(100, 200, 1);
        let original = OriginalNativeClockBracketV3::new(198_000_000_000, paired).unwrap();
        let deadline =
            OriginalNativeDeadlineV3::from_bracket(original, 700, 205_000_000_000).unwrap();
        let straddling = RawPairedClockSample::new_untrusted(
            paired.provenance(),
            paired.host_boot_id(),
            104,
            202_100_000_000,
        )
        .unwrap();

        assert_eq!(deadline.initial.boottime_before, 198_000_000_000);
        assert_eq!(deadline.initial.paired, paired);
        assert_eq!(deadline.expires_seconds, 105);
        assert_eq!(deadline.boottime_deadline, 202_000_000_000);
        assert!(paired.validate_later_sample(straddling).is_ok());
        assert!(deadline.require_current(clock(101, 201, 1)).is_ok());
        assert!(deadline.require_current(straddling).is_err());
    }

    #[test]
    fn reversed_clock_bracket_or_capture_consuming_its_budget_is_rejected() {
        assert!(OriginalNativeClockBracketV3::new(201_000_000_000, clock(100, 200, 1)).is_err());
        for (before, after, expires, mount_cutoff) in [
            (198_000_000_000, 200, 700, 202_000_000_000),
            (198_000_000_000, 205, 700, 210_000_000_000),
            (200_000_000_000, 203, 700, 205_000_000_000),
            (198_000_000_000, 200, 102, 205_000_000_000),
        ] {
            let original = OriginalNativeClockBracketV3::new(before, clock(100, after, 1)).unwrap();
            assert!(
                OriginalNativeDeadlineV3::from_bracket(original, expires, mount_cutoff).is_err()
            );
        }
    }

    pub(super) fn native_deadline_draft(expires_seconds: i64) -> AcquireSourceRequestV1 {
        let mut template = Vec::new();
        for tag in 1_u8..=27 {
            let value = match tag {
                1 => b"AOSMSEM1".to_vec(),
                2 => 1_u16.to_be_bytes().to_vec(),
                _ => vec![tag, tag + 1],
            };
            template.push(tag);
            template.extend_from_slice(&(value.len() as u32).to_be_bytes());
            template.extend_from_slice(&value);
        }
        let template_digest = prospective_mount_apply_template_digest_v1(&template).unwrap();
        let binding = b"native-deadline-data".to_vec();
        let binding_digest = digest_logical_binding_bytes(&binding);
        AcquireSourceRequestV1::new_v2(
            digest(1),
            1,
            [2; 16],
            3,
            template,
            template_digest,
            SourceUseV1::MountCreate,
            [4; 16],
            [5; 16],
            [6; 16],
            7,
            digest(8),
            binding,
            binding_digest,
            expires_seconds,
            600,
            digest(9),
            false,
            0,
            false,
        )
        .unwrap()
    }

    #[test]
    fn native_signed_wire_carries_shorter_mount_expiry_and_preserves_original_intent() {
        let initial = clock(100, 200, 5);
        let deadline =
            OriginalNativeDeadlineV3::from_sample(initial, 700, 205_000_000_000).unwrap();
        let original = native_deadline_draft(700);
        let bounded = bound_native_draft_deadline(original.clone(), &deadline).unwrap();

        // The existing V2 layout ends in deadline[8], lease[8], revocation[32],
        // and flags/reserved/submounts[8]. All other original bytes stay exact.
        let mut expected = encode_acquire_request(&original);
        let deadline_offset = expected.len() - 56;
        expected[deadline_offset..deadline_offset + 8].copy_from_slice(&105_i64.to_be_bytes());
        assert_eq!(encode_acquire_request(&bounded), expected);
        assert_eq!(original.deadline_seconds(), 700);
        assert_eq!(decode_acquire_request(&expected).unwrap(), bounded);
        assert!(bound_native_draft_deadline(native_deadline_draft(104), &deadline).is_err());
        let foreign_boot =
            OriginalNativeDeadlineV3::from_sample(clock(100, 200, 1), 700, 205_000_000_000)
                .unwrap();
        assert!(bound_native_draft_deadline(original.clone(), &foreign_boot).is_err());

        let catalog = NativeAcquireCatalogBindingV3::new(
            digest(9),
            5,
            digest(5),
            4,
            digest(4),
            digest(6),
            digest(7),
        )
        .unwrap();
        let original_native =
            AcquireSourceRequestV1::new_native_v3(original, catalog.clone()).unwrap();
        let bounded_native =
            AcquireSourceRequestV1::new_native_v3(bounded, catalog.clone()).unwrap();
        assert_eq!(bounded_native.native_catalog(), Some(&catalog));
        assert!(bound_native_draft_deadline(bounded_native.clone(), &deadline).is_err());
        assert_eq!(
            source_provider_acquire_intent_digest_v1(&bounded_native),
            source_provider_acquire_intent_digest_v1(&original_native)
        );
        let normalized = |request: &AcquireSourceRequestV1| {
            NormalizedAcquisitionIntentV2::from_original_acquire_request(
                request,
                SourceProviderAuthorityV1::new([10; 16], 11, digest(12)).unwrap(),
                SourceProviderAuthorityV1::new([6; 16], 7, digest(8)).unwrap(),
                [4; 16],
                [5; 16],
                [13; 16],
                14,
                digest(15),
                digest(9),
                1,
                digest(9),
            )
            .unwrap()
        };
        assert_eq!(normalized(&bounded_native), normalized(&original_native));

        // Plain cryptographic DATA verification, not an installed Root signer
        // or received-peer proof: the remote subject itself carries 105.
        let key = SigningKey::from_bytes(&[7; 32]);
        let signer = SourceProviderSigningKeyV1::for_signing_key(
            [6; 16],
            7,
            digest(8),
            [16; 16],
            1,
            SourceProviderKeyUsageV1::RootMountRecord,
            &key,
        )
        .unwrap();
        let signed = sign_request(
            SourceProviderMethod::Acquire,
            encode_acquire_request(&bounded_native),
            signer,
            &key,
        )
        .unwrap();
        let signed =
            SignedSourceProviderRequestV1::from_canonical_bytes(&signed.to_canonical_bytes())
                .unwrap();
        verify_request(&signed, key.verifying_key().as_bytes()).unwrap();
        let received = decode_acquire_request(signed.subject()).unwrap();
        assert_eq!(received, bounded_native);
        assert_eq!(received.deadline_seconds(), deadline.expires_seconds);
    }
}
