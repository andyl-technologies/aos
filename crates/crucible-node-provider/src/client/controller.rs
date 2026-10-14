//! Generic CNP/1 control calls and original evidence custody.
//!
//! This controller translates baseline method bodies without selecting a role,
//! device model or receipt oracle. The installed common adapter must separately
//! authenticate native realization, behavioral acceptance and every returned
//! semantic fact. A completed transport response is never native authority.

use std::io::{self, Write};
use std::time::Duration;

use crucible_node_contract::{Bytes, ContentRef, Extensions, Id, U64, Validate, canonical};
use serde::Serialize;
use serde_json::Value;

use crate::ProviderError;
use crate::bodies::*;
use crate::envelope::{Envelope, MessageKind, Method, Nullable, RequestOrigin};

use super::{ClientCustody, ClientOriginal, ClientSession};

#[path = "controller/registration_read.rs"]
mod registration_read;

#[path = "controller/confirmation.rs"]
mod confirmation;
pub use registration_read::CnpRegistrarRead;

/// Names one node and its indivisible execution owner on an actual connection.
///
/// These labels are routing data. Construction does not authenticate their
/// native meaning or establish an admitted common world.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControllerRoute {
    /// Identifies the logical node whose source semantics are independently installed.
    pub node: Id,
    /// Identifies its original authoritative execution owner.
    pub execution_owner: Id,
}

#[cfg(all(test, unix))]
#[path = "controller/capture_tests.rs"]
mod capture_tests;

/// Retains a generic authenticated stream and its finite original journals.
///
/// The caller retains actual native resources and the handshake registrar for
/// the entire lifetime. Neither this controller nor its decoded results select
/// a native profile or manufacture preparation, execution or cleanup evidence.
pub struct CnpController {
    session: ClientSession,
    custody: ClientCustody,
    route: ControllerRoute,
    budget: Duration,
    fenced: bool,
    protocol_owner: std::rc::Rc<crate::protocol_snapshot::ProtocolCaptureOwner>,
}

impl CnpController {
    /// Authenticates this controller's actual immutable native-five codec.
    ///
    /// The borrowed predicate checks original process/thread, genuine current
    /// registration and the same installed verifier owner without allocation.
    /// It provides codec currentness only, not Capture or fresh-adoption rights.
    ///
    /// # Errors
    /// Refuses another actor, fenced or revoked registration, mutable loss
    /// callbacks, absent native-five codec or replaced verifier ownership.
    pub fn authenticate_native5_source_codec(&self) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        if self.fenced {
            return Err(ProviderError::Correlation(
                "native5 codec controller fenced",
            ));
        }
        self.session.authenticate_native5_source_codec()
    }

    /// Observes the closed confirmation selection on this same installed actor.
    ///
    /// The selected value is data after original registration and sealed verifier
    /// checks. It grants no source Capture, archive or fresh installation right.
    ///
    /// # Errors
    /// Refuses another origin, fenced/revoked controller, callback loss policy,
    /// absent/replaced codec or a selected feature absent from negotiation.
    pub fn original_native5_confirmation_selection(
        &self,
    ) -> Result<
        Option<crate::reference_packet::service::confirmation::PacketNative5ConfirmationSelection>,
        ProviderError,
    > {
        self.authenticate_native5_source_codec()?;
        self.session.original_native5_confirmation_selection()
    }

    /// Borrows the profile of this controller's same installed immutable codec.
    ///
    /// This authenticates the original actor, current registration and actual
    /// verifier owner. A returned profile does not select source capability.
    ///
    /// # Errors
    /// Refuses another original process/thread, fenced or revoked registration,
    /// mutable loss callbacks, absent codec or replaced immutable owner.
    pub fn original_native5_capture_profile(
        &self,
    ) -> Result<&crate::reference_packet::service::PacketNative5CaptureProfile, ProviderError> {
        self.authenticate_native5_source_codec()?;
        self.session.original_native5_capture_profile()
    }

    /// Retains original and genuinely installed fresh native-five codec correspondence.
    ///
    /// This checks durable selected grammar and unchanged negotiated bounds on
    /// an unused fresh controller. It retains both complete immutable policies
    /// for the source factory's separate signed target-context check. It installs
    /// no captured counters, content, frames, native state or Ready permission.
    /// The factory must borrow and authenticate this same live controller again
    /// immediately before any subsequent installation or native effect.
    ///
    /// # Errors
    /// Refuses copied actors, used or fenced journals, absent sealed codecs,
    /// changed durable grammar or bounds, unchanged scope IDs, or an unsettled
    /// original native Capture. Arbitrary decoded snapshots cannot enter.
    pub fn prepare_fresh_native5_protocol_mapping(
        &mut self,
        original: &crate::protocol_snapshot::OriginalProtocolSnapshot,
    ) -> Result<crate::protocol_snapshot::PreparedFreshProtocolMapping, ProviderError> {
        self.authenticate_native5_source_codec()?;
        if self.custody.originals().next().is_some() {
            return Err(ProviderError::Correlation(
                "fresh native5 controller journal already used",
            ));
        }
        self.session
            .prepare_fresh_native5_protocol_mapping(original, &self.protocol_owner)
    }

    /// Rechecks a prepared mapping against this same unused fresh controller.
    ///
    /// The source factory performs this borrowed SDK check immediately before
    /// joining its separate authenticated native and semantic target context.
    /// A prior mapping or portable policy view cannot substitute another actor.
    /// This method installs no state and supplies no fresh-adoption permission.
    ///
    /// # Errors
    /// Refuses a used, fenced, revoked or substituted target/controller/codec,
    /// a foreign original snapshot, or copied process and thread custody.
    pub fn authenticate_fresh_native5_protocol_mapping(
        &self,
        original: &crate::protocol_snapshot::OriginalProtocolSnapshot,
        mapping: &crate::protocol_snapshot::PreparedFreshProtocolMapping,
    ) -> Result<(), ProviderError> {
        self.authenticate_native5_source_codec()?;
        if self.custody.originals().next().is_some() {
            return Err(ProviderError::Correlation(
                "fresh native5 mapped controller journal already used",
            ));
        }
        self.session.authenticate_fresh_native5_protocol_mapping(
            original,
            mapping,
            &self.protocol_owner,
        )
    }

    /// Reports original lifetime journal use under this same sealed registration.
    ///
    /// The source can preflight remaining response-prefix credit from actual
    /// original maps rather than treating outstanding-request limits as lifetime
    /// capacity. This getter allocates nothing and grants no Capture permission.
    ///
    /// # Errors
    /// Refuses foreign actors, fenced/revoked registrations, mutable loss
    /// callbacks, absent sealed codec or changed verifier ownership.
    pub fn original_native5_custody_facts(
        &self,
    ) -> Result<super::OriginalNative5CustodyFacts, ProviderError> {
        self.authenticate_native5_source_codec()?;
        let entries = self.session.original_native5_journal_entries()?;
        Ok(self.custody.original_native5_custody_facts(entries))
    }

    /// Reports actual retained storage of this controller's sealed native-five codec.
    ///
    /// This origin-guarded getter allocates nothing and retains the same bank.
    /// Baseline and connected-four markers cannot supply these complete-source
    /// facts. Values are data; they do not authenticate native capture enrollment.
    ///
    /// # Errors
    /// Refuses another process or thread, fenced or revoked authority, a mutable
    /// loss callback, absent native-five codec or a concurrently borrowed bank.
    pub fn original_native5_storage_facts(
        &self,
    ) -> Result<crate::protocol_snapshot::OriginalProtocolStorageFacts, ProviderError> {
        self.protocol_owner.ensure_current()?;
        if self.fenced {
            return Err(ProviderError::Correlation(
                "native5 storage controller fenced",
            ));
        }
        self.session.original_native5_storage_facts()
    }

    /// Captures complete actual controller, correlation, content and literal frames.
    ///
    /// The caller supplies snapshot capacity charged before child construction.
    /// Literal Hello originals and the actual native/semantic owners remain under
    /// the source's separate custody. This result confers no fresh-adoption right.
    ///
    /// # Errors
    /// Refuses callback codecs, partial/missing history, outstanding correlations,
    /// a fenced controller, or insufficient whole borrowed snapshot credit.
    pub fn capture_original_protocol_state(
        &mut self,
        reservation: &mut crate::protocol_snapshot::ProtocolSnapshotReservation,
        cut: crate::protocol_snapshot::ProtocolCaptureCut,
    ) -> Result<(), ProviderError> {
        if self.fenced {
            return Err(ProviderError::Correlation("captured controller fenced"));
        }
        self.session.protocol_capture_preflight(cut)?;
        self.session.preflight_protocol_reservation(reservation)?;
        reservation.validate_source_encoding(
            self.session.original_native5_codec_owner(),
            cut,
            true,
        )?;
        reservation.bind(
            self.session.authority(),
            &self.protocol_owner,
            cut,
            self.session.protocol_original_deadline(),
        )?;
        reservation.retain_native5_codec(self.session.original_native5_codec_owner())?;
        if reservation.uses_compact_encoding() {
            reservation.encode(&(
                "source-private.cnp-protocol/7",
                &self.route.node,
                &self.route.execution_owner,
                crucible_node_contract::U64::new(self.budget.as_secs()),
                self.budget.subsec_nanos(),
                self.fenced,
                self.session.original_native5_capture_profile()?,
                self.session.compact_protocol_view(),
                self.custody.compact_protocol_view(),
            ))?;
            return self.session.retain_frozen_protocol_frames(reservation);
        }
        let state = (
            "source-private.cnp-protocol/5",
            &self.route.node,
            &self.route.execution_owner,
            crucible_node_contract::U64::new(self.budget.as_secs()),
            self.budget.subsec_nanos(),
            self.fenced,
            self.session.protocol_view(),
            self.custody.protocol_view(),
        );
        reservation.encode(&state)?;
        self.session.retain_frozen_protocol_frames(reservation)
    }

    /// Moves a completed original snapshot buffer into this actual owner's result.
    ///
    /// # Errors
    /// Refuses a missing completed snapshot, changed original authority or a cut
    /// that no longer matches the current controller. Decoded data cannot enter.
    pub fn take_original_protocol_snapshot(
        &mut self,
        reservation: &mut Option<crate::protocol_snapshot::ProtocolSnapshotReservation>,
        cut: crate::protocol_snapshot::ProtocolCaptureCut,
    ) -> Result<crate::protocol_snapshot::OriginalProtocolSnapshot, ProviderError> {
        self.session.protocol_capture_preflight(cut)?;
        crate::protocol_snapshot::ProtocolSnapshotReservation::finish_from_slot(
            reservation,
            self.session.authority(),
            &self.protocol_owner,
            cut,
        )
    }

    /// Retains a completed original snapshot in the caller's owning result slot.
    ///
    /// Failure leaves the same reservation in its original slot. Success fills
    /// the empty result slot before the source performs any later guard or copy;
    /// no fallible revalidation occurs after the reservation moves.
    ///
    /// # Errors
    /// Refuses an occupied result, absent or incomplete reservation, foreign
    /// original issuer, changed registration or incompatible current cut.
    pub fn take_original_protocol_snapshot_into(
        &mut self,
        reservation: &mut Option<crate::protocol_snapshot::ProtocolSnapshotReservation>,
        completed: &mut Option<crate::protocol_snapshot::OriginalProtocolSnapshot>,
        cut: crate::protocol_snapshot::ProtocolCaptureCut,
    ) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        if completed.is_some() {
            return Err(ProviderError::Conflict(
                "original snapshot result slot occupied",
            ));
        }
        let original = self.take_original_protocol_snapshot(reservation, cut)?;
        *completed = Some(original);
        Ok(())
    }

    /// Compares actual source-issued owner and original registration identities.
    pub fn owns_original_protocol_snapshot(
        &self,
        snapshot: &crate::protocol_snapshot::OriginalProtocolSnapshot,
    ) -> bool {
        snapshot.same_owner(&self.protocol_owner, self.session.authority())
    }

    /// Installs a precharged literal frame bank with the immutable packet codec.
    ///
    /// The reservation must be owned and charged before child construction.
    /// This selects only exact transport retention; it authenticates no source,
    /// world, captured state, process or fresh-adoption permission.
    ///
    /// # Errors
    /// Refuses an already used or fenced controller and mutable loss callbacks.
    /// Native5 source-specific schema and capture admission remain separate.
    pub fn install_native5_frame_bank(
        &mut self,
        reservation: crate::transport::original_frames::OriginalFrameReservation,
    ) -> Result<(), ProviderError> {
        if self.fenced || self.custody.originals().next().is_some() {
            return Err(ProviderError::Correlation(
                "native5 bank requires original unused controller",
            ));
        }
        self.session.install_native5_frame_bank(reservation)
    }

    /// Installs the closed complete source-five grammar and original literal bank.
    ///
    /// The source factory supplies the same selected native realization and
    /// coordinator after genuine Hello. It charges bank, full immutable policy
    /// and temporary metadata before Child. This transports source grammar only;
    /// complete semantic/native capture and fresh installation remain separate.
    ///
    /// # Errors
    /// Refuses copied actor identities, used/fenced journals or banks, foreign
    /// source routes, unnegotiated features, callback codecs or changed policy.
    pub fn install_native5_source_codec(
        &mut self,
        bank: &mut Option<crate::transport::original_frames::OriginalFrameReservation>,
        selection: crate::reference_packet::control::PacketControlSelection,
        coordinator: crate::reference_service::InstalledContent,
    ) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        if self.fenced
            || self.custody.originals().next().is_some()
            || selection.realization.bindings.len() != 1
            || selection.realization.owner_bindings.len() != 1
            || self.route.node != selection.realization.bindings[0].compatibility.node_id
            || self.route.execution_owner != selection.realization.owner_bindings[0].owner.id
        {
            return Err(ProviderError::Correlation(
                "native5 codec requires original unused source controller",
            ));
        }
        self.session
            .install_native5_source_codec(bank, selection, coordinator)
    }

    /// Installs the same original immutable source codec with an explicit edition.
    ///
    /// The supplied profile becomes frozen data in the actual source policy.
    /// It confers no Capture, semantic settlement or fresh installation right.
    ///
    /// # Errors
    /// Refuses invalid profile bounds, copied or used actors, foreign routes,
    /// revoked negotiation, replaced policy or already-used literal banks.
    pub fn install_native5_source_codec_with_profile(
        &mut self,
        bank: &mut Option<crate::transport::original_frames::OriginalFrameReservation>,
        selection: crate::reference_packet::control::PacketControlSelection,
        coordinator: crate::reference_service::InstalledContent,
        profile: crate::reference_packet::service::PacketNative5CaptureProfile,
    ) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        if self.fenced
            || self.custody.originals().next().is_some()
            || selection.realization.bindings.len() != 1
            || selection.realization.owner_bindings.len() != 1
            || self.route.node != selection.realization.bindings[0].compatibility.node_id
            || self.route.execution_owner != selection.realization.owner_bindings[0].owner.id
        {
            return Err(ProviderError::Correlation(
                "native5 codec requires original unused source controller",
            ));
        }
        self.session.install_native5_source_codec_with_profile(
            bank,
            selection,
            coordinator,
            profile,
        )
    }

    /// Installs source-selected confirmation grammar on the original unused actor.
    ///
    /// The additional immutable schema, same source route, selected negotiation
    /// and original bank are checked before bank transfer. Transport selection
    /// supplies no semantic/native Capture or fresh restoration authority.
    ///
    /// # Errors
    /// Refuses a used/foreign controller, wrong source tuple, absent additional
    /// schema/feature, mutable loss callback or already installed verifier/bank.
    pub fn install_native5_source_confirmation_codec(
        &mut self,
        bank: &mut Option<crate::transport::original_frames::OriginalFrameReservation>,
        selection: crate::reference_packet::control::PacketControlSelection,
        coordinator: crate::reference_service::InstalledContent,
        profile: crate::reference_packet::service::PacketNative5CaptureProfile,
    ) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        if self.fenced
            || self.custody.originals().next().is_some()
            || selection.realization.bindings.len() != 1
            || selection.realization.owner_bindings.len() != 1
            || self.route.node != selection.realization.bindings[0].compatibility.node_id
            || self.route.execution_owner != selection.realization.owner_bindings[0].owner.id
        {
            return Err(ProviderError::Correlation(
                "confirmation codec requires original unused source controller",
            ));
        }
        self.session.install_native5_source_confirmation_codec(
            bank,
            selection,
            coordinator,
            profile,
        )
    }

    /// Installs the original connected input codec and a precharged literal bank.
    ///
    /// The source charges the actual bank and schema metadata before Child.
    /// This one-shot seam preserves the original route and negotiated Input4
    /// schema without replacing it with the baseline no-extension codec. It
    /// grants no complete Native5 capture, native adoption or readiness.
    ///
    /// # Errors
    /// Refuses used/fenced journals, foreign routes, absent or used banks,
    /// unnegotiated source features, schema replacement or mutable loss callbacks.
    /// Validation refusal leaves the supplied original bank in its same slot.
    pub fn install_native5_connected_frame_bank(
        &mut self,
        reservation: &mut Option<crate::transport::original_frames::OriginalFrameReservation>,
        binding: &crucible_node_contract::NodeBinding,
        owner: &crucible_node_contract::OwnerBinding,
    ) -> Result<(), ProviderError> {
        if self.fenced
            || self.custody.originals().next().is_some()
            || self.route.node != binding.compatibility.node_id
            || self.route.execution_owner != owner.owner.id
        {
            return Err(ProviderError::Correlation(
                "connected archive requires original unused source controller",
            ));
        }
        self.session
            .install_native5_connected_frame_bank(reservation, binding, owner)
    }

    /// Installs the immutable packet codec before any original control request.
    ///
    /// This selects source-owned no-extension transport validation only. It
    /// grants no profile, native, readiness, behavioral or operation authority.
    /// Existing generic controllers retain their independently supplied verifier.
    ///
    /// # Errors
    /// Refuses a fenced controller, a used original journal or any prior control
    /// frame. A failed installation does not dispatch native work.
    pub fn install_packet_transport_schema(&mut self) -> Result<(), ProviderError> {
        if self.fenced || self.custody.originals().next().is_some() {
            return Err(ProviderError::Correlation(
                "packet schema requires original unused controller",
            ));
        }
        self.session.install_packet_schema()
    }

    /// Reports the actual connection's immutable packet codec selection as data.
    ///
    /// This source fact cannot be set by a vendor verifier or portable record.
    /// It is only a necessary conjunction for an installed packet source policy.
    pub fn has_packet_transport_schema(&self) -> bool {
        self.session.has_packet_schema()
    }

    /// Installs the closed connected packet input codec on the original controller.
    ///
    /// The immutable verifier binds negotiated transport and source-owned routing
    /// records. Syntax and registration confer no native, activation or Ready
    /// authority; the source dispatcher still authenticates its active world and
    /// every original staging receipt. The no-extension installer stays separate.
    ///
    /// # Errors
    /// Refuses a fenced or used original controller, an unnegotiated feature,
    /// inconsistent source bindings, or replacement of an installed packet codec.
    pub fn install_connected_packet_transport_schema(
        &mut self,
        binding: &crucible_node_contract::NodeBinding,
        owner: &crucible_node_contract::OwnerBinding,
    ) -> Result<(), ProviderError> {
        if self.fenced
            || self.custody.originals().next().is_some()
            || self.route.node != binding.compatibility.node_id
            || self.route.execution_owner != owner.owner.id
        {
            return Err(ProviderError::Correlation(
                "connected packet schema requires original unused source controller",
            ));
        }
        self.session.install_connected_packet_schema(binding, owner)
    }

    /// Reports source installation of the immutable connected packet codec.
    ///
    /// The marker is distinct from the no-extension packet codec and grants no
    /// semantic or native authority merely because it is present.
    pub fn has_connected_packet_transport_schema(&self) -> bool {
        self.session.has_connected_packet_schema()
    }

    /// Checks complete source-selected reply and blob custody before dispatch.
    ///
    /// This pure capacity check grants no operation or receipt authority. The
    /// caller must hold this same controller exclusively through the subsequent
    /// exchange and authenticate the source's complete response population. It
    /// checks both original endpoint journals and all immutable transfer/content
    /// slots; a response extent alone is not a complete blob-transfer allowance.
    /// Existing call and wire behavior is unchanged for callers not using it.
    ///
    /// # Errors
    /// Refuses a fenced lease, nonfinite allowances, exhausted negotiated or
    /// local journals, and insufficient complete object/transfer byte custody.
    pub fn preflight_source_reply(
        &self,
        controller_requests: usize,
        provider_requests: usize,
        journal_bytes: usize,
        content_objects: usize,
        content_bytes: usize,
    ) -> Result<(), ProviderError> {
        if self.fenced
            || controller_requests > 4096
            || provider_requests > 4096
            || content_objects > 4096
            || journal_bytes > 256 * 1024 * 1024
            || content_bytes > 256 * 1024 * 1024
        {
            return Err(ProviderError::ResourceExhausted(
                "source response allowance",
            ));
        }
        self.session.authority().ensure_live()?;
        let negotiated_entries =
            usize::try_from(self.session.authority().limits().journal_entries.get())
                .map_err(|_| ProviderError::ResourceExhausted("source journal platform bound"))?;
        self.custody.preflight_response(
            controller_requests,
            provider_requests,
            journal_bytes,
            negotiated_entries,
        )?;
        self.custody
            .content()
            .preflight_capacity(content_objects, content_bytes)
    }

    /// Takes the original negotiated stream and finite immutable byte custody.
    ///
    /// Refusal drops the supplied session, custody and route. Native owners that
    /// must retain these originals use [`Self::new_retained`] with caller-owned slots.
    ///
    /// # Errors
    /// Refuses expired registration, missing evidence delivery, or zero or
    /// greater-than-one-minute operational exchange budgets.
    pub fn new(
        session: ClientSession,
        custody: ClientCustody,
        route: ControllerRoute,
        budget: Duration,
    ) -> Result<Self, ProviderError> {
        session.authority().ensure_live()?;
        if budget.is_zero()
            || budget > Duration::from_secs(60)
            || !session
                .authority()
                .selected_features()
                .iter()
                .any(|feature| feature.as_str() == "cnp.control-evidence/1")
        {
            return Err(ProviderError::Correlation(
                "generic controller lacks bounded original evidence scope",
            ));
        }
        Ok(Self {
            session,
            custody,
            route,
            budget,
            fenced: false,
            protocol_owner: std::rc::Rc::new(crate::protocol_snapshot::ProtocolCaptureOwner::new()),
        })
    }

    /// Validates caller-owned originals before taking the negotiated session.
    ///
    /// The caller retains these slots outside any unwind boundary. Refusal
    /// leaves every slot unchanged; success moves the same session, complete
    /// journals and route into this controller without another allocation.
    /// The slots and route can be prepared before Child, while the actual
    /// session is installed immediately after the original Hello completes.
    /// The ordinary `new` API and its validation remain unchanged.
    ///
    /// # Errors
    /// Refuses missing original slots, expired registration, unsupported evidence
    /// delivery or zero/greater-than-one-minute exchange budget. Every refusal
    /// leaves the original session, custody and route in the caller's slots.
    pub fn new_retained(
        session: &mut Option<ClientSession>,
        custody: &mut Option<ClientCustody>,
        route: &mut Option<ControllerRoute>,
        budget: Duration,
    ) -> Result<Self, ProviderError> {
        let original = session.as_ref().ok_or(ProviderError::Correlation(
            "generic controller original session absent",
        ))?;
        if custody.is_none() || route.is_none() {
            return Err(ProviderError::Correlation(
                "generic controller original custody or route absent",
            ));
        }
        original.authority().ensure_live()?;
        if budget.is_zero()
            || budget > Duration::from_secs(60)
            || !original
                .authority()
                .selected_features()
                .iter()
                .any(|feature| feature.as_str() == "cnp.control-evidence/1")
        {
            return Err(ProviderError::Correlation(
                "generic controller lacks bounded original evidence scope",
            ));
        }

        // No callback or allocation separates validation from these moves.
        // Even an inconsistent slot set is returned to its original holder.
        match (session.take(), custody.take(), route.take()) {
            (Some(session), Some(custody), Some(route)) => Ok(Self {
                session,
                custody,
                route,
                budget,
                fenced: false,
                protocol_owner: std::rc::Rc::new(
                    crate::protocol_snapshot::ProtocolCaptureOwner::new(),
                ),
            }),
            (original_session, original_custody, original_route) => {
                *session = original_session;
                *custody = original_custody;
                *route = original_route;
                Err(ProviderError::Correlation(
                    "generic controller original slots changed",
                ))
            }
        }
    }

    /// Returns the actual kernel peer checked during the original negotiation.
    pub fn peer_pid(&self) -> u32 {
        self.session.peer_pid()
    }

    /// Borrows the independently measured actual endpoint executable reference.
    pub fn peer_executable(&self) -> &ContentRef {
        self.session.peer_executable()
    }

    /// Borrows the original host-authenticated transport registration.
    pub fn authority(&self) -> &crate::handshake::ConnectionAuthority {
        self.session.authority()
    }

    /// Borrows the fixed public route without granting owner authority.
    pub fn route(&self) -> &ControllerRoute {
        &self.route
    }

    /// Borrows one retained original request and its authentic last response.
    ///
    /// Missing or unresolved originals are never reconstructed from later
    /// observations. Reading does not retry or retire an original operation.
    pub fn original(&self, request: &Id) -> Option<&ClientOriginal> {
        self.custody.original(RequestOrigin::Controller, request)
    }

    /// Enumerates both endpoint namespaces under the original finite custody.
    pub fn originals(&self) -> impl Iterator<Item = &ClientOriginal> {
        self.custody.originals()
    }

    /// Enumerates retained originals from one exact endpoint namespace.
    ///
    /// This reads the same original custody without reconstructing requests or
    /// inferring that a matching ID in the other namespace is the same request.
    pub fn originals_by_origin(
        &self,
        origin: RequestOrigin,
    ) -> impl Iterator<Item = &ClientOriginal> {
        self.custody.originals_by_origin(origin)
    }

    /// Borrows complete hash-verified bytes for an independent source oracle.
    ///
    /// # Errors
    /// Refuses unavailable original bytes or changed reference metadata.
    pub fn content(&self, reference: &ContentRef) -> Result<&[u8], ProviderError> {
        self.custody.content().get(reference)
    }

    /// Decodes a bounded closed receipt as data without authenticating its meaning.
    ///
    /// # Errors
    /// Refuses missing original bytes, exceeded frame bounds or an invalid record.
    pub fn record<T: serde::de::DeserializeOwned + Validate>(
        &self,
        reference: &ContentRef,
    ) -> Result<T, ProviderError> {
        Ok(canonical::decode(
            self.content(reference)?,
            self.maximum_frame()?,
        )?)
    }

    /// Sends one original closed baseline method and retains promised evidence.
    ///
    /// Direct Rust bodies pass a nonretaining whole-envelope sizing pass before
    /// allocating a JSON value or dispatching a native request. Immutable request
    /// identity includes the complete original body and scope; only transport
    /// sequence changes on an identical retry. Refusals remain typed responses.
    ///
    /// # Errors
    /// Refuses oversized or invalid bodies, changed originals, unavailable
    /// registration, exhausted journals, transport loss or missing receipt bytes.
    pub fn call(
        &mut self,
        request_id: Id,
        operation_id: Option<Id>,
        method: Method,
        owner_scoped: bool,
        body: impl Serialize,
    ) -> Result<ResponseBody, ProviderError> {
        self.call_with_extensions(
            request_id,
            operation_id,
            method,
            owner_scoped,
            body,
            Extensions::new(),
        )
    }

    /// Sends a negotiated envelope extension through the same original request journal.
    ///
    /// Complete borrowed-envelope credit precedes JSON allocation. The selected
    /// connection schema must independently admit every extension; this method
    /// supplies no source, consumption or execution authority.
    ///
    /// # Errors
    /// Refuses oversized or invalid complete frames, unnegotiated extensions,
    /// changed originals, exhausted custody or uncertain original transport.
    pub fn call_with_extensions(
        &mut self,
        request_id: Id,
        operation_id: Option<Id>,
        method: Method,
        owner_scoped: bool,
        body: impl Serialize,
        extensions: Extensions,
    ) -> Result<ResponseBody, ProviderError> {
        self.call_scoped(
            request_id,
            CallScope {
                operation_id,
                method,
                owner_scoped,
                capture_owner: None,
            },
            body,
            extensions,
        )
    }

    /// Sends one original administrative capture on the retained controller.
    ///
    /// The installed source independently authenticates the capture owner,
    /// complete participants, cut and original runtime ticket. This method
    /// retains the same original transport and request journal; it installs no
    /// preservation capability and supplies no capture or restoration authority.
    ///
    /// # Errors
    /// Refuses a non-Capture Begin body, an invalid complete request, exhausted
    /// custody, changed originals, unavailable registration or uncertain I/O.
    pub fn call_original_capture(
        &mut self,
        request_id: Id,
        operation_id: Id,
        capture_owner: Id,
        request: BeginRequest,
    ) -> Result<ResponseBody, ProviderError> {
        // The ordinary call path counts the complete borrowed envelope before
        // decoding arguments or allocating another body. Inspecting only this
        // Copy discriminator avoids an unbounded precredit argument clone.
        if request.kind != BeginKind::Capture {
            return Err(ProviderError::Correlation(
                "original capture requires Capture arguments",
            ));
        }
        self.call_scoped(
            request_id,
            CallScope {
                operation_id: Some(operation_id),
                method: Method::Begin,
                owner_scoped: true,
                capture_owner: Some(capture_owner),
            },
            request,
            Extensions::new(),
        )
    }

    fn call_scoped(
        &mut self,
        request_id: Id,
        scope: CallScope,
        body: impl Serialize,
        extensions: Extensions,
    ) -> Result<ResponseBody, ProviderError> {
        let CallScope {
            operation_id,
            method,
            owner_scoped,
            capture_owner,
        } = scope;
        if self.fenced {
            return Err(ProviderError::Correlation(
                "generic original controller is fenced",
            ));
        }
        let session_id = self.session.authority().session_id().clone();
        let incarnation_id = self.session.authority().incarnation_id().clone();
        let node_id = owner_scoped.then(|| self.route.node.clone());
        let execution_owner_id =
            (owner_scoped && capture_owner.is_none()).then(|| self.route.execution_owner.clone());
        let wire = BorrowedEnvelope {
            protocol: "CNP/1",
            message: MessageKind::Request,
            session_id: &session_id,
            incarnation_id: &incarnation_id,
            node_id: &node_id,
            execution_owner_id: &execution_owner_id,
            capture_owner_id: capture_owner.as_ref(),
            request_id: &request_id,
            operation_id: &operation_id,
            sequence: U64::new(u64::MAX),
            method,
            body: &body,
            extensions: &extensions,
        };
        count_serialized(&wire, self.maximum_frame()?)?;

        let body =
            serde_json::to_value(body).map_err(crucible_node_contract::ContractError::from)?;
        let Value::Object(body) = body else {
            return Err(ProviderError::Frame("generic method body is not an object"));
        };
        let original = decode_request(method, &body)?;
        let request = Envelope {
            protocol: "CNP/1".into(),
            message: MessageKind::Request,
            session_id: Nullable(Some(session_id)),
            incarnation_id: Nullable(Some(incarnation_id)),
            node_id: Nullable(node_id),
            execution_owner_id: Nullable(execution_owner_id),
            capture_owner_id: Nullable(capture_owner),
            request_id: Nullable(Some(request_id)),
            operation_id: Nullable(operation_id),
            sequence: U64::new(2),
            method,
            body,
            extensions,
        };
        let reply = self
            .session
            .exchange(&mut self.custody, request, self.budget)?;
        let response = decode_response(&original, &reply.body)?;
        if matches!(response.shape, ResponseShape::Completed { .. }) {
            let mut roots = Vec::new();
            references(&Value::Object(reply.body), &mut roots)?;
            self.session
                .receive_content(&mut self.custody, &roots, self.budget)?;
        }
        Ok(response)
    }

    /// Transfers exact original immutable content through baseline blob methods.
    ///
    /// Uploading bytes grants no modeled input or receipt authority. Identical
    /// transfers keep their original IDs; partial or uncertain transfer failures
    /// retain every original request and owned byte buffer.
    ///
    /// # Errors
    /// Refuses changed content, insufficient finite custody, invalid progress,
    /// exhausted journals, overlong identities or uncertain transport effects.
    pub fn upload(&mut self, reference: &ContentRef, bytes: &[u8]) -> Result<(), ProviderError> {
        if self.fenced {
            return Err(ProviderError::Correlation(
                "generic original controller is fenced",
            ));
        }
        reference.verify(bytes)?;
        // Reuse the current borrowed installation preflight before any body copy.
        self.custody
            .content_mut()
            .install_borrowed(std::iter::once((reference, bytes)))?;
        let transfer = Id::new(format!("cnp-content-{}", reference.hash.digest))?;
        let begun = self.call(
            Id::new(format!("cnp-blob-begin-{}", reference.hash.digest))?,
            None,
            Method::BlobBegin,
            false,
            BlobBeginRequest {
                transfer_id: transfer.clone(),
                content: reference.clone(),
                extensions: Extensions::new(),
            },
        )?;
        let Some(MethodResult::BlobBegin(progress)) = begun.result else {
            return Err(ProviderError::Correlation(
                "original blob reservation refused",
            ));
        };
        if progress.transfer_id != transfer || progress.next_offset > reference.length {
            return Err(ProviderError::Correlation(
                "original blob reservation changed",
            ));
        }
        let frame_room = self
            .session
            .authority()
            .limits()
            .frame_bytes
            .get()
            .saturating_sub(2048)
            .saturating_mul(3)
            / 4;
        let maximum = progress
            .maximum_chunk_bytes
            .min(self.session.authority().limits().blob_chunk_bytes)
            .get()
            .min(frame_room);
        let maximum = usize::try_from(maximum)
            .ok()
            .filter(|value| *value != 0)
            .ok_or(ProviderError::ResourceExhausted("blob frame allowance"))?;
        let mut offset = 0usize;
        for chunk in bytes.chunks(maximum) {
            let response =
                self.call(
                    Id::new(format!("cnp-blob-chunk-{}-{offset}", reference.hash.digest))?,
                    None,
                    Method::BlobChunk,
                    false,
                    BlobChunkRequest {
                        transfer_id: transfer.clone(),
                        offset: U64::new(u64::try_from(offset).map_err(|_| {
                            ProviderError::ResourceExhausted("blob platform offset")
                        })?),
                        bytes: Bytes::new(chunk.to_vec()),
                        extensions: Extensions::new(),
                    },
                )?;
            offset = offset
                .checked_add(chunk.len())
                .ok_or(ProviderError::ResourceExhausted("blob offset"))?;
            if !matches!(response.result, Some(MethodResult::BlobChunk(ref progress))
                if progress.transfer_id == transfer && progress.next_offset.get() == offset as u64)
            {
                return Err(ProviderError::Correlation("original blob chunk changed"));
            }
        }
        let response = self.call(
            Id::new(format!("cnp-blob-finish-{}", reference.hash.digest))?,
            None,
            Method::BlobFinish,
            false,
            BlobFinishRequest {
                transfer_id: transfer,
                extensions: Extensions::new(),
            },
        )?;
        if !matches!(response.result, Some(MethodResult::BlobFinish(ref progress))
            if progress.content == *reference)
        {
            return Err(ProviderError::Correlation(
                "original blob completion changed",
            ));
        }
        Ok(())
    }

    /// Fences the original stream while preserving native and journal obligations.
    pub fn fence(&mut self) {
        self.fenced = true;
        self.session.close();
    }

    fn maximum_frame(&self) -> Result<usize, ProviderError> {
        usize::try_from(self.session.authority().limits().frame_bytes.get())
            .map_err(|_| ProviderError::ResourceExhausted("generic platform frame ceiling"))
    }
}

// Scope is inert routing data; source and native checks remain mandatory.
struct CallScope {
    operation_id: Option<Id>,
    method: Method,
    owner_scoped: bool,
    capture_owner: Option<Id>,
}

#[derive(Serialize)]
struct BorrowedEnvelope<'a, T> {
    protocol: &'static str,
    message: MessageKind,
    session_id: &'a Id,
    incarnation_id: &'a Id,
    node_id: &'a Option<Id>,
    execution_owner_id: &'a Option<Id>,
    capture_owner_id: Option<&'a Id>,
    request_id: &'a Id,
    operation_id: &'a Option<Id>,
    sequence: U64,
    method: Method,
    body: &'a T,
    extensions: &'a Extensions,
}

fn count_serialized(value: &impl Serialize, maximum: usize) -> Result<(), ProviderError> {
    struct Counter {
        used: usize,
        maximum: usize,
    }

    impl Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let Some(next) = self.used.checked_add(bytes.len()) else {
                return Err(io::Error::other("generic body length overflow"));
            };
            if next > self.maximum {
                return Err(io::Error::other("generic frame exceeds original credit"));
            }
            self.used = next;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    serde_json::to_writer(&mut Counter { used: 0, maximum }, value)
        .map_err(|_| ProviderError::ResourceExhausted("generic whole-frame precredit"))
}

fn references(value: &Value, output: &mut Vec<ContentRef>) -> Result<(), ProviderError> {
    match value {
        Value::Object(object)
            if object.contains_key("hash")
                && object.contains_key("length")
                && object.contains_key("media_type") =>
        {
            let reference: ContentRef = serde_json::from_value(value.clone())
                .map_err(crucible_node_contract::ContractError::from)?;
            reference.validate()?;
            if !output.contains(&reference) {
                if output.len() == 4096 {
                    return Err(ProviderError::ResourceExhausted("generic evidence roots"));
                }
                output.push(reference);
            }
        }
        Value::Object(object) => {
            for child in object.values() {
                references(child, output)?;
            }
        }
        Value::Array(array) => {
            for child in array {
                references(child, output)?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
#[path = "controller/construction_tests.rs"]
mod construction_tests;
