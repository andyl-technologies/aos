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

#[path = "controller/ack_emitter.rs"]
mod ack_emitter;
pub(crate) use ack_emitter::maximum_canonical_ack_framed_bytes;
mod assigned_admit;
mod assigned_restore;
mod installed_activation;
mod installed_observation;
#[path = "controller/restored_suffix_host.rs"]
mod restored_suffix_host;
pub use installed_activation::{
    CompletedOriginalInstalledRestorationActivation, CompletedOriginalInstalledRestorationUpload,
    OriginalRestorationActivationTargetBindingData, PreparedOriginalInstalledRestorationActivation,
    PreparedOriginalInstalledRestorationUpload,
};
pub use installed_observation::{
    CompletedOriginalInstalledRestorationObservation,
    PreparedOriginalInstalledRestorationObservation,
};
pub use restored_suffix_host::PreparedOriginalRestoredInputReactive17HostAttempt;
pub use restored_suffix_host::{
    OriginalRestoredSuffixBody, OriginalRestoredSuffixHostAttempt,
    OriginalRestoredSuffixHostHistoricalData, PreparedOriginalRestoredSuffixHostAttempt,
};
mod assigned_transfer;
mod fresh_restore_query;
#[path = "controller/input_emitter.rs"]
mod input_emitter;
mod owned11_quote;
mod restore_upload;
pub use ack_emitter::OriginalCanonicalBlobAckEmitter;
pub use assigned_admit::{CompletedOriginalCanonicalAckAdmit, PreparedOriginalCanonicalAckAdmit};
pub use assigned_restore::{CompletedOriginalCompleteRestore, PreparedOriginalCompleteRestore};
pub use assigned_transfer::{
    CompletedOriginalCompleteRestoreTransfer, OriginalFreshRestorePrepareBindingStorageData,
    PreparedOriginalCompleteRestoreTransfer,
};
pub use fresh_restore_query::{OriginalFreshRestoreQuery, OriginalFreshRestoreQueryStorageData};
pub use input_emitter::OriginalCanonicalRestoreInputEmitter;
pub use restore_upload::{
    OriginalCompleteRestoreInputUpload, OriginalCompleteRestoreInputUploadProspectiveStorageData,
    OriginalCompleteRestoreInputUploadStorageData, OriginalCompleteRestoreUploadBeforeMappingData,
};

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
    original_ack_admit: Option<assigned_admit::AssignedOriginalCanonicalAckAdmit>,
    original_complete_restore: Option<assigned_restore::AssignedOriginalCompleteRestore>,
    original_complete_restore_prepare: Option<assigned_restore::AssignedOriginalCompleteRestore>,
    original_complete_restore_commit: Option<assigned_restore::AssignedOriginalCompleteRestore>,
    installed_complete_restore: Option<complete_installation::InstalledArchivedProtocolState>,
    original_installed_restoration_activation:
        [Option<installed_activation::AssignedOriginalInstalledRestorationActivation>; 2],
    original_installed_restoration_upload: [Option<installed_activation::AssignedUpload>; 2],
    original_installed_restoration_observation:
        Option<installed_observation::AssignedOriginalInstalledRestorationObservation>,
}

impl CnpController {
    /// Observes exact current whole-eleven metadata backing and capacity-row count.
    ///
    /// This reads the same owning controller and its actual installed codec. It
    /// allocates no record bank and invokes no callback, serializer or I/O. Future
    /// journal growth and physical tree/control-block/stack peak remain separate.
    ///
    /// # Errors
    /// Refuses a foreign or revoked original actor, mutable response-loss callback,
    /// unsettled assigned Admit, checked extent overflow or traversal exhaustion.
    pub fn original_owned11_metadata_facts(
        &self,
    ) -> Result<crate::protocol_snapshot::RetainedProtocolMetadataFacts, ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        if let Some(assigned) = &self.original_ack_admit {
            assigned.validate_owned_snapshot()?;
        }
        let mut observer = crate::retained_metadata::MetadataObserver::new();
        self.observe_owned11_metadata(&mut observer)?;
        self.authenticate_native5_source_codec()?;
        Ok(observer.finish())
    }

    fn observe_owned11_metadata(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), ProviderError> {
        // Exhaustive destructuring keeps future retained fields visible.
        let Self {
            session,
            custody,
            route,
            budget: _,
            fenced,
            protocol_owner,
            original_ack_admit,
            original_complete_restore,
            original_complete_restore_prepare,
            original_complete_restore_commit,
            installed_complete_restore,
            original_installed_restoration_activation,
            original_installed_restoration_upload,
            original_installed_restoration_observation,
        } = self;
        if original_installed_restoration_observation.is_some()
            || original_installed_restoration_upload
                .iter()
                .any(Option::is_some)
            || original_installed_restoration_activation
                .iter()
                .any(Option::is_some)
            || installed_complete_restore.is_some()
            || original_complete_restore_prepare.is_some()
            || original_complete_restore_commit.is_some()
        {
            return Err(ProviderError::Correlation(
                "installed archived graph requires extended host complete class",
            ));
        }
        observer.observe(&route.node)?;
        observer.observe(&route.execution_owner)?;
        observer.observe(fenced)?;
        observer.shared_original(
            crate::retained_metadata::aliases::MetadataSharedKind::ProtocolOwner,
            protocol_owner.as_ref(),
        )?;
        session.observe_owned_metadata(observer)?;
        custody.observe_owned_metadata(observer)?;
        if let Some(assigned) = original_ack_admit {
            assigned.observe_owned_metadata(observer)?;
        }
        if let Some(restore) = original_complete_restore {
            restore.observe_owned_metadata(observer)?;
        }
        Ok(())
    }

    /// Returns raw Hello digests from this exact recorded controller connection.
    ///
    /// The source separately binds its own original journal/native/key context.
    /// This check requires the same retained bank Rc; equal bytes alone cannot
    /// stand in for the Hello used by this actual negotiated connection.
    ///
    /// # Errors
    /// Refuses a foreign actor, revoked or unselected codec, different Hello
    /// bank, missing recorded association or incomplete literal framing.
    pub fn original_canonical_ack_hello_frame_digests(
        &self,
        journal: &super::OriginalHelloJournal,
    ) -> Result<crate::native_hello::OriginalHelloFrameDigests, ProviderError> {
        self.authenticate_native5_source_codec()?;
        if self.original_native5_ack_emitter_selection()? != Some(crate::reference_packet::service::ack_emitter::PacketNative5AckEmitterSelection::CanonicalSdkBlob5) {
            return Err(ProviderError::Correlation("canonical ACK original Hello selection absent"));
        }
        self.session.original_ack_hello_digests(journal)
    }

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

    /// Observes this actor's actual immutable canonical acknowledgement selection.
    ///
    /// The returned value is data. It grants no native frame limit, source
    /// capture or permission to install a captured state.
    ///
    /// # Errors
    /// Refuses changed actor, revoked registrar, replaced codec, callback loss
    /// policy or selected mechanism missing from the negotiated source features.
    pub fn original_native5_ack_emitter_selection(
        &self,
    ) -> Result<
        Option<crate::reference_packet::service::ack_emitter::PacketNative5AckEmitterSelection>,
        ProviderError,
    > {
        self.authenticate_native5_source_codec()?;
        self.session.original_native5_ack_emitter_selection()
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

    /// Borrows the actual settled original frame history without copying it.
    ///
    /// # Errors
    /// Refuses a foreign actor, revoked/foreign codec, mutable loss callback,
    /// unresolved exchange or conflicting literal-bank borrow. It grants no
    /// source token or semantic permission; the caller brackets journal effects.
    pub fn original_native5_frame_history(
        &self,
    ) -> Result<crate::connection::OriginalNative5FrameHistory<'_>, ProviderError> {
        self.protocol_owner.ensure_current()?;
        if let Some(assigned) = &self.original_ack_admit {
            assigned.validate_owned_snapshot()?;
        }
        self.session.original_native5_frame_history()
    }

    /// Counts actual full protocol and supervisor metadata without owner copies.
    ///
    /// # Errors
    /// Refuses a foreign witness, active callback, changed original registration
    /// or bounded traversal/extent exhaustion. Facts grant no source permission.
    pub fn original_owned11_metadata_facts_with_supervisor(
        &self,
        witness: &crate::connection::OriginalProtocolSupervisor,
    ) -> Result<crate::protocol_snapshot::RetainedProtocolMetadataFacts, ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.session
            .authenticate_original_protocol_supervisor(witness)?;
        let mut facts = None;
        witness.with_original_state(&mut |view| {
            let mut observer = crate::retained_metadata::MetadataObserver::new();
            self.observe_owned11_metadata(&mut observer)?;
            witness.observe_original_header(&mut observer)?;
            view.observe_owned11_metadata(&mut observer)?;
            facts = Some(observer.finish());
            Ok(())
        })?;
        self.session
            .authenticate_original_protocol_supervisor(witness)?;
        facts.ok_or(ProviderError::Correlation(
            "original supervisor facts absent",
        ))
    }

    /// Counts a known retention supervisor directly beside this actual controller.
    ///
    /// The SDK-owned concrete family supplies the incident bank. This observer
    /// invokes no erased supervisor callback, serializer, formatting or I/O.
    /// It counts the owner handle's shared edge and, when supplied, the existing
    /// protocol witness's independent actor and supervisor edges. Enclosing
    /// handle headers remain part of the caller's owning row.
    ///
    /// # Errors
    /// Refuses another actor, supervisor or codec, mutable loss callbacks,
    /// active or incomplete incident callbacks, conflicting borrows or checked
    /// metadata traversal exhaustion. Facts provide no allocation permission.
    pub fn original_owned11_metadata_facts_with_retained_supervisor(
        &self,
        owner: &crate::connection::OriginalRetainedSupervisor,
        witness: Option<&crate::connection::OriginalProtocolSupervisor>,
    ) -> Result<crate::protocol_snapshot::RetainedProtocolMetadataFacts, ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.session
            .authenticate_original_retained_supervisor(owner)?;
        if let Some(witness) = witness {
            self.session
                .authenticate_original_protocol_supervisor(witness)?;
        }
        let mut observer = crate::retained_metadata::MetadataObserver::new();
        self.observe_owned11_metadata(&mut observer)?;
        owner.observe_retained_metadata(&mut observer)?;
        if let Some(witness) = witness {
            witness.observe_original_header(&mut observer)?;
            witness.observe_original_actor(&mut observer)?;
        }
        self.session
            .authenticate_original_retained_supervisor(owner)?;
        Ok(observer.finish())
    }

    /// Retains the actual original supervisor witness beside its owning controller.
    ///
    /// # Errors
    /// Refuses a foreign actor, changed codec/registration, mutable response-loss
    /// callback or a supervisor without a supported actual retained-state loan.
    pub fn retain_original_protocol_supervisor(
        &self,
    ) -> Result<crate::connection::OriginalProtocolSupervisor, ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.session.retain_original_protocol_supervisor()
    }

    /// Captures complete protocol data while holding the same supervisor bank loan.
    ///
    /// The source retains the witness and precharged reservation. A successful
    /// data capture still grants no Core ticket, semantic Capture or fresh world.
    ///
    /// # Errors
    /// Refuses a different witness, unsupported/active supervisor, incomplete
    /// protocol state or insufficient actual snapshot/metadata bank capacity.
    pub fn capture_original_protocol_state_with_supervisor(
        &mut self,
        reservation: &mut crate::protocol_snapshot::ProtocolSnapshotReservation,
        cut: crate::protocol_snapshot::ProtocolCaptureCut,
        witness: &crate::connection::OriginalProtocolSupervisor,
    ) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.session
            .authenticate_original_protocol_supervisor(witness)?;
        witness.with_original_state(&mut |view| {
            self.capture_original_protocol_state_inner(reservation, cut, Some((witness, &view)))
        })
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
        self.ensure_no_pending_original_complete_restore()?;
        self.capture_original_protocol_state_inner(reservation, cut, None)
    }

    fn capture_original_protocol_state_inner(
        &mut self,
        reservation: &mut crate::protocol_snapshot::ProtocolSnapshotReservation,
        cut: crate::protocol_snapshot::ProtocolCaptureCut,
        supervisor: Option<(
            &crate::connection::OriginalProtocolSupervisor,
            &crate::connection::OriginalSupervisorProtocolView<'_>,
        )>,
    ) -> Result<(), ProviderError> {
        if self.original_installed_restoration_observation.is_some()
            || self
                .original_installed_restoration_upload
                .iter()
                .any(Option::is_some)
            || self
                .original_installed_restoration_activation
                .iter()
                .any(Option::is_some)
            || self.original_complete_restore_prepare.is_some()
            || self.original_complete_restore_commit.is_some()
        {
            return Err(ProviderError::Correlation(
                "restore transfer retained owner requires extended complete host class",
            ));
        }
        if reservation.uses_owned11_encoding() && supervisor.is_none() {
            return Err(ProviderError::Correlation(
                "complete protocol supervisor loan absent",
            ));
        }
        if self.fenced {
            return Err(ProviderError::Correlation("captured controller fenced"));
        }
        if (self.original_ack_admit.is_some() || self.original_complete_restore.is_some())
            && !reservation.uses_owned11_encoding()
        {
            return Err(ProviderError::Correlation(
                "assigned Admit complete protocol edition not selected",
            ));
        }
        if reservation.uses_owned11_encoding()
            && let Some(assigned) = &self.original_ack_admit
        {
            assigned.validate_owned_snapshot()?;
        }

        if let Some(restore) = &self.original_complete_restore {
            restore.validate_owned_snapshot()?;
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
        if reservation.uses_owned11_encoding() {
            self.session.retain_owned_hello(reservation)?;
            let (witness, supervisor) = supervisor.ok_or(ProviderError::Correlation(
                "complete supervisor loan absent",
            ))?;
            reservation.record_owned_metadata(|observer| {
                self.observe_owned11_metadata(observer)?;
                witness.observe_original_header(observer)?;
                supervisor.observe_owned11_metadata(observer)
            })?;
            reservation.retain_original_assigned_cut(
                self.original_ack_admit
                    .as_ref()
                    .map(assigned_admit::AssignedOriginalCanonicalAckAdmit::original_cut),
            );
            reservation.retain_original_restore_cut(
                self.original_complete_restore
                    .as_ref()
                    .map(assigned_restore::AssignedOriginalCompleteRestore::original_cut),
            );
            let data = self.complete_owned11_protocol_data(supervisor)?;
            reservation.encode_owned11(&data)?;
            return self.session.retain_frozen_protocol_frames(reservation);
        }
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
        if let Some(assigned) = &self.original_ack_admit {
            if reservation
                .as_ref()
                .is_none_or(|bank| !bank.uses_owned11_encoding())
            {
                return Err(ProviderError::Correlation(
                    "assigned Admit complete protocol edition not selected",
                ));
            }
            assigned.validate_owned_snapshot()?;
        }
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

    /// Installs the source-selected canonical ACK and confirmation grammar once.
    ///
    /// The extra definition and genuine current negotiation are checked before
    /// moving the original bank. A portable selection never creates this owner,
    /// a native peer read limit, source ticket or restoration authority.
    ///
    /// # Errors
    /// Refuses foreign routes/actors, used custody or callbacks, missing source
    /// definitions/features, changed policies or already installed original bank.
    pub fn install_native5_source_ack_emitter_codec(
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
                "canonical ACK codec requires original unused source controller",
            ));
        }
        self.session
            .install_native5_source_ack_emitter_codec(bank, selection, coordinator, profile)
    }

    /// Returns the selected metadata extent of the same installed source codec.
    ///
    /// This guarded data read grants no allocation identity or native permission.
    ///
    /// # Errors
    /// Refuses a foreign process/thread, revoked registration, changed source
    /// codec or an actor without the original sealed source installation.
    pub fn original_native5_codec_metadata_extent(
        &self,
    ) -> Result<Option<crate::connection::CanonicalAckCodecMetadataExtent>, ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.session.original_native5_codec_metadata_extent()
    }

    /// Installs a source-selected finite codec metadata edition once.
    ///
    /// Complete immutable source fields are retained and counted against the
    /// closed selected extent before transferring the supplied literal bank.
    /// Actual allocation and whole snapshot credits remain independent.
    ///
    /// # Errors
    /// Refuses wrong or used actors, missing schemas/negotiation, replaced
    /// policies, used banks or a complete codec view exceeding the selection.
    pub fn install_native5_source_ack_emitter_codec_with_metadata_extent(
        &mut self,
        bank: &mut Option<crate::transport::original_frames::OriginalFrameReservation>,
        selection: crate::reference_packet::control::PacketControlSelection,
        coordinator: crate::reference_service::InstalledContent,
        profile: crate::reference_packet::service::PacketNative5CaptureProfile,
        metadata_extent: crate::connection::CanonicalAckCodecMetadataExtent,
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
                "canonical ACK codec requires original unused source controller",
            ));
        }
        self.session
            .install_native5_source_ack_emitter_codec_with_metadata_extent(
                bank,
                selection,
                coordinator,
                profile,
                metadata_extent,
            )
    }

    /// Installs the independently selected complete-restore schema on an unused source controller.
    ///
    /// # Errors
    /// Refuses changed routes, used banks, absent complete schemas/negotiation or
    /// excessive immutable metadata. This installs grammar and grants no restore right.
    pub fn install_native5_source_complete_restore_codec_with_metadata_extent(
        &mut self,
        bank: &mut Option<crate::transport::original_frames::OriginalFrameReservation>,
        selection: crate::reference_packet::control::PacketControlSelection,
        coordinator: crate::reference_service::InstalledContent,
        profile: crate::reference_packet::service::PacketNative5CaptureProfile,
        metadata_extent: crate::connection::CanonicalAckCodecMetadataExtent,
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
                "canonical ACK codec requires original unused source controller",
            ));
        }
        self.session
            .install_native5_source_complete_restore_codec_with_metadata_extent(
                bank,
                selection,
                coordinator,
                profile,
                metadata_extent,
            )
    }

    /// Installs the separately source-selected twelve transfer codec on an unused controller.
    ///
    /// # Errors
    /// Refuses changed source declarations, missing full phase schemas or live
    /// negotiation, occupied original banks, another role or encoded credit.
    pub fn install_native5_source_complete_restore_transfer_codec_with_metadata_extent(
        &mut self,
        bank: &mut Option<crate::transport::original_frames::OriginalFrameReservation>,
        selection: crate::reference_packet::control::PacketControlSelection,
        coordinator: crate::reference_service::InstalledContent,
        profile: crate::reference_packet::service::PacketNative5CaptureProfile,
        metadata_extent: crate::connection::CanonicalAckCodecMetadataExtent,
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
                "canonical ACK codec requires original unused source controller",
            ));
        }
        self.session
            .install_native5_source_complete_restore_transfer_codec_with_metadata_extent(
                bank,
                selection,
                coordinator,
                profile,
                metadata_extent,
            )
    }

    /// Installs the source-selected original canonical restoration uploader codec.
    ///
    /// # Errors
    /// Refuses used banks, wrong source declarations, role, negotiation or finite codec credit.
    pub fn install_native5_source_restore_input_emitter_codec_with_metadata_extent(
        &mut self,
        bank: &mut Option<crate::transport::original_frames::OriginalFrameReservation>,
        selection: crate::reference_packet::control::PacketControlSelection,
        coordinator: crate::reference_service::InstalledContent,
        profile: crate::reference_packet::service::PacketNative5CaptureProfile,
        metadata_extent: crate::connection::CanonicalAckCodecMetadataExtent,
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
                "canonical ACK codec requires original unused source controller",
            ));
        }
        self.session
            .install_native5_source_restore_input_emitter_codec_with_metadata_extent(
                bank,
                selection,
                coordinator,
                profile,
                metadata_extent,
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
            original_ack_admit: None,
            original_complete_restore: None,
            original_complete_restore_prepare: None,
            original_complete_restore_commit: None,
            installed_complete_restore: None,
            original_installed_restoration_activation: [None, None],
            original_installed_restoration_observation: None,
            original_installed_restoration_upload: [None, None],
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
                original_ack_admit: None,
                original_complete_restore: None,
                original_complete_restore_prepare: None,
                original_complete_restore_commit: None,
                installed_complete_restore: None,
                original_installed_restoration_activation: [None, None],
                original_installed_restoration_observation: None,
                original_installed_restoration_upload: [None, None],
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
        self.ensure_no_pending_original_ack_admit()?;
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
        self.ensure_no_pending_original_ack_admit()?;
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

impl CnpController {
    /// Retains an archive-only data mapping to this same actual fresh controller.
    ///
    /// # Errors
    /// Refuses an occupied slot, partial historical classes, changed native data,
    /// unresolved current calls, stale target actors or reused scope/nonce. It
    /// grants no native restoration permission and requires no old source owner.
    pub fn prepare_archived_protocol_mapping_into(
        &mut self,
        host: &crate::protocol_snapshot::owned11::outer::SealedHistoricalControllerState,
        native: &crate::protocol_snapshot::owned11::native::outer::SealedHistoricalNativeState,
        archive_protocol: &ContentRef,
        native_protocol: &ContentRef,
        nonce: [u8; 32],
        completed: &mut Option<crate::protocol_snapshot::PreparedArchivedProtocolMapping>,
    ) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        if completed.is_some() {
            return Err(ProviderError::Conflict(
                "archived mapping result slot occupied",
            ));
        }
        if let Some(assigned) = &self.original_ack_admit {
            assigned.validate_owned_snapshot()?;
        }
        self.ensure_no_pending_original_complete_restore()?;
        self.session.begin_original_ack_admit(self.budget)?;
        let input = crate::protocol_snapshot::ArchivedProtocolMappingInput {
            host,
            native,
            archive_protocol,
            native_protocol,
            nonce,
        };
        let mapping = self
            .session
            .prepare_archived_protocol_mapping(input, &self.protocol_owner)?;
        *completed = Some(mapping);
        self.authenticate_archived_protocol_mapping(
            completed
                .as_ref()
                .ok_or(ProviderError::Correlation("archived mapping result absent"))?,
        )
    }

    /// Authenticates the same live target without installing historical data.
    ///
    /// # Errors
    /// Refuses changed actor, registration, sealed codec or original target cut.
    pub fn authenticate_archived_protocol_mapping(
        &self,
        mapping: &crate::protocol_snapshot::PreparedArchivedProtocolMapping,
    ) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.session
            .authenticate_archived_protocol_mapping(mapping, &self.protocol_owner)
    }
}

impl CnpController {
    /// Returns the actual immutable selected restoration mechanism of this controller.
    ///
    /// # Errors
    /// Refuses foreign origin, revoked registration or a replaced/unselected codec.
    pub fn original_native5_complete_restore_selection(&self) -> Result<Option<crate::reference_packet::service::complete_restore::PacketNative5CompleteRestoreSelection>, ProviderError>{
        self.authenticate_native5_source_codec()?;
        self.session.original_native5_complete_restore_selection()
    }
}

mod restoration_retained;

mod complete_installation;
pub use complete_installation::InstalledArchivedProtocolState;

impl CnpController {
    /// Observes the actual installed closed uploader selection without granting receive rights.
    ///
    /// # Errors
    /// Refuses a foreign origin, absent codec or revoked original negotiation.
    pub fn original_native5_restore_input_emitter_selection(&self) -> Result<Option<crate::reference_packet::service::complete_restore::PacketNative5RestoreInputEmitterSelection>, ProviderError>{
        self.authenticate_native5_source_codec()?;
        self.session
            .original_native5_restore_input_emitter_selection()
    }
}

impl CnpController {
    /// Reports fixed SDK observation headers before an owning live-host walk.
    ///
    /// This names explicit observer/result/borrow headers, not compiler call
    /// frames, recursion, allocator overhead or physical stack measurement.
    pub const fn original_live_host_metadata_counter_scratch_data() -> usize {
        std::mem::size_of::<crate::retained_metadata::MetadataObserver<'static>>()
            + std::mem::size_of::<crate::protocol_snapshot::RetainedProtocolMetadataFacts>()
            + crate::connection::OriginalRetainedSupervisor::metadata_counter_scratch_data()
            + std::mem::size_of::<crate::transport::OriginalFrameReaderFacts>()
            // Count Connection, reader and separately retained Session Hello loans.
            + 3 * std::mem::size_of::<
                std::cell::Ref<
                    'static,
                    crate::transport::original_frames::OriginalFrameReservation,
                >,
            >()
    }

    /// Observes actual live host protocol owners with a known direct supervisor.
    ///
    /// Adds the actual reader, literal banks, Hello backing, deadline and every
    /// shared edge to the existing tuple metadata. Each retained view is charged
    /// conservatively; this provides no alias discount. Enclosing inline owner
    /// headers and kernel resources remain separate caller terms. No erased
    /// callback, formatting, serializer, allocation or I/O runs in this walk.
    ///
    /// # Errors
    /// Refuses a foreign/revoked actor, wrong known supervisor, mutable callbacks,
    /// unsupported restoration/native owner roots, conflicting loans or checked
    /// metadata traversal exhaustion. Facts grant no Source budget or authority.
    pub fn original_live_host_metadata_facts_with_retained_supervisor(
        &self,
        owner: &crate::connection::OriginalRetainedSupervisor,
        witness: Option<&crate::connection::OriginalProtocolSupervisor>,
    ) -> Result<crate::protocol_snapshot::RetainedProtocolMetadataFacts, ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.session
            .authenticate_original_retained_supervisor(owner)?;
        if let Some(witness) = witness {
            self.session
                .authenticate_original_protocol_supervisor(witness)?;
        }
        let mut observer = crate::retained_metadata::MetadataObserver::new();
        self.observe_owned11_metadata(&mut observer)?;
        self.session
            .observe_original_host_live_metadata_extras(&mut observer)?;
        owner.observe_retained_metadata(&mut observer)?;
        if let Some(witness) = witness {
            witness.observe_original_header(&mut observer)?;
            witness.observe_original_actor(&mut observer)?;
        }
        self.session
            .authenticate_original_retained_supervisor(owner)?;
        Ok(observer.finish())
    }
}

impl CnpController {
    pub(in crate::client) fn observe_original_host_startup_metadata(
        &self,
        schemas: &std::rc::Rc<super::host_startup::hello::InitialHelloSchema>,
        supervisor: &crate::connection::OriginalRetainedSupervisor,
        observer: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), ProviderError> {
        let Self {
            session,
            custody,
            route,
            budget: _,
            fenced,
            protocol_owner,
            original_ack_admit,
            original_complete_restore,
            original_complete_restore_prepare,
            original_complete_restore_commit,
            installed_complete_restore,
            original_installed_restoration_activation,
            original_installed_restoration_upload,
            original_installed_restoration_observation,
        } = self;
        protocol_owner.ensure_current()?;
        if *fenced
            || original_ack_admit.is_some()
            || original_installed_restoration_observation.is_some()
            || original_complete_restore.is_some()
            || original_complete_restore_prepare.is_some()
            || original_complete_restore_commit.is_some()
            || installed_complete_restore.is_some()
            || original_installed_restoration_upload
                .iter()
                .any(Option::is_some)
            || original_installed_restoration_activation
                .iter()
                .any(Option::is_some)
            || custody.originals().next().is_some()
        {
            return Err(ProviderError::Correlation(
                "original host startup controller already used",
            ));
        }
        session.observe_original_host_startup_metadata(schemas, supervisor, observer)?;
        custody.observe_owned_metadata(observer)?;
        observer.observe(&route.node)?;
        observer.observe(&route.execution_owner)?;
        observer.shared_value(protocol_owner.as_ref())
    }
}

#[path = "controller/host_initial_lifecycle.rs"]
mod host_initial_lifecycle;
pub use host_initial_lifecycle::OriginalPacketHostInitialResponse;

impl CnpController {
    /// Counts the actual concrete controller stream without opening any handle.
    ///
    /// This raw-origin data walk remains valid for expired or fenced controllers;
    /// it does not authenticate a live connection or installed resource action.
    ///
    /// # Errors
    /// Refuses a foreign creator or actual connection origin.
    pub fn retained_descriptor_count_data(&self) -> Result<usize, ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.session.original_host_retained_descriptor_count_data()
    }
}

impl CnpController {
    /// Hashes the same completed original Observe's actual retained sent literal.
    ///
    /// No Envelope is serialized or cloned. The same actual controller cache,
    /// frame-bank slot and complete canonical correspondence are required. This
    /// readonly digest is correlation data, never allocation or Capture authority.
    ///
    /// # Errors
    /// Refuses foreign/current actor or codec, absent/uncompleted original,
    /// changed complete request, partial/repeated literal or expired registration.
    pub fn original_capture_allocation_observe_hash_data(
        &self,
        original: &Envelope,
    ) -> Result<[u8; 32], ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        if self.fenced {
            return Err(ProviderError::Correlation("Observe controller is fenced"));
        }
        let id = original
            .request_id
            .0
            .as_ref()
            .ok_or(ProviderError::Correlation("Observe original id absent"))?;
        let retained = self
            .original(id)
            .ok_or(ProviderError::Correlation("Observe original cache absent"))?;
        if retained.request != *original || retained.response.is_none() {
            return Err(ProviderError::Correlation("Observe original cache changed"));
        }
        self.session
            .original_capture_allocation_observe_hash_data(&retained.request)
    }
}

impl CnpController {
    /// Returns the actual first proof request sequence for one full raw reference.
    ///
    /// This readonly data walk uses the same provider namespace and exact full
    /// ContentRef fields. Native and Source semantic/currentness guards remain
    /// independent; matching references grant no authority.
    ///
    /// # Errors
    /// Refuses changed actor/codec, missing or repeated original proof begin,
    /// incomplete responses or a different full content reference.
    pub fn original_capture_allocation_first_proof_sequence_data(
        &self,
        reference: &ContentRef,
    ) -> Result<U64, ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        if self.fenced {
            return Err(ProviderError::Correlation(
                "allocation proof controller is fenced",
            ));
        }
        let mut requests = self.originals_by_origin(RequestOrigin::Provider).filter(|original| {
            if original.request.method != Method::BlobBegin { return false; }
            original.request.body.get("content").is_some_and(|value| {
                crate::reference_packet::service::capture_allocation::original_capture_allocation_reference_matches_data(value, reference)
            })
        });
        let original = requests.next().ok_or(ProviderError::Correlation(
            "original allocation proof absent",
        ))?;
        if original.response.is_none() || requests.next().is_some() {
            return Err(ProviderError::Correlation(
                "original allocation proof repeats or is incomplete",
            ));
        }
        self.authority().ensure_live()?;
        self.protocol_owner.ensure_current()?;
        Ok(original.request.sequence)
    }
}

impl CnpController {
    /// Borrows and fully hashes the same retained allocation-report content.
    ///
    /// This purpose-scoped loan compares the complete original ContentRef and
    /// normative CNP blob digest without another owned HashRef or report DOM.
    /// The Source independently authenticates selection, receipt and currentness.
    ///
    /// # Errors
    /// Refuses changed/fenced actor or codec, absent/full-reference mismatch,
    /// wrong report media/length, changed bytes or expired registration.
    pub fn original_capture_allocation_body_data(
        &self,
        reference: &ContentRef,
    ) -> Result<&[u8], ProviderError> {
        use crate::reference_packet::service::capture_allocation::{
            MAXIMUM_NATIVE_CAPTURE_ALLOCATION_REPORT_BYTES, PACKET_NATIVE_CAPTURE_ALLOCATION_MEDIA,
        };
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        if self.fenced
            || reference.media_type != PACKET_NATIVE_CAPTURE_ALLOCATION_MEDIA
            || reference.length.get() == 0
            || reference.length.get() > MAXIMUM_NATIVE_CAPTURE_ALLOCATION_REPORT_BYTES as u64
        {
            return Err(ProviderError::Correlation(
                "original allocation content scope",
            ));
        }
        let body = self
            .custody
            .content()
            .original_capture_allocation_body_data(reference)?;
        self.authority().ensure_live()?;
        self.protocol_owner.ensure_current()?;
        Ok(body)
    }
}

#[path = "controller/archived_restoration_mapping.rs"]
mod archived_restoration_mapping;
