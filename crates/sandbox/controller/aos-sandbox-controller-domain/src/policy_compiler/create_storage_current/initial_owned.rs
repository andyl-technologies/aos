//! Owns the genuine native INITIAL caller without releasing failed originals.
//!
//! The whole classified Prelude supplies the same handler and exclusive Flight.
//! Atomic transfer moves the existing producer and retained stream beside that
//! handler into native custody. This author-input entry ends at genuine issuer
//! pins, signed inputs, Ownership trust, Source, Bundle, Cache and Controller. Later
//! purposes and terminal Root6 remain required.
//! The installed production entry stays unchanged until that whole cut exists.

mod bundle_cache;
mod continuation;
mod controller;
mod frame;
mod geometry;
mod use_authorized;
mod use_prospective_geometry;
mod use_reserved;
mod use_admitted;
mod signed_bound;
mod signed_geometry;

pub(crate) use controller::RootOwnedControllerPreparedStageV1;

use std::error::Error as StdError;
use std::os::unix::net::UnixStream;

use aos_sandbox_broker::receiving::RootObservationErrorV1;
use aos_sandbox_model::ResourceVector;
use aos_sandbox_policy::native::{
    RootInitialBundleOwnershipErrorV1, RootInitialCacheProofErrorV1,
    RootInitialControllerReadonlyErrorV1, RootInitialOpenErrorV1, RootInitialPinsBorrowV1,
    RootInitialPinsErrorV1, RootInitialPolicyInputsErrorV1, RootInitialSourceExchangeErrorV1,
    RootInitialSourceQueryErrorV1, RootInitialTrustErrorV1, RootInitialUseAuthorizedErrorV1,
    RootOwnedCurrentOriginalV1,
};
use aos_sandbox_policy::root_policy_inputs_data::{
    RootCurrentPolicyInputDataV1, RootSignedProjectSourcesDataV1,
};
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    HistoryErrorV1,
    transport::{OPEN_BYTES, OpenQueryV1},
};

use super::RootCreateStorageCurrentErrorV1 as Error;
use crate::normal_root::{
    NormalRootStartupErrorV1, ProductionNormalRootStartupV1, RootOwnedCurrentStageV1 as Stage,
    RootPolicyAcceptedFlightV1,
};
use crate::policy_compiler::root_policy_prelude::{
    RootPolicyDispositionGuardV1, RootPolicyPreludeNativeOriginalV1, RootPolicyPreludeOriginalV1,
    RootPolicyPurposeV1,
};
use aos_sandbox_broker::bounded_stream_io::{DeadlineStreamDirectionV1, FixedDeadlineStreamIoV1};

/// Retains the owning result returned at an actual upper/native caller frontier.
#[derive(Debug, thiserror::Error)]
pub(crate) enum RootInitialCurrentActionErrorV1 {
    /// Retains the same actual upper lock or startup refusal.
    #[error(transparent)]
    Upper(NormalRootStartupErrorV1),
    /// Retains a returned native Initial/financial/arm error.
    #[error(transparent)]
    Native(RootObservationErrorV1),
    /// Retains the actual native Open or Ready operation result.
    #[error(transparent)]
    Operation(RootInitialOpenErrorV1),
    /// Retains the actual issuer operation result.
    #[error(transparent)]
    Pins(RootInitialPinsErrorV1),
    /// Retains the actual signed-input verification or completed-prefix error.
    #[error(transparent)]
    Inputs(RootInitialPolicyInputsErrorV1),
    /// Retains actual Ownership trust capture, typed decoding or completion refusal.
    #[error(transparent)]
    Trust(RootInitialTrustErrorV1),
    /// Retains the actual Initial Source query or correlation refusal.
    #[error(transparent)]
    Query(RootInitialSourceQueryErrorV1),
    /// Retains the actual Initial Source exchange, authentication or post refusal.
    #[error(transparent)]
    Exchange(RootInitialSourceExchangeErrorV1),
    /// Retains actual same-frame typed Ownership or independent post refusal.
    #[error(transparent)]
    Bundle(RootInitialBundleOwnershipErrorV1),
    /// Retains actual Initial Cache framing, signer, proof or post refusal.
    #[error(transparent)]
    Cache(RootInitialCacheProofErrorV1),
    /// Retains the genuine Controller reader/model/compilation or post refusal.
    #[error(transparent)]
    Controller(RootInitialControllerReadonlyErrorV1),
    /// Retains actual Root Use admission/body/append/send refusal.
    #[error(transparent)]
    UseAuthorized(RootInitialUseAuthorizedErrorV1),
    /// Retains actual Reserved frame, financial, replay or independent post refusal.
    #[error(transparent)]
    Reserved(aos_sandbox_policy::native::RootUseReservedErrorV1),
    /// Retains the actual local Root3 append, readback, framing or send refusal.
    #[error(transparent)]
    UseAdmitted(aos_sandbox_policy::native::RootUseAdmittedErrorV1),
    /// Retains the actual native Signed receiving, Controller, append or send cause.
    #[error(transparent)]
    Signed(aos_sandbox_policy::native::RootSignedBoundErrorV1),
    /// Retains the exact actual indexed Signed input or parser return.
    #[error(transparent)]
    SignedInput(aos_sandbox_policy::native::RootSignedInputErrorV1),
}

type Action = RootInitialCurrentActionErrorV1;
const ACTION_COUNT: usize = 162;
type Actions = [Option<Result<(), Action>>; ACTION_COUNT];

#[derive(Clone, Copy)]
enum First {
    PreludeBefore,
    Peer,
    Remainder,
    Decode,
    PreludeAfter,
    Action(usize),
    Native,
    UseProposal,
    FrameBefore,
    FrameSubject,
    FrameAfter,
    FrameResult,
}

/// Retains the whole native INITIAL and every reached upper refusal.
///
/// This private author input has no positive finalizer or bundle extractor.
/// Its first field prevents unfinished custody from unwinding. Genuine pins
/// can lend only the same native owner; they cannot synthesize a terminal pair.
pub(crate) struct RootOwnedInitialCurrentAttemptV1<'flight, 'listener, 'startup> {
    disposition: RootPolicyDispositionGuardV1,
    original: Option<UnixStream>,
    flight: &'flight mut RootPolicyAcceptedFlightV1<'listener, 'startup>,
    prelude: RootPolicyPreludeNativeOriginalV1,
    peer: Option<Result<(), NormalRootStartupErrorV1>>,
    open_bytes: [u8; OPEN_BYTES],
    remainder_io: FixedDeadlineStreamIoV1<{ OPEN_BYTES - 32 }>,
    remainder_bytes: [u8; OPEN_BYTES - 32],
    remainder_read: Option<Result<(), Error>>,
    decoded: Option<Result<OpenQueryV1, HistoryErrorV1>>,
    native: Option<RootOwnedCurrentOriginalV1<'startup>>,
    semantic: [Option<Result<ResourceVector, crate::journal::JournalError>>; 2],
    actions: Actions,
    use_proposal:
        Option<Result<ResourceVector, use_prospective_geometry::RootUseProspectiveGeometryErrorV1>>,
    frame: frame::FrameTrace,
    first: Option<First>,
    completion: Option<Result<(), Error>>,
    negative: Option<Result<(), NormalRootStartupErrorV1>>,
    reentry: bool,
}

impl<'flight, 'listener, 'startup> RootOwnedInitialCurrentAttemptV1<'flight, 'listener, 'startup> {
    pub(in crate::policy_compiler) fn from_prelude_v1(
        prelude: RootPolicyPreludeOriginalV1<'flight, 'listener, 'startup>,
    ) -> Self {
        if prelude.purpose_v1() != Some(RootPolicyPurposeV1::CreateStorage) {
            std::process::abort();
        }
        let RootPolicyPreludeOriginalV1 {
            disposition,
            original,
            flight,
            native,
            ..
        } = prelude;
        Self {
            disposition,
            original: Some(original),
            flight,
            prelude: native,
            peer: None,
            open_bytes: [0; OPEN_BYTES],
            remainder_io: Default::default(),
            remainder_bytes: [0; OPEN_BYTES - 32],
            remainder_read: None,
            decoded: None,
            native: None,
            semantic: [None, None],
            actions: [const { None }; ACTION_COUNT],
            use_proposal: None,
            frame: frame::FrameTrace::new(),
            first: None,
            completion: None,
            negative: None,
            reentry: false,
        }
    }

    /// Runs the genuine INITIAL prefix through the actual Controller reader.
    ///
    /// # Errors
    /// Retains every actual failed owner and returned cause before the owed
    /// posts. A positive result retains the genuine completed Controller model,
    /// never a complete Current exchange or terminal Root6 handoff.
    pub(crate) fn receive_initial_once_v1(
        &mut self,
        data: &RootCurrentPolicyInputDataV1<'_>,
        source_signer_uid: u32,
        source_socket_gid: u32,
        private: aos_sandbox_policy::storage_create_use_data::StorageCreateUseSecurityShapeDataV1,
    ) -> Result<(), Error> {
        if self.completion.is_some() {
            self.reentry = true;
            return Err(Error::Original);
        }
        self.disposition.entered = true;
        self.completion = Some(self.receive_initial_inner_v1(
            data,
            source_signer_uid,
            source_socket_gid,
            private,
        ));
        match &self.completion {
            Some(Ok(())) => Ok(()),
            _ => Err(Error::Open),
        }
    }

    fn receive_initial_inner_v1(
        &mut self,
        data: &RootCurrentPolicyInputDataV1<'_>,
        source_signer_uid: u32,
        source_socket_gid: u32,
        private: aos_sandbox_policy::storage_create_use_data::StorageCreateUseSecurityShapeDataV1,
    ) -> Result<(), Error> {
        self.receive_open_frame_once_v1()?;
        let startup = match self.flight.current_cut_startup() {
            Ok(startup) => startup,
            Err(error) => return self.record_v1(0, Err(Action::Upper(error))),
        };

        // Move the same standard handler first; a failed atomic pair transfer
        // restores it on this owner before exposing the actual returned error.
        let handler = match self.original.take() {
            Some(handler) => handler,
            None => return Err(Error::Original),
        };
        let originals = match self.flight.take_initial_current_originals_v1() {
            Ok(originals) => originals,
            Err(error) => {
                self.original = Some(handler);
                return self.record_v1(1, Err(Action::Upper(error)));
            }
        };
        // This factory is inert and infallible; all three genuine originals
        // are parked together before any stage, observation or fallible quote.
        self.native = Some(RootOwnedCurrentOriginalV1::from_originals_v1(
            originals, handler,
        ));
        self.semantic[0] = Some(crate::journal::cache_native_semantic_supplement_v1());
        self.semantic[1] = Some(crate::journal::cache_native_semantic_supplement_v1());
        self.drive_v1(startup, Stage::Writers, 2)?;
        let open = match &self.decoded {
            Some(Ok(open)) => *open,
            _ => return Err(Error::Open),
        };
        self.receive_open_native_once_v1(startup, open)?;
        self.receive_ready_once_v1(startup)?;
        self.receive_pins_once_v1(startup)?;
        self.receive_policy_inputs_once_v1(startup, data)?;
        self.receive_trust_once_v1(startup)?;
        self.receive_source_query_once_v1(startup)?;
        self.receive_source_exchange_once_v1(startup, source_signer_uid, source_socket_gid)?;
        // Preserve the old passive input-completion check after Source exchange.
        let returned = self
            .native
            .as_ref()
            .ok_or(Error::Original)?
            .require_initial_policy_inputs_complete_v1()
            .map_err(Action::Inputs);
        self.record_v1(40, returned)?;
        self.receive_bundle_ownership_once_v1(startup)?;
        self.receive_cache_proof_once_v1(startup)?;
        self.receive_controller_readonly_once_v1(startup, data)?;
        self.receive_use_authorized_once_v1(startup, private)?;
        self.receive_use_reserved_once_v1(startup, data)?;
        self.receive_use_refresh_and_admitted_once_v1(startup, source_signer_uid, source_socket_gid)?;
        self.receive_signed_once_v1(startup, data)
    }

    fn receive_open_frame_once_v1(&mut self) -> Result<(), Error> {
        let received = self.receive_open_remainder_v1();
        // This is the same original opening post, after peer/decode and before
        // writer growth, including negative peer or partial remainder paths.
        let posted = self.prelude.finish_opening_once_v1();
        if received.is_err() {
            return received;
        }
        if posted.is_err() {
            self.first.get_or_insert(First::PreludeAfter);
            return Err(Error::Open);
        }
        Ok(())
    }

    fn receive_open_remainder_v1(&mut self) -> Result<(), Error> {
        let cutoff = match self.prelude.cutoff_v1() {
            Ok(cutoff) => cutoff,
            Err(_) => {
                self.first.get_or_insert(First::PreludeBefore);
                return Err(Error::Open);
            }
        };
        self.open_bytes[..32].copy_from_slice(self.prelude.prefix_bytes_v1());
        self.peer = Some(self.flight.admit_current_controller_peer_once());
        if !matches!(self.peer, Some(Ok(()))) {
            self.first.get_or_insert(First::Peer);
            return Err(Error::Original);
        }
        let handler = match &mut self.original {
            Some(handler) => handler,
            None => return Err(Error::Original),
        };
        self.remainder_read = Some(
            self.remainder_io
                .run_once(
                    handler,
                    &mut self.remainder_bytes,
                    cutoff,
                    DeadlineStreamDirectionV1::Read,
                )
                .map_err(|_| Error::Open),
        );
        if !matches!(self.remainder_read, Some(Ok(()))) {
            self.first.get_or_insert(First::Remainder);
            return Err(Error::Open);
        }
        self.open_bytes[32..].copy_from_slice(&self.remainder_bytes);
        self.decoded = Some(OpenQueryV1::decode(&self.open_bytes));
        if !matches!(self.decoded, Some(Ok(_))) {
            self.first.get_or_insert(First::Decode);
            return Err(Error::Open);
        }
        Ok(())
    }

    fn drive_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
        stage: Stage,
        slot: usize,
    ) -> Result<(), Error> {
        let supplements = [
            self.semantic[0]
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .copied(),
            self.semantic[1]
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .copied(),
        ];
        let returned = match &mut self.native {
            Some(native) => startup.drive_owned_current_stage_v1(native, stage, supplements),
            None => return Err(Error::Original),
        };
        self.record_v1(slot, returned)
    }

    fn receive_open_native_once_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
        open: OpenQueryV1,
    ) -> Result<(), Error> {
        let body = self.receive_open_native_body_v1(startup, open);
        if let Some(native) = &mut self.native {
            native.finish_initial_open_posts_once_v1();
        }
        self.latch_native_v1();
        body?;
        let returned = self
            .native
            .as_ref()
            .ok_or(Error::Original)?
            .require_initial_open_complete_v1()
            .map_err(Action::Operation);
        self.record_v1(7, returned)
    }

    fn receive_open_native_body_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
        open: OpenQueryV1,
    ) -> Result<(), Error> {
        self.drive_v1(startup, Stage::OpenEntry, 3)?;
        self.drive_v1(startup, Stage::OpenOuter, 4)?;
        let returned = self
            .native
            .as_mut()
            .ok_or(Error::Original)?
            .prepare_initial_open_once_v1(open)
            .map_err(Action::Operation);
        self.record_v1(5, returned)?;
        self.drive_v1(startup, Stage::OpenCrossing, 6)?;
        let returned = self
            .native
            .as_mut()
            .ok_or(Error::Original)?
            .append_initial_open_once_v1()
            .map_err(Action::Operation);
        self.record_v1(7, returned)
    }

    fn receive_ready_once_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
    ) -> Result<(), Error> {
        let body = self.receive_ready_body_v1(startup);
        if let Some(native) = &mut self.native {
            native.observe_initial_ready_names_once_v1();
        }
        self.latch_native_v1();
        let armed = self.drive_v1(startup, Stage::ReadyPost, 15);
        if armed.is_err() {
            if let Some(native) = &mut self.native {
                native.refuse_initial_ready_post_arm_once_v1();
            }
        }
        if let Some(native) = &mut self.native {
            native.observe_initial_ready_post_once_v1();
        }
        self.latch_native_v1();
        body?;
        armed?;
        // This is only a readiness check on the genuine owner. The borrowed
        // bytes never construct a phase, issuer, replacement writer or grant.
        let returned = self
            .native
            .as_ref()
            .ok_or(Error::Original)?
            .initial_ready_bytes_v1()
            .map(|_| ())
            .map_err(Action::Operation);
        self.record_v1(16, returned)
    }

    fn receive_ready_body_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
    ) -> Result<(), Error> {
        let entry = self.drive_v1(startup, Stage::ReadyEntry, 8);
        if entry.is_err() {
            if let Some(native) = &mut self.native {
                native.refuse_initial_ready_entry_once_v1();
            }
            return entry;
        }
        let returned = self
            .native
            .as_mut()
            .ok_or(Error::Original)?
            .send_initial_ready_hello_once_v1()
            .map_err(Action::Operation);
        self.record_v1(9, returned)?;
        {
            let native = self.native.as_mut().ok_or(Error::Original)?;
            let mut frame = match native.borrow_initial_ready_index_v1() {
                Ok(frame) => frame,
                Err(error) => {
                    self.actions[10] = Some(Err(Action::Operation(error)));
                    self.first.get_or_insert(First::Action(10));
                    return Err(Error::Ready);
                }
            };
            frame::receive_frame_v1(startup, &mut frame, &mut self.frame, &mut self.first)?;
        }
        let returned = self
            .native
            .as_mut()
            .ok_or(Error::Original)?
            .decode_initial_ready_index_once_v1()
            .map_err(Action::Operation);
        self.record_v1(11, returned)?;
        self.drive_v1(startup, Stage::ReadyBytes, 12)?;
        self.receive_indexed_ready_once_v1(startup)
    }

    fn receive_indexed_ready_once_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
    ) -> Result<(), Error> {
        macro_rules! indexed_stage {
            (extent, $total:ident) => {
                let $total = match self
                    .native
                    .as_ref()
                    .ok_or(Error::Original)?
                    .initial_ready_extent_v1()
                {
                    Ok(total) => total,
                    Err(error) => return self.record_v1(13, Err(Action::Operation(error))),
                };
            };
            (allocate, $total:ident) => {
                let returned = self
                    .native
                    .as_mut()
                    .ok_or(Error::Original)?
                    .allocate_initial_ready_once_v1()
                    .map_err(Action::Operation);
                self.record_v1(13, returned)?;
            };
            (has_next) => {
                match self
                    .native
                    .as_ref()
                    .ok_or(Error::Original)?
                    .initial_ready_has_next_v1()
                {
                    Ok(next) => next,
                    Err(error) => return self.record_v1(13, Err(Action::Operation(error))),
                }
            };
            (prepare_frame, $frame:ident) => {
                let returned = self
                    .native
                    .as_mut()
                    .ok_or(Error::Original)?
                    .prepare_initial_ready_frame_once_v1()
                    .map_err(Action::Operation);
                self.record_v1(13, returned)?;
            };
            (receive_frame, $frame:ident) => {{
                let native = self.native.as_mut().ok_or(Error::Original)?;
                let mut $frame = match native.borrow_initial_ready_frame_v1() {
                    Ok(frame) => frame,
                    Err(error) => {
                        self.actions[13] = Some(Err(Action::Operation(error)));
                        self.first.get_or_insert(First::Action(13));
                        return Err(Error::Ready);
                    }
                };
                frame::receive_frame_v1(startup, &mut $frame, &mut self.frame, &mut self.first)?;
            }};
            (bind_copy, $frame:ident, $total:ident) => {
                let returned = self
                    .native
                    .as_mut()
                    .ok_or(Error::Original)?
                    .copy_initial_ready_frame_once_v1()
                    .map_err(Action::Operation);
                self.record_v1(13, returned)?;
            };
            (dispose_frame, $frame:ident) => {
                let returned = self
                    .native
                    .as_mut()
                    .ok_or(Error::Original)?
                    .dispose_initial_ready_frame_once_v1()
                    .map_err(Action::Operation);
                self.record_v1(13, returned)?;
            };
            (digest, $total:ident) => {
                let returned = self
                    .native
                    .as_mut()
                    .ok_or(Error::Original)?
                    .digest_initial_ready_once_v1()
                    .map_err(Action::Operation);
                self.record_v1(14, returned)
            };
        }
        aos_sandbox_broker::root_indexed_transfer_receive_v1!(indexed_stage)
    }

    fn receive_pins_once_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
    ) -> Result<(), Error> {
        let body = self.receive_pins_body_v1(startup);
        if let Some(native) = &mut self.native {
            native.observe_initial_pins_native_posts_once_v1();
        }
        self.latch_native_v1();
        let armed = self.drive_v1(startup, Stage::PinsPost, 19);
        if armed.is_err() {
            if let Some(native) = &mut self.native {
                native.refuse_initial_pins_post_arm_once_v1();
            }
        }
        if let Some(native) = &mut self.native {
            native.observe_initial_pins_post_once_v1();
        }
        self.latch_native_v1();
        body?;
        armed?;
        let returned = self
            .native
            .as_ref()
            .ok_or(Error::Original)?
            .require_initial_pins_complete_v1()
            .map_err(Action::Pins);
        self.record_v1(20, returned)
    }

    fn receive_pins_body_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
    ) -> Result<(), Error> {
        let entry = self.drive_v1(startup, Stage::PinsEntry, 17);
        if entry.is_err() {
            if let Some(native) = &mut self.native {
                native.refuse_initial_pins_entry_once_v1();
            }
            return entry;
        }
        let returned = self
            .native
            .as_mut()
            .ok_or(Error::Original)?
            .capture_initial_pins_once_v1()
            .map_err(Action::Pins);
        self.record_v1(18, returned)
    }

    fn receive_policy_inputs_once_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
        data: &RootCurrentPolicyInputDataV1<'_>,
    ) -> Result<(), Error> {
        let body = self.receive_policy_inputs_body_v1(startup, data);
        if let Some(native) = &mut self.native {
            native.observe_initial_policy_inputs_native_posts_once_v1();
        }
        self.latch_native_v1();
        let armed = self.drive_v1(startup, Stage::InputsPost, 23);
        if armed.is_err() {
            if let Some(native) = &mut self.native {
                native.refuse_initial_policy_inputs_post_arm_once_v1();
            }
        }
        if let Some(native) = &mut self.native {
            native.observe_initial_policy_inputs_post_once_v1();
        }
        self.latch_native_v1();
        body?;
        armed?;
        let returned = self
            .native
            .as_ref()
            .ok_or(Error::Original)?
            .require_initial_policy_inputs_complete_v1()
            .map_err(Action::Inputs);
        self.record_v1(24, returned)
    }

    fn receive_policy_inputs_body_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
        data: &RootCurrentPolicyInputDataV1<'_>,
    ) -> Result<(), Error> {
        let entry = self.drive_v1(startup, Stage::InputsEntry, 21);
        if entry.is_err() {
            // Preserve the owning upper/native entry error before closing the
            // unentered native path. Its independent posts remain owed.
            if let Some(native) = &mut self.native {
                native.refuse_initial_policy_inputs_entry_once_v1();
            }
            return entry;
        }
        let returned = self
            .native
            .as_mut()
            .ok_or(Error::Original)?
            .verify_initial_policy_inputs_once_v1(data)
            .map_err(Action::Inputs);
        self.record_v1(22, returned)
    }

    /// Borrows authenticated comparison DATA from the same verified native owner.
    ///
    /// # Errors
    /// Refuses incomplete or failed verification or posts. Returned DATA cannot
    /// construct a native purpose, renew the original clock or release custody.
    pub(crate) fn verified_initial_sources_data_v1(
        &self,
    ) -> Result<&RootSignedProjectSourcesDataV1, RootInitialPolicyInputsErrorV1> {
        if self.reentry || !matches!(self.completion, Some(Ok(()))) {
            return Err(RootInitialPolicyInputsErrorV1::Incomplete);
        }
        self.native
            .as_ref()
            .ok_or(RootInitialPolicyInputsErrorV1::Incomplete)?
            .verified_initial_sources_data_v1()
    }

    fn record_v1(&mut self, slot: usize, returned: Result<(), Action>) -> Result<(), Error> {
        if slot >= self.actions.len() || matches!(self.actions[slot], Some(Err(_))) {
            std::process::abort();
        }
        self.actions[slot] = Some(returned);
        if matches!(self.actions[slot], Some(Err(_))) {
            let owner = if self
                .native
                .as_ref()
                .is_some_and(|native| native.failure_v1().is_some())
            {
                First::Native
            } else {
                First::Action(slot)
            };
            self.first.get_or_insert(owner);
            return Err(Error::Open);
        }
        Ok(())
    }

    fn latch_native_v1(&mut self) {
        if self
            .native
            .as_ref()
            .is_some_and(|native| native.failure_v1().is_some())
        {
            self.first.get_or_insert(First::Native);
        }
    }

    /// Borrows only genuinely completed Initial pins from this same native owner.
    ///
    /// # Errors
    /// Refuses an incomplete or failed invocation. It supplies no terminal Root6
    /// receipt or original extraction; later native purposes must borrow here.
    pub(crate) fn borrow_initial_pins_v1(
        &self,
    ) -> Result<RootInitialPinsBorrowV1<'_, 'startup>, RootInitialPinsErrorV1> {
        if self.reentry || !matches!(self.completion, Some(Ok(()))) {
            return Err(RootInitialPinsErrorV1::Stale);
        }
        let native = self.native.as_ref().ok_or(RootInitialPinsErrorV1::Stale)?;
        native.borrow_initial_pins_v1()
    }

    /// Runs same-socket negative shutdown and the unconditional original Root post.
    ///
    /// # Errors
    /// Retains missing/repeated disposition and the real native shutdown or Root
    /// post cause while all three originals remain in their native owner.
    pub(crate) fn finish_negative_once_v1(&mut self) -> Result<(), NormalRootStartupErrorV1> {
        if self.negative.is_some() || !matches!(self.completion, Some(Err(_))) {
            self.reentry = true;
            return Err(NormalRootStartupErrorV1::Service);
        }
        self.negative = Some(match &mut self.native {
            Some(native) => self.flight.finish_owned_current_negative_once_v1(native),
            None => self.flight.finish_dispatch_once(Err(Box::new(Error::Open))),
        });
        match &self.negative {
            Some(Ok(())) => Ok(()),
            _ => Err(NormalRootStartupErrorV1::Service),
        }
    }

    /// Borrows the first reached cause without reordering independent post debt.
    #[must_use]
    pub(crate) fn failure_v1(&self) -> Option<&(dyn StdError + 'static)> {
        let Some(first) = self.first else {
            return self
                .completion
                .as_ref()?
                .as_ref()
                .err()
                .map(|error| error as _);
        };
        match first {
            First::PreludeBefore => self.prelude.failure_before_v1(),
            First::Peer => self
                .flight
                .failure()
                .or_else(|| self.peer.as_ref()?.as_ref().err().map(|error| error as _)),
            First::Remainder => self.remainder_io.failure().or_else(|| {
                self.remainder_read
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|error| error as _)
            }),
            First::Decode => self
                .decoded
                .as_ref()?
                .as_ref()
                .err()
                .map(|error| error as _),
            First::PreludeAfter => self.prelude.failure_after_v1(),
            First::Action(slot) => self
                .actions
                .get(slot)?
                .as_ref()?
                .as_ref()
                .err()
                .map(|error| error as _),
            First::UseProposal => self
                .use_proposal
                .as_ref()?
                .as_ref()
                .err()
                .map(|error| error as _),
            First::Native => {
                let native = self.native.as_ref()?;
                match native.deferred_semantic_quote_role_v1() {
                    Some(role) => self
                        .semantic
                        .get(role)?
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|error| error as _),
                    None => native.failure_v1(),
                }
            }
            First::FrameBefore => self
                .frame
                .before
                .as_ref()?
                .as_ref()
                .err()
                .map(|error| error as _),
            First::FrameSubject => self
                .frame
                .subject
                .as_ref()?
                .as_ref()
                .err()
                .map(|error| error as _),
            First::FrameAfter => self
                .frame
                .after
                .as_ref()?
                .as_ref()
                .err()
                .map(|error| error as _),
            First::FrameResult => self
                .frame
                .result
                .as_ref()?
                .as_ref()
                .err()
                .map(|error| error as _),
        }
    }
}
