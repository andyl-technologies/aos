//! Owns the independent once observation after a physically published World.
//!
//! The receive slot is spent before the reader or artifact parser can fail.
//! Its raw original, typed partials and terminal stay in the same boot. A
//! released lifecycle witness supplies chronology only: the separate Source
//! MAC and recounted observation row precede every model/proof allocation.

use super::released::OriginalRestorationReleased;
use super::*;
use crate::connection::{ExchangeRecord, ReceivedBody};
use crate::reference_packet::control::ReleasedWorldControlInputsData;
use crate::reference_packet::service::complete_restore::restoration_observe::*;

#[path = "observation_suffix.rs"]
mod restored_suffix;
pub(crate) use restored_suffix::{
    OriginalRestoredSuffixPostObservation,
    original_restored_suffix_post_observation_counter_scratch_data,
};

pub(crate) struct NativeRestorationObservationAttempt {
    creator: u32,
    thread: ThreadId,
    original: Option<Envelope>,
    body: Option<crate::bodies::ObserveRequest>,
    artifact: Option<PacketRestorationObservationArtifact>,
    context: Option<PacketRestorationObservationContext>,
    terminal: Option<Envelope>,
    received: bool,
    verified: bool,
    dispatched: bool,
    published: bool,
}

/// Holds one spent read slot and the same positively authenticated release.
///
/// The boot owns the attempt, while only this short-lived token owns a boot
/// handle. Neither the attempt nor its typed data creates a strong boot cycle.
pub(crate) struct OriginalRestorationObservationRead {
    released: OriginalRestorationReleased,
    attempt: Rc<RefCell<NativeRestorationObservationAttempt>>,
    read_started: std::cell::Cell<bool>,
}

/// Carries the same MAC-authenticated original into its private Control branch.
pub(crate) struct OriginalRestorationObservationPermit {
    read: OriginalRestorationObservationRead,
}

impl NativeAckBoot {
    /// Consumes one independently prepaid receive before any new frame is read.
    ///
    /// # Errors
    /// Refuses another connection, incomplete World, absent negotiation, replay
    /// or an insufficient independently pre-Child admitted ingress row.
    pub(crate) fn retain_restoration_observation_read_data<S: ProviderStream>(
        released: OriginalRestorationReleased,
        connection: &Connection<S>,
        control: &PacketControl,
        records: &[ExchangeRecord],
    ) -> Result<OriginalRestorationObservationRead, ProviderError> {
        released.authenticate_current_data(connection, control, records)?;
        let admission = connection.original_native_owned11_admission()?;
        authenticate_restoration_observe_selection_data(
            admission
                .policy
                .original_restoration_activation_selection_data(),
            &admission.authority,
        )?;
        let maximum = usize::try_from(admission.authority.limits().frame_bytes.get())
            .map_err(|_| refused())?;
        let mut owner = admission.boot.try_borrow_mut().map_err(|_| borrowed())?;
        owner.authenticate_original_invocation_prepare_target_data()?;
        owner
            .startup
            .as_ref()
            .ok_or_else(refused)?
            .allocation
            .native_birth
            .authenticate_actual_data(&original_native_restoration_observation_ingress_row_data(
                maximum,
            )?)?;
        if owner.restoration_observation.is_some() {
            return Err(ProviderError::Conflict(
                "restored observation already attempted",
            ));
        }
        let attempt = Rc::new(RefCell::new(NativeRestorationObservationAttempt {
            creator: std::process::id(),
            thread: std::thread::current().id(),
            original: None,
            body: None,
            artifact: None,
            context: None,
            terminal: None,
            received: false,
            verified: false,
            dispatched: false,
            published: false,
        }));
        owner.restoration_observation = Some(Rc::clone(&attempt));
        drop(owner);
        Ok(OriginalRestorationObservationRead {
            released,
            attempt,
            read_started: std::cell::Cell::new(false),
        })
    }
}

impl NativeRestorationObservationAttempt {
    // This is the actual ownership cut, before any artifact/header decode.
    fn retain_original_data(&mut self, original: Envelope) -> Result<(), ProviderError> {
        self.ensure_origin()?;
        if self.original.is_some()
            || self.received
            || self.verified
            || self.dispatched
            || self.published
        {
            return Err(refused());
        }
        self.original = Some(original);
        Ok(())
    }

    fn ensure_origin(&self) -> Result<(), ProviderError> {
        if self.creator != std::process::id() || self.thread != std::thread::current().id() {
            return Err(refused());
        }
        Ok(())
    }
}

impl OriginalRestorationObservationRead {
    /// Spends this token before the first transport call, including EOF/error.
    ///
    /// # Errors
    /// Refuses a second invocation or changed actual connection/boot ownership.
    pub(crate) fn begin_receive_data<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
    ) -> Result<(), ProviderError> {
        if self.read_started.replace(true) {
            return Err(refused());
        }
        self.authenticate_receive_data(connection)
    }

    pub(crate) fn authenticate_receive_data<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
    ) -> Result<(), ProviderError> {
        let admission = connection.original_native_owned11_admission()?;
        admission.authenticate_current(connection)?;
        let owner = admission.boot.try_borrow().map_err(|_| borrowed())?;
        let flight = self.attempt.try_borrow().map_err(|_| borrowed())?;
        flight.ensure_origin()?;
        if !Rc::ptr_eq(&admission.boot, &self.released.boot)
            || owner
                .restoration_observation
                .as_ref()
                .is_none_or(|slot| !Rc::ptr_eq(slot, &self.attempt))
            || flight.received
            || flight.verified
            || flight.dispatched
            || flight.published
        {
            return Err(refused());
        }
        authenticate_restoration_observe_selection_data(
            admission
                .policy
                .original_restoration_activation_selection_data(),
            &admission.authority,
        )
    }

    // Move before method, extension, scalar or typed-body validation. On every
    // subsequent refusal this original remains in the same spent boot slot.
    pub(crate) fn retain_original_data(&self, original: Envelope) -> Result<(), ProviderError> {
        self.attempt
            .try_borrow_mut()
            .map_err(|_| borrowed())?
            .retain_original_data(original)
    }

    pub(crate) fn original_data(&self) -> Result<std::cell::Ref<'_, Envelope>, ProviderError> {
        let flight = self.attempt.try_borrow().map_err(|_| borrowed())?;
        flight.ensure_origin()?;
        std::cell::Ref::filter_map(flight, |flight| flight.original.as_ref()).map_err(|_| refused())
    }

    pub(crate) fn retain_body_data(&self, body: ReceivedBody) -> Result<(), ProviderError> {
        let mut flight = self.attempt.try_borrow_mut().map_err(|_| borrowed())?;
        flight.ensure_origin()?;
        if flight.body.is_some() || flight.received {
            return Err(refused());
        }
        let ReceivedBody::Request(body) = body else {
            return Err(refused());
        };
        let crate::bodies::RequestBody::Observe(body) = *body else {
            return Err(refused());
        };
        flight.body = Some(body);
        Ok(())
    }

    pub(crate) fn complete_receive_data(&self) -> Result<(), ProviderError> {
        let mut flight = self.attempt.try_borrow_mut().map_err(|_| borrowed())?;
        flight.ensure_origin()?;
        if !self.read_started.get()
            || flight.original.is_none()
            || flight.body.is_none()
            || flight.received
        {
            return Err(refused());
        }
        flight.received = true;
        Ok(())
    }

    /// Authenticates the full assigned request and independent native row.
    ///
    /// # Errors
    /// Refuses changed release owners, invalid Source MAC/World pair, foreign
    /// request scope, typed body disagreement or any short allocation axis.
    pub(crate) fn verify_data<S: ProviderStream>(
        self,
        connection: &Connection<S>,
        control: &PacketControl,
        records: &[ExchangeRecord],
    ) -> Result<OriginalRestorationObservationPermit, ProviderError> {
        self.released
            .authenticate_current_data(connection, control, records)?;
        let admission = connection.original_native_owned11_admission()?;
        admission.authenticate_current(connection)?;
        let maximum_frame = usize::try_from(admission.authority.limits().frame_bytes.get())
            .map_err(|_| refused())?;
        {
            let artifact = {
                let flight = self.attempt.try_borrow().map_err(|_| borrowed())?;
                flight.ensure_origin()?;
                if !flight.received || flight.verified {
                    return Err(refused());
                }
                let original = flight.original.as_ref().ok_or_else(refused)?;
                let value = original
                    .extensions
                    .get(PACKET_RESTORATION_OBSERVE_FEATURE)
                    .ok_or_else(refused)?;
                crate::connection::serialized_credit(
                    value,
                    MAXIMUM_RESTORATION_OBSERVE_ARTIFACT_BYTES,
                )?;
                PacketRestorationObservationArtifact::deserialize(value)
                    .map_err(ContractError::from)?
            };
            self.attempt
                .try_borrow_mut()
                .map_err(|_| borrowed())?
                .artifact = Some(artifact);
        }
        let owner = admission.boot.try_borrow().map_err(|_| borrowed())?;
        owner.authenticate_original_invocation_prepare_target_data()?;
        let commit = self.released.commit.try_borrow().map_err(|_| borrowed())?;
        commit.ensure_origin()?;
        let mut flight = self.attempt.try_borrow_mut().map_err(|_| borrowed())?;
        let artifact = flight.artifact.as_ref().ok_or_else(refused)?;
        artifact.validate_data()?;
        let original = flight.original.as_ref().ok_or_else(refused)?;
        if original.extensions.len() != 1 {
            return Err(refused());
        }
        let body = flight.body.as_ref().ok_or_else(refused)?;
        artifact.request.authenticate_body_data(body)?;
        self.released.authenticate_observation_request_data(
            &artifact.request,
            connection,
            records,
        )?;
        authenticate_completed_commit(&owner, &commit, &artifact.request.scope)?;
        let assigned = restoration_observe_assigned_request_digest(original, maximum_frame)?;
        let context = PacketRestorationObservationContext {
            request: artifact.request.clone(),
            assigned_request: Bytes::new(assigned.to_vec()),
        };
        flight.context = Some(context);
        let artifact = flight.artifact.as_ref().ok_or_else(refused)?;
        let key: &[u8; 32] = owner
            .data
            .private_key
            .as_slice()
            .try_into()
            .map_err(|_| refused())?;
        verify_restoration_observe_proof_data(
            key,
            flight.context.as_ref().ok_or_else(refused)?,
            &artifact.proof,
        )?;

        let inputs = connection.original_complete_restore_input_state()?;
        let request = commit.request.as_ref().ok_or_else(refused)?;
        let launch = commit.launch.as_ref().ok_or_else(refused)?;
        let selected = PacketCompleteRestoreSelectedOwnerInputs {
            owner_state: inputs.original_input(3)?,
            journal: inputs.original_input(4)?,
            control: inputs.original_input(1)?,
            anchor: inputs.original_input(2)?,
            maximum_input_bytes: usize::try_from(
                request.prepare.allocation.maximum_input_bytes.get(),
            )
            .map_err(|_| refused())?,
            maximum_before_bytes: usize::try_from(
                launch
                    .capture_profile
                    .native_before_bytes(&launch.storage)
                    .get(),
            )
            .map_err(|_| refused())?,
            maximum_requested_bytes: usize::try_from(
                artifact.request.native_allocation.requested_bytes_data()?,
            )
            .map_err(|_| refused())?,
        };
        let required = original_native_restoration_observation_required_storage_data(
            launch,
            &selected,
            maximum_frame,
        )?;
        authenticate_row(&artifact.request.native_allocation, &required)?;
        flight.verified = true;
        drop(flight);
        drop(commit);
        drop(owner);
        self.released
            .authenticate_current_data(connection, control, records)?;
        Ok(OriginalRestorationObservationPermit { read: self })
    }
}

fn refused() -> ProviderError {
    ProviderError::Correlation("restored observation once original or independent permit differs")
}

fn borrowed() -> ProviderError {
    ProviderError::Conflict("restored observation owner borrowed")
}

/// Quotes the actual independent Rc/RefCell once owner, excluding scratch.
pub(crate) fn original_native_restoration_observation_attempt_backing_data()
-> Result<usize, ProviderError> {
    size_of::<RefCell<NativeRestorationObservationAttempt>>()
        .checked_add(
            crate::retained_metadata::requested_storage::shared_header_storage_data(
                1,
                std::mem::align_of::<RefCell<NativeRestorationObservationAttempt>>(),
            )?,
        )
        .ok_or_else(refused)
}

/// Names the complete explicit local views of this native observation path.
///
/// These terms describe Rust-owned headers and fixed hash banks. Dynamic raw,
/// canonical, typed and reply owners are independently charged on their rows.
pub(crate) fn original_native_restoration_observation_counter_scratch_data() -> usize {
    use std::cell::{BorrowError, BorrowMutError, Ref, RefMut};
    crate::connection::original_restored_response_counter_scratch_data()
        + size_of::<NativeRestorationObservationAttempt>()
        + size_of::<OriginalRestorationObservationRead>()
        + size_of::<OriginalRestorationObservationPermit>()
        + size_of::<Result<OriginalRestorationObservationRead, ProviderError>>()
        + size_of::<Result<OriginalRestorationObservationPermit, ProviderError>>()
        + size_of::<Option<OriginalRestorationObservationRead>>()
        + size_of::<Result<Option<OriginalRestorationObservationRead>, ProviderError>>()

        + size_of::<Result<Ref<'static, NativeAckBoot>, BorrowError>>()
        + size_of::<Result<RefMut<'static, NativeAckBoot>, BorrowMutError>>()
        + size_of::<Result<Ref<'static, NativeCompleteRestoreAttempt>, BorrowError>>()
        + size_of::<Result<Ref<'static, NativeRestorationObservationAttempt>, BorrowError>>()
        + size_of::<Result<RefMut<'static, NativeRestorationObservationAttempt>, BorrowMutError>>()
        + size_of::<Result<Ref<'static, Envelope>, ProviderError>>()
        + size_of::<Result<Ref<'static, Envelope>, Ref<'static, NativeRestorationObservationAttempt>>>()
        + size_of::<Result<PacketRestorationObservationArtifact, ContractError>>()
        + size_of::<Result<PacketRestorationActivationAllocationRow, ProviderError>>()

        + size_of::<PacketCompleteRestoreSelectedOwnerInputs<'static>>()
        + size_of::<std::cell::Ref<'static, crate::connection::OriginalCompleteRestoreInputCustody>>()
        + size_of::<Result<std::cell::Ref<'static, crate::connection::OriginalCompleteRestoreInputCustody>, ProviderError>>()
        + size_of::<crate::connection::ReceivedBody>()
        + size_of::<Result<crate::connection::ReceivedBody, ProviderError>>()
        + size_of::<[u8; 32]>()
        + size_of::<Result<&'static [u8;32], std::array::TryFromSliceError>>()
        + size_of::<[usize; 7]>()
        + size_of::<std::array::IntoIter<usize,7>>()
        + size_of::<std::ops::Range<usize>>()
        + size_of::<Option<&'static crate::bodies::ObserveRequest>>()
        + size_of::<Result<&'static crate::bodies::ObserveRequest, ProviderError>>()
        + size_of::<Result<usize, std::num::TryFromIntError>>()
        + size_of::<crate::retained_metadata::serialization_storage::OriginalJsonValueStorageExtentData>() * 2
        + size_of::<Result<crate::retained_metadata::serialization_storage::OriginalJsonValueStorageExtentData, ProviderError>>()
        + size_of::<crate::reference_packet::service::native_startup::PacketNativeStartupAllocationRow>()
        + size_of::<Result<crate::reference_packet::service::native_startup::PacketNativeStartupAllocationRow, ProviderError>>()
        + crate::retained_metadata::serialization_storage::original_json_value_storage_extent_counter_scratch_data()

        + restoration_observe_protocol_counter_scratch_data()
        + super::released::counter_scratch_data()
        + crate::connection::original_native_restoration_observation_receive_counter_scratch_data()
}

/// Quotes the seventh full untrusted original before its signed row is known.
///
/// This independent pre-Child admission covers malformed raw Envelope/DOM,
/// typed artifact/context partials, bounded canonical MAC work and the actual
/// once allocation. It neither consumes nor reuses a Commit/World phase row.
pub(crate) fn original_native_restoration_observation_ingress_row_data(
    maximum_frame: usize,
) -> Result<
    crate::reference_packet::service::native_startup::PacketNativeStartupAllocationRow,
    ProviderError,
> {
    use crate::retained_metadata::serialization_storage::{
        original_json_value_storage_extent_data,
        original_serialization_tree_node_requested_bytes_data,
    };
    let frame = original_json_value_storage_extent_data(maximum_frame)?;
    let artifact =
        original_json_value_storage_extent_data(MAXIMUM_RESTORATION_OBSERVE_ARTIFACT_BYTES)?;
    let map_roots = frame
        .maximum_value_nodes
        .checked_mul(original_serialization_tree_node_requested_bytes_data::<
            String,
            serde_json::Value,
        >()?)
        .ok_or_else(refused)?;
    let typed = artifact
        .maximum_value_nodes
        .checked_mul(4)
        .and_then(|nodes| {
            nodes.checked_mul(
                size_of::<ContentRef>()
                    .max(size_of::<crucible_node_format::HashRef>())
                    .max(size_of::<String>()),
            )
        })
        .ok_or_else(refused)?;
    // The ordinary body decoder clones its Map for canonical validation and
    // again for typed construction. Its retained Observe HashRef owns three
    // independent Strings; body extensions were refused empty before decoding.
    let body_strings = frame
        .maximum_decoded_string_bytes
        .checked_mul(4)
        .and_then(|bytes| bytes.checked_add(3usize.checked_mul(256)?))
        .ok_or_else(refused)?;
    let body_map_root =
        original_serialization_tree_node_requested_bytes_data::<String, serde_json::Value>()?;
    let retained = frame
        .value_dom_requested_bytes
        .checked_add(map_roots)
        .and_then(|bytes| bytes.checked_add(body_strings))
        .and_then(|bytes| bytes.checked_add(body_map_root))
        .and_then(|bytes| bytes.checked_add(artifact.value_dom_requested_bytes.checked_mul(2)?))
        .and_then(|bytes| {
            bytes.checked_add(MAXIMUM_RESTORATION_OBSERVE_ARTIFACT_BYTES.checked_mul(8)?)
        })
        .and_then(|bytes| bytes.checked_add(typed))
        .and_then(|bytes| bytes.checked_add(size_of::<PacketRestorationObservationArtifact>()))
        .and_then(|bytes| bytes.checked_add(size_of::<PacketRestorationObservationContext>()))
        .and_then(|bytes| bytes.checked_add(size_of::<Envelope>()))
        .ok_or_else(refused)?
        .checked_add(original_native_restoration_observation_attempt_backing_data()?)
        .ok_or_else(refused)?;
    let artifact_pass = artifact.canonical_pass_requested_bytes()?;
    // The completed-Commit guard constructs one full expected Source-birth
    // ContentRef. Its four bounded algorithm/domain/digest/media Strings are
    // independent of the incoming artifact/context banks.
    let reference_work = 4usize.checked_mul(4 * 128 + 256).ok_or_else(refused)?;
    let transient = frame
        .canonical_pass_requested_bytes()?
        .checked_add(maximum_frame)
        .and_then(|bytes| bytes.checked_add(reference_work))
        .and_then(|bytes| bytes.checked_add(frame.value_dom_requested_bytes))
        .and_then(|bytes| bytes.checked_add(body_strings))
        .and_then(|bytes| bytes.checked_add(size_of::<crate::bodies::ObserveRequest>()))
        .and_then(|bytes| bytes.checked_add(artifact_pass.checked_mul(4)?))
        .and_then(|bytes| bytes.checked_add(typed))
        .and_then(|bytes| {
            bytes.checked_add(MAXIMUM_RESTORATION_OBSERVE_ARTIFACT_BYTES.checked_mul(4)?)
        })
        .ok_or_else(refused)?;
    Ok(
        crate::reference_packet::service::native_startup::PacketNativeStartupAllocationRow {
            retained_requested_bytes: U64::new(u64::try_from(retained).map_err(|_| refused())?),
            maximum_simultaneous_transient_bytes: U64::new(
                u64::try_from(transient).map_err(|_| refused())?,
            ),
            declared_counter_scratch_bytes: U64::new(
                u64::try_from(original_native_restoration_observation_counter_scratch_data())
                    .map_err(|_| refused())?,
            ),
        },
    )
}

impl NativeAckBoot {
    pub(in crate::reference_packet::service::ack_emitter::native_boot) fn observe_restoration_observation_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        self.ensure_origin()?;
        if let Some(attempt) = &self.restoration_observation {
            observer.shared_original(crate::retained_metadata::aliases::MetadataSharedKind::NativeRestorationObservationAttempt, attempt.as_ref())?;
            let flight = attempt.try_borrow().map_err(|_| borrowed())?;
            flight.ensure_origin()?;
            let NativeRestorationObservationAttempt {
                creator,
                thread: _,
                original,
                body,
                artifact,
                context,
                terminal,
                received,
                verified,
                dispatched,
                published,
            } = &*flight;
            observer.observe(creator)?;
            observer.observe(original)?;
            if let Some(body) = body {
                let crate::bodies::ObserveRequest {
                    binding_hash,
                    owner_generation,
                    after_observation_sequence,
                    maximum_items,
                    extensions,
                } = body;
                observer.observe(binding_hash)?;
                observer.observe(owner_generation)?;
                observer.observe(after_observation_sequence)?;
                observer.observe(maximum_items)?;
                observer.observe(extensions)?;
            }
            if let Some(artifact) = artifact {
                artifact.observe_owned_metadata_data(observer)?;
            }
            if let Some(context) = context {
                context.observe_owned_metadata_data(observer)?;
            }
            observer.observe(terminal)?;
            observer.observe(received)?;
            observer.observe(verified)?;
            observer.observe(dispatched)?;
            observer.observe(published)?;
        }
        Ok(())
    }
}

impl OriginalRestorationObservationPermit {
    pub(crate) fn original_data(&self) -> Result<std::cell::Ref<'_, Envelope>, ProviderError> {
        self.read.original_data()
    }

    pub(crate) fn begin_dispatch_data(&self) -> Result<(), ProviderError> {
        let mut flight = self.read.attempt.try_borrow_mut().map_err(|_| borrowed())?;
        flight.ensure_origin()?;
        if !flight.verified || flight.dispatched || flight.published {
            return Err(refused());
        }
        flight.dispatched = true;
        Ok(())
    }

    pub(crate) fn authenticate_control_request_data(
        &self,
        original: &Envelope,
        selection: &crate::reference_packet::control::PacketControlSelection,
        control: &PacketControl,
    ) -> Result<(), ProviderError> {
        let released = &self.read.released;
        released
            .policy
            .authenticate_original_control_selection(selection)?;
        let owner = released.boot.try_borrow().map_err(|_| borrowed())?;
        owner.authenticate_original_invocation_prepare_target_data()?;
        let flight = self.read.attempt.try_borrow().map_err(|_| borrowed())?;
        let world = released.world.try_borrow().map_err(|_| borrowed())?;
        let commit = released.commit.try_borrow().map_err(|_| borrowed())?;
        flight.ensure_origin()?;
        world.ensure_origin()?;
        commit.ensure_origin()?;
        if !flight.verified
            || !flight.dispatched
            || flight.published
            || !std::ptr::eq(original, flight.original.as_ref().ok_or_else(refused)?)
            || owner
                .restoration_observation
                .as_ref()
                .is_none_or(|slot| !Rc::ptr_eq(slot, &self.read.attempt))
            || owner.restoration_activation[1]
                .as_ref()
                .is_none_or(|slot| !Rc::ptr_eq(slot, &released.world))
            || owner
                .restoration
                .as_ref()
                .is_none_or(|slot| !Rc::ptr_eq(slot, &released.commit))
            || !world.verified
            || !world.dispatched
            || !world.published
            || released.hold.physical_gate_data()?
        {
            return Err(refused());
        }
        let artifact = flight.artifact.as_ref().ok_or_else(refused)?;
        if artifact.request.scope != world.artifact.as_ref().ok_or_else(refused)?.request.scope {
            return Err(refused());
        }
        artifact
            .request
            .authenticate_body_data(flight.body.as_ref().ok_or_else(refused)?)?;
        control.authenticate_original_restoration_released_control_data(
            ReleasedWorldControlInputsData {
                original: world.original.as_ref().ok_or_else(refused)?,
                terminal: world.terminal.as_ref().ok_or_else(refused)?,
                scope: &artifact.request.scope,
                boot: &released.boot,
                mapping: &commit.mapping,
                hold: &released.hold,
                policy: &released.policy,
            },
        )
    }

    pub(crate) fn complete_publication_data<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        control: &PacketControl,
        records: &[ExchangeRecord],
    ) -> Result<(), ProviderError> {
        self.read
            .released
            .authenticate_current_data(connection, control, records)?;
        let record = records.last().ok_or_else(refused)?;
        if record.sent() != record.originals().len() {
            return Err(refused());
        }
        let mut flight = self.read.attempt.try_borrow_mut().map_err(|_| borrowed())?;
        flight.ensure_origin()?;
        if !flight.verified || !flight.dispatched || flight.published || flight.terminal.is_some() {
            return Err(refused());
        }
        let (terminal_index, terminal) = {
            let original = flight.original.as_ref().ok_or_else(refused)?;
            crate::connection::original_restored_response_data(original, record.originals())?
        };
        // The actual terminal remains owned even if its closed success check
        // or subsequent literal/currentness check refuses.
        flight.terminal = Some(terminal.clone());
        let original = flight.original.as_ref().ok_or_else(refused)?;
        if terminal.message != crate::envelope::MessageKind::Response
            || terminal.method != original.method
            || terminal.request_id != original.request_id
            || terminal.session_id != original.session_id
            || terminal.incarnation_id != original.incarnation_id
        {
            return Err(refused());
        }
        control.authenticate_original_restoration_observation_terminal_data(original, terminal)?;
        if record
            .original_sent_frame(connection, terminal_index)?
            .original()
            != terminal
        {
            return Err(refused());
        }
        for index in 0..record.originals().len() {
            record.original_sent_frame(connection, index)?;
        }
        flight.published = true;
        drop(flight);
        self.read
            .released
            .authenticate_current_data(connection, control, records)?;
        restored_suffix::retain_published_suffix_observation_data(
            self, connection, control, records,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn once_original_survives_bad_artifact_and_replacement_refusal() {
        let mut original = crate::envelope::tests::request();
        original.method = crate::envelope::Method::Observe;
        original.extensions.insert(
            PACKET_RESTORATION_OBSERVE_FEATURE.into(),
            serde_json::json!({"invalid":"retained"}),
        );
        let mut attempt = NativeRestorationObservationAttempt {
            creator: std::process::id(),
            thread: std::thread::current().id(),
            original: None,
            body: None,
            artifact: None,
            context: None,
            terminal: None,
            received: false,
            verified: false,
            dispatched: false,
            published: false,
        };
        attempt.retain_original_data(original.clone()).unwrap();
        let value = attempt
            .original
            .as_ref()
            .unwrap()
            .extensions
            .get(PACKET_RESTORATION_OBSERVE_FEATURE)
            .unwrap();
        assert!(PacketRestorationObservationArtifact::deserialize(value).is_err());

        let mut other = original.clone();
        other.sequence = U64::new(other.sequence.get() + 1);
        assert!(attempt.retain_original_data(other).is_err());
        assert_eq!(attempt.original.as_ref(), Some(&original));
        assert!(attempt.artifact.is_none());
        assert!(!attempt.verified && !attempt.dispatched && !attempt.published);
    }
}

#[path = "observation/settled.rs"]
mod settled;

pub(crate) use restored_suffix::{
    NativeObservation17OwningCheckpointData,
    original_observation17_checkpoint_owner_counter_scratch_data,
};
