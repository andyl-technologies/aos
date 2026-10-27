//! Registers the selected original Capture under its actual publication plan.
//!
//! Registration uses the same closed body parser, source selection and stopped
//! cut predicates as the legacy path. It avoids serializing/reparsing the same
//! immutable envelope or cloning model inventory solely to inspect a cut.
//! Every new cache/tree/request owner is counted before insertion; the opaque
//! completed Observe currency remains an independent currentness prerequisite.

use super::*;
use crate::envelope::MessageKind;
use crate::reference_packet::control::restore_fresh::PacketLiveCaptureControlCurrency;
use crate::reference_packet::serialization_storage::{
    NativeSerializationStorageData, actual_serialization_storage_data,
};
use crate::reference_packet::service::capture_allocation::{
    PacketNative5CaptureAllocationSelection, PacketNativeCaptureAllocationReport,
};
use crate::retained_metadata::{
    MetadataObserver, requested_metadata_backing_storage_data,
    serialization_storage::OriginalSerializationStorageProjection,
};
use serde::ser::SerializeStruct;
use std::mem::size_of;

pub(crate) struct NativeStartupCaptureRegistrationData {
    pub(crate) projected: NativeProjectedCaptureRequestData,
    pub(crate) inventory: NativeSerializationStorageData,
    pub(crate) binding: NativeSerializationStorageData,
    pub(crate) request_identity: NativeSerializationStorageData,
    pub(crate) registration_retained_bytes: usize,
    pub(crate) registration_transient_bytes: usize,
}

fn sum(terms: &[usize]) -> Result<usize, ProviderError> {
    terms.iter().try_fold(0usize, |sum, next| {
        sum.checked_add(*next).ok_or_else(exhausted)
    })
}

fn limit(value: U64) -> Result<usize, ProviderError> {
    usize::try_from(value.get()).map_err(|_| exhausted())
}
fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("native startup Capture registration storage")
}
fn refused() -> ProviderError {
    ProviderError::Correlation("native startup Capture registration/currentness differs")
}

fn scope(
    control: &PacketControl,
    currency: &PacketLiveCaptureControlCurrency,
    report: &PacketNativeCaptureAllocationReport,
) -> Result<(), ProviderError> {
    if control.complete_capture_allocation_selection
        != Some(PacketNative5CaptureAllocationSelection::OriginalObserve12)
        || report.scope.native_pid.get() != u64::from(std::process::id())
        || report.scope.model_cursor != currency.cursor()
        || report.scope.control_originals_before.get() != currency.originals_before() as u64
    {
        return Err(refused());
    }
    currency.authenticate_capture_boundary(control, None)
}

impl PacketControl {
    pub(crate) fn quote_startup_capture_registration(
        &self,
        request: &Envelope,
        observed: &Envelope,
        currency: &PacketLiveCaptureControlCurrency,
        report: &PacketNativeCaptureAllocationReport,
        maximum_frame_bytes: usize,
    ) -> Result<NativeStartupCaptureRegistrationData, ProviderError> {
        scope(self, currency, report)?;
        let maximum = limit(report.transients.model_control_encoding_bytes)?;
        let projected =
            self.quote_original_next_capture_request(observed, maximum_frame_bytes, maximum)?;
        let actual = actual_serialization_storage_data(request, Default::default(), maximum)?;
        // This is a scalar DATA domination check before any original clone or
        // typed reparse. The private real incoming SDK guard remains conjunct.
        for (actual, bound) in [
            (
                actual.maximum_encoded_bytes,
                projected.envelope.maximum_encoded_bytes,
            ),
            (
                actual.dom_and_canonical_scratch_bytes,
                projected.envelope.dom_and_canonical_scratch_bytes,
            ),
            (
                actual.projected_parser_requested_bytes,
                projected.envelope.projected_parser_requested_bytes,
            ),
            (
                actual.serialized_value_nodes,
                projected.envelope.serialized_value_nodes,
            ),
            (
                actual.serialized_capacity_records,
                projected.envelope.serialized_capacity_records,
            ),
        ] {
            if actual > bound {
                return Err(exhausted());
            }
        }
        let mut unknown = OriginalSerializationStorageProjection::new(maximum)?;
        super::super::observe_control_growth::unknown_capture(&mut unknown)?;
        let unknown = unknown.finish(maximum)?;
        let mut trees = MetadataObserver::new();
        trees.tree::<Id, (HashRef, PacketControlReply)>(1)?;
        trees.tree::<Id, BeginRequest>(1)?;
        trees.tree::<Id, Id>(1)?;
        let registration_retained_bytes = sum(&[
            requested_metadata_backing_storage_data(&trees.finish())?,
            5 * 128,
            "blake3-256".len() + "cnp.request.v1".len() + 64,
            unknown.dom_and_canonical_scratch_bytes,
            projected
                .begin_requested_bytes
                .checked_mul(2)
                .ok_or_else(exhausted)?,
            projected.arguments_requested_bytes,
            // The native fourth owner and reservation retain independent
            // clones of the actual incoming original.
            actual.dom_and_canonical_scratch_bytes,
            actual.dom_and_canonical_scratch_bytes,
            size_of::<Envelope>(),
            size_of::<PacketOriginalCaptureReservation>(),
        ])?;
        let inventory = self.program.quote_original_capture_inventory(maximum)?;
        let owner = self
            .selection
            .realization
            .owner_bindings
            .first()
            .ok_or_else(refused)?;
        let binding = actual_serialization_storage_data(owner, Default::default(), maximum)?;
        let request_identity = actual_serialization_storage_data(
            &StartupRequestIdentity(request),
            Default::default(),
            maximum,
        )?;
        let registration_transient_bytes = sum(&[
            actual.requested_total()?,
            projected.body.requested_total()?,
            projected.arguments.requested_total()?,
            projected.begin_requested_bytes,
            projected.arguments_requested_bytes,
            unknown.requested_total()?,
            inventory.requested_total()?,
            binding.requested_total()?,
            request_identity.requested_total()?,
            size_of::<blake3::Hasher>(),
            size_of::<NativeStartupCaptureRegistrationData>(),
        ])?;
        if registration_retained_bytes > limit(report.growth.capture_publication_bytes)?
            || registration_transient_bytes > maximum
        {
            return Err(exhausted());
        }
        scope(self, currency, report)?;
        Ok(NativeStartupCaptureRegistrationData {
            projected,
            inventory,
            binding,
            request_identity,
            registration_retained_bytes,
            registration_transient_bytes,
        })
    }

    pub(crate) fn reserve_startup_capture(
        &mut self,
        request: &Envelope,
        currency: &PacketLiveCaptureControlCurrency,
        report: &PacketNativeCaptureAllocationReport,
        admitted: &NativeStartupCaptureRegistrationData,
    ) -> Result<PacketOriginalCaptureReservation, ProviderError> {
        scope(self, currency, report)?;
        if sum(&[
            admitted.inventory.requested_total()?,
            admitted.binding.requested_total()?,
            admitted.request_identity.requested_total()?,
        ])? > admitted.registration_transient_bytes
            || admitted.registration_retained_bytes
                > limit(report.growth.capture_publication_bytes)?
            || admitted.registration_transient_bytes
                > limit(report.transients.model_control_encoding_bytes)?
        {
            return Err(exhausted());
        }
        // The selected SDK already retained and validated THIS sole original.
        // Recheck the complete native semantic scope, but parse each typed body
        // only once after its closed construction phase has been admitted.
        let RequestBody::Begin(begin) = decode_request(request.method, &request.body)? else {
            return Err(refused());
        };
        let BeginArguments::Capture(arguments) = begin.decoded_arguments()? else {
            return Err(refused());
        };
        let [binding] = self.selection.realization.bindings.as_slice() else {
            return Err(refused());
        };
        let [owner] = self.selection.realization.owner_bindings.as_slice() else {
            return Err(refused());
        };
        let id = request.request_id.0.as_ref().ok_or_else(refused)?;
        let operation = request.operation_id.0.as_ref().ok_or_else(refused)?;
        if request.protocol != "CNP/1"
            || request.message != MessageKind::Request
            || request.method != Method::Begin
            || self
                .selection
                .provider
                .implementation
                .implementation_id
                .as_str()
                != IMPLEMENTATION
            || self.selection.provider.supported_profiles.len() != 1
            || self.selection.provider.supported_profiles[0]
                .profile_id
                .as_str()
                != PRESERVATION
            || arguments.preservation_contract.as_str() != PRESERVATION
            || request.session_id.0.as_ref() != Some(&binding.authority.session_id)
            || request.incarnation_id.0.as_ref() != Some(&binding.authority.incarnation_id)
            || request.node_id.0.as_ref() != Some(&binding.compatibility.node_id)
            || request.capture_owner_id.0.as_ref() != Some(&binding.compatibility.capture_owner.id)
            || request.execution_owner_id.0.is_some()
            || !request.extensions.is_empty()
            || !begin.extensions.is_empty()
            || begin.binding_hash != owner.identity()?
            || begin.owner_generation != binding.authority.owner_generation
            || arguments.participant_ids != owner.owner.participant_ids
            || self.active.as_ref().is_none_or(|active| {
                begin.activation_id.0.as_ref() != Some(&active.activation_id)
                    || begin.world_generation != active.world_generation
                    || active.world_binding_hash != self.selection.world
            })
            || self.current_operation.is_some()
            || self.originals.len() >= ORIGINALS
            || self.begins.len() >= 64
            || self.originals.contains_key(id)
            || self.begins.contains_key(operation)
        {
            return Err(refused());
        }
        self.program
            .authenticate_original_capture_cut(arguments.cut)?;
        let retained_request = request.clone();
        let identity = startup_request_hash(
            request,
            limit(report.transients.model_control_encoding_bytes)?,
        )?;
        let unknown = object(ResponseShape::Error {
            operation_state: OperationState::Unknown,
            error: ErrorRecord {
                code: "OUTCOME_UNKNOWN".into(),
                message: "original native Capture remains unresolved".into(),
                effect: EffectCertainty::Unknown,
                retryable: false,
                details: Map::new(),
            },
            extensions: Extensions::new(),
        })?;
        // All fallible parsing/canonical work precedes mutation. From the first
        // insertion the endpoint also retains this exact incoming original.
        self.originals.insert(
            id.clone(),
            (
                identity,
                PacketControlReply {
                    body: unknown,
                    evidence: Vec::new(),
                },
            ),
        );
        self.begins.insert(operation.clone(), begin.clone());
        self.begin_requests.insert(operation.clone(), id.clone());
        self.current_operation = Some(operation.clone());
        Ok(PacketOriginalCaptureReservation {
            owner: std::rc::Rc::clone(&self.capture_identity),
            creator: std::process::id(),
            request: retained_request,
            arguments,
            begin,
        })
    }
}

#[derive(Serialize)]
struct StartupAnchor<'a> {
    schema: &'static str,
    native_pid: U64,
    request: &'a Envelope,
    request_hash: &'a HashRef,
    capture: &'a CaptureArguments,
    world: &'a HashRef,
    binding: &'a HashRef,
    local_cursor: Position,
    control_snapshot: &'a ContentRef,
    inventory_hash: &'a HashRef,
}

#[derive(Serialize)]
struct StartupCaptureResultView<'a> {
    capture_manifest: &'a ContentRef,
    owner_state_refs: [&'a ContentRef; 1],
    unchanged_cut_receipt: &'a ContentRef,
}

#[derive(Serialize)]
struct StartupCaptureCompletedView<'a> {
    status: &'static str,
    operation_state: OperationState,
    result: StartupCaptureResultView<'a>,
    extensions: &'a Extensions,
}

/// Keeps the same private produced reply through prefix preparation and cache move.
/// It is never deserialized and cannot be constructed from response JSON.
pub(crate) struct NativeStartupCaptureReply {
    reply: PacketControlReply,
    owner: std::rc::Rc<()>,
    creator: u32,
    snapshot: ContentRef,
    request_hash: HashRef,
    inventory_hash: HashRef,
    pub(crate) cache_retained_bytes: usize,
}

impl NativeStartupCaptureReply {
    pub(crate) fn body(&self) -> &Map<String, Value> {
        &self.reply.body
    }

    fn authenticate_origin(&self, identity: &std::rc::Rc<()>) -> Result<(), ProviderError> {
        if self.creator != std::process::id() || !std::rc::Rc::ptr_eq(identity, &self.owner) {
            return Err(refused());
        }
        Ok(())
    }
}

impl PacketControl {
    pub(crate) fn capture_reserved_startup_control(
        &self,
        reservation: &PacketOriginalCaptureReservation,
        currency: &PacketLiveCaptureControlCurrency,
        report: &PacketNativeCaptureAllocationReport,
        maximum_bytes: usize,
    ) -> Result<
        (
            PacketOriginalCaptureComponent,
            NativeSerializationStorageData,
        ),
        ProviderError,
    > {
        currency.authenticate_capture_boundary(self, Some(reservation.request()))?;
        self.authenticate_startup_capture_reservation_data(
            reservation,
            limit(report.transients.model_control_encoding_bytes)?,
        )?;
        let maximum = limit(report.transients.model_control_encoding_bytes)?;
        let inventory = self.program.quote_original_capture_inventory(maximum)?;
        // These independent inventory/hash and full model/Control phases are
        // admitted together, even though only their retained hashes coexist.
        let inventory_phase = sum(&[
            inventory.requested_total()?,
            fixed_hash_backing(),
            size_of::<HashRef>(),
        ])?;
        if inventory_phase > maximum {
            return Err(exhausted());
        }
        let before = self.program.original_capture_inventory_hash(maximum)?;
        let (snapshot, control_encoding) =
            self.capture_registered_startup_control(reservation, currency, report, maximum_bytes)?;
        let request_hash = startup_request_hash(&reservation.request, maximum)?;
        let binding = self.selection.realization.owner_bindings[0].identity()?;
        let anchor = StartupAnchor {
            schema: "source-owned.packet-native-unchanged-cut/5",
            native_pid: U64::new(u64::from(std::process::id())),
            request: &reservation.request,
            request_hash: &request_hash,
            capture: &reservation.arguments,
            world: &self.selection.world,
            binding: &binding,
            local_cursor: snapshot.local_cursor(),
            control_snapshot: snapshot.reference(),
            inventory_hash: &before,
        };
        let encoding = actual_serialization_storage_data(&anchor, Default::default(), maximum)?;
        if encoding.maximum_encoded_bytes > 8192
            || encoding.requested_total()? > limit(report.transients.native_before_encoding_bytes)?
        {
            return Err(exhausted());
        }
        let bytes = crate::reference_packet::serialization_storage::encode_original_precharged_serialization(&anchor, &encoding)?;
        let reference = canonical::content_ref(&bytes, "application/json")?;
        self.authenticate_startup_capture_reservation_data(
            reservation,
            limit(report.transients.model_control_encoding_bytes)?,
        )?;
        currency.authenticate_capture_boundary(self, Some(reservation.request()))?;
        if self.program.original_capture_inventory_hash(maximum)? != before {
            return Err(refused());
        }
        Ok((
            PacketOriginalCaptureComponent {
                owner: std::rc::Rc::clone(&self.capture_identity),
                creator: std::process::id(),
                request_hash,
                inventory_hash: before,
                snapshot,
                anchor: (reference, bytes),
            },
            control_encoding,
        ))
    }

    pub(crate) fn original_startup_capture_reply(
        &self,
        reservation: &PacketOriginalCaptureReservation,
        component: &PacketOriginalCaptureComponent,
        complete_snapshot: &ContentRef,
        currency: &PacketLiveCaptureControlCurrency,
        report: &PacketNativeCaptureAllocationReport,
        retained_publication_before_reply: usize,
    ) -> Result<NativeStartupCaptureReply, ProviderError> {
        self.authenticate_startup_component(reservation, component, currency, report)?;
        complete_snapshot.validate()?;
        if complete_snapshot == &component.anchor.0 {
            return Err(refused());
        }
        let extensions = Extensions::new();
        let view = StartupCaptureCompletedView {
            status: "completed",
            operation_state: OperationState::Completed,
            result: StartupCaptureResultView {
                capture_manifest: complete_snapshot,
                owner_state_refs: [component.snapshot.reference()],
                unchanged_cut_receipt: &component.anchor.0,
            },
            extensions: &extensions,
        };
        let maximum = limit(report.transients.native_before_encoding_bytes)?;
        let encoding = actual_serialization_storage_data(&view, Default::default(), maximum)?;
        let cache_retained_bytes = startup_capture_terminal_cache_storage_data(&encoding)?;
        if encoding.maximum_encoded_bytes > FRAME
            || sum(&[retained_publication_before_reply, cache_retained_bytes])?
                > limit(report.growth.capture_publication_bytes)?
        {
            return Err(exhausted());
        }
        // The complete endpoint snapshot/registration/prefix owners and both cache
        // bodies were admitted together before constructing this first body.
        // The same private borrowed producer supplies the cache body directly.
        // No arbitrary raw body or selector can bypass a typed/owning check.
        let Value::Object(body) = serde_json::to_value(&view).map_err(ContractError::from)? else {
            return Err(refused());
        };
        Ok(NativeStartupCaptureReply {
            reply: PacketControlReply {
                body,
                evidence: Vec::new(),
            },
            owner: std::rc::Rc::clone(&self.capture_identity),
            creator: std::process::id(),
            snapshot: complete_snapshot.clone(),
            request_hash: component.request_hash.clone(),
            inventory_hash: component.inventory_hash.clone(),
            cache_retained_bytes,
        })
    }

    pub(crate) fn settle_startup_capture(
        &mut self,
        reservation: &PacketOriginalCaptureReservation,
        component: &PacketOriginalCaptureComponent,
        complete_snapshot: &ContentRef,
        currency: &PacketLiveCaptureControlCurrency,
        report: &PacketNativeCaptureAllocationReport,
        produced: NativeStartupCaptureReply,
    ) -> Result<(), ProviderError> {
        self.authenticate_startup_component(reservation, component, currency, report)?;
        produced.authenticate_origin(&self.capture_identity)?;
        if produced.snapshot != *complete_snapshot
            || produced.request_hash != component.request_hash
            || produced.inventory_hash != component.inventory_hash
            || produced.cache_retained_bytes > limit(report.growth.capture_publication_bytes)?
        {
            return Err(refused());
        }
        let request = reservation
            .request
            .request_id
            .0
            .as_ref()
            .ok_or_else(refused)?;
        let operation = reservation
            .request
            .operation_id
            .0
            .as_ref()
            .ok_or_else(refused)?;
        // The actual producer is moved into the original cache. Only the
        // independent operation-terminal body is cloned, under the same sum.
        let terminal = produced.reply.body.clone();
        self.originals
            .insert(request.clone(), (produced.request_hash, produced.reply));
        self.terminals.insert(operation.clone(), terminal);
        self.current_operation = None;
        Ok(())
    }

    fn authenticate_startup_component(
        &self,
        reservation: &PacketOriginalCaptureReservation,
        component: &PacketOriginalCaptureComponent,
        currency: &PacketLiveCaptureControlCurrency,
        report: &PacketNativeCaptureAllocationReport,
    ) -> Result<(), ProviderError> {
        self.authenticate_startup_capture_reservation_data(
            reservation,
            limit(report.transients.model_control_encoding_bytes)?,
        )?;
        currency.authenticate_capture_boundary(self, Some(reservation.request()))?;
        if component.creator != std::process::id()
            || !std::rc::Rc::ptr_eq(&self.capture_identity, &component.owner)
            || component.request_hash
                != startup_request_hash(
                    &reservation.request,
                    limit(report.transients.model_control_encoding_bytes)?,
                )?
            || component.snapshot.administrative_cut() != reservation.arguments.cut
            || self.program.original_capture_inventory_hash(limit(
                report.transients.model_control_encoding_bytes,
            )?)? != component.inventory_hash
        {
            return Err(refused());
        }
        component
            .snapshot
            .reference()
            .verify(component.snapshot.bytes())?;
        component.anchor.0.verify(&component.anchor.1)?;
        Ok(())
    }
}

/// Counts both independently retained terminal bodies and their real owners.
///
/// The Observe-time caller supplies a full terminal Envelope projection, which
/// dominates this body-only serializer. The actual producer supplies its body.
pub(crate) fn startup_capture_terminal_cache_storage_data(
    encoding: &NativeSerializationStorageData,
) -> Result<usize, ProviderError> {
    let mut trees = MetadataObserver::new();
    trees.tree::<Id, Map<String, Value>>(1)?;
    sum(&[
        requested_metadata_backing_storage_data(&trees.finish())?,
        encoding.dom_and_canonical_scratch_bytes,
        encoding.dom_and_canonical_scratch_bytes,
        128,
        3 * fixed_hash_backing(),
        "application/json".len(),
        size_of::<NativeStartupCaptureReply>(),
        size_of::<PacketControlReply>(),
    ])
}

const fn fixed_hash_backing() -> usize {
    "blake3-256".len() + "source-owned.packet-connected-inventory/4".len() + 64
}

pub(crate) const fn original_startup_capture_counter_scratch_data() -> usize {
    size_of::<NativeStartupCaptureRegistrationData>()
        + size_of::<NativeStartupCaptureReply>()
        + size_of::<MetadataObserver<'static>>()
        + size_of::<crate::retained_metadata::RetainedProtocolMetadataFacts>()
        + size_of::<OriginalSerializationStorageProjection>()
        + size_of::<[NativeSerializationStorageData; 8]>()
        + size_of::<StartupAnchor<'static>>()
        + size_of::<[usize; 16]>()
        + size_of::<blake3::Hasher>()
}

// Exact normative RequestOrigin projection, borrowing the genuine retained
// original instead of validating and cloning its complete DOM repeatedly.
// This DATA serializer grants no source, reply or registration permission.
pub(in crate::reference_packet::control) struct StartupRequestIdentity<'a>(
    pub(in crate::reference_packet::control) &'a Envelope,
);

impl Serialize for StartupRequestIdentity<'_> {
    fn serialize<T: serde::Serializer>(&self, serializer: T) -> Result<T::Ok, T::Error> {
        let original = self.0;
        let mut value = serializer.serialize_struct("OriginalRequestIdentity", 12)?;
        value.serialize_field("protocol", &original.protocol)?;
        value.serialize_field("session_id", &original.session_id)?;
        value.serialize_field("incarnation_id", &original.incarnation_id)?;
        value.serialize_field("node_id", &original.node_id)?;
        value.serialize_field("execution_owner_id", &original.execution_owner_id)?;
        value.serialize_field("capture_owner_id", &original.capture_owner_id)?;
        value.serialize_field("request_id", &original.request_id)?;
        value.serialize_field("operation_id", &original.operation_id)?;
        value.serialize_field("method", &original.method)?;
        value.serialize_field("body", &original.body)?;
        value.serialize_field("extensions", &original.extensions)?;
        value.serialize_field("request_origin", &RequestOrigin::Controller)?;
        value.end()
    }
}

fn startup_request_hash(original: &Envelope, maximum: usize) -> Result<HashRef, ProviderError> {
    if original.message != MessageKind::Request || original.method != Method::Begin {
        return Err(refused());
    }
    let view = StartupRequestIdentity(original);
    actual_serialization_storage_data(&view, Default::default(), maximum)?;
    canonical::json_hash("cnp.request.v1", &view).map_err(Into::into)
}

impl PacketControl {
    pub(in crate::reference_packet::control) fn authenticate_startup_capture_reservation_data(
        &self,
        reservation: &PacketOriginalCaptureReservation,
        maximum: usize,
    ) -> Result<(), ProviderError> {
        if self.capture_creator != std::process::id()
            || reservation.creator != std::process::id()
            || !std::rc::Rc::ptr_eq(&self.capture_identity, &reservation.owner)
            || self.fenced
        {
            return Err(refused());
        }
        let request = reservation
            .request
            .request_id
            .0
            .as_ref()
            .ok_or_else(refused)?;
        let operation = reservation
            .request
            .operation_id
            .0
            .as_ref()
            .ok_or_else(refused)?;
        let retained = self.originals.get(request).ok_or_else(refused)?;
        if retained.0 != startup_request_hash(&reservation.request, maximum)?
            || self.begins.get(operation) != Some(&reservation.begin)
            || self.begin_requests.get(operation) != Some(request)
            || self.current_operation.as_ref() != Some(operation)
            || retained
                .1
                .body
                .get("operation_state")
                .and_then(Value::as_str)
                != Some("unknown")
            || !retained.1.evidence.is_empty()
        {
            return Err(refused());
        }
        Ok(())
    }
}

impl PacketControl {
    pub(crate) fn startup_capture_request_hash_data(
        &self,
        request: &Envelope,
        currency: &PacketLiveCaptureControlCurrency,
        report: &PacketNativeCaptureAllocationReport,
    ) -> Result<HashRef, ProviderError> {
        currency.authenticate_capture_boundary(self, Some(request))?;
        if report.scope.native_pid.get() != u64::from(self.capture_creator)
            || report.scope.model_cursor != currency.cursor()
            || report.scope.control_originals_before.get() != currency.originals_before() as u64
        {
            return Err(refused());
        }
        startup_request_hash(
            request,
            limit(report.transients.native_after_encoding_bytes)?,
        )
    }
}

// crucible-lint: allow panic-shortcut -- actual serializer/canonical identity and private allocation guards are the observations.
#[cfg(test)]
mod startup_producer_data_tests {
    use super::*;
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn original() -> Result<Envelope, ProviderError> {
        let generation = U64::new(1);
        let arguments = CaptureArguments {
            capture_id: Id::new("capture-data-id")?,
            participant_ids: vec![Id::new("native/0")?],
            cut_id: Id::new("cut-data-id")?,
            cut: Position::new(generation, generation, Phase::Reaction),
            event_ordinal: generation,
            ordering_profile: "superdense-v1".into(),
            preservation_contract: Id::new(PRESERVATION)?,
        };
        let arguments = object(arguments)?;
        let begin = BeginRequest {
            kind: BeginKind::Capture,
            binding_hash: canonical::json_hash("cnp.owner-binding.v1", &())?,
            owner_generation: generation,
            activation_id: Nullable(Some(Id::new("active-data-id")?)),
            world_generation: generation,
            arguments,
            extensions: Extensions::new(),
        };
        Ok(Envelope {
            protocol: "CNP/1".into(),
            message: MessageKind::Request,
            session_id: Nullable(Some(Id::new("session")?)),
            incarnation_id: Nullable(Some(Id::new("incarnation")?)),
            node_id: Nullable(Some(Id::new("native/0")?)),
            execution_owner_id: Nullable(None),
            capture_owner_id: Nullable(Some(Id::new("native-owner")?)),
            request_id: Nullable(Some(Id::new("request")?)),
            operation_id: Nullable(Some(Id::new("operation")?)),
            sequence: generation,
            method: Method::Begin,
            body: object(begin)?,
            extensions: Extensions::new(),
        })
    }

    #[test]
    fn borrowed_capture_identity_matches_normative_hash_and_preserves_changed_originals()
    -> TestResult {
        // Inert full typed requests test exact transformation; no selected
        // policy, live reservation, completed Report or grant is fabricated.
        let mut request = original()?;
        let before = serde_json::to_value(&request)?;
        for phase in ["1.0", "1e0", "-0", "3"] {
            request
                .body
                .get_mut("arguments")
                .and_then(Value::as_object_mut)
                .ok_or_else(refused)?
                .get_mut("cut")
                .and_then(Value::as_object_mut)
                .ok_or_else(refused)?
                .insert("phase".into(), serde_json::from_str(phase)?);
            assert_eq!(
                startup_request_hash(&request, 16 * 1024 * 1024)?,
                request.request_hash(RequestOrigin::Controller)?
            );
        }
        let hash = startup_request_hash(&request, 16 * 1024 * 1024)?;
        request.sequence = U64::new(900);
        assert_eq!(hash, startup_request_hash(&request, 16 * 1024 * 1024)?);
        request.operation_id = Nullable(Some(Id::new("changed-operation")?));
        assert_ne!(hash, startup_request_hash(&request, 16 * 1024 * 1024)?);
        request.message = MessageKind::Response;
        assert!(startup_request_hash(&request, 16 * 1024 * 1024).is_err());
        assert_eq!(before["operation_id"], "operation");
        Ok(())
    }

    #[test]
    fn actual_borrowed_completed_capture_body_matches_legacy_canonical_reply() -> TestResult {
        let snapshot = canonical::content_ref(b"actual data snapshot", "application/json")?;
        let control = canonical::content_ref(b"actual data control", "application/json")?;
        let anchor = canonical::content_ref(b"actual data anchor", "application/json")?;
        let extensions = Extensions::new();
        let view = StartupCaptureCompletedView {
            status: "completed",
            operation_state: OperationState::Completed,
            result: StartupCaptureResultView {
                capture_manifest: &snapshot,
                owner_state_refs: [&control],
                unchanged_cut_receipt: &anchor,
            },
            extensions: &extensions,
        };
        let actual = serde_json::to_value(&view)?;
        let expected = object(ResponseShape::Completed {
            operation_state: OperationState::Completed,
            result: object(CaptureResult {
                capture_manifest: snapshot.clone(),
                owner_state_refs: vec![control.clone()],
                unchanged_cut_receipt: anchor.clone(),
            })?,
            extensions: Extensions::new(),
        })?;
        assert_eq!(
            canonical::canonical_json(&actual)?,
            canonical::canonical_json(&Value::Object(expected))?
        );
        let counter =
            actual_serialization_storage_data(&view, Default::default(), 16 * 1024 * 1024)?;
        let encoded = crate::reference_packet::serialization_storage::encode_original_precharged_serialization(&view, &counter)?;
        assert_eq!(encoded, canonical::canonical_json(&actual)?);
        Ok(())
    }

    #[test]
    fn actual_borrowed_unchanged_cut_receipt_and_evidence_match_original_canonical_producer()
    -> TestResult {
        let request = original()?;
        let RequestBody::Begin(begin) = decode_request(request.method, &request.body)? else {
            return Err(refused().into());
        };
        let BeginArguments::Capture(arguments) = begin.decoded_arguments()? else {
            return Err(refused().into());
        };
        let request_hash = request.request_hash(RequestOrigin::Controller)?;
        let world = canonical::json_hash("cnp.world-binding.v1", &())?;
        let binding = begin.binding_hash.clone();
        let control = canonical::content_ref(b"actual control byte evidence", "application/json")?;
        let inventory = canonical::json_hash("source-owned.packet-inventory.v1", &())?;
        let view = StartupAnchor {
            schema: "source-owned.packet-native-unchanged-cut/5",
            native_pid: U64::new(u64::from(std::process::id())),
            request: &request,
            request_hash: &request_hash,
            capture: &arguments,
            world: &world,
            binding: &binding,
            local_cursor: arguments.cut,
            control_snapshot: &control,
            inventory_hash: &inventory,
        };
        let expected = serde_json::json!({
            "schema":"source-owned.packet-native-unchanged-cut/5", "native_pid":U64::new(u64::from(std::process::id())),
            "request":&request, "request_hash":&request_hash, "capture":&arguments, "world":&world,
            "binding":&binding, "local_cursor":arguments.cut, "control_snapshot":&control, "inventory_hash":&inventory,
        });
        let data = actual_serialization_storage_data(&view, Default::default(), 16 * 1024 * 1024)?;
        let bytes = crate::reference_packet::serialization_storage::encode_original_precharged_serialization(&view, &data)?;
        assert_eq!(bytes, canonical::canonical_json(&expected)?);
        let reference = canonical::content_ref(&bytes, "application/json")?;
        reference.verify(&bytes)?;
        let evidence = (reference, bytes);
        assert_eq!(
            serde_json::to_value(&evidence)?,
            serde_json::to_value(&(
                canonical::content_ref(&canonical::canonical_json(&expected)?, "application/json")?,
                canonical::canonical_json(&expected)?
            ))?
        );
        Ok(())
    }

    #[test]
    fn produced_reply_origin_rejects_equal_foreign_allocations_without_losing_body() -> TestResult {
        let owner = std::rc::Rc::new(());
        let foreign = std::rc::Rc::new(());
        // A closed data-only origin test: this private literal is never passed
        // to a Control, service, grant issuer or settlement constructor.
        let body = object(serde_json::json!({"retained":"actual original cache body"}))?;
        let mut observer = MetadataObserver::new();
        observer.observe(&body)?;
        let actual_body_backing = requested_metadata_backing_storage_data(&observer.finish())?;
        let reply = NativeStartupCaptureReply {
            reply: PacketControlReply {
                body,
                evidence: Vec::new(),
            },
            owner: std::rc::Rc::clone(&owner),
            creator: std::process::id(),
            snapshot: canonical::content_ref(b"snapshot data", "application/json")?,
            request_hash: canonical::hash("cnp.request.v1", b"original data")?,
            inventory_hash: canonical::hash("source-owned.packet-inventory.v1", b"inventory data")?,
            cache_retained_bytes: actual_body_backing
                .checked_add(size_of::<NativeStartupCaptureReply>())
                .ok_or_else(exhausted)?,
        };
        let bytes = canonical::canonical_json(&Value::Object(reply.body().clone()))?;
        reply.authenticate_origin(&owner)?;
        assert!(reply.authenticate_origin(&foreign).is_err());
        assert_eq!(
            bytes,
            canonical::canonical_json(&Value::Object(reply.body().clone()))?
        );
        Ok(())
    }
}
