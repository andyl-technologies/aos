//! Owns original native Capture registration without granting host preservation.
//!
//! Registration retains the same administrative Begin in the actual Control
//! journal before snapshot work. Completion settles that exact reservation once;
//! the enclosing endpoint must retain the complete protocol snapshot and actual
//! reply prefix. These methods never construct an installed native capture.

use super::*;

const IMPLEMENTATION: &str = "source-owned.packet-native/5";
const PRESERVATION: &str = "source-owned.packet-complete-original-lineage/5";

/// Retains one original native administrative reservation on its owning Control.
///
/// The value cannot be decoded, cloned or constructed from portable metadata.
/// It is consumed by completion on the same live Control allocation. The source
/// installer still owns kernel, transport, effect-receipt and host ticket joins.
pub struct PacketOriginalCaptureReservation {
    owner: std::rc::Rc<()>,
    creator: u32,
    request: Envelope,
    arguments: CaptureArguments,
    begin: BeginRequest,
}

/// Retains one same-owner control snapshot and its unchanged-cut anchor.
///
/// This opaque component excludes endpoint, host and restoration authority. Its
/// private owner anchor joins the stopped bytes to the original reservation.
pub struct PacketOriginalCaptureComponent {
    owner: std::rc::Rc<()>,
    creator: u32,
    request_hash: HashRef,
    inventory_hash: HashRef,
    snapshot: PacketOriginalControlSnapshot,
    anchor: (ContentRef, Vec<u8>),
}

impl PacketOriginalCaptureComponent {
    /// Borrows the complete original control/model snapshot.
    pub fn snapshot(&self) -> &PacketOriginalControlSnapshot {
        &self.snapshot
    }

    pub(crate) fn retained_anchor_capacity_data(&self) -> usize {
        self.anchor.1.capacity()
    }

    /// Borrows the independently hashed unchanged-cut anchor.
    pub fn anchor(&self) -> (&ContentRef, &[u8]) {
        (&self.anchor.0, &self.anchor.1)
    }
}

impl PacketOriginalCaptureReservation {
    /// Borrows the exact original registered administrative request.
    pub fn request(&self) -> &Envelope {
        &self.request
    }

    /// Borrows its complete global cut and original capture identity.
    pub fn arguments(&self) -> &CaptureArguments {
        &self.arguments
    }
}

impl PacketControl {
    pub(crate) fn is_complete_original_source(&self) -> bool {
        self.complete_coordinator.is_some()
    }

    pub(crate) fn authenticate_complete_birth(&self) -> Result<(), ProviderError> {
        if self.capture_creator != std::process::id() {
            return Err(ProviderError::Correlation(
                "native5 complete birth foreign creator",
            ));
        }
        self.complete_storage
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "native5 complete storage birth absent",
            ))?
            .validate()?;
        let installed = self
            .complete_coordinator
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "native5 complete birth source absent",
            ))?;
        installed.validate(&self.selection)?;
        self.endpoint_scope()?;
        Ok(())
    }

    // Endpoint allocations must use the SAME storage/Hello tuple retained at
    // original service birth, including after a recoverable constructor refusal.
    pub(crate) fn authenticate_complete_storage(
        &self,
        storage: &super::super::service::PacketNative5StorageLimits,
        limits: crate::handshake::Limits,
    ) -> Result<(), ProviderError> {
        self.authenticate_complete_birth()?;
        let original = self
            .complete_storage
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "native5 complete storage birth absent",
            ))?;
        if &original.storage != storage || original.limits != limits {
            return Err(ProviderError::Correlation(
                "native5 endpoint storage differs from original birth",
            ));
        }
        Ok(())
    }

    /// Registers an original Capture before any snapshot or protocol effect.
    ///
    /// This distinct route requires the selected edition-five implementation and
    /// complete original capture owner. Legacy constructors cannot use it. The
    /// reservation retains the private original owner anchor through completion;
    /// matching portable identities cannot enroll a substitute Control.
    ///
    /// # Errors
    /// Refuses legacy selection, a changed route, inactive gate, unresolved
    /// modeled work, duplicate IDs, unretired outputs, a cut before the local
    /// cursor, invalid administrative grammar or exhausted lifetime journals.
    pub fn reserve_original_capture(
        &mut self,
        request: &Envelope,
    ) -> Result<PacketOriginalCaptureReservation, ProviderError> {
        let (begin, arguments) = self.validate_original_capture(request)?;
        let id = request
            .request_id
            .0
            .as_ref()
            .ok_or(ProviderError::Frame("native5 Capture request absent"))?;
        let operation = request
            .operation_id
            .0
            .as_ref()
            .ok_or(ProviderError::Frame("native5 Capture operation absent"))?;

        let retained_request = request.clone();
        let identity = request.request_hash(RequestOrigin::Controller)?;
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

    /// Checks current complete control bytes before registering a Capture.
    ///
    /// The stopped model is read without advancing its cursor, gate or journals.
    /// The additional bound covers the original pending request, Begin entry,
    /// request association and unresolved reply that registration will retain.
    /// This count grants no capture or protocol settlement authority.
    ///
    /// # Errors
    /// Refuses the original scope or selected control byte credit without
    /// inserting any request, consuming an operation ID or changing the model.
    pub fn preflight_original_capture(
        &self,
        request: &Envelope,
        maximum_bytes: usize,
    ) -> Result<usize, ProviderError> {
        let (_, arguments) = self.validate_original_capture(request)?;
        let before = self.capture_control_state(arguments.cut, maximum_bytes)?;
        let original = crate::connection::serialized_credit(request, FRAME)?;
        let complete = original
            .checked_mul(4)
            .and_then(|pending| pending.checked_add(4096))
            .and_then(|pending| before.bytes().len().checked_add(pending))
            .filter(|bytes| *bytes <= maximum_bytes)
            .ok_or(ProviderError::ResourceExhausted(
                "native5 pending Capture control capacity",
            ))?;
        self.validate_original_capture(request)?;
        Ok(complete)
    }

    fn validate_original_capture(
        &self,
        request: &Envelope,
    ) -> Result<(BeginRequest, CaptureArguments), ProviderError> {
        if self.capture_creator != std::process::id() {
            return Err(ProviderError::Correlation(
                "native5 Capture foreign creator",
            ));
        }
        self.complete_storage
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "native5 Capture storage birth absent",
            ))?
            .validate()?;
        encode(request)?;
        request.validate()?;
        let RequestBody::Begin(begin) = decode_request(request.method, &request.body)? else {
            return Err(ProviderError::Frame(
                "native5 Capture requires original Begin",
            ));
        };
        let BeginArguments::Capture(arguments) = begin.decoded_arguments()? else {
            return Err(ProviderError::Frame(
                "native5 administrative kind is not Capture",
            ));
        };
        let binding = &self.selection.realization.bindings[0];
        let owner = &self.selection.realization.owner_bindings[0];
        let id = request
            .request_id
            .0
            .as_ref()
            .ok_or(ProviderError::Frame("native5 Capture request absent"))?;
        let operation = request
            .operation_id
            .0
            .as_ref()
            .ok_or(ProviderError::Frame("native5 Capture operation absent"))?;
        let inventory = self.program.inventory()?;
        if self
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
            || begin.binding_hash != owner.identity()?
            || begin.owner_generation != binding.authority.owner_generation
            || arguments.participant_ids != owner.owner.participant_ids
            || self.fenced
            || !self.immediate
            || self.active.as_ref().is_none_or(|active| {
                begin.activation_id.0.as_ref() != Some(&active.activation_id)
                    || begin.world_generation != active.world_generation
                    || active.world_binding_hash != self.selection.world
            })
            || inventory.gate_closed
            || self.current_operation.is_some()
            || !inventory.retained_outputs.is_empty()
            || arguments.cut < inventory.reached
            || inventory
                .pending
                .iter()
                .any(|event| event.completion < arguments.cut)
            || self.originals.len() >= ORIGINALS
            || self.begins.len() >= 64
            || self.originals.contains_key(id)
            || self.begins.contains_key(operation)
        {
            return Err(ProviderError::Correlation("native5 original Capture scope"));
        }

        Ok((begin, arguments))
    }

    /// Captures the registered original control/model and its unchanged-cut anchor.
    ///
    /// The reservation and stopped native state remain owned by this Control.
    /// The returned pair excludes mandatory endpoint and host custody; it is a
    /// component of the enclosing snapshot rather than a complete capture seal.
    ///
    /// # Errors
    /// Refuses a foreign creator or owner, changed reservation, altered native
    /// state, exhausted complete byte credit or invalid full typed references.
    pub fn capture_reserved_control(
        &self,
        reservation: &PacketOriginalCaptureReservation,
        maximum_bytes: usize,
    ) -> Result<PacketOriginalCaptureComponent, ProviderError> {
        self.authenticate_capture_reservation(reservation)?;
        let before = self.program.inventory_hash()?;
        let snapshot = self.capture_control_state(reservation.arguments.cut, maximum_bytes)?;
        let anchor = serde_json::json!({
            "schema": "source-owned.packet-native-unchanged-cut/5",
            "native_pid": U64::new(u64::from(std::process::id())),
            "request": reservation.request,
            "request_hash": reservation.request.request_hash(RequestOrigin::Controller)?,
            "capture": reservation.arguments,
            "world": self.selection.world,
            "binding": self.selection.realization.owner_bindings[0].identity()?,
            "local_cursor": snapshot.local_cursor(),
            "control_snapshot": snapshot.reference(),
            "inventory_hash": before,
        });
        crate::connection::serialized_credit(&anchor, 8192)?;
        let bytes = canonical::canonical_json(&anchor)?;
        let reference = canonical::content_ref(&bytes, "application/json")?;
        self.authenticate_capture_reservation(reservation)?;
        if self.program.inventory_hash()? != before {
            return Err(ProviderError::Correlation(
                "native5 Capture moved original cut",
            ));
        }
        Ok(PacketOriginalCaptureComponent {
            owner: std::rc::Rc::clone(&self.capture_identity),
            creator: std::process::id(),
            request_hash: reservation
                .request
                .request_hash(RequestOrigin::Controller)?,
            inventory_hash: before,
            snapshot,
            anchor: (reference, bytes),
        })
    }

    /// Builds a prospective reply for the same stopped original capture.
    ///
    /// The enclosing endpoint must finish its own complete snapshot and preflight
    /// every proof frame before settling this reply. A reply value alone grants
    /// no installed native capture or fresh-adoption authority.
    ///
    /// # Errors
    /// Refuses a foreign component, changed native inventory, replaced original
    /// reservation, invalid complete snapshot reference or exhausted frame credit.
    pub fn original_capture_reply(
        &self,
        reservation: &PacketOriginalCaptureReservation,
        component: &PacketOriginalCaptureComponent,
        complete_snapshot: &ContentRef,
    ) -> Result<PacketControlReply, ProviderError> {
        self.authenticate_capture_component(reservation, component)?;
        complete_snapshot.validate()?;
        if complete_snapshot == &component.anchor.0 {
            return Err(ProviderError::Correlation("native5 snapshot/anchor alias"));
        }
        let result = CaptureResult {
            capture_manifest: complete_snapshot.clone(),
            owner_state_refs: vec![component.snapshot.reference().clone()],
            unchanged_cut_receipt: component.anchor.0.clone(),
        };
        result.validate()?;
        let reply = PacketControlReply {
            body: object(ResponseShape::Completed {
                operation_state: OperationState::Completed,
                result: object(result)?,
                extensions: Extensions::new(),
            })?,
            evidence: Vec::new(),
        };
        crate::connection::serialized_credit(&reply.body, FRAME)?;
        self.authenticate_capture_component(reservation, component)?;
        Ok(reply)
    }

    /// Settles only the same original pending Capture after whole-prefix preflight.
    ///
    /// The caller retains all original endpoint and proof-prefix custody. Native
    /// completion does not establish successful publication; partial writes must
    /// hold that endpoint and cannot produce a capture settlement token.
    ///
    /// # Errors
    /// Refuses changed originals, forged prospective replies or another component.
    pub fn settle_original_capture(
        &mut self,
        reservation: &PacketOriginalCaptureReservation,
        component: &PacketOriginalCaptureComponent,
        complete_snapshot: &ContentRef,
        prospective: &PacketControlReply,
    ) -> Result<(), ProviderError> {
        let expected = self.original_capture_reply(reservation, component, complete_snapshot)?;
        if prospective.body != expected.body || prospective.evidence != expected.evidence {
            return Err(ProviderError::Correlation(
                "native5 Capture prospective reply changed",
            ));
        }
        let request = reservation
            .request
            .request_id
            .0
            .as_ref()
            .ok_or(ProviderError::Frame("native5 Capture request absent"))?;
        let operation = reservation
            .request
            .operation_id
            .0
            .as_ref()
            .ok_or(ProviderError::Frame("native5 Capture operation absent"))?;
        let identity = reservation
            .request
            .request_hash(RequestOrigin::Controller)?;
        let terminal = expected.body.clone();
        self.originals.insert(request.clone(), (identity, expected));
        self.terminals.insert(operation.clone(), terminal);
        self.current_operation = None;
        Ok(())
    }

    fn authenticate_capture_component(
        &self,
        reservation: &PacketOriginalCaptureReservation,
        component: &PacketOriginalCaptureComponent,
    ) -> Result<(), ProviderError> {
        if component.creator != std::process::id() {
            return Err(ProviderError::Correlation(
                "native5 component foreign creator",
            ));
        }
        self.authenticate_capture_reservation(reservation)?;
        if !std::rc::Rc::ptr_eq(&self.capture_identity, &component.owner)
            || component.request_hash
                != reservation
                    .request
                    .request_hash(RequestOrigin::Controller)?
            || component.snapshot.administrative_cut() != reservation.arguments.cut
            || self.program.inventory_hash()? != component.inventory_hash
        {
            return Err(ProviderError::Correlation(
                "native5 original component changed",
            ));
        }
        component
            .snapshot
            .reference()
            .verify(component.snapshot.bytes())?;
        component.anchor.0.verify(&component.anchor.1)?;
        self.authenticate_capture_reservation(reservation)
    }

    fn authenticate_capture_reservation(
        &self,
        reservation: &PacketOriginalCaptureReservation,
    ) -> Result<(), ProviderError> {
        if self.capture_creator != std::process::id() || reservation.creator != std::process::id() {
            return Err(ProviderError::Correlation(
                "native5 Capture foreign creator",
            ));
        }
        if !std::rc::Rc::ptr_eq(&self.capture_identity, &reservation.owner) {
            return Err(ProviderError::Correlation(
                "native5 Capture original owner changed",
            ));
        }
        let request = reservation
            .request
            .request_id
            .0
            .as_ref()
            .ok_or(ProviderError::Frame("native5 Capture request absent"))?;
        let operation = reservation
            .request
            .operation_id
            .0
            .as_ref()
            .ok_or(ProviderError::Frame("native5 Capture operation absent"))?;
        let retained = self
            .originals
            .get(request)
            .ok_or(ProviderError::Correlation(
                "native5 Capture reservation missing",
            ))?;
        if retained.0
            != reservation
                .request
                .request_hash(RequestOrigin::Controller)?
            || self.begins.get(operation) != Some(&reservation.begin)
            || self.begin_requests.get(operation) != Some(request)
            || self.current_operation.as_ref() != Some(operation)
            || retained.1.body.get("operation_state") != Some(&Value::String("unknown".into()))
            || !retained.1.evidence.is_empty()
            || self.fenced
        {
            return Err(ProviderError::Correlation(
                "native5 Capture reservation changed",
            ));
        }
        Ok(())
    }
}

#[path = "capture_startup.rs"]
mod startup;
pub(crate) use startup::{
    NativeStartupCaptureRegistrationData, NativeStartupCaptureReply,
    original_startup_capture_counter_scratch_data, startup_capture_terminal_cache_storage_data,
};

pub(in crate::reference_packet::control) use startup::StartupRequestIdentity;
