//! Original CNP lifecycle and grant dispatch beneath the actual packet program.
//!
//! The independent installer supplies the complete selected tuple. This native
//! dispatcher does not install acceptance policy or issue host qualification.
//! Initial readiness describes its genuine unopened gate; only a complete
//! original activation manifest opens it. No optional preservation/CPU route is
//! inferred from CNP method syntax or a successful response.

use std::collections::BTreeMap;

use crucible_node_contract::*;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::{
    ProviderError,
    bodies::*,
    envelope::{Envelope, Method, Nullable, RequestOrigin},
};

use super::{PacketGrant, PacketInventory, PacketProgram};

mod capture;
mod continuation;
pub use capture::{PacketOriginalCaptureComponent, PacketOriginalCaptureReservation};
mod input;
mod native5;

pub use native5::{
    PacketNative5Record, PacketNative5StorageSelection, PacketNative5UnderlyingRecord,
};

pub use continuation::{
    PacketDecodedControlSnapshot, PacketOriginalControlSnapshot, decode_packet_control_snapshot,
};
mod program;

use program::NativeProgram;

const FRAME: usize = 65_536;
const ORIGINALS: usize = 256;
const OBJECTS: usize = 256;
const CONTENT_BYTES: usize = 4 * 1024 * 1024;

/// Defines the complete independently installed original native control scope.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketControlSelection {
    /// Names the actual source-selected provider implementation and formats.
    pub provider: ProviderManifest,
    /// Names the complete unchanged realized descriptors, bindings and owners.
    pub realization: RealizationManifest,
    /// Retains the original host-selected realization request.
    pub realize: RealizeRequest,
    /// Names the actual closed native preparation.
    pub prepared_token: Id,
    /// Names the independent host admission, checked before staging.
    pub admission: Id,
    /// Names the exact complete transaction, without granting host publication.
    pub transaction: Id,
    /// Names the original actual native gate.
    pub gate: Id,
    /// Binds the complete source-installed world, never a request-selected subset.
    pub world: HashRef,
    /// Names the independently expected host admission body.
    pub admission_receipt: ContentRef,
}

/// Retains native original proof bytes without turning their syntax into authority.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNativeRecord {
    /// Names the distinct versioned source-native dialect.
    pub schema: String,
    /// Names the actual native process that constructed this original record.
    pub native_pid: U64,
    /// Retains the actual original CNP request identity and body.
    pub original: Envelope,
    /// Retains the actual complete native callback/output inventory.
    pub inventory: PacketInventory,
    /// Retains an actual complete original grant, or null for nonexecuting reads.
    pub grant: Option<PacketGrant>,
}

/// Retains one actual original response and complete source-native proof objects.
pub struct PacketControlReply {
    /// Contains the complete original baseline response body.
    pub body: Map<String, Value>,
    /// Contains full immutable original source proofs for the CNP blob channel.
    pub evidence: Vec<(ContentRef, Vec<u8>)>,
}

// A failed preparation cannot authorize a second publication or callback.
// The source owner retains its original Unknown reservation independently of
// whatever correlation the transport preparation managed to reserve.
type PrepareReply<'a> = dyn FnMut(&PacketControlReply) -> Result<(), ProviderError> + 'a;

struct ReplyPreparation<'a> {
    callback: Option<&'a mut PrepareReply<'a>>,
    attempted: bool,
}

impl ReplyPreparation<'_> {
    fn prepare(
        &mut self,
        reply: &PacketControlReply,
        fenced: &mut bool,
    ) -> Result<(), ProviderError> {
        if let Some(callback) = self.callback.as_mut() {
            if self.attempted {
                return Err(ProviderError::Conflict("packet original prepared twice"));
            }
            self.attempted = true;
            // The native owner survives an unwinding endpoint callback. Only a
            // successful preparation restores its prior dispatch eligibility.
            let previous_fence = *fenced;
            *fenced = true;
            callback(reply)?;
            *fenced = previous_fence;
        }
        Ok(())
    }
}

/// Owns the native packet source, all initial/global gates and immutable originals.
pub struct PacketControl {
    selection: PacketControlSelection,
    program: NativeProgram,
    // These private lifetime facts authenticate the same capture owner. Fresh
    // constructors create new anchors; portable snapshot data cannot mint one.
    capture_creator: u32,
    capture_identity: std::rc::Rc<()>,
    originals: BTreeMap<Id, (HashRef, PacketControlReply)>,
    begins: BTreeMap<Id, BeginRequest>,
    begin_requests: BTreeMap<Id, Id>,
    content: BTreeMap<ContentRef, Vec<u8>>,
    content_bytes: usize,
    realized: bool,
    admitted: bool,
    staged: Option<(ActivateRequest, ContentRef)>,
    active: Option<WorldActivateRequest>,
    fenced: bool,
    native_effect_attempted: bool,
    immediate: bool,
    current_operation: Option<Id>,
    terminals: BTreeMap<Id, Map<String, Value>>,
    common_coordinator: Option<super::coordinator::PacketCoordinatorInstallation>,
    world_coordinator: Option<super::coordinator::PacketWorldCoordinatorInstallation>,
    connected_coordinator: Option<super::coordinator::PacketConnectedCoordinatorInstallation>,
    complete_coordinator: Option<super::coordinator::PacketNative5CoordinatorInstallation>,
    complete_storage: Option<native5::PacketNative5StorageSelection>,
}

impl PacketControl {
    pub(super) fn install_common_coordinator(
        &mut self,
        installed: super::coordinator::PacketCoordinatorInstallation,
    ) -> Result<(), ProviderError> {
        self.endpoint_scope()?;
        if self.common_coordinator.is_some()
            || self.world_coordinator.is_some()
            || self.connected_coordinator.is_some()
        {
            return Err(ProviderError::Correlation(
                "packet coordinator already installed",
            ));
        }
        installed.validate(&self.selection)?;
        self.common_coordinator = Some(installed);
        Ok(())
    }

    pub(super) fn install_world_coordinator(
        &mut self,
        installed: super::coordinator::PacketWorldCoordinatorInstallation,
    ) -> Result<(), ProviderError> {
        self.endpoint_scope()?;
        if self.common_coordinator.is_some()
            || self.world_coordinator.is_some()
            || self.connected_coordinator.is_some()
        {
            return Err(ProviderError::Correlation(
                "packet coordinator already installed",
            ));
        }
        installed.validate(&self.selection)?;
        self.world_coordinator = Some(installed);
        Ok(())
    }

    pub(super) fn install_connected_coordinator(
        &mut self,
        installed: super::coordinator::PacketConnectedCoordinatorInstallation,
    ) -> Result<(), ProviderError> {
        self.endpoint_scope()?;
        if self.common_coordinator.is_some()
            || self.world_coordinator.is_some()
            || self.connected_coordinator.is_some()
        {
            return Err(ProviderError::Correlation(
                "packet coordinator already installed",
            ));
        }
        installed.validate(&self.selection)?;
        self.connected_coordinator = Some(installed);
        Ok(())
    }

    pub(super) fn endpoint_scope(&self) -> Result<&PacketControlSelection, ProviderError> {
        if !self.immediate || self.fenced || self.realized || !self.program.inventory()?.gate_closed
        {
            return Err(ProviderError::Correlation(
                "packet endpoint requires original unopened source2",
            ));
        }
        Ok(&self.selection)
    }

    /// Takes complete source-installed scope and genuine unopened native custody.
    ///
    /// # Errors
    /// Refuses malformed, heterogeneous or changed source/native initial state.
    pub fn new(
        selection: PacketControlSelection,
        program: PacketProgram,
    ) -> Result<Self, ProviderError> {
        Self::new_native(selection, NativeProgram::OutputOnly(program))
    }

    fn new_native(
        selection: PacketControlSelection,
        program: NativeProgram,
    ) -> Result<Self, ProviderError> {
        selection.provider.validate()?;
        selection.realization.validate()?;
        selection.realize.validate()?;
        selection.world.validate()?;
        let realization = &selection.realization;
        let actual_configuration = reference(&encode(&program.configuration()?)?)?;
        if realization.bindings.len() != 1
            || realization.owners.len() != 1
            || realization.descriptors.len() != 1
            || realization.owner_bindings.len() != 1
            || realization.realization_id != selection.realize.realization_id
            || realization.provider_manifest != reference(&encode(&selection.provider)?)?
            || selection.realize.requested_node_ids != [realization.descriptors[0].id.clone()]
            || selection.realize.configuration != actual_configuration
            || realization.bindings[0].compatibility.configuration_ref != actual_configuration
            || realization.descriptors[0].model_ref != actual_configuration
            || !program.inventory()?.gate_closed
            || !program.inventory()?.retained_outputs.is_empty()
        {
            return Err(ProviderError::Correlation(
                "packet complete installed native scope",
            ));
        }
        Ok(Self {
            selection,
            program,
            capture_creator: std::process::id(),
            capture_identity: std::rc::Rc::new(()),
            originals: BTreeMap::new(),
            begins: BTreeMap::new(),
            begin_requests: BTreeMap::new(),
            content: BTreeMap::new(),
            content_bytes: 0,
            realized: false,
            admitted: false,
            staged: None,
            active: None,
            fenced: false,
            native_effect_attempted: false,
            immediate: false,
            current_operation: None,
            terminals: BTreeMap::new(),
            common_coordinator: None,
            world_coordinator: None,
            connected_coordinator: None,
            complete_coordinator: None,
            complete_storage: None,
        })
    }

    /// Installs the distinct immediate-original dialect with read-only polling.
    ///
    /// The complete native callback and result are prebuilt and executed under
    /// the original Begin. Poll and cancel only query retained originals. The
    /// earlier deferred component dialect remains separate and unqualified.
    ///
    /// # Errors
    /// Refuses an absent explicit source-owned packet receipt edition 2, or any
    /// invalid/changed initial native selection rejected by the base constructor.
    pub fn new_immediate(
        selection: PacketControlSelection,
        program: PacketProgram,
    ) -> Result<Self, ProviderError> {
        Self::new_immediate_profile(selection, program, "source-owned.packet-emitter/2")
    }

    /// Constructs the explicit immediate world dialect under its complete coordinator.
    ///
    /// # Errors
    /// Refuses a foreign local source, incomplete world, wrong world profile or
    /// changed native program. The original gate remains unopened throughout.
    pub(super) fn new_world_immediate(
        selection: PacketControlSelection,
        program: PacketProgram,
        world: super::coordinator::PacketWorldCoordinatorInstallation,
    ) -> Result<Self, ProviderError> {
        world.validate(&selection)?;
        let mut native =
            Self::new_immediate_profile(selection, program, "source-owned.packet-emitter-world/3")?;
        native.install_world_coordinator(world)?;

        Ok(native)
    }

    fn new_immediate_profile(
        selection: PacketControlSelection,
        program: PacketProgram,
        profile_id: &str,
    ) -> Result<Self, ProviderError> {
        let definition = reference(&super::contracts::immediate_packet_contract()?)?;
        let configuration = program.definition();
        let descriptor = selection.realization.descriptors.first();
        let profile = selection.provider.supported_profiles.first();
        if !selection
            .provider
            .implementation
            .formats
            .iter()
            .any(|format| {
                format.id.as_str() == "source-owned.packet-receipt/2"
                    && format.version == 2
                    && format.definition == definition
            })
            || selection.provider.supported_profiles.len() != 1
            || profile.is_none_or(|profile| {
                profile.profile_id.as_str() != profile_id
                    || profile.roles.len() != 1
                    || profile.roles[0].as_str() != "external_device"
                    || profile.configuration_schema.id.as_str() != "source-owned.packet-program/1"
                    || profile.configuration_schema.version != 1
                    || profile.configuration_schema.definition != definition
            })
            || descriptor.is_none_or(|descriptor| {
                descriptor.roles.len() != 1
                    || descriptor.roles[0].as_str() != "external_device"
                    || descriptor.ports.len() != 1
                    || descriptor.ports[0].lanes.len() != 1
                    || descriptor.ports[0].lanes[0].direction != Direction::Output
                    || descriptor.ports[0].lanes[0].payload_schema.id.as_str()
                        != "source-owned.packet-octets/1"
                    || descriptor.ports[0].lanes[0].payload_schema.version != 1
                    || descriptor.ports[0].lanes[0].payload_schema.definition != definition
                    || descriptor.ports[0].lanes[0].maximum_payload_bytes.get() != 32
                    || descriptor.ports[0].lanes[0].maximum_pending_events.get() != 1
            })
            || configuration.events.len() != 2
            || configuration.events[0].payload.is_some()
            || configuration.events[1].payload.is_none()
            || configuration.events[1]
                .payload
                .as_ref()
                .is_some_and(|payload| payload.as_slice().len() > 32)
            || configuration.events[0].evaluation != configuration.events[0].completion
            || configuration.events[0].evaluation >= configuration.events[1].evaluation
            || configuration.events[1].completion <= configuration.events[1].evaluation
            || configuration
                .events
                .iter()
                .any(|event| event.evaluation.phase != Phase::Reaction)
            || configuration.events[1].completion.phase != Phase::Publication
        {
            return Err(ProviderError::Correlation(
                "packet immediate dialect not selected",
            ));
        }
        let mut control = Self::new(selection, program)?;
        control.immediate = true;
        Ok(control)
    }

    /// Constructs the distinct phased connected native dialect beneath a closed gate.
    ///
    /// This constructor grants no host admission or class qualification. Its
    /// caller independently installs the complete measured source selection;
    /// the original all-owner barrier must still authenticate gate opening.
    ///
    /// # Errors
    /// Refuses a missing explicit connected edition, changed configuration or
    /// invalid original source tuple. Unsupported control routes remain closed.
    pub fn new_connected(
        selection: PacketControlSelection,
        program: super::connected::PacketConnectedProgram,
    ) -> Result<Self, ProviderError> {
        let expected = super::contracts::connected_packet_contract()?;
        let definition = reference(&expected)?;
        if selection.provider.supported_profiles.len() != 1
            || selection.provider.supported_profiles[0].profile_id.as_str()
                != "source-owned.packet-connected/4"
            || !selection
                .provider
                .implementation
                .formats
                .iter()
                .any(|format| {
                    format.id.as_str() == "source-owned.packet-receipt/4"
                        && format.version == 4
                        && format.definition == definition
                        && format.extensions.is_empty()
                })
        {
            return Err(ProviderError::Correlation(
                "packet connected edition not installed",
            ));
        }
        let mut control = Self::new_native(selection, NativeProgram::Connected(program))?;
        control.immediate = true;
        Ok(control)
    }

    /// Installs a connected native interpreter under the complete original world.
    ///
    /// # Errors
    /// Refuses undeclared routes, a changed source selection or another coordinator.
    pub fn new_connected_world(
        selection: PacketControlSelection,
        program: super::connected::PacketConnectedProgram,
        coordinator: super::coordinator::PacketConnectedCoordinatorInstallation,
    ) -> Result<Self, ProviderError> {
        coordinator.validate(&selection)?;
        let world: WorldBinding = serde_json::from_value(coordinator.template["world"].clone())
            .map_err(ContractError::from)?;
        let node = &selection.realization.descriptors[0].id;
        let incoming = world
            .connections
            .iter()
            .filter(|route| &route.consumer.node_id == node)
            .collect::<Vec<_>>();
        if incoming.len() != program.definition().connections.len()
            || program.definition().connections.iter().any(|native| {
                incoming.iter().all(|route| {
                    route.id != native.id
                        || route.policy_ref != native.policy
                        || route.producer != native.producer
                        || route.consumer != native.consumer
                        || route.minimum_latency_ps != native.delay_ps
                })
            })
        {
            return Err(ProviderError::Correlation(
                "packet native routes differ from installed world",
            ));
        }
        let mut native = Self::new_connected(selection, program)?;
        native.install_connected_coordinator(coordinator)?;
        Ok(native)
    }

    /// Installs the unchanged source-2 producer inside a connected original world.
    ///
    /// # Errors
    /// Refuses source-2 profile changes, an incomplete roster or another coordinator.
    pub fn new_producer_in_connected_world(
        selection: PacketControlSelection,
        program: PacketProgram,
        coordinator: super::coordinator::PacketConnectedCoordinatorInstallation,
    ) -> Result<Self, ProviderError> {
        coordinator.validate(&selection)?;
        let mut native =
            Self::new_immediate_profile(selection, program, "source-owned.packet-emitter-world/3")?;
        native.install_connected_coordinator(coordinator)?;
        Ok(native)
    }

    /// Retains verified inert original content before a consuming native operation.
    ///
    /// # Errors
    /// Refuses changed bytes, conflicting originals or exhausted complete credit.
    pub fn install_content(
        &mut self,
        object: ContentRef,
        bytes: &[u8],
    ) -> Result<(), ProviderError> {
        if (self.connected_coordinator.is_some() || self.complete_coordinator.is_some())
            && bytes.len() > super::coordinator::PACKET_CONNECTED_COORDINATOR_BYTES
        {
            return Err(ProviderError::ResourceExhausted(
                "packet complete connected content",
            ));
        }
        object.verify(bytes)?;
        if let Some(original) = self.content.get(&object) {
            return if original == bytes {
                Ok(())
            } else {
                Err(ProviderError::Conflict("packet original content"))
            };
        }
        let total = self
            .content_bytes
            .checked_add(bytes.len())
            .ok_or(ProviderError::ResourceExhausted("packet content bytes"))?;
        // Only explicitly installed connected-four/complete-five coordinators need the larger
        // complete coordinator object. Socket frames and old profiles stay fixed;
        // every byte remains charged to the same original total content ledger.
        let maximum_object =
            if self.connected_coordinator.is_some() || self.complete_coordinator.is_some() {
                super::coordinator::PACKET_CONNECTED_COORDINATOR_BYTES
            } else {
                FRAME
            };
        if self.content.len() >= OBJECTS || total > CONTENT_BYTES || bytes.len() > maximum_object {
            return Err(ProviderError::ResourceExhausted(
                "packet complete native content",
            ));
        }
        self.content.insert(object, bytes.to_vec());
        self.content_bytes = total;
        Ok(())
    }

    /// Copies the administrative native projection without executing a callback.
    ///
    /// Connected input/phase proof uses its separate complete native record.
    ///
    /// # Errors
    /// Refuses failed or foreign originating-process custody for connected sources.
    pub fn inventory(&self) -> Result<PacketInventory, ProviderError> {
        self.program.inventory()
    }

    /// Borrows an original native response for independent source custody checks.
    pub fn original(&self, request: &Id) -> Option<&PacketControlReply> {
        self.originals.get(request).map(|(_, reply)| reply)
    }

    /// Dispatches one actual original baseline CNP request under selected source scope.
    ///
    /// Identical originals return their retained response/proof population. No
    /// receipt reconstruction, changed Begin retry or output retirement can run
    /// another callback. A native error fences subsequent new dispatches.
    ///
    /// # Errors
    /// Refuses oversized/invalid/foreign requests, changed originals, exhausted
    /// journal/body credit, unavailable dependencies or unsupported native facets.
    /// Native failures retain the original unknown result and complete custody.
    pub fn dispatch(&mut self, request: &Envelope) -> Result<&PacketControlReply, ProviderError> {
        self.dispatch_prepared(
            request,
            &mut ReplyPreparation {
                callback: None,
                attempted: false,
            },
        )
    }

    /// Prepares the complete original reply before source-2 native effects.
    ///
    /// The installed endpoint supplies a same-connection preparation callback.
    /// It must retain complete canonical response and evidence-transfer bodies
    /// before returning success. The callback receives prospective source data,
    /// not permission to publish it. Publication follows successful native
    /// execution and equality with the reserved original result. A preparation
    /// error fences this dispatcher and retains its original Unknown; native
    /// custody remains owned here rather than passing to the transport guard.
    /// The deferred source-1 component cannot use this execution seam.
    ///
    /// # Errors
    /// Refuses another source dialect, invalid requests or native dispatch,
    /// failed preparation, and original/body capacity exhaustion. A callback
    /// error grants neither rollback nor permission to reexecute an original.
    ///
    /// # Panics
    /// Installed preparation or source callbacks may panic. The caller must
    /// retain this borrowed dispatcher and its original native custody across
    /// unwind; a panic does not authorize reexecution or imply rollback.
    pub fn dispatch_with_preflight(
        &mut self,
        request: &Envelope,
        prepare: &mut dyn FnMut(&PacketControlReply) -> Result<(), ProviderError>,
    ) -> Result<&PacketControlReply, ProviderError> {
        if !self.immediate {
            return Err(ProviderError::Correlation("packet prepared source dialect"));
        }
        self.dispatch_prepared(
            request,
            &mut ReplyPreparation {
                callback: Some(prepare),
                attempted: false,
            },
        )
    }

    fn dispatch_prepared(
        &mut self,
        request: &Envelope,
        preparation: &mut ReplyPreparation<'_>,
    ) -> Result<&PacketControlReply, ProviderError> {
        if self.capture_creator != std::process::id() {
            return Err(ProviderError::Correlation(
                "packet original dispatch foreign creator",
            ));
        }
        if self.complete_coordinator.is_some() && self.complete_storage.is_none() {
            return Err(ProviderError::Correlation(
                "native5 original storage birth is unbound",
            ));
        }
        encode(request)?;
        request.validate()?;
        let id = request
            .request_id
            .0
            .as_ref()
            .ok_or(ProviderError::Frame("packet original request absent"))?
            .clone();
        let identity = request.request_hash(RequestOrigin::Controller)?;
        if let Some((original, _)) = self.originals.get(&id) {
            if original != &identity {
                return Err(ProviderError::Conflict("packet original request changed"));
            }
            let reply = &self
                .originals
                .get(&id)
                .ok_or(ProviderError::Frame("packet original response absent"))?
                .1;
            if let Err(error) = preparation.prepare(reply, &mut self.fenced) {
                self.fenced = true;
                return Err(error);
            }
            return Ok(reply);
        }
        if self.fenced || self.originals.len() >= ORIGINALS {
            return Err(ProviderError::ResourceExhausted(
                "packet original native dispatch",
            ));
        }
        let binding = &self.selection.realization.bindings[0];
        if request.session_id.0.as_ref() != Some(&binding.authority.session_id)
            || request.incarnation_id.0.as_ref() != Some(&binding.authority.incarnation_id)
            || request
                .node_id
                .0
                .as_ref()
                .is_some_and(|node| node != &binding.compatibility.node_id)
            || request
                .execution_owner_id
                .0
                .as_ref()
                .is_some_and(|owner| owner != &self.selection.realization.owners[0].id)
            || request.capture_owner_id.0.is_some()
            || (!request.extensions.is_empty()
                && !(self.program.is_connected() && request.method == Method::Input))
        {
            return Err(ProviderError::Correlation("packet original native route"));
        }
        let decoded = decode_request(request.method, &request.body)?;
        if self.program.is_connected() && request.method == Method::Input {
            super::input::PacketInputContext::decode(&request.extensions)?;
        }
        // Reserve the original unknown response before any setter or callback.
        self.originals.insert(
            id.clone(),
            (
                identity,
                PacketControlReply {
                    body: object(ResponseShape::Error {
                        operation_state: OperationState::Unknown,
                        error: ErrorRecord {
                            code: "OUTCOME_UNKNOWN".into(),
                            message: "original native dispatch remains unresolved".into(),
                            effect: EffectCertainty::Unknown,
                            retryable: false,
                            details: Map::new(),
                        },
                        extensions: Extensions::new(),
                    })?,
                    evidence: Vec::new(),
                },
            ),
        );
        self.native_effect_attempted = false;
        let result = self.execute(request, decoded, preparation);
        match result {
            Ok(reply) => {
                if !preparation.attempted
                    && let Err(error) = preparation.prepare(&reply, &mut self.fenced)
                {
                    self.fenced = true;
                    return Err(error);
                }
                let original = self
                    .originals
                    .get_mut(&id)
                    .ok_or(ProviderError::Frame("packet original reservation absent"))?;
                original.1 = reply;
                Ok(&original.1)
            }
            Err(error) => {
                if self.native_effect_attempted || preparation.attempted {
                    self.fenced = true;
                    return Err(error);
                }
                let body = object(ResponseShape::Error {
                    operation_state: OperationState::NotStarted,
                    error: ErrorRecord {
                        code: "INVALID_STATE".into(),
                        message: error.to_string(),
                        effect: EffectCertainty::NotStarted,
                        retryable: false,
                        details: Map::new(),
                    },
                    extensions: Extensions::new(),
                })?;
                let original = self.originals.get_mut(&id).ok_or(ProviderError::Frame(
                    "packet original refusal reservation absent",
                ))?;
                let refused = PacketControlReply {
                    body,
                    evidence: Vec::new(),
                };
                if let Err(error) = preparation.prepare(&refused, &mut self.fenced) {
                    self.fenced = true;
                    return Err(error);
                }
                original.1 = refused;
                Ok(&original.1)
            }
        }
    }

    fn proof(
        &mut self,
        request: &Envelope,
        grant: Option<PacketGrant>,
    ) -> Result<(ContentRef, Vec<u8>), ProviderError> {
        self.retain_record(request, self.program.inventory()?, grant)
    }

    fn retain_record(
        &mut self,
        request: &Envelope,
        inventory: PacketInventory,
        grant: Option<PacketGrant>,
    ) -> Result<(ContentRef, Vec<u8>), ProviderError> {
        let bytes = if let Some(record) =
            self.program
                .connected_record(request, &inventory, grant.as_ref())?
        {
            encode(&record)?
        } else {
            encode(&PacketNativeRecord {
                schema: if self.immediate {
                    "source-owned.packet-native/2"
                } else {
                    "source-owned.packet-native/1"
                }
                .into(),
                native_pid: U64::new(u64::from(std::process::id())),
                original: request.clone(),
                inventory,
                grant,
            })?
        };
        let raw = reference(&bytes)?;
        self.install_content(raw.clone(), &bytes)?;
        if self.complete_coordinator.is_some() {
            return self.retain_complete_record(request, raw);
        }
        Ok((raw, bytes))
    }

    fn execute(
        &mut self,
        request: &Envelope,
        body: RequestBody,
        preparation: &mut ReplyPreparation<'_>,
    ) -> Result<PacketControlReply, ProviderError> {
        if request.body.get("extensions").is_some_and(|extensions| {
            extensions
                .as_object()
                .is_none_or(|fields| !fields.is_empty())
        }) {
            return Err(ProviderError::Correlation(
                "packet native body extensions unsupported",
            ));
        }
        let owners = vec![self.selection.realization.owners[0].id.clone()];
        match body {
            RequestBody::Discover(discover) => {
                if discover.cursor.is_some()
                    || discover.profile_ids.iter().any(|requested| {
                        !self
                            .selection
                            .provider
                            .supported_profiles
                            .iter()
                            .any(|profile| &profile.profile_id == requested)
                    })
                    || !discover.extensions.is_empty()
                {
                    return Err(ProviderError::Correlation(
                        "packet required profile unsupported",
                    ));
                }
                reply(
                    DiscoverResult {
                        provider_manifest: self.selection.provider.clone(),
                        profiles: self.selection.provider.supported_profiles.clone(),
                        facet_schemas: self.selection.provider.implementation.formats.clone(),
                        complete: true,
                        next_cursor: Nullable(None),
                    },
                    vec![],
                )
            }
            RequestBody::Realize(realize) => {
                if self.realized || realize != self.selection.realize {
                    return Err(ProviderError::Correlation("packet original realization"));
                }
                let proof = self.proof(request, None)?;
                self.realized = true;
                reply(
                    RealizeResult {
                        realization_manifest: self.selection.realization.clone(),
                        prepared_token: self.selection.prepared_token.clone(),
                        closed_gate_receipt: proof.0.clone(),
                    },
                    self.record_evidence(proof)?,
                )
            }
            RequestBody::Admit(admit) => {
                if !self.realized
                    || self.admitted
                    || admit.bindings != self.selection.realization.bindings
                    || admit.world_binding_hash != self.selection.world
                    || admit.admission_receipt != self.selection.admission_receipt
                {
                    return Err(ProviderError::Correlation("packet original host admission"));
                }
                self.admitted = true;
                reply(
                    AdmitResult {
                        accepted_binding_hashes: vec![
                            self.selection.realization.bindings[0].identity()?,
                        ],
                        admission_id: self.selection.admission.clone(),
                    },
                    vec![],
                )
            }
            RequestBody::Activate(activate) => {
                if !self.admitted
                    || self.staged.is_some()
                    || activate.admission_id != self.selection.admission
                    || activate.prepared_token != self.selection.prepared_token
                    || activate.world_binding_hash != self.selection.world
                    || activate.gate_id != self.selection.gate
                    || !self.program.inventory()?.gate_closed
                {
                    return Err(ProviderError::Correlation(
                        "packet original nonexecuting activation",
                    ));
                }
                let proof = self.proof(request, None)?;
                self.staged = Some((activate, proof.0.clone()));
                reply(
                    ActivateResult {
                        staged: true,
                        gate_id: self.selection.gate.clone(),
                        staged_owner_ids: owners,
                        activation_receipt: proof.0.clone(),
                    },
                    self.record_evidence(proof)?,
                )
            }
            RequestBody::WorldActivate(activate) => {
                self.activate_world(request, activate, preparation)
            }
            RequestBody::Begin(begin) => self.begin(request, begin, preparation),
            RequestBody::Input(input) => self.input(request, input),
            RequestBody::Poll(_) => self.poll(request),
            RequestBody::Cancel(_) => self.cancel(request),
            RequestBody::Observe(observe) => self.observe(request, observe),
            RequestBody::Retire(retire) => self.retire(retire),
            // The installed source has no ingress or optional state/mutation
            // facet. Unsupported syntax cannot fabricate another native path.
            _ => Err(ProviderError::Correlation(
                "packet selected native method unsupported",
            )),
        }
    }

    fn activate_world(
        &mut self,
        request: &Envelope,
        activate: WorldActivateRequest,
        preparation: &mut ReplyPreparation<'_>,
    ) -> Result<PacketControlReply, ProviderError> {
        let (staged, ready) = self
            .staged
            .as_ref()
            .ok_or(ProviderError::Correlation("packet original staging absent"))?;
        let bytes =
            self.content
                .get(&activate.activation_manifest)
                .ok_or(ProviderError::Correlation(
                    "packet complete original manifest absent",
                ))?;
        let manifest: ActivationManifest = canonical::decode(bytes, FRAME)?;
        let binding = &self.selection.realization.bindings[0];
        let expected_owner = PreparedOwner {
            owner_id: self.selection.realization.owners[0].id.clone(),
            incarnation_id: binding.authority.incarnation_id.clone(),
            owner_generation: binding.authority.owner_generation,
            binding_hashes: vec![binding.identity()?],
            prepared_token: self.selection.prepared_token.clone(),
            ready_receipt: ready.clone(),
            extensions: Extensions::new(),
        };
        if self.active.is_some()
            || activate.transaction_id != self.selection.transaction
            || activate.activation_id != staged.activation_id
            || activate.world_generation != staged.world_generation
            || activate.gate_id != self.selection.gate
            || activate.prepared_token != self.selection.prepared_token
            || activate.world_binding_hash != self.selection.world
            || manifest.transaction_id != activate.transaction_id
            || manifest.activation_id != activate.activation_id
            || manifest.world_generation != activate.world_generation
            || manifest.gate_id != activate.gate_id
            || manifest.world_binding_hash != activate.world_binding_hash
            || (self.world_coordinator.is_none()
                && self.connected_coordinator.is_none()
                && self.complete_coordinator.is_none()
                && manifest.owners != [expected_owner])
            || !self.content.contains_key(&manifest.coordinator_state_ref)
        {
            return Err(ProviderError::Correlation(
                "packet complete original all-owner activation",
            ));
        }
        if let Some(installed) = &self.common_coordinator {
            let coordinator = self.content.get(&manifest.coordinator_state_ref).ok_or(
                ProviderError::Correlation("packet common coordinator absent"),
            )?;
            installed.authenticate_staged(coordinator, &self.selection, staged, ready)?;
        }
        if let Some(installed) = &self.world_coordinator {
            let coordinator = self.content.get(&manifest.coordinator_state_ref).ok_or(
                ProviderError::Correlation("packet full-world coordinator absent"),
            )?;
            installed.authenticate_staged(
                coordinator,
                &self.selection,
                staged,
                ready,
                &manifest,
            )?;
        }
        if let Some(installed) = &self.connected_coordinator {
            let coordinator = self.content.get(&manifest.coordinator_state_ref).ok_or(
                ProviderError::Correlation("packet connected coordinator absent"),
            )?;
            installed.authenticate_staged(
                coordinator,
                &self.selection,
                staged,
                ready,
                &manifest,
            )?;
        }
        if let Some(installed) = &self.complete_coordinator {
            let coordinator = self.content.get(&manifest.coordinator_state_ref).ok_or(
                ProviderError::Correlation("native5 complete coordinator absent"),
            )?;
            installed.authenticate_staged(
                coordinator,
                &self.selection,
                staged,
                ready,
                &manifest,
            )?;
        }
        let mut inventory = self.program.inventory()?;
        inventory.gate_closed = false;
        let proof = self.retain_record(request, inventory, None)?;
        let response = reply(
            WorldActivateResult {
                armed_owner_ids: vec![self.selection.realization.owners[0].id.clone()],
                gate_id: self.selection.gate.clone(),
                activation_receipt: proof.0.clone(),
            },
            self.record_evidence(proof)?,
        )?;
        preparation.prepare(&response, &mut self.fenced)?;
        self.native_effect_attempted = true;
        self.program.open_gate()?;
        self.active = Some(activate);
        Ok(response)
    }

    fn begin(
        &mut self,
        request: &Envelope,
        begin: BeginRequest,
        preparation: &mut ReplyPreparation<'_>,
    ) -> Result<PacketControlReply, ProviderError> {
        let operation = request
            .operation_id
            .0
            .as_ref()
            .ok_or(ProviderError::Frame("packet original operation absent"))?;
        let active = self.active.as_ref().ok_or(ProviderError::Correlation(
            "packet original global gate closed",
        ))?;
        let arguments = match begin.decoded_arguments()? {
            BeginArguments::ExactRun(arguments) | BeginArguments::BoundarySettle(arguments) => {
                arguments
            }
            _ => return Err(ProviderError::Correlation("packet nonexact native grant")),
        };
        let binding = &self.selection.realization.bindings[0];
        if self.current_operation.is_some()
            || self.begins.len() >= 64
            || self.begins.contains_key(operation)
            || begin.binding_hash != self.selection.realization.owner_bindings[0].identity()?
            || begin.owner_generation != binding.authority.owner_generation
            || arguments.grant_id != *operation
            || arguments.participant_ids != self.selection.realization.owners[0].participant_ids
            || arguments.realization_id != self.selection.realize.realization_id
            || arguments.activation_id != active.activation_id
            || arguments.world_generation != active.world_generation
            || arguments.owner_generation != binding.authority.owner_generation
            || arguments.input_epoch != binding.authority.input_epoch
            || (!self.program.is_connected() && arguments.input_watermark.get() != 0)
            || arguments.boundary_policy != BoundaryPolicy::OrdinaryStop
            || !self.content.contains_key(&arguments.input_authorization)
            || arguments.start != self.program.inventory()?.reached
        {
            return Err(ProviderError::Correlation(
                "packet original native grant binding",
            ));
        }
        let input =
            self.content
                .get(&arguments.input_authorization)
                .ok_or(ProviderError::Correlation(
                    "packet original common authorization absent",
                ))?;
        if let Some(installed) = &self.complete_coordinator {
            let consumed =
                match &self.program {
                    NativeProgram::OutputOnly(_) => None,
                    NativeProgram::Connected(program) => {
                        let (record, reference) = program.committed_input()?;
                        let consumed_id = record.original.request_id.0.as_ref().ok_or(
                            ProviderError::Correlation("native5 original consumed request absent"),
                        )?;
                        let original =
                            self.originals
                                .get(consumed_id)
                                .ok_or(ProviderError::Correlation(
                                    "native5 original consumed response absent",
                                ))?;
                        let decoded =
                            decode_request(record.original.method, &record.original.body)?;
                        let response = decode_response(&decoded, &original.1.body)?;
                        if !matches!(response.result, Some(MethodResult::Input(_))) {
                            return Err(ProviderError::Correlation(
                                "native5 input commitment not completed",
                            ));
                        }
                        Some((record, reference))
                    }
                };
            super::common::PacketNative5CommonGrant::authenticate_live(
                super::common::LiveNative5Grant {
                    bytes: input,
                    selection: &self.selection,
                    active,
                    operation,
                    begin: &begin,
                    arguments: &arguments,
                    installed,
                    consumed,
                },
            )?;
        } else if let NativeProgram::Connected(program) = &self.program {
            let installed =
                self.connected_coordinator
                    .as_ref()
                    .ok_or(ProviderError::Correlation(
                        "packet original connected coordinator absent",
                    ))?;
            let (consumed, reference) = program.committed_input()?;
            let consumed_id =
                consumed
                    .original
                    .request_id
                    .0
                    .as_ref()
                    .ok_or(ProviderError::Correlation(
                        "packet original consumed request absent",
                    ))?;
            let original = self
                .originals
                .get(consumed_id)
                .ok_or(ProviderError::Correlation(
                    "packet original consumed response absent",
                ))?;
            let decoded = decode_request(consumed.original.method, &consumed.original.body)?;
            let response = decode_response(&decoded, &original.1.body)?;
            if !matches!(response.result, Some(MethodResult::Input(_))) {
                return Err(ProviderError::Correlation(
                    "packet input commitment not completed",
                ));
            }
            super::common::PacketConnectedCommonGrant::authenticate(
                input,
                &self.selection,
                active,
                operation,
                &begin,
                &arguments,
                installed,
                consumed,
                reference,
            )?;
        } else if let Some(installed) = &self.connected_coordinator {
            super::common::PacketCommonGrant::authenticate_connected_world(
                input,
                &self.selection,
                active,
                operation,
                &begin,
                &arguments,
                installed,
            )?;
        } else if let Some(installed) = &self.world_coordinator {
            super::common::PacketCommonGrant::authenticate_world(
                input,
                &self.selection,
                active,
                operation,
                &begin,
                &arguments,
                installed,
            )?;
        } else {
            super::common::PacketCommonGrant::authenticate(
                input,
                &self.selection,
                active,
                operation,
                &begin,
                &arguments,
            )?;
        }
        self.current_operation = Some(operation.clone());
        self.begins.insert(operation.clone(), begin.clone());
        self.begin_requests.insert(
            operation.clone(),
            request
                .request_id
                .0
                .as_ref()
                .ok_or(ProviderError::Frame("packet original Begin request absent"))?
                .clone(),
        );
        if self.immediate {
            return self.execute_original_begin(request, &arguments, preparation);
        }
        Ok(PacketControlReply {
            body: object(ResponseShape::Accepted {
                operation_state: OperationState::Running,
                result: object(BeginAccepted {
                    operation_id: operation.clone(),
                    kind: begin.kind,
                })?,
                extensions: Extensions::new(),
            })?,
            evidence: vec![],
        })
    }

    fn execute_original_begin(
        &mut self,
        request: &Envelope,
        arguments: &ExactRunArguments,
        preparation: &mut ReplyPreparation<'_>,
    ) -> Result<PacketControlReply, ProviderError> {
        let operation = request.operation_id.0.as_ref().ok_or(ProviderError::Frame(
            "packet immediate original operation absent",
        ))?;
        let prospective = self
            .program
            .preview(operation, arguments.start, arguments.limit)?;
        let proof = self.retain_record(
            request,
            prospective.inventory.clone(),
            Some(prospective.clone()),
        )?;
        let next_attention = Bound {
            kind: BoundKind::At,
            position: Some(self.program.attention(&prospective)?),
            evidence: Some(proof.0.clone()),
        };
        let terminal = object(ResponseShape::Completed {
            operation_state: OperationState::Completed,
            result: object(ExactRunResult {
                grant_id: operation.clone(),
                reached: prospective.inventory.reached,
                stop_reason: if prospective.inventory.reached == arguments.limit {
                    StopReason::Ceiling
                } else {
                    StopReason::Attention
                },
                stop_receipt: proof.0.clone(),
                observation_batch: proof.0.clone(),
                pending_inventory: proof.0.clone(),
                next_attention,
            })?,
            extensions: Extensions::new(),
        })?;
        let response = PacketControlReply {
            body: terminal.clone(),
            evidence: self.record_evidence(proof)?,
        };
        let native_operation = operation.clone();
        // Register every owned terminal/callback/body slot before the first
        // actual socket effect. Native failure keeps the original unknown fence.
        self.terminals.insert(native_operation.clone(), terminal);
        preparation.prepare(&response, &mut self.fenced)?;
        self.native_effect_attempted = true;
        let actual = self
            .program
            .execute(native_operation, arguments.start, arguments.limit)?;
        if actual != prospective {
            return Err(ProviderError::Correlation(
                "packet immediate actual result differs from reserved original",
            ));
        }
        Ok(response)
    }

    fn cancel(&mut self, request: &Envelope) -> Result<PacketControlReply, ProviderError> {
        let operation = request.operation_id.0.as_ref().ok_or(ProviderError::Frame(
            "packet cancel original operation absent",
        ))?;
        if !self.begins.contains_key(operation) {
            return Err(ProviderError::Correlation(
                "packet cancel original operation unknown",
            ));
        }
        let state = if self
            .program
            .original(operation)?
            .is_some_and(|original| original.complete)
        {
            OperationState::Completed
        } else {
            OperationState::Running
        };
        reply(
            CancelResult {
                cancel_requested: false,
                operation_state: state,
            },
            vec![],
        )
    }

    fn poll(&mut self, request: &Envelope) -> Result<PacketControlReply, ProviderError> {
        let operation = request
            .operation_id
            .0
            .as_ref()
            .ok_or(ProviderError::Frame("packet poll original absent"))?;
        if self.immediate {
            let terminal = self
                .terminals
                .get(operation)
                .ok_or(ProviderError::Correlation(
                    "packet original immediate completion absent",
                ))?;
            return reply(
                PollResult {
                    operation_id: operation.clone(),
                    operation_state: OperationState::Completed,
                    outcome: Nullable(Some(terminal.clone())),
                    observations: vec![],
                    next_observation_sequence: U64::new(1),
                },
                vec![],
            );
        }
        let begin = self
            .begins
            .get(operation)
            .ok_or(ProviderError::Correlation("packet original begin absent"))?;
        let arguments = match begin.decoded_arguments()? {
            BeginArguments::ExactRun(arguments) | BeginArguments::BoundarySettle(arguments) => {
                arguments
            }
            _ => return Err(ProviderError::Correlation("packet original poll type")),
        };
        let prospective = self
            .program
            .preview(operation, arguments.start, arguments.limit)?;
        let proof = self.retain_record(
            request,
            prospective.inventory.clone(),
            Some(prospective.clone()),
        )?;
        let next_attention = prospective.inventory.pending.first().map_or(
            Bound {
                kind: BoundKind::At,
                position: Some(prospective.inventory.reached),
                evidence: Some(proof.0.clone()),
            },
            |event| Bound {
                kind: BoundKind::At,
                position: Some(event.completion),
                evidence: Some(proof.0.clone()),
            },
        );
        let outcome = object(ResponseShape::Completed {
            operation_state: OperationState::Completed,
            result: object(ExactRunResult {
                grant_id: operation.clone(),
                reached: prospective.inventory.reached,
                stop_reason: StopReason::Ceiling,
                stop_receipt: proof.0.clone(),
                observation_batch: proof.0.clone(),
                pending_inventory: proof.0.clone(),
                next_attention,
            })?,
            extensions: Extensions::new(),
        })?;
        let response = reply(
            PollResult {
                operation_id: operation.clone(),
                operation_state: OperationState::Completed,
                outcome: Nullable(Some(outcome)),
                observations: vec![],
                next_observation_sequence: U64::new(1),
            },
            self.record_evidence(proof)?,
        )?;
        let native_operation = operation.clone();
        self.native_effect_attempted = true;
        let grant = self
            .program
            .execute(native_operation, arguments.start, arguments.limit)?;
        if grant != prospective {
            return Err(ProviderError::Correlation(
                "packet actual callback differs from reserved complete result",
            ));
        }
        Ok(response)
    }

    fn observe(
        &mut self,
        request: &Envelope,
        observe: ObserveRequest,
    ) -> Result<PacketControlReply, ProviderError> {
        let binding = &self.selection.realization.bindings[0];
        if observe.binding_hash != self.selection.realization.owner_bindings[0].identity()?
            || observe.owner_generation != binding.authority.owner_generation
            || observe.after_observation_sequence.get() != 0
            || observe.maximum_items.get() == 0
            || observe.maximum_items.get() > 64
            || !observe.extensions.is_empty()
        {
            return Err(ProviderError::Correlation(
                "packet original observation scope",
            ));
        }
        let active = self
            .active
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "packet observation before global activation",
            ))?
            .clone();
        let proof = self.proof(request, None)?;
        let binding = &self.selection.realization.bindings[0];
        let batch = ObservationBatch {
            schema_version: 1,
            execution_owner_id: self.selection.realization.owners[0].id.clone(),
            owner_binding_hash: self.selection.realization.owner_bindings[0].identity()?,
            world_binding_hash: self.selection.world.clone(),
            activation_id: active.activation_id,
            world_generation: active.world_generation,
            owner_generation: binding.authority.owner_generation,
            operation_id: request
                .request_id
                .0
                .as_ref()
                .ok_or(ProviderError::Frame("packet observation identity"))?
                .clone(),
            grant_id: None,
            first_sequence: U64::new(0),
            last_sequence: U64::new(0),
            events: vec![],
            visibility: Visibility::Staged,
            measurement_ref: proof.0.clone(),
            extensions: Extensions::new(),
        };
        reply(
            ObserveResult {
                observations: vec![batch],
                next_sequence: U64::new(1),
                complete: true,
                inventory_hash: self.program.inventory_hash()?,
            },
            self.record_evidence(proof)?,
        )
    }

    fn retire(&mut self, retire: RetireRequest) -> Result<PacketControlReply, ProviderError> {
        if retire.operation_ids.len() != 1
            || retire.request_ids.len() != 1
            || retire.disposition != RetirementDisposition::Consumed
        {
            return Err(ProviderError::Correlation(
                "packet complete original retirement",
            ));
        }
        let operation = &retire.operation_ids[0];
        if self.begin_requests.get(operation) != Some(&retire.request_ids[0]) {
            return Err(ProviderError::Correlation(
                "packet original Begin retirement identity",
            ));
        }
        let receipt = retire
            .custody_receipt
            .0
            .as_ref()
            .ok_or(ProviderError::Frame("packet consumption absent"))?;
        let body = self.content.get(receipt).ok_or(ProviderError::Correlation(
            "packet consumption bytes absent",
        ))?;
        let expected = self
            .program
            .original(operation)?
            .ok_or(ProviderError::Correlation("packet retirement grant absent"))?
            .newborn
            .iter()
            .map(|output| output.event.clone())
            .collect::<Vec<_>>();
        let consumption: Value = canonical::parse_json(body, FRAME)?;
        let schema = if self.program.is_connected() {
            "source-owned.packet-consumption.v4"
        } else {
            "source-owned.packet-consumption.v1"
        };
        if consumption
            != serde_json::json!({"schema":schema, "operation":operation,"outputs":expected})
        {
            return Err(ProviderError::Correlation(
                "packet original consumption changed",
            ));
        }
        let response = reply(
            RetireResult {
                retired_request_ids: retire.request_ids,
                retired_operation_ids: vec![operation.clone()],
            },
            vec![],
        )?;
        self.native_effect_attempted = true;
        self.program.retire(operation, &expected)?;
        if self.current_operation.as_ref() == Some(operation) {
            self.current_operation = None;
        }
        Ok(response)
    }
}

fn encode(value: &impl Serialize) -> Result<Vec<u8>, ProviderError> {
    let mut writer = Extent(0);
    serde_json::to_writer(&mut writer, value).map_err(ContractError::from)?;
    Ok(canonical::canonical_json(
        &serde_json::to_value(value).map_err(ContractError::from)?,
    )?)
}

fn reference(bytes: &[u8]) -> Result<ContentRef, ProviderError> {
    Ok(canonical::content_ref(bytes, "application/json")?)
}

fn object(value: impl Serialize) -> Result<Map<String, Value>, ProviderError> {
    let bytes = encode(&value)?;
    let Value::Object(object) = canonical::parse_json(&bytes, FRAME)? else {
        return Err(ProviderError::Frame("packet response is not an object"));
    };
    Ok(object)
}

fn reply(
    value: impl Serialize,
    evidence: Vec<(ContentRef, Vec<u8>)>,
) -> Result<PacketControlReply, ProviderError> {
    Ok(PacketControlReply {
        body: object(ResponseShape::Completed {
            operation_state: OperationState::Completed,
            result: object(value)?,
            extensions: Extensions::new(),
        })?,
        evidence,
    })
}

struct Extent(usize);

impl std::io::Write for Extent {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len())
            .filter(|size| *size <= FRAME)
            .ok_or_else(|| std::io::Error::other("packet complete source frame credit"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
