//! Walks closed future Capture/confirmation fields without creating wire owners.

use super::*;
use crate::reference_packet::service::{
    restored_input_reactive17::observation_geometry::hash,
    restored_settled_capture::{
        RESTORED_SETTLED_CAPTURE_REQUEST, restored_settled_capture_proof_layout_data,
    },
    restored_settled_confirmation::{
        PACKET_RESTORED_SETTLED_AFTER_CONFIRMATION_FEATURE as CONFIRMATION_FEATURE,
        PACKET_RESTORED_SETTLED_AFTER_CONFIRMATION_RECEIPT_SCHEMA as CONFIRMATION_RECEIPT,
        PACKET_RESTORED_SETTLED_AFTER_CONFIRMATION_REQUEST_SCHEMA as CONFIRMATION_REQUEST,
    },
};

pub(super) struct Shapes {
    pub(super) capture: Shape,
    pub(super) capture_identity: Shape,
    pub(super) begin: Shape,
    pub(super) arguments: Shape,
    pub(super) request: Shape,
    pub(super) unknown: Shape,
    pub(super) result: Shape,
    pub(super) terminal: Shape,
    pub(super) confirmation: Shape,
    pub(super) confirmation_identity: Shape,
    pub(super) confirmation_result: Shape,
    pub(super) confirmation_receipt: Shape,
    pub(super) confirmation_terminal: Shape,
}

pub(super) fn shapes(
    input: &PacketRestoredSettledCaptureControlFutureInputs<'_>,
    binding: &NodeBinding,
    owner: &OwnerBinding,
    maximum: usize,
) -> Result<Shapes, ProviderError> {
    project(Inputs::Runtime(input), binding, owner, maximum)
}

pub(super) fn shapes_prebirth(
    launch: &PacketNative5SourceLaunch,
    maximum: usize,
) -> Result<Shapes, ProviderError> {
    let [binding] = launch.selection.realization.bindings.as_slice() else {
        return Err(refused());
    };
    let [owner] = launch.selection.realization.owner_bindings.as_slice() else {
        return Err(refused());
    };
    if owner.owner.participant_ids.is_empty() {
        return Err(refused());
    }
    project(Inputs::Prebirth(launch), binding, owner, maximum)
}

#[derive(Clone, Copy)]
enum Inputs<'a, 'b> {
    Runtime(&'a PacketRestoredSettledCaptureControlFutureInputs<'b>),
    Prebirth(&'a PacketNative5SourceLaunch),
}

fn project(
    input: Inputs<'_, '_>,
    binding: &NodeBinding,
    owner: &OwnerBinding,
    maximum: usize,
) -> Result<Shapes, ProviderError> {
    let shape = |project: &dyn Fn(&mut Projection) -> Result<(), ProviderError>| {
        let mut out = Projection::new(maximum)?;
        project(&mut out)?;
        let mut result = out.finish(maximum)?;
        // The actual scope's one32-byte digest can invoke a43-byte formatter
        // during add_value. This known leaf was prepaid before the quote.
        result.serializer_temporary_requested_bytes =
            result.serializer_temporary_requested_bytes.max(43);
        if result.requested_total()? > maximum {
            return Err(exhausted());
        }
        Ok::<_, ProviderError>(result)
    };
    Ok(Shapes {
        capture: shape(&|out| envelope(out, input, binding, owner, false, false, false))?,
        capture_identity: shape(&|out| envelope(out, input, binding, owner, false, false, true))?,
        begin: shape(&|out| begin(out, input, owner))?,
        arguments: shape(&|out| arguments(out, input, owner))?,
        request: shape(&|out| capture_request(out, input, owner))?,
        unknown: shape(&|out| super::super::super::observe_control_growth::unknown_capture(out))?,
        result: shape(&|out| terminal::project_body(out))?,
        terminal: shape(&|out| envelope(out, input, binding, owner, true, false, false))?,
        confirmation: shape(&|out| envelope(out, input, binding, owner, false, true, false))?,
        confirmation_identity: shape(&|out| {
            envelope(out, input, binding, owner, false, true, true)
        })?,
        confirmation_result: shape(&|out| confirmation_result(out))?,
        confirmation_receipt: shape(&|out| confirmation_receipt(out))?,
        confirmation_terminal: shape(&|out| {
            envelope(out, input, binding, owner, true, true, false)
        })?,
    })
}

fn envelope(
    out: &mut Projection,
    input: Inputs<'_, '_>,
    binding: &NodeBinding,
    owner: &OwnerBinding,
    terminal: bool,
    confirmation: bool,
    identity: bool,
) -> Result<(), ProviderError> {
    let fields: &[&str] = if identity {
        &[
            "protocol",
            "session_id",
            "incarnation_id",
            "node_id",
            "execution_owner_id",
            "capture_owner_id",
            "request_id",
            "operation_id",
            "method",
            "body",
            "extensions",
            "request_origin",
        ]
    } else {
        &[
            "protocol",
            "message",
            "session_id",
            "incarnation_id",
            "node_id",
            "execution_owner_id",
            "capture_owner_id",
            "request_id",
            "operation_id",
            "sequence",
            "method",
            "body",
            "extensions",
        ]
    };
    project_object(out, fields)?;
    out.add_string("CNP/1")?;
    if !identity {
        out.add_value(&if terminal {
            MessageKind::Response
        } else {
            MessageKind::Request
        })?;
    }
    out.add_value(&binding.authority.session_id)?;
    out.add_value(&binding.authority.incarnation_id)?;
    out.add_value(&binding.compatibility.node_id)?;
    out.add_value(&())?;
    out.add_value(&binding.compatibility.capture_owner.id)?;
    identifier(out)?;
    identifier(out)?;
    if !identity {
        decimal(out)?;
    }
    out.add_value(&if confirmation {
        Method::Poll
    } else {
        Method::Begin
    })?;
    match (terminal, confirmation) {
        (false, false) => begin(out, input, owner)?,
        (true, false) => terminal::project_body(out)?,
        (false, true) => {
            project_object(out, &["after_observation_sequence", "extensions"])?;
            out.add_value(&U64::new(0))?;
            out.add_object()?;
        }
        (true, true) => confirmation_result(out)?,
    }
    match (terminal, confirmation) {
        (false, false) => {
            project_object(out, &[RESTORED_SETTLED_CAPTURE_FEATURE])?;
            project_object(out, &["request", "proof"])?;
            capture_request(out, input, owner)?;
            proof(out)?;
        }
        (true, false) => out.add_object()?,
        (false, true) => {
            project_object(out, &[CONFIRMATION_FEATURE])?;
            confirmation_request(out)?;
        }
        (true, true) => {
            project_object(out, &[CONFIRMATION_FEATURE])?;
            confirmation_receipt(out)?;
        }
    }
    if identity {
        out.add_value(&crate::envelope::RequestOrigin::Controller)?;
    }
    Ok(())
}

fn arguments(
    out: &mut Projection,
    input: Inputs<'_, '_>,
    owner: &OwnerBinding,
) -> Result<(), ProviderError> {
    project_object(
        out,
        &[
            "capture_id",
            "participant_ids",
            "cut_id",
            "cut",
            "event_ordinal",
            "ordering_profile",
            "preservation_contract",
        ],
    )?;
    match input {
        Inputs::Runtime(input) => out.add_value(input.capture_id)?,
        Inputs::Prebirth(_) => identifier(out)?,
    }
    out.add_value(&owner.owner.participant_ids)?;
    identifier(out)?;
    match input {
        Inputs::Runtime(input) => {
            out.add_value(&input.cut)?;
            out.add_value(&input.event_ordinal)?;
        }
        Inputs::Prebirth(_) => {
            project_object(out, &["time_ps", "microstep", "phase"])?;
            decimal(out)?;
            decimal(out)?;
            out.add_value(&crucible_node_contract::Phase::Reaction)?;
            decimal(out)?;
        }
    }
    out.add_string("superdense-v1")?;
    out.add_string(crate::reference_packet::continuation_contracts::PACKET_COMPLETE_LINEAGE_PROFILE)
}

fn begin(
    out: &mut Projection,
    input: Inputs<'_, '_>,
    owner: &OwnerBinding,
) -> Result<(), ProviderError> {
    project_object(
        out,
        &[
            "kind",
            "binding_hash",
            "owner_generation",
            "activation_id",
            "world_generation",
            "arguments",
            "extensions",
        ],
    )?;
    out.add_string("capture")?;
    hash(out, "cnp.owner-binding.v1")?;
    match input {
        Inputs::Runtime(input) => {
            out.add_value(&input.scope.target.owner_generation)?;
            out.add_value(&input.scope.target.activation)?;
            out.add_value(&input.scope.target.generation)?;
        }
        Inputs::Prebirth(_) => {
            decimal(out)?;
            identifier(out)?;
            decimal(out)?;
        }
    }
    arguments(out, input, owner)?;
    out.add_object()
}

fn capture_request(
    out: &mut Projection,
    input: Inputs<'_, '_>,
    owner: &OwnerBinding,
) -> Result<(), ProviderError> {
    project_object(
        out,
        &[
            "schema",
            "scope",
            "capture",
            "capture_owner",
            "capture_operation",
            "runtime_object",
            "coordinator_checkpoint",
            "parent_archive",
            "first_observation",
            "current_record",
            "current_model",
            "history_prefix",
            "history_next_sequence",
            "native_schema",
            "native_allocation",
        ],
    )?;
    out.add_string(RESTORED_SETTLED_CAPTURE_REQUEST)?;
    match input {
        Inputs::Runtime(input) => out.add_value(input.scope)?,
        Inputs::Prebirth(launch) => super::prebirth::scope(out, launch)?,
    }
    arguments(out, input, owner)?;
    identifier(out)?;
    identifier(out)?;
    reference_with_media(
        out,
        "application/vnd.crucible.runtime-original-lineage+json;version=7",
    )?;
    reference_with_media(
        out,
        "application/vnd.crucible.coordinator-commitment-checkpoint+json;version=17",
    )?;
    reference_with_media(
        out,
        "application/vnd.crucible.native-signed-index-body.v3+json",
    )?;
    match input {
        Inputs::Runtime(input) => {
            out.add_value(input.first_observation)?;
            out.add_value(input.current_record_reference)?;
            out.add_value(&input.current_record.native_receipt.native_record)?;
        }
        Inputs::Prebirth(_) => {
            project_reference(out)?;
            project_reference(out)?;
            project_reference(out)?;
        }
    }
    project_reference(out)?;
    decimal(out)?;
    project_reference(out)?;
    project_object(
        out,
        &[
            "retained_requested_bytes",
            "maximum_simultaneous_transient_bytes",
            "declared_counter_scratch_bytes",
        ],
    )?;
    decimal(out)?;
    decimal(out)?;
    decimal(out)
}

fn proof(out: &mut Projection) -> Result<(), ProviderError> {
    let (schema, algorithm, digest, mac) = restored_settled_capture_proof_layout_data();
    project_object(out, &["schema", "algorithm", "context_digest", "mac"])?;
    out.add_string(schema)?;
    out.add_string(algorithm)?;
    out.add_unescaped_ascii_extent(encoded(digest)?)?;
    out.add_unescaped_ascii_extent(encoded(mac)?)
}

fn confirmation_request(out: &mut Projection) -> Result<(), ProviderError> {
    project_object(
        out,
        &[
            "schema",
            "capture_request_id",
            "capture_request_hash",
            "capture_operation_id",
            "capture_terminal_hash",
            "capture_terminal_sequence",
            "settled_capture_request",
            "native_snapshot_ref",
            "native_control_ref",
            "native_anchor_ref",
        ],
    )?;
    out.add_string(CONFIRMATION_REQUEST)?;
    identifier(out)?;
    hash(out, "cnp.request.v1")?;
    identifier(out)?;
    hash(out, PACKET_RESTORED_SETTLED_CAPTURE_TERMINAL_DOMAIN)?;
    decimal(out)?;
    for _ in 0..4 {
        project_reference(out)?;
    }
    Ok(())
}

fn confirmation_result(out: &mut Projection) -> Result<(), ProviderError> {
    project_object(out, &["status", "operation_state", "result", "extensions"])?;
    out.add_string("completed")?;
    out.add_value(&OperationState::Completed)?;
    project_object(
        out,
        &[
            "operation_id",
            "operation_state",
            "outcome",
            "observations",
            "next_observation_sequence",
        ],
    )?;
    identifier(out)?;
    out.add_value(&OperationState::Completed)?;
    terminal::project_body(out)?;
    out.add_array_extent(0)?;
    out.add_value(&U64::new(1))?;
    out.add_object()
}

fn confirmation_receipt(out: &mut Projection) -> Result<(), ProviderError> {
    project_object(
        out,
        &[
            "schema",
            "capture",
            "native_after_ref",
            "native_after_capacity",
        ],
    )?;
    out.add_string(CONFIRMATION_RECEIPT)?;
    confirmation_request(out)?;
    project_reference(out)?;
    decimal(out)
}

fn reference_with_media(out: &mut Projection, media: &str) -> Result<(), ProviderError> {
    project_object(out, &["hash", "length", "media_type"])?;
    hash(out, "cnp.blob.v1")?;
    decimal(out)?;
    out.add_string(media)
}

fn identifier(out: &mut Projection) -> Result<(), ProviderError> {
    out.add_unescaped_ascii_extent(128)
}
fn decimal(out: &mut Projection) -> Result<(), ProviderError> {
    out.add_unescaped_ascii_extent(20)
}
fn encoded(bytes: usize) -> Result<usize, ProviderError> {
    bytes
        .checked_div(3)
        .and_then(|groups| groups.checked_mul(4))
        .and_then(|whole| {
            whole.checked_add(match bytes % 3 {
                0 => 0,
                1 => 2,
                _ => 3,
            })
        })
        .ok_or_else(exhausted)
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<Inputs<'static, 'static>>()
        + size_of::<Shapes>()
        + size_of::<Result<Shapes, ProviderError>>()
        + size_of::<Projection>()
        + size_of::<Shape>()
        + size_of::<&dyn Fn(&mut Projection) -> Result<(), ProviderError>>()
        + size_of::<&NodeBinding>()
        + size_of::<&OwnerBinding>()
        + size_of::<&mut Projection>()
        + size_of::<[&str; 15]>()
        + size_of::<[&str; 13]>()
        + size_of::<[&str; 12]>()
        + size_of::<[&str; 10]>()
        + size_of::<[&str; 7]>()
        + size_of::<[&str; 5]>()
        + size_of::<[&str; 4]>()
        + size_of::<[&str; 3]>()
        + size_of::<[&str; 2]>()
        + size_of::<(&'static str, &'static str, usize, usize)>()
        + size_of::<&[&str]>()
        + size_of::<std::ops::Range<usize>>()
        + size_of::<usize>() * 3
        + size_of::<bool>() * 3
        + size_of::<Option<usize>>()
}

// These nonexecuted exhaustive rosters couple the hand-written projections and
// formatter admission to their defining DTOs. New fields require a review of
// the actual closed grammar; no DTO is constructed here.
const _:fn(
    &Envelope,&BeginRequest,&CaptureArguments,
    &PacketRestoredSettledCaptureRequest,
    &PacketRestorationActivationScope,
    &crate::reference_packet::service::restored_settled_confirmation::PacketRestoredSettledAfterConfirmationRequest,
    &crate::reference_packet::service::restored_settled_confirmation::PacketRestoredSettledAfterConfirmationReceipt,
)=|envelope,begin,args,capture,scope,confirmation,receipt|{
    let Envelope{protocol:_,message:_,session_id:_,incarnation_id:_,node_id:_,execution_owner_id:_,capture_owner_id:_,request_id:_,operation_id:_,sequence:_,method:_,body:_,extensions:_}=envelope;
    let BeginRequest{kind:_,binding_hash:_,owner_generation:_,activation_id:_,world_generation:_,arguments:_,extensions:_}=begin;
    let CaptureArguments{capture_id:_,participant_ids:_,cut_id:_,cut:_,event_ordinal:_,ordering_profile:_,preservation_contract:_}=args;
    let PacketRestoredSettledCaptureRequest{schema:_,scope:_,capture:_,capture_owner:_,capture_operation:_,runtime_object:_,coordinator_checkpoint:_,parent_archive:_,first_observation:_,current_record:_,current_model:_,history_prefix:_,history_next_sequence:_,native_schema:_,native_allocation:_}=capture;
    let PacketRestorationActivationScope{source_birth:_,source_runtime:_,scope_proof:_,target,restoration}=scope;
    let crate::reference_packet::service::complete_restore::activation::PacketRestorationActivationTarget{native_pid:_,session:_,incarnation:_,node:_,owner:_,owner_generation:_,binding_hash:_,world:_,activation:_,generation:_,prepared_token:_,gate:_,admission:_,transaction:_}=target;
    let crate::reference_packet::service::complete_restore::activation::PacketRestorationActivationOriginals{captured_owner_state:_,captured_control:_,captured_journal:_,mapping:_,commit_request:_,commit_response:_,context_digest:_}=restoration;
    let crate::reference_packet::service::restored_settled_confirmation::PacketRestoredSettledAfterConfirmationRequest{schema:_,capture_request_id:_,capture_request_hash:_,capture_operation_id:_,capture_terminal_hash:_,capture_terminal_sequence:_,settled_capture_request:_,native_snapshot_ref:_,native_control_ref:_,native_anchor_ref:_}=confirmation;
    let crate::reference_packet::service::restored_settled_confirmation::PacketRestoredSettledAfterConfirmationReceipt{schema:_,capture:_,native_after_ref:_,native_after_capacity:_}=receipt;
};
