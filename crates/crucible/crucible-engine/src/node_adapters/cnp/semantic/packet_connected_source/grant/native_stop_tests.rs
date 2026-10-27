//! Compares source stop translation with the independent baseline wire decoder.
//!
//! These controls establish grammar and lossless position mapping only; they
//! do not execute a native peer or grant capture, readiness or acceptance.

use crucible_node_format::{Extensions, Id, OperatingMode, Validate, canonical};
use crucible_node_transport::envelope::{Method, Nullable};

use super::*;

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

fn position(time: u64, microstep: u64, phase: Phase) -> Position {
    Position::new(U64::new(time), U64::new(microstep), phase)
}

fn wire_decode(request: &OperationRequest) -> TestResult<RequestBody> {
    let (kind, start, limit) = match request {
        OperationRequest::ExactRun { start, limit, .. } => (BeginKind::ExactRun, *start, *limit),
        OperationRequest::BoundarySettle { start, limit } => {
            (BeginKind::BoundarySettle, *start, *limit)
        }
        _ => return Err("fixture supports only exact/settle bodies".into()),
    };
    let arguments = ExactRunArguments {
        grant_id: Id::new("source-stop-control")?,
        participant_ids: vec![Id::new("original-node")?],
        realization_id: Id::new("original-realization")?,
        activation_id: Id::new("original-activation")?,
        world_generation: U64::new(1),
        owner_generation: U64::new(1),
        input_epoch: Id::new("original-epoch")?,
        mode: OperatingMode::Exact,
        ordering_profile: "superdense-v1".into(),
        start,
        limit,
        boundary_policy: BoundaryPolicy::OrdinaryStop,
        input_authorization: canonical::content_ref(
            b"opaque source authority fixture",
            "application/json",
        )?,
        input_watermark: U64::new(1),
    };
    arguments.validate()?;
    let serde_json::Value::Object(arguments) = serde_json::to_value(arguments)? else {
        return Err("fixture argument shape".into());
    };
    let begin = BeginRequest {
        kind,
        binding_hash: canonical::hash("cnp.owner-binding.v1", b"original owner fixture")?,
        owner_generation: U64::new(1),
        activation_id: Nullable(Some(Id::new("original-activation")?)),
        world_generation: U64::new(1),
        arguments,
        extensions: Extensions::new(),
    };
    let serde_json::Value::Object(body) = serde_json::to_value(begin)? else {
        return Err("fixture body shape".into());
    };
    Ok(decode_request(Method::Begin, &body)?)
}

#[test]
fn physical_exact_and_full_phase_settlement_preserve_the_wire_interval() -> TestResult<()> {
    let start = position(1, 0, Phase::BoundaryControl);
    let physical = position(6, 0, Phase::BoundaryControl);
    let request = OperationRequest::ExactRun {
        start,
        limit: physical,
        boundary_policy: ExactBoundaryPolicy::HorizonPark,
    };
    assert!(wire_decode(&request).is_ok());
    assert_eq!(
        native_request(&request).map_err(|error| error.reason)?,
        PacketCommonRequest::ExactRun {
            start,
            limit: physical,
            boundary_policy: PacketCommonBoundaryPolicy::HorizonPark
        }
    );

    for limit in [
        position(6, 0, Phase::Delivery),
        position(6, 0, Phase::Reaction),
        position(6, 1, Phase::Publication),
    ] {
        let request = OperationRequest::BoundarySettle {
            start: physical,
            limit,
        };
        assert!(wire_decode(&request).is_ok());
        assert_eq!(
            native_request(&request).map_err(|error| error.reason)?,
            PacketCommonRequest::BoundarySettle {
                start: physical,
                limit
            }
        );
    }
    Ok(())
}

#[test]
fn unrepresentable_full_phase_exact_refuses_without_coarsening() -> TestResult<()> {
    let start = position(1, 0, Phase::BoundaryControl);
    for limit in [
        position(6, 0, Phase::Delivery),
        position(6, 0, Phase::Reaction),
        position(6, 1, Phase::Publication),
        position(6, 1, Phase::BoundaryControl),
    ] {
        let request = OperationRequest::ExactRun {
            start,
            limit,
            boundary_policy: ExactBoundaryPolicy::HorizonPark,
        };
        assert!(wire_decode(&request).is_err());
        let failure = native_request(&request)
            .err()
            .ok_or("source silently coarsened the original full interval")?;
        assert_eq!(failure.effects, crate::node_contract::EffectKnowledge::None);
    }
    let request = OperationRequest::BoundarySettle {
        start,
        limit: position(6, 0, Phase::Delivery),
    };
    assert!(wire_decode(&request).is_err());
    assert_eq!(
        native_request(&request)
            .err()
            .ok_or("cross-tick settlement silently admitted")?
            .effects,
        crate::node_contract::EffectKnowledge::None
    );
    Ok(())
}
