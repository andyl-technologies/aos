//! Exercises the production replay fence with retained phased output custody.
//!
//! These source-only controls do not execute a native peer or establish readiness.

use crucible_node_format::Bytes;
use crucible_node_transport::reference_packet::connected::PacketReaction;

use super::*;

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

fn published_inventory(operation: &Id) -> TestResult<PacketConnectedInventory> {
    let mut initial = initial_inventory();
    initial.gate_closed = false;
    initial.reactions.push(PacketReaction {
        input_event: Id::new("original-input")?,
        input_producer: Id::new("original-producer")?,
        input_sequence: U64::new(0),
        stage_operation: Id::new("original-stage")?,
        commit_request: Id::new("original-commit")?,
        payload: Bytes::new(vec![1, 2, 3]),
        parent: Position::new(U64::new(1), U64::new(0), Phase::Delivery),
        evaluation: Position::new(U64::new(1), U64::new(0), Phase::Reaction),
    });
    let end = Position::new(U64::new(2), U64::new(0), Phase::BoundaryControl);
    let grant = project_grant(&initial, operation, initial.reached, end, true)
        .map_err(|failure| failure.reason)?;
    assert_eq!(grant.inventory.retained_outputs.len(), 1);
    assert_eq!(grant.inventory.delivered_inputs.len(), 1);
    assert_eq!(grant.inventory.reactions_completed, U64::new(1));
    Ok(grant.inventory)
}

fn consumption(operation: &Id, inventory: &PacketConnectedInventory) -> serde_json::Value {
    let outputs: Vec<_> = inventory
        .retained_outputs
        .iter()
        .map(|row| &row.output.event)
        .collect();
    serde_json::json!({
        "schema": "source-owned.packet-consumption.v4",
        "operation": operation,
        "outputs": outputs
    })
}

#[test]
fn empty_and_phased_output_retirements_require_the_closed_v4_body() -> TestResult<()> {
    let operation = Id::new("original-grant")?;
    let completed = vec![operation.clone()];
    for inventory in [initial_inventory(), published_inventory(&operation)?] {
        let original = inventory.clone();
        let body = consumption(&operation, &inventory);
        assert!(validate_retirement_consumption(&completed, &completed, &inventory, &body).is_ok());

        for schema in [
            "source-owned.packet-consumption.v1",
            "source-owned.packet-consumption.v5",
        ] {
            let mut changed = body.clone();
            changed["schema"] = schema.into();
            assert!(
                validate_retirement_consumption(&completed, &completed, &inventory, &changed)
                    .is_err()
            );
        }
        let mut changed = body;
        changed["extra"] = true.into();
        assert!(
            validate_retirement_consumption(&completed, &completed, &inventory, &changed).is_err()
        );
        assert_eq!(inventory, original);
    }
    Ok(())
}

#[test]
fn changed_operation_or_output_population_preserves_retained_custody() -> TestResult<()> {
    let operation = Id::new("original-grant")?;
    let foreign = Id::new("foreign-grant")?;
    let completed = vec![operation.clone()];
    let inventory = published_inventory(&operation)?;
    let original = inventory.clone();
    let body = consumption(&operation, &inventory);

    for changed in [
        consumption(&foreign, &inventory),
        serde_json::json!({"schema":"source-owned.packet-consumption.v4", "operation":operation, "outputs":[]}),
        serde_json::json!({"schema":"source-owned.packet-consumption.v4", "operation":operation, "outputs":["foreign-output"]}),
        serde_json::json!({"schema":"source-owned.packet-consumption.v4", "operation":operation, "outputs":[inventory.retained_outputs[0].output.event, inventory.retained_outputs[0].output.event]}),
    ] {
        assert!(
            validate_retirement_consumption(&completed, &completed, &inventory, &changed).is_err()
        );
    }
    for requested in [
        vec![],
        vec![foreign.clone()],
        vec![operation.clone(), foreign.clone()],
    ] {
        assert!(
            validate_retirement_consumption(&requested, &completed, &inventory, &body).is_err()
        );
    }
    assert!(validate_retirement_consumption(&completed, &[], &inventory, &body).is_err());

    let mut foreign_owner = inventory.clone();
    foreign_owner.retained_outputs[0].output.operation = foreign;
    assert!(
        validate_retirement_consumption(&completed, &completed, &foreign_owner, &body).is_err()
    );
    assert_eq!(inventory, original);
    Ok(())
}
