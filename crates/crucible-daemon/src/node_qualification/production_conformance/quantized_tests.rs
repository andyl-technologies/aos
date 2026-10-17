//! Rejects timing-family and original window substitutions in host data controls.

use super::*;
use crucible::node_contract::{ExactBoundaryPolicy, PhysicalState, QuantumClosureEvidence};
use crucible_node_contract::{Id, Phase, Position};

#[test]
fn quantized_permission_keeps_complete_original_window_and_batch() -> Result<(), QualificationError>
{
    let start = Position::new(0.into(), 0.into(), Phase::BoundaryControl);
    let end = Position::new(1000.into(), 0.into(), Phase::Publication);
    let reference =
        canonical::content_ref(b"synthetic native closure", "application/octet-stream")?;
    let request = OperationRequest::QuantumBegin {
        window: Id::new("original")?,
        start,
        end,
        input_batch: Id::new("original-input")?,
        host_budget: std::time::Duration::from_millis(1),
    };
    let mut progress = ProgressEvidence::Quantized {
        window: Id::new("original")?,
        publication: end,
        physical: PhysicalState::Active,
        closure: Box::new(QuantumClosureEvidence {
            input_batch: Id::new("original-input")?,
            close_receipt: reference.clone(),
            output_inventory: reference.clone(),
            pending_inventory: reference.clone(),
            clock_evidence: reference,
        }),
    };
    assert!(lawful_permission(&request, &progress));
    assert!(!lawful_permission(
        &OperationRequest::ExactRun {
            start,
            limit: end,
            boundary_policy: ExactBoundaryPolicy::HorizonPark
        },
        &progress
    ));
    if let ProgressEvidence::Quantized { closure, .. } = &mut progress {
        closure.input_batch = Id::new("substituted-input")?;
    }
    assert!(!lawful_permission(&request, &progress));
    if let ProgressEvidence::Quantized {
        closure,
        publication,
        ..
    } = &mut progress
    {
        closure.input_batch = Id::new("original-input")?;
        *publication = start;
    }
    assert!(!lawful_permission(&request, &progress));
    Ok(())
}
