//! Exact frame-batch validation before a native output stop is exposed.

use super::*;

pub(super) fn exact_output_boundary(
    report: &crate::QemuAsyncNodeStepReport,
    requested_ceiling: Icount,
) -> Result<Option<Icount>, QemuNodeError> {
    if report.emitted_frames.is_empty() {
        return Ok(None);
    }

    let boundary = report.final_state.map(|state| state.current_icount).ok_or(
        QemuNodeError::NetworkOutputBoundary {
            message: String::from("frame batch has no completed physical boundary"),
        },
    )?;
    let paired_outcome = match report.outcome {
        QemuAsyncNodeStepOutcome::Completed {
            advance: AdvanceOutcome::Paused { at },
        } => at == boundary,
        QemuAsyncNodeStepOutcome::Completed {
            advance: AdvanceOutcome::ReachedHorizon,
        } => boundary == requested_ceiling,
        QemuAsyncNodeStepOutcome::Crashed { .. } => false,
    };
    if !paired_outcome || boundary.retired > requested_ceiling.retired {
        return Err(QemuNodeError::NetworkOutputBoundary {
            message: format!(
                "physical coordinate {} is not paired with the completed advance to {}",
                boundary.retired, requested_ceiling.retired,
            ),
        });
    }
    for frame in &report.emitted_frames {
        if frame.emit_icount != boundary {
            return Err(QemuNodeError::NetworkOutputBoundary {
                message: format!(
                    "frame {} was emitted at {} but the producer stopped at {}",
                    frame.sequence, frame.emit_icount.retired, boundary.retired,
                ),
            });
        }
    }

    Ok(Some(boundary))
}
