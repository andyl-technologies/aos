//! Deterministic World-link emission and injected-draw replay.

use super::*;

/// Emits one network-link frame from an explicit canonical RNG stream cursor.
///
/// A logical World link uses one stream across both directed runtime edges.
/// The scheduler therefore owns the shared cursor and supplies it here rather
/// than allowing either concrete [`NetLink`] to restart from its local cursor.
///
/// # Errors
///
/// Returns [`DeviceError`] when the link cannot emit the frame, including clock
/// overflow or fail-loud past-delivery guards.
pub fn emit_link_frame_with_recorded_stream_at_position(
    seed: Seed,
    stream: &RngStreamId,
    _fault_id: &DeviceId,
    rng_position: u64,
    link: &mut NetLink,
    frame: &Frame,
    policy: PastDeliveryPolicy,
) -> Result<LinkEmitDecisionRecord, DeviceError> {
    let mut rng = DeviceRng::restore(
        seed.decision_rng().root_seed(),
        &stream.domain,
        &stream.name,
        rng_position,
    );
    let (outcome, draws) = link.emit_with_rng_draws(frame, &mut rng, policy)?;
    let decisions = link_rng_draw_decisions(stream, &draws);
    Ok(LinkEmitDecisionRecord {
        outcome,
        draws,
        decisions,
    })
}

/// Emits one network-link frame from explorer-injected fixed-order draws.
///
/// This is the live-search twin of
/// [`emit_link_frame_with_recorded_stream_at_position`]. It applies the supplied
/// draws to the real [`NetLink`] and advances the captured RNG cursor by exactly
/// the number of draws the current fault table consumes, so a selected branch
/// has the same continuation semantics as an uninterrupted seeded run.
///
/// # Errors
///
/// Returns [`DeviceError`] when the draw vector has the wrong shape for the
/// effective link fault table or the link rejects the resulting delivery.
pub fn emit_link_frame_with_injected_draws_at_position(
    stream: &RngStreamId,
    _fault_id: &DeviceId,
    rng_position: u64,
    link: &mut NetLink,
    frame: &Frame,
    draws: FrameDraws,
    policy: PastDeliveryPolicy,
) -> Result<LinkEmitDecisionRecord, DeviceError> {
    let faults = link.faults().clone();
    if draws.additional_loss.len() != faults.additional_loss.len()
        || draws.corruption_selectors.len() != faults.corruption_selector_draws() as usize
    {
        return Err(DeviceError::InvalidInjectedDraws {
            message: String::from(
                "injected network draws do not match the effective link fault table",
            ),
        });
    }
    let consumed = 5_u64
        .saturating_add(draws.additional_loss.len() as u64)
        .saturating_add(draws.corruption_selectors.len() as u64);
    let outcome = link.emit(frame, &draws, policy)?;
    link.set_rng_position_for_branch(rng_position.saturating_add(consumed));
    let decisions = link_rng_draw_decisions(stream, &draws);
    Ok(LinkEmitDecisionRecord {
        outcome,
        draws,
        decisions,
    })
}
