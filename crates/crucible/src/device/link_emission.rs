//! Deterministic World-link emission and injected-draw replay.

use super::*;

/// Emits one network-link frame from its event-keyed draws.
///
/// A logical World link uses one stream across both directed runtime edges.
/// Each frame's draws are addressed by `draw_key`, the frame's direction and
/// producer sequence, so a value never depends on how the two directions'
/// frames were admitted relative to each other ([SCHED-50]). `rng_position` is
/// the shared logical cursor; it only counts draws taken on the stream.
///
/// # Errors
///
/// Returns [`DeviceError`] when the link cannot emit the frame, including clock
/// overflow or fail-loud past-delivery guards.
pub fn emit_link_frame_with_keyed_draws(
    seed: Seed,
    stream: &RngStreamId,
    draw_key: LinkFrameDrawKey,
    rng_position: u64,
    link: &mut NetLink,
    frame: &Frame,
    policy: PastDeliveryPolicy,
) -> Result<LinkEmitDecisionRecord, DeviceError> {
    let mut rng = DeviceRng::for_event(
        seed.decision_rng().root_seed(),
        &stream.domain,
        &stream.name,
        &draw_key.encode(),
    );
    let (outcome, draws) = link.emit_with_event_rng_draws(frame, &mut rng, rng_position, policy)?;
    let decisions = link_rng_draw_decisions(stream, &draws);
    Ok(LinkEmitDecisionRecord {
        outcome,
        draws,
        decisions,
    })
}

/// Emits one network-link frame from explorer-injected fixed-order draws.
///
/// This is the live-search twin of [`emit_link_frame_with_keyed_draws`]. It
/// applies the supplied draws to the real [`NetLink`] and advances the shared
/// cursor by exactly the number of draws the current fault table consumes, so a
/// selected branch keeps the same draw count as an uninterrupted seeded run.
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
