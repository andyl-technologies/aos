//! Deterministic World-link emission and injected-draw replay.

use super::*;

/// Where one link frame's draws sit on its World link's stream.
///
/// The frame's `direction` and `producer_sequence` are its event identity: they
/// key a seeded draw and name every recorded draw's address ([SCHED-50]).
/// `rng_position` is the shared logical cursor before the frame; it only counts
/// draws taken on the stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkFrameDrawSite<'a> {
    /// The World link's decision stream, shared by both directions.
    pub stream: &'a RngStreamId,
    /// The directed edge whose producer emitted the frame.
    pub direction: NetworkLinkDirection,
    /// The producer's own sequence number for the frame.
    pub producer_sequence: u64,
    /// The stream cursor before this frame's draws.
    pub rng_position: u64,
}

/// Emits one network-link frame from its event-keyed draws.
///
/// A logical World link uses one stream across both directed runtime edges.
/// Each frame's draws are addressed by the frame's direction and producer
/// sequence in `site`, so a value never depends on how the two directions'
/// frames were admitted relative to each other ([SCHED-50]).
///
/// # Errors
///
/// Returns [`DeviceError`] when the link cannot emit the frame, including clock
/// overflow or fail-loud past-delivery guards.
pub fn emit_link_frame_with_keyed_draws(
    seed: Seed,
    site: LinkFrameDrawSite<'_>,
    link: &mut NetLink,
    frame: &Frame,
    policy: PastDeliveryPolicy,
) -> Result<LinkEmitDecisionRecord, DeviceError> {
    let draw_key = site.direction.frame_draw_key(site.producer_sequence);
    let mut rng = DeviceRng::for_event(
        seed.decision_rng().root_seed(),
        &site.stream.domain,
        &site.stream.name,
        &draw_key.encode(),
    );
    let (outcome, draws) =
        link.emit_with_event_rng_draws(frame, &mut rng, site.rng_position, policy)?;
    let decisions = link_rng_draw_decisions(site, &draws);
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
/// The recorded draws carry the frame's seeded addresses, so an injected value
/// replaces a seeded one at the same address.
///
/// # Errors
///
/// Returns [`DeviceError`] when the draw vector has the wrong shape for the
/// effective link fault table or the link rejects the resulting delivery.
pub fn emit_link_frame_with_injected_draws_at_position(
    site: LinkFrameDrawSite<'_>,
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
    link.set_rng_position_for_branch(site.rng_position.saturating_add(consumed));
    let decisions = link_rng_draw_decisions(site, &draws);
    Ok(LinkEmitDecisionRecord {
        outcome,
        draws,
        decisions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_frame_draws_record_the_address_their_value_was_derived_from() {
        let seed = Seed::from_u64(0x5eed_0050);
        let stream = RngStreamId::for_link("client--server");
        let direction = NetworkLinkDirection::EndpointBToEndpointA;
        let producer_sequence = 12;
        let event = direction.frame_draw_key(producer_sequence).encode();
        let mut rng = DeviceRng::for_event(
            seed.decision_rng().root_seed(),
            &stream.domain,
            &stream.name,
            &event,
        );
        let draws =
            FrameDraws::from_rng_for_faults(&mut rng, &crucible_device::LinkFaults::default());

        let site = LinkFrameDrawSite {
            stream: &stream,
            direction,
            producer_sequence,
            rng_position: 0,
        };
        let decisions = link_rng_draw_decisions(site, &draws);

        // Each recorded value is exactly the keyed event draw at its role.
        let keyed = crucible_determinism::DecisionRng::new(seed.decision_rng().root_seed())
            .event_in_domain(&stream.domain, &stream.name, &event);
        assert_eq!(decisions.len(), 5);
        for (role, decision) in (0_u64..).zip(&decisions) {
            assert_eq!(
                decision,
                &Decision::RngDraw(RngDecision {
                    stream: stream.clone(),
                    address: RngDrawAddress::LinkFrame {
                        direction,
                        producer_sequence,
                        role,
                    },
                    value: keyed.draw_at(role),
                })
            );
        }
    }
}
