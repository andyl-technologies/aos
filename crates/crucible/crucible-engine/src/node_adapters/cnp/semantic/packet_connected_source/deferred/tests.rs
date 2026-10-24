//! Exercises the pending-publication conjunction with production phased projections.
//!
//! These fixtures authenticate neither a Child nor a native retirement. The
//! installed source separately joins original controller records before calling
//! the same conjunction exercised here.

use super::*;
use crucible_node_format::Bytes;
use crucible_node_transport::reference_packet::connected::PacketReaction;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type Projection = (
    PacketConnectedGrant,
    PacketConnectedGrant,
    Endpoint,
    NativePublication,
);

fn projected_originals() -> TestResult<Projection> {
    let mut initial = super::super::native::initial_inventory();
    initial.gate_closed = false;
    initial.reached = Position::new(U64::new(6), U64::new(0), Phase::Delivery);
    initial.reactions.push(PacketReaction {
        input_event: Id::new("original-input")?,
        input_producer: Id::new("original-producer")?,
        input_sequence: U64::new(0),
        stage_operation: Id::new("original-stage")?,
        commit_request: Id::new("original-commit")?,
        payload: Bytes::new(vec![0xff, 0, 2, 3]),
        parent: initial.reached,
        evaluation: Position::new(U64::new(6), U64::new(0), Phase::Reaction),
    });
    let split = Position::new(U64::new(6), U64::new(1), Phase::Publication);
    let prior = super::super::native::project_grant(
        &initial,
        &Id::new("original-reaction-grant")?,
        initial.reached,
        split,
        true,
    )
    .map_err(|failure| failure.reason)?;
    let end = Position::new(U64::new(6), U64::new(2), Phase::Delivery);
    let current = super::super::native::project_grant(
        &prior.inventory,
        &Id::new("original-emission-grant")?,
        split,
        end,
        true,
    )
    .map_err(|failure| failure.reason)?;
    let endpoint = Endpoint {
        node_id: Id::new("original-relay")?,
        port_id: Id::new("wire-tx")?,
        lane_id: Id::new("output")?,
    };
    let row = &current.newborn[0];
    let publication = NativePublication {
        publication_id: row.output.event.clone(),
        endpoint: endpoint.clone(),
        native_sequence: row.output.sequence,
        publication: row.output.publication,
        evaluation: Some(row.output.evaluation),
        causal_parents: vec![row.pending.reaction.parent],
        payload: canonical::content_ref(row.output.payload.as_slice(), "application/octet-stream")?,
        payload_bytes: row.output.payload.as_slice().to_vec(),
    };
    Ok((current, prior, endpoint, publication))
}

#[test]
fn deferred_publication_preserves_the_original_reaction_and_emitting_windows() -> TestResult {
    let (current, prior, endpoint, publication) = projected_originals()?;
    let before = (current.clone(), prior.clone());
    assert!(prior.newborn.is_empty());
    assert_eq!(prior.inventory.publications.len(), 1);
    assert_eq!(current.newborn.len(), 1);
    assert!(
        publication
            .evaluation
            .is_some_and(|evaluation| evaluation < current.start)
    );
    assert!(validate_pending_publication(&current, &prior, &endpoint, &publication).is_ok());
    assert_eq!((current, prior), before);
    Ok(())
}

#[test]
fn foreign_or_changed_deferred_tuples_cannot_authorize_publication() -> TestResult {
    let (current, prior, endpoint, publication) = projected_originals()?;
    let mut changed = prior.clone();
    changed.operation = Id::new("foreign-reaction-grant")?;
    assert!(validate_pending_publication(&current, &changed, &endpoint, &publication).is_err());
    changed = prior.clone();
    changed.inventory.publications.clear();
    assert!(validate_pending_publication(&current, &changed, &endpoint, &publication).is_err());
    changed = prior.clone();
    changed.start = changed.limit;
    assert!(validate_pending_publication(&current, &changed, &endpoint, &publication).is_err());
    changed = prior.clone();
    changed.complete = false;
    assert!(validate_pending_publication(&current, &changed, &endpoint, &publication).is_err());

    let mut changed_publication = publication.clone();
    changed_publication.payload_bytes[0] ^= 1;
    assert!(
        validate_pending_publication(&current, &prior, &endpoint, &changed_publication).is_err()
    );
    changed_publication = publication.clone();
    changed_publication.native_sequence = U64::new(publication.native_sequence.get() + 1);
    assert!(
        validate_pending_publication(&current, &prior, &endpoint, &changed_publication).is_err()
    );
    changed_publication = publication.clone();
    changed_publication.causal_parents.clear();
    assert!(
        validate_pending_publication(&current, &prior, &endpoint, &changed_publication).is_err()
    );
    changed_publication = publication.clone();
    changed_publication.publication = current.limit;
    assert!(
        validate_pending_publication(&current, &prior, &endpoint, &changed_publication).is_err()
    );
    let mut changed_current = current.clone();
    changed_current.newborn[0].pending.reaction.commit_request = Id::new("foreign-commit")?;
    assert!(
        validate_pending_publication(&changed_current, &prior, &endpoint, &publication).is_err()
    );
    Ok(())
}
