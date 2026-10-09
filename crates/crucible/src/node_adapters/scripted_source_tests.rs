//! Native source codec, pending same-instant transition and cold future tests.

use super::*;

fn source() -> ScriptedSource {
    ScriptedSource::new(
        ScriptedRequestKind::Block,
        vec![
            ScriptedRequest {
                time_ps: 10,
                payload: BlockRequest::write(1, 0, vec![7, 8, 9]).encode().unwrap(),
            },
            ScriptedRequest {
                time_ps: 10,
                payload: BlockRequest::read(2, 0, 3).encode().unwrap(),
            },
            ScriptedRequest {
                time_ps: 20,
                payload: BlockRequest::get_length(3).encode().unwrap(),
            },
        ],
    )
    .unwrap()
}

#[test]
fn cold_siblings_preserve_evaluated_unpublished_requests_and_future_fifo() {
    let mut original = source();
    original.evaluate();
    original.park(10).unwrap();
    let frozen = original.capture().unwrap();
    let mut first = ScriptedSource::from_script_bytes(&original.script_bytes().unwrap()).unwrap();
    let mut second = ScriptedSource::from_script_bytes(&original.script_bytes().unwrap()).unwrap();
    first.restore(&frozen).unwrap();
    second.restore(&frozen).unwrap();

    for instance in [&mut original, &mut first, &mut second] {
        assert_eq!(instance.cursor(), 0);
        assert_eq!(
            instance.next_position(),
            Some(Position::new(10.into(), 1.into(), Phase::Publication))
        );
    }
    let expected = original.publish_due(10);
    assert_eq!(expected.len(), 2);
    assert_eq!(first.publish_due(10), expected);
    assert_eq!(second.publish_due(10), expected);

    for instance in [&mut original, &mut first, &mut second] {
        instance.park(15).unwrap();
        assert_eq!(
            instance.next_position(),
            Some(Position::new(20.into(), 0.into(), Phase::Reaction))
        );
        instance.evaluate();
    }
    let expected = original.publish_due(20);
    assert_eq!(first.publish_due(20), expected);
    assert_eq!(second.publish_due(20), expected);
    assert!(original.next_position().is_none());
    original.park(100).unwrap();
    first.park(100).unwrap();
    second.park(100).unwrap();
    assert_eq!(original.capture().unwrap(), first.capture().unwrap());
    assert_eq!(original.capture().unwrap(), second.capture().unwrap());
}

#[test]
fn closed_codec_refuses_truncation_trailing_content_and_changed_future() {
    let original = source();
    let script = original.script_bytes().unwrap();
    for length in 0..script.len() {
        assert!(ScriptedSource::from_script_bytes(&script[..length]).is_err());
    }
    let mut trailing = script.clone();
    trailing.push(0);
    assert!(ScriptedSource::from_script_bytes(&trailing).is_err());

    let frozen = original.capture().unwrap();
    let mut different = ScriptedSource::new(
        ScriptedRequestKind::Block,
        vec![ScriptedRequest {
            time_ps: 10,
            payload: BlockRequest::write(1, 0, vec![0, 0, 0]).encode().unwrap(),
        }],
    )
    .unwrap();
    assert!(different.restore(&frozen).is_err());
    assert_eq!(different.cursor(), 0);
}

#[test]
fn source_refuses_skipped_requests_and_unrepresentable_response_geometry() {
    let mut original = source();
    assert!(original.park(11).is_err());
    assert_eq!(original.time_ps(), 0);
    assert!(
        ScriptedSource::new(
            ScriptedRequestKind::Block,
            vec![ScriptedRequest {
                time_ps: 0,
                payload: BlockRequest::read(1, 0, u32::MAX).encode().unwrap(),
            }]
        )
        .is_err()
    );
    assert!(
        ScriptedSource::new(
            ScriptedRequestKind::Block,
            vec![ScriptedRequest {
                time_ps: 0,
                payload: vec![0; crucible_shmem::MAX_FRAME_DATA + 1],
            }]
        )
        .is_err()
    );
}
