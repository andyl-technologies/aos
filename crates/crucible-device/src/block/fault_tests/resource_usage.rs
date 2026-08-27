//! Tests retained and prospective block-fault resource accounting.

use super::*;

#[test]
fn pending_operation_usage_tracks_count_and_largest_request_extent() {
    let mut storage = state(BlockCompletionDurability::Durable);
    let request = BlockRequest::write(7, 3, vec![0x5a; 11]);
    storage
        .install(
            request.identity(),
            ResolvedBlockFaultDirective::fault_free(&request, 32),
        )
        .unwrap_or_else(|error| panic!("pending request should install: {error}"));

    assert_eq!(
        storage
            .pending_operation_usage()
            .unwrap_or_else(|error| panic!("pending usage should be representable: {error}")),
        (1, 11)
    );
}

#[test]
fn media_rule_usage_tracks_existing_and_prospective_intervals() {
    let base = BaseImage::new(vec![0x5a; 32]);
    let mut durable = CowOverlay::new();
    let mut state = state(BlockCompletionDurability::Durable);
    let rule = ResolvedBlockMediaRule {
        contributor: [0x31; 32],
        start: 8,
        length: 8,
        state: crate::block::BlockMediaRangeState::Bad,
        operations: vec![BlockOp::Read],
        count_threshold: None,
        time_threshold_nanos: None,
    };

    assert_eq!(
        state
            .media_rule_usage(std::slice::from_ref(&rule))
            .unwrap_or_else(|error| panic!("initial media usage: {error}")),
        (0, 1)
    );
    let request = BlockRequest::read(40, 8, 4);
    let _response = response(&mut state, &base, &mut durable, &request, |directive| {
        directive.media_rules.push(rule.clone());
    });
    assert_eq!(
        state
            .media_rule_usage(std::slice::from_ref(&rule))
            .unwrap_or_else(|error| panic!("retained media usage: {error}")),
        (1, 0)
    );

    let mut distinct = rule;
    distinct.contributor = [0x32; 32];
    assert_eq!(
        state
            .media_rule_usage(&[distinct])
            .unwrap_or_else(|error| panic!("prospective media usage: {error}")),
        (1, 1)
    );
}
