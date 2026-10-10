//! Control-boundary request custody under a concurrent node-state publication.
//!
//! The clamp and request are the real host implementation. The plugin's
//! unfinished publication is modeled by holding the node seqlock odd; it grants
//! no native callback, phase, or execution authority.

use super::*;

#[test]
fn request_custody_reports_an_unfinished_node_publication_as_unavailable()
-> Result<(), FixtureError> {
    let fixture = LaunchFixture::cold(1)?;
    let region = mapped(&fixture)?;
    let mut channel = fixture.hot_path()?;
    start(&mut channel, 100)?;
    let custody = custody(&fixture)?;
    let slot = region
        .node_slot(0)
        .map_err(|_| ConsoleOwnerError::Storage)?;
    slot.publish_reached_icount(100)?;
    custody.publish_clamp(
        slot,
        crucible_shmem::authorize_advance_ceiling(100, 100, None)?,
    )?;
    let clamp_table = || {
        region
            .native_console_segment(0)
            .map(|segment| segment.clamp.snapshot().ok())
            .ok()
            .flatten()
    };
    let table_before = clamp_table();
    let ack_before = slot.snapshot().control_boundary_ack;

    let writer = slot.begin_node_state_publication_for_test();
    let refused = custody.request_boundary(&region, 0, None);
    drop(writer);

    // Contention leaves no request, paired fields, or claim behind.
    assert!(
        matches!(refused, Err(ConsoleOwnerError::Unavailable)),
        "{refused:?}"
    );
    assert_eq!(slot.snapshot().control_boundary_ack, ack_before);
    assert_eq!(clamp_table(), table_before);
    custody.request_boundary(&region, 0, None)?;
    fixture.finish()
}
