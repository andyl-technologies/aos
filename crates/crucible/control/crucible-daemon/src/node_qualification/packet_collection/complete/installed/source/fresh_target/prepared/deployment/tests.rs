//! Exercises the actual ordinary holder before any deployment selection.

use super::*;

/// Reuses the genuine admitted ordinary fixture without installing process limits.
pub(in super::super) fn assert_ordinary_original_stays_unfunded(
    owner: &PreparedCompleteRestoration,
) {
    assert!(owner.import18_templates.deployment.is_none());
    assert!(!owner.import18_templates.funded_complete);
    assert!(owner.authenticate_funded_templates_data().is_err());
    assert!(owner.observe_funded_templates_data([0; 3]).is_err());

    let mut first =
        crate::node_qualification::packet_collection::complete::retained::Counter::new(usize::MAX);
    HostSource17SetupBorrow::prepared_data(owner)
        .charge_data(&mut first, None)
        .unwrap();
    let exact = first.bytes();
    assert!(exact > 0);

    let mut admitted =
        crate::node_qualification::packet_collection::complete::retained::Counter::new(exact);
    HostSource17SetupBorrow::prepared_data(owner)
        .charge_data(&mut admitted, None)
        .unwrap();
    assert_eq!(admitted.bytes(), exact);
    let mut short =
        crate::node_qualification::packet_collection::complete::retained::Counter::new(exact - 1);
    assert!(
        HostSource17SetupBorrow::prepared_data(owner)
            .charge_data(&mut short, None)
            .is_err()
    );
    assert!(owner.import18_templates.deployment.is_none());
    assert!(!owner.prebirth_attempted);
    assert!(owner.prebirth.is_none());
}
