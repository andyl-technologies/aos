//! Source-level guard that keeps the cryptographic foundation unadvertised.

const FEATURE: &str = "aos.sandbox.authentication.broker-session";
const CONSTANT: &str = "BROKER_SESSION_AUTHENTICATION_FEATURE_NAMESPACE";

#[test]
fn production_brokers_and_controller_do_not_activate_the_feature() {
    let production_surfaces = [
        (
            "Host",
            include_str!("../../aos-sandbox-host/src/service.rs"),
        ),
        (
            "Storage",
            include_str!("../../aos-sandbox-storage/src/service.rs"),
        ),
        (
            "Mount",
            include_str!("../../aos-sandbox-mount/src/service.rs"),
        ),
        (
            "Network",
            include_str!("../../aos-sandbox-network/src/service.rs"),
        ),
        (
            "controller",
            concat!(
                include_str!("../../aos-sandbox/src/controller.rs"),
                include_str!("../../aos-sandbox/src/dispatch.rs"),
                include_str!("../../aos-sandbox/src/resource_inventory.rs"),
                include_str!("../../aos-sandbox/src/mount_preparation.rs"),
                include_str!("../../aos-sandbox/src/mount_attempt/completion.rs"),
            ),
        ),
    ];

    for (name, source) in production_surfaces {
        assert!(
            !source.contains(FEATURE),
            "{name} advertises the inert feature"
        );
        assert!(
            !source.contains(CONSTANT),
            "{name} references the inert feature constant"
        );
    }
}

#[test]
fn staged_network_seams_are_defined_but_unreachable() {
    let service = include_str!("../../aos-sandbox-network/src/service.rs");
    let controller = include_str!("../../aos-sandbox/src/resource_inventory.rs");

    assert_eq!(
        service
            .matches("staged_authenticated_network_inventory_observation<")
            .count(),
        1
    );
    assert_eq!(
        service
            .matches("staged_authenticated_network_inventory_observation(")
            .count(),
        0,
        "Network production service reached the staged authenticated seam"
    );
    assert_eq!(
        controller
            .matches("staged_authenticated_network_inventory_snapshot<")
            .count(),
        1
    );
    assert_eq!(
        controller
            .matches("staged_authenticated_network_inventory_snapshot(")
            .count(),
        0,
        "controller production query reached the staged authenticated seam"
    );
}
