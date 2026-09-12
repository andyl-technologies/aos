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
