//! Debug-listener policy tests for the production quantum loop.

use super::*;

fn debug_config(allow_requested_loopback_listen: bool) -> ProductionVmDebugConfig {
    ProductionVmDebugConfig {
        node: None,
        operator_listen: String::from("127.0.0.1:0"),
        all_nodes: allow_requested_loopback_listen,
        allow_requested_loopback_listen,
    }
}

#[test]
fn daemon_debug_policy_accepts_an_explicit_loopback_listener() {
    let listen = GdbListen::new("127.0.0.1:9000")
        .unwrap_or_else(|error| panic!("loopback listener should parse: {error}"));

    let requested = trusted_debug_listener(&debug_config(true), &listen)
        .unwrap_or_else(|error| panic!("daemon listener should be admitted: {error}"));

    assert_eq!(requested, SocketAddr::from(([127, 0, 0, 1], 9000)));
}

#[test]
fn fixed_debug_policy_rejects_a_different_listener() {
    let listen = GdbListen::new("127.0.0.1:9000")
        .unwrap_or_else(|error| panic!("loopback listener should parse: {error}"));

    let error = match trusted_debug_listener(&debug_config(false), &listen) {
        Ok(address) => panic!("fixed listener policy admitted {address}"),
        Err(error) => error,
    };

    assert!(
        error
            .to_string()
            .contains("does not match configured listener")
    );
}

#[test]
fn daemon_debug_policy_rejects_a_non_loopback_listener() {
    let listen = GdbListen::new("0.0.0.0:9000")
        .unwrap_or_else(|error| panic!("socket listener should parse: {error}"));

    let error = match trusted_debug_listener(&debug_config(true), &listen) {
        Ok(address) => panic!("daemon listener policy admitted {address}"),
        Err(error) => error,
    };

    assert!(error.to_string().contains("must be loopback"));
}
