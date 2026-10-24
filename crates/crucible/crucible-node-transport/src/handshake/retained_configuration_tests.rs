//! Checks retained fresh-issuer construction without any exchange or lease.

use super::*;

fn configuration() -> (Option<TrustedInstallation>, Option<NegotiationPolicy>) {
    (
        Some(TrustedInstallation {
            session_id: id("session"),
            incarnation_id: id("incarnation"),
            measured_implementation: manifest().implementation,
            launch_receipt: reference(),
            admission_token: [7; 32],
        }),
        Some(NegotiationPolicy {
            supported_features: vec![id("cnp.core/1")],
            required_features: vec![id("cnp.core/1")],
            provider_limits: limits(),
            required_schemas: Vec::new(),
            required_guarantees: reference(),
            envelope_extension_features: Default::default(),
        }),
    )
}

#[test]
fn retained_configuration_failures_preserve_the_original_allocations() {
    for fault in 0..3 {
        let (mut installation, mut policy) = configuration();
        match fault {
            0 => {
                installation
                    .as_mut()
                    .unwrap()
                    .measured_implementation
                    .schema_version = 2
            }
            1 => {
                installation.as_mut().unwrap().launch_receipt.hash.algorithm = "unsupported".into()
            }
            2 => policy.as_mut().unwrap().required_features.clear(),
            _ => unreachable!(),
        }
        let session = installation.as_ref().unwrap().session_id.as_str().as_ptr();
        let implementation = installation
            .as_ref()
            .unwrap()
            .measured_implementation
            .implementation_id
            .as_str()
            .as_ptr();
        let features = policy.as_ref().unwrap().supported_features.as_ptr();
        let mut output = None;

        let failure = Handshake::from_retained_configuration_data(
            &mut installation,
            &mut policy,
            &mut output,
        );

        assert!(failure.is_err(), "fault={fault}");
        assert!(output.is_none());
        assert_eq!(
            installation.as_ref().unwrap().session_id.as_str().as_ptr(),
            session
        );
        assert_eq!(
            installation
                .as_ref()
                .unwrap()
                .measured_implementation
                .implementation_id
                .as_str()
                .as_ptr(),
            implementation
        );
        assert_eq!(
            policy.as_ref().unwrap().supported_features.as_ptr(),
            features
        );
    }
}

#[test]
fn retained_configuration_success_moves_once_without_cloning_inputs() {
    let (mut installation, mut policy) = configuration();
    let session = installation.as_ref().unwrap().session_id.as_str().as_ptr();
    let features = policy.as_ref().unwrap().supported_features.as_ptr();
    let mut output = None;

    Handshake::from_retained_configuration_data(&mut installation, &mut policy, &mut output)
        .unwrap();

    assert!(installation.is_none());
    assert!(policy.is_none());
    let facts = output
        .as_ref()
        .unwrap()
        .retained_metadata_facts_data()
        .unwrap();
    assert_eq!(facts.shared_backing_views, 2);
    // The complete original negotiation view requires a real connection and
    // verifier. These controls deliberately stop before that boundary.
    assert!(facts.string_capacity_bytes >= "session".len() + "incarnation".len());

    let (mut next_installation, mut next_policy) = configuration();
    assert!(
        Handshake::from_retained_configuration_data(
            &mut next_installation,
            &mut next_policy,
            &mut output
        )
        .is_err()
    );
    assert!(next_installation.is_some());
    assert!(next_policy.is_some());
    assert_eq!(
        facts,
        output
            .as_ref()
            .unwrap()
            .retained_metadata_facts_data()
            .unwrap()
    );

    // Check the actual moved field addresses through the owning module's test
    // helper; no configuration or issuer copy is used to establish this join.
    assert_eq!(
        output
            .as_ref()
            .unwrap()
            .retained_configuration_addresses_data(),
        (session, features)
    );
}

#[test]
fn retained_configuration_missing_inputs_preserve_the_other_owner() {
    let (mut installation, mut policy) = configuration();
    let saved_policy = policy.take();
    let session = installation.as_ref().unwrap().session_id.as_str().as_ptr();
    let mut output = None;

    assert!(
        Handshake::from_retained_configuration_data(&mut installation, &mut policy, &mut output)
            .is_err()
    );
    assert_eq!(
        installation.as_ref().unwrap().session_id.as_str().as_ptr(),
        session
    );
    assert!(output.is_none());

    installation = None;
    policy = saved_policy;
    let features = policy.as_ref().unwrap().supported_features.as_ptr();
    assert!(
        Handshake::from_retained_configuration_data(&mut installation, &mut policy, &mut output)
            .is_err()
    );
    assert_eq!(
        policy.as_ref().unwrap().supported_features.as_ptr(),
        features
    );
    assert!(output.is_none());
}
