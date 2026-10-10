//! Model-only peer negotiation controls; no native or behavioral qualification.

use std::cell::Cell;
use std::rc::Rc;

use super::*;

struct Installed {
    supported: Vec<ExtensionSelection>,
    required: Vec<ExtensionSelection>,
    calls: Cell<usize>,
    deny: bool,
}

impl InstalledExtensionNegotiationVerifier for Installed {
    fn supported(&self) -> &[ExtensionSelection] {
        &self.supported
    }

    fn required(&self) -> &[ExtensionSelection] {
        &self.required
    }

    fn verify_selection(&self, _: &[ExtensionSelection], _: &IdSet) -> Result<(), ProviderError> {
        self.calls.set(self.calls.get() + 1);
        if self.deny {
            Err(ProviderError::Correlation("model installed policy refused"))
        } else {
            Ok(())
        }
    }
}

fn selection() -> ExtensionSelection {
    ExtensionSelection {
        declaration: reference(),
        identifier: id("vendor.example/contract"),
        semantic_version: SemanticVersion {
            major: U64::new(1),
            minor: U64::new(0),
            patch: U64::new(0),
            prerelease: None,
            build: None,
        },
        schema_digest: reference().hash,
    }
}

fn installed(deny: bool) -> Rc<Installed> {
    Rc::new(Installed {
        supported: vec![selection()],
        required: vec![selection()],
        calls: Cell::new(0),
        deny,
    })
}

fn configured() -> Handshake {
    let feature = id(EXTENSION_NEGOTIATION_V1);
    Handshake::new(
        TrustedInstallation {
            session_id: id("session"),
            incarnation_id: id("incarnation"),
            measured_implementation: manifest().implementation,
            launch_receipt: reference(),
            admission_token: [7; 32],
        },
        NegotiationPolicy {
            supported_features: vec![id("cnp.core/1"), feature.clone(), id("cnp.resume/1")],
            required_features: vec![id("cnp.core/1"), feature.clone()],
            provider_limits: limits(),
            required_schemas: vec![],
            required_guarantees: reference(),
            envelope_extension_features: std::collections::BTreeMap::from([(
                EXTENSION_NEGOTIATION_V1.into(),
                feature,
            )]),
        },
    )
    .unwrap()
}

fn pair(resume: bool, request_id: &str) -> (crate::envelope::Envelope, crate::envelope::Envelope) {
    let mut request = hello();
    let mut response = result();
    request.required_features.push(id(EXTENSION_NEGOTIATION_V1));
    response
        .selected_features
        .insert(1, id(EXTENSION_NEGOTIATION_V1));
    if resume {
        (request, response) = resumed(&request, &response);
    }
    let (mut request, mut response) = envelopes(&request, &response, request_id);
    request.extensions.insert(
        EXTENSION_NEGOTIATION_V1.into(),
        serde_json::to_value(ExtensionOfferV1 {
            format: U64::new(1),
            required: vec![selection()],
            optional: vec![],
        })
        .unwrap(),
    );
    response.extensions.insert(
        EXTENSION_NEGOTIATION_V1.into(),
        serde_json::to_value(ExtensionSelectionV1 {
            format: U64::new(1),
            selected: vec![selection()],
        })
        .unwrap(),
    );
    (request, response)
}

#[test]
fn exact_installed_contract_is_retained_in_same_connection_authority() {
    let source = installed(false);
    let mut handshake = ExtensionHandshake::new(configured(), source.clone()).unwrap();
    let mut verifier = Verifier::default();
    let (request, response) = pair(false, "hello/1");

    let authority = handshake
        .admit_envelopes(&request, &response, id("connection/1"), &mut verifier)
        .unwrap();

    assert_eq!(
        authority.selected_extensions(),
        Some([selection()].as_slice())
    );
    assert!(authority.ensure_live().is_ok());
    assert_eq!(source.calls.get(), 1);
    assert_eq!(verifier.authenticated, 1);
    assert_eq!(verifier.contracts, 1);
}

#[test]
fn legacy_entrypoint_preserves_bytes_and_refuses_typed_marker_authority() {
    let request = hello();
    let response = result();
    // These bytes come from the original legacy field contract and fixture,
    // including omitted resume_session and URL-safe challenge encoding.
    assert_eq!(
        serde_json::to_vec(&request).unwrap(),
        include_bytes!("fixtures/hello-request-v1.json")
    );
    assert_eq!(
        serde_json::to_vec(&response).unwrap(),
        include_bytes!("fixtures/hello-result-v1.json")
    );
    let authority = handshake()
        .admit_exchange(&request, &response, id("legacy"), &mut Verifier::default())
        .unwrap();
    assert!(authority.selected_extensions().is_none());

    let (request, response) = pair(false, "typed/1");
    let mut legacy = configured();
    let mut verifier = Verifier::default();
    assert!(
        legacy
            .admit_envelopes(&request, &response, id("connection"), &mut verifier)
            .is_err()
    );
    assert_eq!(verifier.authenticated, 0);
}

#[test]
fn complete_encoded_credit_refuses_before_typed_decoding() {
    use crate::handshake::extension_contract::{decode_bounded, preflight_encoded};

    // JSON's two quotes are part of the complete encoded ceiling.
    let exact = Value::String("x".repeat(MAXIMUM_EXTENSION_NEGOTIATION_BYTES - 2));
    assert_eq!(
        serde_json::to_vec(&exact).unwrap().len(),
        MAXIMUM_EXTENSION_NEGOTIATION_BYTES
    );
    assert!(preflight_encoded(&exact).is_ok());

    let oversized = Value::String("x".repeat(MAXIMUM_EXTENSION_NEGOTIATION_BYTES - 1));
    assert!(matches!(
        preflight_encoded(&oversized),
        Err(ProviderError::ResourceExhausted(
            "extension negotiation bytes"
        ))
    ));
    assert!(matches!(
        decode_bounded::<ExtensionOfferV1>(&oversized),
        Err(ProviderError::ResourceExhausted(
            "extension negotiation bytes"
        ))
    ));
}

#[test]
fn changed_required_version_schema_or_declaration_refuses_before_callbacks() {
    for field in ["semantic_version", "schema_digest", "declaration"] {
        let source = installed(false);
        let mut handshake = ExtensionHandshake::new(configured(), source.clone()).unwrap();
        let (mut request, response) = pair(false, "hello/1");
        let value = request
            .extensions
            .get_mut(EXTENSION_NEGOTIATION_V1)
            .unwrap();
        match field {
            "semantic_version" => value["required"][0][field]["minor"] = Value::String("1".into()),
            "schema_digest" => {
                value["required"][0][field]["digest"] = Value::String("0".repeat(64))
            }
            _ => value["required"][0][field]["length"] = Value::String("1".into()),
        }
        let mut verifier = Verifier::default();
        assert!(
            handshake
                .admit_envelopes(&request, &response, id("connection"), &mut verifier)
                .is_err()
        );
        assert_eq!(source.calls.get(), 0);
        assert_eq!(verifier.authenticated, 0);
    }
}

#[test]
fn edition_shape_and_aggregate_bytes_refuse_before_callbacks() {
    for value in [
        serde_json::json!({"format":"2","required":[],"optional":[]}),
        serde_json::json!({"format":"1","required":[]}),
        serde_json::json!({"format":"1","required":null,"optional":[]}),
        serde_json::json!({"format":"1","required":[],"optional":[],"unknown":true}),
        serde_json::json!({"oversized":"x".repeat(MAXIMUM_EXTENSION_NEGOTIATION_BYTES)}),
    ] {
        let source = installed(false);
        let mut handshake = ExtensionHandshake::new(configured(), source.clone()).unwrap();
        let (mut request, response) = pair(false, "hello/1");
        request
            .extensions
            .insert(EXTENSION_NEGOTIATION_V1.into(), value);
        let mut verifier = Verifier::default();
        assert!(
            handshake
                .admit_envelopes(&request, &response, id("connection"), &mut verifier)
                .is_err()
        );
        assert_eq!(source.calls.get(), 0);
        assert_eq!(verifier.authenticated, 0);
    }
}

#[test]
fn changed_resume_selection_preserves_original_lease_secret_and_journal() {
    let source = installed(false);
    let mut handshake = ExtensionHandshake::new(configured(), source.clone()).unwrap();
    let mut verifier = Verifier::default();
    let (request, response) = pair(false, "hello/1");
    let original = handshake
        .admit_envelopes(&request, &response, id("connection/1"), &mut verifier)
        .unwrap();
    let (request, mut response) = pair(true, "hello/2");
    response
        .extensions
        .get_mut(EXTENSION_NEGOTIATION_V1)
        .unwrap()["selected"][0]["semantic_version"]["patch"] = Value::String("1".into());

    assert!(
        handshake
            .admit_envelopes(&request, &response, id("connection/2"), &mut verifier)
            .is_err()
    );
    assert!(original.ensure_live().is_ok());
    assert!(verifier.fenced.is_empty());
    assert_eq!(source.calls.get(), 1);

    let (request, response) = pair(true, "hello/2");
    let current = handshake
        .admit_envelopes(&request, &response, id("connection/2"), &mut verifier)
        .unwrap();
    assert!(original.ensure_live().is_err());
    assert_eq!(
        current.selected_extensions(),
        Some([selection()].as_slice())
    );
    assert_eq!(verifier.fenced, vec![id("connection/1")]);
}

#[test]
fn installed_policy_refusal_cannot_issue_registration_lease() {
    let source = installed(true);
    let mut handshake = ExtensionHandshake::new(configured(), source.clone()).unwrap();
    let (request, response) = pair(false, "hello/1");
    let mut verifier = Verifier::default();

    assert!(
        handshake
            .admit_envelopes(&request, &response, id("connection"), &mut verifier)
            .is_err()
    );
    assert_eq!(source.calls.get(), 1);
    assert_eq!(verifier.authenticated, 1);
    assert!(verifier.fenced.is_empty());
}

#[test]
fn ambiguous_offers_refuse_and_unsupported_optional_tuple_is_omitted() {
    let source = installed(false);
    let mut offer = ExtensionOfferV1 {
        format: U64::new(1),
        required: vec![selection()],
        optional: vec![selection()],
    };
    assert!(select_installed_extensions(&offer, source.as_ref(), &vec![]).is_err());
    assert_eq!(source.calls.get(), 0);

    let mut optional = selection();
    optional.identifier = id("vendor.example/optional");
    optional.semantic_version.minor = U64::new(2);
    offer.optional = vec![optional];
    assert_eq!(
        select_installed_extensions(&offer, source.as_ref(), &vec![])
            .unwrap()
            .selected,
        vec![selection()]
    );
    assert_eq!(source.calls.get(), 1);
}

#[cfg(unix)]
#[test]
fn installed_typed_client_route_uses_actual_framed_peer_credentials() {
    use crate::client::{ClientPeer, ClientSession};
    use crate::connection::{
        BodySchemaVerifier, ConnectionIncident, ConnectionSupervisor, ReceivedBody,
    };
    use crate::transport::{FrameReader, write_frame_with_limits};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    struct Supervisor;

    impl ConnectionSupervisor for Supervisor {
        fn quarantine(&self, _: ConnectionIncident) {}
    }

    struct Schemas;

    impl BodySchemaVerifier for Schemas {
        fn verify(
            &self,
            authority: &ConnectionAuthority,
            _: &crate::envelope::Envelope,
            _: &ReceivedBody,
        ) -> Result<(), ProviderError> {
            if authority.selected_extensions() == Some([selection()].as_slice()) {
                Ok(())
            } else {
                Err(ProviderError::Correlation(
                    "typed selection was not retained",
                ))
            }
        }
    }

    let (controller, mut provider) = UnixStream::pair().unwrap();
    provider
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    provider
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let (request, response) = pair(false, "hello/socket");
    let original = serde_json::to_value(&request).unwrap();
    let response = serde_json::to_value(response).unwrap();
    let server = std::thread::spawn(move || {
        let mut reader =
            FrameReader::with_limits(provider.try_clone().unwrap(), 65536, 64).unwrap();
        assert_eq!(reader.read().unwrap(), Some(original));
        write_frame_with_limits(&mut provider, &response, 65536, 64).unwrap();
    });
    let executable =
        crate::conformance::measure_executable(&std::env::current_exe().unwrap()).unwrap();
    let peer = ClientPeer {
        pid: std::process::id(),
        uid: rustix::process::getuid().as_raw(),
        executable,
    };
    let source = installed(false);
    let mut handshake = ExtensionHandshake::new(configured(), source.clone()).unwrap();

    // The original actual socket peer is this fixture process; this control
    // validates transport/registry composition, not a native provider class.
    let session = ClientSession::negotiate_extensions(
        controller,
        &peer,
        &request,
        id("connection/socket"),
        &mut handshake,
        &mut Verifier::default(),
        Rc::new(Supervisor),
        Rc::new(Schemas),
        Duration::from_secs(2),
        65536,
        64,
    )
    .unwrap();

    assert_eq!(session.peer_pid(), std::process::id());
    assert_eq!(
        session.authority().selected_extensions(),
        Some([selection()].as_slice())
    );
    assert_eq!(source.calls.get(), 1);
    server.join().unwrap();
}

#[test]
fn raw_roster_credit_precedes_typed_reconstruction_and_installed_callbacks() {
    use super::extension_contract::decode_bounded;
    use serde::Deserialize;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static DECODE_CALLS: AtomicUsize = AtomicUsize::new(0);

    struct DecodeProbe;

    impl<'de> Deserialize<'de> for DecodeProbe {
        fn deserialize<D: serde::Deserializer<'de>>(_: D) -> Result<Self, D::Error> {
            DECODE_CALLS.fetch_add(1, Ordering::Relaxed);
            Err(serde::de::Error::custom("typed reconstruction reached"))
        }
    }

    let roster: Vec<_> = (0..=MAXIMUM_NEGOTIATED_EXTENSIONS)
        .map(|index| {
            let mut tuple = selection();
            tuple.identifier = id(&format!("vendor.example/contract{index:03}"));
            tuple
        })
        .collect();
    let values = [
        serde_json::json!({"format":"1","required":roster,"optional":[]}),
        serde_json::json!({"format":"1","required":roster[..128],"optional":roster[128..]}),
        serde_json::json!({"format":"1","selected":roster}),
    ];
    for value in &values {
        assert!(serde_json::to_vec(value).unwrap().len() < MAXIMUM_EXTENSION_NEGOTIATION_BYTES);
        assert!(matches!(
            decode_bounded::<DecodeProbe>(value),
            Err(ProviderError::ResourceExhausted(
                "extension negotiation entries"
            ))
        ));
    }
    // Struct deserialization can accept positional arrays. A closed wire
    // object is required before any tuple reconstruction, including this form.
    let positional = serde_json::json!(["1", roster, []]);
    assert!(decode_bounded::<DecodeProbe>(&positional).is_err());
    assert_eq!(DECODE_CALLS.load(Ordering::Relaxed), 0);

    let exact = serde_json::json!({"format":"1","selected":roster[..256]});
    let selected: ExtensionSelectionV1 = decode_bounded(&exact).unwrap();
    selected.validate().unwrap();
    assert_eq!(selected.selected.len(), MAXIMUM_NEGOTIATED_EXTENSIONS);

    let source = installed(false);
    let mut handshake = ExtensionHandshake::new(configured(), source.clone()).unwrap();
    let (mut request, response) = pair(false, "hello/entry-credit");
    request
        .extensions
        .insert(EXTENSION_NEGOTIATION_V1.into(), values[1].clone());
    assert!(
        handshake
            .admit_envelopes(
                &request,
                &response,
                id("connection/entry-credit"),
                &mut Verifier::default(),
            )
            .is_err()
    );
    assert_eq!(source.calls.get(), 0);
}

#[test]
fn registrar_refuses_equal_wire_identity_from_another_original_gate() {
    let source = installed(false);
    let mut original = ExtensionHandshake::new(configured(), source.clone()).unwrap();
    let mut foreign = ExtensionHandshake::new(configured(), source).unwrap();
    let (request, response) = pair(false, "hello/same");
    let own = original
        .admit_envelopes(
            &request,
            &response,
            id("connection/same"),
            &mut Verifier::default(),
        )
        .unwrap();
    let other = foreign
        .admit_envelopes(
            &request,
            &response,
            id("connection/same"),
            &mut Verifier::default(),
        )
        .unwrap();

    assert_eq!(own.selected_extensions(), other.selected_extensions());
    assert_eq!(own.session_id(), other.session_id());
    assert_eq!(own.incarnation_id(), other.incarnation_id());
    assert!(original.verify_authority(&own).is_ok());
    assert!(original.verify_authority(&other).is_err());
    assert!(foreign.verify_authority(&own).is_err());
    assert!(other.ensure_live().is_ok());
}

#[test]
fn registrar_containment_refuses_its_retained_controller_lease() {
    let mut original = ExtensionHandshake::new(configured(), installed(false)).unwrap();
    let (request, response) = pair(false, "hello/1");
    let own = original
        .admit_envelopes(
            &request,
            &response,
            id("connection/1"),
            &mut Verifier::default(),
        )
        .unwrap();
    assert!(original.verify_authority(&own).is_ok());

    original.contain();

    assert!(original.verify_authority(&own).is_err());
    assert_eq!(own.selected_extensions(), Some([selection()].as_slice()));
}

#[test]
fn registrar_refuses_superseded_epoch_while_preserving_exact_resumed_selection() {
    let mut original = ExtensionHandshake::new(configured(), installed(false)).unwrap();
    let mut verifier = Verifier::default();
    let (request, response) = pair(false, "hello/1");
    let old = original
        .admit_envelopes(&request, &response, id("connection/1"), &mut verifier)
        .unwrap();
    let (request, response) = pair(true, "hello/2");

    let current = original
        .admit_envelopes(&request, &response, id("connection/2"), &mut verifier)
        .unwrap();

    assert!(original.verify_authority(&old).is_err());
    assert!(original.verify_authority(&current).is_ok());
    assert_eq!(old.selected_extensions(), current.selected_extensions());
}
