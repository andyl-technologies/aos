//! Exact production encodings, disabled forwarding and unknown-byte refusals.

use super::*;
use aos_proto_types::{GetRegistryResponse, WhoAmIRequest, WhoAmIResponse};
use axum::body::{to_bytes, Body};

#[tokio::test]
async fn disabled_scope_attaches_nothing_and_reads_nothing() {
    let mut response = Response::new(Body::from("unchanged"));
    produced(
        &mut response,
        b"unchanged",
        "synthetic_fixture",
        b"synthetic source",
        "unresolved",
    );
    assert!(response.extensions().get::<BodyEvidence>().is_none());
    assert!(
        rpc::request::<WhoAmIRequest, WhoAmIResponse>(&WhoAmIRequest::default(), b"{}").is_none()
    );
    assert_eq!(
        to_bytes(response.into_body(), 32).await.unwrap(),
        "unchanged"
    );
}

#[tokio::test]
async fn exact_real_dto_encoding_refuses_unknown_fields_and_wrong_reply_pair() {
    observe(async {
        let original = WhoAmIRequest::default();
        let raw = serde_json::to_vec(&original).unwrap();
        let prepared = rpc::request::<WhoAmIRequest, WhoAmIResponse>(&original, &raw);
        let reply = WhoAmIResponse::default();
        let evidence = rpc::reply(prepared, &reply).unwrap();
        assert_eq!(
            evidence.request.as_ref().unwrap().sha256,
            image(&raw).sha256
        );
        assert_eq!(
            evidence.reply.sha256,
            image(&serde_json::to_vec(&reply).unwrap()).sha256
        );
        assert_eq!(
            evidence.required_projection,
            "bounded_original_and_current_sql_projection"
        );

        assert!(serde_json::from_slice::<WhoAmIRequest>(b"{\"ignored\":\"payload\"}").is_err());
        assert!(rpc::request::<WhoAmIRequest, WhoAmIResponse>(
            &original,
            b"{\"ignored\":\"payload\"}"
        )
        .is_none());
        assert!(rpc::request::<WhoAmIRequest, WhoAmIResponse>(&original, b"{} ").is_none());
        assert!(rpc::request::<WhoAmIRequest, GetRegistryResponse>(&original, &raw).is_none());
        assert!(canonical(&"bounded synthetic field", 2).is_none());
    })
    .await;
}

#[tokio::test]
async fn actual_static_asset_constructor_matches_actual_offered_bytes() {
    let response = observe(crate::web::assets::stylesheet()).await;
    let evidence = response.extensions().get::<BodyEvidence>().unwrap().clone();
    let bytes = to_bytes(response.into_body(), 128 * 1024).await.unwrap();
    assert_eq!(evidence.constructor, "embedded_static_asset");
    assert_eq!(evidence.reply.byte_size, bytes.len().to_string());
    assert_eq!(evidence.reply.sha256, image(&bytes).sha256);
    assert_eq!(&bytes[..], crate::web::assets::STYLESHEET.as_bytes());
    assert!(evidence.request.is_none());
}

#[tokio::test]
async fn encoded_secret_values_are_not_in_the_extension() {
    observe(async {
        let private_value = "synthetic private value; not an actual credential";
        let mut response = Response::new(Body::from(private_value));
        produced(
            &mut response,
            private_value.as_bytes(),
            "synthetic_secret_fixture",
            b"synthetic source",
            "independent_actual_authentication_required",
        );
        let evidence = response.extensions().get::<BodyEvidence>().unwrap();
        let encoded = serde_json::to_string(evidence).unwrap();
        assert!(!encoded.contains(private_value));
        assert_eq!(
            evidence.reply.sha256,
            image(private_value.as_bytes()).sha256
        );
        assert_eq!(
            to_bytes(response.into_body(), 128).await.unwrap(),
            private_value
        );
    })
    .await;
}
