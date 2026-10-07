//! Offline contracts for finite requests, custody, byte bounds and unknown facts.

use std::os::{fd::AsRawFd, unix::fs::PermissionsExt};

use super::{
    config::{Credentials, Operation, Selection},
    journal::Journal,
    transport,
};

fn selection() -> Selection {
    Selection {
        version: 1,
        provider: "s3".into(),
        endpoint: "https://storage.example".into(),
        bucket: "fixture-bucket".into(),
        prefix: "tenant/run".into(),
        object_keys: vec!["tenant/run/object".into()],
        operations: vec![
            Operation::BucketHead,
            Operation::Objects,
            Operation::Multipart,
            Operation::ObjectHead,
        ],
        account_id: None,
        token_id: None,
        token_kind: None,
        starts_at: 100,
        expires_at: 200,
        maximum_response_bytes: 4096,
    }
}

fn credentials() -> Credentials {
    serde_json::from_str(r#"{"s3":{"accessKey":"EXAMPLEACCESS","secretKey":"example-private-fixture-secret","region":"auto"},"cloudflareToken":"example-private-fixture-token"}"#).unwrap()
}

#[test]
fn requests_are_closed_metadata_reads_with_exact_prefix() {
    let selected = selection();
    selected.validate(150).unwrap();
    let requests = transport::requests(&selected, &credentials(), 150, 30).unwrap();
    assert_eq!(requests.len(), 4);
    for request in &requests {
        assert!(matches!(request.method.as_str(), "GET" | "HEAD"));
        assert!(!request.semantic.to_string().contains("EXAMPLEACCESS"));
        let url = url::Url::parse(&request.url).unwrap();
        assert_eq!(url.host_str(), Some("storage.example"));
        assert_eq!(url.scheme(), "https");
    }
    let objects = url::Url::parse(&requests[1].url).unwrap();
    assert!(objects
        .query_pairs()
        .any(|(key, value)| key == "prefix" && value == "tenant/run/"));
    assert!(objects
        .query_pairs()
        .any(|(key, value)| key == "max-keys" && value == "1000"));
    assert_eq!(requests[3].method, reqwest::Method::HEAD);
}

#[test]
fn selection_refuses_escape_expiry_bulk_and_mutating_selectors() {
    for prefix in [
        "../outside",
        "tenant//run",
        "tenant/run?grant",
        "tenant\\run",
    ] {
        let mut selected = selection();
        selected.prefix = prefix.into();
        assert!(selected.validate(150).is_err());
    }
    let mut selected = selection();
    selected.object_keys = vec!["tenant/other/object".into()];
    assert!(selected.validate(150).is_err());
    assert!(selection().validate(200).is_err());
    let mut selected = selection();
    selected.expires_at = 401;
    assert!(selected.validate(150).is_err());
    let mut value = serde_json::to_value(selection()).unwrap();
    for operation in ["get_object", "put_object", "delete_object", "create_token"] {
        value["operations"] = serde_json::json!([operation]);
        assert!(serde_json::from_value::<Selection>(value.clone()).is_err());
    }
}

#[test]
fn api_token_routes_are_exact_and_permission_facts_stay_unknown() {
    let mut selected = selection();
    selected.provider = "r2".into();
    selected.account_id = Some("a".repeat(32));
    selected.token_id = Some("b".repeat(32));
    selected.token_kind = Some("account".into());
    selected.operations = vec![
        Operation::TokenVerify,
        Operation::TokenDetails,
        Operation::R2Cors,
    ];
    selected.validate(150).unwrap();
    let requests = transport::requests(&selected, &credentials(), 150, 30).unwrap();
    assert_eq!(
        requests[0].url.as_str(),
        format!(
            "https://api.cloudflare.com/client/v4/accounts/{}/tokens/verify",
            "a".repeat(32)
        )
    );
    let facts = transport::facts(
        Operation::TokenVerify,
        br#"{"success":true,"result":{"status":"active","id":"fixture"}}"#,
        &selected,
    )
    .unwrap();
    assert!(facts["permissionInterpretation"].is_null());
    assert!(facts["selectedCredentialAssociation"].is_null());
    assert!(transport::facts(
        Operation::TokenVerify,
        br#"{"success":false,"result":null}"#,
        &selected
    )
    .is_err());
}

#[test]
fn response_bounds_preserve_exposed_count_without_claiming_eof() {
    let mut body = transport::Body::new();
    body.push(b"1234", 5).unwrap();
    assert!(body.push(b"5678", 5).is_err());
    assert_eq!(body.exposed, 8);
    assert_eq!(body.bytes.as_slice(), b"12345");
    assert!(!body.eof);
    assert_eq!(body.outcome, "unread");
}

#[test]
fn credential_reflection_and_new_token_values_are_withheld_without_hashing() {
    let credentials = credentials();
    assert!(transport::sensitive(
        b"example-private-fixture-secret",
        &credentials
    ));
    assert!(transport::sensitive(
        br#"{"result":{"value":"newly-returned-private-value"}}"#,
        &credentials
    ));
    assert!(transport::sensitive(
        br#"{"result":{"v\u0061lue":"escaped-private-value"}}"#,
        &credentials
    ));
    assert!(transport::sensitive(
        br#"{"result":{"status":"example\u002dprivate-fixture-secret"}}"#,
        &credentials
    ));
    assert!(transport::sensitive(
        b"https://storage.example?X-Amz-Signature=example",
        &credentials
    ));
    assert!(!transport::sensitive(
        br#"{"result":{"status":"active","policies":[]}}"#,
        &credentials
    ));
}

#[test]
fn object_listing_requires_selected_scope_and_preserves_truncation() {
    let xml = "<ListBucketResult><Name>fixture-bucket</Name><Prefix>tenant/run/</Prefix><IsTruncated>true</IsTruncated><NextContinuationToken>opaque</NextContinuationToken><Contents><Key>tenant/run/object</Key><Size>17</Size><ETag>&quot;strong&quot;</ETag></Contents></ListBucketResult>";
    let facts = transport::facts(Operation::Objects, xml.as_bytes(), &selection()).unwrap();
    assert_eq!(facts["listedObjects"][0]["size"], 17);
    assert_eq!(facts["truncated"], true);
    assert!(facts["fullInventory"].is_null());
    assert!(transport::facts(
        Operation::Objects,
        xml.replace("tenant/run/object", "other/object").as_bytes(),
        &selection()
    )
    .is_err());
    assert!(transport::facts(
        Operation::Objects,
        xml.replace("tenant/run/</Prefix>", "other/</Prefix>")
            .as_bytes(),
        &selection()
    )
    .is_err());
}

#[test]
fn inherited_private_input_has_real_count_and_mode_custody() {
    let mut file = tempfile::tempfile().unwrap();
    use std::io::Write;
    file.write_all(b"fixture-private-input").unwrap();
    // Use a named single-link file: an unlinked tempfile is intentionally refused.
    assert!(super::config::inherited(file.as_raw_fd() as u32, 64).is_err());
    let directory = tempfile::tempdir_in(".").unwrap();
    let path = directory.path().join("input.json");
    std::fs::write(&path, b"fixture-private-input").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let file = std::fs::File::open(&path).unwrap();
    assert_eq!(
        super::config::inherited(file.as_raw_fd() as u32, 64)
            .unwrap()
            .as_slice(),
        b"fixture-private-input"
    );
    assert!(super::config::inherited(file.as_raw_fd() as u32, 4).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(super::config::inherited(file.as_raw_fd() as u32, 64).is_err());
}

#[test]
fn journal_is_create_only_private_and_refuses_symlink_parent() {
    let directory = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in(".")
        .unwrap();
    let journal = Journal::create(&directory.path().join("observations")).unwrap();
    let observed = journal.write("intent.json", b"{}").unwrap();
    assert_eq!(observed["byteSize"], "2");
    assert!(journal.write("intent.json", b"changed").is_err());
    assert!(journal.write("../escaped", b"{}").is_err());
    assert_eq!(
        std::fs::metadata(directory.path().join("observations/intent.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    std::os::unix::fs::symlink(
        directory.path().join("observations"),
        directory.path().join("alias"),
    )
    .unwrap();
    assert!(Journal::create(&directory.path().join("alias/second")).is_err());
}

#[test]
fn elapsed_original_cutoff_cannot_be_renewed_after_durable_intent() {
    let now = transport::unix_now().unwrap();
    let mut selected = selection();
    selected.starts_at = now;
    selected.expires_at = now + 3;
    let cutoff = transport::Cutoff::new(&selected).unwrap();
    let directory = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in(".")
        .unwrap();
    let journal = Journal::create(&directory.path().join("observations")).unwrap();
    journal.write("intent.json", b"{}").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1100));
    assert!(cutoff.remaining().is_err());
    assert!(selected.validate(now + 3).is_err());
}
