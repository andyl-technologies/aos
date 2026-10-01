//! Provider origin, DNS and bearer-capability privacy regressions.

use super::*;
use aos_proto_types::direct_upload::*;

fn profile(id: u64, origin: &str) -> DirectProviderProfile {
    DirectProviderProfile {
        placement_id: WireInteger::new(id),
        placement_resource_version: WireInteger::new(1),
        write_spec_version: WireInteger::new(1),
        binding_id: WireInteger::new(id),
        binding_resource_version: WireInteger::new(1),
        binding_write_revision: WireInteger::new(1),
        checksum_algorithm: DirectChecksumAlgorithm::Md5,
        provider_origin: origin.into(),
        profile_fingerprint: "a2".repeat(32),
        private_policy_digest: "a3".repeat(32),
    }
}

#[test]
fn provider_origins_are_closed_https_not_path_or_credential_locators() {
    assert_eq!(
        checked_origin("https://s3.provider.test").unwrap(),
        "https://s3.provider.test"
    );
    assert_eq!(
        checked_origin("https://s3.provider.test/").unwrap(),
        "https://s3.provider.test"
    );
    assert_eq!(
        checked_origin("https://s3.provider.test:9443").unwrap(),
        "https://s3.provider.test:9443"
    );

    for origin in [
        "http://s3.provider.test",
        "https://credential-canary@s3.provider.test",
        "https://user:credential-canary@s3.provider.test",
        "https://s3.provider.test/stage",
        "https://s3.provider.test?X-Amz-Signature=credential-canary",
        "https://s3.provider.test#credential-canary",
        "https://S3.provider.test",
        "https://s3.provider.test:443",
        "file:///credential-canary",
    ] {
        let error = checked_origin(origin).unwrap_err();
        assert_eq!(error, ProviderError::InvalidGrant);
        assert!(!format!("{error:?} {error}").contains("credential-canary"));
    }
}

#[test]
fn metadata_and_link_local_are_refused_even_with_private_operator_allowance() {
    for text in [
        "0.0.0.0",
        "0.1.2.3",
        "169.254.169.254",
        "169.254.170.2",
        "224.0.0.1",
        "255.255.255.255",
        "::",
        "fe80::1",
        "ff02::1",
        "fd00:ec2::254",
        "::ffff:169.254.169.254",
        "::169.254.169.254",
    ] {
        let address: IpAddr = text.parse().unwrap();
        assert_eq!(
            check_address(address, false),
            Err(ProviderError::InvalidGrant),
            "{text}"
        );
        assert_eq!(
            check_address(address, true),
            Err(ProviderError::InvalidGrant),
            "{text}"
        );
    }
}

#[test]
fn local_network_exemption_requires_independent_operator_selection() {
    for text in [
        "127.0.0.1",
        "10.1.2.3",
        "172.16.0.1",
        "192.168.0.1",
        "::1",
        "fd00::1",
    ] {
        let address: IpAddr = text.parse().unwrap();
        assert_eq!(
            check_address(address, false),
            Err(ProviderError::InvalidGrant),
            "{text}"
        );
        assert_eq!(check_address(address, true), Ok(()), "{text}");
    }
    for text in ["100.64.0.1", "198.18.0.1", "192.0.0.1"] {
        assert_eq!(
            check_address(text.parse().unwrap(), false),
            Err(ProviderError::InvalidGrant)
        );
    }
    for text in ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"] {
        assert_eq!(check_address(text.parse().unwrap(), false), Ok(()));
    }
}

#[test]
fn profile_counts_origins_and_private_policy_are_bounded_and_debug_redacted() {
    let options = ProviderOptions {
        private_endpoints: vec![PrivateProviderEndpoint {
            origin: "https://operator-origin-canary.test".into(),
            private_cidrs: vec!["10.42.0.0/24".into()],
        }],
        ..Default::default()
    };
    let transport = ProviderTransport::new(
        vec![
            profile(1, "https://s3.provider.test"),
            profile(2, "https://s3.provider.test"),
        ],
        options,
    )
    .unwrap();
    assert_eq!(transport.clients.len(), 1);
    assert_eq!(transport.profiles.len(), 2);
    assert!(
        !transport
            .private_origins
            .contains_key("https://s3.provider.test")
    );
    assert!(!format!("{transport:?}").contains("operator-origin-canary"));

    assert!(ProviderTransport::new(vec![], ProviderOptions::default()).is_err());
    assert!(
        ProviderTransport::new(
            vec![profile(1, "https://s3.provider.test"); 2],
            ProviderOptions::default()
        )
        .is_err()
    );
    let profiles = (1..=17)
        .map(|id| profile(id, "https://s3.provider.test"))
        .collect();
    assert!(ProviderTransport::new(profiles, ProviderOptions::default()).is_err());
    let mut invalid = profile(1, "https://s3.provider.test");
    invalid.private_policy_digest = "unknown".into();
    assert!(ProviderTransport::new(vec![invalid], ProviderOptions::default()).is_err());
}

#[test]
fn provider_errors_expose_no_underlying_transport_or_bearer_values() {
    for error in [
        ProviderError::InvalidGrant,
        ProviderError::Unavailable,
        ProviderError::Denied,
        ProviderError::Expired,
        ProviderError::Rejected,
        ProviderError::Clock,
    ] {
        assert!(std::error::Error::source(&error).is_none());
        let output = format!("{error:?}: {error}");
        assert!(!output.contains("https://"));
        assert!(!output.contains("X-Amz"));
    }
    let invalid = ProviderOptions {
        private_endpoints: vec![PrivateProviderEndpoint {
            origin: "https://operator.test?credential-canary".into(),
            private_cidrs: vec!["10.42.0.0/24".into()],
        }],
        ..Default::default()
    };
    let error =
        ProviderTransport::new(vec![profile(1, "https://s3.provider.test")], invalid).unwrap_err();
    assert!(!format!("{error:?}: {error}").contains("credential-canary"));
}

#[test]
fn exact_private_subnet_admits_fleet_peer_but_not_other_private_or_metadata() {
    let ranges = vec![super::super::network::PrivateRange::parse("10.42.0.0/24").unwrap()];
    assert_eq!(
        check_selected_address("10.42.0.12".parse().unwrap(), Some(&ranges)),
        Ok(())
    );
    for address in [
        "10.43.0.12",
        "127.0.0.1",
        "172.16.0.1",
        "169.254.169.254",
        "fd00:ec2::254",
    ] {
        assert_eq!(
            check_selected_address(address.parse().unwrap(), Some(&ranges)),
            Err(ProviderError::InvalidGrant)
        );
    }
    assert_eq!(
        check_selected_address("10.42.0.12".parse().unwrap(), None),
        Err(ProviderError::InvalidGrant)
    );
    assert_eq!(
        check_selected_address("8.8.8.8".parse().unwrap(), None),
        Ok(())
    );
    let ula = vec![super::super::network::PrivateRange::parse("fd12:3456::/64").unwrap()];
    assert_eq!(
        check_selected_address("fd12:3456::2".parse().unwrap(), Some(&ula)),
        Ok(())
    );
    assert_eq!(
        check_selected_address("fd12:3457::2".parse().unwrap(), Some(&ula)),
        Err(ProviderError::InvalidGrant)
    );
}

#[test]
fn private_cidrs_are_canonical_wholly_private_and_cannot_authorize_metadata() {
    for cidr in [
        "0.0.0.0/0",
        "10.0.0.0/7",
        "10.42.0.1/24",
        "169.254.0.0/16",
        "8.8.8.0/24",
        "100.64.0.0/10",
        "::/0",
        "fe80::/10",
        "fc00::/6",
        "::ffff:10.42.0.0/120",
        "private-canary",
    ] {
        assert!(
            super::super::network::PrivateRange::parse(cidr).is_err(),
            "{cidr}"
        );
    }
    let ranges = vec![super::super::network::PrivateRange::parse("fd00::/8").unwrap()];
    assert_eq!(
        check_selected_address("fd00:ec2::254".parse().unwrap(), Some(&ranges)),
        Err(ProviderError::InvalidGrant)
    );
}

#[test]
fn real_current_date_grant_checks_use_current_clock_and_refuse_expired_retained_capability() {
    use base64::Engine as _;
    use sha2::{Digest as _, Sha256};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let iso = aws_sdk_s3::primitives::DateTime::from_secs(now as i64)
        .fmt(aws_sdk_s3::primitives::DateTimeFormat::DateTime)
        .unwrap();
    let date = iso.replace('-', "").replace(':', "");
    let date = date.trim_end_matches('Z').to_owned() + "Z";
    assert_eq!(date.len(), 16);
    let digest = Sha256::digest(b"abc");
    let intent = DirectUploadIntent {
        version: 1,
        client_operation_id: "11".repeat(32),
        target: DirectUploadTarget::CacheObject {
            cache_id: "cache".into(),
            path: "nar/blob".into(),
        },
        expected_sha256: hex::encode(digest),
        byte_size: WireInteger::new(3),
        part_size: WireInteger::new(8 * 1024 * 1024),
        dependency_phase: DirectDependencyPhase::Content,
        transfer_mode: DirectTransferMode::DirectRequired,
    };
    let part = DirectPart {
        part_number: 1,
        offset: WireInteger::new(0),
        byte_size: WireInteger::new(3),
        sha256: hex::encode(digest),
        checksum: DirectPartChecksum {
            algorithm: DirectChecksumAlgorithm::Md5,
            value: base64::engine::general_purpose::STANDARD
                .encode(<md5::Md5 as md5::Digest>::digest(b"abc")),
        },
    };
    let placement = DirectPlacementRef {
        placement_id: WireInteger::new(1),
        placement_fingerprint: "21".repeat(32),
        placement_resource_version: WireInteger::new(1),
        write_spec_version: WireInteger::new(1),
        binding_id: WireInteger::new(1),
        binding_resource_version: WireInteger::new(1),
        binding_write_revision: WireInteger::new(1),
        profile_fingerprint: "a2".repeat(32),
        private_policy_digest: "a3".repeat(32),
        checksum_algorithm: DirectChecksumAlgorithm::Md5,
    };
    let context = ProviderContext {
        session: DirectSessionRef {
            session_id: "session".into(),
            logical_fingerprint: "31".repeat(32),
        },
        placement: placement.clone(),
        intent,
    };
    let grant = DirectPartGrant {
        session_id: "session".into(),
        logical_fingerprint: "31".repeat(32),
        placement,
        grant_id: "41".repeat(32),
        grant_revision: WireInteger::new(1),
        part: part.clone(),
        method: "PUT".into(),
        url: format!(
            "https://provider.test/bucket/stage?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=access%2F{}%2Fauto%2Fs3%2Faws4_request&X-Amz-Date={date}&X-Amz-Expires=300&X-Amz-Signature={}&X-Amz-SignedHeaders=content-length%3Bcontent-md5%3Bhost&partNumber=1&uploadId=private-upload-canary",
            &date[..8],
            "00".repeat(32)
        ),
        required_headers: vec![
            DirectRequiredHeader {
                name: "content-length".into(),
                value: "3".into(),
            },
            DirectRequiredHeader {
                name: "content-md5".into(),
                value: part.checksum.value.clone(),
            },
        ],
        expires_at: WireInteger::new(now + 300),
    };
    let transport = ProviderTransport::new(
        vec![profile(1, "https://provider.test")],
        ProviderOptions::default(),
    )
    .unwrap();
    transport.check_grant(&context, &part, &grant).unwrap();
    assert!(
        grant
            .validate_for(
                &context.session,
                &context.placement,
                &context.intent,
                &part,
                0,
                0
            )
            .is_err()
    );
    let expired = DirectPartGrant {
        expires_at: WireInteger::new(now),
        ..grant.clone()
    };
    assert_eq!(
        transport.check_grant(&context, &part, &expired),
        Err(ProviderError::Expired)
    );
    let changed = DirectPartGrant {
        part: DirectPart {
            byte_size: WireInteger::new(2),
            ..part.clone()
        },
        ..grant.clone()
    };
    assert_eq!(
        transport.check_grant(&context, &part, &changed),
        Err(ProviderError::InvalidGrant)
    );
    assert!(!format!("{grant:?}").contains("private-upload-canary"));
}

#[tokio::test]
async fn aggregate_stream_budget_spaces_concurrent_parts_without_holding_reservation_lock() {
    let budget = Arc::new(ByteBudget {
        rate: 1000,
        next: tokio::sync::Mutex::new(tokio::time::Instant::now()),
    });
    let start = tokio::time::Instant::now();
    let first = budget.acquire(100).await;
    assert!(first.is_ok());
    let waits = futures_util::future::join(budget.acquire(100), budget.acquire(100)).await;
    assert!(waits.0.is_ok() && waits.1.is_ok());
    assert!(start.elapsed() >= Duration::from_millis(190));
    let unlimited = ByteBudget {
        rate: 0,
        next: tokio::sync::Mutex::new(tokio::time::Instant::now()),
    };
    unlimited.acquire(usize::MAX).await.unwrap();
}
