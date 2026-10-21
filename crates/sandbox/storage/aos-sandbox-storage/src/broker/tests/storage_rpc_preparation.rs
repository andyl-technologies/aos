//! Signs fresh fixture preparation arguments before the real session selects its header.

use super::*;

/// Keeps the portable expiry inside the existing ten-second request lifetime.
/// The fixture issuer signs these new arguments; the transport never edits them.
pub(super) fn fresh(
    fixture: &Fixture,
    template: &[u8],
    clock: &RawPairedClockSample,
) -> (Vec<u8>, ValidatedUntrustedAuthorizationArtifacts) {
    let mut request = PrepareStorageCatalogRequest::decode_from_slice(template).unwrap();
    let expiry = clock
        .boottime_nanoseconds()
        .checked_add(8_000_000_000)
        .unwrap();
    request.preparation_expires_boottime_nanoseconds = expiry;
    request
        .header
        .get_or_insert_default()
        .deadline_boottime_nanoseconds = expiry.checked_add(1).unwrap();
    let request = request.encode_to_vec();
    let artifacts = fixture.preparation_artifacts_for_rpc(&request, clock);

    (request, artifacts)
}

#[test]
fn fresh_signed_expiry_survives_the_session_header_deadline() {
    let fixture = Fixture::new();
    let initial_clock = clock_at([50; 16], 1_750_000_000, 123_456_789_123);
    let later_clock = clock_at([50; 16], 1_750_000_020, 143_456_789_123);
    let catalog = vm_create_catalog(41, 42, "aosproof/aos/project/pinned-workspace");
    let apply = vm_prepare_create_request(
        ObjectDigest::from_bytes([71; 32]),
        initial_clock.boottime_nanoseconds() + 240_000_000_000,
    );
    let (template, _, _) = preparation_request(&apply, &catalog);
    let (request, artifacts) = fresh(&fixture, &template, &later_clock);

    // The real session replaces only this transport header. The separately
    // signed portable expiry remains literal through admission and replay.
    let mut reheadered = PrepareStorageCatalogRequest::decode_from_slice(&request).unwrap();
    let expiry = reheadered.preparation_expires_boottime_nanoseconds;
    reheadered
        .header
        .get_or_insert_default()
        .deadline_boottime_nanoseconds = later_clock.boottime_nanoseconds() + 10_000_000_000;
    let bytes = reheadered.encode_to_vec();
    let semantics = CanonicalStoragePreparationSemanticsV1::decode(
        &bytes,
        rpc_peer(),
        rpc_peer_policy(),
        later_clock.boottime_nanoseconds(),
    )
    .unwrap();
    let admission = fixture
        .authority()
        .admit_preparation(
            &artifacts,
            &semantics,
            &bytes,
            ProtocolVersion::new(1, 0),
            rpc_peer(),
            rpc_peer_policy(),
            &later_clock,
            None,
        )
        .unwrap();

    assert_eq!(semantics.expires_boottime_nanoseconds(), expiry);
    assert!(expiry > later_clock.boottime_nanoseconds());
    assert!(expiry < admission.effect_deadline_boottime_nanoseconds());
    assert_eq!(
        semantics.argument_commitment(),
        CanonicalStoragePreparationSemanticsV1::decode(
            &request,
            rpc_peer(),
            rpc_peer_policy(),
            later_clock.boottime_nanoseconds(),
        )
        .unwrap()
        .argument_commitment(),
    );

    reheadered.preparation_expires_boottime_nanoseconds += 1;
    let changed_bytes = reheadered.encode_to_vec();
    let changed = CanonicalStoragePreparationSemanticsV1::decode(
        &changed_bytes,
        rpc_peer(),
        rpc_peer_policy(),
        later_clock.boottime_nanoseconds(),
    )
    .unwrap();
    assert!(
        fixture
            .authority()
            .admit_preparation(
                &artifacts,
                &changed,
                &changed_bytes,
                ProtocolVersion::new(1, 0),
                rpc_peer(),
                rpc_peer_policy(),
                &later_clock,
                None,
            )
            .is_err()
    );
}
