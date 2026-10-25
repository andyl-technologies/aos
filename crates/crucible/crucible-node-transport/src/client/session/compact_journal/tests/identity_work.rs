//! Checks actual frame-bounded identity work independently of lifetime storage.
//!
//! These controls use real compact SDK sockets beneath the inert schema fixture.
//! Their DATA rows and typed transfers create no Source or native permission.

use super::*;
use std::io::Write;

#[test]
fn outgoing_frame_preflight_precedes_hash_validation_and_retention() -> TestResult {
    let (_lease, mut session, mut custody, mut peer, mut request) = fixture(BANK_BYTES);
    let frame = usize::try_from(session.authority.limits().frame_bytes.get())?;
    let work = session.compact_request_identity_storage_data(&custody, usize::MAX)?;
    request.protocol = "invalid protocol sentinel".into();
    request
        .body
        .insert("large".into(), json!("x".repeat(frame)));
    let (_, canonical) = CompactJson::envelope_extents(&request, BANK_BYTES, CONTENT_BYTES)?;
    assert!(canonical > frame);
    assert!(canonical < custody.journal.maximum_bytes);
    let original = request.clone();

    let result = session.exchange_compact(&mut custody, &mut request, Duration::from_secs(2));

    assert!(
        matches!(result, Err(ProviderError::ResourceExhausted(_))),
        "{result:?}"
    );
    assert_eq!(request, original);
    assert_eq!(custody.originals().count(), 0);
    assert_eq!(custody.retained_journal_bytes(), 0);
    assert!(custody.pending_envelope().is_none());
    assert_eq!(
        session.compact_request_identity_storage_data(&custody, usize::MAX)?,
        work
    );
    assert_eq!(peer.read(&mut [0])?, 0);
    Ok(())
}

#[test]
fn exact_canonical_frame_still_publishes_and_retains_its_original() -> TestResult {
    let (_lease, mut session, mut custody, mut peer, mut request) = fixture(BANK_BYTES);
    let frame = usize::try_from(session.authority.limits().frame_bytes.get())?;
    request
        .body
        .insert("extensions".into(), json!({"padding": ""}));
    let base = super::super::super::envelope_bytes(&request)?;
    request.body["extensions"]["padding"] = json!("x".repeat(frame - base));
    assert_eq!(super::super::super::envelope_bytes(&request)?, frame);
    let expected = request.clone();
    let server = std::thread::spawn(move || {
        let mut reader = FrameReader::new(peer.try_clone().unwrap(), frame).unwrap();
        let original = read(&mut reader);
        let terminal = response(&original, json!({}), 2);
        write(&mut peer, &terminal);
        (original, terminal)
    });

    let terminal = session.exchange_compact(&mut custody, &mut request, Duration::from_secs(2))?;
    let (published, received) = server.join().unwrap();

    assert_eq!(published, expected);
    assert_eq!(terminal, received);
    let original = custody
        .original(
            RequestOrigin::Controller,
            request.request_id.0.as_ref().unwrap(),
        )
        .unwrap();
    assert_eq!(original.materialize_request()?, expected);
    assert!(original.has_response());
    Ok(())
}

#[test]
fn identity_quote_uses_actual_frame_and_preserves_independent_journal_credit() -> TestResult {
    let (_lease, session, custody, _peer, _request) = fixture(BANK_BYTES);
    let row = session.compact_request_identity_storage_data(&custody, usize::MAX)?;
    assert_eq!(row[0], 0);
    assert!(row[1] > 0);
    assert_eq!(
        row[2],
        ClientSession::compact_request_identity_counter_scratch_data()
    );
    let peak: usize = row.into_iter().sum();
    assert_eq!(
        session.compact_request_identity_storage_data(&custody, peak)?,
        row
    );
    assert!(
        session
            .compact_request_identity_storage_data(&custody, peak - 1)
            .is_err()
    );

    let mut rows = Vec::new();
    let mut journals = Vec::new();
    for ceiling in [16 * 1024 * 1024, 32 * 1024 * 1024] {
        let content = ClientContent::new(ceiling, 8, 4096)?;
        let large = CompactClientCustody::new(8, content, 9 * ceiling)?;
        rows.push(session.compact_request_identity_storage_data(&large, usize::MAX)?);
        journals.push(large.journal_retained_storage_data(usize::MAX)?);
        assert_eq!(large.retained_journal_bytes(), 0);
        assert_eq!(large.originals().count(), 0);
    }
    // Once the independent journal is larger than any frame's JCS output, its
    // increase changes persistent bank funding, not the identity population.
    assert_eq!(rows[0], rows[1]);
    assert!(journals[1] > journals[0]);
    assert_eq!(custody.retained_journal_bytes(), 0);
    assert_eq!(custody.originals().count(), 0);
    Ok(())
}

#[test]
fn received_noncanonical_frame_can_expand_beyond_outgoing_frame_limit() -> TestResult {
    let (_lease, mut session, mut custody, mut peer, mut request) = fixture(BANK_BYTES);
    let frame = usize::try_from(session.authority.limits().frame_bytes.get())?;
    let work = session.compact_request_identity_storage_data(&custody, usize::MAX)?;
    let server = std::thread::spawn(move || {
        let mut reader = FrameReader::new(peer.try_clone().unwrap(), frame).unwrap();
        let original = read(&mut reader);
        let mut incoming = original.clone();
        incoming.method = Method::BlobBegin;
        incoming.request_id = Nullable(Some(Id::new("numeric-provider-original").unwrap()));
        incoming.sequence = U64::new(2);
        incoming.body = super::super::super::object(BlobBeginRequest {
            transfer_id: Id::new("numeric-transfer").unwrap(),
            content: canonical::content_ref(b"x", "application/octet-stream").unwrap(),
            extensions: Extensions::from([("numeric_data".into(), json!(vec![1e20; 4000]))]),
        })
        .unwrap();
        let raw = serde_json::to_vec(&incoming).unwrap();
        let canonical_bytes = super::super::super::envelope_bytes(&incoming).unwrap();
        assert!(raw.len() < frame);
        assert!(canonical_bytes > frame);
        peer.write_all(&u32::try_from(raw.len()).unwrap().to_be_bytes())
            .unwrap();
        peer.write_all(&raw).unwrap();
        let ack = read(&mut reader);
        let terminal = response(&original, json!({}), 3);
        write(&mut peer, &terminal);
        (incoming, canonical_bytes, ack, terminal)
    });

    let terminal = session.exchange_compact(&mut custody, &mut request, Duration::from_secs(5))?;
    let (incoming, canonical_bytes, ack, expected) = server.join().unwrap();

    assert_eq!(terminal, expected);
    incoming.matches_response(&ack)?;
    let original = custody
        .original(
            RequestOrigin::Provider,
            incoming.request_id.0.as_ref().unwrap(),
        )
        .unwrap();
    assert_eq!(original.materialize_request()?, incoming);
    assert_eq!(
        original.identity(),
        &incoming.request_hash(RequestOrigin::Provider)?
    );
    assert!(original.has_response());
    assert!(work[1] > canonical_bytes);
    assert_eq!(
        session.compact_request_identity_storage_data(&custody, usize::MAX)?,
        work
    );
    Ok(())
}
