//! Refuses unrelated live correlation before an ordinary compact exchange starts.

use super::*;

#[test]
fn outgoing_original_blocks_exchange_before_journal_or_caller_changes() -> TestResult {
    let (_lease, mut session, mut custody, peer, mut request) = fixture(BANK_BYTES);
    let mut unrelated = request.clone();
    unrelated.request_id = Nullable(Some(Id::new("unrelated-control")?));
    session.connection.send_compact(&unrelated)?;
    let mut reader = FrameReader::new(peer.try_clone()?, 65_536)?;
    assert_eq!(read(&mut reader), unrelated);

    request.sequence = U64::new(777);
    let original = request.clone();
    let cut = session.deadline.original_cut();
    let result = session.exchange_compact(&mut custody, &mut request, Duration::from_secs(2));

    assert!(
        matches!(result, Err(ProviderError::Conflict(_))),
        "{result:?}"
    );
    assert_eq!(request, original);
    assert_eq!(session.deadline.original_cut(), cut);
    assert_eq!(custody.originals().count(), 0);
    assert_eq!(custody.retained_journal_bytes(), 0);
    assert!(custody.pending_envelope().is_none());
    assert!(reader.read()?.is_none());
    Ok(())
}

#[test]
fn incoming_original_blocks_exchange_before_journal_or_publication() -> TestResult {
    let (_lease, mut session, mut custody, mut peer, mut request) = fixture(BANK_BYTES);
    let mut unrelated = request.clone();
    unrelated.method = Method::BlobFinish;
    unrelated.request_id = Nullable(Some(Id::new("unrelated-provider")?));
    unrelated.body = super::super::super::object(BlobFinishRequest {
        transfer_id: Id::new("unrelated-transfer")?,
        extensions: Extensions::new(),
    })?;
    write(&mut peer, &unrelated);
    assert_eq!(session.connection.receive()?.unwrap().envelope, unrelated);

    request.sequence = U64::new(777);
    let original = request.clone();
    let cut = session.deadline.original_cut();
    let result = session.exchange_compact(&mut custody, &mut request, Duration::from_secs(2));

    assert!(
        matches!(result, Err(ProviderError::Conflict(_))),
        "{result:?}"
    );
    assert_eq!(request, original);
    assert_eq!(session.deadline.original_cut(), cut);
    assert_eq!(custody.originals().count(), 0);
    assert_eq!(custody.retained_journal_bytes(), 0);
    assert!(custody.pending_envelope().is_none());
    assert_eq!(peer.read(&mut [0])?, 0);
    Ok(())
}
