//! Exercises independent journals against actual retained legacy custody.
//!
//! Socket traffic, immutable content and original identities are real SDK
//! mechanics beneath the modeled registrar. These controls issue no Source18
//! action, memory admission, native phase claim or restoration evidence.

use super::*;
use crate::client::session::compact_journal::prefix::CompactJournalPrefix;
use crate::client::{ClientCustody, ClientOriginal};

fn exchange(
    session: &mut ClientSession,
    legacy: &mut ClientCustody,
    journal: &mut CompactClientJournal,
    request: &mut Envelope,
) -> Result<Envelope, ProviderError> {
    let ClientCustody {
        maximum_requests,
        maximum_bytes,
        retained_bytes,
        controller,
        provider,
        content,
    } = legacy;
    let prefix = CompactJournalPrefix {
        maximum_requests: *maximum_requests,
        remaining_bytes: maximum_bytes
            .checked_sub(*retained_bytes)
            .ok_or_else(credit)?,
        controller,
        provider,
    };
    session.exchange_compact_parts(
        journal,
        content,
        Some(&prefix),
        request,
        Duration::from_secs(2),
    )
}

fn journal(legacy: &ClientCustody) -> Result<CompactClientJournal, ProviderError> {
    let remaining = legacy
        .maximum_bytes
        .checked_sub(legacy.retained_bytes)
        .ok_or_else(credit)?;
    CompactClientJournal::new(legacy.maximum_requests, remaining, 9 * remaining)
}

fn seed(legacy: &mut ClientCustody, origin: RequestOrigin, request: Envelope, completed: bool) {
    let id = request.request_id.0.clone().unwrap();
    let response = completed.then(|| response(&request, json!({}), request.sequence.get()));
    let bytes = canonical::canonical_json(&serde_json::to_value(&request).unwrap())
        .unwrap()
        .len()
        + response.as_ref().map_or(0, |value| {
            canonical::canonical_json(&serde_json::to_value(value).unwrap())
                .unwrap()
                .len()
        });
    legacy.retained_bytes += bytes;
    let original = ClientOriginal {
        identity: request.request_hash(origin).unwrap(),
        request,
        response,
    };
    match origin {
        RequestOrigin::Controller => legacy.controller.insert(id, original),
        RequestOrigin::Provider => legacy.provider.insert(id, original),
    };
}

fn readonly_journals(legacy: &ClientCustody) -> Vec<u8> {
    serde_json::to_vec(&(
        legacy.maximum_requests,
        legacy.maximum_bytes,
        legacy.retained_bytes,
        &legacy.controller,
        &legacy.provider,
    ))
    .unwrap()
}

fn transfer(
    original: &Envelope,
    id: &str,
    transfer: &Id,
    reference: &crucible_node_format::ContentRef,
    bytes: &[u8],
    method: Method,
    sequence: u64,
) -> Envelope {
    let mut incoming = original.clone();
    incoming.request_id = Nullable(Some(Id::new(id).unwrap()));
    incoming.sequence = U64::new(sequence);
    incoming.method = method;
    incoming.body = match method {
        Method::BlobBegin => super::super::super::object(BlobBeginRequest {
            transfer_id: transfer.clone(),
            content: reference.clone(),
            extensions: Extensions::new(),
        })
        .unwrap(),
        Method::BlobChunk => super::super::super::object(BlobChunkRequest {
            transfer_id: transfer.clone(),
            offset: U64::new(0),
            bytes: Bytes::new(bytes.to_vec()),
            extensions: Extensions::new(),
        })
        .unwrap(),
        Method::BlobFinish => super::super::super::object(BlobFinishRequest {
            transfer_id: transfer.clone(),
            extensions: Extensions::new(),
        })
        .unwrap(),
        _ => panic!("test transfer method"),
    };
    incoming
}

#[test]
fn original_content_and_cached_prefix_replies_survive_a_real_compact_suffix() -> TestResult {
    let (_lease, mut session, custody, mut peer, mut request) = fixture(BANK_BYTES);
    let mut legacy = ClientCustody::new(8, custody.content)?;
    request.request_id = Nullable(Some(Id::new("legacy-controller")?));
    let original_request = request.clone();
    let old_ref = canonical::content_ref(b"original bytes", "application/octet-stream")?;
    let new_ref = canonical::content_ref(b"new bytes", "application/octet-stream")?;
    let peer_old_ref = old_ref.clone();
    let peer_new_ref = new_ref.clone();
    let (done, wait) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || {
        let mut reader = FrameReader::new(peer.try_clone().unwrap(), 65_536).unwrap();
        let first = read(&mut reader);
        let mut old_chunk = None;
        for (index, method) in [Method::BlobBegin, Method::BlobChunk, Method::BlobFinish]
            .into_iter()
            .enumerate()
        {
            let incoming = transfer(
                &first,
                ["legacy-begin", "legacy-chunk", "legacy-finish"][index],
                &Id::new("legacy-transfer").unwrap(),
                &peer_old_ref,
                b"original bytes",
                method,
                index as u64 + 2,
            );
            if method == Method::BlobChunk {
                old_chunk = Some(incoming.clone());
            }
            write(&mut peer, &incoming);
            read(&mut reader);
        }
        write(&mut peer, &response(&first, json!({"legacy": true}), 5));

        let second = read(&mut reader);
        let mut replay = old_chunk.unwrap();
        replay.sequence = U64::new(6);
        write(&mut peer, &replay);
        let cached_ack = read(&mut reader);
        for (index, method) in [Method::BlobBegin, Method::BlobChunk, Method::BlobFinish]
            .into_iter()
            .enumerate()
        {
            let incoming = transfer(
                &second,
                ["legacy-controller", "runtime-chunk", "runtime-finish"][index],
                &Id::new("runtime-transfer").unwrap(),
                &peer_new_ref,
                b"new bytes",
                method,
                index as u64 + 7,
            );
            write(&mut peer, &incoming);
            read(&mut reader);
        }
        let terminal = response(&second, json!({"runtime": true}), 10);
        write(&mut peer, &terminal);
        wait.recv_timeout(Duration::from_secs(5)).unwrap();
        peer.set_nonblocking(true).unwrap();
        assert!(
            matches!(peer.read(&mut [0]), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
        (cached_ack, terminal)
    });
    let first = session.exchange(&mut legacy, request.clone(), Duration::from_secs(2))?;
    let original_pointer = legacy.content().get(&old_ref)?.as_ptr();
    let prefix_before = readonly_journals(&legacy);
    let quotas = legacy.byte_reservations();
    let mut suffix = journal(&legacy)?;
    request.request_id = Nullable(Some(Id::new("runtime-controller")?));

    let terminal = exchange(&mut session, &mut legacy, &mut suffix, &mut request)?;

    assert_eq!(legacy.content().get(&old_ref)?.as_ptr(), original_pointer);
    assert_eq!(legacy.content().get(&new_ref)?, b"new bytes");
    assert_eq!(readonly_journals(&legacy), prefix_before);
    assert_eq!(legacy.byte_reservations(), quotas);
    assert_eq!(suffix.controller.len(), 1);
    assert_eq!(suffix.provider.len(), 3);
    assert!(legacy.retained_bytes + suffix.retained_bytes <= quotas.0);
    let sequence = session.sequence;
    let retained = suffix.retained_bytes;
    let mut cached = original_request;
    cached.sequence = U64::new(999);

    assert_eq!(
        exchange(&mut session, &mut legacy, &mut suffix, &mut cached)?,
        first
    );

    assert_eq!(cached.sequence, U64::new(999));
    assert_eq!(session.sequence, sequence);
    assert_eq!(suffix.retained_bytes, retained);
    assert_eq!(readonly_journals(&legacy), prefix_before);
    done.send(())?;
    let (ack, expected) = server.join().unwrap();
    assert_eq!(terminal, expected);
    assert_eq!(ack.method, Method::BlobChunk);
    assert_eq!(ack.request_id.0, Some(Id::new("legacy-chunk")?));
    Ok(())
}

#[test]
fn changed_or_unsettled_prefix_and_renewed_credit_refuse_before_assignment() -> TestResult {
    for case in [
        "namespace",
        "changed-original",
        "unsettled",
        "byte-credit",
        "request-credit",
    ] {
        let (_lease, mut session, custody, mut peer, mut request) = fixture(BANK_BYTES);
        let mut legacy = ClientCustody::new(1, custody.content)?;
        seed(
            &mut legacy,
            RequestOrigin::Controller,
            request.clone(),
            case != "unsettled",
        );
        let mut suffix = journal(&legacy)?;
        match case {
            "namespace" => request.request_id = Nullable(Some(Id::new("new-id")?)),
            "changed-original" => {
                request.body.insert("cursor".into(), json!("different"));
            }
            "byte-credit" => suffix.maximum_bytes += 1,
            "request-credit" => suffix.maximum_requests += 1,
            _ => {}
        }
        request.sequence = U64::new(999);
        let before = readonly_journals(&legacy);
        let content = serde_json::to_vec(&legacy.content.protocol_view())?;
        let sequence = session.sequence;

        assert!(
            exchange(&mut session, &mut legacy, &mut suffix, &mut request).is_err(),
            "{case}"
        );

        assert_eq!(session.sequence, sequence, "{case}");
        assert_eq!(request.sequence, U64::new(999), "{case}");
        assert!(suffix.controller.is_empty(), "{case}");
        assert!(suffix.provider.is_empty(), "{case}");
        assert!(suffix.pending.is_none(), "{case}");
        assert_eq!(readonly_journals(&legacy), before, "{case}");
        assert_eq!(
            serde_json::to_vec(&legacy.content.protocol_view())?,
            content,
            "{case}"
        );
        assert_eq!(peer.read(&mut [0])?, 0, "{case}");
    }
    Ok(())
}

#[test]
fn exhausted_provider_prefix_or_changed_replay_retains_the_received_request() -> TestResult {
    for changed_replay in [false, true] {
        let (_lease, mut session, custody, mut peer, mut request) = fixture(BANK_BYTES);
        let mut legacy = ClientCustody::new(1, custody.content)?;
        let reference = canonical::content_ref(b"old", "application/octet-stream")?;
        let old = transfer(
            &request,
            "old-provider",
            &Id::new("old-transfer")?,
            &reference,
            b"old",
            Method::BlobBegin,
            2,
        );
        seed(&mut legacy, RequestOrigin::Provider, old.clone(), true);
        let before = readonly_journals(&legacy);
        let content_before = serde_json::to_vec(&legacy.content.protocol_view())?;
        let mut suffix = journal(&legacy)?;
        let mut incoming = old;
        if changed_replay {
            incoming
                .body
                .insert("transfer_id".into(), json!("changed-transfer"));
        } else {
            incoming.request_id = Nullable(Some(Id::new("new-provider")?));
        }
        let expected = incoming.clone();
        let server = std::thread::spawn(move || {
            let mut reader = FrameReader::new(peer.try_clone().unwrap(), 65_536).unwrap();
            read(&mut reader);
            write(&mut peer, &incoming);
            assert_eq!(peer.read(&mut [0]).unwrap(), 0);
        });

        assert!(exchange(&mut session, &mut legacy, &mut suffix, &mut request).is_err());

        assert_eq!(suffix.pending.as_ref().unwrap().envelope, expected);
        assert!(suffix.provider.is_empty());
        assert_eq!(readonly_journals(&legacy), before);
        assert_eq!(
            serde_json::to_vec(&legacy.content.protocol_view())?,
            content_before
        );
        server.join().unwrap();
    }
    Ok(())
}
