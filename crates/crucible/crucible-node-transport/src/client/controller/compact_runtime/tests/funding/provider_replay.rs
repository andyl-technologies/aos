//! Checks provider-only replay funding against actual retained socket traffic.

use super::*;

#[test]
fn packet_replay_prices_provider_clones_without_controller_history_credit() -> TestResult {
    let (mut handshake, mut original, mut peer, reference) = fixture(256);
    let controller = original.as_mut().unwrap();
    assert_eq!(
        controller.original_packet_runtime_provider_replay_storage_data(0)?,
        [0, 0]
    );
    let server = std::thread::spawn(move || {
        let mut reader = FrameReader::new(peer.try_clone().unwrap(), 65_536).unwrap();
        let first = read(&mut reader);
        let mut terminal = refusal(&first, 2);
        terminal.body["error"]["details"] = json!({"dense": vec![json!({"": [0, "text"]}); 512]});
        write(&mut peer, &terminal);

        let second = read(&mut reader);
        for index in 0..3 {
            let mut incoming = blob(
                &second,
                &reference,
                b"original content",
                index,
                index as u64 + 3,
            );
            incoming.extensions.insert(
                "resume-envelope".into(),
                json!({"dense": vec![json!({"": [0, "provider history"]}); 512]}),
            );
            write(&mut peer, &incoming);
            incoming.matches_response(&read(&mut reader)).unwrap();
        }
        write(&mut peer, &refusal(&second, 6));
    });
    controller.call(
        id("controller-only"),
        None,
        Method::Discover,
        false,
        discover(),
    )?;
    assert_eq!(
        controller.original_packet_runtime_provider_replay_storage_data(0)?,
        [0, 0]
    );
    controller.call(
        id("provider-content"),
        None,
        Method::Discover,
        false,
        discover(),
    )?;
    server.join().unwrap();
    let before = prefix(controller);
    let quotas = controller.custody.runtime_journal_bytes_data();

    let row = controller.original_packet_runtime_provider_replay_storage_data(usize::MAX)?;

    let mut largest = 0;
    let mut count = 0;
    for original in controller
        .custody
        .originals_by_origin(RequestOrigin::Provider)
    {
        let response = original.response.as_ref().unwrap().clone();
        let bytes = canonical::canonical_json(&serde_json::to_value(&response)?)?.len();
        largest = largest.max(bytes);
        count += 1;
        let mut observer = MetadataObserver::new();
        observer.observe(&response)?;
        let backing = requested_metadata_backing_storage_data(&observer.finish())?;
        assert!(row[1] >= backing + std::mem::size_of::<Envelope>());
    }
    assert_eq!(count, 3);
    assert_eq!(row[0], largest);
    assert!(row[0] > 4096);
    assert!(controller.original_compact_runtime_legacy_clone_storage_data(usize::MAX)? > row[1]);
    let maximum = *row.iter().max().unwrap();
    assert_eq!(
        controller.original_packet_runtime_provider_replay_storage_data(maximum)?,
        row
    );
    assert!(
        controller
            .original_packet_runtime_provider_replay_storage_data(maximum - 1)
            .is_err()
    );

    let prior = original.take().unwrap();
    let (mut smaller_handshake, authority) =
        crate::handshake::tests::controller_authority_with_frame_limit(true, 4096)?;
    let (session, _peer) =
        ClientSession::controller_fixture(authority, Rc::new(Supervisor), Rc::new(Schemas))?;
    let mut controller = CnpController::new(session, prior.custody, prior.route, prior.budget)?;
    assert_eq!(
        controller.original_packet_runtime_provider_replay_storage_data(maximum)?,
        row
    );

    controller.fence();
    handshake.contain();
    smaller_handshake.contain();

    assert!(controller.authority().ensure_live().is_err());
    assert_eq!(
        controller.original_packet_runtime_provider_replay_storage_data(maximum)?,
        row
    );
    assert_eq!(controller.custody.runtime_journal_bytes_data(), quotas);
    assert_eq!(prefix(&controller), before);
    Ok(())
}

#[test]
fn packet_replay_does_not_price_unresolved_provider_history_as_empty() -> TestResult {
    let (_handshake, mut original, mut peer, _) = fixture(256);
    let controller = original.as_mut().unwrap();
    let reference = canonical::content_ref(&vec![0; 262_145], "application/octet-stream")?;
    let server = std::thread::spawn(move || {
        let mut reader = FrameReader::new(peer.try_clone().unwrap(), 65_536).unwrap();
        let request = read(&mut reader);
        let incoming = blob(&request, &reference, b"", 0, 2);
        write(&mut peer, &incoming);
    });

    // The original provider request is retained before its excessive content
    // reservation refuses. The real failed exchange leaves that reply absent.
    let result = controller.call(
        id("provider-content"),
        None,
        Method::Discover,
        false,
        discover(),
    );
    server.join().unwrap();
    assert!(matches!(
        result,
        Err(ProviderError::ResourceExhausted("client content custody"))
    ));
    let originals = controller
        .custody
        .originals_by_origin(RequestOrigin::Provider)
        .collect::<Vec<_>>();
    assert_eq!(originals.len(), 1);
    assert!(originals[0].response.is_none());
    let before = prefix(controller);
    let quotas = controller.custody.runtime_journal_bytes_data();

    assert!(
        controller
            .original_packet_runtime_provider_replay_storage_data(usize::MAX)
            .is_err()
    );
    assert_eq!(controller.custody.runtime_journal_bytes_data(), quotas);
    assert_eq!(prefix(controller), before);
    Ok(())
}
