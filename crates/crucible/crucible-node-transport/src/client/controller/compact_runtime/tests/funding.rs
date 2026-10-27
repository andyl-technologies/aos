//! Checks pre-handoff funding inputs against actual original SDK history.
//!
//! These DATA controls neither issue Source admission nor select native work.

use super::*;
use crate::retained_metadata::{MetadataObserver, requested_metadata_backing_storage_data};

mod provider_replay;

#[test]
fn handoff_preflight_preserves_actual_history_content_and_unconsumed_credit() -> TestResult {
    let (_handshake, mut original, mut peer, reference) = fixture(8);
    let server = std::thread::spawn(move || {
        let mut reader = FrameReader::new(peer.try_clone().unwrap(), 65_536).unwrap();
        let request = read(&mut reader);
        write(&mut peer, &refusal(&request, 2));
    });
    let controller = original.as_mut().unwrap();
    controller.call(id("legacy"), None, Method::Discover, false, discover())?;
    server.join().unwrap();
    let before = prefix(controller);
    let quotas = controller.custody.runtime_journal_bytes_data();
    let content_address = controller.content(&reference)?.as_ptr();
    let journal_quote =
        controller.original_compact_runtime_journal_retained_storage_data(usize::MAX)?;

    // A funding caller holds only an immutable original. Repeated inspection
    // must neither spend its remaining credit nor register a suffix original.
    let controller = original.as_ref().unwrap();
    for _ in 0..2 {
        let suffix = controller.prepare_compact_runtime_handoff_data()?;

        assert_eq!(suffix.runtime_retained_bytes(), 0);
        assert_eq!(
            suffix.runtime_originals(RequestOrigin::Controller).count(),
            0
        );
        assert_eq!(suffix.runtime_originals(RequestOrigin::Provider).count(), 0);
        assert_eq!(suffix.retained_storage_data(usize::MAX)?, journal_quote);
        assert_eq!(controller.custody.runtime_journal_bytes_data(), quotas);
        assert_eq!(prefix(controller), before);
        assert_eq!(controller.content(&reference)?.as_ptr(), content_address);
    }

    let mut output = None;
    CompactRuntimeController::retain_into(&mut original, &mut output)?;
    let runtime = output.as_ref().unwrap();

    assert!(original.is_none());
    assert_eq!(
        runtime.journal_byte_reservations_data(),
        [quotas[0], quotas[1], 0]
    );
    assert_eq!(prefix(&runtime.original), before);
    assert_eq!(runtime.content(&reference)?.as_ptr(), content_address);
    Ok(())
}

#[test]
fn revoked_handoff_preflight_and_move_preserve_original_without_containment() -> TestResult {
    let (mut handshake, session, owner, _witness, _peer) =
        ClientSession::restoration_retained_fixture();
    let content = ClientContent::new(262_144, 8, 4096)?;
    let custody = ClientCustody::new(8, content)?;
    let mut original = Some(CnpController::new(
        session,
        custody,
        ControllerRoute {
            node: id("node"),
            execution_owner: id("owner"),
        },
        Duration::from_secs(2),
    )?);
    let controller = original.as_ref().unwrap();
    controller.prepare_compact_runtime_handoff_data()?;
    let before = prefix(controller);
    let quotas = controller.custody.runtime_journal_bytes_data();
    assert!(owner.is_empty_data()?);

    handshake.contain();
    let controller = original.as_ref().unwrap();
    assert!(controller.prepare_compact_runtime_handoff_data().is_err());
    assert!(!controller.fenced);
    assert_eq!(prefix(controller), before);
    assert_eq!(controller.custody.runtime_journal_bytes_data(), quotas);
    assert!(owner.is_empty_data()?);

    let mut output = None;
    assert!(CompactRuntimeController::retain_into(&mut original, &mut output).is_err());
    assert!(output.is_none());
    let controller = original.as_ref().unwrap();
    assert!(!controller.fenced);
    assert_eq!(prefix(controller), before);
    assert_eq!(controller.custody.runtime_journal_bytes_data(), quotas);
    assert!(owner.is_empty_data()?);
    Ok(())
}

#[test]
fn runtime_identity_query_preserves_original_history_and_survives_fencing() -> TestResult {
    let (mut handshake, mut original, mut peer, _) = fixture(256);
    let controller = original.as_mut().unwrap();
    let empty = controller.original_compact_runtime_identity_storage_data(usize::MAX)?;
    let server = std::thread::spawn(move || {
        let mut reader = FrameReader::new(peer.try_clone().unwrap(), 65_536).unwrap();
        let request = read(&mut reader);
        write(&mut peer, &refusal(&request, 2));
    });
    controller.call(id("legacy"), None, Method::Discover, false, discover())?;
    server.join().unwrap();
    let before = prefix(controller);
    let quotas = controller.custody.runtime_journal_bytes_data();

    let row = controller.original_compact_runtime_identity_storage_data(usize::MAX)?;

    // Retry work is a frame population, independent of new suffix byte credit.
    assert_eq!(row, empty);
    assert_eq!(row[0], 0);
    assert!(row[1] > 0);
    assert_eq!(
        row[2],
        CnpController::original_compact_runtime_identity_counter_scratch_data()
    );
    let peak: usize = row.into_iter().sum();
    assert_eq!(
        controller.original_compact_runtime_identity_storage_data(peak)?,
        row
    );
    assert!(
        controller
            .original_compact_runtime_identity_storage_data(peak - 1)
            .is_err()
    );
    controller.fence();
    handshake.contain();

    assert_eq!(
        controller.original_compact_runtime_identity_storage_data(peak)?,
        row
    );
    assert!(controller.authority().ensure_live().is_err());
    assert_eq!(controller.custody.runtime_journal_bytes_data(), quotas);
    assert_eq!(prefix(controller), before);
    Ok(())
}

#[test]
fn legacy_clone_query_covers_actual_clones_without_using_unused_credit() -> TestResult {
    let (_handshake, mut original, mut peer, reference) = fixture(256);
    let controller = original.as_mut().unwrap();
    assert_eq!(
        controller.original_compact_runtime_legacy_clone_storage_data(0)?,
        0
    );
    let server = std::thread::spawn(move || {
        let mut reader = FrameReader::new(peer.try_clone().unwrap(), 65_536).unwrap();
        let request = read(&mut reader);
        for index in 0..3 {
            let incoming = blob(
                &request,
                &reference,
                b"original content",
                index,
                index as u64 + 2,
            );
            write(&mut peer, &incoming);
            incoming.matches_response(&read(&mut reader)).unwrap();
        }
        let mut terminal = refusal(&request, 5);
        terminal.body["error"]["details"] = json!({"dense": vec![json!({"": [0, "text"]}); 512]});
        write(&mut peer, &terminal);
    });
    controller.call(id("legacy"), None, Method::Discover, false, discover())?;
    server.join().unwrap();
    let before = prefix(controller);
    let quotas = controller.custody.runtime_journal_bytes_data();

    let quote = controller.original_compact_runtime_legacy_clone_storage_data(usize::MAX)?;

    assert!(quote > 0);
    for original in controller.custody.originals() {
        let response = original.response.as_ref().unwrap().clone();
        let mut observer = MetadataObserver::new();
        observer.observe(&response)?;
        let backing = requested_metadata_backing_storage_data(&observer.finish())?;
        assert!(quote >= backing + std::mem::size_of::<Envelope>());
    }
    assert_eq!(
        controller.original_compact_runtime_legacy_clone_storage_data(quote)?,
        quote
    );
    assert!(
        controller
            .original_compact_runtime_legacy_clone_storage_data(quote - 1)
            .is_err()
    );
    let prior = original.take().unwrap();
    let (_smaller_handshake, authority) =
        crate::handshake::tests::controller_authority_with_frame_limit(true, 4096)?;
    let (session, _peer) =
        ClientSession::controller_fixture(authority, Rc::new(Supervisor), Rc::new(Schemas))?;
    let mut controller = CnpController::new(session, prior.custody, prior.route, prior.budget)?;
    assert!(controller.custody.originals().any(|original| {
        let response = original.response.as_ref().unwrap();
        canonical::canonical_json(&serde_json::to_value(response).unwrap())
            .unwrap()
            .len()
            > 4096
    }));
    assert_eq!(
        controller.original_compact_runtime_legacy_clone_storage_data(quote)?,
        quote
    );
    controller.fence();
    assert_eq!(
        controller.original_compact_runtime_legacy_clone_storage_data(quote)?,
        quote
    );
    assert_eq!(controller.custody.runtime_journal_bytes_data(), quotas);
    assert_eq!(prefix(&controller), before);
    Ok(())
}
