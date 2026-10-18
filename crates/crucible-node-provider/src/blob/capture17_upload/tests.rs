//! Exercises actual inert receiver transitions without manufacturing native actions.

use super::*;
use crucible_node_contract::canonical;

#[derive(Default)]
struct Supervisor(RefCell<Vec<BlobQuarantine>>);
impl BlobSupervisor for Supervisor {
    fn quarantine(&self, custody: BlobQuarantine) {
        self.0.borrow_mut().push(custody);
    }
}

fn receiver() -> Result<(BlobReceiver, Rc<Supervisor>), ProviderError> {
    let supervisor = Rc::new(Supervisor::default());
    let receiver = BlobReceiver::new(
        Id::new("session")?,
        Id::new("incarnation")?,
        BlobLimits {
            reserved_bytes: 1_048_576,
            content_bytes: 65536,
            chunk_bytes: 64,
            transfers_per_origin: 128,
            tombstones_per_origin: 128,
            chunks_per_transfer: 65536,
            operation_pins: 128,
        },
        supervisor.clone(),
    )?;
    Ok((receiver, supervisor))
}

fn key(transfer: &str) -> Result<TransferKey, ProviderError> {
    Ok(TransferKey {
        origin: RequestOrigin::Controller,
        session: Id::new("session")?,
        incarnation: Id::new("incarnation")?,
        transfer: Id::new(transfer)?,
    })
}

fn borrowed(key: &TransferKey) -> NativeCapture17UploadKey<'_> {
    NativeCapture17UploadKey {
        origin: key.origin,
        session: &key.session,
        incarnation: &key.incarnation,
        transfer: &key.transfer,
    }
}

#[test]
fn begin_prices_full_new_bank_and_retry_keeps_only_new_result_reply_owners()
-> Result<(), ProviderError> {
    let (mut receiver, _) = receiver()?;
    let (other, _) = self::receiver()?;
    let key = key("transfer")?;
    let reference = canonical::content_ref(&[7; 512], "application/octet-stream")?;
    let input = NativeCapture17UploadInput::Begin {
        key: borrowed(&key),
        content: &reference,
    };
    let first = receiver.quote_capture17_upload_storage_data(input, usize::MAX)?;
    first.authenticate_data(&receiver, input)?;
    assert!(first.authenticate_owner_input_data(&other, input).is_err());
    let exact =
        usize::try_from(first.row_data().requested_peak_data()?).map_err(|_| exhausted())?;
    assert!(
        receiver
            .quote_capture17_upload_storage_data(input, exact)
            .is_ok()
    );
    assert!(
        receiver
            .quote_capture17_upload_storage_data(input, exact - 1)
            .is_err()
    );

    let progress = receiver.begin(key.clone(), reference.clone())?;

    assert_eq!(progress.next_offset.get(), 0);
    assert!(first.authenticate_data(&receiver, input).is_err());
    first.authenticate_owner_input_data(&receiver, input)?;
    let retry = receiver.quote_capture17_upload_storage_data(input, usize::MAX)?;
    let node = tree::insertion_data::<TransferKey, TransferRecord>(0)?;
    assert!(
        first.row_data().retained_requested_bytes.get()
            >= retry.row_data().retained_requested_bytes.get()
                + 512
                + u64::try_from(node).map_err(|_| exhausted())?
    );
    assert!(
        receiver
            .state
            .borrow()
            .records
            .get(&key)
            .ok_or_else(refused)?
            .bytes
            .capacity()
            >= 512
    );
    Ok(())
}

#[test]
fn populated_record_and_chunk_maps_price_full_split_chain_from_actual_lengths()
-> Result<(), ProviderError> {
    let (mut receiver, _) = receiver()?;
    let reference = canonical::content_ref(&[7; 512], "application/octet-stream")?;
    for index in 0..10 {
        receiver.begin(key(&format!("old-{index:02}"))?, reference.clone())?;
    }
    let next = key("next")?;
    let input = NativeCapture17UploadInput::Begin {
        key: borrowed(&next),
        content: &reference,
    };
    let at_ten = receiver.quote_capture17_upload_storage_data(input, usize::MAX)?;
    receiver.begin(key("old-10")?, reference.clone())?;
    let at_eleven = receiver.quote_capture17_upload_storage_data(input, usize::MAX)?;
    let growth = tree::insertion_data::<TransferKey, TransferRecord>(11)?
        - tree::insertion_data::<TransferKey, TransferRecord>(10)?;
    assert_eq!(
        at_eleven.row_data().retained_requested_bytes.get()
            - at_ten.row_data().retained_requested_bytes.get(),
        u64::try_from(growth).map_err(|_| exhausted())?
    );

    receiver.begin(next.clone(), reference)?;
    let byte = Bytes::new(vec![7]);
    for offset in 0..10 {
        receiver.chunk(&next, U64::new(offset), &byte)?;
    }
    let at_ten = receiver.quote_capture17_upload_storage_data(
        NativeCapture17UploadInput::Chunk {
            key: borrowed(&next),
            offset: U64::new(10),
            bytes: &byte,
        },
        usize::MAX,
    )?;
    receiver.chunk(&next, U64::new(10), &byte)?;
    let at_eleven = receiver.quote_capture17_upload_storage_data(
        NativeCapture17UploadInput::Chunk {
            key: borrowed(&next),
            offset: U64::new(11),
            bytes: &byte,
        },
        usize::MAX,
    )?;
    assert!(
        at_eleven.row_data().retained_requested_bytes > at_ten.row_data().retained_requested_bytes
    );
    let retry = receiver.quote_capture17_upload_storage_data(
        NativeCapture17UploadInput::Chunk {
            key: borrowed(&next),
            offset: U64::new(0),
            bytes: &byte,
        },
        usize::MAX,
    )?;
    assert_eq!(
        at_eleven.row_data().retained_requested_bytes.get()
            - retry.row_data().retained_requested_bytes.get(),
        u64::try_from(tree::insertion_data::<usize, usize>(11)?).map_err(|_| exhausted())?
    );
    Ok(())
}

#[test]
fn changed_retry_gap_and_overrun_preserve_original_acked_bytes_and_boundaries()
-> Result<(), ProviderError> {
    let (mut receiver, _) = receiver()?;
    let key = key("transfer")?;
    receiver.begin(
        key.clone(),
        canonical::content_ref(b"abcd", "application/octet-stream")?,
    )?;
    receiver.chunk(&key, U64::new(0), &Bytes::new(b"ab".to_vec()))?;
    let valid = Bytes::new(b"cd".to_vec());
    let input = NativeCapture17UploadInput::Chunk {
        key: borrowed(&key),
        offset: U64::new(2),
        bytes: &valid,
    };
    let quote = receiver.quote_capture17_upload_storage_data(input, usize::MAX)?;
    let changed = Bytes::new(b"zz".to_vec());
    assert!(
        receiver
            .quote_capture17_upload_storage_data(
                NativeCapture17UploadInput::Chunk {
                    key: borrowed(&key),
                    offset: U64::new(0),
                    bytes: &changed,
                },
                usize::MAX
            )
            .is_err()
    );
    assert!(receiver.chunk(&key, U64::new(0), &changed).is_err());
    assert!(receiver.chunk(&key, U64::new(3), &valid).is_err());
    assert!(receiver.chunk(&key, U64::new(4), &valid).is_err());
    quote.authenticate_data(&receiver, input)?;
    let state = receiver.state.borrow();
    let record = state.records.get(&key).ok_or_else(refused)?;
    assert_eq!(record.bytes, b"ab");
    assert_eq!(record.chunks, BTreeMap::from([(0, 2)]));
    Ok(())
}

#[test]
fn corrupt_and_truncated_finish_quotes_allow_real_quarantine_and_keep_full_bank()
-> Result<(), ProviderError> {
    for content in [b"wrong".as_slice(), b"ri".as_slice()] {
        let (mut receiver, _) = receiver()?;
        let key = key("transfer")?;
        receiver.begin(
            key.clone(),
            canonical::content_ref(b"right", "application/octet-stream")?,
        )?;
        receiver.chunk(&key, U64::new(0), &Bytes::new(content.to_vec()))?;
        let input = NativeCapture17UploadInput::Finish {
            key: borrowed(&key),
        };
        let quote = receiver.quote_capture17_upload_storage_data(input, usize::MAX)?;
        quote.authenticate_data(&receiver, input)?;
        let capacity = receiver
            .state
            .borrow()
            .records
            .get(&key)
            .ok_or_else(refused)?
            .bytes
            .capacity();

        assert!(receiver.finish(&key).is_err());

        assert!(quote.authenticate_data(&receiver, input).is_err());
        assert!(
            receiver
                .quote_capture17_upload_storage_data(input, usize::MAX)
                .is_err()
        );
        let state = receiver.state.borrow();
        let record = state.records.get(&key).ok_or_else(refused)?;
        assert!(record.quarantined);
        assert!(!record.verified);
        assert!(record.charged);
        assert_eq!(record.bytes, content);
        assert_eq!(record.bytes.capacity(), capacity);
        assert_eq!(state.reserved, 5);
    }
    Ok(())
}

#[test]
fn successful_finish_retry_owns_real_distinct_possession_and_supervised_same_ledger()
-> Result<(), ProviderError> {
    let (mut receiver, supervisor) = receiver()?;
    let key = key("transfer")?;
    let reference = canonical::content_ref(b"actual", "application/octet-stream")?;
    receiver.begin(key.clone(), reference.clone())?;
    receiver.chunk(&key, U64::new(0), &Bytes::new(b"actual".to_vec()))?;
    let first = receiver.finish(&key)?;
    let input = NativeCapture17UploadInput::Finish {
        key: borrowed(&key),
    };
    let quote = receiver.quote_capture17_upload_storage_data(input, usize::MAX)?;
    let retry = receiver.finish(&key)?;
    quote.authenticate_data(&receiver, input)?;
    assert_eq!(first.content(), retry.content());
    assert_eq!(retry.transfer(), &key);
    assert!(!std::ptr::eq(first.content(), retry.content()));
    let owner = Rc::clone(&receiver.state);

    drop(receiver);

    let custody = supervisor.0.borrow();
    assert_eq!(custody.len(), 1);
    assert!(Rc::ptr_eq(&custody[0].state, &owner));
    assert_eq!(
        owner.borrow().records.get(&key).ok_or_else(refused)?.bytes,
        b"actual"
    );
    Ok(())
}

#[test]
fn readonly_state_stamp_covers_custody_flags_counters_limits_and_actual_capacities()
-> Result<(), ProviderError> {
    let (mut receiver, _) = receiver()?;
    let key = key("transfer")?;
    receiver.begin(
        key.clone(),
        canonical::content_ref(b"actual", "application/octet-stream")?,
    )?;
    let before = identity::receiver_data(&receiver)?;
    for flag in 0..4 {
        {
            let mut state = receiver.state.borrow_mut();
            let record = state.records.get_mut(&key).ok_or_else(refused)?;
            let field = match flag {
                0 => &mut record.verified,
                1 => &mut record.quarantined,
                2 => &mut record.exposed,
                _ => &mut record.charged,
            };
            *field = !*field;
        }
        assert_ne!(identity::receiver_data(&receiver)?, before);
        {
            let mut state = receiver.state.borrow_mut();
            let record = state.records.get_mut(&key).ok_or_else(refused)?;
            let field = match flag {
                0 => &mut record.verified,
                1 => &mut record.quarantined,
                2 => &mut record.exposed,
                _ => &mut record.charged,
            };
            *field = !*field;
        }
    }
    assert_eq!(identity::receiver_data(&receiver)?, before);
    receiver.limits.chunk_bytes += 1;
    assert_ne!(identity::receiver_data(&receiver)?, before);
    receiver.limits.chunk_bytes -= 1;
    receiver.state.borrow_mut().next_pin += 1;
    assert_ne!(identity::receiver_data(&receiver)?, before);
    receiver.state.borrow_mut().next_pin -= 1;
    receiver
        .state
        .borrow_mut()
        .records
        .get_mut(&key)
        .ok_or_else(refused)?
        .content
        .media_type
        .reserve(128);
    assert_ne!(identity::receiver_data(&receiver)?, before);
    Ok(())
}

#[test]
fn actual_quote_retains_partial_ledger_after_generic_receiver_drop_without_new_drop_policy()
-> Result<(), ProviderError> {
    let (mut receiver, supervisor) = receiver()?;
    let key = key("partial")?;
    receiver.begin(
        key.clone(),
        canonical::content_ref(b"actual", "application/octet-stream")?,
    )?;
    receiver.chunk(&key, U64::new(0), &Bytes::new(b"ac".to_vec()))?;
    let input = NativeCapture17UploadInput::Finish {
        key: borrowed(&key),
    };
    let quote = receiver.quote_capture17_upload_storage_data(input, usize::MAX)?;

    drop(receiver);

    // The existing generic destructor does not supervise unverified partials.
    // The new actual same-ledger owner keeps its ACKed state reachable instead.
    assert!(supervisor.0.borrow().is_empty());
    let state = quote.owner.borrow();
    let actual = state.records.get(&key).ok_or_else(refused)?;
    assert_eq!(actual.bytes, b"ac");
    assert_eq!(actual.chunks, BTreeMap::from([(0, 2)]));
    assert!(actual.charged);
    Ok(())
}

#[test]
fn actual_storage_data_keeps_real_shared_alias_edges_without_copying_ledger()
-> Result<(), ProviderError> {
    use crate::retained_metadata::{aliases::MetadataAliasBank, records::MetadataRecordBank};
    let (receiver, _) = receiver()?;
    let key = key("transfer")?;
    let reference = canonical::content_ref(b"data", "application/octet-stream")?;
    let quote = receiver.quote_capture17_upload_storage_data(
        NativeCapture17UploadInput::Begin {
            key: borrowed(&key),
            content: &reference,
        },
        usize::MAX,
    )?;
    let view = serde_json::to_value(quote.borrowed_current17_fields_data())
        .map_err(crucible_node_contract::ContractError::from)?;
    assert_eq!(
        view.get("ledger").and_then(serde_json::Value::as_str),
        Some("current-native-blob-ledger")
    );
    assert!(view.get("records").is_none());
    let mut records = MetadataRecordBank::reserve(16)?;
    let mut aliases = MetadataAliasBank::reserve(8)?;
    let mut observer = MetadataObserver::recording_with_aliases(&mut records, &mut aliases);
    quote.observe_current17_metadata_data(&mut observer)?;
    let facts = observer.finish();
    assert_eq!(facts.shared_backing_views, 2);
    assert_eq!(aliases.retained_rows(), 2);
    assert!(Rc::ptr_eq(&quote.owner, &receiver.state));
    Ok(())
}

#[test]
fn static_correspondence_binds_complete_actual_phase_key_reference_offset_and_bytes()
-> Result<(), ProviderError> {
    let (mut receiver, _) = receiver()?;
    let key = key("transfer")?;
    let reference = canonical::content_ref(b"actual", "application/octet-stream")?;
    let begin = NativeCapture17UploadInput::Begin {
        key: borrowed(&key),
        content: &reference,
    };
    let quote = receiver.quote_capture17_upload_storage_data(begin, usize::MAX)?;
    for changed in [
        ContentRef {
            length: U64::new(7),
            ..reference.clone()
        },
        ContentRef {
            media_type: "application/json".into(),
            ..reference.clone()
        },
        canonical::content_ref(b"change", "application/octet-stream")?,
    ] {
        assert!(
            quote
                .authenticate_owner_input_data(
                    &receiver,
                    NativeCapture17UploadInput::Begin {
                        key: borrowed(&key),
                        content: &changed
                    },
                )
                .is_err()
        );
    }
    let other_key = self::key("another")?;
    assert!(
        quote
            .authenticate_owner_input_data(
                &receiver,
                NativeCapture17UploadInput::Begin {
                    key: borrowed(&other_key),
                    content: &reference
                },
            )
            .is_err()
    );
    assert!(
        quote
            .authenticate_owner_input_data(
                &receiver,
                NativeCapture17UploadInput::Finish {
                    key: borrowed(&key)
                },
            )
            .is_err()
    );

    receiver.begin(key.clone(), reference)?;
    let bytes = Bytes::new(b"act".to_vec());
    let chunk = NativeCapture17UploadInput::Chunk {
        key: borrowed(&key),
        offset: U64::new(0),
        bytes: &bytes,
    };
    let quote = receiver.quote_capture17_upload_storage_data(chunk, usize::MAX)?;
    let changed = Bytes::new(b"alt".to_vec());
    assert!(
        quote
            .authenticate_owner_input_data(
                &receiver,
                NativeCapture17UploadInput::Chunk {
                    key: borrowed(&key),
                    offset: U64::new(0),
                    bytes: &changed,
                },
            )
            .is_err()
    );
    assert!(
        quote
            .authenticate_owner_input_data(
                &receiver,
                NativeCapture17UploadInput::Chunk {
                    key: borrowed(&key),
                    offset: U64::new(1),
                    bytes: &bytes,
                },
            )
            .is_err()
    );
    quote.authenticate_owner_input_data(&receiver, chunk)?;
    assert!(
        receiver
            .state
            .borrow()
            .records
            .get(&key)
            .ok_or_else(refused)?
            .bytes
            .is_empty()
    );
    Ok(())
}
