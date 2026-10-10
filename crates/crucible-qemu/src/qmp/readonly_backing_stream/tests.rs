//! Synthetic stream grammar and saved-account custody controls.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crucible_cas::owned_decode::{DecodeResourceAuthority, ResourceLoan};

use super::*;

struct Authority {
    used: Arc<AtomicU64>,
    calls: AtomicU64,
    revoked: AtomicBool,
    failure: DecodeAdmissionError,
}

struct Credit(Arc<AtomicU64>, u64);

impl Drop for Credit {
    fn drop(&mut self) {
        self.0.fetch_sub(self.1, Ordering::SeqCst);
    }
}

impl DecodeResourceAuthority for Authority {
    fn verify_live(&self) -> Result<(), DecodeAdmissionError> {
        if self.revoked.load(Ordering::SeqCst) {
            Err(self.failure.clone())
        } else {
            Ok(())
        }
    }

    fn reserve(&self, bytes: u64) -> Result<ResourceLoan, DecodeAdmissionError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.verify_live()?;
        self.used.fetch_add(bytes, Ordering::SeqCst);
        Ok(ResourceLoan::new(Credit(self.used.clone(), bytes)))
    }
}

fn original() -> (DecodeBudget, Arc<Authority>) {
    let authority = Arc::new(Authority {
        used: Arc::new(AtomicU64::new(0)),
        calls: AtomicU64::new(0),
        revoked: AtomicBool::new(false),
        failure: DecodeAdmissionError::new(fmt::Error),
    });
    let budget = DecodeBudget::new(authority.clone(), 1024 * 1024).unwrap();
    (budget, authority)
}

fn binding() -> QmpReadOnlyBackingBinding {
    QmpReadOnlyBackingBinding {
        correlation: 7,
        generation: 9,
    }
}

fn material(owners: &[(&[u8], u32, &[u8])]) -> (Vec<u8>, QmpReadOnlyBackingReceipt) {
    let receipt = QmpReadOnlyBackingReceipt {
        schema_version: 1,
        request_correlation: 7,
        stopped_generation: 9,
        owner_count: owners.len() as u64,
        total_used: owners
            .iter()
            .map(|(_, _, payload)| payload.len() as u64)
            .sum(),
        ram_section_bytes: owners
            .iter()
            .map(|(id, _, payload)| 44 + id.len() as u64 + payload.len() as u64)
            .sum(),
        readonly_projection_bytes: 0,
    };
    let mut bytes = b"CRUCALL1".to_vec();
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    for value in [
        receipt.owner_count,
        receipt.total_used,
        receipt.ram_section_bytes,
        0,
        receipt.request_correlation,
        receipt.stopped_generation,
    ] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    for (id, classification, payload) in owners {
        bytes.extend_from_slice(&(id.len() as u32).to_le_bytes());
        bytes.extend_from_slice(id);
        bytes.extend_from_slice(&classification.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        for value in [
            payload.len() as u64,
            payload.len() as u64,
            123,
            payload.len() as u64,
        ] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes.extend_from_slice(payload);
    }
    (bytes, receipt)
}

#[test]
fn fragmented_all_owner_material_preserves_raw_ids_flags_and_payload() {
    let (bytes, receipt) = material(&[(b"A", 0, b""), (&[0xff], 15, b"abc")]);
    for width in [1, 3, 17, 65536] {
        let (budget, _) = original();
        let mut seen = Vec::new();
        let mut payload = Vec::new();
        {
            let mut parser = QmpReadOnlyBackingParser::prepare(&budget, &binding(), |event| {
                match event {
                    BackingEvent::Owner(owner) => {
                        seen.push((
                            owner.id.to_vec(),
                            owner.classification,
                            owner.used,
                            owner.maximum,
                            owner.page,
                        ));
                    }
                    BackingEvent::Payload {
                        owner,
                        offset,
                        bytes,
                    } => {
                        assert_eq!(owner.id, [0xff]);
                        assert_eq!(offset, payload.len() as u64);
                        payload.extend_from_slice(bytes);
                    }
                }
                Ok(())
            })
            .unwrap();
            for chunk in bytes.chunks(width) {
                parser.feed(chunk).unwrap();
            }
            parser.finish(&receipt).unwrap();
            assert!(matches!(
                parser.feed(&[]),
                Err(QmpReadOnlyBackingStreamError::Terminal)
            ));
            assert!(matches!(
                parser.finish(&receipt),
                Err(QmpReadOnlyBackingStreamError::Terminal)
            ));
        }
        assert_eq!(
            seen,
            [(b"A".to_vec(), 0, 0, 0, 123), (vec![0xff], 15, 3, 3, 123)]
        );
        assert_eq!(payload, b"abc");
    }
}

fn refuses(bytes: &[u8], receipt: &QmpReadOnlyBackingReceipt) {
    let (budget, authority) = original();
    let mut parser = QmpReadOnlyBackingParser::prepare(&budget, &binding(), |_| Ok(())).unwrap();
    let result = parser.feed(bytes).and_then(|()| parser.finish(receipt));
    assert!(result.is_err());
    let calls = authority.calls.load(Ordering::SeqCst);
    assert!(matches!(
        parser.feed(&[]),
        Err(QmpReadOnlyBackingStreamError::Terminal)
    ));
    assert!(matches!(
        parser.finish(receipt),
        Err(QmpReadOnlyBackingStreamError::Terminal)
    ));
    assert_eq!(authority.calls.load(Ordering::SeqCst), calls);
}

#[test]
fn every_framing_extent_and_receipt_field_refuses_independently() {
    let (valid, receipt) = material(&[(b"A", 0, b"abc")]);
    for (offset, value) in [
        (0, 0),
        (8, 2),
        (12, 1),
        (16, 0),
        (24, 0),
        (32, 0),
        (40, 1),
        (48, 0),
        (56, 0),
        (64, 0),
        (68, 0),
        (69, 16),
        (73, 1),
        (77, 4),
        (85, 2),
        (101, 2),
    ] {
        let mut bad = valid.clone();
        bad[offset] = value;
        refuses(&bad, &receipt);
    }
    for length in 0..valid.len() {
        refuses(&valid[..length], &receipt);
    }
    let mut trailing = valid.clone();
    trailing.push(0);
    refuses(&trailing, &receipt);
    for field in 0..7 {
        let mut bad = receipt;
        match field {
            0 => bad.schema_version += 1,
            1 => bad.request_correlation += 1,
            2 => bad.stopped_generation += 1,
            3 => bad.owner_count += 1,
            4 => bad.total_used += 1,
            5 => bad.ram_section_bytes += 1,
            _ => bad.readonly_projection_bytes += 1,
        }
        refuses(&valid, &bad);
    }
}

#[test]
fn duplicate_descending_nul_and_oversized_ids_refuse() {
    for ids in [
        [b"A".as_slice(), b"A".as_slice()],
        [b"B".as_slice(), b"A".as_slice()],
        [b"A".as_slice(), b"\0".as_slice()],
    ] {
        let (bytes, receipt) = material(&[(ids[0], 1, b""), (ids[1], 1, b"")]);
        refuses(&bytes, &receipt);
    }
    let (mut bytes, receipt) = material(&[(b"A", 1, b"")]);
    bytes[64..68].copy_from_slice(&256_u32.to_le_bytes());
    refuses(&bytes, &receipt);
}

#[test]
fn callback_io_remains_primary_with_saved_original_secondary() {
    let (budget, authority) = original();
    let (bytes, _) = material(&[(b"A", 1, b"abc")]);
    let mut parser = QmpReadOnlyBackingParser::prepare(&budget, &binding(), |_| {
        authority.revoked.store(true, Ordering::SeqCst);
        Err(io::Error::from(io::ErrorKind::PermissionDenied))
    })
    .unwrap();
    let error = parser.feed(&bytes).unwrap_err();
    let QmpReadOnlyBackingStreamError::Failure(error) = error else {
        panic!("callback must retain its prepared failure owner");
    };
    let primary = error.source().unwrap().downcast_ref::<io::Error>().unwrap();
    assert_eq!(primary.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(error.original_secondary(), Some(&authority.failure));
    assert_eq!(budget.failure().unwrap(), Some(authority.failure.clone()));
}

#[test]
fn callback_refusal_and_ambient_account_switch_cannot_accept() {
    let (budget, authority) = original();
    let (other, other_authority) = original();
    let other_calls = other_authority.calls.load(Ordering::SeqCst);
    let (bytes, receipt) = material(&[(b"A", 1, b"")]);
    let scope = other.enter();
    let mut parser = QmpReadOnlyBackingParser::prepare(&budget, &binding(), |_| {
        authority.revoked.store(true, Ordering::SeqCst);
        Ok(())
    })
    .unwrap();
    let error = parser.feed(&bytes).unwrap_err();
    assert_eq!(
        error
            .source()
            .unwrap()
            .source()
            .unwrap()
            .downcast_ref::<DecodeAdmissionError>(),
        Some(&authority.failure)
    );
    assert!(matches!(
        parser.finish(&receipt),
        Err(QmpReadOnlyBackingStreamError::Terminal)
    ));
    assert_eq!(other_authority.calls.load(Ordering::SeqCst), other_calls);
    drop(scope);
}

#[test]
fn failure_slot_retains_original_credit_after_parser_drop() {
    let (budget, authority) = original();
    let initial = authority.used.load(Ordering::SeqCst);
    let error = {
        let mut parser =
            QmpReadOnlyBackingParser::prepare(&budget, &binding(), |_| Ok(())).unwrap();
        assert_eq!(authority.calls.load(Ordering::SeqCst), 3);
        parser.feed(&vec![0; MAX_FEED_BYTES + 1]).unwrap_err()
    };
    assert_eq!(
        authority.used.load(Ordering::SeqCst),
        initial + std::mem::size_of::<FailureData>() as u64
    );
    drop(error);
    assert_eq!(authority.used.load(Ordering::SeqCst), initial);
}

#[test]
fn completion_final_live_cut_and_unwind_close_prepaid_storage() {
    let (budget, authority) = original();
    let initial = authority.used.load(Ordering::SeqCst);
    let (bytes, receipt) = material(&[]);
    {
        let mut parser =
            QmpReadOnlyBackingParser::prepare(&budget, &binding(), |_| Ok(())).unwrap();
        parser.feed(&bytes).unwrap();
        authority.revoked.store(true, Ordering::SeqCst);
        assert!(parser.finish(&receipt).is_err());
    }
    assert_eq!(authority.used.load(Ordering::SeqCst), initial);

    let (budget, authority) = original();
    let initial = authority.used.load(Ordering::SeqCst);
    let (bytes, _) = material(&[(b"A", 0, b"")]);
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut parser = QmpReadOnlyBackingParser::prepare(&budget, &binding(), |_| {
            panic!("intentional visitor unwind");
        })
        .unwrap();
        let _ = parser.feed(&bytes);
    }));
    assert!(unwind.is_err());
    assert_eq!(authority.used.load(Ordering::SeqCst), initial);
}

#[test]
fn receipt_rejects_unknown_fields() {
    let (_, receipt) = material(&[]);
    let mut value = serde_json::to_value(receipt).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("unknown".into(), 0.into());
    assert!(serde_json::from_value::<QmpReadOnlyBackingReceipt>(value).is_err());
}

#[test]
fn initial_refusal_is_exact_before_any_parser_storage_birth() {
    let (budget, authority) = original();
    let calls = authority.calls.load(Ordering::SeqCst);
    let used = authority.used.load(Ordering::SeqCst);
    authority.revoked.store(true, Ordering::SeqCst);

    let result = QmpReadOnlyBackingParser::prepare(&budget, &binding(), |_| Ok(()));
    let Err(QmpReadOnlyBackingStreamError::Admission(error)) = result else {
        panic!("initial refusal must prevent parser storage");
    };
    assert_eq!(error, authority.failure);
    assert_eq!(budget.failure().unwrap(), Some(error));
    assert_eq!(authority.calls.load(Ordering::SeqCst), calls);
    assert_eq!(authority.used.load(Ordering::SeqCst), used);
}

#[test]
fn count_and_length_arithmetic_refuse_without_an_owner_collection() {
    let (bytes, receipt) = material(&[]);
    for (offset, value) in [
        (16, 4097),
        (16, u64::MAX),
        (24, u64::MAX),
        (32, u64::MAX),
        (56, u64::MAX),
    ] {
        let mut bad = bytes.clone();
        bad[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        refuses(&bad, &receipt);
    }
    println!(
        "fixed parser state={} failure slot={}",
        std::mem::size_of::<State>(),
        std::mem::size_of::<FailureData>()
    );
}
