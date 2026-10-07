//! Typed compact-decoder admission and recursive syntax boundary regressions.

use super::*;
use crate::owned_decode::{DecodeAdmissionError, DecodeBudget, DecodeResourceAuthority};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

struct Authority {
    used: Arc<AtomicU64>,
    maximum: u64,
}

struct Receipt {
    used: Arc<AtomicU64>,
    bytes: u64,
}

impl Drop for Receipt {
    fn drop(&mut self) {
        self.used.fetch_sub(self.bytes, Ordering::SeqCst);
    }
}

impl DecodeResourceAuthority for Authority {
    fn verify_live(&self) -> Result<(), DecodeAdmissionError> {
        if self.used.load(Ordering::SeqCst) > self.maximum {
            return Err(DecodeAdmissionError::new(std::io::Error::other(
                "original component accounting is invalid",
            )));
        }
        Ok(())
    }

    fn reserve(&self, bytes: u64) -> Result<Arc<dyn Send + Sync>, DecodeAdmissionError> {
        self.used
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                used.checked_add(bytes).filter(|next| *next <= self.maximum)
            })
            .map_err(|_| {
                DecodeAdmissionError::new(std::io::Error::other("original fixture allowance"))
            })?;
        Ok(Arc::new(Receipt {
            used: Arc::clone(&self.used),
            bytes,
        }))
    }
}

fn authority(maximum: u64) -> Arc<Authority> {
    Arc::new(Authority {
        used: Arc::new(AtomicU64::new(0)),
        maximum,
    })
}

#[test]
fn typed_vector_admission_refuses_before_reservation_or_input_consumption()
-> Result<(), Box<dyn std::error::Error>> {
    let budget = DecodeBudget::new(authority(4096), 4096)?;
    let _scope = budget.enter();
    let reader = ScenarioBinaryReader::new(b"", b"")?;

    let result = reader.allocate_vec::<[u64; 1024]>(1);

    assert!(matches!(
        result,
        Err(EngineError::ArtifactDecodeAdmission { .. })
    ));
    assert_eq!(reader.offset, 0);
    assert!(budget.failure()?.is_some());
    Ok(())
}

#[test]
fn ordered_map_nodes_are_admitted_before_decoding_the_first_entry()
-> Result<(), Box<dyn std::error::Error>> {
    let budget = DecodeBudget::new(authority(512), 512)?;
    let _scope = budget.enter();
    let mut bytes = 1u64.to_le_bytes().to_vec();
    bytes.extend_from_slice(&[0; 16]);
    let mut reader = ScenarioBinaryReader::new(&bytes, b"")?;

    let result = read_node_icounts_binary(&mut reader);

    assert!(matches!(
        result,
        Err(EngineError::ArtifactDecodeAdmission { .. })
    ));
    assert_eq!(reader.offset, 8);
    assert!(budget.failure()?.is_some());
    Ok(())
}

#[test]
fn invalid_utf8_is_rejected_before_owned_string_admission() -> Result<(), Box<dyn std::error::Error>>
{
    let authority = authority(4096);
    let budget = DecodeBudget::new(authority.clone(), 4096)?;
    let _scope = budget.enter();
    let used_before = authority.used.load(Ordering::SeqCst);
    let mut bytes = 1u64.to_le_bytes().to_vec();
    bytes.push(0xff);
    let mut reader = ScenarioBinaryReader::new(&bytes, b"")?;

    assert!(matches!(
        reader.read_string(),
        Err(EngineError::ScenarioSerialization { .. })
    ));

    assert_eq!(authority.used.load(Ordering::SeqCst), used_before);
    assert!(budget.failure()?.is_none());
    Ok(())
}

#[test]
fn compact_owned_bytes_retain_original_credit_until_last_custody()
-> Result<(), Box<dyn std::error::Error>> {
    let authority = authority(4096);
    let budget = DecodeBudget::new(authority.clone(), 4096)?;
    let scope = budget.enter();
    let mut bytes = 4u64.to_le_bytes().to_vec();
    bytes.extend_from_slice(b"page");
    let mut reader = ScenarioBinaryReader::new(&bytes, b"")?;
    let decoded = reader.read_owned_blob("fixture")?;
    let custody = budget.custody();
    let used = authority.used.load(Ordering::SeqCst);

    drop(scope);
    drop(budget);
    assert_eq!(decoded, b"page");
    assert_eq!(authority.used.load(Ordering::SeqCst), used);
    drop(decoded);
    drop(custody);
    assert_eq!(authority.used.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn recursive_actions_refuse_excess_depth_and_restore_reader_depth()
-> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    for _ in 0..MAX_BINARY_DECODE_NESTING {
        bytes.push(9);
        bytes.extend_from_slice(&1u64.to_le_bytes());
    }
    bytes.push(6);
    let mut reader = ScenarioBinaryReader::new(&bytes, b"")?;

    let result = read_action_binary(&mut reader);

    assert!(matches!(
        result,
        Err(EngineError::ScenarioSerialization { .. })
    ));
    assert_eq!(reader.nesting, 0);
    assert_eq!(read_action_binary(&mut reader)?, Action::Pass);
    Ok(())
}

#[test]
fn component_decoding_preserves_exact_string_and_blob_bytes()
-> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = 3u64.to_le_bytes().to_vec();
    bytes.extend_from_slice("ram".as_bytes());
    bytes.extend_from_slice(&3u64.to_le_bytes());
    bytes.extend_from_slice(&[0, 0xff, 1]);
    let mut reader = ScenarioBinaryReader::new(&bytes, b"")?;

    assert_eq!(reader.read_string()?, "ram");
    assert_eq!(reader.read_owned_blob("fixture")?, [0, 0xff, 1]);
    reader.finish()?;
    Ok(())
}
