//! Original admission for manual node string and byte copies.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crucible::owned_decode::{
    DecodeAdmissionError, DecodeBudget, DecodeResourceAuthority, ResourceLoan,
};

use super::*;

struct Authority {
    refusing: AtomicBool,
    calls: AtomicU64,
    last_extent: AtomicU64,
}

impl DecodeResourceAuthority for Authority {
    fn verify_live(&self) -> Result<(), DecodeAdmissionError> {
        Ok(())
    }

    fn reserve(&self, bytes: u64) -> Result<ResourceLoan, DecodeAdmissionError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.last_extent.store(bytes, Ordering::SeqCst);
        if self.refusing.load(Ordering::SeqCst) {
            return Err(DecodeAdmissionError::new(std::fmt::Error));
        }
        Ok(ResourceLoan::new(()))
    }
}

fn original() -> Result<(DecodeBudget, Arc<Authority>), DecodeAdmissionError> {
    let authority = Arc::new(Authority {
        refusing: AtomicBool::new(false),
        calls: AtomicU64::new(0),
        last_extent: AtomicU64::new(0),
    });
    let budget = DecodeBudget::new(authority.clone(), 1024 * 1024)?;
    authority.calls.store(0, Ordering::SeqCst);
    authority.last_extent.store(0, Ordering::SeqCst);
    Ok((budget, authority))
}

#[test]
fn manual_node_copy_requests_actual_bytes_before_owned_conversion()
-> Result<(), Box<dyn std::error::Error>> {
    let (original, authority) = original()?;
    let _scope = original.enter();
    let mut bytes = 5_u64.to_le_bytes().to_vec();
    bytes.extend_from_slice(b"alpha");
    let mut reader = NodeContinuationReader::new(&bytes, b"")?;

    assert_eq!(reader.string("node name")?, "alpha");
    assert_eq!(authority.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        authority.last_extent.load(Ordering::SeqCst),
        5 + (4 * std::mem::size_of::<ResourceLoan>()) as u64
    );
    reader.finish()?;
    Ok(())
}

#[test]
fn manual_node_copy_refuses_under_same_sticky_original_before_output()
-> Result<(), Box<dyn std::error::Error>> {
    let (original, authority) = original()?;
    let _scope = original.enter();
    authority.refusing.store(true, Ordering::SeqCst);
    let mut bytes = 4_u64.to_le_bytes().to_vec();
    bytes.extend_from_slice(b"beta");
    let mut reader = NodeContinuationReader::new(&bytes, b"")?;

    assert!(matches!(
        reader.string("node name"),
        Err(QemuNodeCheckpointCodecError::ResourceLimit { requested: 4, .. })
    ));
    let first = original.failure()?.expect("recorded original refusal");
    let mut repeated = NodeContinuationReader::new(&bytes, b"")?;
    assert!(repeated.string("node name").is_err());
    assert_eq!(first, original.failure()?.expect("sticky original refusal"));
    assert_eq!(authority.calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn malformed_node_blob_does_not_reach_owning_admission() -> Result<(), Box<dyn std::error::Error>> {
    let (original, authority) = original()?;
    let _scope = original.enter();
    let bytes = 4_u64.to_le_bytes();
    let mut reader = NodeContinuationReader::new(&bytes, b"")?;

    assert_eq!(
        reader.owned_blob_bounded("node name", 8),
        Err(QemuNodeCheckpointCodecError::Malformed("node name"))
    );
    assert_eq!(authority.calls.load(Ordering::SeqCst), 0);
    assert!(original.failure()?.is_none());
    Ok(())
}
