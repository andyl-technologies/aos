//! Adversarial whole-placement verification tests.

// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts for exact failure localization.
#![allow(clippy::expect_used)]

use std::collections::BTreeMap;
use std::io::{self, Cursor, Read};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use super::*;

#[derive(Clone)]
struct ScriptedObject {
    inventory_length: u64,
    source: Arc<ScriptedSource>,
}

struct ScriptedSource {
    bytes: Arc<[u8]>,
    declared_length: u64,
    maximum_read: usize,
    fail_at_eof: bool,
}

impl BlobSource for ScriptedSource {
    fn logical_length(&self) -> u64 {
        self.declared_length
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        Ok(Box::new(ScriptedReader {
            bytes: Cursor::new(Arc::clone(&self.bytes)),
            maximum_read: self.maximum_read,
            fail_at_eof: self.fail_at_eof,
            eof_failure_returned: false,
        }))
    }
}

struct ScriptedReader {
    bytes: Cursor<Arc<[u8]>>,
    maximum_read: usize,
    fail_at_eof: bool,
    eof_failure_returned: bool,
}

impl Read for ScriptedReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let limit = output.len().min(self.maximum_read);
        let read = self.bytes.read(&mut output[..limit])?;
        if read == 0 && self.fail_at_eof && !self.eof_failure_returned {
            self.eof_failure_returned = true;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "injected deferred authentication failure",
            ));
        }
        Ok(read)
    }
}

struct ScriptedPhysicalState {
    backend: Mutex<String>,
    generation: AtomicU64,
    objects: Mutex<BTreeMap<ContentId, ScriptedObject>>,
    active_fences: AtomicUsize,
}

impl ScriptedPhysicalState {
    fn new(backend: &str, objects: impl IntoIterator<Item = (ContentId, ScriptedObject)>) -> Self {
        Self {
            backend: Mutex::new(backend.to_owned()),
            generation: AtomicU64::new(1),
            objects: Mutex::new(objects.into_iter().collect()),
            active_fences: AtomicUsize::new(0),
        }
    }

    fn generation(&self) -> InventoryGeneration {
        let generation = self.generation.load(Ordering::SeqCst).to_be_bytes();
        let mut bytes = [0_u8; 32];
        bytes[..generation.len()].copy_from_slice(&generation);
        InventoryGeneration::from_bytes(bytes)
    }
}

struct ScriptedBackend {
    name: String,
    state: Arc<ScriptedPhysicalState>,
}

impl ImmutableBlobBackend for ScriptedBackend {
    fn name(&self) -> &str {
        &self.name
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            range_read: true,
            streaming_read: true,
            repair_inventory: true,
            planned_delete: true,
            ..BackendCapabilities::default()
        }
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        Ok(self
            .state
            .objects
            .lock()
            .expect("scripted object lock")
            .contains_key(&id))
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        if range.is_some() {
            return Err(StoreError::Unsupported {
                capability: "scripted range read",
            });
        }
        let object = self
            .state
            .objects
            .lock()
            .expect("scripted object lock")
            .get(&id)
            .cloned()
            .ok_or(StoreError::NotFound { id })?;
        Ok(BlobHandle::integrity_checked(id, object.source))
    }

    fn put_if_absent(
        &self,
        _id: ContentId,
        _source: &BlobHandle,
    ) -> Result<PutReceipt, StoreError> {
        Err(StoreError::Unsupported {
            capability: "scripted put",
        })
    }
}

struct ScriptedAdmin {
    state: Arc<ScriptedPhysicalState>,
}

impl BlobStoreAdmin for ScriptedAdmin {
    fn acquire_inventory_fence(&self) -> Result<Box<dyn BlobInventoryFence + '_>, StoreError> {
        self.state.active_fences.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(ScriptedFence {
            state: Arc::clone(&self.state),
        }))
    }
}

struct ScriptedFence {
    state: Arc<ScriptedPhysicalState>,
}

impl Drop for ScriptedFence {
    fn drop(&mut self) {
        self.state.active_fences.fetch_sub(1, Ordering::SeqCst);
    }
}

impl BlobInventoryFence for ScriptedFence {
    fn visit_inventory(
        &mut self,
        visitor: &mut dyn FnMut(BlobInventoryRecord) -> Result<(), StoreError>,
    ) -> Result<BlobInventorySummary, StoreError> {
        let objects = self.state.objects.lock().expect("scripted object lock");
        let mut count = 0_u64;
        let mut logical_bytes = 0_u64;
        for (id, object) in objects.iter() {
            visitor(BlobInventoryRecord::new(*id, object.inventory_length))?;
            count = count.checked_add(1).ok_or(StoreError::Quota)?;
            logical_bytes = logical_bytes
                .checked_add(object.inventory_length)
                .ok_or(StoreError::Quota)?;
        }
        let backend = self
            .state
            .backend
            .lock()
            .expect("scripted backend lock")
            .clone();
        Ok(BlobInventorySummary::new(
            backend,
            PhysicalStorageIdentity::from_bytes([7; 32]),
            self.state.generation(),
            count,
            logical_bytes,
        ))
    }

    fn delete_candidate(&mut self, _id: ContentId) -> Result<PlannedDeleteDisposition, StoreError> {
        Err(StoreError::Unsupported {
            capability: "scripted deletion",
        })
    }
}

fn object(bytes: &[u8]) -> (ContentId, ScriptedObject) {
    scripted_object(bytes, bytes.len() as u64, bytes.len() as u64, 1, false)
}

fn scripted_object(
    bytes: &[u8],
    inventory_length: u64,
    declared_length: u64,
    maximum_read: usize,
    fail_at_eof: bool,
) -> (ContentId, ScriptedObject) {
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, bytes);
    (
        id,
        ScriptedObject {
            inventory_length,
            source: Arc::new(ScriptedSource {
                bytes: Arc::from(bytes),
                declared_length,
                maximum_read,
                fail_at_eof,
            }),
        },
    )
}

fn verification_admin(
    physical: impl IntoIterator<Item = (&'static str, Arc<ScriptedPhysicalState>)>,
) -> StoreGraphAdmin {
    let physical = physical
        .into_iter()
        .map(|(node, state)| {
            let node = StoreNodeId::new(node).expect("valid test node");
            let backend: Arc<dyn ImmutableBlobBackend> = Arc::new(ScriptedBackend {
                name: node.as_str().to_owned(),
                state: Arc::clone(&state),
            });
            let admin: Arc<dyn BlobStoreAdmin> = Arc::new(ScriptedAdmin { state });
            (
                node,
                StoreGraphPhysicalAuthority {
                    backend,
                    admin,
                    retention: BTreeMap::new(),
                },
            )
        })
        .collect();
    StoreGraphAdmin {
        configuration: StoreGraphConfigurationId([0x31; 32]),
        physical,
        s3_multipart_cleanup: BTreeMap::new(),
    }
}

#[test]
fn verification_streams_partial_reads_and_reports_canonical_aggregate_evidence() {
    let first = Arc::new(ScriptedPhysicalState::new("alpha", [object(b"alpha")]));
    let second = Arc::new(ScriptedPhysicalState::new("zeta", [object(b"zeta-object")]));
    let admin = verification_admin([("zeta", Arc::clone(&second)), ("alpha", Arc::clone(&first))]);

    let report = admin
        .verify_physical_inventory(StoreGraphVerificationLimits::PRODUCTION)
        .expect("stable inventories verify");

    assert_eq!(report.configuration().as_bytes(), [0x31; 32]);
    assert_eq!(report.placements(), 2);
    assert_eq!(report.logical_bytes(), 16);
    assert_eq!(
        report
            .physical()
            .iter()
            .map(|entry| entry.node().as_str())
            .collect::<Vec<_>>(),
        vec!["alpha", "zeta"]
    );
    assert_eq!(first.active_fences.load(Ordering::SeqCst), 0);
    assert_eq!(second.active_fences.load(Ordering::SeqCst), 0);
}

#[test]
fn verification_enforces_aggregate_count_and_byte_limits_across_leaves() {
    let first = Arc::new(ScriptedPhysicalState::new("alpha", [object(b"1234")]));
    let second = Arc::new(ScriptedPhysicalState::new("zeta", [object(b"5678")]));
    let admin = verification_admin([("alpha", Arc::clone(&first)), ("zeta", Arc::clone(&second))]);

    let count_error = admin
        .verify_physical_inventory(
            StoreGraphVerificationLimits::new(1, MAX_STORE_GRAPH_VERIFY_LOGICAL_BYTES)
                .expect("test verification bounds are valid"),
        )
        .expect_err("the second leaf must exceed the aggregate count");
    assert!(matches!(
        count_error,
        StoreGraphVerificationError::LimitExceeded {
            limit: StoreGraphVerificationLimit::Placements,
            ..
        }
    ));

    let byte_error = admin
        .verify_physical_inventory(
            StoreGraphVerificationLimits::new(MAX_STORE_GRAPH_VERIFY_PLACEMENTS, 7)
                .expect("test verification bounds are valid"),
        )
        .expect_err("the second leaf must exceed the aggregate byte limit");
    assert!(matches!(
        byte_error,
        StoreGraphVerificationError::LimitExceeded {
            limit: StoreGraphVerificationLimit::LogicalBytes,
            ..
        }
    ));
    assert_eq!(first.active_fences.load(Ordering::SeqCst), 0);
    assert_eq!(second.active_fences.load(Ordering::SeqCst), 0);
}

#[test]
fn verification_limits_cannot_raise_the_hard_work_bounds() {
    assert_eq!(
        StoreGraphVerificationLimits::new(
            MAX_STORE_GRAPH_VERIFY_PLACEMENTS + 1,
            MAX_STORE_GRAPH_VERIFY_LOGICAL_BYTES,
        ),
        Err(StoreGraphVerificationLimitsError::Placements {
            requested: MAX_STORE_GRAPH_VERIFY_PLACEMENTS + 1,
        })
    );
    assert_eq!(
        StoreGraphVerificationLimits::new(
            MAX_STORE_GRAPH_VERIFY_PLACEMENTS,
            MAX_STORE_GRAPH_VERIFY_LOGICAL_BYTES + 1,
        ),
        Err(StoreGraphVerificationLimitsError::LogicalBytes {
            requested: MAX_STORE_GRAPH_VERIFY_LOGICAL_BYTES + 1,
        })
    );
}

#[test]
fn verification_rejects_short_long_and_deferred_failure_streams() {
    let cases = [
        ("short", scripted_object(b"short", 6, 6, 2, false)),
        ("long", scripted_object(b"long", 3, 3, 2, false)),
        ("deferred", scripted_object(b"deferred", 8, 8, 2, true)),
    ];

    for (node, value) in cases {
        let state = Arc::new(ScriptedPhysicalState::new(node, [value]));
        let admin = verification_admin([(node, Arc::clone(&state))]);
        let error = admin
            .verify_physical_inventory(StoreGraphVerificationLimits::PRODUCTION)
            .expect_err("incomplete authentication must reject verification");

        assert!(matches!(
            error,
            StoreGraphVerificationError::Authenticate { .. }
        ));
        assert_eq!(state.active_fences.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn verification_rejects_opened_length_and_backend_identity_mismatches() {
    let mismatch = scripted_object(b"length", 6, 7, 2, false);
    let state = Arc::new(ScriptedPhysicalState::new("leaf", [mismatch]));
    let admin = verification_admin([("leaf", Arc::clone(&state))]);
    assert!(matches!(
        admin.verify_physical_inventory(StoreGraphVerificationLimits::PRODUCTION),
        Err(StoreGraphVerificationError::LogicalLengthChanged { .. })
    ));
    assert_eq!(state.active_fences.load(Ordering::SeqCst), 0);

    let state = Arc::new(ScriptedPhysicalState::new("foreign", [object(b"body")]));
    let admin = verification_admin([("leaf", Arc::clone(&state))]);
    assert!(matches!(
        admin.verify_physical_inventory(StoreGraphVerificationLimits::PRODUCTION),
        Err(StoreGraphVerificationError::BackendIdentityMismatch { .. })
    ));
    assert_eq!(state.active_fences.load(Ordering::SeqCst), 0);
}

#[test]
fn verification_rejects_generation_aba_after_stream_authentication() {
    let state = Arc::new(ScriptedPhysicalState::new("leaf", [object(b"body")]));
    let admin = verification_admin([("leaf", Arc::clone(&state))]);

    let error = admin
        .verify_physical_inventory_with_observer(
            StoreGraphVerificationLimits::PRODUCTION,
            &mut |_node| {
                state.generation.fetch_add(1, Ordering::SeqCst);
            },
        )
        .expect_err("changed generation must reject stable verification");

    assert!(matches!(
        error,
        StoreGraphVerificationError::InventoryChanged { after: Some(_), .. }
    ));
    assert_eq!(state.active_fences.load(Ordering::SeqCst), 0);
}
