//! Checks actual immutable exchanges without starting a replacement operation.

use super::*;
use std::io::Read;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use crucible_qemu_protocol::ram_page::{
    RamPageResponse, RamPageStatus, read_ram_page_request, write_ram_page_response,
};
use crucible_ram::{RegionClass, RegionTree};

use crate::paged_ram::source::{ObservationOperationError, SourceFetchError};

struct NoReplacementOperation;

impl SourceOperationFactory for NoReplacementOperation {
    fn begin(&self, _: SourceOperationClass) -> io::Result<Box<dyn SourceOperation>> {
        panic!("retained exchange cannot start a replacement operation")
    }
}

struct BorrowedOperation {
    checks: AtomicUsize,
    completed: AtomicUsize,
    refused: AtomicBool,
    refuse_completion: bool,
}

impl BorrowedOperation {
    fn new(refuse_completion: bool) -> Self {
        Self {
            checks: AtomicUsize::new(0),
            completed: AtomicUsize::new(0),
            refused: AtomicBool::new(false),
            refuse_completion,
        }
    }
}

impl SourceOperation for BorrowedOperation {
    fn wait_slice(&self) -> io::Result<Duration> {
        panic!("borrowed exchange must preserve its observation error custody")
    }

    fn complete(&self) -> io::Result<()> {
        panic!("borrowed exchange must not complete an ordinary operation")
    }

    fn wait_slice_for_observation(&self) -> Result<Duration, ObservationOperationError> {
        let checks = self.checks.fetch_add(1, Ordering::AcqRel);
        if self.completed.load(Ordering::Acquire) != 0 {
            return Err(ObservationOperationError::Static {
                kind: io::ErrorKind::Other,
                message: "retained original exchange already completed",
            });
        }
        // This models a finite original refusal; it is not a runtime issuer or
        // a wall-clock bound and is never used by production transport.
        if self.refused.load(Ordering::Acquire) || checks >= 64 {
            return Err(ObservationOperationError::Static {
                kind: io::ErrorKind::TimedOut,
                message: "retained original exchange refused",
            });
        }
        Ok(Duration::from_millis(10))
    }

    fn complete_observation(&self) -> Result<(), ObservationOperationError> {
        self.completed.fetch_add(1, Ordering::AcqRel);
        if self.refuse_completion {
            return Err(ObservationOperationError::Static {
                kind: io::ErrorKind::Interrupted,
                message: "retained original completion refused",
            });
        }
        Ok(())
    }
}

fn fixture() -> (
    RestorePageSource,
    UnixStream,
    UnixStream,
    RegionTree,
    RamPageBinding,
) {
    let budget = MetadataBudget::new(64 * 1024);
    let tree = RegionTree::from_page_digests(7, &[PageDigest::hash(b"content").unwrap()], &budget)
        .unwrap();
    let region = RegionDescriptor::new("machine.main", RegionClass::MutableMain, 7).unwrap();
    let topology = Topology::new(vec![region], Limits::default()).unwrap();
    let record =
        RootRecord::new(topology, crucible_ram::Scope::Exact, vec![tree.digest()]).unwrap();
    let binding = RamPageBinding {
        session: [1; 16],
        owner_incarnation: [2; 16],
        source_generation: 3,
        root_digest: *record.digest().as_bytes(),
    };
    let (client, server) = UnixStream::pair().unwrap();
    let (cancellation, cancellation_owner) = UnixStream::pair().unwrap();
    let connection = LazyPageSource::bind(
        client,
        cancellation.into(),
        binding,
        &record.encode(),
        *record.topology().digest().as_bytes(),
        Limits::default(),
    )
    .unwrap();
    let source = RestorePageSource {
        root: record.digest(),
        record,
        connection: Mutex::new(connection),
        operations: Arc::new(NoReplacementOperation),
        _reservation: budget.reserve_bytes(1024).unwrap(),
    };
    (source, server, cancellation_owner, tree, binding)
}

#[test]
fn actual_proof_exchange_borrows_the_same_operation_without_factory_admission() {
    let (source, mut server, _cancellation, tree, binding) = fixture();
    let worker = std::thread::spawn(move || {
        let request = read_ram_page_request(&mut server).unwrap();
        assert_eq!(request.binding, binding);
        let proof = tree.proof("machine.main", 0).unwrap().encode();
        write_ram_page_response(
            &mut server,
            RamPageResponse {
                binding,
                sequence: request.sequence,
                status: RamPageStatus::Page,
                page: b"content",
                proof: &proof,
            },
        )
        .unwrap();
    });
    let operation = BorrowedOperation::new(false);
    let mut output = [0xa5; PAGE_BYTES];

    let result = source.fetch_with_retained_operation(0, 0, &operation, &mut output, None);
    let Ok((length, digest)) = result else {
        panic!("actual retained source exchange must authenticate its proof")
    };
    worker.join().unwrap();

    assert_eq!(length, 7);
    assert_eq!(digest, PageDigest::hash(b"content").unwrap());
    assert_eq!(&output[..7], b"content");
    assert!(output[7..].iter().all(|byte| *byte == 0));
    assert!(operation.checks.load(Ordering::Acquire) > 0);
    assert_eq!(operation.completed.load(Ordering::Acquire), 1);
    assert_eq!(source.root, source.record.digest());
}

#[test]
fn final_original_refusal_retains_endpoint_poison_and_unpublished_output() {
    let (source, mut server, _cancellation, tree, binding) = fixture();
    let worker = std::thread::spawn(move || {
        let request = read_ram_page_request(&mut server).unwrap();
        let proof = tree.proof("machine.main", 0).unwrap().encode();
        write_ram_page_response(
            &mut server,
            RamPageResponse {
                binding,
                sequence: request.sequence,
                status: RamPageStatus::Page,
                page: b"content",
                proof: &proof,
            },
        )
        .unwrap();
        server
    });
    let operation = BorrowedOperation::new(true);
    let mut output = [0xa5; PAGE_BYTES];

    assert!(
        source
            .fetch_with_retained_operation(0, 0, &operation, &mut output, None)
            .is_err()
    );
    let mut server = worker.join().unwrap();
    let checks = operation.checks.load(Ordering::Acquire);
    assert_eq!(operation.completed.load(Ordering::Acquire), 1);
    assert!(output.iter().all(|byte| *byte == 0xa5));

    assert!(
        source
            .fetch_with_retained_operation(0, 0, &operation, &mut output, None)
            .is_err()
    );
    assert_eq!(operation.checks.load(Ordering::Acquire), checks);
    assert_eq!(operation.completed.load(Ordering::Acquire), 1);
    server.set_nonblocking(true).unwrap();
    assert_eq!(
        server.read(&mut [0; 1]).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}

#[test]
fn busy_source_owner_refuses_before_original_check_or_frame_publication() {
    let (source, mut server, _cancellation, _tree, _binding) = fixture();
    let operation = BorrowedOperation::new(false);
    let held_connection = source.connection.lock().unwrap();
    let mut output = [0xa5; PAGE_BYTES];

    assert!(
        source
            .fetch_with_retained_operation(0, 0, &operation, &mut output, None)
            .is_err()
    );
    assert_eq!(operation.checks.load(Ordering::Acquire), 0);
    assert_eq!(operation.completed.load(Ordering::Acquire), 0);
    assert!(output.iter().all(|byte| *byte == 0xa5));
    server.set_nonblocking(true).unwrap();
    assert_eq!(
        server.read(&mut [0; 1]).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    drop(held_connection);
}

#[test]
fn original_precheck_refuses_before_source_namespace_is_consumed() {
    let (source, mut server, _cancellation, _tree, _binding) = fixture();
    let operation = BorrowedOperation::new(false);
    operation.refused.store(true, Ordering::Release);
    let mut output = [0xa5; PAGE_BYTES];

    let refusal = source.fetch_with_retained_operation(0, 0, &operation, &mut output, None);
    assert!(matches!(
        refusal,
        Err(SourceFetchError::Diagnostic(
            crate::paged_ram::source::SourceDiagnostic::Operation {
                kind: io::ErrorKind::TimedOut,
                message: "retained original exchange refused",
            }
        ))
    ));
    assert_eq!(operation.checks.load(Ordering::Acquire), 1);
    assert_eq!(operation.completed.load(Ordering::Acquire), 0);
    assert!(output.iter().all(|byte| *byte == 0xa5));
    assert!(
        source
            .fetch_with_retained_operation(0, 0, &operation, &mut output, None)
            .is_err()
    );
    assert_eq!(operation.checks.load(Ordering::Acquire), 2);
    server.set_nonblocking(true).unwrap();
    assert_eq!(
        server.read(&mut [0; 1]).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}

#[test]
fn a_different_source_incarnation_never_publishes_or_completes_the_read() {
    let (source, mut server, _cancellation, tree, binding) = fixture();
    let worker = std::thread::spawn(move || {
        let request = read_ram_page_request(&mut server).unwrap();
        let proof = tree.proof("machine.main", 0).unwrap().encode();
        write_ram_page_response(
            &mut server,
            RamPageResponse {
                binding: RamPageBinding {
                    source_generation: binding.source_generation + 1,
                    ..binding
                },
                sequence: request.sequence,
                status: RamPageStatus::Page,
                page: b"content",
                proof: &proof,
            },
        )
        .unwrap();
    });
    let operation = BorrowedOperation::new(false);
    let mut output = [0xa5; PAGE_BYTES];

    assert!(
        source
            .fetch_with_retained_operation(0, 0, &operation, &mut output, None)
            .is_err()
    );
    worker.join().unwrap();
    assert_eq!(operation.completed.load(Ordering::Acquire), 0);
    assert!(output.iter().all(|byte| *byte == 0xa5));
    let checks = operation.checks.load(Ordering::Acquire);
    assert!(
        source
            .fetch_with_retained_operation(0, 0, &operation, &mut output, None)
            .is_err()
    );
    assert_eq!(operation.checks.load(Ordering::Acquire), checks);
}

#[test]
fn held_proof_hydration_uses_the_existing_exchange_and_original_post() {
    for refuse_completion in [false, true] {
        let (source, mut server, _cancellation, tree, binding) = fixture();
        let expected = tree.proof("machine.main", 0).unwrap();
        let worker = std::thread::spawn(move || {
            let request = read_ram_page_request(&mut server).unwrap();
            assert_eq!(request.binding, binding);
            let proof = tree.proof("machine.main", 0).unwrap().encode();
            write_ram_page_response(
                &mut server,
                RamPageResponse {
                    binding,
                    sequence: request.sequence,
                    status: RamPageStatus::Page,
                    page: b"content",
                    proof: &proof,
                },
            )
            .unwrap();
        });
        let operation = BorrowedOperation::new(refuse_completion);
        let mut scratch = [0xa5; PAGE_BYTES];

        let result =
            source.fetch_proof_with_retained_operation("machine.main", 0, &operation, &mut scratch);
        worker.join().unwrap();

        if refuse_completion {
            assert!(result.is_err());
            assert!(scratch.iter().all(|byte| *byte == 0xa5));
        } else {
            assert_eq!(result.unwrap().encode(), expected.encode());
            assert_eq!(&scratch[..7], b"content");
        }
        assert!(operation.checks.load(Ordering::Acquire) > 0);
        assert_eq!(operation.completed.load(Ordering::Acquire), 1);
    }
}

#[test]
fn held_proof_rejects_unknown_region_before_any_original_or_socket_effect() {
    let (source, mut server, _cancellation, _tree, _binding) = fixture();
    server.set_nonblocking(true).unwrap();
    let operation = BorrowedOperation::new(false);
    let mut scratch = [0xa5; PAGE_BYTES];

    let result =
        source.fetch_proof_with_retained_operation("another.region", 0, &operation, &mut scratch);

    assert!(result.is_err());
    assert_eq!(operation.checks.load(Ordering::Acquire), 0);
    assert_eq!(operation.completed.load(Ordering::Acquire), 0);
    assert!(scratch.iter().all(|byte| *byte == 0xa5));
    let mut byte = [0];
    assert_eq!(
        server.read(&mut byte).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}

#[test]
fn held_proof_transport_eof_keeps_the_original_error_and_unpublished_scratch() {
    let (source, mut server, _cancellation, _tree, binding) = fixture();
    let peer = std::thread::spawn(move || {
        let request = read_ram_page_request(&mut server).unwrap();
        assert_eq!(request.binding, binding);
        // Close the real endpoint after accepting the same namespace, before
        // sending any response. No synthetic status substitutes for transport.
    });
    let operation = BorrowedOperation::new(false);
    let mut scratch = [0xa5; PAGE_BYTES];

    let refusal =
        source.fetch_proof_with_retained_operation("machine.main", 0, &operation, &mut scratch);
    peer.join().unwrap();

    let Err(SourceFetchError::Io(original)) = refusal else {
        panic!("retained proof must preserve the actual transport I/O cause")
    };
    assert_eq!(original.kind(), io::ErrorKind::UnexpectedEof);
    assert_eq!(operation.completed.load(Ordering::Acquire), 0);
    assert!(scratch.iter().all(|byte| *byte == 0xa5));
    let checks = operation.checks.load(Ordering::Acquire);
    assert!(
        source
            .fetch_proof_with_retained_operation("machine.main", 0, &operation, &mut scratch,)
            .is_err()
    );
    assert_eq!(operation.checks.load(Ordering::Acquire), checks);
}

#[test]
fn completed_original_cannot_start_a_retained_proof_or_consume_its_namespace() {
    let (source, mut server, _cancellation, _tree, _binding) = fixture();
    server.set_nonblocking(true).unwrap();
    let operation = BorrowedOperation::new(false);
    operation.complete_observation().unwrap();
    let mut scratch = [0xa5; PAGE_BYTES];

    let refusal =
        source.fetch_proof_with_retained_operation("machine.main", 0, &operation, &mut scratch);

    assert!(matches!(
        refusal,
        Err(SourceFetchError::Diagnostic(
            crate::paged_ram::source::SourceDiagnostic::Operation {
                kind: io::ErrorKind::Other,
                message: "retained original exchange already completed",
            }
        ))
    ));
    assert_eq!(operation.completed.load(Ordering::Acquire), 1);
    assert!(scratch.iter().all(|byte| *byte == 0xa5));
    assert_eq!(
        server.read(&mut [0; 1]).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}
