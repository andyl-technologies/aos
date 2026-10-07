//! Control-worker quiescence preserves the parent stream and replay protection.

use super::*;
use crucible_protocol::ram_control::*;

struct Controller {
    target: RamControlTarget,
    worker_thread: std::sync::Mutex<Option<thread::ThreadId>>,
}

struct RecordOperation {
    deadline: std::time::Instant,
}

impl SourceOperation for RecordOperation {
    // crucible-lint: allow clippy-disallowed-method -- This test-only cleanup record samples a host deadline without publishing guest time or execution state.
    #[allow(
        clippy::disallowed_methods,
        reason = "test-only operational record deadline"
    )]
    fn wait_slice(&self) -> io::Result<Duration> {
        self.deadline
            .checked_duration_since(std::time::Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "test record expired"))
    }

    fn complete(&self) -> io::Result<()> {
        self.wait_slice().map(|_| ())
    }
}

impl SourceOperationFactory for Controller {
    // crucible-lint: allow clippy-disallowed-method -- This test-only controller creates the finite original cleanup deadline used by its record.
    #[allow(
        clippy::disallowed_methods,
        reason = "test-only operational record deadline"
    )]
    fn begin(&self, class: SourceOperationClass) -> io::Result<Box<dyn SourceOperation>> {
        assert_eq!(class, SourceOperationClass::Cleanup);
        Ok(Box::new(RecordOperation {
            deadline: std::time::Instant::now() + Duration::from_secs(1),
        }))
    }
}

impl PagerControl for Controller {
    fn identity(&self) -> RamControlTarget {
        self.target
    }

    fn worker_enter(&self) -> io::Result<()> {
        let mut current = self.worker_thread.lock().unwrap();
        assert!(current.is_none());
        *current = Some(thread::current().id());
        Ok(())
    }

    fn worker_exit(&self) -> io::Result<()> {
        let mut current = self.worker_thread.lock().unwrap();
        assert_eq!(*current, Some(thread::current().id()));
        *current = None;
        Ok(())
    }

    fn apply(
        &self,
        _: u64,
        _: u64,
        _: u64,
        _: RamControlPolicy,
        _: RamControlResources,
    ) -> RamControlReply {
        self.status()
    }

    fn test_fault_actor(
        &self,
        _: [u8; 32],
        _: u64,
        _: crucible_protocol::ram_control::RamControlFaultActorAction,
    ) -> RamControlReply {
        let mut report = self.status();
        report.disposition = RamControlDisposition::Unsupported;
        report
    }

    fn sync_outer_cap(&self, _: RamControlOuterCap) -> RamControlReply {
        self.status()
    }

    fn cancel(&self, _: u64) -> RamControlReply {
        self.status()
    }

    fn inventory_region(&self, _: u64, _: u32) -> RamControlReply {
        let mut state = self.status();
        state.disposition = RamControlDisposition::Unavailable;
        state
    }

    fn grant_inventory(&self, _: u64, _: RamControlResources, _: u64) -> RamControlReply {
        let mut state = self.status();
        state.disposition = RamControlDisposition::AdmissionRefused;
        state
    }

    fn status(&self) -> RamControlReply {
        RamControlReply {
            performance: None,
            placement_receipt: None,
            operation_failure: None,
            fault_actor: None,
            kernel_probe: None,
            activity: None,
            disposition: RamControlDisposition::Accepted,
            logical_ram_bytes: 8192,
            inventory: None,
            inventory_region: None,
            requested_policy_revision: 1,
            applied_policy_revision: 1,
            reservation_revision: 1,
            observation_sequence: 1,
            effective_resident_target_bytes: 0,
            effective_floor_bytes: 4096,
            limitation_reasons: RAM_LIMIT_COMPULSORY_FLOOR,
            measurements_available: true,
            private_resident_bytes: 0,
            shared_resident_bytes_observed: 0,
            preserved_backing_bytes: 4096,
            private_dirty_bytes: 0,
            writeback_pending_bytes: 0,
            convergence: RamControlConvergence::Stable,
        }
    }
}

fn exchange(
    host: &mut UnixStream,
    sequence: u64,
    target: RamControlTarget,
    request: RamControlRequest,
) {
    let frame = RamControlFrame {
        session: [4; 32],
        sequence,
        target,
        message: RamControlMessage::Request(request),
    };
    write_ram_control(host, &frame).unwrap();
    let reply = read_ram_control(host).unwrap().unwrap();
    assert_eq!(reply.sequence, sequence);
    let RamControlMessage::Reply { request_digest, .. } = reply.message else {
        panic!("expected reply");
    };
    assert_eq!(request_digest, ram_control_request_digest(&frame).unwrap());
}

#[test]
fn pager_control_quiescence_preserves_parent_sequence_without_socket_shutdown() {
    let target = RamControlTarget {
        daemon_epoch: [1; 32],
        owner_id: [2; 32],
        node_id: [3; 32],
        owner_generation: 1,
        arena_generation: 1,
        retained_template: false,
    };
    let controller: Arc<dyn PagerControl> = Arc::new(Controller {
        target,
        worker_thread: std::sync::Mutex::new(None),
    });
    let (mut host, socket) = UnixStream::pair().unwrap();
    host.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let worker =
        PagerControlWorker::start(socket, [4; 32], target, Arc::clone(&controller)).unwrap();
    exchange(&mut host, 1, target, RamControlRequest::Hello);
    let paused = worker.stop().unwrap().join().unwrap().unwrap();
    assert_eq!(paused.sequence, 1);

    let worker = PagerControlWorker::resume(paused, controller).unwrap();
    exchange(&mut host, 2, target, RamControlRequest::Status);
    let paused = worker.stop().unwrap().join().unwrap().unwrap();
    assert_eq!(paused.sequence, 2);
    // Drop only closes this owner's duplicate; it never invokes shutdown on the
    // inherited shared file description of another retained process endpoint.
    drop(paused);
}
