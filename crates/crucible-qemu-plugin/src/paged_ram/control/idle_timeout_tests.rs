//! Idle socket configuration retains record deadlines and quiescent ownership.

use super::*;

#[test]
fn idle_retries_reuse_configuration_until_a_completed_record() {
    let (mut host, mut socket) = UnixStream::pair().unwrap();
    let mut installed = false;
    let mut installations = 0;

    for _ in 0..3 {
        install_idle_timeout(&mut installed, |timeout| {
            installations += 1;
            socket.set_read_timeout(Some(timeout))
        })
        .unwrap();
        let error = socket.read(&mut [0]).unwrap_err();
        assert!(matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        ));
    }
    assert_eq!(installations, 1);

    // An interrupted admission read follows the same retry path. The already
    // installed timeout must not invoke this setter again.
    install_idle_timeout(&mut installed, |_| {
        panic!("idle retry reconfigured the socket")
    })
    .unwrap();

    host.write_all(&[7]).unwrap();
    let mut first = [0];
    socket.read_exact(&mut first).unwrap();
    assert_eq!(first, [7]);
    socket
        .set_read_timeout(Some(Duration::from_millis(10)))
        .unwrap();
    installed = false;
    install_idle_timeout(&mut installed, |timeout| {
        installations += 1;
        socket.set_read_timeout(Some(timeout))
    })
    .unwrap();
    assert_eq!(installations, 2);
    assert_eq!(
        socket.read_timeout().unwrap(),
        Some(Duration::from_millis(25))
    );
}

#[test]
fn interrupted_timeout_installation_does_not_publish_success() {
    let mut installed = false;
    let error = install_idle_timeout(&mut installed, |_| Err(io::ErrorKind::Interrupted.into()))
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    assert!(!installed);

    install_idle_timeout(&mut installed, |timeout| {
        assert_eq!(timeout, Duration::from_millis(25));
        Ok(())
    })
    .unwrap();
    assert!(installed);
}

#[test]
fn actual_request_after_idle_retries_restores_polling_and_parent_sequence() {
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

    thread::sleep(Duration::from_millis(90));
    exchange(&mut host, 1, target, RamControlRequest::Hello);
    thread::sleep(Duration::from_millis(90));
    let paused = worker.stop().unwrap().join().unwrap().unwrap();
    assert_eq!(paused.sequence, 1);
    assert_eq!(
        paused.stream.read_timeout().unwrap(),
        Some(Duration::from_millis(25))
    );

    let worker = PagerControlWorker::resume(paused, controller).unwrap();
    exchange(&mut host, 2, target, RamControlRequest::Status);
    let paused = worker.stop().unwrap().join().unwrap().unwrap();
    assert_eq!(paused.sequence, 2);
}

#[test]
#[allow(
    clippy::disallowed_methods,
    reason = "finite component record deadline"
)]
fn partial_record_keeps_its_original_absolute_expiry() {
    let (mut host, mut socket) = UnixStream::pair().unwrap();
    let deadline = std::time::Instant::now() + Duration::from_millis(80);
    let mut installed = false;
    install_idle_timeout(&mut installed, |timeout| {
        socket.set_read_timeout(Some(timeout))
    })
    .unwrap();

    // The first byte was consumed by admission. Subsequent empty pulls must
    // expire this same operation, rather than begin another idle period.
    let mut record = RecordStream {
        stream: &mut socket,
        first: Some(0),
        operation: Box::new(RecordOperation { deadline }),
    };
    let mut first = [1];
    record.read_exact(&mut first).unwrap();
    assert_eq!(first, [0]);
    host.write_all(&[0]).unwrap();
    record.read_exact(&mut first).unwrap();

    let error = record.read_exact(&mut first).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(record.operation.complete().is_err());
    assert_eq!(
        record.operation.wait_slice().unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
}
