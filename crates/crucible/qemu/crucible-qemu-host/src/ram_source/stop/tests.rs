//! Keeps actual blocked worker custody through the same Cleanup's expiry.
//!
//! Socket and backing workers are real; no QEMU or native admission is modeled.

use super::*;
use crate::qmp::checkpoint_paged_source_support::ImmutableBacking;
use crucible_host_resources::host_services::{HostServiceAllocator, HostServiceError};
use crucible_host_resources::host_supervision::{HostOperationBudget, HostOperationBudgets};
use std::error::Error;
use std::sync::mpsc;

struct BlockedBacking {
    backing: ImmutableBacking,
    entered: mpsc::Sender<()>,
    released: Mutex<mpsc::Receiver<()>>,
}

impl QemuRamBacking for BlockedBacking {
    fn root_object_id(&self) -> &str {
        self.backing.root_object_id()
    }

    fn root_record(&self) -> &RootRecord {
        self.backing.root_record()
    }

    fn with_page_response(
        &self,
        region_id: &str,
        page_index: u64,
        boundary: &mut QemuRamReadBoundary<'_>,
        consumer: &mut QemuRamResponseConsumer<'_>,
    ) -> Result<(), QemuRamSourceError> {
        self.entered
            .send(())
            .map_err(|_| QemuRamSourceError::Ownership)?;
        self.released
            .lock()
            .map_err(|_| QemuRamSourceError::Ownership)?
            .recv_timeout(Duration::from_secs(2))
            .map_err(|_| QemuRamSourceError::Ownership)?;
        self.backing
            .with_page_response(region_id, page_index, boundary, consumer)
    }
}

// Release remains owning on every fixture exit, including an assertion panic.
struct Release(Option<mpsc::Sender<()>>);

impl Release {
    fn now(&mut self) {
        if let Some(release) = self.0.take() {
            let _ = release.send(());
        }
    }
}

impl Drop for Release {
    fn drop(&mut self) {
        self.now();
    }
}

// The observation deadline bounds only this component test; it never renews
// the expired Cleanup or grants the service permission to wait.
// crucible-lint: allow clippy-disallowed-method -- bounded test observation of actual native join, outside modeled time.
#[allow(clippy::disallowed_methods)]
#[test]
fn expired_cleanup_retains_blocked_service_then_joins_same_worker_without_renewal()
-> Result<(), Box<dyn Error>> {
    let (entered, observed) = mpsc::channel();
    let (release, released) = mpsc::channel();
    let mut release = Release(Some(release));
    let backing = Arc::new(BlockedBacking {
        backing: ImmutableBacking::new(2)?,
        entered,
        released: Mutex::new(released),
    });
    let binding = RamPageBinding {
        session: [1; 16],
        owner_incarnation: [2; 16],
        source_generation: 1,
        root_digest: *backing.root_record().digest().as_bytes(),
    };
    let services = HostServiceAllocator::new(1, 4, 8 * 1024 * 1024)?;
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;
    let original = supervisor.begin(HostOperationClass::Cleanup)?;
    let id = original.status()?.operation_id;
    let (socket, mut peer) = UnixStream::pair()?;
    let mut service = QemuRamSourceService::start_component(
        socket,
        backing,
        binding,
        supervisor.clone(),
        services.clone(),
        None,
    )?;
    peer.write_all(
        &RamPageRequest {
            binding,
            sequence: 1,
            region_ordinal: 0,
            page_index: 0,
        }
        .encode()?,
    )?;
    observed.recv_timeout(Duration::from_secs(2))?;
    let (revision, mut budgets) = supervisor.budgets()?;
    budgets.classes[HostOperationClass::Cleanup as usize] =
        HostOperationBudget::finite(Duration::from_nanos(1));
    supervisor.update_budgets(revision, budgets)?;

    let (joined, status) = service.stop(Some(crate::ram_control::RamCleanupOriginal::direct(
        &original,
        &supervisor,
    )));

    assert!(!joined);
    let first = status.unwrap_err();
    assert!(
        matches!(first.observations[0].0, Some(HostSupervisionError::DeadlineExpired { operation_id, .. }) if operation_id == id)
    );
    assert!(
        matches!(first.observations[0].1, Some(HostSupervisionError::DeadlineExpired { operation_id, .. }) if operation_id == id)
    );
    assert!(service.worker.is_some());
    assert!(matches!(
        services.reserve_resources(1, 0, 0),
        Err(HostServiceError::CapacityExhausted)
    ));

    release.now();
    let until = std::time::Instant::now() + Duration::from_secs(2);
    let (joined, status) = loop {
        let observed = service.stop(Some(crate::ram_control::RamCleanupOriginal::direct(
            &original,
            &supervisor,
        )));
        if observed.0 {
            break observed;
        }
        assert!(
            std::time::Instant::now() < until,
            "same source worker did not return"
        );
        thread::yield_now();
    };
    assert!(joined);
    let joined_history = status.unwrap_err();
    assert_eq!(joined_history.observations[0], first.observations[0]);
    assert!(joined_history.worker.is_some());
    assert!(joined_history.observations[2].0.is_some());
    assert!(joined_history.observations[2].1.is_some());
    assert!(service.worker.is_none());
    assert_eq!(original.status()?.operation_id, id);
    let (joined, status) = service.stop(Some(crate::ram_control::RamCleanupOriginal::direct(
        &original,
        &supervisor,
    )));
    assert!(joined);
    status?;
    assert_eq!(service.stop.history, joined_history);
    // Saved history, not a second worker, holds the same original worker loan.
    drop(service);
    assert!(matches!(
        services.reserve_resources(1, 0, 0),
        Err(HostServiceError::CapacityExhausted)
    ));
    drop(joined_history);
    assert!(services.reserve_resources(1, 0, 0).is_ok());
    Ok(())
}

#[test]
fn refused_creation_retains_both_checks_and_closes_only_actual_no_birth()
-> Result<(), Box<dyn Error>> {
    let backing = Arc::new(ImmutableBacking::new(1)?);
    let binding = RamPageBinding {
        session: [7; 16],
        owner_incarnation: [8; 16],
        source_generation: 1,
        root_digest: *backing.root_record().digest().as_bytes(),
    };
    let services = HostServiceAllocator::new(1, 4, 8 * 1024 * 1024)?;
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;
    let original = supervisor.begin(HostOperationClass::Preparation)?;
    let identity = original.status()?.operation_id;
    let (socket, _peer) = UnixStream::pair()?;
    let mut input = Some(SourceInput::new(socket, backing, binding));
    let mut service =
        QemuRamSourceService::prepare(&mut input, supervisor.clone(), services.clone())?;
    assert!(input.is_none());
    supervisor.cancel()?;

    assert!(service.publish_retained(&original, None).is_err());
    assert!(service.spawn_attempted && service.spawn_returned);
    assert!(!service.worker_started);
    assert!(service.worker.is_none());
    assert!(service.birth_before.is_some() && service.birth_after.is_some());
    assert!(service.failure.snapshot().delivered);
    assert_eq!(original.status()?.operation_id, identity);
    assert!(service.publish_retained(&original, None).is_err());

    // Known no-birth is factual. It needs neither a fresh Cleanup nor a wait
    // under the now-refused creation Original, and cannot authorize any work.
    let (returned, history) = service.stop(None);
    assert!(returned);
    let history = history.unwrap_err();
    assert!(history.birth.0.is_some() && history.birth.1.is_some());
    assert_eq!(history.native_status, None);
    drop(service);
    let _whole = services.reserve_resources(1, 4, 8 * 1024 * 1024)?;
    Ok(())
}

#[test]
fn preparation_refusal_preserves_same_socket_and_backing_before_any_worker()
-> Result<(), Box<dyn Error>> {
    use std::io::{Read, Write};
    let backing: Arc<dyn QemuRamBacking> = Arc::new(ImmutableBacking::new(1)?);
    let mut root_digest = *backing.root_record().digest().as_bytes();
    root_digest[0] ^= 1;
    let binding = RamPageBinding {
        session: [17; 16],
        owner_incarnation: [18; 16],
        source_generation: 1,
        root_digest,
    };
    let (socket, mut peer) = UnixStream::pair()?;
    let mut input = Some(SourceInput::new(socket, Arc::clone(&backing), binding));
    let services = HostServiceAllocator::new(1, 4, 8 * 1024 * 1024)?;
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;

    assert!(matches!(
        QemuRamSourceService::prepare(&mut input, supervisor, services),
        Err(QemuRamSourceError::Ownership)
    ));
    let retained = input.as_mut().expect("same unconsumed preparation input");
    assert!(Arc::ptr_eq(&retained.backing, &backing));
    peer.write_all(b"x")?;
    let mut actual = [0; 1];
    retained.socket.read_exact(&mut actual)?;
    assert_eq!(actual, *b"x");
    Ok(())
}

#[test]
fn prepared_never_published_service_returns_no_birth_and_cannot_publish_later()
-> Result<(), Box<dyn Error>> {
    let backing = Arc::new(ImmutableBacking::new(1)?);
    let binding = RamPageBinding {
        session: [27; 16],
        owner_incarnation: [28; 16],
        source_generation: 1,
        root_digest: *backing.root_record().digest().as_bytes(),
    };
    let (socket, _peer) = UnixStream::pair()?;
    let mut input = Some(SourceInput::new(socket, backing, binding));
    let services = HostServiceAllocator::new(1, 4, 8 * 1024 * 1024)?;
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;
    let original = supervisor.begin(HostOperationClass::Preparation)?;
    let mut service = QemuRamSourceService::prepare(&mut input, supervisor, services.clone())?;
    assert!(!service.spawn_attempted);
    assert!(!service.spawn_returned);
    assert!(service.worker.is_none());

    let (returned, status) = service.stop(None);
    assert!(returned);
    status?;
    assert!(service.stop.history.native_status.is_none());
    assert!(service.stop.history.native.is_none());
    assert!(!service.spawn_attempted && !service.spawn_returned);
    assert!(service.publish_retained(&original, None).is_err());
    assert!(!service.spawn_attempted && !service.worker_started);
    assert!(service.worker.is_none());
    drop(service);
    assert!(services.reserve_resources(1, 0, 0).is_ok());
    Ok(())
}
