//! Tests authentic observed cleanup, exact private archival and one original transfer.

use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::MetadataExt,
};

use rustix::fs::{Mode, OFlags};

use super::*;
use crate::node_contract::{
    GracefulRetirementQualification, QuarantinedRuntime, RuntimeError, RuntimeSnapshot,
    WorldActivation,
};

struct LostArchiveResult;

impl Write for LostArchiveResult {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other(
            "injected lost original archive result",
        ))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct StoredOriginal {
    file: File,
    directory: File,
    bytes: Vec<u8>,
}

struct Release<'a> {
    ledger: &'a RuntimeSnapshot,
    peers: &'a [Rc<RefCell<Vec<CnpPeerCustody>>>],
    files: &'a [RefCell<StoredOriginal>],
}

impl GracefulRetirementQualification for Release<'_> {
    fn authenticate_release(
        &self,
        original: &QuarantinedRuntime,
        activation: &WorldActivation,
    ) -> Result<(), RuntimeError> {
        original.authenticate_retired_ledger(self.ledger, 8 * 1024 * 1024)?;
        for (peers, file) in self.peers.iter().zip(self.files) {
            let peers = peers.borrow();
            if peers.len() != 1 {
                return Err(RuntimeError::OutstandingObligations);
            }
            let peer = &peers[0];
            let runtime = peer.runtime.as_ref().ok_or(RuntimeError::InvalidReceipt)?;
            let owner = activation
                .record()
                .owners
                .iter()
                .find(|owner| owner.owner == runtime.owner_binding.owner.id)
                .ok_or(RuntimeError::ForeignAuthority)?;
            let mut bytes = Vec::new();
            let seal = peer
                .write_resolved_originals(activation.record(), owner, &mut bytes)
                .map_err(|_| RuntimeError::OutstandingObligations)?;
            if !seal.belongs_to(peer) {
                return Err(RuntimeError::ForeignAuthority);
            }
            let mut stored = file.borrow_mut();
            let status = stored
                .file
                .metadata()
                .map_err(|_| RuntimeError::InvalidReceipt)?;
            if status.uid() != rustix::process::geteuid().as_raw()
                || status.mode() & 0o777 != 0o600
                || status.nlink() != 1
                || stored.bytes != bytes
            {
                return Err(RuntimeError::InvalidReceipt);
            }
            stored
                .file
                .seek(SeekFrom::Start(0))
                .map_err(|_| RuntimeError::InvalidReceipt)?;
            let mut readback = Vec::new();
            stored
                .file
                .read_to_end(&mut readback)
                .map_err(|_| RuntimeError::InvalidReceipt)?;
            if readback != bytes {
                return Err(RuntimeError::InvalidReceipt);
            }
        }
        Ok(())
    }
}

pub(super) fn verify_original_retirement(
    runtime: NodeRuntime,
    activation: &WorldActivation,
    peers: &[Rc<RefCell<Vec<CnpPeerCustody>>>],
    supervisor: &custody::WorldSupervisor,
) {
    let ledger = runtime
        .runtime_snapshot(
            position(2000, Phase::BoundaryControl),
            U64::new(0),
            8 * 1024 * 1024,
        )
        .unwrap();
    let before = runtime
        .retirement_histories(activation, 256 * 1024 * 1024)
        .unwrap();
    assert_eq!(before.len(), 2);
    assert!(before.iter().all(|history| history.bodies.len() == 2));
    let mut runtime = Some(runtime);
    let mut retired = Some(NodeRuntime::take_graceful_retirement(&mut runtime).unwrap());
    assert!(runtime.is_none());
    assert!(retired.as_ref().unwrap().shutdown_failure().is_none());
    let mut context = Context::from_waker(Waker::noop());
    for _ in 0..300 {
        match retired.as_mut().unwrap().poll_reclamation(&mut context) {
            Poll::Ready(Ok(())) => break,
            Poll::Ready(Err(error)) => panic!("actual observed retirement failed: {error:?}"),
            Poll::Pending => std::thread::sleep(Duration::from_millis(10)),
        }
    }
    let original = retired.as_mut().unwrap();
    original
        .authenticate_retired_ledger(&ledger, 8 * 1024 * 1024)
        .unwrap();
    original.transfer_retirement_resources().unwrap();
    original.transfer_retirement_resources().unwrap();
    let history = original
        .retirement_histories(activation, 256 * 1024 * 1024)
        .unwrap();
    let repeated = original
        .retirement_histories(activation, 256 * 1024 * 1024)
        .unwrap();
    assert_eq!(
        history.iter().map(|row| &row.bodies).collect::<Vec<_>>(),
        repeated.iter().map(|row| &row.bodies).collect::<Vec<_>>()
    );
    let files = peers
        .iter()
        .map(|peers| {
            let peers = peers.borrow();
            assert_eq!(
                peers.len(),
                1,
                "same reserved native slot transferred only once"
            );
            let peer = &peers[0];
            let runtime = peer.runtime.as_ref().unwrap();
            let owner = activation
                .record()
                .owners
                .iter()
                .find(|owner| owner.owner == runtime.owner_binding.owner.id)
                .unwrap();
            // A failed sink cannot consume the same controller/observer originals.
            let mut lost_result = LostArchiveResult;
            assert!(
                peer.write_resolved_originals(activation.record(), owner, &mut lost_result)
                    .is_err()
            );
            let mut bytes = Vec::new();
            assert!(
                peer.write_resolved_originals(activation.record(), owner, &mut bytes)
                    .unwrap()
                    .belongs_to(peer)
            );
            let decoded: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            let observation = decoded["controller"].as_array().unwrap().last().unwrap();
            assert_eq!(observation["recording_complete"], true);
            assert_eq!(observation["observed_unknown"], false);
            assert!(
                !observation["evidence"]["requests"]
                    .as_array()
                    .unwrap()
                    .is_empty()
            );
            let directory = peer.duplicate_private_directory().unwrap();
            let mut file = File::from(
                rustix::fs::openat(
                    &directory,
                    "native-originals.json",
                    OFlags::RDWR
                        | OFlags::CREATE
                        | OFlags::EXCL
                        | OFlags::NOFOLLOW
                        | OFlags::CLOEXEC,
                    Mode::RUSR | Mode::WUSR,
                )
                .unwrap(),
            );
            file.write_all(&bytes).unwrap();
            file.sync_all().unwrap();
            directory.sync_all().unwrap();
            RefCell::new(StoredOriginal {
                file,
                directory,
                bytes,
            })
        })
        .collect::<Vec<_>>();
    let release = Release {
        ledger: &ledger,
        peers,
        files: &files,
    };
    QuarantinedRuntime::release_after_authenticated_supervision(&mut retired, activation, &release)
        .unwrap();
    assert!(retired.is_none());
    // Positive exact archival released this same runtime; it never entered the
    // fallback world supervisor and never produced a behavioral Accepted token.
    assert!(supervisor.is_empty());
    for file in &files {
        file.borrow().directory.sync_all().unwrap();
    }
}
