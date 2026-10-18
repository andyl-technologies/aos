//! Persists owned bounded state without holding embedded or admission mutexes.
//!
//! Only the real physical executor prepares a write. Completed provenance requires
//! actual file/parent synchronization and bounded state readback, not an in-memory
//! snapshot. Abandonment irreversibly invalidates this owner's write phase.

use super::{
    recovery_manifest_state,
    retention::{Custody, NativeOwnerExecutor, SynchronizedState},
};
use rustix::fs::{Mode, OFlags, openat};
use std::{
    fs::{File, Metadata},
    io,
    os::unix::fs::MetadataExt,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, Ordering},
    },
    thread::{self, ThreadId},
};
use terrane::{
    host::cache::{CacheState, StateLimits},
    store::{LocalFs, TokioLocalFs},
};

const IDLE: u8 = 0;
const WRITING: u8 = 1;
const FAILED: u8 = 2;

/// Owns one exact physical write intent and its actual native parent custody.
pub(super) struct PreparedSnapshotWrite {
    custody: Arc<Mutex<Custody>>,
    state: CacheState,
    path: PathBuf,
    limits: StateLimits,
    generation: u64,
    sequence: u64,
    worker: ThreadId,
    directory: File,
    state_parent: File,
    layout_root: File,
    phase: Arc<AtomicU8>,
    complete: bool,
}

impl Drop for PreparedSnapshotWrite {
    fn drop(&mut self) {
        if !self.complete {
            // An await may be dropped while another guard unwinds. Never lock
            // embedded state here, and never reinstate an earlier proof.
            self.phase.store(FAILED, Ordering::Release);
        }
    }
}

/// Exists only after this module completes native sync and bounded readback.
struct CompletedSnapshotWrite {
    file: File,
    metadata: Metadata,
    state: CacheState,
}

/// Prepares an owned write under the real executor's original worker identity.
///
/// # Errors
/// Refuses stale custody, another worker, overlapping writes, unbounded memory,
/// invalid state, descriptor failure or exhausted write identity.
pub(super) fn prepare(
    executor: &NativeOwnerExecutor,
    owner: &mut Custody,
) -> io::Result<PreparedSnapshotWrite> {
    executor.check_physical_worker()?;
    owner.check_current()?;
    super::admission::AdmissionBounds::new(&owner.preparation.config)?;
    owner
        .state
        .encoded_len(owner.preparation.config.state)
        .map_err(io::Error::other)?;
    let sequence = owner
        .snapshot_sequence
        .checked_add(1)
        .ok_or_else(|| io::Error::other("snapshot sequence exhausted"))?;
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let layout = owner.preparation.layout();
    let state = layout
        .directories
        .get("state")
        .ok_or_else(|| io::Error::other("state parent absent"))?;
    // Duplicate real owned descriptors before changing phase or attempting IO.
    let directory = owner.directory.try_clone()?;
    let state_parent = File::from(openat(state, ".", flags, Mode::empty())?);
    let layout_root = File::from(openat(&layout.root, ".", flags, Mode::empty())?);
    let snapshot = owner.state.clone();
    owner.synchronized_state = None;
    owner.snapshot_sequence = sequence;
    owner.snapshot_phase.store(WRITING, Ordering::Release);
    Ok(PreparedSnapshotWrite {
        custody: Arc::clone(executor.custody()),
        state: snapshot,
        path: owner.preparation.config.location.root().join("state/cache"),
        limits: owner.preparation.config.state,
        generation: owner.generation,
        sequence,
        worker: executor.worker_identity(),
        directory,
        state_parent,
        layout_root,
        phase: Arc::clone(&owner.snapshot_phase),
        complete: false,
    })
}

/// Writes, synchronizes and independently reads back an exact prepared snapshot.
///
/// # Errors
/// Refuses another worker, any failed native effect/readback, changed state or
/// write incarnation. Failures preserve faulted custody and invalidate provenance.
pub(super) async fn persist(
    executor: &NativeOwnerExecutor,
    mut prepared: PreparedSnapshotWrite,
) -> io::Result<()> {
    executor.check_physical_worker()?;
    if executor.worker_identity() != prepared.worker
        || thread::current().id() != prepared.worker
        || !Arc::ptr_eq(executor.custody(), &prepared.custody)
    {
        return Err(io::Error::other(
            "snapshot belongs to another physical executor",
        ));
    }
    // No mutex guard crosses these real async filesystem operations.
    let completed = write_snapshot(SnapshotIo {
        state: &prepared.state,
        path: &prepared.path,
        limits: prepared.limits,
        directory: &prepared.directory,
        state_parent: &prepared.state_parent,
        layout_root: &prepared.layout_root,
    })
    .await?;
    finish(executor, &mut prepared, completed)
}

/// Borrows actual IO inputs without granting native owner or quota authority.
struct SnapshotIo<'a> {
    state: &'a CacheState,
    path: &'a std::path::Path,
    limits: StateLimits,
    directory: &'a File,
    state_parent: &'a File,
    layout_root: &'a File,
}

async fn write_snapshot(input: SnapshotIo<'_>) -> io::Result<CompletedSnapshotWrite> {
    input
        .state
        .persist(&TokioLocalFs, input.path, input.limits)
        .await
        .map_err(io::Error::other)?;
    input.state_parent.sync_all()?;
    input.layout_root.sync_all()?;
    let file = super::open_regular_at(input.directory, "records.toml")?;
    let before = file.metadata()?;
    let path = input.path.join("records.toml");
    let named = TokioLocalFs.symlink_metadata(&path).await?;
    require_same_inode(&before, &named)?;
    let actual = CacheState::load(&TokioLocalFs, input.path, input.limits)
        .await
        .map_err(io::Error::other)?
        .ok_or_else(|| io::Error::other("written snapshot absent"))?;
    recovery_manifest_state::require_same(&actual, input.state)?;
    require_same_inode(&before, &file.metadata()?)?;
    let closing = super::open_regular_at(input.directory, "records.toml")?;
    require_same_inode(&before, &closing.metadata()?)?;
    file.sync_all()?;
    input.directory.sync_all()?;
    Ok(CompletedSnapshotWrite {
        file,
        metadata: before,
        state: actual,
    })
}

fn finish(
    executor: &NativeOwnerExecutor,
    prepared: &mut PreparedSnapshotWrite,
    completed: CompletedSnapshotWrite,
) -> io::Result<()> {
    executor.check_physical_worker()?;
    if executor.worker_identity() != prepared.worker {
        return Err(io::Error::other("snapshot completion changed worker"));
    }
    let mut owner = prepared
        .custody
        .lock()
        .map_err(|_| io::Error::other("snapshot custody poisoned"))?;
    if owner.generation != prepared.generation
        || owner.snapshot_sequence != prepared.sequence
        || !Arc::ptr_eq(&owner.snapshot_phase, &prepared.phase)
        || prepared.phase.load(Ordering::Acquire) != WRITING
    {
        return Err(io::Error::other("snapshot completion is stale"));
    }
    recovery_manifest_state::require_same(&owner.state, &prepared.state)?;
    recovery_manifest_state::require_same(&completed.state, &prepared.state)?;
    require_same_inode(
        &owner.directory.metadata()?,
        &prepared.directory.metadata()?,
    )?;
    owner.preparation.confinement.check_current()?;
    owner.preparation.layout().recheck()?;
    owner.capture_snapshot()?;
    let captured = &owner
        .snapshot
        .as_ref()
        .ok_or_else(|| io::Error::other("snapshot capture absent"))?
        .1;
    require_same_inode(&completed.metadata, captured)?;
    require_same_inode(&completed.metadata, &completed.file.metadata()?)?;
    // Only this actual completed writer may temporarily lift the private busy
    // phase. Drop permanently faults it if any closing currentness check fails.
    prepared.phase.store(IDLE, Ordering::Release);
    owner.check_current()?;
    owner.synchronized_state = Some(SynchronizedState {
        state: prepared.state.clone(),
        generation: prepared.generation,
        device: completed.metadata.dev(),
        inode: completed.metadata.ino(),
    });
    prepared.complete = true;
    Ok(())
}

fn require_same_inode(expected: &Metadata, actual: &Metadata) -> io::Result<()> {
    if !super::retention::same_file(expected, actual) {
        return Err(io::Error::other(
            "snapshot inode changed during write/readback",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::io::Read;

    struct Scratch(PathBuf);

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn actual_snapshot_io_retains_readback_and_rejects_replaced_inode() {
        let mut random = [0; 16];
        File::open("/dev/urandom")
            .unwrap()
            .read_exact(&mut random)
            .unwrap();
        let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let scratch = Scratch(std::env::temp_dir().join(format!("terrane-snapshot-{suffix}")));
        std::fs::create_dir(&scratch.0).unwrap();
        let directory = File::open(&scratch.0).unwrap();
        let mut state = CacheState::default();
        state
            .reservations
            .push(terrane::host::cache::ReservationRecord {
                id: "retained-operation".into(),
                owner: "owner".into(),
                bytes: 1024,
            });
        state.pins.push(terrane::host::cache::PinRecord {
            owner: "retained-operation".into(),
            hash: "ab".repeat(32),
            expires: u64::MAX,
        });
        state.leases.push(terrane::host::cache::LeaseRecord {
            owner: "retained-operation".into(),
            expires: u64::MAX,
        });
        let limits = StateLimits {
            bytes: 4096,
            records: 16,
        };
        // The frozen numeric representation cannot encode unsigned maxima.
        assert!(state.encoded_len(limits).is_err());
        state.pins[0].expires = super::super::RETAINED_LEASE_DEADLINE;
        state.leases[0].expires = super::super::RETAINED_LEASE_DEADLINE;

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        // Exercises real portable persistence + native sync/readback only.
        // No Custody, Installed, helper, worker or pin authority is fabricated.
        let completed = runtime
            .block_on(write_snapshot(SnapshotIo {
                state: &state,
                path: &scratch.0,
                limits,
                directory: &directory,
                state_parent: &directory,
                layout_root: &directory,
            }))
            .unwrap();

        recovery_manifest_state::require_same(&completed.state, &state).unwrap();
        require_same_inode(&completed.metadata, &completed.file.metadata().unwrap()).unwrap();
        let replacement = scratch.0.join("replacement");
        std::fs::write(&replacement, b"unverified replacement").unwrap();
        std::fs::rename(&replacement, scratch.0.join("records.toml")).unwrap();
        let actual = super::super::open_regular_at(&directory, "records.toml").unwrap();
        assert!(require_same_inode(&completed.metadata, &actual.metadata().unwrap()).is_err());
    }
}
