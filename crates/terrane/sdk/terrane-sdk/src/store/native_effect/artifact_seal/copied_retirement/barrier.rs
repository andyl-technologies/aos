//! Retains a genuine NEW destination Trash and its committed creation journal.
//!
//! The enclosing copied preparation executor supplies the closed fresh-key
//! association. Neither decoded journals nor this descriptor observation can
//! independently construct first-ownership permission. Elapsed time starts only
//! after actual synchronization under the complete retained native Frame.

use super::super::{
    FencePolicy, File, MetadataStamp, NativeEffectFailure, PathBuf, Worker, checked_body,
    checked_protected, directories_below, open_native,
};
use crate::store::{Clock, NativeEffectClock};
use std::{
    io,
    sync::Mutex,
    time::{Duration, SystemTime},
};
use terrane_format::gc::retirement::LocalBarrierArtifact;
use terrane_format::gc::{ArtifactBinding, CreationJournal, JournalState, Tombstone};

struct Record {
    path: PathBuf,
    bytes: Vec<u8>,
    stamp: MetadataStamp,
    file: File,
    protected: bool,
    owner: u32,
}

impl Record {
    fn check(&mut self) -> io::Result<()> {
        if self.protected {
            checked_protected(
                &mut self.file,
                &self.path,
                self.stamp,
                &self.bytes,
                self.owner,
            )
        } else {
            checked_body(
                &mut self.file,
                &self.path,
                self.stamp,
                &self.bytes,
                self.owner,
            )
        }
    }
}

/// Owns actual synchronized barrier descriptors and one retained injected clock.
pub(super) struct BarrierHold {
    records: Mutex<RetainedObservation>,
    artifact: LocalBarrierArtifact,
    clock: NativeEffectClock,
    started: Duration,
    wall_started: SystemTime,
}

struct RetainedObservation {
    trash: Record,
    journal: Record,
    last_tick: Duration,
    last_wall: SystemTime,
    valid: bool,
}

struct TimingAttempt<'a> {
    barrier: &'a BarrierHold,
    completed: bool,
}

impl Drop for TimingAttempt<'_> {
    fn drop(&mut self) {
        if !self.completed
            && let Ok(mut observed) = self.barrier.records.lock()
        {
            observed.valid = false;
        }
    }
}

impl BarrierHold {
    /// Opens and synchronizes the exact genuinely committed NEW barrier.
    ///
    /// # Errors
    /// Refuses mismatched retained roots, missing actual exact reads, noncanonical
    /// journals, incorrect nonce/body/incarnation, stale Frame or actual sync error.
    pub(super) fn observe(
        root: &std::path::Path,
        control: &std::path::Path,
        owner: u32,
        artifact: LocalBarrierArtifact,
        clock: NativeEffectClock,
        worker: &mut Worker,
    ) -> Result<Self, NativeEffectFailure> {
        worker.projection.root(root, owner, false)?;
        worker.projection.root(control, owner, true)?;
        if worker.projection.final_check.is_none() {
            return Err(io::Error::other("copied barrier lacks live final check").into());
        }
        let tombstone = Tombstone::decode(&artifact.tombstone).map_err(io::Error::other)?;
        if tombstone.encode() != artifact.tombstone
            || tombstone.removed != 0
            || artifact.key
                != format!(
                    "trash/{}/{}",
                    tombstone.cycle,
                    crate::pack::PackId::from_random_bytes(tombstone.pack)
                )
        {
            return Err(io::Error::other("copied barrier is not exact zero-removal Trash").into());
        }
        let suffix: String = blake3::hash(artifact.key.as_bytes())
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let journal_path = control.join(format!(".terrane-creation/{suffix}"));
        let path = root.join(&artifact.key);
        let trash_read = worker.projection.exact(&path, Some(&artifact.tombstone))?;
        let journal_read = worker
            .projection
            .preimages
            .iter()
            .find(|read| read.path == journal_path)
            .ok_or_else(|| io::Error::other("copied barrier journal was not consumed"))?;
        let bytes = journal_read
            .expected
            .as_deref()
            .ok_or_else(|| io::Error::other("copied barrier journal absent"))?;
        let journal = CreationJournal::decode(bytes).map_err(io::Error::other)?;
        if journal.encode().map_err(io::Error::other)? != bytes
            || journal.key != artifact.key
            || journal.nonce != artifact.nonce
            || !matches!(&journal.state, JournalState::Committed { binding, file_identity }
                if binding == &ArtifactBinding::Trash(artifact.tombstone.clone())
                    && file_identity == &artifact.file_identity)
            || !matches!(trash_read.policy, FencePolicy::Payload { owner: actual } if actual == owner)
            || !matches!(journal_read.policy, FencePolicy::ProtectedRecord { owner: actual } if actual == owner)
        {
            return Err(io::Error::other("copied barrier committed association differs").into());
        }
        let trash_stamp = trash_read
            .metadata
            .ok_or_else(|| io::Error::other("copied barrier metadata absent"))?;
        let mut identity = Vec::with_capacity(16);
        identity.extend_from_slice(&trash_stamp.identity.0.to_be_bytes());
        identity.extend_from_slice(&trash_stamp.identity.1.to_be_bytes());
        if artifact.file_identity != identity {
            return Err(
                io::Error::other("copied barrier journal names another incarnation").into(),
            );
        }
        let journal_stamp = journal_read
            .metadata
            .ok_or_else(|| io::Error::other("copied barrier journal metadata absent"))?;
        let directories = [
            directories_below(trash_read, root, owner, false)?,
            directories_below(journal_read, control, owner, true)?,
        ];
        let mut trash = Record {
            file: open_native(&path, false)?,
            path,
            bytes: artifact.tombstone.clone(),
            stamp: trash_stamp,
            protected: false,
            owner,
        };
        let mut committed = Record {
            file: open_native(&journal_path, false)?,
            path: journal_path,
            bytes: bytes.to_vec(),
            stamp: journal_stamp,
            protected: true,
            owner,
        };
        for (record, parents) in [
            (&mut trash, &directories[0]),
            (&mut committed, &directories[1]),
        ] {
            worker.refresh(&[])?;
            record.check()?;
            worker.file_sync(&record.file, &[])?;
            record.check()?;
            for directory in parents.iter().rev() {
                worker.directory_sync(directory, false, &[])?;
                record.check()?;
            }
        }
        worker.refresh(&[])?;
        trash.check()?;
        committed.check()?;
        let started = clock.monotonic();
        let wall_started = clock.now();
        Ok(Self {
            records: Mutex::new(RetainedObservation {
                trash,
                journal: committed,
                last_tick: started,
                last_wall: wall_started,
                valid: true,
            }),
            artifact,
            clock,
            started,
            wall_started,
        })
    }

    /// Borrows the exact native-observed local barrier association.
    pub(super) fn artifact(&self) -> &LocalBarrierArtifact {
        &self.artifact
    }

    /// Waits through the same retained injected clock without importing age.
    ///
    /// # Errors
    /// Refuses failed timer operations or barrier discontinuity before/after the
    /// timer. The caller separately checks and renews its actual current lease.
    pub(super) async fn sleep(&self, duration: Duration) -> io::Result<()> {
        self.elapsed()?;
        let mut attempt = TimingAttempt {
            barrier: self,
            completed: false,
        };
        self.clock.sleep(duration).await?;
        self.elapsed()?;
        attempt.completed = true;
        Ok(())
    }

    /// Measures actual same-clock elapsed time after descriptor continuity checks.
    ///
    /// # Errors
    /// Refuses replacement/mutation, poisoned retention or clock regression.
    pub(super) fn elapsed(&self) -> io::Result<Duration> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| io::Error::other("copied barrier retention poisoned"))?;
        if !records.valid {
            return Err(io::Error::other(
                "copied barrier continuity previously failed",
            ));
        }
        // An observed discontinuity cannot regain elapsed permission by restoring
        // old bytes or advancing the clock again. A new native observation must
        // start its complete wait from zero.
        records.valid = false;
        records.trash.check()?;
        records.journal.check()?;
        let wall = self.clock.now();
        let tick = self.clock.monotonic();
        if wall < self.wall_started || wall < records.last_wall {
            return Err(io::Error::other("copied barrier wall clock regressed"));
        }
        if tick < records.last_tick {
            return Err(io::Error::other("copied barrier monotonic clock regressed"));
        }
        let elapsed = tick
            .checked_sub(self.started)
            .ok_or_else(|| io::Error::other("copied barrier monotonic clock regressed"))?;
        records.last_tick = tick;
        records.last_wall = wall;
        records.valid = true;
        Ok(elapsed)
    }
}
