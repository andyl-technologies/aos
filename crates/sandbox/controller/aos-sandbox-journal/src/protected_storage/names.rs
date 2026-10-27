//! Retains the original Lock/Journal name-check engine and its reached files.
//!
//! Ordinary callers consume this same disposition immediately. Selected owners
//! keep failed prefixes through their independent posts; a successful complete
//! check may dispose the temporary files without granting writer authority.

use std::fs::File;

use rustix::fs::{Stat, fstat};

use super::{ProtectedFailure, open_read_only_protected_file_original, rustix_io};

/// Parks the exact name-check returns before their original physical checks.
///
/// This once-only DATA owner performs no semantic replay or admission. Keeping
/// the owner preserves both reached Files if a later open, fstat or comparison
/// fails. It exposes no descriptor factory or retry/reset operation.
pub struct ProtectedFileNamesCurrentOriginalsV1<E> {
    named_lock: Option<Result<File, rustix::io::Errno>>,
    named_file: Option<Result<File, rustix::io::Errno>>,
    held_lock: Option<Result<Stat, rustix::io::Errno>>,
    held_file: Option<Result<Stat, rustix::io::Errno>>,
    current_lock: Option<Result<Stat, rustix::io::Errno>>,
    current_file: Option<Result<Stat, rustix::io::Errno>>,
    result: Option<Result<(), E>>,
}

impl<E> Default for ProtectedFileNamesCurrentOriginalsV1<E> {
    fn default() -> Self {
        Self { named_lock: None, named_file: None, held_lock: None, held_file: None,
            current_lock: None, current_file: None, result: None }
    }
}

impl<E: ProtectedFailure> ProtectedFileNamesCurrentOriginalsV1<E> {
    /// Constructs empty result destinations without opening any file.
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Runs Lock, Journal and the four fstats once in their original order.
    ///
    /// Every native return is parked before inspection. Reentry performs no IO
    /// and retains the first result, including an incomplete failed prefix.
    pub fn capture_once(&mut self, directory: &File, name: &str, expected_uid: u32,
        lock: &File, file: &File)
    {
        if self.result.is_some() { return; }
        self.result = Some(self.capture_inner(directory, name, expected_uid, lock, file));
    }

    fn capture_inner(&mut self, directory: &File, name: &str, expected_uid: u32,
        lock: &File, file: &File) -> Result<(), E>
    {
        open_read_only_protected_file_original::<E>(directory, &format!("{name}.lock"),
            expected_uid, &mut self.named_lock)?;
        open_read_only_protected_file_original::<E>(directory, name,
            expected_uid, &mut self.named_file)?;
        self.held_lock = Some(fstat(lock));
        let held_lock = stat::<E>(&self.held_lock)?;
        self.held_file = Some(fstat(file));
        let held_file = stat::<E>(&self.held_file)?;
        let named_lock = match self.named_lock.as_ref() { Some(Ok(file)) => file, _ => return Err(E::BOUNDARY) };
        self.current_lock = Some(fstat(named_lock));
        let current_lock = stat::<E>(&self.current_lock)?;
        let named_file = match self.named_file.as_ref() { Some(Ok(file)) => file, _ => return Err(E::BOUNDARY) };
        self.current_file = Some(fstat(named_file));
        let current_file = stat::<E>(&self.current_file)?;
        if held_lock.st_dev != current_lock.st_dev || held_lock.st_ino != current_lock.st_ino
            || held_file.st_dev != current_file.st_dev || held_file.st_ino != current_file.st_ino {
            return Err(E::STALE_NAME);
        }
        Ok(())
    }

    /// Reports the first complete original physical refusal by reference.
    #[must_use]
    pub fn failure(&self) -> Option<&E> { self.result.as_ref().and_then(|result| result.as_ref().err()) }

    /// Counts the actual fresh Files still owned by this disposition.
    #[must_use]
    pub fn retained_file_count(&self) -> usize {
        usize::from(matches!(self.named_lock, Some(Ok(_))))
            + usize::from(matches!(self.named_file, Some(Ok(_))))
    }

    /// Reports a complete successful comparison of both actual names.
    #[must_use]
    pub fn is_complete(&self) -> bool { matches!(self.result, Some(Ok(()))) }

    /// Returns the already sampled held journal's device, inode and byte length.
    ///
    /// Only a completed successful name comparison exposes this historical
    /// DATA. This issues no new syscall and grants no present currentness,
    /// descriptor, append or role capability.
    #[must_use]
    pub fn completed_held_file_boundary_data_v1(&self) -> Option<(u64, u64, u64)> {
        if !self.is_complete() { return None; }
        let held = self.held_file.as_ref()?.as_ref().ok()?;
        Some((held.st_dev as u64, held.st_ino as u64, u64::try_from(held.st_size).ok()?))
    }

    /// Consumes the disposition for the original ordinary wrapper.
    ///
    /// # Errors
    /// Returns its original physical error, or the fixed boundary if unentered.
    pub fn into_result(mut self) -> Result<(), E> {
        // Ordinary locals previously closed Journal before Lock, including
        // failed prefixes. Keep that schedule in this shared disposition.
        drop(self.named_file.take());
        drop(self.named_lock.take());
        match self.result.take() { Some(result) => result, None => Err(E::BOUNDARY) }
    }
}

fn stat<E: ProtectedFailure>(slot: &Option<Result<Stat, rustix::io::Errno>>) -> Result<&Stat, E> {
    match slot { Some(Ok(stat)) => Ok(stat), Some(Err(error)) => Err(rustix_io::<E>(*error)), None => Err(E::BOUNDARY) }
}
