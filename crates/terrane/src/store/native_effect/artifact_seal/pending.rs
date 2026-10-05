//! Qualifies durable Pending before the first physical artifact mutation.
//!
//! The private receipt retains the same synchronized protected descriptor,
//! exact Pending body and registered association, actual journal directories,
//! and all original exclusions. Its initial absence witness is used only before
//! creation; subsequent artifact seals carry the newly captured physical tree.
//!
//! ```text
//! exact missing artifact + Pending FD -> file sync + control dirs -> receipt
//! receipt -> fixed artifact install -> updated artifact frame -> seal
//! ```

use super::{
    CreationJournal, FencePolicy, File, JournalState, MetadataStamp, NativeEffectFailure,
    NativeOpenedDirectory, Path, PathBuf, Plan, Projection, Worker, checked_protected,
    directories_below, journal_path, open_native,
};
use std::io;
use std::sync::mpsc;

#[cfg(all(test, feature = "tokio"))]
use super::{TestGatePhase, wait_test_gate};

/// Fixes canonical Pending and its exact originally missing artifact.
pub(in super::super) struct PendingRequest {
    root: PathBuf,
    control: PathBuf,
    key: String,
    pending: Vec<u8>,
    owner: u32,
    journal: PathBuf,
    result: mpsc::Sender<PendingReceipt>,
}

impl PendingRequest {
    /// Borrows the exact protected record for native test phase selection.
    #[cfg(test)]
    pub(in super::super) fn journal_path(&self) -> &Path {
        &self.journal
    }
}

/// Consumes a Pending durability result which only the native worker can fill.
pub(in super::super) struct PendingReceiver {
    result: mpsc::Receiver<PendingReceipt>,
}

impl PendingReceiver {
    /// Takes one actual completed protected-descriptor durability receipt.
    ///
    /// # Errors
    /// Returns `Unsupported` after an unexecuted or no-op acknowledged request.
    pub(in super::super) fn take(self) -> Result<PendingReceipt, NativeEffectFailure> {
        self.result.try_recv().map_err(|_| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "native Pending durability unavailable",
            )
            .into()
        })
    }
}

/// Retains the genuine Pending descriptor through fixed artifact creation.
pub(in super::super) struct PendingReceipt {
    file: File,
    stamp: MetadataStamp,
    root: PathBuf,
    control: PathBuf,
    key: String,
    pending: Vec<u8>,
    journal: PathBuf,
    owner: u32,
    missing: PathBuf,
    directories: Vec<NativeOpenedDirectory>,
    projection: Projection,
}

impl PendingReceipt {
    /// Borrows the fixed namespace root solely inside the seal implementation.
    pub(super) fn root(&self) -> &Path {
        &self.root
    }

    /// Borrows the exact registered artifact key carried by this receipt.
    pub(super) fn key(&self) -> &str {
        &self.key
    }

    /// Returns the operator policy already bound to the genuine native receipt.
    pub(super) fn owner(&self) -> u32 {
        self.owner
    }

    /// Checks original Pending while an updated frame carries the created artifact.
    ///
    /// # Errors
    /// Rejects changed Pending descriptor/body/name, replaced controls or original
    /// holds, and a new frame outside this receipt's exact root/key association.
    pub(super) fn recheck_installed(
        &mut self,
        current: &Projection,
    ) -> Result<(), NativeEffectFailure> {
        self.projection.refresh(&[&self.missing])?;
        current.root(&self.root, self.owner, false)?;
        current.root(&self.control, self.owner, true)?;
        current.exact(&self.journal, Some(&self.pending))?;
        for directory in &self.directories {
            directory.check()?;
        }
        checked_protected(
            &mut self.file,
            &self.journal,
            self.stamp,
            &self.pending,
            self.owner,
        )?;
        Ok(())
    }

    /// Preserves untouched original inputs after this operation replaces Pending.
    ///
    /// # Errors
    /// Rejects changed original control/root/exclusion or unrelated preimages.
    /// The caller independently checks the newly committed protected descriptor.
    pub(super) fn recheck_committed(&self) -> Result<(), NativeEffectFailure> {
        self.projection.refresh(&[&self.missing, &self.journal])?;
        for directory in &self.directories {
            directory.check()?;
        }
        Ok(())
    }
}

/// Creates the closed read/sync request without constructing a durability result.
///
/// # Errors
/// Rejects malformed or non-Pending bytes, wrong key association or relative
/// roots. Native execution separately checks the actual missing artifact.
pub(in super::super) fn pending_plan(
    root: &Path,
    control: &Path,
    key: &str,
    pending: &[u8],
    owner: u32,
) -> Result<(Plan, PendingReceiver), NativeEffectFailure> {
    super::container_key(key)?;
    let decoded = CreationJournal::decode(pending).map_err(io::Error::other)?;
    if decoded.key != key
        || decoded.state != JournalState::Pending
        || !root.is_absolute()
        || !control.is_absolute()
    {
        return Err(io::Error::other("invalid Pending durability association").into());
    }
    let (sender, receiver) = mpsc::channel();
    Ok((
        Plan::SealPendingCreation(Box::new(PendingRequest {
            root: root.to_owned(),
            control: control.to_owned(),
            key: key.to_owned(),
            pending: pending.to_vec(),
            owner,
            journal: journal_path(control, key),
            result: sender,
        })),
        PendingReceiver { result: receiver },
    ))
}

/// Completes Pending descriptor and directory durability before first mutation.
///
/// # Errors
/// Rejects missing/malformed associations, unsafe or changed names, incomplete
/// absence witnesses and failed native reads, current checks or synchronization.
pub(super) fn execute(
    request: PendingRequest,
    mut worker: Worker,
) -> Result<(), NativeEffectFailure> {
    worker
        .projection
        .root(&request.root, request.owner, false)?;
    worker
        .projection
        .root(&request.control, request.owner, true)?;
    let artifact = request.root.join(&request.key);
    // A missing registered ancestor qualifies absence when the artifact's
    // parent tree does not yet exist. It must lie strictly inside this root.
    let missing_read = worker
        .projection
        .preimages
        .iter()
        .find(|read| {
            read.expected.is_none()
                && read.identity.is_none()
                && read.metadata.is_none()
                && read.path != request.root
                && read.path.starts_with(&request.root)
                && artifact.starts_with(&read.path)
        })
        .ok_or_else(|| io::Error::other("Pending lacks its exact missing artifact witness"))?;
    if !matches!(missing_read.policy, FencePolicy::Payload { owner } if owner == request.owner) {
        return Err(io::Error::other("Pending absence lacks artifact policy").into());
    }
    let missing = missing_read.path.clone();
    // The witness covers only this one fixed artifact or its absent ancestry.
    // Existing sibling or control names cannot be removed from later checks.
    let pending_read = worker
        .projection
        .exact(&request.journal, Some(&request.pending))?;
    if !matches!(pending_read.policy, FencePolicy::ProtectedRecord { owner } if owner == request.owner)
    {
        return Err(io::Error::other("Pending lacks protected-record policy").into());
    }
    let stamp = pending_read
        .metadata
        .ok_or_else(|| io::Error::other("Pending metadata unavailable"))?;
    if pending_read.identity != Some(stamp.identity) {
        return Err(io::Error::other("Pending descriptor preimage is misbound").into());
    }
    let directories = directories_below(pending_read, &request.control, request.owner, true)?;
    #[cfg(all(test, feature = "tokio"))]
    wait_test_gate(&mut worker.gates, TestGatePhase::BeforeOpen)?;
    let mut file = open_native(&request.journal, false)?;
    #[cfg(all(test, feature = "tokio"))]
    wait_test_gate(&mut worker.gates, TestGatePhase::AfterOpen)?;
    worker.refresh(&[])?;
    checked_protected(
        &mut file,
        &request.journal,
        stamp,
        &request.pending,
        request.owner,
    )?;
    worker.file_sync(&file)?;
    worker.refresh(&[])?;
    checked_protected(
        &mut file,
        &request.journal,
        stamp,
        &request.pending,
        request.owner,
    )?;
    for directory in directories.iter().rev() {
        worker.directory_sync(directory, false)?;
        worker.refresh(&[])?;
        checked_protected(
            &mut file,
            &request.journal,
            stamp,
            &request.pending,
            request.owner,
        )?;
    }
    let receipt = PendingReceipt {
        file,
        stamp,
        root: request.root,
        control: request.control,
        key: request.key,
        pending: request.pending,
        journal: request.journal,
        owner: request.owner,
        missing,
        directories,
        projection: worker.projection,
    };
    let _ = request.result.send(receipt);
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        reason = "Fixture assertions intentionally panic."
    )]
    use super::*;

    #[test]
    fn an_unexecuted_pending_request_never_qualifies_first_mutation() {
        let key = "objects/pack/01/01010101010101010101010101010101.pack";
        let bytes = CreationJournal {
            key: key.into(),
            nonce: [7; 32],
            state: JournalState::Pending,
        }
        .encode()
        .unwrap();
        let (plan, receiver) = pending_plan(
            Path::new("/namespace"),
            Path::new("/control"),
            key,
            &bytes,
            1,
        )
        .unwrap();
        drop(plan);
        assert!(
            matches!(receiver.take(), Err(NativeEffectFailure::Io(error)) if error.kind() == io::ErrorKind::Unsupported)
        );
    }
}
