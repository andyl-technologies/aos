//! Retains the six fixed raw Controller inputs beneath upper typed Q04 pins.
//!
//! This owner shares the sole native read and named-readback engines. It
//! supplies DATA custody only; purpose, payment, and issuer authority stay upper.

use super::*;

/// Retains the six fixed raw Controller inputs without decoding a role signer.
///
/// This is native DATA custody only. The actual upper owner retains its own
/// typed role/signing results and genuine receiving purpose. A ready raw view
/// cannot construct that owner or advance a semantic or financial phase.
pub struct ControllerQ04NativeCredentialCustodyV1 {
    originals: [OriginalControllerCredential; 6],
    ancestors: CredentialAncestors,
    readback: CredentialReadback<6>,
    uid: Option<u32>,
    phase: ControllerCredentialPhase,
    failure: Option<std::sync::Arc<ControllerNixPublicCredentialErrorV1>>,
}

impl ControllerQ04NativeCredentialCustodyV1 {
    /// Describes the additional dynamic and native peak of this fixed batch.
    ///
    /// Inline storage is sized by the enclosing actual typed owner. Three
    /// independent byte lanes are original, original reread, and named reread;
    /// each includes old/new requested Vec growth. Twenty descriptors are the
    /// two independent four-ancestor/six-leaf flights. The two Arc lanes cover
    /// the retained first cause plus a current refused upper reentry.
    #[must_use]
    pub fn additional_geometry_v1() -> Option<ControllerStartupCredentialGeometryV1> {
        let raw = Q04_CONTROLLER_LENGTHS.into_iter().try_fold(0_usize, |sum, length| {
            sum.checked_add(usize::try_from(length).ok()?.checked_add(1)?)
        })?.checked_mul(3)?.checked_mul(3)?;
        let arc = std::mem::size_of::<ControllerNixPublicCredentialErrorV1>()
            .checked_add(2 * std::mem::size_of::<std::sync::atomic::AtomicUsize>())?
            .checked_mul(2)?;
        Some(ControllerStartupCredentialGeometryV1 {
            memory_bytes: raw.checked_add(arc)?.checked_add(4 * 4096)?,
            open_files: 20,
            // Original and named-readback flights each retain four ancestor
            // names and six fixed credential names. Headers are bytes.
            metadata_entries: 2 * (4 + 6),
        })
    }

    /// Creates empty native destinations without IO or allocation.
    #[must_use]
    pub fn new() -> Self {
        Self {
            originals: std::array::from_fn(|_| OriginalControllerCredential {
                public: None, read: CredentialReadSlot::new(),
            }),
            ancestors: CredentialAncestors::new(),
            readback: CredentialReadback::new(),
            uid: None,
            phase: ControllerCredentialPhase::Fresh,
            failure: None,
        }
    }

    /// Captures the compiled six names and their original initial readback.
    ///
    /// # Errors
    /// Retains the actual first native/read/width error and all reached raw
    /// owners, and refuses reentry without replacing that original cause.
    pub fn capture(&mut self)
        -> Result<(), std::sync::Arc<ControllerNixPublicCredentialErrorV1>>
    {
        if self.phase != ControllerCredentialPhase::Fresh {
            return self.finish(Err(credential_state_rejected()));
        }
        self.phase = ControllerCredentialPhase::Closed;
        self.uid = Some(rustix::process::geteuid().as_raw());
        let result = self.capture_pair();
        self.finish(result)
    }

    /// Rechecks the same original files and names without renewing authority.
    ///
    /// # Errors
    /// Preserves the first native cause and interrupted/failed owner; only a
    /// completed previous native readback can supply the next finite batch.
    pub fn recheck(&mut self)
        -> Result<(), std::sync::Arc<ControllerNixPublicCredentialErrorV1>>
    {
        if self.phase != ControllerCredentialPhase::Ready {
            return self.finish(Err(credential_state_rejected()));
        }
        self.phase = ControllerCredentialPhase::Closed;
        self.readback = CredentialReadback::new();
        let result = self.observe_pair();
        self.finish(result)
    }

    /// Borrows the actual six raw inputs only during completed native custody.
    #[must_use]
    pub fn ready(&self) -> Option<[&[u8]; 6]> {
        if self.phase != ControllerCredentialPhase::Ready {
            return None;
        }
        Some([
            self.originals[0].public.as_ref()?.bytes(),
            self.originals[1].public.as_ref()?.bytes(),
            self.originals[2].public.as_ref()?.bytes(),
            self.originals[3].public.as_ref()?.bytes(),
            self.originals[4].public.as_ref()?.bytes(),
            self.originals[5].public.as_ref()?.bytes(),
        ])
    }

    /// Closes this native DATA view without disposing its originals or debt.
    pub fn fence(&mut self) {
        self.phase = ControllerCredentialPhase::Closed;
    }

    /// Borrows the same actual error shared with the upper typed owner.
    #[must_use]
    pub fn failure(&self) -> Option<&ControllerNixPublicCredentialErrorV1> {
        self.failure.as_deref()
    }

    fn finish(&mut self, result: CredentialResult<()>)
        -> Result<(), std::sync::Arc<ControllerNixPublicCredentialErrorV1>>
    {
        match result {
            Ok(()) => {
                self.phase = ControllerCredentialPhase::Ready;
                Ok(())
            }
            Err(cause) => {
                self.phase = ControllerCredentialPhase::Closed;
                Err(std::sync::Arc::clone(self.failure.get_or_insert_with(|| {
                    std::sync::Arc::new(cause)
                })))
            }
        }
    }

    fn capture_pair(&mut self) -> CredentialResult<()> {
        let uid = self.uid.ok_or_else(credential_state_rejected)?;
        let path = Path::new(NIX_CONTROLLER_DIRECTORY);
        open_directory_with_custody(
            path, uid, &mut DirectoryCustody::Resident(&mut self.ancestors),
        )?;
        let directory = self.ancestors.directory()?;
        let directory_identity = self.ancestors.slots[3].identity
            .ok_or_else(credential_state_rejected)?;
        for (index, name) in Q04_CONTROLLER_NAMES.iter().enumerate() {
            require_present_credential(capture_credential_original_slot_inner(
                directory, path, directory_identity, name, uid,
                Q04_CONTROLLER_LENGTHS[index], Some(Q04_CONTROLLER_LENGTHS[index]),
                &mut self.originals[index],
            )?)?;
        }
        self.observe_pair()
    }

    fn observe_pair(&mut self) -> CredentialResult<()> {
        observe_controller_credential_readback(
            self.uid.ok_or_else(credential_state_rejected)?,
            &Q04_CONTROLLER_NAMES, &Q04_CONTROLLER_LENGTHS,
            &mut self.originals, &self.ancestors, &mut self.readback,
        )
    }
}

impl Default for ControllerQ04NativeCredentialCustodyV1 {
    fn default() -> Self {
        Self::new()
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn q04_original_read_failure_is_shared_once_and_survives_fenced_reentry() {
        use std::error::Error as _;
        use std::os::fd::AsRawFd as _;
        use std::os::unix::fs::OpenOptionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("write-only-original");
        let mut file = std::fs::OpenOptions::new()
            .write(true).create_new(true).mode(0o600).open(path).unwrap();
        std::io::Write::write_all(&mut file, b"pin").unwrap();
        let descriptor = file.as_raw_fd();
        let mut bytes = None;
        let cause = read_opened_credential(
            &mut file, &mut bytes, rustix::process::geteuid().as_raw(), 64,
        ).unwrap_err();
        assert!(cause.source().is_some());

        // This is an actual failed native prefix, never a selected C grant.
        let mut owner = ControllerQ04NativeCredentialCustodyV1::new();
        owner.originals[0].read.file = Some(file);
        owner.originals[0].read.bytes = bytes;
        let first = owner.finish(Err(cause)).unwrap_err();
        let repeated = owner.capture().unwrap_err();
        owner.fence();

        assert!(std::sync::Arc::ptr_eq(&first, &repeated));
        assert!(std::ptr::eq(first.as_ref(), owner.failure().unwrap()));
        assert!(owner.ready().is_none());
        assert_eq!(owner.originals[0].read.file.as_ref().unwrap().as_raw_fd(), descriptor);
        assert!(owner.originals[0].read.file.as_ref().unwrap().metadata().is_ok());
    }

}
