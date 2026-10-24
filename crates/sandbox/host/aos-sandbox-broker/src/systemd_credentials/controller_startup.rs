//! Retains the Controller's initial Source pair and public TLS credential reads.
//!
//! Both fixed recipes share the existing protected directory, original-file and
//! named-readback engines. This is native custody and passive geometry only;
//! the enclosing actual Controller startup prepays it before the first read.
//! Later operation and serving rechecks have their own receiving obligations.

use sha2::{Digest as _, Sha256};

use super::{
    CONTROLLER_SOURCE_TREE_SEED_ISSUER_NAME, ControllerNixPublicCredentialErrorV1,
    CredentialAncestors, CredentialFailureClass, CredentialOperation,
    CredentialReadOutcome, CredentialReadSlot, CredentialReadback, CredentialResult,
    Credentials, DirectoryCustody, FixedCredentialDirectoryV1,
    MAXIMUM_CREDENTIAL_BYTES, NAMES, OriginalControllerCredential,
    PROJECT_AUTHORIZATION_ISSUER_NAME, PinnedSystemdCredential,
    SOURCE_GENESIS_PACKET_NAMES, capture_fixed_credential_original_slot,
    credential_state_rejected, observe_fixed_credential_readback,
    open_directory_with_custody, open_read_credential, recheck_credential_ancestors,
    require_present_credential,
};

/// Describes dominant requested carriers of one fixed startup reader.
///
/// This DATA neither admits work nor proves an original, currentness or fit.
/// The same Controller receiving owner must account for it before capture.
#[doc(hidden)]
#[derive(Clone, Copy, Debug)]
pub struct ControllerStartupCredentialGeometryV1 {
    /// Dominant raw, typed, path and error carriers, excluding the inline owner.
    pub memory_bytes: usize,
    /// Original and two independently retained named-readback descriptor sets.
    pub open_files: usize,
    /// Retained file, path, buffer and typed collection carriers.
    pub metadata_entries: usize,
}

#[derive(Clone, Copy)]
enum InitialRole {
    SourceGenesis,
    PublicTls,
}

impl InitialRole {
    fn names(self) -> [&'static str; 4] {
        match self {
            Self::SourceGenesis => [
                SOURCE_GENESIS_PACKET_NAMES[0],
                SOURCE_GENESIS_PACKET_NAMES[1],
                CONTROLLER_SOURCE_TREE_SEED_ISSUER_NAME,
                PROJECT_AUTHORIZATION_ISSUER_NAME,
            ],
            Self::PublicTls => NAMES,
        }
    }

    fn maxima(self) -> [u64; 4] {
        match self {
            Self::SourceGenesis => [
                aos_sandbox_protocol::source_seed_layout::CONTROLLER_SOURCE_TREE_SEED_BYTES_V1 as u64,
                aos_sandbox_protocol::source_project_authorization::PROJECT_AUTHORIZATION_SOURCE_BYTES_V3 as u64,
                80,
                80,
            ],
            Self::PublicTls => [MAXIMUM_CREDENTIAL_BYTES; 4],
        }
    }
}

/// Keeps all reached native prefixes and both finite startup readbacks resident.
pub struct ControllerInitialCredentialCustodyV1 {
    role: InitialRole,
    originals: [OriginalControllerCredential; 4],
    ancestors: CredentialAncestors,
    readbacks: [CredentialReadback<4>; 2],
    observations: [Option<CredentialReadOutcome>; 4],
    capture: Option<CredentialResult<()>>,
    initial_post: Option<CredentialResult<()>>,
    final_post: Option<CredentialResult<()>>,
    reentry: Option<ControllerNixPublicCredentialErrorV1>,
    uid: Option<u32>,
    optional_absent: bool,
    taken: bool,
    settled: bool,
}

impl ControllerInitialCredentialCustodyV1 {
    /// Creates the compiled Controller Source-genesis native reader.
    pub fn source_genesis() -> Self {
        Self::new(InitialRole::SourceGenesis)
    }

    /// Creates the compiled Controller public-TLS native reader.
    pub fn public_tls() -> Self {
        Self::new(InitialRole::PublicTls)
    }

    fn new(role: InitialRole) -> Self {
        Self {
            role,
            originals: std::array::from_fn(|_| OriginalControllerCredential {
                public: None,
                read: CredentialReadSlot::new(),
            }),
            ancestors: CredentialAncestors::new(),
            readbacks: std::array::from_fn(|_| CredentialReadback::new()),
            observations: [None; 4],
            capture: None,
            initial_post: None,
            final_post: None,
            reentry: None,
            uid: None,
            optional_absent: false,
            taken: false,
            settled: false,
        }
    }

    fn geometry(role: InitialRole) -> Option<ControllerStartupCredentialGeometryV1> {
        let bytes = role.maxima().into_iter().try_fold(0_usize, |sum, maximum| {
            sum.checked_add(usize::try_from(maximum).ok()?.checked_add(1)?)
        })?;
        // Each input can retain its original and two original/named readback
        // pairs. Three times each read ceiling conservatively covers requested
        // Vec growth plus its old/new reallocation overlap. Fixed original
        // paths/native scratch are separate; allocator metadata is not exact.
        let memory_bytes = bytes.checked_mul(5)?.checked_mul(3)?
            .checked_add(24 * 256)?;
        Some(ControllerStartupCredentialGeometryV1 {
            memory_bytes,
            open_files: 24,
            // Original plus two named readbacks, each with the same four
            // ancestor and four fixed credential names. No Rust-field fee.
            metadata_entries: 3 * (4 + 4),
        })
    }

    /// Describes the compiled Source-genesis native DATA carriers.
    pub fn source_genesis_geometry() -> Option<ControllerStartupCredentialGeometryV1> {
        Self::geometry(InitialRole::SourceGenesis)
    }

    /// Describes the compiled public-TLS native DATA carriers.
    pub fn public_tls_geometry() -> Option<ControllerStartupCredentialGeometryV1> {
        Self::geometry(InitialRole::PublicTls)
    }

    /// Captures once, then attempts the independently available initial post.
    ///
    /// # Errors
    /// Refuses an unsafe, missing, changed, failed, or already closed fixed
    /// credential observation; it does not confer role or receiving authority.
    pub fn capture_once(&mut self) -> Result<(), ()> {
        if self.capture.is_some() || self.reentry.is_some() || self.taken {
            self.reentry.get_or_insert_with(credential_state_rejected);
            return Err(());
        }
        self.uid = Some(rustix::process::geteuid().as_raw());
        self.capture = Some(self.capture_inner());
        self.initial_post = Some(if matches!(self.capture, Some(Ok(()))) {
            self.observe(0)
        } else {
            // Even a partial initial read keeps its available original ancestry
            // post. Its native cause is later debt, never the primary failure.
            self.uid.ok_or_else(credential_state_rejected)
                .and_then(|uid| recheck_credential_ancestors(&self.ancestors, uid))
        });
        if self.capture_failure().is_none() {
            Ok(())
        } else {
            Err(())
        }
    }

    fn capture_inner(&mut self) -> CredentialResult<()> {
        let uid = self.uid.ok_or_else(credential_state_rejected)?;
        let recipe = FixedCredentialDirectoryV1::Controller;
        open_directory_with_custody(
            recipe.path(), uid, &mut DirectoryCustody::Resident(&mut self.ancestors),
        )?;
        let directory = self.ancestors.directory()?;
        let directory_identity = self.ancestors.slots[3]
            .identity.ok_or_else(credential_state_rejected)?;
        let names = self.role.names();
        let maxima = self.role.maxima();
        for index in 0..4 {
            let observed = capture_fixed_credential_original_slot(
                directory, recipe.path(), directory_identity, names[index], uid,
                maxima[index], &mut self.originals[index],
            )?;
            self.observations[index] = Some(observed);
            if matches!(self.role, InitialRole::SourceGenesis) && index < 2 {
                if let CredentialReadOutcome::Present(_) = observed {
                    let width = self.originals[index].public.as_ref()
                        .ok_or_else(credential_state_rejected)?.bytes().len();
                    let valid = if index == 0 {
                        width == maxima[0] as usize
                    } else {
                        width == aos_sandbox_protocol::source_project_authorization::PROJECT_AUTHORIZATION_SOURCE_BYTES_V2
                            || width == maxima[1] as usize
                    };
                    if !valid {
                        return Err(ControllerNixPublicCredentialErrorV1::rejected(
                            CredentialFailureClass::Configuration,
                            CredentialOperation::FileProvenance,
                        ));
                    }
                    // Preserve the ordinary packet's exact-width later recheck.
                    self.originals[index].public.as_mut()
                        .ok_or_else(credential_state_rejected)?.exact_bytes = Some(width as u64);
                }
                if index == 1 {
                    match (self.observations[0], self.observations[1]) {
                        (Some(CredentialReadOutcome::Absent(_)), Some(CredentialReadOutcome::Absent(_))) => {
                            self.optional_absent = true;
                            return Ok(());
                        }
                        (Some(CredentialReadOutcome::Present(_)), Some(CredentialReadOutcome::Present(_))) => {}
                        (Some(CredentialReadOutcome::Absent(cause)), _) => {
                            return require_present_credential(CredentialReadOutcome::Absent(cause)).map(|_| ());
                        }
                        (_, Some(CredentialReadOutcome::Absent(cause))) => {
                            return require_present_credential(CredentialReadOutcome::Absent(cause)).map(|_| ());
                        }
                        _ => return Err(credential_state_rejected()),
                    }
                }
            } else {
                require_present_credential(observed)?;
            }
        }
        Ok(())
    }

    /// Rechecks this fixed native recipe and retains its original refusal.
    ///
    /// # Errors
    /// Refuses an unsafe, missing, changed, failed, or already closed fixed
    /// credential observation; it does not confer role or receiving authority.
    pub fn recheck_once(&mut self) -> Result<(), ()> {
        if !matches!(self.capture, Some(Ok(()))) || self.final_post.is_some()
            || self.reentry.is_some() || self.taken || self.settled
        {
            self.reentry.get_or_insert_with(credential_state_rejected);
            return Err(());
        }
        self.final_post = Some(self.observe(1));
        if matches!(self.final_post, Some(Ok(()))) {
            Ok(())
        } else {
            Err(())
        }
    }

    fn observe(&mut self, index: usize) -> CredentialResult<()> {
        let uid = self.uid.ok_or_else(credential_state_rejected)?;
        if !self.optional_absent {
            return observe_fixed_credential_readback(
                FixedCredentialDirectoryV1::Controller, uid, &self.role.names(),
                &self.role.maxima(), &mut self.originals, &self.ancestors,
                &mut self.readbacks[index],
            );
        }
        // Optional absence never opens either issuer. It still checks the
        // same original directory and both packet names at each finite post.
        if rustix::process::geteuid().as_raw() != uid {
            return Err(credential_state_rejected());
        }
        recheck_credential_ancestors(&self.ancestors, uid)?;
        let post = &mut self.readbacks[index];
        open_directory_with_custody(
            FixedCredentialDirectoryV1::Controller.path(), uid,
            &mut DirectoryCustody::Resident(&mut post.ancestors),
        )?;
        for (original, named) in self.ancestors.slots.iter().zip(&post.ancestors.slots) {
            if original.identity != named.identity {
                return Err(credential_state_rejected());
            }
        }
        let directory = post.ancestors.directory()?;
        for member in 0..2 {
            let observed = open_read_credential(
                directory, SOURCE_GENESIS_PACKET_NAMES[member], uid,
                self.role.maxima()[member], &mut post.named[member],
            )?;
            if !matches!(observed, CredentialReadOutcome::Absent(_)) {
                return Err(credential_state_rejected());
            }
        }
        recheck_credential_ancestors(&self.ancestors, uid)?;
        recheck_credential_ancestors(&post.ancestors, uid)?;
        if rustix::process::geteuid().as_raw() != uid {
            return Err(credential_state_rejected());
        }
        Ok(())
    }

    /// Reports a completed optional absence without conferring authority.
    pub fn is_absent(&self) -> Option<bool> {
        (self.capture_failure().is_none() && matches!(self.capture, Some(Ok(()))))
            .then_some(self.optional_absent)
    }

    /// Borrows completed raw DATA from this same native custody owner.
    pub fn bytes(&self) -> Option<[&[u8]; 4]> {
        if self.capture_failure().is_some() || self.optional_absent || self.taken {
            return None;
        }
        Some([
            self.originals[0].public.as_ref()?.bytes(),
            self.originals[1].public.as_ref()?.bytes(),
            self.originals[2].public.as_ref()?.bytes(),
            self.originals[3].public.as_ref()?.bytes(),
        ])
    }

    /// Moves the same completed fixed Source credential snapshots once.
    pub fn take_source_genesis(&mut self) -> Option<Option<[PinnedSystemdCredential; 4]>> {
        if !matches!(self.role, InitialRole::SourceGenesis) || self.failure().is_some()
            || !matches!(self.final_post, Some(Ok(()))) || self.taken
        {
            return None;
        }
        self.taken = true;
        if self.optional_absent {
            return Some(None);
        }
        // Exclusive access and four occupied slots make these moves infallible.
        // Validate all slots before taking the first original DATA owner.
        if self.originals.iter().any(|original| original.public.is_none()) {
            return None;
        }
        Some(Some([
            self.originals[0].public.take()?,
            self.originals[1].public.take()?,
            self.originals[2].public.take()?,
            self.originals[3].public.take()?,
        ]))
    }

    /// Derives public TLS digest DATA from the same captured original bytes.
    pub fn public_tls_credentials(&self) -> Option<Credentials> {
        if !matches!(self.role, InitialRole::PublicTls) || self.failure().is_some() {
            return None;
        }
        let first = self.originals[0].public.as_ref()?;
        let bytes = self.bytes()?;
        Some(Credentials {
            path: first.path.clone(), uid: first.uid,
            directory_identity: first.directory_identity,
            digests: std::array::from_fn(|index| Sha256::digest(bytes[index]).into()),
        })
    }

    // Only fixed wrappers with their own complete semantic success call this.
    // Native positivity is checked again before disposing the actual proof
    // descriptors and readback buffers. Negative or interrupted owners cannot
    // obtain this peak reuse, and the once-only holder can never be rearmed.
    /// Retires native proof files and scratch after all native posts complete.
    ///
    /// # Errors
    /// Refuses an unsafe, missing, changed, failed, or already closed fixed
    /// credential observation; it does not confer role or receiving authority.
    pub fn settle_successful_native_once(&mut self) -> Result<(), ()> {
        if self.settled || self.failure().is_some()
            || !matches!(self.capture, Some(Ok(())))
            || !matches!(self.initial_post, Some(Ok(())))
            || !matches!(self.final_post, Some(Ok(())))
        {
            return Err(());
        }
        self.settled = true;
        for original in &mut self.originals {
            drop(original.read.file.take());
            drop(original.read.bytes.take());
            drop(original.public.take());
        }
        for slot in &mut self.ancestors.slots {
            drop(slot.descriptor.take());
        }
        for post in &mut self.readbacks {
            for slot in &mut post.ancestors.slots {
                drop(slot.descriptor.take());
            }
            for slot in &mut post.named {
                drop(slot.file.take());
                drop(slot.bytes.take());
            }
            for bytes in &mut post.original_bytes {
                drop(bytes.take());
            }
        }
        Ok(())
    }

    /// Borrows the earliest retained capture or initial-post cause.
    pub fn capture_failure(&self) -> Option<&ControllerNixPublicCredentialErrorV1> {
        self.capture.as_ref().and_then(|result| result.as_ref().err())
            .or_else(|| self.initial_post.as_ref().and_then(|result| result.as_ref().err()))
    }

    /// Borrows the retained final-post or reentry cause.
    pub fn post_failure(&self) -> Option<&ControllerNixPublicCredentialErrorV1> {
        self.final_post.as_ref().and_then(|result| result.as_ref().err())
            .or(self.reentry.as_ref())
    }

    /// Borrows the earliest retained native or state-refusal cause.
    pub fn failure(&self) -> Option<&ControllerNixPublicCredentialErrorV1> {
        self.capture_failure().or_else(|| self.post_failure())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::read_opened_credential;
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    #[test]
    fn real_failed_read_keeps_the_original_file_and_prevents_positive_disposal() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("credential");
        let mut file = std::fs::OpenOptions::new()
            .write(true).create_new(true).mode(0o600).open(path).unwrap();
        std::io::Write::write_all(&mut file, b"pin").unwrap();
        let descriptor = file.as_raw_fd();
        let mut bytes = None;
        let cause = read_opened_credential(
            &mut file, &mut bytes, rustix::process::geteuid().as_raw(), 64,
        ).unwrap_err();
        assert!(std::error::Error::source(&cause).is_some());

        // This is a real native prefix, not protected startup/C admission.
        let mut owner = ControllerInitialCredentialCustodyV1::public_tls();
        owner.originals[0].read.file = Some(file);
        owner.originals[0].read.bytes = bytes;
        owner.capture = Some(Err(cause));
        let first = owner.capture_failure().unwrap() as *const _;

        assert!(owner.settle_successful_native_once().is_err());
        owner.reentry = Some(credential_state_rejected());

        assert_eq!(owner.failure().unwrap() as *const _, first);
        assert_eq!(owner.originals[0].read.file.as_ref().unwrap().as_raw_fd(), descriptor);
        assert!(owner.originals[0].read.file.as_ref().unwrap().metadata().is_ok());
        assert!(owner.originals[0].read.bytes.is_some());
    }
}
