//! Captures Root's fixed independently installed public trust credentials.
//!
//! Both initial and final named readbacks use the existing retained credential
//! engine. No environment, caller path, key bytes or role selects this recipe.
//! The enclosing genuine Root original prepays this custody before any capture.

mod recurring;
pub use recurring::RootCurrentIssuerReadbackOriginalV1;

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};

use super::{
    CONTROLLER_SOURCE_TREE_SEED_ISSUER_NAME, PROJECT_AUTHORIZATION_ISSUER_NAME,
    ControllerNixPublicCredentialErrorV1, CredentialAncestors, CredentialReadSlot,
    CredentialReadback, CredentialResult, FixedCredentialDirectoryV1,
    OriginalControllerCredential, capture_fixed_credential_originals,
    credential_state_rejected, observe_fixed_credential_readback,
};

const NAMES: [&str; 2] = [
    CONTROLLER_SOURCE_TREE_SEED_ISSUER_NAME,
    PROJECT_AUTHORIZATION_ISSUER_NAME,
];
const MAXIMUM_BYTES: [u64; 2] = [80; 2];

/// Retains Root's fixed public issuer files and two complete readback flights.
///
/// A successful capture supplies bounded local DATA only. The enclosing Root
/// owner independently joins the same paid original, live policy records and
/// every semantic result before considering any current-cut authority.
pub struct RootCurrentIssuerCredentialCustodyV1 {
    originals: [OriginalControllerCredential; 2],
    ancestors: CredentialAncestors,
    readbacks: [CredentialReadback<2>; 2],
    capture: Option<CredentialResult<()>>,
    final_readback: Option<CredentialResult<()>>,
    reentry: Option<ControllerNixPublicCredentialErrorV1>,
    uid: Option<u32>,
}

impl RootCurrentIssuerCredentialCustodyV1 {
    /// Creates vacant fixed slots without IO or allocation.
    pub fn new() -> Self {
        Self {
            originals: std::array::from_fn(|_| OriginalControllerCredential {
                public: None,
                read: CredentialReadSlot::new(),
            }),
            ancestors: CredentialAncestors::new(),
            readbacks: std::array::from_fn(|_| CredentialReadback::new()),
            capture: None,
            final_readback: None,
            reentry: None,
            uid: None,
        }
    }

    /// Measures the fixed dominant carriers and all retained native FDs.
    pub fn dominant_demand() -> Option<ResourceVector> {
        // Original ancestry/files retain six FDs. Each of two independent named
        // readbacks retains four directory and two file FDs. Their original,
        // reread and named byte buffers are independently priced. The fixed
        // path/error carriers and service cgroup cover residual metadata.
        let buffers = 2u64.checked_mul(81)?.checked_mul(4)?.checked_mul(5)?;
        let memory = (std::mem::size_of::<Self>() as u64)
            .checked_add(buffers)?
            .checked_add(18 * 4096)?;
        Some(ResourceVector::ZERO
            .with(D::MemoryBytes, memory)
            .with(D::MetadataEntries, 18)
            .with(D::OpenFiles, 18)
            .with(D::OutputBytes, memory))
    }

    /// Captures the fixed pair and its initial named readback once.
    ///
    /// # Errors
    /// Returns a marker while retaining the original native or shape cause.
    pub fn capture_once(&mut self) -> Result<(), ()> {
        if self.capture.is_some() || self.reentry.is_some() {
            self.reentry.get_or_insert_with(credential_state_rejected);
            return Err(());
        }
        self.uid = Some(rustix::process::geteuid().as_raw());
        self.capture = Some((|| {
            let uid = self.uid.ok_or_else(credential_state_rejected)?;
            if uid != 0 {
                return Err(credential_state_rejected());
            }
            capture_fixed_credential_originals(
                FixedCredentialDirectoryV1::RootCurrent,
                uid,
                &NAMES,
                &MAXIMUM_BYTES,
                &mut self.originals,
                &mut self.ancestors,
            )?;
            observe_fixed_credential_readback(
                FixedCredentialDirectoryV1::RootCurrent,
                uid,
                &NAMES,
                &MAXIMUM_BYTES,
                &mut self.originals,
                &self.ancestors,
                &mut self.readbacks[0],
            )?;
            for original in &self.originals {
                if original.public.as_ref().map(|public| public.bytes().len()) != Some(80) {
                    return Err(credential_state_rejected());
                }
            }
            Ok(())
        })());
        if matches!(self.capture, Some(Ok(()))) {
            Ok(())
        } else {
            Err(())
        }
    }

    /// Retains one independent final readback of the same original files.
    ///
    /// # Errors
    /// Refuses incomplete capture, reentry, replacement or unsafe provenance.
    pub fn recheck_once(&mut self) -> Result<(), ()> {
        if !matches!(self.capture, Some(Ok(())))
            || self.final_readback.is_some()
            || self.reentry.is_some()
        {
            self.reentry.get_or_insert_with(credential_state_rejected);
            return Err(());
        }
        self.final_readback = Some(observe_fixed_credential_readback(
            FixedCredentialDirectoryV1::RootCurrent,
            self.uid.ok_or(())?,
            &NAMES,
            &MAXIMUM_BYTES,
            &mut self.originals,
            &self.ancestors,
            &mut self.readbacks[1],
        ));
        if matches!(self.final_readback, Some(Ok(()))) {
            Ok(())
        } else {
            Err(())
        }
    }

    /// Borrows successfully captured public DATA without transferring custody.
    pub fn bytes(&self) -> Option<[&[u8]; 2]> {
        if !matches!(self.capture, Some(Ok(()))) || self.failure().is_some() {
            return None;
        }
        Some([
            self.originals[0].public.as_ref()?.bytes(),
            self.originals[1].public.as_ref()?.bytes(),
        ])
    }

    /// Borrows the original capture cause before later post failures.
    pub fn capture_failure(&self) -> Option<&ControllerNixPublicCredentialErrorV1> {
        self.capture.as_ref().and_then(|result| result.as_ref().err())
    }

    /// Borrows final readback or reentry debt without resampling.
    pub fn post_failure(&self) -> Option<&ControllerNixPublicCredentialErrorV1> {
        self.final_readback.as_ref().and_then(|result| result.as_ref().err())
            .or(self.reentry.as_ref())
    }

    /// Borrows the earliest retained local credential cause.
    pub fn failure(&self) -> Option<&ControllerNixPublicCredentialErrorV1> {
        self.capture_failure().or_else(|| self.post_failure())
    }
}


pub const ROOT_OWNERSHIP_POLICY_MAXIMUM_BYTES_V1: usize = 64 * 1024;
const OWNERSHIP_NAMES: [&str; 2] = ["ownership-lease-policy.cbor", "ownership-lease-public-key"];
const OWNERSHIP_MAXIMUM_BYTES: [u64; 2] = [ROOT_OWNERSHIP_POLICY_MAXIMUM_BYTES_V1 as u64, 32];

/// Keeps Root's own fixed public Ownership trust files and both named readbacks.
///
/// This selects neither a secret issuer key nor Controller credential custody.
/// The same genuine Root interval prepays it before the first native operation.
pub struct RootCurrentOwnershipCredentialCustodyV1 {
    originals: [OriginalControllerCredential; 2],
    ancestors: CredentialAncestors,
    readbacks: [CredentialReadback<2>; 2],
    capture: Option<CredentialResult<()>>,
    final_readback: Option<CredentialResult<()>>,
    reentry: Option<ControllerNixPublicCredentialErrorV1>,
    uid: Option<u32>,
    entered: bool,
}

impl RootCurrentOwnershipCredentialCustodyV1 {
    /// Creates empty fixed native destinations without IO or authority.
    pub fn new() -> Self {
        Self {
            originals: std::array::from_fn(|_| OriginalControllerCredential {
                public: None, read: CredentialReadSlot::new(),
            }),
            ancestors: CredentialAncestors::new(),
            readbacks: std::array::from_fn(|_| CredentialReadback::new()),
            capture: None, final_readback: None, reentry: None, uid: None, entered: false,
        }
    }

    /// Rechecks this fixed native recipe and retains its original refusal.
    pub fn dominant_demand() -> Option<ResourceVector> {
        let bytes = (ROOT_OWNERSHIP_POLICY_MAXIMUM_BYTES_V1 as u64).checked_add(32 + 2)?;
        let buffers = bytes.checked_mul(4)?.checked_mul(5)?;
        let memory = (std::mem::size_of::<Self>() as u64).checked_mul(2)?
            .checked_add(buffers)?.checked_add(18 * 4096)?;
        // Six original ancestry/files plus two independently resident six-FD
        // readbacks; 64 actual fixed field/entry destinations cover both pairs.
        Some(ResourceVector::ZERO.with(D::MemoryBytes, memory)
            .with(D::OpenFiles, 18).with(D::MetadataEntries, 64)
            .with(D::OutputBytes, buffers))
    }

    /// Rechecks this fixed native recipe and retains its original refusal.
    ///
    /// # Errors
    /// Refuses an unsafe, missing, changed, failed, or already closed fixed
    /// credential observation; it does not confer role or receiving authority.
    pub fn capture_once(&mut self) -> Result<(), ()> {
        if self.entered || self.reentry.is_some() {
            self.reentry.get_or_insert_with(credential_state_rejected);
            return Err(());
        }
        self.entered = true;
        self.uid = Some(rustix::process::geteuid().as_raw());
        self.capture = Some((|| {
            let uid = self.uid.ok_or_else(credential_state_rejected)?;
            if uid != 0 { return Err(credential_state_rejected()); }
            capture_fixed_credential_originals(
                FixedCredentialDirectoryV1::RootCurrent, uid,
                &OWNERSHIP_NAMES, &OWNERSHIP_MAXIMUM_BYTES,
                &mut self.originals, &mut self.ancestors,
            )?;
            observe_fixed_credential_readback(
                FixedCredentialDirectoryV1::RootCurrent, uid,
                &OWNERSHIP_NAMES, &OWNERSHIP_MAXIMUM_BYTES,
                &mut self.originals, &self.ancestors, &mut self.readbacks[0],
            )?;
            if self.originals[1].public.as_ref().map(|public| public.bytes().len()) != Some(32) {
                return Err(credential_state_rejected());
            }
            Ok(())
        })());
        if matches!(self.capture, Some(Ok(()))) { Ok(()) } else { Err(()) }
    }

    // This independent post is owed after either entered capture outcome. A
    // partial ancestry/file causes the same shared engine to retain its refusal;
    // no replacement path or absent credential is promoted to a positive result.
    /// Rechecks this fixed native recipe and retains its original refusal.
    ///
    /// # Errors
    /// Refuses an unsafe, missing, changed, failed, or already closed fixed
    /// credential observation; it does not confer role or receiving authority.
    pub fn recheck_once(&mut self) -> Result<(), ()> {
        if !self.entered || self.final_readback.is_some() || self.reentry.is_some() {
            self.reentry.get_or_insert_with(credential_state_rejected);
            return Err(());
        }
        let uid = self.uid.ok_or(())?;
        self.final_readback = Some(observe_fixed_credential_readback(
            FixedCredentialDirectoryV1::RootCurrent, uid,
            &OWNERSHIP_NAMES, &OWNERSHIP_MAXIMUM_BYTES,
            &mut self.originals, &self.ancestors, &mut self.readbacks[1],
        ));
        if matches!(self.final_readback, Some(Ok(()))) { Ok(()) } else { Err(()) }
    }

    /// Borrows completed raw DATA from this same native custody owner.
    pub fn bytes(&self) -> Option<(&[u8], &[u8])> {
        if !matches!(self.capture, Some(Ok(()))) || self.failure().is_some() { return None; }
        Some((self.originals[0].public.as_ref()?.bytes(), self.originals[1].public.as_ref()?.bytes()))
    }

    /// Borrows the earliest retained capture or initial-post cause.
    pub fn capture_failure(&self) -> Option<&ControllerNixPublicCredentialErrorV1> {
        self.capture.as_ref().and_then(|result| result.as_ref().err())
    }

    /// Borrows the retained final-post or reentry cause.
    pub fn post_failure(&self) -> Option<&ControllerNixPublicCredentialErrorV1> {
        self.final_readback.as_ref().and_then(|result| result.as_ref().err()).or(self.reentry.as_ref())
    }

    /// Borrows the earliest retained native or state-refusal cause.
    pub fn failure(&self) -> Option<&ControllerNixPublicCredentialErrorV1> {
        self.capture_failure().or_else(|| self.post_failure())
    }
}
