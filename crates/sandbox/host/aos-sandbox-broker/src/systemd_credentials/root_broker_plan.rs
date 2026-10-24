//! Retains Root's fixed public Controller broker-plan policy and native posts.
//!
//! This file uses the existing fixed credential reader without opening either
//! endpoint's secret keys. A local manifest is trust DATA only after its real
//! Root caller has paid capture and completed its independent currentness posts.

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use super::{
    ControllerNixPublicCredentialErrorV1, CredentialAncestors, CredentialReadSlot,
    CredentialReadback, CredentialResult, FixedCredentialDirectoryV1,
    OriginalControllerCredential, capture_fixed_credential_originals,
    credential_state_rejected, observe_fixed_credential_readback,
};

const CONTROLLER_NAMES: [&str; 3] = ["broker-plan-policy.cbor", "broker-plan-public-key", "broker-revocation-scope"];
const MOUNT_NAMES: [&str; 3] = [
    "mount-broker-plan-policy.cbor", "mount-broker-plan-public-key", "mount-broker-revocation-scope",
];

#[derive(Clone, Copy)]
enum Purpose { Controller, Mount }

impl Purpose {
    fn names(self) -> &'static [&'static str; 3] {
        match self {
            Self::Controller => &CONTROLLER_NAMES,
            Self::Mount => &MOUNT_NAMES,
        }
    }
}

const MAXIMUM_BYTES: [u64; 3] = [64 * 1024, 32, 16];

/// Retains the fixed public broker-plan triplet and both independently named readbacks.
///
/// The enclosing Root original must admit the complete fixed demand before
/// construction or capture. No caller path, supplied key or session selects it.
pub struct RootCurrentBrokerPlanCredentialCustodyV1 {
    purpose: Purpose,
    originals: [OriginalControllerCredential; 3],
    ancestors: CredentialAncestors,
    readbacks: [CredentialReadback<3>; 2],
    capture: Option<CredentialResult<()>>,
    final_readback: Option<CredentialResult<()>>,
    reentry: Option<ControllerNixPublicCredentialErrorV1>,
    uid: Option<u32>,
    entered: bool,
}

impl RootCurrentBrokerPlanCredentialCustodyV1 {
    /// Creates empty fixed native destinations without IO or authority.
    pub fn new() -> Self {
        Self::new_purpose(Purpose::Controller)
    }

    /// Creates inert custody for Mount's independent public policy/key/scope.
    ///
    /// Capture and both owed readbacks use the same fixed Root credential
    /// engine. This chooses no supplied path, key, account or verification grant.
    #[must_use]
    pub fn mount_v2() -> Self {
        Self::new_purpose(Purpose::Mount)
    }

    fn new_purpose(purpose: Purpose) -> Self {
        Self {
            purpose,
            originals: std::array::from_fn(|_| OriginalControllerCredential {
                public: None, read: CredentialReadSlot::new(),
            }),
            ancestors: CredentialAncestors::new(),
            readbacks: std::array::from_fn(|_| CredentialReadback::new()),
            capture: None, final_readback: None, reentry: None, uid: None, entered: false,
        }
    }

    /// Measures the dominant bounded buffers and three resident native prefixes.
    pub fn dominant_demand() -> Option<ResourceVector> {
        // Original and two independent readbacks each retain four rooted
        // directories and three public files. The existing credential-format
        // ceilings bound all original and reread byte buffers.
        let buffers = (64 * 1024 + 32 + 16 + 3_u64).checked_mul(4)?.checked_mul(5)?;
        let memory = u64::try_from(std::mem::size_of::<Self>()).ok()?.checked_mul(2)?
            .checked_add(buffers)?.checked_add(21 * 4096)?;
        Some(ResourceVector::ZERO.with(D::MemoryBytes, memory)
            // Three native prefixes retain distinct FDs for the same four
            // rooted directories and three names, counted once as namespace.
            .with(D::OpenFiles, 21).with(D::MetadataEntries, 7)
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
                self.purpose.names(), &MAXIMUM_BYTES,
                &mut self.originals, &mut self.ancestors,
            )?;
            observe_fixed_credential_readback(
                FixedCredentialDirectoryV1::RootCurrent, uid,
                self.purpose.names(), &MAXIMUM_BYTES,
                &mut self.originals, &self.ancestors, &mut self.readbacks[0],
            )?;
            if self.originals[1].public.as_ref().map(|public| public.bytes().len()) != Some(32)
                || self.originals[2].public.as_ref().map(|public| public.bytes().len()) != Some(16) {
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
            self.purpose.names(), &MAXIMUM_BYTES,
            &mut self.originals, &self.ancestors, &mut self.readbacks[1],
        ));
        if matches!(self.final_readback, Some(Ok(()))) { Ok(()) } else { Err(()) }
    }

    /// Borrows completed raw DATA from this same native custody owner.
    pub fn bytes(&self) -> Option<(&[u8], &[u8], &[u8])> {
        if !matches!(self.capture, Some(Ok(()))) || self.failure().is_some() { return None; }
        Some((self.originals[0].public.as_ref()?.bytes(),
            self.originals[1].public.as_ref()?.bytes(), self.originals[2].public.as_ref()?.bytes()))
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
