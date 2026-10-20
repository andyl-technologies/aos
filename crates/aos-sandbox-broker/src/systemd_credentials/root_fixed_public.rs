//! Shares the existing Root fixed public credential capture and native posts.
//!
//! This file uses the existing fixed credential reader without opening either
//! endpoint's secret keys. A local manifest is trust DATA only after its real
//! Root caller has paid capture and completed its independent currentness posts.

use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use super::{
    ControllerNixPublicCredentialErrorV1, CredentialAncestors, CredentialReadSlot,
    CredentialReadback, CredentialResult, FixedCredentialDirectoryV1,
    OriginalControllerCredential, capture_fixed_credential_originals,
    credential_state_rejected, observe_fixed_credential_readback,
};


/// Retains the fixed public manifest and both independently named readbacks.
///
/// The enclosing Root original must admit the complete fixed demand before
/// construction or capture. No caller path, supplied key or session selects it.
pub(super) struct RootFixedPublicCredentialCustodyV1<const N: usize> {
    originals: [OriginalControllerCredential; N],
    ancestors: CredentialAncestors,
    readbacks: [CredentialReadback<N>; 2],
    capture: Option<CredentialResult<()>>,
    final_readback: Option<CredentialResult<()>>,
    reentry: Option<ControllerNixPublicCredentialErrorV1>,
    uid: Option<u32>,
    entered: bool,
}

impl<const N: usize> RootFixedPublicCredentialCustodyV1<N> {
    /// Creates empty fixed native destinations without IO or authority.
    pub(super) fn new() -> Self {
        Self {
            originals: std::array::from_fn(|_| OriginalControllerCredential {
                public: None, read: CredentialReadSlot::new(),
            }),
            ancestors: CredentialAncestors::new(),
            readbacks: std::array::from_fn(|_| CredentialReadback::new()),
            capture: None, final_readback: None, reentry: None, uid: None, entered: false,
        }
    }

    /// Measures the dominant bounded buffers and three resident native prefixes.
    pub(super) fn dominant_demand(maximum_bytes: &[u64; N]) -> Option<ResourceVector> {
        // Original and two independent readbacks each retain four rooted
        // directories and this one public file. All byte/reread buffers are
        // bounded by the same exact existing manifest format.
        let buffers = maximum_bytes.iter().try_fold(0_u64, |total, maximum|
            total.checked_add(maximum.checked_add(1)?))?.checked_mul(4)?.checked_mul(5)?;
        let namespace = 4_u64.checked_add(u64::try_from(N).ok()?)?;
        let files = namespace.checked_mul(3)?;
        let memory = (std::mem::size_of::<Self>() as u64).checked_mul(2)?
            .checked_add(buffers)?.checked_add(files.checked_mul(4096)?)?;
        Some(ResourceVector::ZERO.with(D::MemoryBytes, memory)
            // The three native readbacks retain distinct descriptors over the
            // same rooted namespace. Their copies occupy Memory and OpenFiles.
            .with(D::OpenFiles, files).with(D::MetadataEntries, namespace)
            .with(D::OutputBytes, buffers))
    }

    /// Rechecks this fixed native recipe and retains its original refusal.
    ///
    /// # Errors
    /// Refuses an unsafe, missing, changed, failed, or already closed fixed
    /// credential observation; it does not confer role or receiving authority.
    pub(super) fn capture_once(&mut self, names: &[&'static str; N], maximum_bytes: &[u64; N]) -> Result<(), ()> {
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
                names, maximum_bytes,
                &mut self.originals, &mut self.ancestors,
            )?;
            observe_fixed_credential_readback(
                FixedCredentialDirectoryV1::RootCurrent, uid,
                names, maximum_bytes,
                &mut self.originals, &self.ancestors, &mut self.readbacks[0],
            )?;
            for (original, maximum) in self.originals.iter().zip(maximum_bytes) {
                if original.public.as_ref().map(|public| u64::try_from(public.bytes().len()).ok()) != Some(Some(*maximum)) {
                    return Err(credential_state_rejected());
                }
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
    pub(super) fn recheck_once(&mut self, names: &[&str; N], maximum_bytes: &[u64; N]) -> Result<(), ()> {
        if !self.entered || self.final_readback.is_some() || self.reentry.is_some() {
            self.reentry.get_or_insert_with(credential_state_rejected);
            return Err(());
        }
        let uid = self.uid.ok_or(())?;
        self.final_readback = Some(observe_fixed_credential_readback(
            FixedCredentialDirectoryV1::RootCurrent, uid,
            names, maximum_bytes,
            &mut self.originals, &self.ancestors, &mut self.readbacks[1],
        ));
        if matches!(self.final_readback, Some(Ok(()))) { Ok(()) } else { Err(()) }
    }

    /// Borrows completed raw DATA from this same native custody owner.
    pub(super) fn bytes(&self, index: usize) -> Option<&[u8]> {
        if !matches!(self.capture, Some(Ok(()))) || self.failure().is_some() { return None; }
        Some(self.originals.get(index)?.public.as_ref()?.bytes())
    }

    /// Borrows the earliest retained capture or initial-post cause.
    pub(super) fn capture_failure(&self) -> Option<&ControllerNixPublicCredentialErrorV1> {
        self.capture.as_ref().and_then(|result| result.as_ref().err())
    }

    /// Borrows the retained final-post or reentry cause.
    pub(super) fn post_failure(&self) -> Option<&ControllerNixPublicCredentialErrorV1> {
        self.final_readback.as_ref().and_then(|result| result.as_ref().err()).or(self.reentry.as_ref())
    }

    /// Borrows the earliest retained native or state-refusal cause.
    pub(super) fn failure(&self) -> Option<&ControllerNixPublicCredentialErrorV1> {
        self.capture_failure().or_else(|| self.post_failure())
    }
}
