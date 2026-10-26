//! Retains Root's dedicated secret and public pin through native signing posts.
//!
//! The same fixed ancestry, no-follow original and held/named readback engines
//! used by Controller Q04 retain zeroizing secret buffers. This custody exposes
//! raw DATA only; a genuine paid Root floor owner supplies issuance authority.

use super::*;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};

const NAMES: [&str; 2] = ["root-noapply-floor-signing", "root-noapply-floor-public"];
const WIDTHS: [u64; 2] = [80; 2];

/// Keeps the native first cause resident while refusing secret credential use.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("Root NoApply signing credential remains closed with its original")]
pub struct RootNoApplySigningCredentialClosedV2;

#[derive(Clone, Copy)]
enum First {
    Capture,
    Initial,
    Before,
    After,
    Reentry,
}

/// Owns both fixed credential originals and three distinct paired readbacks.
///
/// The enclosing genuine Root purpose must prepay this entire shape before
/// construction. No path, supplied key, callback or general signer is accepted.
#[must_use]
pub struct RootNoApplySigningCredentialOriginalV2 {
    originals: [OriginalControllerCredential; 2],
    ancestors: CredentialAncestors,
    readbacks: [CredentialReadback<2>; 3],
    entered: bool,
    first: Option<First>,
    capture: Option<CredentialResult<()>>,
    initial: Option<CredentialResult<()>>,
    before: Option<CredentialResult<()>>,
    after: Option<CredentialResult<()>>,
    reentry: Option<ControllerNixPublicCredentialErrorV1>,
}

impl RootNoApplySigningCredentialOriginalV2 {
    /// Constructs inert native destinations without opening or allocating.
    #[must_use]
    pub fn new() -> Self {
        Self {
            originals: std::array::from_fn(|_| OriginalControllerCredential {
                public: None,
                read: CredentialReadSlot::new(),
            }),
            ancestors: CredentialAncestors::new(),
            readbacks: std::array::from_fn(|_| CredentialReadback::new()),
            entered: false,
            first: None,
            capture: None,
            initial: None,
            before: None,
            after: None,
            reentry: None,
        }
    }

    /// Prices all retained original, initial, before-sign and owed-after prefixes.
    #[must_use]
    pub fn receiving_demand_v2() -> Option<ResourceVector> {
        // Four directory descriptors and both files remain resident for capture
        // and each independent post, including every failed native prefix.
        let namespace = 4_u64.checked_add(u64::try_from(NAMES.len()).ok()?)?;
        let files = namespace.checked_mul(4)?;
        let traffic = 81_u64
            .checked_mul(7)?
            .checked_mul(u64::try_from(NAMES.len()).ok()?)?;
        let buffers = traffic.checked_mul(4)?;
        let memory = u64::try_from(std::mem::size_of::<Self>())
            .ok()?
            .checked_mul(2)?
            .checked_add(files.checked_mul(4096)?)?
            .checked_add(buffers)?;
        Some(
            ResourceVector::ZERO
                .with(D::MemoryBytes, memory)
                .with(D::OpenFiles, files)
                .with(D::MetadataEntries, namespace)
                .with(D::OutputBytes, traffic),
        )
    }

    /// Captures the compiled Root secret/public pair and initial named post.
    ///
    /// # Errors
    /// Retains missing/unsafe/replaced/short/oversized secret or non-root caller
    /// failures. The independent initial post runs after entered capture failure.
    pub fn capture_once_v2(&mut self) -> Result<(), RootNoApplySigningCredentialClosedV2> {
        if self.entered {
            return self.refuse();
        }
        self.entered = true;
        self.capture = Some((|| {
            if rustix::process::geteuid().as_raw() != 0 {
                return Err(credential_state_rejected());
            }
            capture_fixed_credential_originals(
                FixedCredentialDirectoryV1::RootCurrent,
                0,
                &NAMES,
                &WIDTHS,
                &mut self.originals,
                &mut self.ancestors,
            )?;
            // Both the private seed and independently delivered public pin use
            // root-owned, singleton, immutable credential files.
            for original in &self.originals {
                let original = original
                    .public
                    .as_ref()
                    .ok_or_else(credential_state_rejected)?;
                if original.bytes().len() != 80
                    || original.file_identity.2 != 0
                    || original.file_identity.3 != 0
                    || original.file_identity.4 & 0o7777 != 0o400
                {
                    return Err(credential_state_rejected());
                }
            }
            Ok(())
        })());
        if !matches!(self.capture, Some(Ok(()))) {
            self.first.get_or_insert(First::Capture);
        }
        self.initial = Some(self.observe(0));
        if !matches!(self.initial, Some(Ok(()))) {
            self.first.get_or_insert(First::Initial);
        }
        self.require_positive()
    }

    /// Rechecks both fixed originals immediately before finite attestation signing.
    ///
    /// # Errors
    /// Retains changed original/name or earlier refusal and rejects repeat use.
    pub fn before_sign_once_v2(&mut self) -> Result<(), RootNoApplySigningCredentialClosedV2> {
        if self.before.is_some() || self.after.is_some() {
            return self.refuse();
        }
        self.require_positive()?;
        self.before = Some(self.observe(1));
        if !matches!(self.before, Some(Ok(()))) {
            self.first.get_or_insert(First::Before);
        }
        self.require_positive()
    }

    /// Finishes the independent owed after even following a failed capture/sign.
    ///
    /// # Errors
    /// Retains all reached native causes; rejects missing or repeated entry.
    pub fn finish_posts_once_v2(&mut self) -> Result<(), RootNoApplySigningCredentialClosedV2> {
        if !self.entered || self.after.is_some() {
            return self.refuse();
        }
        self.after = Some(self.observe(2));
        if !matches!(self.after, Some(Ok(()))) {
            self.first.get_or_insert(First::After);
        }
        self.require_positive()
    }

    /// Borrows captured secret DATA without supplying a signer or Root authority.
    #[must_use]
    pub fn bytes_v2(&self) -> Option<&[u8]> {
        self.require_positive().ok()?;
        Some(self.originals[0].public.as_ref()?.bytes())
    }

    /// Borrows the independently delivered public pin as comparison DATA.
    ///
    /// Presence supplies no Root, signing or receiving authority. The dedicated
    /// signing owner compares its canonical generation and key with the secret.
    #[must_use]
    pub fn public_bytes_v2(&self) -> Option<&[u8]> {
        self.require_positive().ok()?;
        Some(self.originals[1].public.as_ref()?.bytes())
    }

    /// Requires all finite signing readbacks before an upper artifact is released.
    ///
    /// # Errors
    /// Rejects an unpaid/partial/failed or incomplete native interval.
    pub fn require_complete_v2(&self) -> Result<(), RootNoApplySigningCredentialClosedV2> {
        self.require_positive()?;
        if matches!(self.before, Some(Ok(()))) && matches!(self.after, Some(Ok(()))) {
            Ok(())
        } else {
            Err(RootNoApplySigningCredentialClosedV2)
        }
    }

    /// Borrows the earliest retained native cause without exposing secret bytes.
    #[must_use]
    pub fn failure(&self) -> Option<&ControllerNixPublicCredentialErrorV1> {
        match self.first {
            Some(First::Capture) => self.capture.as_ref()?.as_ref().err(),
            Some(First::Initial) => self.initial.as_ref()?.as_ref().err(),
            Some(First::Before) => self.before.as_ref()?.as_ref().err(),
            Some(First::After) => self.after.as_ref()?.as_ref().err(),
            Some(First::Reentry) => self.reentry.as_ref(),
            None => None,
        }
    }

    fn observe(&mut self, index: usize) -> CredentialResult<()> {
        observe_fixed_credential_readback(
            FixedCredentialDirectoryV1::RootCurrent,
            0,
            &NAMES,
            &WIDTHS,
            &mut self.originals,
            &self.ancestors,
            &mut self.readbacks[index],
        )
    }

    #[cfg(test)]
    pub(super) fn fixture_owed_after_entered_v2(&self) -> bool {
        self.after.is_some()
    }

    fn require_positive(&self) -> Result<(), RootNoApplySigningCredentialClosedV2> {
        if matches!(self.capture, Some(Ok(())))
            && matches!(self.initial, Some(Ok(())))
            && self.failure().is_none()
        {
            Ok(())
        } else {
            Err(RootNoApplySigningCredentialClosedV2)
        }
    }

    fn refuse<T>(&mut self) -> Result<T, RootNoApplySigningCredentialClosedV2> {
        self.first.get_or_insert(First::Reentry);
        self.reentry.get_or_insert_with(credential_state_rejected);
        Err(RootNoApplySigningCredentialClosedV2)
    }
}

impl Default for RootNoApplySigningCredentialOriginalV2 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn earlier_reentry_cause_survives_later_owed_post_failure() {
        let mut original = RootNoApplySigningCredentialOriginalV2::new();
        original.entered = true;
        original.capture = Some(Ok(()));
        original.initial = Some(Ok(()));
        original.before = Some(Ok(()));

        assert!(original.before_sign_once_v2().is_err());
        let first = original.failure().unwrap() as *const _;
        original.after = Some(Err(credential_state_rejected()));
        original.first.get_or_insert(First::After);

        assert_eq!(original.failure().unwrap() as *const _, first);
        assert!(std::ptr::eq(
            original.failure().unwrap(),
            original.reentry.as_ref().unwrap()
        ));
        assert!(original.bytes_v2().is_none());
        assert!(original.public_bytes_v2().is_none());
        assert!(original.require_complete_v2().is_err());
    }
}
