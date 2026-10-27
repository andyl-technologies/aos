//! Retires original sealed bodies without leaving orphaned publication bindings.
//!
//! Binding removal precedes the final pending unlink. A crash in between keeps
//! an independently inspectable pending inode and its original retirement lease,
//! rather than an orphan binding that has no remaining body to reconcile.
//! A newly published canonical incarnation retains its shared binding.

use super::*;
use terrane_sdk::host::publication::PublicationState;

impl CommandOwner {
    /// Removes only checked private metadata before the original pending unlink.
    pub(super) async fn finish_sealed_binding(
        &mut self,
        descriptor: &Descriptor,
        claim: Option<&PublicationClaim>,
        expected: &File,
    ) -> io::Result<()> {
        let publisher = self
            .publisher
            .take()
            .ok_or_else(|| io::Error::other("native publisher unavailable"))?;
        let (mut native, mut state) = publisher.into_parts();
        let result = async {
            let current = native.inspect_pending_sealed(descriptor)?;
            let original = expected.metadata()?;
            let actual = current.metadata()?;
            if (original.dev(), original.ino()) != (actual.dev(), actual.ino()) {
                return Err(invalid("final retirement changed original pending inode"));
            }

            if let Some(claim) = claim
                && native.existing_canonical_identity(claim)?.is_none()
            {
                let path = state.inner.binding_record_path(claim);
                state.repair.capture(&path)?;
                match state.inner.binding(claim).await? {
                    Some(binding) => {
                        if crate::verity::measure(expected)? != binding {
                            return Err(invalid("retirement binding differs from original seal"));
                        }
                        state.repair.remove(&path)?;
                    }
                    // A previous accepted attempt may have removed the record
                    // before failing its directory sync or final pending unlink.
                    None => state.repair.synchronize_absence(&path)?,
                }
            }

            native.finish_pending_sealed(descriptor, expected)
        }
        .await;
        self.publisher = Some(Publisher::new(native, state));
        result
    }
}
