//! Retains scoped signed file selection across an external backing preparation.
//!
//! Native realizers can prepare verified kernel backing without first allocating
//! the file's complete plaintext. The repository retains its private witnesses
//! and closes the operation with a fresh ordinary authorization check before
//! the caller may disclose the prepared result.

use super::{Error, Repository, read::FileReadMetadata};
use crate::{
    guard::{AuthorizedSnapshot, Guard, SnapshotPathHead},
    store::{Clock, LocalFs, Store},
};
use terrane_format::{identity::Digest, surface::View, tree_format::ContentRef};

/// Retains an exact file selection until its external preparation is authorized.
///
/// Only the repository constructs this value, after ordinary scoped Read,
/// signed history, provenance trust and domain checks. Its accessors disclose
/// only the selected file's metadata, never credentials, history witnesses or
/// sibling entries. No object body is fetched by construction.
///
/// A trusted realizer may use this selection to prepare native backing, but must
/// call [`Self::finish`] successfully before returning that backing to its
/// consumer. Dropping this value does not acknowledge authorization or release
/// any physical work the realizer already accepted. A successful finish grants
/// no enduring Read, exposure lease or native readiness.
#[must_use = "Prepared backing must remain private until finish succeeds."]
pub struct PreparedFileRead<'repository, S, C> {
    guard: &'repository Guard<S, C>,
    snapshot: AuthorizedSnapshot,
    head: SnapshotPathHead,
    absolute: Vec<u8>,
    content: ContentRef,
    size: u64,
}

impl<S: Store, C: Clock> PreparedFileRead<'_, S, C> {
    /// Returns the exact immutable signed commit selected for this operation.
    pub fn commit(&self) -> Digest {
        self.snapshot.commit.identity()
    }

    /// Returns the canonical commit root containing the selected file.
    pub const fn root(&self) -> Digest {
        self.snapshot.evidence.root
    }

    /// Borrows the selected file's absolute path within the commit root.
    pub fn path(&self) -> &[u8] {
        &self.absolute
    }

    /// Borrows the effective physical domain checked by the repository guard.
    pub fn storage_domain(&self) -> &str {
        &self.snapshot.storage_domain
    }

    /// Returns the exact typed inline or manifest reference from signed metadata.
    pub const fn content(&self) -> ContentRef {
        self.content
    }

    /// Returns the selected file's complete logical plaintext size.
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// Rechecks current scoped Read after backing preparation and before disclosure.
    ///
    /// The complete live policy reference must equal the one captured at
    /// preparation. A selected historical commit remains independent of that
    /// current policy head. Returning to the same commit under a later reference
    /// sequence cannot satisfy this closing check.
    ///
    /// # Errors
    /// Refuses changed policy heads, revoked or expired credentials, unavailable
    /// current authority, changed domain policy or lost selected-path trust.
    pub async fn finish(self) -> Result<(), Error> {
        self.head
            .authorize_path(self.guard, &self.snapshot, &self.absolute)
            .await?;
        Ok(())
    }
}

impl<S, C, F> Repository<S, C, F>
where
    S: Store + Sync,
    C: Clock + Sync,
    F: LocalFs + Sync,
{
    /// Selects one authorized file without content reads or sibling disclosure.
    ///
    /// This uses the same signed file selection as [`Self::read_file`], including
    /// view subtrees, provenance trust and immutable commit selection. Native
    /// realizers can prepare whole-file backing using the returned metadata and
    /// then finish its authorization, without a preceding whole-plaintext read.
    /// Only the requested file path needs Read; this does not require a grant
    /// for the entire root. Unknown view policies remain unavailable.
    ///
    /// # Errors
    /// Refuses malformed paths, unavailable or untrusted files, non-file entries,
    /// unregistered policies, missing current authority, denied scopes and failed
    /// signed metadata or domain validation. No file body is requested.
    pub async fn prepare_file_read(
        &self,
        view: &View,
        path: &[u8],
        token: &[u8],
        surface: &str,
    ) -> Result<PreparedFileRead<'_, S, C>, Error> {
        let FileReadMetadata {
            snapshot,
            absolute,
            content,
            size,
        } = self.file_read_metadata(view, path, token, surface).await?;
        let guard = self.coordinator.guard();
        let head = SnapshotPathHead::begin(guard, &snapshot, &absolute).await?;
        guard.check_read_storage(&snapshot, &absolute)?;

        Ok(PreparedFileRead {
            guard,
            snapshot,
            head,
            absolute,
            content,
            size,
        })
    }
}
