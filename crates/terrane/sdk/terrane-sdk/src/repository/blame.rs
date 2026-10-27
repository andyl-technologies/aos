//! Projects entry introduction and merge acceptance from verified signed history.
//!
//! Results contain descriptive claims, never embedded token chains or raw tree
//! witnesses. Current path authority is checked again before disclosure.

use std::collections::{BTreeMap, BTreeSet};

use terrane_format::{
    identity::Digest,
    provenance::VerifiedCommit,
    refs::{CommitSource, PrincipalKind},
    surface::View,
};

use super::{Error, Repository};
use crate::store::{Clock, LocalFs, Store};

/// Describes signed entry provenance without exposing embedded credentials.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntryProvenance {
    /// Identity of the complete signed commit supplying these claims.
    pub commit: Digest,
    /// Advisory Unix seconds asserted by the signer.
    pub timestamp: u64,
    /// Issuer authenticating the committing principal.
    pub issuer: String,
    /// Identifier of the authorizing token, without its contents.
    pub token_id: [u8; 16],
    /// Authenticated principal that signed this commit.
    pub subject: String,
    /// Principal category authenticated by the issuer.
    pub kind: PrincipalKind,
    /// Optional authenticated workload identity.
    pub workload_identity: Option<String>,
    /// Process descriptor asserted by the committer.
    pub process: String,
    /// Advisory observation time asserted by the signer.
    pub observed_at: u64,
    /// Writer fencing epoch bound into the signature.
    pub writer_epoch: u64,
    /// Recorded way in which the tree was produced.
    pub source: CommitSource,
}

impl EntryProvenance {
    fn from_verified(verified: &VerifiedCommit) -> Self {
        let commit = verified.commit();
        let provenance = &commit.provenance;
        Self {
            commit: verified.identity(),
            timestamp: commit.timestamp,
            issuer: provenance.issuer.clone(),
            token_id: provenance.token_id,
            subject: provenance.subject.clone(),
            kind: provenance.kind,
            workload_identity: provenance.workload_identity.clone(),
            process: provenance.process.clone(),
            observed_at: provenance.observed_at,
            writer_epoch: provenance.writer_epoch,
            source: provenance.source,
        }
    }
}

/// Records one authorized entry's content introduction and merge acceptance.
///
/// Metadata-only edits can preserve the original content introduction. These
/// observations grant no enduring authority to read a commit or its siblings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntryBlame {
    /// Exact immutable view selected for this observation.
    pub view_commit: Digest,
    /// Commit that actually introduced the entry's current content identity.
    pub introduction: EntryProvenance,
    /// Merge commits carrying that identity, in parent-before-child order.
    ///
    /// Independent branches follow signed parent order. Unrelated merge
    /// commits and merge commits introducing different content are excluded.
    pub fold_chain: Vec<EntryProvenance>,
}

impl<S, C, F> Repository<S, C, F>
where
    S: Store + Sync,
    C: Clock + Sync,
    F: LocalFs + Sync,
{
    /// Resolves an entry's introducing commit and actual merge carrying history.
    ///
    /// The path is relative to the selected view subtree. Signed canonical
    /// metadata and provenance trust are checked without reading object bodies.
    /// A fresh current-policy check closes the operation before any claims are
    /// returned. Embedded tokens, sibling entries and commit messages remain
    /// private to repository verification.
    ///
    /// # Errors
    /// Refuses invalid or absent paths, unknown policies, denied or expired
    /// authority, untrusted provenance, ambiguous introduction, incomplete
    /// carrying history and changed current authorization.
    pub async fn blame(
        &self,
        view: &View,
        path: &[u8],
        token: &[u8],
        surface: &str,
    ) -> Result<EntryBlame, Error> {
        let (snapshot, absolute) = self.entry_read_metadata(view, path, token, surface).await?;
        let (location, _) = snapshot
            .history
            .locate(snapshot.commit.identity(), &absolute[1..])
            .map_err(|_| Error::Absent)?;
        let introducing = snapshot
            .history
            .introducing_commit(&location)
            .map_err(|_| Error::Denied)?;
        let introduction = snapshot.history.commit(&introducing).ok_or(Error::Denied)?;
        let carrying = snapshot
            .history
            .provenance_walk(&location)
            .map_err(|_| Error::Denied)?;
        let merges = carrying
            .into_iter()
            .filter(|record| record.identity() != introducing && record.commit().parents.len() > 1)
            .map(|record| (record.identity(), record))
            .collect::<BTreeMap<_, _>>();

        // Digest order and signer timestamps do not establish ancestry. Walk
        // signed parents, emitting only the independently checked carrying set.
        let mut pending = vec![(snapshot.commit.identity(), false)];
        let mut seen = BTreeSet::new();
        let mut fold_chain = Vec::new();
        while let Some((identity, finishing)) = pending.pop() {
            if finishing {
                if let Some(record) = merges.get(&identity) {
                    fold_chain.push(EntryProvenance::from_verified(record));
                }
                continue;
            }
            if !seen.insert(identity) {
                continue;
            }
            // Disclosure boundaries can deliberately omit private parents.
            // The carrying set above already requires complete public evidence.
            let Some(record) = snapshot.history.commit(&identity) else {
                continue;
            };
            pending.push((identity, true));
            pending.extend(
                record
                    .commit()
                    .parents
                    .iter()
                    .rev()
                    .map(|parent| (*parent, false)),
            );
        }
        if fold_chain.len() != merges.len() {
            return Err(Error::Denied);
        }
        let result = EntryBlame {
            view_commit: snapshot.commit.identity(),
            introduction: EntryProvenance::from_verified(introduction),
            fold_chain,
        };
        self.coordinator
            .guard()
            .authorize_snapshot_path(&snapshot, &absolute)
            .await?;
        Ok(result)
    }
}
