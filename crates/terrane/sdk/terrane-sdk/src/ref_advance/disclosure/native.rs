//! Preloads untrusted payload before genuine paired disclosure authority capture.
//!
//! Early reads use the ordinary source guard and publish no bytes. The paired
//! producer subsequently verifies the identical physical source, immutable
//! selection, content and effective domain before minting any certificate.

use super::{DisclosureCommitRequest, DisclosureCommitSelection};
use crate::bucket::{BucketBinding, FileBucket};
use crate::guard::Guard;
use crate::ref_advance::{AdvanceError, Coordinator, StagedUpload, WriterSession};
use crate::store::{Clock, ContentStore, ContentValidator, LocalFs, StoreFailure};
use terrane_format::identity::{Digest, IdentityKind, TERRANE_V1};
use terrane_format::tree_format::{ContentRef, EntryKind};

/// Carries checked-read bytes as untrusted inputs, never publication authority.
pub(crate) struct PreloadedSelection {
    /// Exact caller-selected source and destination occurrence inputs.
    pub(crate) selector: DisclosureCommitSelection,
    /// Actual configured source association, requiring separate held qualification.
    pub(crate) physical_source: crate::guard::OriginalAuthority,
    /// Authenticated historical introducer of the selected entry.
    pub(crate) introducer: Digest,
    /// Physical containing root of the selected source occurrence.
    pub(crate) root: Digest,
    /// Root-local path of the selected source entry.
    pub(crate) path: Vec<u8>,
    /// Effective domain under the source view's retained interpretation.
    pub(crate) domain: String,
    /// Selected file identity and plaintext length, absent for non-file entries.
    pub(crate) content: Option<(ContentRef, u64)>,
    /// Ordinary staged encoded payloads requiring independent destination validation.
    pub(crate) uploads: Vec<StagedUpload>,
}

impl<F, B, V, C> crate::repository::Repository<FileBucket<F, B, V>, C, F>
where
    F: LocalFs + BucketBinding + Sync,
    B: Clock + BucketBinding + Sync,
    V: ContentValidator + BucketBinding + Sync,
    C: Clock + Sync,
    FileBucket<F, B, V>: Sync,
{
    /// Publishes selected source entries through independently checked native factories.
    ///
    /// The source repository supplies current Read authority and dedicated
    /// disclosure signing. The destination supplies current Commit authority;
    /// original authoring context stays independently bound to retained controls.
    ///
    /// # Errors
    /// Preserves invalid provenance or payload, stale heads and epochs, denied
    /// current authority, conflicting retained controls, unsupported projections,
    /// expired operation timing and indeterminate selected-publication failures.
    pub async fn commit_disclosure<D: Clock + Sync>(
        &self,
        source: &crate::repository::Repository<FileBucket<F, B, V>, D, F>,
        session: &mut WriterSession,
        request: DisclosureCommitRequest,
    ) -> Result<terrane_format::refs::RefRecord, crate::repository::Error> {
        self.coordinator()
            .advance_disclosure(source.coordinator().guard(), session, request)
            .await
            .map_err(crate::repository::Error::Advance)
    }
}

impl<F, B, V, C> Coordinator<FileBucket<F, B, V>, C, F>
where
    F: LocalFs + BucketBinding + Sync,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    /// Publishes a complete certified disclosure under both actual native guards.
    ///
    /// Source Read and destination Commit remain independent current decisions.
    /// Dedicated role signing and original authoring authority are retained under
    /// separate protected controls; reopening needs only the destination records.
    ///
    /// # Errors
    /// Rejects unrelated principals, stale whole heads or epochs, denied current
    /// roots, invalid history or payload, unsupported raw projections, conflicting
    /// protected imports, expired timing and uncertain selected publication.
    pub async fn advance_disclosure<D: Clock>(
        &self,
        source: &Guard<FileBucket<F, B, V>, D>,
        session: &mut WriterSession,
        request: DisclosureCommitRequest,
    ) -> Result<terrane_format::refs::RefRecord, AdvanceError> {
        if request.selections.is_empty() || session.fenced {
            return Err(crate::guard::invalid().into());
        }
        let started = self.guard().clock().monotonic();
        let mut selections = Vec::with_capacity(request.selections.len());
        for selector in request.selections {
            let mut selection = preload(source, selector, &request.proposal.surface).await?;
            // Source reads validate the exact immutable encoding under its own
            // registered profile. Staging supplies the destination's validation
            // parameters; it never imports the source's random profile seed.
            // Actual destination validation still checks every encoded payload.
            for upload in &mut selection.uploads {
                if let StagedUpload::Chunk { profile, .. } = upload {
                    *profile = self.guard().config().chunk_profile.clone();
                }
            }
            selections.push(selection);
            self.check_time(started)?;
        }
        crate::selected_bridge::native_guard::disclosure::publish(
            self,
            source,
            session,
            request.proposal,
            selections,
            started,
            self.timing,
        )
        .await
    }
}

async fn preload<F, B, V, C>(
    source: &Guard<FileBucket<F, B, V>, C>,
    selector: DisclosureCommitSelection,
    surface: &str,
) -> Result<PreloadedSelection, StoreFailure>
where
    F: LocalFs + BucketBinding + Sync,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    let physical_source = source.configured_original_authority()?;
    let snapshot = source
        .read_commit_snapshot(
            selector.source_commit,
            &selector.source_token,
            &selector.source_path,
            surface,
        )
        .await?;
    let relative = selector
        .source_path
        .strip_prefix(b"/")
        .ok_or_else(crate::guard::invalid)?;
    let (location, _) = snapshot
        .history
        .locate(selector.source_commit, relative)
        .map_err(|_| crate::guard::invalid())?;
    let entry = snapshot
        .history
        .entry(&location)
        .map_err(|_| crate::guard::invalid())?;
    let layers = snapshot
        .evidence
        .policy_path(&selector.source_path, source.config().min_chunk_size)?;
    let layers = layers
        .iter()
        .map(
            |(properties, overrides)| terrane_format::properties::RootLayer {
                properties,
                overrides,
            },
        )
        .collect::<Vec<_>>();
    let effective = snapshot
        .interpretation
        .resolve(&layers, source.defaults_for(&snapshot.evidence))
        .map_err(|_| crate::guard::invalid())?;
    let domain = crate::guard::domain_label(&effective)
        .map_err(|_| crate::guard::invalid())?
        .to_owned();
    let content = match entry.kind {
        EntryKind::File { content, size, .. } => Some((content, size)),
        EntryKind::Directory { .. } | EntryKind::Symlink { .. } => None,
        _ => return Err(crate::guard::invalid()),
    };
    let mut uploads = Vec::new();
    if let Some((content, size)) = content {
        // This verifies exact entry scope, decoded chunks, complete manifests,
        // dictionary dependencies and current Read rights through the real guard.
        let dictionaries = source
            .read_content_dictionaries(&snapshot, &selector.source_path, content, size)
            .await?;
        // These are genuine stored envelopes in dependency order. The reader
        // verified each dictionary's plaintext identity and standalone-final
        // length; destination admission revalidates the actual encoded bytes.
        for (identity, encoded, declared_plaintext_len) in dictionaries {
            uploads.push(StagedUpload::Chunk {
                encoded,
                identity,
                declared_plaintext_len,
                position: crate::store::ChunkPosition::Final,
                profile: source.config().chunk_profile.clone(),
            });
        }
        let chunks = match content {
            ContentRef::Inline(digest) => vec![(digest, size)],
            ContentRef::Manifest(digest) => {
                let identity = TERRANE_V1
                    .from_digest(IdentityKind::Manifest, &digest)
                    .map_err(|_| crate::guard::invalid())?;
                source
                    .authorize_snapshot_path(&snapshot, &selector.source_path)
                    .await?;
                let bytes = source.store().get(&identity, None).await?;
                let manifest = terrane_format::manifest::Manifest::decode_verified(
                    &bytes,
                    &source.config().chunk_profile,
                    &identity,
                )
                .map_err(|_| crate::guard::invalid())?;
                if manifest.size != size {
                    return Err(crate::guard::invalid());
                }
                uploads.push(StagedUpload::Meta {
                    kind: IdentityKind::Manifest,
                    bytes,
                });
                manifest
                    .chunks
                    .into_iter()
                    .map(|chunk| (chunk.digest, chunk.length))
                    .collect()
            }
        };
        for (index, (digest, length)) in chunks.iter().enumerate() {
            source
                .authorize_snapshot_path(&snapshot, &selector.source_path)
                .await?;
            let identity = TERRANE_V1
                .from_digest(IdentityKind::Chunk, digest)
                .map_err(|_| crate::guard::invalid())?;
            let encoded = source.store().get(&identity, None).await?;
            uploads.push(StagedUpload::Chunk {
                encoded,
                identity,
                declared_plaintext_len: usize::try_from(*length)
                    .map_err(|_| crate::guard::invalid())?,
                position: if index + 1 == chunks.len() {
                    crate::store::ChunkPosition::Final
                } else {
                    crate::store::ChunkPosition::NonFinal
                },
                profile: source.config().chunk_profile.clone(),
            });
        }
        source
            .authorize_snapshot_path(&snapshot, &selector.source_path)
            .await?;
    }
    Ok(PreloadedSelection {
        introducer: snapshot
            .history
            .introducing_commit(&location)
            .map_err(|_| crate::guard::invalid())?,
        physical_source,
        root: location.root,
        path: location.path,
        domain,
        content,
        selector,
        uploads,
    })
}
