//! Keeps authenticated read witnesses private and rechecks live policy before reachable content I/O.

use terrane_core::auth::{self, Request, RequestRoot, Verb};
use terrane_core::codec::{Codec, parse_envelope};
use terrane_core::identity::{Digest, IdentityKind, TERRANE_V1};
use terrane_core::manifest::Manifest;
use terrane_core::properties::{self, RootLayer};
use terrane_core::provenance::{Preset, Selector, TrustContext, VerifiedCommit, VerifiedHistory};
use terrane_core::tree_format::{ContentRef, EntryKind};

use super::{Guard, HistoryObservation, TreeEvidence, denied, domain_label, invalid};
use crate::store::{Clock, Store, StoreErrorKind, StoreFailure};

/// Holds an authorized scoped target without exposing its private historical witnesses.
pub struct AuthorizedSnapshot {
    pub(crate) history: VerifiedHistory,
    pub(crate) commit: VerifiedCommit,
    pub(crate) evidence: TreeEvidence,
    pub(crate) scope: Vec<u8>,
    pub(crate) storage_domain: String,
    authority_reference: String,
    token: Vec<u8>,
    surface: String,
}

impl<S: Store, C: Clock> Guard<S, C> {
    /// Issues hash-read evidence only for the exact authenticated file selection.
    ///
    /// # Errors
    /// Denies current policy, scope, reachability or content validation failures.
    /// Root node bytes are excluded because they can reveal unauthorized siblings.
    pub async fn domain_content_access(
        &self,
        snapshot: &AuthorizedSnapshot,
        path: &[u8],
        content: ContentRef,
        size: u64,
    ) -> Result<crate::domain::DomainAccess, StoreFailure> {
        self.read_content(snapshot, path, content, size).await?;
        let mut identities = Vec::new();
        let chunks = match content {
            ContentRef::Inline(digest) => vec![digest],
            ContentRef::Manifest(digest) => {
                let identity = TERRANE_V1
                    .from_digest(IdentityKind::Manifest, &digest)
                    .map_err(|_| invalid())?;
                self.authorize_snapshot_path(snapshot, path).await?;
                let bytes = self.store().get(&identity, None).await?;
                let manifest =
                    Manifest::decode_verified(&bytes, &self.config().chunk_profile, &identity)
                        .map_err(|_| invalid())?;
                identities.push(identity);
                manifest
                    .chunks
                    .into_iter()
                    .map(|chunk| chunk.digest)
                    .collect()
            }
        };
        for digest in chunks {
            let identity = TERRANE_V1
                .from_digest(IdentityKind::Chunk, &digest)
                .map_err(|_| invalid())?;
            self.authorize_snapshot_path(snapshot, path).await?;
            let bytes = self.store().get(&identity, None).await?;
            if let Codec::ZstdDictionary(dictionary) =
                parse_envelope(&bytes).map_err(|_| invalid())?.codec
            {
                identities.push(
                    TERRANE_V1
                        .from_digest(IdentityKind::Chunk, &dictionary)
                        .map_err(|_| invalid())?,
                );
            }
            identities.push(identity);
        }
        self.authorize_snapshot_path(snapshot, path).await?;
        let access = self
            .domain_access(
                &snapshot.authority_reference,
                &snapshot.token,
                Verb::Read,
                path,
                &snapshot.surface,
            )
            .await?;
        if access.binding().domain != snapshot.storage_domain {
            return Err(denied(&snapshot.authority_reference, Verb::Read));
        }
        let relative = path.strip_prefix(b"/").ok_or_else(invalid)?;
        let (location, _) = snapshot
            .history
            .locate(snapshot.commit.identity(), relative)
            .map_err(|_| invalid())?;
        let occurrences = snapshot
            .evidence
            .occurrences(self.config().min_chunk_size)?;
        let occurrence = occurrences
            .iter()
            .find(|occurrence| {
                if occurrence.root != location.root {
                    return false;
                }
                let mut full = occurrence.path.clone();
                if full != b"/" {
                    full.push(b'/');
                }
                full.extend_from_slice(&location.path);
                full == path
            })
            .ok_or_else(invalid)?;
        let record = access.reference_record().cloned().ok_or_else(invalid)?;
        let selected = crate::domain::DomainAccess::authorized(
            crate::domain::DomainBinding {
                domain: snapshot.storage_domain.clone(),
                reference: snapshot.authority_reference.clone(),
                root: TERRANE_V1
                    .from_digest(IdentityKind::Node, &location.root)
                    .map_err(|_| invalid())?,
                path: occurrence.path.clone(),
            },
            Verb::Read,
            access.subject().to_owned(),
            *access.token_id(),
        )?
        .with_reference_record(record)
        .with_read_commit(snapshot.commit.identity());
        let mut access = selected.with_read_identities(identities.clone());
        for identity in identities {
            access = access.with_read_path(identity, path.to_vec())?;
        }
        Ok(access)
    }

    /// Authenticates the current ref target and its private scoped read witnesses.
    ///
    /// # Errors
    /// Denies unavailable current authority, invalid historical evidence, or a
    /// ref that changes while the snapshot is being established.
    pub async fn read_snapshot(
        &self,
        reference: &str,
        token: &[u8],
        path: &[u8],
        surface: &str,
    ) -> Result<AuthorizedSnapshot, StoreFailure> {
        let authorized = self
            .authorize(reference, token, Verb::Read, &[path.to_vec()], surface)
            .await?;
        let record = authorized
            .record()
            .ok_or_else(|| denied(reference, Verb::Read))?;
        let snapshot = self
            .snapshot(
                record.commit,
                reference.to_owned(),
                token,
                path,
                surface,
                HistoryObservation::default(),
            )
            .await?;
        let current = self
            .authorize(reference, token, Verb::Read, &[path.to_vec()], surface)
            .await?;
        if current.record() != Some(record) {
            return Err(denied(reference, Verb::Read));
        }
        Ok(snapshot)
    }

    /// Selects an exact immutable commit while checking a separate live policy authority.
    ///
    /// # Errors
    /// Denies missing or invalid target evidence, missing live policy authority,
    /// expired capabilities, and current ACL or domain restrictions.
    pub async fn read_commit_snapshot(
        &self,
        identity: Digest,
        token: &[u8],
        path: &[u8],
        surface: &str,
    ) -> Result<AuthorizedSnapshot, StoreFailure> {
        self.read_commit_snapshot_observed(
            identity,
            token,
            path,
            surface,
            HistoryObservation::default(),
        )
        .await
    }

    /// Selects an immutable commit and checks its separate current authority while held.
    ///
    /// # Errors
    /// Reports invalid history, protected evidence, current ACL/token denial, or storage failure.
    pub(crate) async fn read_commit_snapshot_observed(
        &self,
        identity: Digest,
        token: &[u8],
        path: &[u8],
        surface: &str,
        observation: HistoryObservation<'_>,
    ) -> Result<AuthorizedSnapshot, StoreFailure> {
        self.read_commit_snapshot_authorizations_observed(
            identity,
            token,
            path,
            surface,
            observation,
        )
        .await
        .map(|(snapshot, _)| snapshot)
    }

    /// Retains the exact successful requests from immutable snapshot authorization.
    ///
    /// # Errors
    /// Preserves canonical history, live ACL/token and protected storage failures.
    pub(super) async fn read_commit_snapshot_authorizations_observed(
        &self,
        identity: Digest,
        token: &[u8],
        path: &[u8],
        surface: &str,
        observation: HistoryObservation<'_>,
    ) -> Result<(AuthorizedSnapshot, Vec<super::AuthorizedRef>), StoreFailure> {
        // Commit selection is immutable. A separate current policy lookup
        // establishes live permission without changing the selected identity.
        let verified = self.verified_tree_observed(identity, observation).await?;
        let original = verified
            .commit
            .commit()
            .profile_pair
            .commit_context
            .as_ref()
            .ok_or_else(invalid)?
            .reference();
        let authority = self
            .config()
            .policy_authority
            .as_deref()
            .unwrap_or(original)
            .to_owned();
        self.snapshot_authorizations(identity, authority, token, path, surface, observation)
            .await
    }

    async fn snapshot(
        &self,
        identity: Digest,
        authority_reference: String,
        token: &[u8],
        path: &[u8],
        surface: &str,
        observation: HistoryObservation<'_>,
    ) -> Result<AuthorizedSnapshot, StoreFailure> {
        self.snapshot_authorizations(
            identity,
            authority_reference,
            token,
            path,
            surface,
            observation,
        )
        .await
        .map(|(snapshot, _)| snapshot)
    }

    async fn snapshot_authorizations(
        &self,
        identity: Digest,
        authority_reference: String,
        token: &[u8],
        path: &[u8],
        surface: &str,
        observation: HistoryObservation<'_>,
    ) -> Result<(AuthorizedSnapshot, Vec<super::AuthorizedRef>), StoreFailure> {
        let verified = self.verified_tree_observed(identity, observation).await?;
        let history = self
            .verified_history_observed(identity, observation)
            .await?;
        let policy_layers = verified
            .evidence
            .policy_path(path, self.config().min_chunk_size)?;
        let layers = policy_layers
            .iter()
            .map(|(properties, overrides)| RootLayer {
                properties,
                overrides,
            })
            .collect::<Vec<_>>();
        let policy = properties::resolve(&layers, self.defaults_for(&verified.evidence))
            .map_err(|_| invalid())?;
        let domain = domain_label(&policy).map_err(|_| invalid())?.to_owned();
        if domain != self.config().storage_domain {
            return Err(denied(&authority_reference, Verb::Read));
        }
        let snapshot = AuthorizedSnapshot {
            history,
            commit: verified.commit,
            evidence: verified.evidence,
            scope: path.to_vec(),
            storage_domain: domain,
            authority_reference,
            token: token.to_vec(),
            surface: surface.to_owned(),
        };
        let requests = self
            .snapshot_authorizations_observed(&snapshot, path, observation)
            .await?;
        Ok((snapshot, requests))
    }

    /// Rechecks live read authority and root trust for one path in the snapshot scope.
    ///
    /// # Errors
    /// Denies paths outside the scope or current ACL/token authority. Reports
    /// absence when verified provenance fails the immutable root trust policy.
    pub async fn authorize_snapshot_path(
        &self,
        snapshot: &AuthorizedSnapshot,
        path: &[u8],
    ) -> Result<(), StoreFailure> {
        self.authorize_snapshot_path_observed(snapshot, path, HistoryObservation::default())
            .await
    }

    async fn authorize_snapshot_path_observed(
        &self,
        snapshot: &AuthorizedSnapshot,
        path: &[u8],
        observation: HistoryObservation<'_>,
    ) -> Result<(), StoreFailure> {
        self.snapshot_authorizations_observed(snapshot, path, observation)
            .await
            .map(|_| ())
    }

    /// Retains the actual live and selected-root Read requests after full path checks.
    ///
    /// # Errors
    /// Preserves scoped trust, live policy, canonical root, token and storage failures.
    pub(super) async fn snapshot_authorizations_observed(
        &self,
        snapshot: &AuthorizedSnapshot,
        path: &[u8],
        observation: HistoryObservation<'_>,
    ) -> Result<Vec<super::AuthorizedRef>, StoreFailure> {
        if !(snapshot.scope == b"/"
            || path == snapshot.scope
            || path
                .strip_prefix(snapshot.scope.as_slice())
                .is_some_and(|suffix| suffix.starts_with(b"/")))
        {
            return Err(denied(&snapshot.authority_reference, Verb::Read));
        }
        if path != b"/" {
            let trust = TrustContext::new(
                &snapshot.history,
                snapshot.commit.identity(),
                Selector::preset(Preset::Any),
                &snapshot.storage_domain,
                None,
            )
            .map_err(|_| invalid())?;
            let relative = path.strip_prefix(b"/").ok_or_else(invalid)?;
            if !trust.accepts_path(relative) {
                let identity = TERRANE_V1
                    .from_digest(IdentityKind::Commit, &snapshot.commit.identity())
                    .map_err(|_| invalid())?;
                return Err(StoreFailure::new(StoreErrorKind::Absent(identity)));
            }
        }
        let current = self
            .authorize_observed(
                &snapshot.authority_reference,
                &snapshot.token,
                Verb::Read,
                &[path.to_vec()],
                &snapshot.surface,
                observation,
            )
            .await?;
        let record = current
            .record()
            .ok_or_else(|| denied(&snapshot.authority_reference, Verb::Read))?;
        let live = self
            .verified_tree_observed(record.commit, observation)
            .await?
            .evidence;
        let live_roots = live.occurrences(self.config().min_chunk_size)?;
        for bound in snapshot
            .evidence
            .occurrences(self.config().min_chunk_size)?
        {
            let covers = bound.path == b"/"
                || path == bound.path
                || path
                    .strip_prefix(bound.path.as_slice())
                    .is_some_and(|suffix| suffix.starts_with(b"/"));
            if covers && !live_roots.iter().any(|root| root.path == bound.path) {
                // Removing a named policy root cannot delegate its historical
                // content to an accidentally broader surviving ancestor ACL.
                return Err(denied(&snapshot.authority_reference, Verb::Read));
            }
        }
        let now = self.now(&snapshot.authority_reference, Verb::Read)?;
        let token = auth::verify(&snapshot.token, self.keys(), now)
            .map_err(|_| denied(&snapshot.authority_reference, Verb::Read))?;
        let layers = snapshot
            .evidence
            .policy_path(path, self.config().min_chunk_size)?;
        let layers = layers
            .iter()
            .map(|(properties, overrides)| RootLayer {
                properties,
                overrides,
            })
            .collect::<Vec<_>>();
        let policy = properties::resolve(&layers, self.defaults_for(&snapshot.evidence))
            .map_err(|_| invalid())?;
        let domain = domain_label(&policy).map_err(|_| invalid())?;
        let root_path = snapshot
            .evidence
            .containing_root(path, self.config().min_chunk_size)?;
        token
            .authorize(&Request {
                reference: snapshot.authority_reference.as_bytes(),
                verb: Verb::Read,
                roots: &[RequestRoot {
                    path: &root_path,
                    domain,
                }],
                now,
                surface: &snapshot.surface,
                locality: &self.config().home,
                epochs: &[(&snapshot.authority_reference, record.writer_epoch)],
            })
            .map_err(|_| denied(&snapshot.authority_reference, Verb::Read))?;
        let selected = super::AuthorizedRef {
            reference: snapshot.authority_reference.clone(),
            record: current.record().cloned(),
            token,
            verb: Verb::Read,
            root_paths: vec![root_path],
            root_domains: vec![domain.to_owned()],
            surface: snapshot.surface.clone(),
            token_bytes: snapshot.token.clone(),
        };
        Ok(vec![current, selected])
    }

    /// Returns verified plaintext only for the exact authorized file entry.
    ///
    /// # Errors
    /// Rejects changed authority, scope violations, mismatched content selectors,
    /// untrusted provenance, malformed content and unavailable decoding resources.
    pub async fn read_content(
        &self,
        snapshot: &AuthorizedSnapshot,
        path: &[u8],
        content: ContentRef,
        size: u64,
    ) -> Result<Vec<u8>, StoreFailure> {
        self.authorize_snapshot_path(snapshot, path).await?;
        let relative = path.strip_prefix(b"/").ok_or_else(invalid)?;
        {
            let (location, _) = snapshot
                .history
                .locate(snapshot.commit.identity(), relative)
                .map_err(|_| invalid())?;
            let entry = snapshot.history.entry(&location).map_err(|_| invalid())?;
            if !matches!(&entry.kind, EntryKind::File { content: actual, size: length, .. } if *actual == content && *length == size)
            {
                return Err(denied(&snapshot.authority_reference, Verb::Read));
            }
        }
        match content {
            ContentRef::Inline(digest) => self.read_chunk(snapshot, path, digest, size, true).await,
            ContentRef::Manifest(digest) => {
                let identity = TERRANE_V1
                    .from_digest(IdentityKind::Manifest, &digest)
                    .map_err(|_| invalid())?;
                let bytes = self.store().get(&identity, None).await?;
                let manifest =
                    Manifest::decode_verified(&bytes, &self.config().chunk_profile, &identity)
                        .map_err(|_| invalid())?;
                if manifest.size != size {
                    return Err(invalid());
                }
                let mut plaintext = Vec::new();
                for (index, chunk) in manifest.chunks.iter().enumerate() {
                    self.authorize_snapshot_path(snapshot, path).await?;
                    let bytes = self
                        .read_chunk(
                            snapshot,
                            path,
                            chunk.digest,
                            chunk.length,
                            index + 1 == manifest.chunks.len(),
                        )
                        .await?;
                    plaintext.extend(bytes);
                }
                if plaintext.len() as u64 != size
                    || manifest.hashes.get("blake3").map(Vec::as_slice)
                        != Some(blake3::hash(&plaintext).as_bytes().as_slice())
                {
                    return Err(invalid());
                }
                Ok(plaintext)
            }
        }
    }

    async fn read_chunk(
        &self,
        snapshot: &AuthorizedSnapshot,
        path: &[u8],
        digest: Digest,
        size: u64,
        final_chunk: bool,
    ) -> Result<Vec<u8>, StoreFailure> {
        self.authorize_snapshot_path(snapshot, path).await?;
        let identity = TERRANE_V1
            .from_digest(IdentityKind::Chunk, &digest)
            .map_err(|_| invalid())?;
        let encoded = self.store().get(&identity, None).await?;
        let envelope = parse_envelope(&encoded).map_err(|_| invalid())?;
        let dictionary = if let Codec::ZstdDictionary(digest) = envelope.codec {
            let identity = TERRANE_V1
                .from_digest(IdentityKind::Chunk, &digest)
                .map_err(|_| invalid())?;
            let bytes = self.store().get(&identity, None).await?;
            let encoded = parse_envelope(&bytes).map_err(|_| invalid())?;
            if encoded.codec != Codec::Raw {
                return Err(StoreFailure::new(StoreErrorKind::Unsupported));
            }
            TERRANE_V1
                .verify(&identity, encoded.body)
                .map_err(|_| invalid())?;
            Some(encoded.body.to_vec())
        } else {
            None
        };
        let chunk = crate::codec::decode_verified(
            &encoded,
            usize::try_from(size).map_err(|_| invalid())?,
            &self.config().chunk_profile,
            final_chunk,
            &identity,
            dictionary.as_deref(),
        )
        .map_err(|_| invalid())?;
        Ok(chunk.plaintext().to_vec())
    }
}
