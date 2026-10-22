//! Keeps authenticated read witnesses private and rechecks live policy before reachable content I/O.

#[cfg(feature = "std")]
pub mod indexes;

#[cfg(all(feature = "std", unix))]
mod existing_references;
#[cfg(all(feature = "std", unix))]
pub(crate) use existing_references::ExistingOwnerReferences;

use terrane_format::auth::{self, Request, RequestRoot, Verb};
use terrane_format::identity::{Digest, IdentityKind, TERRANE_V1};
use terrane_format::manifest::Manifest;
use terrane_format::properties::RootLayer;
use terrane_format::provenance::{Preset, Selector, VerifiedCommit, VerifiedHistory};
use terrane_format::tree_format::{ContentRef, EntryKind};

use super::{Guard, HistoryObservation, TreeEvidence, denied, domain_label, invalid};
use crate::store::{Clock, Store, StoreErrorKind, StoreFailure};

mod dictionaries;
#[cfg(feature = "std")]
mod path_batch;
#[cfg(feature = "std")]
pub(crate) use path_batch::SnapshotPathBatch;
#[cfg(all(test, feature = "tokio", feature = "surface-sdk", unix))]
mod dictionary_tests;

use dictionaries::{ReadContent, ReadDictionary};

/// Holds an authorized scoped target without exposing its private historical witnesses.
pub struct AuthorizedSnapshot {
    /// Retains the complete immutable history checked for this scoped target.
    pub(crate) history: VerifiedHistory,
    /// Retains the exact signed target selected by the read operation.
    pub(crate) commit: VerifiedCommit,
    /// Retains canonical tree metadata for reachable scoped reads.
    pub(crate) evidence: TreeEvidence,
    /// Names the absolute path whose reachability and current Read were checked.
    pub(crate) scope: Vec<u8>,
    /// Names the resolved physical content domain for this target.
    pub(crate) storage_domain: String,
    /// Fixed caller interpretation selected from checked immutable view/root evidence.
    pub(crate) interpretation: super::recorded_properties::SelectedReadInterpretation,
    authority_reference: String,
    token: Vec<u8>,
    surface: String,
}

impl AuthorizedSnapshot {
    /// Borrows exact internal credentials for repeating a private source check.
    #[cfg(feature = "std")]
    pub(in crate::guard) fn maintenance_credentials(&self) -> (&str, &[u8], &str) {
        (&self.authority_reference, &self.token, &self.surface)
    }
}

// Borrows immutable witnesses without manufacturing another authorized snapshot.
// The common checker still derives every current request independently.
struct SnapshotRead<'a> {
    history: &'a VerifiedHistory,
    commit: &'a VerifiedCommit,
    evidence: &'a TreeEvidence,
    scope: &'a [u8],
    storage_domain: &'a str,
    interpretation: &'a super::recorded_properties::SelectedReadInterpretation,
    authority_reference: &'a str,
    token: &'a [u8],
    surface: &'a str,
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
        self.domain_content_access_observed(
            snapshot,
            path,
            content,
            size,
            HistoryObservation::default(),
        )
        .await
    }

    /// Issues exact content reachability under the same actual held observation.
    ///
    /// # Errors
    /// Preserves caller Read, selected content, dictionaries, history and current
    /// whole-record failures without reacquiring the held namespace.
    pub(crate) async fn domain_content_access_observed(
        &self,
        snapshot: &AuthorizedSnapshot,
        path: &[u8],
        content: ContentRef,
        size: u64,
        observation: HistoryObservation<'_>,
    ) -> Result<crate::domain::DomainAccess, StoreFailure> {
        let identities = self
            .read_content_checked_observed(snapshot, path, content, size, observation)
            .await?
            .identities;
        self.authorize_snapshot_path_observed(snapshot, path, observation)
            .await?;
        let access = self
            .domain_access_observed(
                &snapshot.authority_reference,
                &snapshot.token,
                Verb::Read,
                path,
                &snapshot.surface,
                observation,
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
        let observation = HistoryObservation::default().requested_target();
        let authorized = self
            .authorize_observed(
                reference,
                token,
                Verb::Read,
                &[path.to_vec()],
                surface,
                observation,
            )
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
                observation,
            )
            .await?;
        let current = self
            .authorize_observed(
                reference,
                token,
                Verb::Read,
                &[path.to_vec()],
                surface,
                observation,
            )
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
        let observation = observation.requested_target();
        // Commit selection is immutable. A separate current policy lookup
        // establishes live permission without changing the selected identity.
        let (verified, history) = self
            .verified_tree_history_observed(identity, observation.requested_target())
            .await?;
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
        self.snapshot_from_verified_history(
            (verified, history),
            authority,
            token,
            path,
            surface,
            observation,
        )
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
        let observation = observation.requested_target();
        let (verified, history) = self
            .verified_tree_history_observed(identity, observation.requested_target())
            .await?;
        self.snapshot_from_verified_history(
            (verified, history),
            authority_reference,
            token,
            path,
            surface,
            observation,
        )
        .await
    }

    // The immutable witnesses remain local to this invocation. Every live
    // authority, scope, token and trust check still runs below after completion.
    async fn snapshot_from_verified_history(
        &self,
        (verified, history): (super::history::VerifiedTree, VerifiedHistory),
        authority_reference: String,
        token: &[u8],
        path: &[u8],
        surface: &str,
        observation: HistoryObservation<'_>,
    ) -> Result<(AuthorizedSnapshot, Vec<super::AuthorizedRef>), StoreFailure> {
        let interpretation = self.select_view(
            verified.commit.identity(),
            verified.evidence.root,
            observation,
        )?;
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
        let policy = interpretation.resolve(&layers, self.defaults_for(&verified.evidence))?;
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
            interpretation,
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
        self.authorize_snapshot_path_observed(
            snapshot,
            path,
            HistoryObservation::default().requested_target(),
        )
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
        self.snapshot_read_authorizations(
            SnapshotRead {
                history: &snapshot.history,
                commit: &snapshot.commit,
                evidence: &snapshot.evidence,
                scope: &snapshot.scope,
                storage_domain: &snapshot.storage_domain,
                interpretation: &snapshot.interpretation,
                authority_reference: &snapshot.authority_reference,
                token: &snapshot.token,
                surface: &snapshot.surface,
            },
            path,
            observation,
        )
        .await
    }

    /// Checks a producer path using this invocation's immutable history witnesses.
    ///
    /// No live permission is retained. The selected domain and every ordinary
    /// ACL, token, epoch and trust check are recomputed for the actual path.
    ///
    /// # Errors
    /// Preserves selected interpretation, domain, current authority and trust failures.
    pub(in crate::guard) async fn producer_authorizations_from_history(
        &self,
        (verified, history): (&super::history::VerifiedTree, &VerifiedHistory),
        token: &[u8],
        path: &[u8],
        surface: &str,
        observation: HistoryObservation<'_>,
    ) -> Result<(String, Vec<super::AuthorizedRef>), StoreFailure> {
        let observation = observation.requested_target();
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
            .unwrap_or(original);
        let interpretation = self.select_view(
            verified.commit.identity(),
            verified.evidence.root,
            observation,
        )?;
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
        let policy = interpretation.resolve(&layers, self.defaults_for(&verified.evidence))?;
        let domain = domain_label(&policy).map_err(|_| invalid())?.to_owned();
        if domain != self.config().storage_domain {
            return Err(denied(authority, Verb::Read));
        }
        let requests = self
            .snapshot_read_authorizations(
                SnapshotRead {
                    history,
                    commit: &verified.commit,
                    evidence: &verified.evidence,
                    scope: path,
                    storage_domain: &domain,
                    interpretation: &interpretation,
                    authority_reference: authority,
                    token,
                    surface,
                },
                path,
                observation,
            )
            .await?;
        Ok((domain, requests))
    }

    /// Captures the Originals associated with a successfully completed local history.
    ///
    /// # Errors
    /// Refuses missing protected Original contexts for any reached record.
    #[cfg(feature = "std")]
    pub(in crate::guard) fn producer_originals(
        &self,
        history: &VerifiedHistory,
    ) -> Result<Vec<super::OriginalCommitContext>, StoreFailure> {
        history
            .commits()
            .map(|commit| self.original_commit(&commit.identity()))
            .collect()
    }

    /// Refreshes every Original and installed selection in an immutable preparation.
    ///
    /// The record inventory includes disclosure-expanded dependencies. It grants
    /// no completion by itself; callers supply only their successfully completed
    /// invocation-local history and retain the owning closing control checks.
    ///
    /// # Errors
    /// Refuses changed selected meanings, unavailable Originals and changed controls.
    #[cfg(feature = "std")]
    pub(in crate::guard) async fn refresh_producer_history(
        &self,
        history: &VerifiedHistory,
        originals: &[super::OriginalCommitContext],
        observation: HistoryObservation<'_>,
    ) -> Result<(), StoreFailure> {
        if history.commits().count() != originals.len() {
            return Err(invalid());
        }
        for (commit, original) in history.commits().zip(originals) {
            let view = commit.identity();
            if *original.commit() != view || self.original_commit(&view)? != *original {
                return Err(invalid());
            }
            let baseline = original.baseline();
            let association = super::AssociationView {
                commit: &view,
                id: baseline.authority().id(),
                reference: baseline.reference(),
                epoch: baseline.epoch(),
            };
            let checked = match observation.identity() {
                Some(held) if held.writable() => {
                    self.recheck_original_commit_observed(baseline, association, held)
                        .await?
                }
                Some(held) => {
                    self.recheck_original_commit_read_observed(baseline, association, held)
                        .await?
                }
                None => self.check_original_commit(baseline, association).await?,
            };
            if &checked != original {
                return Err(invalid());
            }
            observation.check_completion_original(&checked)?;
            observation.record_original(&checked)?;
            let selected = self.select_view(view, commit.commit().tree, observation)?;
            if selected.selection()
                != history
                    .property_selection(view)
                    .map_err(|error| StoreFailure::with_source(invalid().kind().clone(), error))?
            {
                return Err(invalid());
            }
        }
        Ok(())
    }

    async fn snapshot_read_authorizations(
        &self,
        snapshot: SnapshotRead<'_>,
        path: &[u8],
        observation: HistoryObservation<'_>,
    ) -> Result<Vec<super::AuthorizedRef>, StoreFailure> {
        if self.select_view(
            snapshot.commit.identity(),
            snapshot.evidence.root,
            observation,
        )? != *snapshot.interpretation
        {
            return Err(invalid());
        }
        if !(snapshot.scope == b"/"
            || path == snapshot.scope
            || path
                .strip_prefix(snapshot.scope)
                .is_some_and(|suffix| suffix.starts_with(b"/")))
        {
            return Err(denied(snapshot.authority_reference, Verb::Read));
        }
        if path != b"/" {
            // Keep the existing per-path evaluator, including its history clone.
            // Its Rc-backed state must finish before the following native await.
            let trust = snapshot.interpretation.evaluator(
                snapshot.history,
                (snapshot.commit.identity(), snapshot.evidence.root),
                Selector::preset(Preset::Any),
                snapshot.storage_domain,
                None,
            )?;
            let relative = path.strip_prefix(b"/").ok_or_else(invalid)?;
            if !trust.accepts_path(relative) {
                let identity = TERRANE_V1
                    .from_digest(IdentityKind::Commit, &snapshot.commit.identity())
                    .map_err(|_| invalid())?;
                return Err(StoreFailure::new(StoreErrorKind::Absent(identity)));
            }
        }
        let (current, live) = self
            .authorize_observed_with_evidence(
                snapshot.authority_reference,
                snapshot.token,
                Verb::Read,
                &[path.to_vec()],
                snapshot.surface,
                observation,
            )
            .await?;
        let record = current
            .record()
            .ok_or_else(|| denied(snapshot.authority_reference, Verb::Read))?;
        // Reuse only the evidence freshly checked for this exact current ref.
        // Every path and content boundary still performs its own authorization.
        let live = live.ok_or_else(|| denied(snapshot.authority_reference, Verb::Read))?;
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
                return Err(denied(snapshot.authority_reference, Verb::Read));
            }
        }
        let now = self.now(snapshot.authority_reference, Verb::Read)?;
        let token = auth::verify(snapshot.token, self.keys(), now)
            .map_err(|_| denied(snapshot.authority_reference, Verb::Read))?;
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
        let policy = snapshot
            .interpretation
            .resolve(&layers, self.defaults_for(snapshot.evidence))?;
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
                surface: snapshot.surface,
                locality: &self.config().home,
                epochs: &[(snapshot.authority_reference, record.writer_epoch)],
            })
            .map_err(|_| denied(snapshot.authority_reference, Verb::Read))?;
        let selected = super::AuthorizedRef {
            reference: snapshot.authority_reference.to_owned(),
            record: current.record().cloned(),
            token,
            verb: Verb::Read,
            root_paths: vec![root_path],
            root_domains: vec![domain.to_owned()],
            surface: snapshot.surface.to_owned(),
            token_bytes: snapshot.token.to_vec(),
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
        self.read_content_observed(snapshot, path, content, size, HistoryObservation::default())
            .await
    }

    /// Returns verified plaintext under the same actual held namespace observation.
    ///
    /// # Errors
    /// Preserves current caller policy, exact file selection, identity, size,
    /// dictionary-chain, original-control and decoding failures.
    pub(crate) async fn read_content_observed(
        &self,
        snapshot: &AuthorizedSnapshot,
        path: &[u8],
        content: ContentRef,
        size: u64,
        observation: HistoryObservation<'_>,
    ) -> Result<Vec<u8>, StoreFailure> {
        Ok(self
            .read_content_checked_observed(snapshot, path, content, size, observation)
            .await?
            .plaintext)
    }

    /// Reads genuine stored dictionary envelopes after checking the exact file selection.
    ///
    /// The returned dependency-first records are ordinary data. Consumers must
    /// independently validate them before native preload or content admission.
    ///
    /// # Errors
    /// Preserves current policy, scoped content and dictionary validation failures.
    #[cfg(feature = "std")]
    pub(crate) async fn read_content_dictionaries(
        &self,
        snapshot: &AuthorizedSnapshot,
        path: &[u8],
        content: ContentRef,
        size: u64,
    ) -> Result<Vec<(terrane_format::identity::Identity, Vec<u8>, usize)>, StoreFailure> {
        Ok(self
            .read_content_checked(snapshot, path, content, size)
            .await?
            .dictionaries
            .into_iter()
            .map(|dictionary| {
                (
                    dictionary.identity,
                    dictionary.encoded,
                    dictionary.plaintext.len(),
                )
            })
            .collect())
    }

    async fn read_content_checked(
        &self,
        snapshot: &AuthorizedSnapshot,
        path: &[u8],
        content: ContentRef,
        size: u64,
    ) -> Result<ReadContent, StoreFailure> {
        self.read_content_checked_observed(
            snapshot,
            path,
            content,
            size,
            HistoryObservation::default(),
        )
        .await
    }

    async fn read_content_checked_observed(
        &self,
        snapshot: &AuthorizedSnapshot,
        path: &[u8],
        content: ContentRef,
        size: u64,
        observation: HistoryObservation<'_>,
    ) -> Result<ReadContent, StoreFailure> {
        let observation = observation.requested_target();
        self.authorize_snapshot_path_observed(snapshot, path, observation)
            .await?;
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
            ContentRef::Inline(digest) => {
                self.read_chunk(snapshot, path, digest, size, true, observation)
                    .await
            }
            ContentRef::Manifest(digest) => {
                let identity = TERRANE_V1
                    .from_digest(IdentityKind::Manifest, &digest)
                    .map_err(|_| invalid())?;
                self.authorize_snapshot_path_observed(snapshot, path, observation)
                    .await?;
                let bytes = self.store().get(&identity, None).await?;
                let manifest =
                    Manifest::decode_verified(&bytes, &self.config().chunk_profile, &identity)
                        .map_err(|_| invalid())?;
                if manifest.size != size {
                    return Err(invalid());
                }
                let mut result = ReadContent {
                    plaintext: Vec::new(),
                    identities: vec![identity],
                    dictionaries: Vec::new(),
                };
                for (index, chunk) in manifest.chunks.iter().enumerate() {
                    self.authorize_snapshot_path_observed(snapshot, path, observation)
                        .await?;
                    let chunk = self
                        .read_chunk(
                            snapshot,
                            path,
                            chunk.digest,
                            chunk.length,
                            index + 1 == manifest.chunks.len(),
                            observation,
                        )
                        .await?;
                    result.plaintext.extend(chunk.plaintext);
                    result.identities.extend(chunk.identities);
                    result.dictionaries.extend(chunk.dictionaries);
                }
                if result.plaintext.len() as u64 != size
                    || manifest.hashes.get("blake3").map(Vec::as_slice)
                        != Some(blake3::hash(&result.plaintext).as_bytes().as_slice())
                {
                    return Err(invalid());
                }
                Ok(result)
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
        observation: HistoryObservation<'_>,
    ) -> Result<ReadContent, StoreFailure> {
        let observation = observation.requested_target();
        self.authorize_snapshot_path_observed(snapshot, path, observation)
            .await?;
        let identity = TERRANE_V1
            .from_digest(IdentityKind::Chunk, &digest)
            .map_err(|_| invalid())?;
        let encoded = self.store().get(&identity, None).await?;
        let length = usize::try_from(size).map_err(|_| invalid())?;
        crate::codec::inspect_chunk(&encoded, length, self.config().chunk_profile.maximum())
            .map_err(|_| invalid())?;
        let dictionaries = self
            .read_chunk_dictionaries(snapshot, path, &identity, &encoded, observation)
            .await?;
        let dictionary = dictionaries
            .last()
            .map(|dictionary| dictionary.plaintext.as_slice());
        let chunk = crate::codec::decode_object_chunk_verified(
            &encoded,
            length,
            &self.config().chunk_profile,
            final_chunk,
            &identity,
            dictionary,
        )
        .map_err(|_| invalid())?;
        let mut identities = dictionaries
            .iter()
            .map(|dictionary: &ReadDictionary| dictionary.identity.clone())
            .collect::<Vec<_>>();
        identities.push(identity);
        Ok(ReadContent {
            plaintext: chunk.plaintext().to_vec(),
            identities,
            dictionaries,
        })
    }
}
