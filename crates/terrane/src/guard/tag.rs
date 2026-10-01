//! Binds create-once tag publication to current source authority.

use terrane_core::auth::{Request, RequestRoot, Token, Verb};
use terrane_core::refs::{RefClass, RefName, RefRecord};

use super::{Guard, HistoryObservation, denied, invalid};
use crate::store::{Clock, Store, StoreFailure};

/// Retains the complete source fence and its authenticated root scopes.
pub(crate) struct TagPublication {
    pub(crate) source: RefRecord,
    pub(crate) target: RefRecord,
    target_name: RefName,
    roots: Vec<(Vec<u8>, String)>,
}

impl TagPublication {
    /// Checks the exact canonical destination admitted and signed for this tag.
    ///
    /// # Errors
    /// Rejects malformed or different target names before any target mutation.
    pub(crate) fn validate_target(&self, target: &str) -> Result<(), StoreFailure> {
        let name = RefName::parse(target).map_err(|_| invalid())?;
        if name != self.target_name {
            return Err(denied(target, Verb::Tag));
        }
        Ok(())
    }
}

impl<S: Store, C: Clock> Guard<S, C> {
    /// Admits a canonical create-once tag using current source Tag authority.
    ///
    /// # Errors
    /// Rejects malformed target namespaces, absent sources, invalid historical
    /// evidence, and current Tag denial; preserves storage failures.
    pub(crate) async fn admit_tag(
        &self,
        source: &str,
        target: &str,
        token: &[u8],
        surface: &str,
    ) -> Result<TagPublication, StoreFailure> {
        let target_name = RefName::parse(target).map_err(|_| invalid())?;
        if target_name.class() != RefClass::Tags {
            return Err(invalid());
        }
        let authorized = self
            .authorize(source, token, Verb::Tag, &[], surface)
            .await?;
        let record = authorized
            .record()
            .cloned()
            .ok_or_else(|| denied(source, Verb::Tag))?;
        self.verified_history(record.commit).await?;
        let selected = self.verified_tree(record.commit).await?;
        let roots = self.authoring_roots(&selected.evidence)?;
        let publication = TagPublication {
            target: RefRecord::first(record.commit, record.writer_epoch, record.home.clone()),
            target_name,
            source: record,
            roots,
        };
        self.revalidate_tag(source, token, surface, &publication)
            .await?;
        Ok(publication)
    }

    /// Signs an annotation bound to the admitted target name and source commit.
    ///
    /// # Errors
    /// Rejects invalid tokens, terminal keys, annotations, source caveats, and
    /// signature bindings; preserves clock failures.
    pub(crate) fn annotate_tag(
        &self,
        source: &str,
        token: &[u8],
        surface: &str,
        publication: &mut TagPublication,
        annotation: &crate::ref_advance::TagAnnotation,
    ) -> Result<(), StoreFailure> {
        let now = self.now(source, Verb::Tag)?;
        let token = Token::decode(token).map_err(|_| invalid())?;
        let domains = &publication.roots;
        let roots = domains
            .iter()
            .map(|(path, domain)| RequestRoot { path, domain })
            .collect::<Vec<_>>();
        let request = Request {
            reference: source.as_bytes(),
            verb: Verb::Tag,
            roots: &roots,
            now,
            surface,
            locality: &publication.source.home,
            epochs: &[(source, publication.source.writer_epoch)],
        };
        let tag = publication.target_name.clone();
        let envelope = terrane_core::refs::SnapshotEnvelope {
            tag: tag.clone(),
            commit: publication.source.commit,
            attestation: annotation.attestation.clone(),
            signer_key: String::new(),
            signature: [0; 64],
        };
        let signed = terrane_core::provenance::sign_snapshot(
            envelope,
            &token,
            &annotation.terminal_secret,
            self.keys(),
            &request,
        )
        .map_err(|_| denied(source, Verb::Tag))?;
        terrane_core::provenance::verify_snapshot(
            &signed,
            &tag,
            publication.source.commit,
            &token,
            self.keys(),
            &request,
        )
        .map_err(|_| denied(source, Verb::Tag))?;
        publication.target.policy = Some(terrane_core::refs::RefPolicy {
            snapshot: Some(signed),
            ..Default::default()
        });
        Ok(())
    }

    /// Rechecks current Tag grants against the complete admitted source record.
    ///
    /// # Errors
    /// Rejects changed sources and current authorization denial; preserves
    /// storage, historical verification, and clock failures.
    pub(crate) async fn revalidate_tag(
        &self,
        source: &str,
        token: &[u8],
        surface: &str,
        publication: &TagPublication,
    ) -> Result<(), StoreFailure> {
        self.revalidate_tag_observed(
            source,
            token,
            surface,
            publication,
            HistoryObservation::default(),
        )
        .await
    }

    /// Rechecks every authentic source root and the complete source authority record.
    ///
    /// # Errors
    /// Rejects changed source snapshots and current Tag denial; preserves storage failures.
    pub(crate) async fn revalidate_tag_observed(
        &self,
        source: &str,
        token: &[u8],
        surface: &str,
        publication: &TagPublication,
        observation: HistoryObservation<'_>,
    ) -> Result<(), StoreFailure> {
        self.capture_tag_authorizations_observed(source, token, surface, publication, observation)
            .await
            .map(|_| ())
    }

    /// Retains actual current Tag requests and checks the complete target binding.
    ///
    /// # Errors
    /// Rejects source changes, current Tag denial, altered target records or
    /// annotation signatures; preserves historical, clock and storage failures.
    pub(crate) async fn capture_tag_authorizations_observed(
        &self,
        source: &str,
        token: &[u8],
        surface: &str,
        publication: &TagPublication,
        observation: HistoryObservation<'_>,
    ) -> Result<Vec<super::AuthorizedRef>, StoreFailure> {
        let selected = self
            .verified_tree_observed(publication.source.commit, observation)
            .await?;
        if self.authoring_roots(&selected.evidence)? != publication.roots {
            return Err(invalid());
        }
        let expected = RefRecord::first(
            publication.source.commit,
            publication.source.writer_epoch,
            publication.source.home.clone(),
        );
        let mut target = publication.target.clone();
        target.policy = None;
        if target != expected {
            return Err(invalid());
        }
        if let Some(snapshot) = publication
            .target
            .policy
            .as_ref()
            .and_then(|policy| policy.snapshot.as_ref())
        {
            let now = self.now(source, Verb::Tag)?;
            let capability = Token::decode(token).map_err(|_| invalid())?;
            let roots = publication
                .roots
                .iter()
                .map(|(path, domain)| RequestRoot { path, domain })
                .collect::<Vec<_>>();
            let request = Request {
                reference: source.as_bytes(),
                verb: Verb::Tag,
                roots: &roots,
                now,
                surface,
                locality: &publication.source.home,
                epochs: &[(source, publication.source.writer_epoch)],
            };
            terrane_core::provenance::verify_snapshot(
                snapshot,
                &publication.target_name,
                publication.source.commit,
                &capability,
                self.keys(),
                &request,
            )
            .map_err(|_| denied(source, Verb::Tag))?;
        }
        // Canonical occurrence resolution always includes the view root, even
        // for an empty tree, and authoring_roots rejects an empty result above.
        // Every admitted tag therefore retains a genuine current Tag request.
        let mut captured = Vec::new();
        for (path, _) in &publication.roots {
            let authorized = self
                .authorize_observed(
                    source,
                    token,
                    Verb::Tag,
                    std::slice::from_ref(path),
                    surface,
                    observation,
                )
                .await?;
            if authorized.record() != Some(&publication.source) {
                return Err(denied(source, Verb::Tag));
            }
            captured.push(authorized);
        }
        if self.store().ref_get(source).await?.as_ref() != Some(&publication.source) {
            return Err(denied(source, Verb::Tag));
        }
        Ok(captured)
    }
}
