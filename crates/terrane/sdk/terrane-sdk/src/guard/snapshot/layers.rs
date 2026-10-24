//! Keeps signed overlay operands distinct from ordinary serving namespaces.
//!
//! Input order is semantic. A source reference supplies independently checked
//! current Read authority; its immutable commit supplies the signed layer root.

use terrane_format::identity::Digest;

/// Selects one immutable signed layer under a separate current policy reference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OverlayInput {
    /// Current policy reference against which source Read permission is checked.
    pub reference: String,
    /// Exact signed source commit whose root is used at this layer position.
    pub commit: Digest,
}

use super::super::admission::SourceAuthorization;
use super::super::{AuthorizedRef, Guard, HistoryObservation, denied, domain_label, invalid};
use crate::store::{Clock, Store, StoreFailure};
use terrane_format::auth::{self, Request, RequestRoot, Verb};
use terrane_format::properties::RootLayer;

impl<S: Store, C: Clock> Guard<S, C> {
    /// Rechecks both the live policy reference and the exact signed layer context.
    ///
    /// # Errors
    /// Rejects changed full source records, removed policy roots, expired or
    /// attenuated Read authority, incomplete histories and invalid Original scopes.
    pub(crate) async fn authorize_overlay_source_observed(
        &self,
        commit: Digest,
        source: &SourceAuthorization,
        token_bytes: &[u8],
        surface: &str,
        observation: HistoryObservation<'_>,
    ) -> Result<Vec<AuthorizedRef>, StoreFailure> {
        let (selected, _) = self
            .verified_overlay_layer_history_observed(commit, observation)
            .await?;
        let original = self.original_commit(&commit)?;
        let authority = self
            .config()
            .policy_authority
            .as_deref()
            .unwrap_or(original.baseline().reference());
        if authority != source.reference {
            return Err(denied(&source.reference, Verb::Read));
        }
        let interpretation = self.select_view(commit, selected.evidence.root, observation)?;
        let occurrences = selected
            .evidence
            .occurrences(self.config().min_chunk_size)?;
        if occurrences
            .iter()
            .map(|root| &root.path)
            .ne(source.paths.iter())
        {
            return Err(invalid());
        }
        let mut captured = Vec::new();
        for path in &source.paths {
            let (current, live) = self
                .authorize_observed_with_evidence(
                    &source.reference,
                    token_bytes,
                    Verb::Read,
                    std::slice::from_ref(path),
                    surface,
                    observation,
                )
                .await?;
            if current.record() != Some(&source.record) {
                return Err(denied(&source.reference, Verb::Read));
            }
            let live = live.ok_or_else(|| denied(&source.reference, Verb::Read))?;
            let live_roots = live.occurrences(self.config().min_chunk_size)?;
            if !live_roots.iter().any(|root| &root.path == path) {
                return Err(denied(&source.reference, Verb::Read));
            }
            let now = self.now(&source.reference, Verb::Read)?;
            let token = auth::verify(token_bytes, self.keys(), now)
                .map_err(|_| denied(&source.reference, Verb::Read))?;
            let layers = selected
                .evidence
                .policy_path(path, self.config().min_chunk_size)?;
            let layers = layers
                .iter()
                .map(|(properties, overrides)| RootLayer {
                    properties,
                    overrides,
                })
                .collect::<Vec<_>>();
            let policy = interpretation.resolve(&layers, self.defaults_for(&selected.evidence))?;
            let domain = domain_label(&policy).map_err(|_| invalid())?;
            token
                .authorize(&Request {
                    reference: source.reference.as_bytes(),
                    verb: Verb::Read,
                    roots: &[RequestRoot { path, domain }],
                    now,
                    surface,
                    locality: &self.config().home,
                    epochs: &[(&source.reference, source.record.writer_epoch)],
                })
                .map_err(|_| denied(&source.reference, Verb::Read))?;
            let bound = AuthorizedRef {
                reference: source.reference.clone(),
                record: Some(source.record.clone()),
                token,
                verb: Verb::Read,
                root_paths: vec![path.clone()],
                root_domains: vec![domain.to_owned()],
                surface: surface.to_owned(),
                token_bytes: token_bytes.to_vec(),
            };
            captured.push(current);
            captured.push(bound);
        }
        Ok(captured)
    }
}
