//! Checks canonical candidate trees and builds signed entry-origin receipts.

pub(in crate::guard) mod index_inline;
pub(in crate::guard) mod index_writer;
mod layers;
mod validation;

pub use index_writer::{
    IndexBindingGap, IndexGraftPreparationWork, IndexGraftPropagationWork,
    IndexGraftValidationWork, IndexOperationWork, IndexPublicationWork,
};

use std::collections::{BTreeMap, BTreeSet};

use terrane_format::auth::{self, Request, RequestRoot, Verb};
use terrane_format::identity::Digest;
use terrane_format::properties::{self, PropertyName, RootLayer, Value};
use terrane_format::provenance::{self, VerifiedCommit};
use terrane_format::refs::{
    CommitContext, EntryOrigin, EntryReceipt, EntrySource, Provenance, RefRecord,
};

use super::{CommitRequest, StagedUpload};
use super::{Guard, TreeEvidence, denied};
use crate::store::{Clock, Store, StoreErrorKind, StoreFailure};

#[cfg(all(test, feature = "tokio", unix))]
pub(super) mod tests;

/// Reports an opt-in test boundary without changing admission inputs.
///
/// # Panics
/// Panics if enabled diagnostics cannot write to standard error.
#[cfg(test)]
fn trace_index_admission(phase: &'static str) {
    if std::env::var_os("TERRANE_INDEX_REBUILD_TRACE").is_some() {
        eprintln!("index-admission-subphase phase={phase}");
    }
}

/// Retains the exact live source authority selected by canonical fork or join admission.
#[derive(Clone)]
pub(crate) struct SourceAuthorization {
    /// Names the source reference whose live record supplied authority.
    pub(crate) reference: String,
    /// Records the operation independently authorized on the source.
    pub(crate) verb: Verb,
    /// Retains the actual source root scopes checked for the operation.
    pub(crate) paths: Vec<Vec<u8>>,
    /// Retains the exact source head that must remain current.
    pub(crate) record: RefRecord,
    /// Keeps this prepared attempt's cold route alive without granting authority.
    pub(crate) cold_route_lifetime: Option<std::sync::Arc<()>>,
}

/// Retains canonical root alternatives for one necessary current Admin decision.
pub(super) struct AdminCheck {
    /// Lists actual root scopes that can supply the required Admin decision.
    pub(super) alternatives: Vec<Vec<u8>>,
}

/// Retains checked producer requirements and current authority units for admission.
pub(super) struct CandidateValidation {
    /// Retains independently checked attribute-producer requirements.
    pub(super) requirements: Vec<super::attributes::RequirementEvidence>,
    /// Retains current Admin decisions required by canonical policy changes.
    pub(super) admin_checks: Vec<AdminCheck>,
    /// Exact canonical candidate/prior root claims selected by this validation.
    pub(super) root_claims: Vec<(Vec<u8>, String)>,
}

/// Retains the checked prior tree and its independently selected signed view.
#[derive(Clone, Copy)]
pub(super) struct CandidatePrevious<'a> {
    /// Borrows the canonical namespace evidence for the prior baseline.
    pub(super) evidence: &'a TreeEvidence,
    /// Borrows the exact independently selected prior-view semantics.
    pub(super) interpretation: &'a super::SelectedReadInterpretation,
    /// Absent only for a copied bootstrap baseline, which grants no current authority.
    pub(super) commit: Option<&'a VerifiedCommit>,
}

/// Separates new authoring from an existing view's independently selected meaning.
pub(super) enum CandidateInterpretation<'a> {
    /// Uses the independently installed inputs for a newly authored namespace.
    Authoring,
    /// Retains the successful existing-view verifier's original selection.
    Existing {
        /// Exact property interpretation of the existing signed view.
        selected: &'a super::SelectedReadInterpretation,
        /// Exact independently selected namespace profile for that view.
        profile: &'a terrane_format::gc::publication::evidence::ConfiguredRegistryInputs,
    },
}

impl CandidateInterpretation<'_> {
    fn property_selection<S, C>(
        &self,
        guard: &Guard<S, C>,
    ) -> Result<properties::selected::Selection, StoreFailure> {
        match self {
            Self::Authoring => Ok(guard.completion_inputs()?.selection),
            Self::Existing { selected, .. } => Ok(selected.selection()),
        }
    }

    fn attribute_revision<S, C>(&self, guard: &Guard<S, C>) -> Result<u64, StoreFailure> {
        match self {
            Self::Authoring => Ok(guard.completion_inputs()?.registries.attribute_revision),
            Self::Existing { profile, .. } => Ok(profile.attribute_revision),
        }
    }
}

/// A signed commit bound to the exact current-policy record it may replace.
pub(crate) struct AdmittedCommit {
    /// Retains an explicit input-only layer context through owning publication.
    pub(crate) tree_usage: terrane_format::tree_format::TreeUse,
    /// Retains every independently checked current overlay input Read decision.
    pub(crate) overlay_sources: Vec<(Digest, SourceAuthorization)>,
    /// Retains actual unchanged-owner placement only for a closed native caller.
    #[cfg(unix)]
    pub(crate) existing_owner_references: Option<super::read::ExistingOwnerReferences>,
    /// Separates actual unsigned index preparation from selected publication.
    pub(crate) index_work: IndexPublicationWork,
    /// Retains the signed candidate produced by successful admission.
    pub(crate) commit: VerifiedCommit,
    /// Routes only a genuinely cold-prepared candidate to mandatory fresh qualification.
    #[cfg(unix)]
    pub(crate) cold_fork: Option<super::cold_fork::ColdForkBinding>,
    /// Captures the actual constructor-selected ordinary interpretation and profile.
    pub(super) completion_inputs: super::history::completion::SelectedInputs,
    /// Retains the interpretation actually executed by admission, not a later lookup.
    #[cfg(feature = "std")]
    pub(super) admission_interpretation: super::recorded_properties::SelectedReadInterpretation,
    /// Retains the registered profile selected by the actual successful admission.
    #[cfg(feature = "std")]
    pub(super) admission_profile:
        terrane_format::gc::publication::evidence::ConfiguredRegistryInputs,
    /// Retains independently checked attribute-producer requirements.
    pub(super) requirements: Vec<super::attributes::RequirementEvidence>,
    /// Retains current Admin decisions required by canonical policy changes.
    pub(super) admin_checks: Vec<AdminCheck>,
    /// Names the destination reference bound to this admitted attempt.
    pub(super) publication_reference: String,
    /// Canonical current publication units, independent of signed historical claims.
    pub(super) publication_paths: Vec<Vec<u8>>,
    /// Retains the validated immutable uploads needed by publication.
    pub(crate) uploads: Vec<StagedUpload>,
    /// Retains the signed first-parent baseline expected by this proposal.
    pub(crate) expected: Option<RefRecord>,
    /// Captures live authority separately from the signed historical first parent.
    pub(crate) observed_current: Option<RefRecord>,
    /// Retains the surface used by the current operation authorization.
    pub(crate) surface: String,
    /// Retains the separately checked live source authority when required.
    pub(crate) source_authorization: Option<SourceAuthorization>,
    /// Retains the current operation token for mandatory publication rechecks.
    pub(crate) token: Vec<u8>,
    /// Identifies the principal selected by current token verification.
    pub(crate) principal: String,
    /// Records the observation time used by successful admission.
    pub(crate) timestamp: u64,
    /// Records the destination operation requiring fresh current authorization.
    pub(crate) publication_verb: Verb,
    /// Distinguishes an unchanged ref policy from replacement or removal.
    pub(crate) policy_override: Option<Option<terrane_format::refs::RefPolicy>>,
}

impl AdmittedCommit {
    /// Copies the ordinary semantics retained by the successful admission.
    ///
    /// This projection grants no current rights or completed-history authority.
    #[cfg(feature = "std")]
    pub(crate) fn admitted_property_selection(&self) -> properties::selected::Selection {
        self.admission_interpretation.selection()
    }

    /// Borrows exact canonical current units retained by owning admission.
    pub(crate) fn publication_paths(&self) -> &[Vec<u8>] {
        &self.publication_paths
    }
}

/// Retains the owned source evidence and replacement baseline for one admission.
///
/// These inputs describe candidate ancestry; they do not grant live authority.
struct AdmissionSources {
    usage: terrane_format::tree_format::TreeUse,
    overlay: Vec<(Digest, TreeEvidence)>,
    copied: Option<(Digest, TreeEvidence)>,
    base: Option<RefRecord>,
    merged_source: Option<(Digest, TreeEvidence)>,
}

/// Borrows one candidate proposal without granting admission or publication authority.
pub(super) struct CandidateRequest<'a> {
    /// Borrows the unsigned canonical candidate commit.
    pub(super) commit: &'a terrane_format::refs::Commit,
    /// Borrows staged immutable witnesses offered for candidate validation.
    pub(super) uploads: &'a [StagedUpload],
    /// Borrows the current operation token rather than historical credentials.
    pub(super) token: &'a [u8],
    /// Names the surface used for current authorization.
    pub(super) surface: &'a str,
    /// Borrows independently supplied content-domain records.
    pub(super) reference_records: &'a [crate::domain::DomainRecord],
}

impl<'a> From<&'a CommitRequest> for CandidateRequest<'a> {
    fn from(request: &'a CommitRequest) -> Self {
        Self {
            commit: &request.commit,
            uploads: &request.uploads,
            token: &request.token,
            surface: &request.surface,
            reference_records: &request.reference_records,
        }
    }
}

impl<S: Store, C: Clock> Guard<S, C> {
    /// Checks current administrative permission under the exact borrowed observation.
    ///
    /// # Errors
    /// Preserves current token, ACL, signed target, Original and storage failures.
    pub(super) async fn current_admin_observed(
        &self,
        reference: &str,
        token: &[u8],
        paths: &[Vec<u8>],
        surface: &str,
        observation: super::HistoryObservation<'_>,
    ) -> Result<bool, StoreFailure> {
        match self
            .authorize_observed(reference, token, Verb::Admin, paths, surface, observation)
            .await
        {
            Ok(_) => Ok(true),
            Err(failure) if matches!(failure.kind(), StoreErrorKind::Denied { .. }) => Ok(false),
            Err(failure) => Err(failure),
        }
    }

    /// Checks and signs a proposal under current destination authority.
    ///
    /// # Errors
    /// Preserves canonical candidate, current authority, Original, producer and
    /// storage failures before publication.
    pub(crate) async fn admit(
        &self,
        reference: &str,
        epoch: u64,
        request: CommitRequest,
    ) -> Result<AdmittedCommit, StoreFailure> {
        self.admit_inner(reference, epoch, request, None, None, None)
            .await
    }

    /// Admits a paired proposal under its actual excluded destination namespace.
    ///
    /// This preserves complete current and Original verification while allowing
    /// the paired producer to check its exact pending import transition later.
    /// It selects no configuration and supplies no publication authority.
    ///
    /// # Errors
    /// Preserves ordinary admission failures and rejects a foreign held identity.
    #[cfg(all(feature = "std", unix))]
    pub(crate) async fn admit_held(
        &self,
        reference: &str,
        epoch: u64,
        request: CommitRequest,
        identity: &crate::bucket::held::HeldIdentity<'_>,
    ) -> Result<AdmittedCommit, StoreFailure> {
        self.admit_inner_observed(
            reference,
            epoch,
            request,
            AdmissionSources {
                overlay: Vec::new(),
                usage: terrane_format::tree_format::TreeUse::Ordinary,
                copied: None,
                base: None,
                merged_source: None,
            },
            super::HistoryObservation::held(identity).requested_target(),
        )
        .await
    }

    /// Signs an input-only layer under the ordinary current destination authority.
    ///
    /// The owning repository retains its immutable metadata and Original context;
    /// it must not select this root as an ordinary serving namespace.
    ///
    /// # Errors
    /// Preserves all current Commit/Admin, canonical layer, producer, Original
    /// and storage failures. A recipe-bearing layer is not an authored input.
    pub(crate) async fn admit_overlay_layer(
        &self,
        reference: &str,
        epoch: u64,
        request: CommitRequest,
    ) -> Result<AdmittedCommit, StoreFailure> {
        if request.commit.profile_pair.recipe.is_some() {
            return Err(super::invalid());
        }
        self.admit_inner_observed(
            reference,
            epoch,
            request,
            AdmissionSources {
                overlay: Vec::new(),
                usage: terrane_format::tree_format::TreeUse::OverlayLayer,
                copied: None,
                base: None,
                merged_source: None,
            },
            super::HistoryObservation::default().requested_target(),
        )
        .await
    }

    /// Checks a proposal against its captured losing-writer baseline.
    ///
    /// # Errors
    /// Preserves current authority, canonical candidate, Original, producer and
    /// storage failures while retaining the supplied baseline.
    pub(crate) async fn admit_losing(
        &self,
        reference: &str,
        epoch: u64,
        request: CommitRequest,
        base: RefRecord,
    ) -> Result<AdmittedCommit, StoreFailure> {
        self.admit_inner(reference, epoch, request, None, Some(base), None)
            .await
    }

    /// Admits a copied source tree after independent current Fork authorization.
    ///
    /// # Errors
    /// Rejects missing source authority or unexpected uploads and preserves
    /// complete source history and ordinary destination admission failures.
    pub(crate) async fn admit_fork(
        &self,
        source: &str,
        reference: &str,
        epoch: u64,
        mut request: CommitRequest,
    ) -> Result<AdmittedCommit, StoreFailure> {
        let authorized = self
            .authorize(source, &request.token, Verb::Fork, &[], &request.surface)
            .await?;
        let record = authorized
            .record()
            .ok_or_else(|| denied(source, Verb::Fork))?;
        // This exact tree check includes complete original/provenance history.
        // Retain it only for this admission; current source/path checks remain fresh.
        let verified = self.verified_tree(record.commit).await?;
        let paths = verified
            .evidence
            .occurrences(self.config().min_chunk_size)?
            .into_iter()
            .map(|root| root.path)
            .collect::<Vec<_>>();
        for path in &paths {
            self.authorize(
                source,
                &request.token,
                Verb::Fork,
                std::slice::from_ref(path),
                &request.surface,
            )
            .await?;
        }
        if !request.uploads.is_empty() {
            return Err(denied(reference, Verb::Commit));
        }
        request.commit.tree = verified.evidence.root;
        request.commit.parents = vec![verified.commit.identity()];
        let mut admitted = self
            .admit_inner(
                reference,
                epoch,
                request,
                Some((verified.commit.identity(), verified.evidence)),
                None,
                None,
            )
            .await?;
        if admitted.expected.is_some() {
            return Err(denied(reference, Verb::Commit));
        }
        admitted.source_authorization = Some(SourceAuthorization {
            reference: source.to_owned(),
            verb: Verb::Fork,
            paths,
            record: record.clone(),
            cold_route_lifetime: None,
        });
        Ok(admitted)
    }

    /// Admits ordinary metadata with independently completed current targets.
    ///
    /// # Errors
    /// Rejects denied authority, invalid namespace/provenance, incomplete index
    /// relationships and unsupported semantics; preserves originating store failures.
    pub(super) async fn admit_inner(
        &self,
        reference: &str,
        epoch: u64,
        request: CommitRequest,
        copied: Option<(Digest, TreeEvidence)>,
        base: Option<RefRecord>,
        merged_source: Option<(Digest, TreeEvidence)>,
    ) -> Result<AdmittedCommit, StoreFailure> {
        self.admit_inner_observed(
            reference,
            epoch,
            request,
            AdmissionSources {
                overlay: Vec::new(),
                usage: terrane_format::tree_format::TreeUse::Ordinary,
                copied,
                base,
                merged_source,
            },
            super::HistoryObservation::default().requested_target(),
        )
        .await
    }

    /// Admits a canonical correction using separately authenticated repair sources.
    ///
    /// The private purpose cannot certify the source's auxiliary coverage. The
    /// candidate still requires complete canonical relationships and normal signing.
    /// Namespace continuity is enforced separately by the unchanged-owner receipt
    /// consumed by the coordinator.
    ///
    /// # Errors
    /// Preserves current authorization, Original and metadata failures; rejects a
    /// different selected source and incomplete candidate indexes.
    pub(crate) async fn admit_index_rebuild(
        &self,
        reference: &str,
        epoch: u64,
        request: CommitRequest,
        purpose: &super::index_maintenance::Purpose,
    ) -> Result<AdmittedCommit, StoreFailure> {
        self.admit_inner_observed(
            reference,
            epoch,
            request,
            AdmissionSources {
                overlay: Vec::new(),
                usage: terrane_format::tree_format::TreeUse::Ordinary,
                copied: None,
                base: None,
                merged_source: None,
            },
            super::HistoryObservation::default().maintenance(purpose),
        )
        .await
    }

    /// Admits metadata while retaining the operation's exact source qualification.
    ///
    /// # Errors
    /// Preserves signature, policy, Original, producer and storage failures;
    /// rejects invalid templates, unsupported semantics and incomplete candidates.
    async fn admit_inner_observed(
        &self,
        reference: &str,
        epoch: u64,
        mut request: CommitRequest,
        sources: AdmissionSources,
        observation: super::HistoryObservation<'_>,
    ) -> Result<AdmittedCommit, StoreFailure> {
        let AdmissionSources {
            usage,
            overlay,
            copied,
            base,
            merged_source,
        } = sources;

        // A scoped upload receipt does not establish a durable source-origin proof.
        // Publication must consume an authenticated certificate rather than drop it.
        if !request.disclosures.is_empty() {
            return Err(denied(reference, Verb::Commit));
        }

        if request.commit.profile_pair.chunk_profile != self.config().chunk_profile_name
            || self.config().min_chunk_size != self.config().chunk_profile.minimum() as u64
            || request.uploads.iter().any(|upload| matches!(upload,
                StagedUpload::Chunk { profile, .. } if profile.as_ref() != self.config().chunk_profile.as_ref())) {
            return Err(denied(reference, Verb::Commit));
        }
        // Authenticate the capability before loading canonical comparison data.
        // Current root authority is checked only at independently derived units.
        terrane_format::refs::RefName::parse(reference)
            .map_err(|_| denied(reference, Verb::Commit))?;
        let now = self.now(reference, Verb::Commit)?;
        let token = auth::verify(&request.token, self.keys(), now)
            .map_err(|_| denied(reference, Verb::Commit))?;
        let live_record = self.store().ref_get(reference).await?;
        if live_record
            .as_ref()
            .is_some_and(|record| record.home != self.config().home)
        {
            return Err(denied(reference, Verb::Commit));
        }
        let expected = base.or_else(|| live_record.clone());
        if expected
            .as_ref()
            .is_some_and(|record| record.home != self.config().home)
        {
            return Err(denied(reference, Verb::Commit));
        }
        if live_record
            .as_ref()
            .is_some_and(|record| epoch < record.writer_epoch)
        {
            return Err(denied(reference, Verb::Commit));
        }
        #[cfg(test)]
        trace_index_admission("candidate-load-before");
        let mut candidate = TreeEvidence::load_tree_for(
            self.store(),
            request.commit.tree,
            &request.uploads,
            self.config().min_chunk_size,
            usage,
        )
        .await?;
        #[cfg(test)]
        trace_index_admission("candidate-load-after");
        let previous_identity = copied
            .as_ref()
            .map(|(identity, _)| *identity)
            .or_else(|| expected.as_ref().map(|record| record.commit));
        let (previous, previous_commit) = match copied {
            Some((_, evidence)) if expected.is_none() => (Some(evidence), None),
            Some(_) => return Err(denied(reference, Verb::Commit)),
            None => match &expected {
                // Retain the same successful historical verifier result. Pure
                // selection below does not repeat its protected/native reads.
                Some(record) => {
                    #[cfg(test)]
                    trace_index_admission("previous-verification-before");
                    let verified = self
                        .verified_tree_observed(record.commit, observation)
                        .await?;
                    #[cfg(test)]
                    trace_index_admission("previous-verification-after");
                    (Some(verified.evidence), Some(verified.commit))
                }
                None => (None, None),
            },
        };
        if let Some(purpose) = observation.maintenance
            && previous_identity != Some(purpose.source())
        {
            return Err(super::invalid());
        }
        let previous_interpretation = previous
            .as_ref()
            .zip(previous_identity)
            .map(|(evidence, view)| self.select_view(view, evidence.root, observation))
            .transpose()?;
        #[cfg(test)]
        trace_index_admission("initial-candidate-validation-before");
        let CandidateValidation {
            mut requirements,
            mut admin_checks,
            mut root_claims,
        } = self
            .validate_candidate_observed(
                reference,
                CandidateRequest::from(&request),
                &candidate,
                CandidateInterpretation::Authoring,
                previous.as_ref().zip(previous_interpretation.as_ref()).map(
                    |(evidence, interpretation)| CandidatePrevious {
                        evidence,
                        interpretation,
                        commit: previous_commit.as_ref(),
                    },
                ),
                observation,
            )
            .await?;
        #[cfg(test)]
        trace_index_admission("initial-candidate-validation-after");
        let authoring = self.configured_authoring_registries()?;
        let active = (
            authoring.property_revision,
            authoring.attribute_revision,
            authoring.tree_revision,
        ) == (3, 2, 1);
        let previous_profile = if active {
            match previous
                .as_ref()
                .zip(previous_interpretation.as_ref())
                .zip(previous_identity)
            {
                Some(((evidence, interpretation), identity)) => {
                    let profile = if let Some(commit) = &previous_commit {
                        let (selected, profile) =
                            self.selected_view_profile(commit, observation)?;
                        if selected != *interpretation {
                            return Err(super::invalid());
                        }
                        profile
                    } else {
                        self.index_previous_profile(identity, evidence, interpretation)
                            .await?
                    };
                    Some(profile)
                }
                None => None,
            }
        } else {
            None
        };
        let previous_index = previous
            .as_ref()
            .zip(previous_interpretation.as_ref())
            .zip(previous_profile)
            .map(
                |((evidence, interpretation), profile)| index_writer::Previous {
                    evidence,
                    interpretation,
                    profile,
                },
            );
        let mut index_work = IndexPublicationWork::default();
        #[cfg(test)]
        trace_index_admission("index-preparation-before");
        let output = if observation.maintenance.is_some() {
            self.verify_rebuilt_indexes(&candidate, &request.uploads)
                .await?;
            None
        } else if overlay.is_empty() {
            self.maintain_candidate_indexes(&candidate, &request.uploads, previous_index)
                .await?
        } else {
            self.maintain_overlay_candidate_indexes(
                &candidate,
                &request.uploads,
                previous_index,
                &overlay,
                observation,
            )
            .await?
        };
        #[cfg(test)]
        trace_index_admission("index-preparation-after");
        if let Some(output) = output {
            index_work = output.work;
            if output.root != candidate.root {
                index_writer::append_nodes(&mut request.uploads, output.nodes)?;
                request.commit.tree = output.root;
                #[cfg(test)]
                trace_index_admission("completed-candidate-load-before");
                candidate = TreeEvidence::load_tree_for(
                    self.store(),
                    output.root,
                    &request.uploads,
                    self.config().min_chunk_size,
                    candidate.usage,
                )
                .await?;
                #[cfg(test)]
                trace_index_admission("completed-candidate-load-after");
                #[cfg(test)]
                trace_index_admission("completed-candidate-validation-before");
                let checked = self
                    .validate_candidate_observed(
                        reference,
                        CandidateRequest::from(&request),
                        &candidate,
                        CandidateInterpretation::Authoring,
                        previous.as_ref().zip(previous_interpretation.as_ref()).map(
                            |(evidence, interpretation)| CandidatePrevious {
                                evidence,
                                interpretation,
                                commit: previous_commit.as_ref(),
                            },
                        ),
                        observation,
                    )
                    .await?;
                #[cfg(test)]
                trace_index_admission("completed-candidate-validation-after");
                requirements = checked.requirements;
                admin_checks = checked.admin_checks;
                root_claims = checked.root_claims;
            }
        }
        #[cfg(test)]
        trace_index_admission("receipts-and-signing-before");
        let mut parents = if overlay.is_empty() {
            previous_identity.into_iter().collect::<Vec<_>>()
        } else {
            previous_identity
                .into_iter()
                .chain(overlay.iter().map(|(commit, _)| *commit))
                .collect::<Vec<_>>()
        };
        if let Some((identity, _)) = &merged_source {
            parents.push(*identity);
        }
        if request.commit.parents != parents
            || request.commit.profile_pair.recipe.is_some()
                != (merged_source.is_some() || !overlay.is_empty())
        {
            return Err(denied(reference, Verb::Commit));
        }
        let tree = candidate.tree(candidate.root, self.config().min_chunk_size)?;
        let root_properties = tree.props().unwrap_or(&[]);
        let effective = self
            .resolve_authoring(
                &[RootLayer {
                    properties: root_properties,
                    overrides: &[],
                }],
                self.defaults_for(&candidate),
            )
            .map_err(|_| denied(reference, Verb::Commit))?;
        let root_bindings = root_claims;
        let roots = root_bindings
            .iter()
            .map(|(path, domain)| RequestRoot { path, domain })
            .collect::<Vec<_>>();
        let epochs = [(reference, epoch)];
        let context = Request {
            reference: reference.as_bytes(),
            verb: Verb::Commit,
            roots: &roots,
            now,
            surface: &request.surface,
            locality: &self.config().home,
            epochs: &epochs,
        };
        token
            .authorize(&context)
            .map_err(|_| denied(reference, Verb::Commit))?;

        let previous_tree = previous
            .as_ref()
            .map(|previous| previous.tree(previous.root, self.config().min_chunk_size))
            .transpose()?;
        if let (Some(previous_tree), Some(previous)) = (&previous_tree, &previous) {
            let old_effective = previous_interpretation
                .as_ref()
                .ok_or_else(super::invalid)?
                .resolve(
                    &[RootLayer {
                        properties: previous_tree.props().unwrap_or(&[]),
                        overrides: &[],
                    }],
                    self.defaults_for(previous),
                )
                .map_err(|_| denied(reference, Verb::Commit))?;
            if !effective
                .domain()
                .map_err(|_| denied(reference, Verb::Commit))?
                .permits_reference(
                    old_effective
                        .domain()
                        .map_err(|_| denied(reference, Verb::Commit))?,
                )
            {
                return Err(denied(reference, Verb::Commit));
            }
        }

        let candidate_occurrences = candidate.occurrences(self.config().min_chunk_size)?;
        let previous_occurrences = previous
            .as_ref()
            .map(|previous| previous.occurrences(self.config().min_chunk_size))
            .transpose()?
            .unwrap_or_default();
        let merged_occurrences = merged_source
            .as_ref()
            .map(|(_, evidence)| evidence.occurrences(self.config().min_chunk_size))
            .transpose()?
            .unwrap_or_default();
        let mut receipt_map = BTreeMap::new();
        for occurrence in &candidate_occurrences {
            let tree = candidate.tree(occurrence.root, self.config().min_chunk_size)?;
            let old_occurrence = previous_occurrences
                .iter()
                // An exact carried root keeps its own checked producers even
                // when it replaces another root with equal entry bytes. Only a
                // root edited in place inherits from the prior path occurrence;
                // descriptor and graft authority checks remain independent.
                .find(|old| old.root == occurrence.root)
                .or_else(|| {
                    previous_occurrences
                        .iter()
                        .find(|old| old.path == occurrence.path)
                });
            let old_tree = match (previous.as_ref(), old_occurrence) {
                (Some(previous), Some(old)) => {
                    Some(previous.tree(old.root, self.config().min_chunk_size)?)
                }
                _ => None,
            };
            let merged_occurrence = merged_occurrences
                .iter()
                .find(|old| old.path == occurrence.path);
            let merged_tree = match (&merged_source, merged_occurrence) {
                (Some((_, evidence)), Some(old)) => {
                    Some(evidence.tree(old.root, self.config().min_chunk_size)?)
                }
                _ => None,
            };
            for item in tree.iter() {
                let prior = old_tree.as_ref().and_then(|tree| tree.get(&item.key));
                let merged_prior = merged_tree.as_ref().and_then(|tree| tree.get(&item.key));
                let mut source = prior
                    .filter(|entry| provenance::same_content(entry, &item.entry))
                    .and(previous_identity)
                    .map(|commit| EntrySource {
                        commit,
                        root: old_occurrence.map_or(occurrence.root, |old| old.root),
                        path: item.key.clone(),
                    });
                if source.is_none()
                    && merged_prior
                        .is_some_and(|entry| provenance::same_content(entry, &item.entry))
                {
                    let (commit, _) = merged_source.as_ref().ok_or_else(super::invalid)?;
                    source = Some(EntrySource {
                        commit: *commit,
                        root: merged_occurrence.ok_or_else(super::invalid)?.root,
                        path: item.key.clone(),
                    });
                }
                let overlay_prior = layers::overlay_source_entry(
                    &overlay,
                    &occurrence.path,
                    &item.key,
                    self.config().min_chunk_size,
                )?;
                if !overlay.is_empty() {
                    source = overlay_prior
                        .as_ref()
                        .filter(|source| provenance::same_content(&source.entry, &item.entry))
                        .map(|source| EntrySource {
                            commit: source.commit,
                            root: source.root,
                            path: source.path.clone(),
                        });
                }
                if source.is_none() && item.entry.provenance.is_some() {
                    return Err(denied(reference, Verb::Commit));
                }
                let attributes = item
                    .entry
                    .attrs
                    .iter()
                    .map(|attribute| {
                        let preserved = prior.is_some_and(|entry| {
                            entry.attrs.iter().any(|prior| prior == attribute)
                        });
                        let origin = if preserved
                            && prior
                                .is_some_and(|entry| provenance::same_content(entry, &item.entry))
                        {
                            previous_identity
                                .map(|commit| {
                                    EntryOrigin::Source(EntrySource {
                                        commit,
                                        root: old_occurrence
                                            .map_or(occurrence.root, |old| old.root),
                                        path: item.key.clone(),
                                    })
                                })
                                .unwrap_or(EntryOrigin::Current)
                        } else if merged_prior.is_some_and(|entry| {
                            provenance::same_content(entry, &item.entry)
                                && entry.attrs.iter().any(|prior| prior == attribute)
                        }) {
                            match (&merged_source, merged_occurrence) {
                                (Some((commit, _)), Some(old)) => {
                                    EntryOrigin::Source(EntrySource {
                                        commit: *commit,
                                        root: old.root,
                                        path: item.key.clone(),
                                    })
                                }
                                _ => EntryOrigin::Current,
                            }
                        } else {
                            EntryOrigin::Current
                        };
                        let origin = if !overlay.is_empty() {
                            overlay_prior
                                .as_ref()
                                .filter(|source| {
                                    provenance::same_content(&source.entry, &item.entry)
                                        && source.entry.attrs.iter().any(|prior| prior == attribute)
                                })
                                .map_or(EntryOrigin::Current, |source| {
                                    EntryOrigin::Source(EntrySource {
                                        commit: source.commit,
                                        root: source.root,
                                        path: source.path.clone(),
                                    })
                                })
                        } else {
                            origin
                        };
                        (attribute.name.to_owned(), origin)
                    })
                    .collect();
                let receipt = EntryReceipt {
                    root: occurrence.root,
                    path: item.key.clone(),
                    origin: source.map_or(EntryOrigin::Current, EntryOrigin::Source),
                    attributes: Some(attributes),
                    reintroduced_from: None,
                    disclosure_proof: None,
                };
                let key = (occurrence.root, item.key.clone());
                if receipt_map.get(&key).is_some_and(|prior| prior != &receipt) {
                    return Err(denied(reference, Verb::Commit));
                }
                receipt_map.insert(key, receipt);
            }
        }
        let receipts = receipt_map.into_values().collect();

        // Snapshot requirements using canonical values, so later changes do not
        // rewrite the admission rules under which this immutable commit passed.
        let mut required = Vec::new();
        let names = [
            PropertyName::Index,
            PropertyName::Hashes,
            PropertyName::Classify,
            PropertyName::StrictAttrs,
        ];
        terrane_format::cbor::write_map(&mut required, names.len());
        for name in names {
            terrane_format::cbor::write_text(&mut required, name.as_str());
            match effective.get(name) {
                Some(Value::Names(values)) => {
                    terrane_format::cbor::write_array(&mut required, values.len());
                    for value in values {
                        terrane_format::cbor::write_text(&mut required, value);
                    }
                }
                Some(Value::Boolean(value)) => required.push(if *value { 0xf5 } else { 0xf4 }),
                _ => return Err(denied(reference, Verb::Commit)),
            }
        }
        request.commit.profile_pair.required_properties = Some(required);
        request.commit.profile_pair.entry_receipts = Some(receipts);
        request.commit.profile_pair.conflicted =
            Some(candidate.roots.iter().try_fold(false, |conflicted, root| {
                Ok::<_, StoreFailure>(
                    conflicted
                        || candidate
                            .tree(*root, self.config().min_chunk_size)?
                            .has_conflicts(),
                )
            })?);
        request.commit.timestamp = now;
        let authority = token.authority();
        request.commit.provenance = Provenance {
            issuer: authority.issuer.clone(),
            token_id: authority.token_id,
            subject: authority.subject.clone(),
            kind: authority.kind,
            workload_identity: authority.workload.clone(),
            process: request.commit.provenance.process,
            observed_at: now,
            writer_epoch: epoch,
            source: request.commit.provenance.source,
            embedded_token: Some(request.token.clone()),
        };
        request.commit.profile_pair.commit_context = Some(
            CommitContext::from_request(&context).map_err(|_| denied(reference, Verb::Commit))?,
        );
        let commit = provenance::sign_authored(
            request.commit,
            &request.terminal_secret,
            self.keys(),
            &context,
            epoch,
        )
        .map_err(|_| denied(reference, Verb::Commit))?;
        let (admission_interpretation, admission_profile) =
            self.admitted_authoring_inputs(&commit)?;
        #[cfg(test)]
        trace_index_admission("receipts-and-signing-after");
        Ok(AdmittedCommit {
            tree_usage: candidate.usage,
            overlay_sources: Vec::new(),
            #[cfg(unix)]
            cold_fork: None,
            completion_inputs: self.completion_inputs()?,
            existing_owner_references: None,
            index_work,
            commit,
            #[cfg(feature = "std")]
            admission_interpretation,
            #[cfg(feature = "std")]
            admission_profile,
            requirements,
            admin_checks,
            publication_reference: reference.to_owned(),
            publication_paths: root_bindings
                .iter()
                .map(|(path, _)| path.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            uploads: request.uploads,
            expected,
            observed_current: live_record,
            surface: request.surface,
            source_authorization: None,
            token: request.token,
            principal: token.authority().subject.clone(),
            timestamp: now,
            publication_verb: Verb::Commit,
            policy_override: None,
        })
    }

    /// Compares candidate Commit/Admin grants against trusted initial authority.
    pub(super) fn bootstrap_acl_widens(&self, grants: &[(&str, u8)]) -> bool {
        grants.iter().any(|(principal, mask)| {
            let initial = self
                .config()
                .initial_acl
                .iter()
                .filter(|(name, _)| name == principal)
                .fold(0u8, |mask, (_, grant)| mask | grant);
            let authority_bits = |mask| if mask & 16 != 0 { 20 } else { mask & 4 };
            authority_bits(*mask) & !authority_bits(initial) != 0
        })
    }
}
