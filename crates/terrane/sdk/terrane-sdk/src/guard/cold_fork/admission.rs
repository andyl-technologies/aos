//! Signs an unchanged-root fork only from a genuinely qualified source.
//!
//! New authoring inputs are selected independently. Reuse requires the complete
//! supported profile to agree, so old attribute/index evidence cannot be silently
//! grandfathered under a different destination interpretation.

use terrane_format::{
    auth::{Request, RequestRoot, Verb},
    properties::Value,
    provenance,
    refs::{CommitContext, Provenance},
};

use super::*;
use crate::guard::CommitRequest;
use crate::guard::admission::{AdminCheck, AdmittedCommit, SourceAuthorization};
use crate::selected_bridge::native_guard::cold_fork::QualifiedSource;
use crate::store::StoreErrorKind;

impl<F, B, V, C> Guard<HeldBucket<'_, F, B, V, true>, C>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    /// Signs a fresh namespace while retaining the source's exact physical tree.
    ///
    /// # Errors
    /// Rejects uploads/disclosures, changed semantic inputs, denied destination
    /// Commit/bootstrap Admin, invalid signing keys or unsupported physical data.
    pub(crate) async fn admit_qualified_cold_fork(
        &self,
        qualified: &mut QualifiedSource<'_, '_, F>,
        reference: &str,
        epoch: u64,
        original: &crate::guard::RetainedBootstrap,
        mut request: CommitRequest,
    ) -> Result<AdmittedCommit, StoreFailure> {
        if !request.uploads.is_empty()
            || !request.disclosures.is_empty()
            || !request.reference_records.is_empty()
        {
            return Err(denied(reference, Verb::Commit));
        }
        let policies = qualified.policies();
        if self.configured_authoring_registries()? != *policies.source_profile()? {
            return Err(StoreFailure::new(StoreErrorKind::Unsupported));
        }
        let destination = self
            .authorize_cold_fork_destination(
                policies,
                reference,
                epoch,
                &request.token,
                &request.surface,
            )
            .await?;
        let mut admin_checks = Vec::new();
        for view in policies.source_views() {
            for root in &view.roots {
                let widens = with_occurrence_policy(
                    root,
                    view,
                    policies.configuration(),
                    policies.interpretation(view)?,
                    |policy| {
                        let Some(Value::Grants(grants)) =
                            policy.get(terrane_format::properties::PropertyName::Acl)
                        else {
                            return Err(invalid());
                        };
                        Ok(root.path == b"/" && self.bootstrap_acl_widens(grants))
                    },
                )?;
                if widens && admin_checks.is_empty() {
                    let initial = self
                        .config
                        .initial_acl
                        .iter()
                        .map(|(name, mask)| (name.as_str(), *mask))
                        .collect::<Vec<_>>();
                    if !acl_permits(&initial, &destination.token, Verb::Admin) {
                        return Err(denied(reference, Verb::Admin));
                    }
                    let roots = [RequestRoot {
                        path: b"/",
                        domain: destination.root_domains.first().ok_or_else(invalid)?,
                    }];
                    destination
                        .token
                        .authorize(&Request {
                            reference: reference.as_bytes(),
                            verb: Verb::Admin,
                            roots: &roots,
                            now: self.now(reference, Verb::Admin)?,
                            surface: &request.surface,
                            locality: &self.config.home,
                            epochs: &[(reference, epoch)],
                        })
                        .map_err(|_| denied(reference, Verb::Admin))?;
                    admin_checks.push(AdminCheck {
                        alternatives: vec![b"/".to_vec()],
                    });
                }
            }
        }
        request.commit.profile_pair = qualified.commit().commit().profile_pair.clone();
        terrane_format::algebra::fork(
            qualified.commit().commit().tree,
            qualified.commit().identity(),
            policies.source_record().seq,
        )
        .bind_commit(&mut request.commit);
        let now = self.now(reference, Verb::Commit)?;
        let authority = destination.token.authority();
        request.commit.timestamp = now;
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
        let roots = destination
            .root_paths
            .iter()
            .zip(&destination.root_domains)
            .map(|(path, domain)| RequestRoot { path, domain })
            .collect::<Vec<_>>();
        let context = Request {
            reference: reference.as_bytes(),
            verb: Verb::Commit,
            roots: &roots,
            now,
            surface: &request.surface,
            locality: &self.config.home,
            epochs: &[(reference, epoch)],
        };
        request.commit.profile_pair.commit_context =
            Some(CommitContext::from_request(&context).map_err(|_| invalid())?);
        let commit = provenance::sign_authored(
            request.commit,
            &request.terminal_secret,
            self.keys(),
            &context,
            epoch,
        )
        .map_err(|_| denied(reference, Verb::Commit))?;
        check_original_bootstrap(self, policies, &commit, original)?;
        let completion_inputs = self.completion_inputs()?;
        let cold_fork = Some(super::ColdForkBinding::prepared(&commit, policies));
        let (admission_interpretation, admission_profile) =
            self.admitted_authoring_inputs(&commit)?;
        Ok(AdmittedCommit {
            tree_usage: terrane_format::tree_format::TreeUse::Ordinary,
            overlay_sources: Vec::new(),
            #[cfg(unix)]
            existing_owner_references: None,
            index_work: Default::default(),
            commit,
            completion_inputs,
            cold_fork,
            admission_interpretation,
            admission_profile,
            requirements: Vec::new(),
            admin_checks,
            publication_reference: reference.to_owned(),
            publication_paths: destination.root_paths.clone(),
            uploads: Vec::new(),
            expected: None,
            observed_current: None,
            surface: request.surface,
            source_authorization: Some(SourceAuthorization {
                reference: policies.source_name().to_owned(),
                verb: Verb::Fork,
                paths: qualified.authorization().root_paths.clone(),
                record: policies.source_record().clone(),
                cold_route_lifetime: None,
            }),
            token: request.token,
            principal: authority.subject.clone(),
            timestamp: now,
            publication_verb: Verb::Commit,
            policy_override: None,
        })
    }
}

impl<F, B, V, C> Guard<HeldBucket<'_, F, B, V, true>, C>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    /// Checks fresh signed fork data against independently qualified unchanged inputs.
    ///
    /// # Errors
    /// Refuses substituted parents, physical/semantic inputs, copied introduction
    /// receipts, source whole heads, authoring contexts or bootstrap authority.
    pub(crate) async fn check_cold_fork_candidate(
        &self,
        qualified: &mut QualifiedSource<'_, '_, F>,
        admitted: &AdmittedCommit,
        reference: &str,
        epoch: u64,
        original: &crate::guard::RetainedBootstrap,
    ) -> Result<AuthorizedRef, StoreFailure> {
        let policies = qualified.policies();
        let source = admitted.source_authorization.as_ref().ok_or_else(invalid)?;
        let commit = admitted.commit.commit();
        if source.verb != Verb::Fork
            || source.reference != policies.source_name()
            || source.record != *policies.source_record()
            || commit.tree != qualified.commit().commit().tree
            || commit.parents != [qualified.commit().identity()]
            || !admitted.uploads.is_empty()
            || admitted.expected.is_some()
            || admitted.observed_current.is_some()
            || admitted.policy_override.is_some()
        {
            return Err(invalid());
        }
        let mut expected = commit.clone();
        expected.profile_pair = qualified.commit().commit().profile_pair.clone();
        terrane_format::algebra::fork(
            qualified.commit().commit().tree,
            qualified.commit().identity(),
            policies.source_record().seq,
        )
        .bind_commit(&mut expected);
        expected.profile_pair.commit_context = commit.profile_pair.commit_context.clone();
        if expected.tree != commit.tree
            || expected.parents != commit.parents
            || expected.profile_pair != commit.profile_pair
        {
            return Err(invalid());
        }
        let current = self.completion_inputs()?;
        if current != admitted.completion_inputs
            || current.registries != *policies.source_profile()?
        {
            return Err(StoreFailure::new(StoreErrorKind::Unsupported));
        }
        admitted
            .cold_fork
            .as_ref()
            .ok_or_else(invalid)?
            .check(admitted)?;
        let (selected, profile) = self.admitted_authoring_inputs(&admitted.commit)?;
        if profile != admitted.admission_profile || selected != admitted.admission_interpretation {
            return Err(invalid());
        }
        let destination = self
            .authorize_cold_fork_destination(
                policies,
                reference,
                epoch,
                &admitted.token,
                &admitted.surface,
            )
            .await?;
        let roots = destination
            .root_paths
            .iter()
            .zip(&destination.root_domains)
            .map(|(path, domain)| RequestRoot { path, domain })
            .collect::<Vec<_>>();
        let context = commit
            .profile_pair
            .commit_context
            .as_ref()
            .ok_or_else(invalid)?;
        let request = Request {
            reference: reference.as_bytes(),
            verb: Verb::Commit,
            roots: &roots,
            now: commit.timestamp,
            surface: &admitted.surface,
            locality: &self.config.home,
            epochs: &[(reference, epoch)],
        };
        if *context != CommitContext::from_request(&request).map_err(|_| invalid())? {
            return Err(invalid());
        }
        let verified =
            provenance::verify_history(commit, self.keys(), &roots, &[(reference, epoch)])
                .map_err(|_| invalid())?;
        if verified.identity() != admitted.commit.identity() {
            return Err(invalid());
        }
        check_original_bootstrap(self, policies, &verified, original)?;

        // Current configured widening uses only the live operation token. The
        // independently retained Original comparison above exclusively governs
        // historical Admin; current ACL membership cannot supply or deny it.
        for view in policies.source_views() {
            for root in &view.roots {
                if root.path != b"/" {
                    continue;
                }
                let widens = with_occurrence_policy(
                    root,
                    view,
                    policies.configuration(),
                    policies.interpretation(view)?,
                    |policy| {
                        let Some(Value::Grants(grants)) =
                            policy.get(terrane_format::properties::PropertyName::Acl)
                        else {
                            return Err(invalid());
                        };
                        Ok(self.bootstrap_acl_widens(grants))
                    },
                )?;
                if widens {
                    let initial = self
                        .config
                        .initial_acl
                        .iter()
                        .map(|(name, mask)| (name.as_str(), *mask))
                        .collect::<Vec<_>>();
                    if !acl_permits(&initial, &destination.token, Verb::Admin) {
                        return Err(denied(reference, Verb::Admin));
                    }
                    let root_request = [RequestRoot {
                        path: &root.path,
                        domain: destination.root_domains.first().ok_or_else(invalid)?,
                    }];
                    destination
                        .token
                        .authorize(&Request {
                            reference: reference.as_bytes(),
                            verb: Verb::Admin,
                            roots: &root_request,
                            now: self.now(reference, Verb::Admin)?,
                            surface: &admitted.surface,
                            locality: &self.config.home,
                            epochs: &[(reference, epoch)],
                        })
                        .map_err(|_| denied(reference, Verb::Admin))?;
                }
            }
        }
        Ok(destination)
    }

    /// Retains immutable inputs only after genuine cold completion and Original checks.
    ///
    /// # Errors
    /// Rejects changed source/profile/Original coordinates or conflicting retained inputs.
    pub(crate) fn retain_cold_fork_selection(
        &self,
        qualified: &QualifiedSource<'_, '_, F>,
        admitted: &AdmittedCommit,
        original: &crate::guard::OriginalCommitContext,
    ) -> Result<(), StoreFailure> {
        if admitted.commit.commit().tree != qualified.commit().commit().tree
            || admitted.commit.commit().parents != [qualified.commit().identity()]
            || admitted.completion_inputs.registries != *qualified.policies().source_profile()?
            || original.commit() != &admitted.commit.identity()
            || self.original_commit(original.commit())? != *original
        {
            return Err(invalid());
        }
        self.capture_candidate_inputs(admitted)?;
        self.retain_executed_view_inputs(
            admitted.commit.identity(),
            admitted.commit.commit().tree,
            &admitted.completion_inputs,
        )
    }
}

// Core's fresh-authority bootstrap comparison uses separately retained Original
// ACL inputs. Current configuration never supplies that historical baseline.
fn check_original_bootstrap<S, C>(
    guard: &Guard<S, C>,
    policies: &super::QualifiedPolicies,
    verified: &provenance::VerifiedCommit,
    original: &crate::guard::RetainedBootstrap,
) -> Result<(), StoreFailure> {
    let commit = verified.commit();
    let context = commit
        .profile_pair
        .commit_context
        .as_ref()
        .ok_or_else(invalid)?;
    if original.reference() != context.reference()
        || original.epoch() != commit.provenance.writer_epoch
    {
        return Err(invalid());
    }
    let original_token = auth::verify(
        commit
            .provenance
            .embedded_token
            .as_deref()
            .ok_or_else(invalid)?,
        guard.keys(),
        commit.timestamp,
    )
    .map_err(|_| invalid())?;
    for view in policies.source_views() {
        for root in &view.roots {
            if root.path != b"/" {
                continue;
            }
            let widens = with_occurrence_policy(
                root,
                view,
                policies.configuration(),
                policies.interpretation(view)?,
                |policy| {
                    let Some(Value::Grants(grants)) =
                        policy.get(terrane_format::properties::PropertyName::Acl)
                    else {
                        return Err(invalid());
                    };
                    Ok(widens_original_acl(grants, original.acl()))
                },
            )?;
            if widens {
                let domain = occurrence_domain(
                    root,
                    view,
                    policies.configuration(),
                    policies.interpretation(view)?,
                )?;
                let roots = [RequestRoot {
                    path: &root.path,
                    domain: &domain,
                }];
                original_token
                    .authorize(&Request {
                        reference: context.reference().as_bytes(),
                        verb: Verb::Admin,
                        roots: &roots,
                        now: commit.timestamp,
                        surface: context.surface(),
                        locality: context.locality(),
                        epochs: &[(context.reference(), original.epoch())],
                    })
                    .map_err(|_| denied(context.reference(), Verb::Admin))?;
            }
        }
    }
    Ok(())
}

// AUTH22 Admin implies Commit. Repeated protected grants contribute their union,
// just as Core's Original bootstrap comparison does; wire masks remain unchanged.
fn widens_original_acl(grants: &[(&str, u8)], original: &[(String, u8)]) -> bool {
    let administrative_verbs = |mask: u8| if mask & 16 != 0 { 20 } else { mask & 4 };
    grants.iter().any(|(principal, verbs)| {
        let inherited = original
            .iter()
            .filter(|(name, _)| name == principal)
            .fold(0, |mask, (_, verbs)| mask | administrative_verbs(*verbs));
        administrative_verbs(*verbs) & !inherited != 0
    })
}
