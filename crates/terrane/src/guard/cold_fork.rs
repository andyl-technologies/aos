//! Owns current-policy checks for privately qualified native cold-fork inputs.
//!
//! Retained lineage bytes alone do not establish current operation authority.

mod admission;

use terrane_core::auth::{self, Request, RequestRoot, Verb};
use terrane_core::cbor::Decoder;
use terrane_core::gc::publication::evidence::{ConsumedRootPolicy, ConsumedViewPolicy};
use terrane_core::properties::{Defaults, EffectiveProperties, RootLayer};
use terrane_core::refs::RefName;
use terrane_core::tree_format::{MAX_NODE_ITEMS_BYTES, Property};

use super::history::completion::InterpretationSelection;
use super::{AuthorizedRef, Guard, acl_permits, denied, domain_label, invalid};
use crate::bucket::BucketBinding;
use crate::bucket::held::HeldBucket;
use crate::selected_bridge::native_guard::cold_fork::QualifiedPolicies;
use crate::store::{Clock, ContentValidator, LocalFs, RefStore, StoreErrorKind, StoreFailure};

/// Resolves a previously qualified occurrence without opening its TreeNode.
///
/// # Errors
/// Rejects malformed canonical property maps or unresolved effective domains.
pub(crate) fn occurrence_domain<S, C>(
    guard: &Guard<S, C>,
    occurrence: &ConsumedRootPolicy,
    view: &ConsumedViewPolicy,
    configuration: &terrane_core::gc::publication::evidence::TrustedGuardConfig,
) -> Result<String, StoreFailure> {
    with_occurrence_policy(guard, occurrence, view, configuration, |policy| {
        Ok(domain_label(policy).map_err(|_| invalid())?.to_owned())
    })
}

/// Resolves retained layers using this Guard's actual Legacy constructor selection.
///
/// The callback borrows effective values only while the decoded layer owners
/// remain alive. Neither lineage labels nor a missing association select legacy.
///
/// # Errors
/// Rejects malformed maps, invalid effective properties or callback refusals.
pub(crate) fn with_occurrence_policy<S, C, T>(
    guard: &Guard<S, C>,
    occurrence: &ConsumedRootPolicy,
    view: &ConsumedViewPolicy,
    configuration: &terrane_core::gc::publication::evidence::TrustedGuardConfig,
    use_policy: impl FnOnce(&EffectiveProperties<'_>) -> Result<T, StoreFailure>,
) -> Result<T, StoreFailure> {
    let (properties, overrides) = decode_layers(occurrence)?;
    let layers = properties
        .iter()
        .zip(&overrides)
        .map(|(properties, overrides)| RootLayer {
            properties,
            overrides,
        })
        .collect::<Vec<_>>();
    match guard.interpretation {
        InterpretationSelection::Legacy => {}
        InterpretationSelection::Active => {
            return Err(StoreFailure::new(StoreErrorKind::Unsupported));
        }
    }
    let policy = terrane_core::properties::resolve(
        &layers,
        Defaults {
            store: &configuration.store_name,
            private_domain: &view.default_domain,
            home: configuration.home.region.as_deref().unwrap_or("local"),
        },
    )
    .map_err(|_| invalid())?;
    use_policy(&policy)
}

fn property_map(bytes: &[u8]) -> Result<Vec<Property<'_>>, StoreFailure> {
    let mut decoder = Decoder::new(bytes);
    let count = decoder.map(MAX_NODE_ITEMS_BYTES).map_err(|_| invalid())?;
    let mut properties = Vec::with_capacity(count);
    for _ in 0..count {
        let name = decoder.text(255).map_err(|_| invalid())?;
        let value = decoder
            .raw_value(MAX_NODE_ITEMS_BYTES)
            .map_err(|_| invalid())?;
        properties.push(Property { name, value });
    }
    decoder.finish().map_err(|_| invalid())?;
    Ok(properties)
}

type PolicyLayers<'a> = (Vec<Vec<Property<'a>>>, Vec<Vec<Property<'a>>>);

fn decode_layers(occurrence: &ConsumedRootPolicy) -> Result<PolicyLayers<'_>, StoreFailure> {
    let mut properties = Vec::with_capacity(occurrence.layers.len());
    let mut overrides = Vec::with_capacity(occurrence.layers.len());
    for layer in &occurrence.layers {
        properties.push(property_map(&layer.properties)?);
        overrides.push(property_map(&layer.overrides)?);
    }
    Ok((properties, overrides))
}

impl<F, B, V, C> Guard<HeldBucket<'_, F, B, V, true>, C>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    /// Checks every current source root against actual held lineage and live credentials.
    ///
    /// # Errors
    /// Rejects another Guard configuration, changed whole source head, token
    /// expiry, locality or epoch caveats, and any current root ACL denial.
    pub(crate) async fn authorize_cold_fork_source(
        &self,
        policies: &QualifiedPolicies,
        token: &[u8],
        surface: &str,
    ) -> Result<AuthorizedRef, StoreFailure> {
        policies.check_guard(self)?;
        policies.check_backend(&self.store().identity_proof())?;
        let reference = policies.source_name();
        let record = self.store().ref_get(reference).await?;
        if record.as_ref() != Some(policies.source_record())
            || policies.source_record().home != self.config.home
        {
            return Err(denied(reference, Verb::Fork));
        }
        let now = self.now(reference, Verb::Fork)?;
        let verified =
            auth::verify(token, self.keys(), now).map_err(|_| denied(reference, Verb::Fork))?;
        let mut occurrences = std::collections::BTreeMap::new();
        for view in policies.source_views() {
            for occurrence in &view.roots {
                let domain = with_occurrence_policy(
                    self,
                    occurrence,
                    view,
                    policies.configuration(),
                    |policy| {
                        self.check_acl(&verified, policy, reference, Verb::Fork)?;
                        Ok(domain_label(policy).map_err(|_| invalid())?.to_owned())
                    },
                )?;
                if occurrences
                    .insert(occurrence.path.clone(), domain.clone())
                    .is_some_and(|old| old != domain)
                {
                    return Err(invalid());
                }
            }
        }
        let (paths, domains): (Vec<_>, Vec<_>) = occurrences.into_iter().unzip();
        let roots = paths
            .iter()
            .zip(&domains)
            .map(|(path, domain)| RequestRoot { path, domain })
            .collect::<Vec<_>>();
        verified
            .authorize(&Request {
                reference: reference.as_bytes(),
                verb: Verb::Fork,
                roots: &roots,
                now,
                surface,
                locality: &self.config.home,
                epochs: &[(reference, policies.source_record().writer_epoch)],
            })
            .map_err(|_| denied(reference, Verb::Fork))?;

        let authorized = AuthorizedRef {
            reference: reference.to_owned(),
            record,
            token: verified,
            verb: Verb::Fork,
            root_paths: paths,
            root_domains: domains,
            surface: surface.to_owned(),
            token_bytes: token.to_vec(),
        };
        self.refresh_authorized_time(&authorized)?;
        Ok(authorized)
    }

    /// Checks first-publication authority separately from the source's Fork grant.
    ///
    /// The absent destination uses its trusted bootstrap ACL, never the source
    /// ACL as destination authority. Its token must cover every copied root's
    /// effective domain at the new writer epoch.
    ///
    /// # Errors
    /// Rejects an existing destination, malformed ref, changed configuration,
    /// bootstrap ACL denial, expired credentials, or uncovered root/epoch caveats.
    pub(crate) async fn authorize_cold_fork_destination(
        &self,
        policies: &QualifiedPolicies,
        reference: &str,
        epoch: u64,
        token: &[u8],
        surface: &str,
    ) -> Result<AuthorizedRef, StoreFailure> {
        policies.check_guard(self)?;
        policies.check_backend(&self.store().identity_proof())?;
        RefName::parse(reference).map_err(|_| denied(reference, Verb::Commit))?;
        let record = self.store().ref_get(reference).await?;
        if record.is_some() {
            return Err(denied(reference, Verb::Commit));
        }
        let now = self.now(reference, Verb::Commit)?;
        let verified =
            auth::verify(token, self.keys(), now).map_err(|_| denied(reference, Verb::Commit))?;
        let initial = self
            .config
            .initial_acl
            .iter()
            .map(|(name, mask)| (name.as_str(), *mask))
            .collect::<Vec<_>>();
        if !acl_permits(&initial, &verified, Verb::Commit) {
            return Err(denied(reference, Verb::Commit));
        }
        let mut occurrences = std::collections::BTreeMap::new();
        for view in policies.source_views() {
            for root in &view.roots {
                let domain = occurrence_domain(self, root, view, policies.configuration())?;
                if occurrences
                    .insert(root.path.clone(), domain.clone())
                    .is_some_and(|old| old != domain)
                {
                    return Err(invalid());
                }
            }
        }
        let (paths, domains): (Vec<_>, Vec<_>) = occurrences.into_iter().unzip();
        let roots = paths
            .iter()
            .zip(&domains)
            .map(|(path, domain)| RequestRoot { path, domain })
            .collect::<Vec<_>>();
        verified
            .authorize(&Request {
                reference: reference.as_bytes(),
                verb: Verb::Commit,
                roots: &roots,
                now,
                surface,
                locality: &self.config.home,
                epochs: &[(reference, epoch)],
            })
            .map_err(|_| denied(reference, Verb::Commit))?;
        let authorized = AuthorizedRef {
            reference: reference.to_owned(),
            record,
            token: verified,
            verb: Verb::Commit,
            root_paths: paths,
            root_domains: domains,
            surface: surface.to_owned(),
            token_bytes: token.to_vec(),
        };
        // The operation's absent-head request and the signed new epoch are
        // distinct. The final native writer fence must retain the latter.
        self.refresh_authorized_time(&authorized)?;
        Ok(authorized)
    }
}

/// Routes a genuinely cold-prepared candidate by its exact operation identity.
///
/// This owns no authority, coverage or selected interpretation. Private admission
/// alone constructs it; final publication always performs new source qualification.
pub(crate) struct ColdForkBinding {
    candidate: terrane_core::identity::Digest,
    source: String,
    record: terrane_core::refs::RefRecord,
}

impl ColdForkBinding {
    /// Captures exact routing coordinates after actual private cold admission.
    pub(in crate::guard) fn prepared(
        candidate: &terrane_core::provenance::VerifiedCommit,
        policies: &QualifiedPolicies,
    ) -> Self {
        Self {
            candidate: candidate.identity(),
            source: policies.source_name().to_owned(),
            record: policies.source_record().clone(),
        }
    }

    /// Refuses substitution while granting no eligibility to the matched operation.
    ///
    /// # Errors
    /// Rejects a different signed candidate, source operation or whole source head.
    pub(crate) fn check(
        &self,
        admitted: &crate::guard::AdmittedCommit,
    ) -> Result<(), StoreFailure> {
        let source = admitted.source_authorization.as_ref().ok_or_else(invalid)?;
        if self.candidate != admitted.commit.identity()
            || self.source != source.reference
            || self.record != source.record
            || source.verb != Verb::Fork
        {
            return Err(invalid());
        }
        Ok(())
    }
}

/// Projects the fresh candidate's independently executed actual Legacy inputs.
///
/// This ordinary data projection cannot qualify a source or mint completed history.
/// Only the selected producer derives candidate rows after fresh signature/Original
/// checks and exact unchanged-root fork recomputation.
///
/// # Errors
/// Rejects changed actual inputs, unsupported physical/profile meanings or signed
/// candidate context mismatches. No decoded context selects an implementation.
pub(crate) fn candidate_context<S, C>(
    guard: &Guard<S, C>,
    admitted: &crate::guard::AdmittedCommit,
) -> Result<terrane_core::gc::publication::evidence::ConsumedViewInterpretation, StoreFailure> {
    let actual = guard.completion_inputs()?;
    if actual != admitted.completion_inputs {
        return Err(invalid());
    }
    let context = terrane_core::gc::publication::evidence::ConsumedViewInterpretation {
        view: admitted.commit.identity(),
        original_root: admitted.commit.commit().tree,
        mode: match guard.interpretation {
            InterpretationSelection::Legacy => {
                terrane_core::gc::publication::evidence::ViewInterpretationMode::Legacy
            }
            InterpretationSelection::Active => {
                return Err(StoreFailure::new(StoreErrorKind::Unsupported));
            }
        },
        registries: actual.registries,
    };
    context
        .check_signed_view_data(admitted.commit.commit())
        .map_err(|_| invalid())?;
    context
        .check_supported_interpretation()
        .map_err(|_| invalid())?;
    Ok(context)
}
