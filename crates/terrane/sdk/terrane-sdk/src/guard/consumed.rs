//! Tracks privately consumed canonical policy and protected original controls.
//!
//! A trace is local to one held operation. It records successful checked reads,
//! never accepts a caller dependency list, and does not mint publication authority.
//! Selected Guard/revision and physical checks still belong to the held factory.

use std::collections::BTreeMap;
use std::sync::Mutex;

use terrane_format::gc::publication::evidence::{
    AuthorityGrant, ConsumedViewPolicy, ControlKind, DisclosureRow, GuardSnapshot, IssuerRow,
    LineageUsedInputs, LocalOriginalRegistration, PhysicalRegistration, RequiredControlPin,
    SeededChunkProfile, TrustedGuardConfig,
};

use super::{Guard, OriginalAuthority, OriginalCommitContext, invalid};

mod disclosure_inputs;
mod snapshot_disclosure;
pub(in crate::guard) mod view_interpretation;

use crate::store::StoreFailure;
pub(crate) use snapshot_disclosure::SnapshotDisclosureInputs;

#[derive(Default)]
struct Consumed {
    controls: BTreeMap<Vec<u8>, RequiredControlPin>,
    views: BTreeMap<[u8; 32], ConsumedViewPolicy>,
    contexts: view_interpretation::ViewContextTrace,
    issuers: BTreeMap<(String, String), IssuerRow>,
    #[cfg(unix)]
    historical_issuers: BTreeMap<([u8; 32], [u8; 32]), (IssuerRow, RequiredControlPin)>,
    disclosures: BTreeMap<(String, String, [u8; 32], u64), DisclosureRow>,
}

/// Accumulates checked consumption inside a single actual held observation.
pub(crate) struct ConsumedResolver {
    snapshot: GuardSnapshot,
    completion_authority: OriginalAuthority,
    consumed: Mutex<Consumed>,
}

impl ConsumedResolver {
    /// Reuses only exact successful pure data within this operation's pending trace.
    ///
    /// The caller freshly checks selected inputs, canonical metadata and issuer
    /// evidence before this method. This never completes a history or namespace.
    ///
    /// # Errors
    /// Preserves preparation failures, contradictory pending data and unavailable
    /// synchronization. No failure is cached.
    pub(super) fn prepare_candidate(
        &self,
        key: Option<super::history::candidate_preparation::Key>,
        inputs: &super::history::completion::SelectedInputs,
        commit: &terrane_format::provenance::VerifiedCommit,
        evidence: &super::TreeEvidence,
    ) -> Result<(), StoreFailure> {
        self.consumed
            .lock()
            .map_err(|_| unavailable())?
            .contexts
            .prepare_candidate(key, inputs, commit, evidence)
    }

    /// Reports actual pure preparations and successful reuse in this test resolver.
    ///
    /// # Errors
    /// Reports unavailable trace synchronization.
    #[cfg(all(test, feature = "tokio", unix))]
    pub(in crate::guard) fn candidate_preparation_work(
        &self,
    ) -> Result<(usize, usize), StoreFailure> {
        Ok(self
            .consumed
            .lock()
            .map_err(|_| unavailable())?
            .contexts
            .candidate_preparation_work())
    }

    /// Observes an actual pending row without constructing completion evidence.
    ///
    /// # Errors
    /// Reports unavailable trace synchronization.
    #[cfg(all(test, feature = "tokio", unix))]
    pub(in crate::guard) fn candidate_preparation_pending(
        &self,
        view: terrane_format::identity::Digest,
    ) -> Result<Option<super::history::completion::PendingViewUse>, StoreFailure> {
        Ok(self
            .consumed
            .lock()
            .map_err(|_| unavailable())?
            .contexts
            .candidate_preparation_pending(view))
    }

    /// Injects issuer retirement into this isolated test resolver's actual verifier inputs.
    #[cfg(all(test, feature = "tokio", unix))]
    pub(in crate::guard) fn candidate_preparation_issuer_retirement(
        &mut self,
        retirement: Option<u64>,
    ) {
        for issuer in &mut self.snapshot.issuers {
            issuer.retired_at = retirement;
        }
    }

    /// Starts a trace from the concrete factory's complete trusted configuration.
    ///
    /// # Errors
    /// Rejects invalid configuration encodings; this alone establishes no fresh authority.
    pub(crate) fn new<S, C>(
        guard: &Guard<S, C>,
        authority: &OriginalAuthority,
    ) -> Result<Self, StoreFailure> {
        Self::for_registration(guard, registration(authority), authority)
    }

    /// Captures ordinary disclosure inputs from the actual native configuration.
    ///
    /// The producer holds and revalidates the native controls separately. Only
    /// public role rows are retained; no Original or completion capability is copied.
    ///
    /// # Errors
    /// Rejects unavailable retained trust or conflicting disclosure selectors.
    pub(crate) fn snapshot_disclosure_inputs<S, C>(
        guard: &Guard<S, C>,
    ) -> Result<SnapshotDisclosureInputs, StoreFailure> {
        disclosure_inputs::capture(guard)
    }

    /// Reconstructs configuration with separately captured ordinary disclosure inputs.
    ///
    /// The private producer retains actual native controls and independently
    /// rechecks source, Original and current request authority. These rows never
    /// initialize any of those capabilities or select historical semantics.
    ///
    /// # Errors
    /// Rejects malformed complete configuration or snapshot encodings.
    pub(crate) fn new_with_snapshot_disclosures<S, C>(
        guard: &Guard<S, C>,
        authority: &OriginalAuthority,
        disclosures: &SnapshotDisclosureInputs,
    ) -> Result<Self, StoreFailure> {
        Self::for_registration_with_disclosures(
            guard,
            registration(authority),
            authority,
            Some(disclosures),
        )
    }

    // Kept private: supplied registration is data for comparing configured
    // snapshots, never a caller original-authority or root-history factory.
    fn for_registration<S, C>(
        guard: &Guard<S, C>,
        binding: PhysicalRegistration,
        completion_authority: &OriginalAuthority,
    ) -> Result<Self, StoreFailure> {
        Self::for_registration_with_disclosures(guard, binding, completion_authority, None)
    }

    fn for_registration_with_disclosures<S, C>(
        guard: &Guard<S, C>,
        binding: PhysicalRegistration,
        completion_authority: &OriginalAuthority,
        supplied_disclosures: Option<&SnapshotDisclosureInputs>,
    ) -> Result<Self, StoreFailure> {
        if binding != registration(completion_authority) {
            return Err(invalid());
        }
        let config = guard.config();
        let profile = &config.chunk_profile;
        // Historical authoring fences never choose the complete current snapshot.
        let registries = guard.configured_current_registries()?;
        let configuration = TrustedGuardConfig {
            store_name: config.store_name.clone(),
            private_domain_hint: config.private_domain.clone(),
            home: config.home.clone(),
            initial_acl: config
                .initial_acl
                .iter()
                .map(|(principal, verbs)| AuthorityGrant {
                    principal: principal.clone(),
                    verbs: *verbs,
                })
                .collect(),
            minimum_chunk_size: config.min_chunk_size,
            storage_domain: config.storage_domain.clone(),
            chunk_profile_name: config.chunk_profile_name.clone(),
            chunk_profile: SeededChunkProfile {
                minimum: profile.minimum() as u64,
                target: profile.target() as u64,
                maximum: profile.maximum() as u64,
                window: profile.window(),
                normalization: profile.normalization(),
                seed: profile.seed(),
            },
            policy_authority: config.policy_authority.clone(),
        };
        let mut issuers = guard
            .keys()
            .iter()
            .map(|key| IssuerRow {
                issuer: key.issuer.clone(),
                key_id: key.key_id.clone(),
                public_key: key.public_key,
                retired_at: key.retirement,
            })
            .collect::<Vec<_>>();
        issuers.sort_by(|left, right| {
            (&left.issuer, &left.key_id).cmp(&(&right.issuer, &right.key_id))
        });
        let mut issuer_map = BTreeMap::new();
        for key in issuers {
            if issuer_map
                .insert((key.issuer.clone(), key.key_id.clone()), key)
                .is_some()
            {
                return Err(invalid());
            }
        }
        let captured_disclosures;
        let disclosures = match supplied_disclosures {
            Some(disclosures) => disclosures,
            None => {
                captured_disclosures = disclosure_inputs::capture(guard)?;
                &captured_disclosures
            }
        };
        let snapshot = GuardSnapshot {
            registration: binding,
            issuers: issuer_map.into_values().collect(),
            disclosures: disclosures.rows().to_vec(),
            configuration,
            registries,
        };
        let resolver = Self {
            snapshot,
            completion_authority: completion_authority.clone(),
            consumed: Mutex::new(Consumed::default()),
        };
        resolver.snapshot_bytes()?;
        Ok(resolver)
    }

    /// Checks that the historical Guard has this exact actual configured snapshot.
    ///
    /// # Errors
    /// Rejects different configuration, issuers, retained trust, disclosure roles
    /// or registry inputs and preserves canonical snapshot/retained-read failures.
    /// The retained registration is used only for equality; no new authority or
    /// caller registration constructor is exposed.
    pub(crate) fn check_guard<S, C>(&self, guard: &Guard<S, C>) -> Result<(), StoreFailure> {
        let configured = Self::for_registration(
            guard,
            self.snapshot.registration.clone(),
            &self.completion_authority,
        )?;
        if configured.snapshot_bytes()? != self.snapshot_bytes()? {
            return Err(invalid());
        }
        Ok(())
    }

    /// Encodes the complete concrete configuration as untrusted snapshot data.
    ///
    /// These bytes require independent selected-Guard and fresh physical binding
    /// checks; serialization alone does not install trust or certify lineage.
    ///
    /// # Errors
    /// Rejects a malformed complete configuration or registration encoding.
    pub(crate) fn snapshot_bytes(&self) -> Result<Vec<u8>, StoreFailure> {
        self.snapshot.encode().map_err(|_| invalid())
    }

    /// Records the configured issuer used by an actual successful live request.
    ///
    /// # Errors
    /// Rejects a missing or ambiguous configured key and poisoned synchronization.
    pub(crate) fn operation(&self, authorized: &super::AuthorizedRef) -> Result<(), StoreFailure> {
        let authority = authorized.token.authority();
        let mut matching = self
            .snapshot
            .issuers
            .iter()
            .filter(|key| key.issuer == authority.issuer && key.key_id == authority.key_id);
        let key = matching.next().ok_or_else(invalid)?.clone();
        if matching.next().is_some() {
            return Err(invalid());
        }
        self.consumed
            .lock()
            .map_err(|_| unavailable())?
            .issuers
            .insert((key.issuer.clone(), key.key_id.clone()), key);
        Ok(())
    }

    /// Records the exact issuer selected by a successfully verified embedded token.
    ///
    /// # Errors
    /// Rejects missing or ambiguous configured issuer rows and poisoned synchronization.
    pub(crate) fn issuer(
        &self,
        commit: &terrane_format::provenance::VerifiedCommit,
    ) -> Result<(), StoreFailure> {
        let token = terrane_format::auth::Token::decode(
            commit
                .commit()
                .provenance
                .embedded_token
                .as_deref()
                .ok_or_else(invalid)?,
        )
        .map_err(|_| invalid())?;
        let keys = self
            .snapshot
            .issuers
            .iter()
            .map(|key| terrane_format::auth::IssuerKey {
                issuer: key.issuer.clone(),
                key_id: key.key_id.clone(),
                public_key: key.public_key,
                retirement: key.retired_at,
            })
            .collect::<Vec<_>>();
        let token = token
            .verify(&keys, commit.commit().timestamp)
            .map_err(|_| invalid())?;
        let mut matching = self.snapshot.issuers.iter().filter(|key| {
            key.issuer == token.authority().issuer && key.key_id == token.authority().key_id
        });
        let key = matching.next().ok_or_else(invalid)?.clone();
        if matching.next().is_some() {
            return Err(invalid());
        }
        self.consumed
            .lock()
            .map_err(|_| unavailable())?
            .issuers
            .insert((key.issuer.clone(), key.key_id.clone()), key);
        Ok(())
    }

    /// Records a foreign issuer within its exact retained original import scope.
    ///
    /// Local operation and historical keys remain in the local snapshot. Foreign
    /// public keys and retirement bounds are exhaustively retained through the
    /// existing import-trust pin, with its import, binding and original context.
    ///
    /// # Errors
    /// Rejects invalid historical tokens, missing scoped trust pins, contradictory
    /// keys or retirement bounds and unavailable trace synchronization.
    #[cfg(unix)]
    pub(crate) fn historical_issuer(
        &self,
        commit: &terrane_format::provenance::VerifiedCommit,
        original: &OriginalCommitContext,
    ) -> Result<(), StoreFailure> {
        let Some(keys) = original.historical_keys()? else {
            return self.issuer(commit);
        };
        if original.commit() != &commit.identity() {
            return Err(invalid());
        }
        let token = terrane_format::auth::Token::decode(
            commit
                .commit()
                .provenance
                .embedded_token
                .as_deref()
                .ok_or_else(invalid)?,
        )
        .map_err(|_| invalid())?;
        let token = token
            .verify(&keys, commit.commit().timestamp)
            .map_err(|_| invalid())?;
        let mut matching = keys.iter().filter(|key| {
            key.issuer == token.authority().issuer && key.key_id == token.authority().key_id
        });
        let key = matching.next().ok_or_else(invalid)?;
        if matching.next().is_some() {
            return Err(invalid());
        }
        let row = IssuerRow {
            issuer: key.issuer.clone(),
            key_id: key.key_id.clone(),
            public_key: key.public_key,
            retired_at: key.retirement,
        };
        let pins = super::original::consumed_pins(original)?;
        let mut trusts = pins
            .into_iter()
            .filter(|pin| pin.kind == ControlKind::ImportTrust);
        let trust = trusts.next().ok_or_else(invalid)?;
        if trusts.next().is_some() {
            return Err(invalid());
        }
        self.original(original)?;
        let selector = (*original.baseline().authority().id(), commit.identity());
        let value = (row, trust);
        let mut consumed = self.consumed.lock().map_err(|_| unavailable())?;
        if consumed
            .historical_issuers
            .get(&selector)
            .is_some_and(|prior| prior != &value)
        {
            return Err(invalid());
        }
        consumed.historical_issuers.insert(selector, value);
        Ok(())
    }

    /// Records only a role selected by a completed disclosure boundary.
    ///
    /// # Errors
    /// Rejects an absent configured row, ambiguous historical windows or poisoned state.
    pub(crate) fn disclosure(
        &self,
        boundary: &terrane_format::provenance::VerifiedDisclosureBoundary,
    ) -> Result<(), StoreFailure> {
        let mut matching = self.snapshot.disclosures.iter().filter(|row| {
            row.repository == boundary.authority_repository()
                && row.domain == boundary.authority_domain()
                && &row.public_key == boundary.authority_key()
                && row.not_before <= boundary.observed_at()
                && row.not_after.is_none_or(|end| boundary.observed_at() < end)
        });
        let row = matching.next().ok_or_else(invalid)?.clone();
        if matching.next().is_some() {
            return Err(invalid());
        }
        let selector = (
            row.repository.clone(),
            row.domain.clone(),
            row.public_key,
            row.not_before,
        );
        self.consumed
            .lock()
            .map_err(|_| unavailable())?
            .disclosures
            .insert(selector, row);
        Ok(())
    }

    /// Records prepared data without claiming signed-history completion.
    ///
    /// # Errors
    /// Rejects contradictory repeated inputs or unavailable synchronization.
    pub(super) fn pending_view(
        &self,
        pending: &super::history::completion::PendingViewUse,
    ) -> Result<(), StoreFailure> {
        self.consumed
            .lock()
            .map_err(|_| unavailable())?
            .contexts
            .pending(pending)
    }

    /// Refuses completion retained outside this concrete factory after Original verification.
    ///
    /// # Errors
    /// Refuses a genuine Original context retained by another concrete factory.
    /// Imported historical authority remains independently verified and does not
    /// replace the actual local owner of its protected retention records.
    /// Ordinary Original/control consumption remains a separate operation.
    pub(super) fn check_completion_original(
        &self,
        context: &OriginalCommitContext,
    ) -> Result<(), StoreFailure> {
        if !context.retained_by(&self.completion_authority) {
            return Err(StoreFailure::new(crate::store::StoreErrorKind::Unsupported));
        }
        Ok(())
    }

    /// Observes genuine completed contexts for finite native history fault tests.
    ///
    /// # Errors
    /// Reports poisoned synchronization; this readonly observation completes nothing.
    #[cfg(all(test, feature = "tokio", unix))]
    pub(crate) fn observed_completed_view_contexts_for_tests(
        &self,
    ) -> Result<
        Vec<terrane_format::gc::publication::evidence::ConsumedViewInterpretation>,
        StoreFailure,
    > {
        Ok(self
            .consumed
            .lock()
            .map_err(|_| unavailable())?
            .contexts
            .observed_completed())
    }

    /// Atomically consumes only the owning full-history completion results.
    ///
    /// # Errors
    /// Rejects absent preparation, contradictory repeated views, or unavailable
    /// synchronization without partially promoting this invocation's views.
    pub(super) fn complete_views(
        &self,
        completed: &[super::history::CompletedViewUse],
    ) -> Result<(), StoreFailure> {
        let mut consumed = self.consumed.lock().map_err(|_| unavailable())?;
        let mut contexts = consumed.contexts.clone();
        let mut views = consumed.views.clone();
        for view in completed {
            contexts.complete(view)?;
            let policy = view.prepared().policy();
            if views.get(&policy.view).is_some_and(|old| old != policy) {
                return Err(invalid());
            }
            views.insert(policy.view, policy.clone());
        }
        consumed.contexts = contexts;
        consumed.views = views;
        Ok(())
    }

    /// Consumes authenticated namespace dependencies without index-serving proof.
    ///
    /// # Errors
    /// Rejects contradictory preparation and policy; commits no partial trace.
    pub(super) fn namespace_views(
        &self,
        checked: &[super::history::SourceResolvedViewUse],
    ) -> Result<(), StoreFailure> {
        let mut consumed = self.consumed.lock().map_err(|_| unavailable())?;
        let mut contexts = consumed.contexts.clone();
        let mut views = consumed.views.clone();
        for view in checked {
            contexts.namespace(view)?;
            let policy = view.prepared().policy();
            if views.get(&policy.view).is_some_and(|old| old != policy) {
                return Err(invalid());
            }
            views.insert(policy.view, policy.clone());
        }
        consumed.contexts = contexts;
        consumed.views = views;
        Ok(())
    }

    /// Records the actual destination registration freshly checked by its factory.
    ///
    /// # Errors
    /// Rejects contradictory control bytes or unavailable trace synchronization.
    pub(crate) fn registration(&self, authority: &OriginalAuthority) -> Result<(), StoreFailure> {
        let owner = registration(authority);
        let bytes = owner.encode().map_err(|_| invalid())?;
        let pin = RequiredControlPin {
            kind: ControlKind::Registration,
            owner,
            key: "registration.cbor".into(),
            digest: *blake3::hash(&bytes).as_bytes(),
        };
        pin.check_record(&bytes).map_err(|_| invalid())?;
        let mut selector = pin.owner.encode().map_err(|_| invalid())?;
        selector.extend_from_slice(pin.key.as_bytes());
        let mut consumed = self.consumed.lock().map_err(|_| unavailable())?;
        if consumed
            .controls
            .get(&selector)
            .is_some_and(|old| old != &pin)
        {
            return Err(invalid());
        }
        consumed.controls.insert(selector, pin);
        Ok(())
    }

    /// Records only rows derived from freshly checked opaque original context.
    ///
    /// # Errors
    /// Rejects contradictory exact records and unavailable synchronization.
    pub(crate) fn original(&self, context: &OriginalCommitContext) -> Result<(), StoreFailure> {
        let pins = super::original::consumed_pins(context)?;
        let mut consumed = self.consumed.lock().map_err(|_| unavailable())?;
        for pin in pins {
            let mut selector = pin.owner.encode().map_err(|_| invalid())?;
            selector.extend_from_slice(pin.key.as_bytes());
            if consumed
                .controls
                .get(&selector)
                .is_some_and(|old| old != &pin)
            {
                return Err(invalid());
            }
            consumed.controls.insert(selector, pin);
        }
        Ok(())
    }

    /// Copies actual recorded pins without finalizing any view context.
    ///
    /// Rows retain finish's canonical kind/owner/key order. No completed lineage
    /// or permission is constructed by this controls-only observation.
    ///
    /// # Errors
    /// Refuses poisoned trace state or invalid canonical owner encoding.
    pub(crate) fn control_pins(&self) -> Result<Vec<RequiredControlPin>, StoreFailure> {
        let consumed = self.consumed.lock().map_err(|_| unavailable())?;
        canonical_control_pins(&consumed)
    }

    /// Requires full auxiliary completion of an exact signed lineage source.
    ///
    /// # Errors
    /// Rejects absent completion, source-only ancestry or mismatched signed data.
    pub(crate) fn check_completed_target(
        &self,
        commit: &terrane_format::provenance::VerifiedCommit,
    ) -> Result<(), StoreFailure> {
        let consumed = self.consumed.lock().map_err(|_| unavailable())?;
        consumed.contexts.require_completed(commit)
    }

    /// Validates recorded ordinary inputs without converting them to authority.
    ///
    /// # Errors
    /// Rejects invalid canonical records or poisoned synchronization.
    pub(crate) fn finish(&self) -> Result<LineageUsedInputs, StoreFailure> {
        let consumed = self.consumed.lock().map_err(|_| unavailable())?;
        #[cfg(unix)]
        for (_, trust) in consumed.historical_issuers.values() {
            if !consumed.controls.values().any(|pin| pin == trust) {
                return Err(invalid());
            }
        }
        let controls = canonical_control_pins(&consumed)?;
        let views = consumed.views.values().cloned().collect::<Vec<_>>();
        let contexts = consumed.contexts.finish()?;
        let inputs = LineageUsedInputs {
            issuers: consumed.issuers.values().cloned().collect(),
            disclosures: consumed.disclosures.values().cloned().collect(),
            controls,
            registries: self.snapshot.registries.clone(),
            configuration: self.snapshot.configuration.clone(),
            views,
            view_interpretations: Some(contexts),
        };
        inputs.encode().map_err(|_| invalid())?;
        inputs
            .check_supported_view_contexts()
            .map_err(|_| invalid())?;
        Ok(inputs)
    }
}

// Keeps early physical-retention order identical to final lineage order while
// leaving view completion, issuers, contexts and lineage validation to finish.
fn canonical_control_pins(consumed: &Consumed) -> Result<Vec<RequiredControlPin>, StoreFailure> {
    let mut keyed = consumed
        .controls
        .values()
        .map(|pin| {
            Ok((
                (
                    pin.kind,
                    pin.owner.encode().map_err(|_| invalid())?,
                    pin.key.clone(),
                ),
                pin.clone(),
            ))
        })
        .collect::<Result<Vec<_>, StoreFailure>>()?;
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(keyed.into_iter().map(|(_, pin)| pin).collect())
}

/// Derives canonical local registration data from an already verified opaque authority.
///
/// This immutable reconstruction grants no new original or publication authority.
pub(crate) fn registration(authority: &OriginalAuthority) -> PhysicalRegistration {
    let (root, coordination) = authority.physical_identity();
    PhysicalRegistration::Local(LocalOriginalRegistration {
        original_id: *authority.id(),
        root: authority.root().as_os_str().as_encoded_bytes().to_vec(),
        domain: authority.domain().to_owned(),
        root_device: root.0,
        root_inode: root.1,
        coordination_device: coordination.0,
        coordination_inode: coordination.1,
        control: authority.control().as_os_str().as_encoded_bytes().to_vec(),
    })
}

fn unavailable() -> StoreFailure {
    StoreFailure::new(crate::store::StoreErrorKind::Unavailable { retry_after: None })
}
