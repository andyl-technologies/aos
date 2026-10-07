//! Tracks privately consumed canonical policy and protected original controls.
//!
//! A trace is local to one held operation. It records successful checked reads,
//! never accepts a caller dependency list, and does not mint publication authority.
//! Selected Guard/revision and physical checks still belong to the held factory.

mod view_interpretation;

use std::collections::BTreeMap;
use std::sync::Mutex;

use terrane_core::gc::publication::evidence::{
    AuthorityGrant, ConsumedViewPolicy, ControlKind, GuardSnapshot, IssuerRow, LineageUsedInputs,
    LocalOriginalRegistration, PhysicalRegistration, RequiredControlPin, SeededChunkProfile,
    TrustedGuardConfig,
};

use super::{Guard, OriginalAuthority, OriginalCommitContext, invalid};
use crate::store::StoreFailure;

#[derive(Default)]
struct Consumed {
    controls: BTreeMap<Vec<u8>, RequiredControlPin>,
    views: BTreeMap<[u8; 32], ConsumedViewPolicy>,
    contexts: view_interpretation::ViewContextTrace,
    issuers: BTreeMap<(String, String), IssuerRow>,
}

/// Accumulates checked consumption inside a single actual held observation.
pub(crate) struct ConsumedResolver {
    snapshot: GuardSnapshot,
    completion_authority: OriginalAuthority,
    consumed: Mutex<Consumed>,
}

impl ConsumedResolver {
    /// Starts a trace from the concrete factory's complete trusted configuration.
    ///
    /// # Errors
    /// Rejects invalid configuration encodings; this alone establishes no fresh authority.
    pub(crate) fn new<S, C>(
        guard: &Guard<S, C>,
        authority: &OriginalAuthority,
    ) -> Result<Self, StoreFailure> {
        let config = guard.config();
        let profile = &config.chunk_profile;
        let registries = guard.completion_inputs()?.registries;
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
        let snapshot = GuardSnapshot {
            registration: registration(authority),
            issuers,
            disclosures: Vec::new(),
            configuration,
            registries,
        };
        let resolver = Self {
            snapshot,
            completion_authority: authority.clone(),
            consumed: Mutex::new(Consumed::default()),
        };
        resolver.snapshot_bytes()?;
        Ok(resolver)
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
        commit: &terrane_core::provenance::VerifiedCommit,
    ) -> Result<(), StoreFailure> {
        let token = terrane_core::auth::Token::decode(
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
            .map(|key| terrane_core::auth::IssuerKey {
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

    /// Refuses unsupported foreign completion after real Original verification.
    ///
    /// # Errors
    /// Refuses a genuine Original context outside this concrete local factory.
    /// Ordinary Original/control consumption remains a separate operation.
    pub(super) fn check_completion_original(
        &self,
        context: &OriginalCommitContext,
    ) -> Result<(), StoreFailure> {
        if context.baseline().authority() != &self.completion_authority {
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
        Vec<terrane_core::gc::publication::evidence::ConsumedViewInterpretation>,
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

    /// Copies only the actual recorded control pins for physical retention.
    ///
    /// This controls-only snapshot neither reads nor completes any pending view,
    /// serializes consumed-view context, or creates LineageUsedInputs. It grants
    /// no publication/actor/history authority. The actual held factory still
    /// checks configured ownership, snapshot equality and every physical record.
    /// Pins use the same canonical (kind, encoded owner, key) order as finish.
    /// Final finish remains separate; this method supplies no completed-view evidence.
    ///
    /// # Errors
    /// Rejects poisoned synchronization or an invalid recorded owner encoding.
    pub(crate) fn control_pins(&self) -> Result<Vec<RequiredControlPin>, StoreFailure> {
        let consumed = self.consumed.lock().map_err(|_| unavailable())?;
        canonical_control_pins(&consumed)
    }

    /// Validates recorded ordinary inputs without converting them to authority.
    ///
    /// # Errors
    /// Rejects invalid canonical records or poisoned synchronization.
    pub(crate) fn finish(&self) -> Result<LineageUsedInputs, StoreFailure> {
        let consumed = self.consumed.lock().map_err(|_| unavailable())?;
        let controls = canonical_control_pins(&consumed)?;
        let inputs = LineageUsedInputs {
            issuers: consumed.issuers.values().cloned().collect(),
            disclosures: self.snapshot.disclosures.clone(),
            controls,
            registries: self.snapshot.registries.clone(),
            configuration: self.snapshot.configuration.clone(),
            views: consumed.views.values().cloned().collect(),
            view_interpretations: Some(consumed.contexts.finish()?),
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
