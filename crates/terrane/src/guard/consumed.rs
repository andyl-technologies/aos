//! Tracks privately consumed canonical policy and protected original controls.
//!
//! A trace is local to one held operation. It records successful checked reads,
//! never accepts a caller dependency list, and does not mint publication authority.
//! Selected Guard/revision and physical checks still belong to the held factory.

use std::collections::BTreeMap;
use std::sync::Mutex;

use terrane_core::gc::publication::evidence::{
    AuthorityGrant, ConfiguredRegistryInputs, ConsumedRootLayer, ConsumedRootPolicy,
    ConsumedViewPolicy, ControlKind, GuardSnapshot, IssuerRow, LineageUsedInputs,
    LocalOriginalRegistration, PhysicalRegistration, RequiredControlPin, SeededChunkProfile,
    TrustedGuardConfig,
};
use terrane_core::tree_format::Property;
use terrane_core::{cbor, properties::PropertyName};

use super::{Guard, OriginalAuthority, OriginalCommitContext, TreeEvidence, invalid};
use crate::store::StoreFailure;

#[derive(Default)]
struct Consumed {
    controls: BTreeMap<Vec<u8>, RequiredControlPin>,
    views: BTreeMap<[u8; 32], ConsumedViewPolicy>,
    issuers: BTreeMap<(String, String), IssuerRow>,
}

/// Accumulates checked consumption inside a single actual held observation.
pub(crate) struct ConsumedResolver {
    snapshot: GuardSnapshot,
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
        let mut properties = PropertyName::ALL
            .iter()
            .map(|name| name.as_str().to_owned())
            .collect::<Vec<_>>();
        properties.sort();
        let registries = ConfiguredRegistryInputs {
            property_revision: 1,
            behavioral_properties: properties,
            attribute_revision: 1,
            selector_revision: 1,
            tree_revision: 1,
            chunk_revision: 1,
            identity_profile: "terrane-v1".into(),
            later_properties: Vec::new(),
        };
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

    /// Records canonical root policies actually traversed by signed-history checks.
    ///
    /// # Errors
    /// Rejects malformed trees, contradictory repeated views or unavailable synchronization.
    pub(crate) fn view(
        &self,
        identity: [u8; 32],
        evidence: &TreeEvidence,
        minimum: u64,
    ) -> Result<(), StoreFailure> {
        let roots = evidence
            .occurrences(minimum)?
            .into_iter()
            .map(|occurrence| ConsumedRootPolicy {
                root: occurrence.root,
                path: occurrence.path,
                layers: occurrence
                    .layers
                    .iter()
                    .map(|(properties, overrides)| ConsumedRootLayer {
                        properties: property_map(properties),
                        overrides: property_map(overrides),
                    })
                    .collect(),
            })
            .collect();
        let view = ConsumedViewPolicy {
            view: identity,
            default_domain: evidence.default_domain.clone(),
            roots,
        };
        let mut consumed = self.consumed.lock().map_err(|_| unavailable())?;
        if consumed
            .views
            .get(&identity)
            .is_some_and(|old| old != &view)
        {
            return Err(invalid());
        }
        consumed.views.insert(identity, view);
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

    /// Validates recorded ordinary inputs without converting them to authority.
    ///
    /// # Errors
    /// Rejects invalid canonical records or poisoned synchronization.
    pub(crate) fn finish(&self) -> Result<LineageUsedInputs, StoreFailure> {
        let consumed = self.consumed.lock().map_err(|_| unavailable())?;
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
        let controls = keyed.into_iter().map(|(_, pin)| pin).collect();
        let inputs = LineageUsedInputs {
            issuers: consumed.issuers.values().cloned().collect(),
            disclosures: self.snapshot.disclosures.clone(),
            controls,
            registries: self.snapshot.registries.clone(),
            configuration: self.snapshot.configuration.clone(),
            views: consumed.views.values().cloned().collect(),
        };
        inputs.encode().map_err(|_| invalid())?;
        Ok(inputs)
    }
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

fn property_map(properties: &[Property<'_>]) -> Vec<u8> {
    let mut bytes = Vec::new();
    cbor::write_map(&mut bytes, properties.len());
    for property in properties {
        cbor::write_text(&mut bytes, property.name);
        bytes.extend_from_slice(property.value);
    }
    bytes
}

fn unavailable() -> StoreFailure {
    StoreFailure::new(crate::store::StoreErrorKind::Unavailable { retry_after: None })
}
