//! Protected Network preparation-policy catalog and handle reservation.
//!
//! The catalog accepts only complete portable assignment manifests paired with
//! their exact sandbox specifications and one root-configured policy profile.
//! It mints the opaque future namespace handle under the Network journal key,
//! retains reservations append-only, and returns an assignment-bound carrier
//! that the admission coordinator can authenticate. The durable format is
//! canonical versioned JSON:
//!
//! ```text
//! {"version":1,"record":{...}}
//! ```
//!
//! This catalog does not claim that a namespace exists. It closes the
//! pre-effect resolution boundary only; kernel realization and current-resource
//! inventory remain separate lifecycle steps.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use aos_sandbox::{Journal, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace};
use aos_sandbox_core::model::{NetworkKind, NetworkProfile, SandboxSpec};
use aos_sandbox_core::{
    BrokerAssignment, CanonicalAssignmentManifestV1, DecodeLimits, NodeId, ObjectDigest,
    decode_sandbox_spec, descriptor_for_bytes, encode_sandbox_spec,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::authorization::NetworkAuthorityV1;
use crate::catalog::{
    AuthenticatedNetworkPreparationV1, ResolvedEndpointV1, ResolvedNetworkPreparationV1,
};
use crate::policy::NetworkPolicyProgramV1;

const PREPARATION_JOURNAL_FILE: &str = "network-preparations.journal";
const HEAD_KEY: &[u8] = b"aos.network.preparation.head.v1\0";
const RECORD_KEY_PREFIX: &[u8] = b"aos.network.preparation.v1\0";
const RECORD_FORMAT_VERSION: u16 = 1;
const POLICY_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.network.policy-catalog.v1\0";
const RESERVATION_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.network.preparation-reservation.v1\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.network.preparation-transaction.v1\0";
const MAXIMUM_PROFILES: usize = 256;
const MAXIMUM_RESERVATIONS: usize = 16_384;
const MAXIMUM_ENDPOINTS: usize = 256;
const MAXIMUM_RECORD_BYTES: usize = 256 * 1024;

/// Reports protected preparation-policy or reservation failure.
#[derive(Debug, thiserror::Error)]
pub enum NetworkPreparationCatalogError {
    /// The protected journal failed validation, locking, or publication.
    #[error("network preparation journal failure: {0}")]
    Journal(#[from] aos_sandbox::JournalError),
    /// A configured policy catalog is empty, noncanonical, or incomplete.
    #[error("network preparation policy catalog is invalid")]
    InvalidPolicy,
    /// Portable assignment, specification, and policy inputs disagree.
    #[error("network preparation reservation input is invalid")]
    InvalidCandidate,
    /// Durable bytes violate the closed catalog schema.
    #[error("network preparation catalog record is corrupt")]
    CorruptRecord,
    /// A retained assignment or handle would be rebound or equivocated.
    #[error("network preparation reservation conflicts with retained state")]
    IdentityConflict,
    /// Protected policy generation moved backwards or forked.
    #[error("network preparation policy catalog rolled back or forked")]
    Rollback,
    /// The append-only reservation epoch has no remaining slots.
    #[error("network preparation reservation epoch is exhausted")]
    ResourceExhausted,
    /// Network authority could not mint or authenticate the reservation.
    #[error("network preparation authority rejected the reservation")]
    Authority,
}

/// Maps one exact portable network profile to protected local policy objects.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkPolicyProfileV1 {
    portable_profile: NetworkProfile,
    program: NetworkPolicyProgramV1,
    endpoints: Vec<ResolvedEndpointV1>,
}

impl NetworkPolicyProfileV1 {
    /// Constructs one complete root-configured policy selection.
    ///
    /// The typed program must implement the portable profile's network kind and
    /// reproduce its endpoint IDs in exact canonical order. Profile and
    /// endpoint digests are derived from that program rather than accepted as
    /// opaque caller assertions.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkPreparationCatalogError::InvalidPolicy`] for a kind or
    /// endpoint mismatch.
    pub fn new(
        portable_profile: NetworkProfile,
        program: NetworkPolicyProgramV1,
    ) -> Result<Self, NetworkPreparationCatalogError> {
        if portable_profile.kind() != program.kind()
            || !portable_profile.endpoint_ids().iter().copied().eq(program
                .endpoints()
                .iter()
                .map(|endpoint| endpoint.endpoint_id()))
        {
            return Err(NetworkPreparationCatalogError::InvalidPolicy);
        }
        let endpoints = program
            .endpoints()
            .iter()
            .map(|endpoint| {
                ResolvedEndpointV1::new(*endpoint.endpoint_id().as_bytes(), endpoint.digest())
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| NetworkPreparationCatalogError::InvalidPolicy)?;

        Ok(Self {
            portable_profile,
            program,
            endpoints,
        })
    }

    /// Returns the exact portable profile selected by this entry.
    #[must_use]
    pub const fn portable_profile(&self) -> &NetworkProfile {
        &self.portable_profile
    }

    /// Returns the protected local policy-program digest.
    #[must_use]
    pub const fn profile_digest(&self) -> ObjectDigest {
        self.program.digest()
    }

    /// Returns the complete typed local policy program.
    #[must_use]
    pub const fn program(&self) -> &NetworkPolicyProgramV1 {
        &self.program
    }

    /// Returns canonical logical-endpoint to local-policy bindings.
    #[must_use]
    pub fn endpoints(&self) -> &[ResolvedEndpointV1] {
        &self.endpoints
    }
}

/// Defines one complete versioned node-local Network policy catalog.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkPolicyCatalogV1 {
    node: NodeId,
    generation: u64,
    digest: ObjectDigest,
    profiles: Vec<NetworkPolicyProfileV1>,
}

impl NetworkPolicyCatalogV1 {
    /// Constructs a nonempty canonical policy catalog.
    ///
    /// Profiles must be ordered by their local digest and no two entries may
    /// select the same portable profile. The node identity prevents a
    /// protected catalog directory from being relocated between nodes.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkPreparationCatalogError::InvalidPolicy`] for a zero
    /// node, generation, empty/oversized set, duplicate portable profile, or
    /// noncanonical digest order.
    pub fn new(
        node: NodeId,
        generation: u64,
        profiles: Vec<NetworkPolicyProfileV1>,
    ) -> Result<Self, NetworkPreparationCatalogError> {
        if node.as_bytes() == &[0; 16]
            || generation == 0
            || profiles.is_empty()
            || profiles.len() > MAXIMUM_PROFILES
            || profiles.windows(2).any(|pair| {
                pair[0].profile_digest().as_bytes() >= pair[1].profile_digest().as_bytes()
            })
        {
            return Err(NetworkPreparationCatalogError::InvalidPolicy);
        }
        let mut portable_profiles = Vec::with_capacity(profiles.len());
        for profile in &profiles {
            if portable_profiles
                .iter()
                .any(|existing| *existing == profile.portable_profile())
            {
                return Err(NetworkPreparationCatalogError::InvalidPolicy);
            }
            portable_profiles.push(profile.portable_profile());
        }

        let digest = policy_catalog_digest(node, generation, &profiles)?;
        Ok(Self {
            node,
            generation,
            digest,
            profiles,
        })
    }

    /// Returns the node that owns this protected policy catalog.
    #[must_use]
    pub const fn node(&self) -> NodeId {
        self.node
    }

    /// Returns the monotonic protected policy generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the commitment to every configured profile and endpoint policy.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.digest
    }

    /// Returns the canonical configured profile set.
    #[must_use]
    pub fn profiles(&self) -> &[NetworkPolicyProfileV1] {
        &self.profiles
    }

    fn resolve(&self, profile: &NetworkProfile) -> Option<&NetworkPolicyProfileV1> {
        self.profiles
            .iter()
            .find(|candidate| candidate.portable_profile() == profile)
    }
}

/// Carries one validated portable assignment awaiting protected reservation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkPreparationReservationV1 {
    assignment: BrokerAssignment,
    node: NodeId,
    manifest_bytes: Vec<u8>,
    sandbox_spec_bytes: Vec<u8>,
    network_profile: NetworkProfile,
}

impl NetworkPreparationReservationV1 {
    /// Validates an assignment manifest and its exact sandbox specification.
    ///
    /// Host networking does not create a private namespace and is rejected at
    /// this boundary. The manifest's spec, environment, and root descriptors
    /// must match the supplied specification exactly.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkPreparationCatalogError::InvalidCandidate`] when the
    /// assignment or descriptor relationships disagree, or the profile selects
    /// host networking.
    pub fn new(
        manifest: &CanonicalAssignmentManifestV1,
        sandbox_spec: &SandboxSpec,
    ) -> Result<Self, NetworkPreparationCatalogError> {
        let assignment = manifest
            .broker_assignment()
            .map_err(|_| NetworkPreparationCatalogError::InvalidCandidate)?;
        let manifest_model = manifest.manifest();
        let sandbox_spec_bytes = encode_sandbox_spec(sandbox_spec);
        let observed_spec = descriptor_for_bytes(
            manifest_model.sandbox_spec().media_type().clone(),
            &sandbox_spec_bytes,
        );
        if observed_spec != *manifest_model.sandbox_spec()
            || sandbox_spec.environment() != manifest_model.environment()
            || sandbox_spec.root_view() != manifest_model.root_view()
            || sandbox_spec.network_profile().kind() == NetworkKind::Host
        {
            return Err(NetworkPreparationCatalogError::InvalidCandidate);
        }
        Ok(Self {
            assignment,
            node: manifest_model.node(),
            manifest_bytes: manifest.canonical_bytes().to_vec(),
            sandbox_spec_bytes,
            network_profile: sandbox_spec.network_profile().clone(),
        })
    }

    /// Returns the exact assignment receiving the future namespace.
    #[must_use]
    pub const fn assignment(&self) -> BrokerAssignment {
        self.assignment
    }
}

/// Classifies one append-only handle reservation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NetworkPreparationCatalogOutcomeV1 {
    /// A new opaque handle and protected resolution were retained.
    Reserved(AuthenticatedNetworkPreparationV1),
    /// The byte-exact existing reservation was returned without a new record.
    Replay(AuthenticatedNetworkPreparationV1),
}

impl NetworkPreparationCatalogOutcomeV1 {
    /// Returns the authenticated resolution for broker admission.
    #[must_use]
    pub const fn preparation(&self) -> &AuthenticatedNetworkPreparationV1 {
        match self {
            Self::Reserved(preparation) | Self::Replay(preparation) => preparation,
        }
    }

    /// Consumes the outcome and returns its authenticated resolution.
    #[must_use]
    pub fn into_preparation(self) -> AuthenticatedNetworkPreparationV1 {
        match self {
            Self::Reserved(preparation) | Self::Replay(preparation) => preparation,
        }
    }
}

/// Owns the protected policy head and append-only preparation reservations.
pub struct NetworkPreparationCatalogV1 {
    journal: Journal,
    policy: NetworkPolicyCatalogV1,
    records: BTreeMap<[u8; 32], PreparationRecordV1>,
}

impl NetworkPreparationCatalogV1 {
    /// Opens a root-owned catalog and advances it to trusted newer policy.
    ///
    /// The state directory must satisfy the protected journal's root-owned
    /// ancestry and mode contract. A newer supplied policy generation is
    /// durably installed before this method returns; equal generations must
    /// have the exact same digest.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkPreparationCatalogError`] for unsafe filesystem state,
    /// malformed records, identity conflicts, a policy fork, or rollback below
    /// `minimum_generation`.
    pub fn open_root_owned(
        directory: &Path,
        policy: NetworkPolicyCatalogV1,
        minimum_generation: u64,
    ) -> Result<Self, NetworkPreparationCatalogError> {
        let (journal, _) = Journal::open_protected_at(
            directory,
            PREPARATION_JOURNAL_FILE,
            preparation_journal_limits(),
        )?;
        Self::recover(journal, policy, minimum_generation)
    }

    #[cfg(test)]
    fn open_for_test(
        directory: &Path,
        policy: NetworkPolicyCatalogV1,
        minimum_generation: u64,
    ) -> Result<Self, NetworkPreparationCatalogError> {
        let (journal, _) = Journal::open(
            directory.join(PREPARATION_JOURNAL_FILE),
            preparation_journal_limits(),
        )?;
        Self::recover(journal, policy, minimum_generation)
    }

    fn recover(
        mut journal: Journal,
        policy: NetworkPolicyCatalogV1,
        minimum_generation: u64,
    ) -> Result<Self, NetworkPreparationCatalogError> {
        if policy.generation() < minimum_generation {
            return Err(NetworkPreparationCatalogError::Rollback);
        }

        let mut head = None;
        let mut records = BTreeMap::new();
        for (key, value) in journal.records(RecordNamespace::NetworkResourceInventory) {
            if key == HEAD_KEY {
                if head.replace(decode_head(value)?).is_some() {
                    return Err(NetworkPreparationCatalogError::CorruptRecord);
                }
                continue;
            }
            let handle = decode_record_key(key)?;
            let record = decode_record(value)?;
            if record.network_handle != handle || records.insert(handle, record).is_some() {
                return Err(NetworkPreparationCatalogError::CorruptRecord);
            }
        }

        let stored_generation = match &head {
            None if records.is_empty() => policy.generation(),
            None => return Err(NetworkPreparationCatalogError::CorruptRecord),
            Some(head) if head.node != *policy.node().as_bytes() => {
                return Err(NetworkPreparationCatalogError::Rollback);
            }
            Some(head) if head.generation > policy.generation() => {
                return Err(NetworkPreparationCatalogError::Rollback);
            }
            Some(head) if head.generation == policy.generation() => {
                if head.digest != *policy.digest().as_bytes() {
                    return Err(NetworkPreparationCatalogError::Rollback);
                }
                head.generation
            }
            Some(head) => head.generation,
        };
        // Validate the recovered snapshot against its durable head before a
        // trusted policy roll-forward can publish any new state.
        validate_record_set(&records, policy.node(), stored_generation)?;

        match head {
            None => initialize_head(&mut journal, &policy)?,
            Some(head) if head.generation < policy.generation() => {
                advance_head(&mut journal, &policy)?;
            }
            Some(_) => {}
        }
        Ok(Self {
            journal,
            policy,
            records,
        })
    }

    /// Returns the active protected policy generation.
    #[must_use]
    pub const fn policy_generation(&self) -> u64 {
        self.policy.generation()
    }

    /// Returns the next durable journal boundary after the current snapshot.
    #[must_use]
    pub const fn journal_sequence(&self) -> u64 {
        self.journal.snapshot_sequence()
    }

    /// Reserves an opaque handle and authenticates its exact local resolution.
    ///
    /// Reservations are append-only. An exact retry returns the original
    /// handle, while any different assignment generation for an already
    /// retained sandbox/incarnation fails instead of rebinding that identity.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkPreparationCatalogError`] when the portable profile is
    /// not configured, retained state conflicts, capacity is exhausted, or
    /// protected authority cannot mint/authenticate the handle.
    pub fn reserve(
        &mut self,
        reservation: NetworkPreparationReservationV1,
        authority: &NetworkAuthorityV1,
    ) -> Result<NetworkPreparationCatalogOutcomeV1, NetworkPreparationCatalogError> {
        if reservation.node != self.policy.node() {
            return Err(NetworkPreparationCatalogError::InvalidCandidate);
        }
        if let Some(existing) = self.records.values().find(|record| {
            record.assignment_pair()
                == (
                    *reservation.assignment.sandbox().as_bytes(),
                    *reservation.assignment.incarnation().as_bytes(),
                )
        }) {
            if !existing.matches_reservation(&reservation)? {
                return Err(NetworkPreparationCatalogError::IdentityConflict);
            }
            let preparation = existing.authenticate(authority)?;
            return Ok(NetworkPreparationCatalogOutcomeV1::Replay(preparation));
        }
        if self.records.len() >= MAXIMUM_RESERVATIONS {
            return Err(NetworkPreparationCatalogError::ResourceExhausted);
        }
        let profile = self
            .policy
            .resolve(&reservation.network_profile)
            .ok_or(NetworkPreparationCatalogError::InvalidCandidate)?;
        let handle_preimage = reservation_preimage(&reservation, &self.policy, profile)?;
        let network_handle = authority
            .mint_network_handle(reservation.assignment, &handle_preimage)
            .map_err(|_| NetworkPreparationCatalogError::Authority)?;
        if self.records.contains_key(&network_handle) {
            return Err(NetworkPreparationCatalogError::IdentityConflict);
        }

        let resolution = ResolvedNetworkPreparationV1::new(
            self.policy.generation(),
            network_handle,
            profile.profile_digest(),
            profile.endpoints().to_vec(),
        )
        .map_err(|_| NetworkPreparationCatalogError::InvalidCandidate)?;
        let mut record = PreparationRecordV1 {
            network_handle,
            assignment: AssignmentWire::from(reservation.assignment),
            manifest_bytes: reservation.manifest_bytes,
            sandbox_spec_bytes: reservation.sandbox_spec_bytes,
            catalog_generation: self.policy.generation(),
            profile_digest: *profile.profile_digest().as_bytes(),
            endpoints: profile.endpoints().iter().map(EndpointWire::from).collect(),
            resolution_digest: *resolution.binding().digest().as_bytes(),
            reservation_digest: [0; 32],
        };
        record.reservation_digest = record.derive_digest()?;
        record.validate()?;

        let bytes = encode_record(&record)?;
        let transaction = JournalTransaction::new(
            transaction_id(b"reserve", &network_handle, self.policy.generation()),
            vec![JournalRecord::put(
                RecordNamespace::NetworkResourceInventory,
                record_key(&network_handle),
                bytes,
            )],
        )?;
        self.journal.commit(&transaction)?;
        self.records.insert(network_handle, record);

        let preparation = authority
            .authenticate_protected_catalog_for_assignment(resolution, reservation.assignment)
            .map_err(|_| NetworkPreparationCatalogError::Authority)?;
        Ok(NetworkPreparationCatalogOutcomeV1::Reserved(preparation))
    }

    // Namespace publication must reproduce this catalog's retained assignment,
    // not recover it from a caller-supplied manifest or a newer policy head.
    pub(crate) fn assignment_for_resolution(
        &self,
        network_handle: [u8; 32],
        resolution: &ResolvedNetworkPreparationV1,
    ) -> Result<BrokerAssignment, NetworkPreparationCatalogError> {
        let record = self
            .records
            .get(&network_handle)
            .ok_or(NetworkPreparationCatalogError::InvalidCandidate)?;
        if record.resolution()? != *resolution {
            return Err(NetworkPreparationCatalogError::InvalidCandidate);
        }
        record.assignment.assignment()
    }

    /// Resolves one retained preparation to its complete typed packet policy.
    ///
    /// The durable reservation must exactly reproduce `resolution`. Its
    /// retained portable specification then selects a program from the current
    /// trusted policy catalog, and that program must reproduce every committed
    /// profile and endpoint digest. A policy roll-forward must therefore retain
    /// an unsettled program unchanged until its prepared effect is committed or
    /// resolved by observation.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkPreparationCatalogError::InvalidCandidate`] when the
    /// handle, retained resolution, portable profile, or current typed program
    /// does not form one exact association.
    pub fn program_for_resolution(
        &self,
        network_handle: [u8; 32],
        resolution: &ResolvedNetworkPreparationV1,
    ) -> Result<&NetworkPolicyProgramV1, NetworkPreparationCatalogError> {
        let record = self
            .records
            .get(&network_handle)
            .ok_or(NetworkPreparationCatalogError::InvalidCandidate)?;
        if record.resolution()? != *resolution {
            return Err(NetworkPreparationCatalogError::InvalidCandidate);
        }
        let sandbox_spec = decode_sandbox_spec(&record.sandbox_spec_bytes, DecodeLimits::default())
            .map_err(|_| NetworkPreparationCatalogError::CorruptRecord)?;
        let profile = self
            .policy
            .resolve(sandbox_spec.network_profile())
            .filter(|profile| {
                profile.profile_digest() == resolution.profile_digest()
                    && profile.endpoints() == resolution.endpoints()
            })
            .ok_or(NetworkPreparationCatalogError::InvalidCandidate)?;

        Ok(profile.program())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CatalogHeadV1 {
    node: [u8; 16],
    generation: u64,
    digest: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct VersionedHeadV1 {
    version: u16,
    head: CatalogHeadV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct AssignmentWire {
    sandbox_id: [u8; 16],
    incarnation_id: [u8; 16],
    assignment_epoch: u64,
    desired_generation: u64,
    assignment_digest: [u8; 32],
}

impl From<BrokerAssignment> for AssignmentWire {
    fn from(value: BrokerAssignment) -> Self {
        Self {
            sandbox_id: *value.sandbox().as_bytes(),
            incarnation_id: *value.incarnation().as_bytes(),
            assignment_epoch: value.epoch().get(),
            desired_generation: value.desired_generation().get(),
            assignment_digest: *value.digest().as_bytes(),
        }
    }
}

impl AssignmentWire {
    fn assignment(&self) -> Result<BrokerAssignment, NetworkPreparationCatalogError> {
        use aos_sandbox_core::{AssignmentEpoch, DesiredGeneration, IncarnationId, SandboxId};

        BrokerAssignment::new(
            SandboxId::from_bytes(self.sandbox_id),
            IncarnationId::from_bytes(self.incarnation_id),
            AssignmentEpoch::new(self.assignment_epoch),
            DesiredGeneration::new(self.desired_generation),
            ObjectDigest::from_bytes(self.assignment_digest),
        )
        .map_err(|_| NetworkPreparationCatalogError::CorruptRecord)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct EndpointWire {
    id: [u8; 16],
    policy_digest: [u8; 32],
}

impl From<&ResolvedEndpointV1> for EndpointWire {
    fn from(value: &ResolvedEndpointV1) -> Self {
        Self {
            id: *value.id(),
            policy_digest: *value.policy_digest().as_bytes(),
        }
    }
}

impl EndpointWire {
    fn endpoint(&self) -> Result<ResolvedEndpointV1, NetworkPreparationCatalogError> {
        ResolvedEndpointV1::new(self.id, ObjectDigest::from_bytes(self.policy_digest))
            .map_err(|_| NetworkPreparationCatalogError::CorruptRecord)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PreparationRecordV1 {
    network_handle: [u8; 32],
    assignment: AssignmentWire,
    manifest_bytes: Vec<u8>,
    sandbox_spec_bytes: Vec<u8>,
    catalog_generation: u64,
    profile_digest: [u8; 32],
    endpoints: Vec<EndpointWire>,
    resolution_digest: [u8; 32],
    reservation_digest: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct VersionedRecordV1 {
    version: u16,
    record: PreparationRecordV1,
}

impl PreparationRecordV1 {
    const fn assignment_pair(&self) -> ([u8; 16], [u8; 16]) {
        (self.assignment.sandbox_id, self.assignment.incarnation_id)
    }

    fn resolution(&self) -> Result<ResolvedNetworkPreparationV1, NetworkPreparationCatalogError> {
        let endpoints = self
            .endpoints
            .iter()
            .map(EndpointWire::endpoint)
            .collect::<Result<Vec<_>, _>>()?;
        let resolution = ResolvedNetworkPreparationV1::new(
            self.catalog_generation,
            self.network_handle,
            ObjectDigest::from_bytes(self.profile_digest),
            endpoints,
        )
        .map_err(|_| NetworkPreparationCatalogError::CorruptRecord)?;
        if resolution.binding().digest().as_bytes() != &self.resolution_digest {
            return Err(NetworkPreparationCatalogError::CorruptRecord);
        }
        Ok(resolution)
    }

    fn validate(&self) -> Result<NodeId, NetworkPreparationCatalogError> {
        if self.network_handle == [0; 32]
            || self.catalog_generation == 0
            || self.profile_digest == [0; 32]
            || self.resolution_digest == [0; 32]
            || self.reservation_digest == [0; 32]
            || self.manifest_bytes.is_empty()
            || self.sandbox_spec_bytes.is_empty()
            || self.endpoints.len() > MAXIMUM_ENDPOINTS
            || self.derive_digest()? != self.reservation_digest
        {
            return Err(NetworkPreparationCatalogError::CorruptRecord);
        }
        let manifest = CanonicalAssignmentManifestV1::from_canonical_bytes(
            &self.manifest_bytes,
            DecodeLimits::default(),
        )
        .map_err(|_| NetworkPreparationCatalogError::CorruptRecord)?;
        if manifest.broker_assignment().ok() != Some(self.assignment.assignment()?) {
            return Err(NetworkPreparationCatalogError::CorruptRecord);
        }
        let sandbox_spec = decode_sandbox_spec(&self.sandbox_spec_bytes, DecodeLimits::default())
            .map_err(|_| NetworkPreparationCatalogError::CorruptRecord)?;
        if encode_sandbox_spec(&sandbox_spec) != self.sandbox_spec_bytes {
            return Err(NetworkPreparationCatalogError::CorruptRecord);
        }
        NetworkPreparationReservationV1::new(&manifest, &sandbox_spec)
            .map_err(|_| NetworkPreparationCatalogError::CorruptRecord)?;
        if !sandbox_spec
            .network_profile()
            .endpoint_ids()
            .iter()
            .map(|endpoint| endpoint.as_bytes())
            .eq(self.endpoints.iter().map(|endpoint| &endpoint.id))
        {
            return Err(NetworkPreparationCatalogError::CorruptRecord);
        }
        self.resolution()?;
        Ok(manifest.manifest().node())
    }

    fn matches_reservation(
        &self,
        reservation: &NetworkPreparationReservationV1,
    ) -> Result<bool, NetworkPreparationCatalogError> {
        Ok(self.assignment.assignment()? == reservation.assignment
            && self.manifest_bytes == reservation.manifest_bytes
            && self.sandbox_spec_bytes == reservation.sandbox_spec_bytes)
    }

    fn authenticate(
        &self,
        authority: &NetworkAuthorityV1,
    ) -> Result<AuthenticatedNetworkPreparationV1, NetworkPreparationCatalogError> {
        authority
            .authenticate_protected_catalog_for_assignment(
                self.resolution()?,
                self.assignment.assignment()?,
            )
            .map_err(|_| NetworkPreparationCatalogError::Authority)
    }

    fn derive_digest(&self) -> Result<[u8; 32], NetworkPreparationCatalogError> {
        let mut digest = Sha256::new();
        digest.update(RESERVATION_DIGEST_DOMAIN);
        digest.update(self.network_handle);
        digest.update(self.assignment.sandbox_id);
        digest.update(self.assignment.incarnation_id);
        digest.update(self.assignment.assignment_epoch.to_be_bytes());
        digest.update(self.assignment.desired_generation.to_be_bytes());
        digest.update(self.assignment.assignment_digest);
        digest.update(
            u32::try_from(self.manifest_bytes.len())
                .map_err(|_| NetworkPreparationCatalogError::CorruptRecord)?
                .to_be_bytes(),
        );
        digest.update(&self.manifest_bytes);
        digest.update(
            u32::try_from(self.sandbox_spec_bytes.len())
                .map_err(|_| NetworkPreparationCatalogError::CorruptRecord)?
                .to_be_bytes(),
        );
        digest.update(&self.sandbox_spec_bytes);
        digest.update(self.catalog_generation.to_be_bytes());
        digest.update(self.profile_digest);
        digest.update(
            u16::try_from(self.endpoints.len())
                .map_err(|_| NetworkPreparationCatalogError::CorruptRecord)?
                .to_be_bytes(),
        );
        for endpoint in &self.endpoints {
            digest.update(endpoint.id);
            digest.update(endpoint.policy_digest);
        }
        digest.update(self.resolution_digest);
        Ok(digest.finalize().into())
    }
}

fn policy_catalog_digest(
    node: NodeId,
    generation: u64,
    profiles: &[NetworkPolicyProfileV1],
) -> Result<ObjectDigest, NetworkPreparationCatalogError> {
    let mut digest = Sha256::new();
    digest.update(POLICY_DIGEST_DOMAIN);
    digest.update(node.as_bytes());
    digest.update(generation.to_be_bytes());
    digest.update(
        u16::try_from(profiles.len())
            .map_err(|_| NetworkPreparationCatalogError::InvalidPolicy)?
            .to_be_bytes(),
    );
    for profile in profiles {
        digest.update([network_kind_code(profile.portable_profile().kind())]);
        digest.update(profile.profile_digest().as_bytes());
        digest.update(
            u16::try_from(profile.portable_profile().endpoint_ids().len())
                .map_err(|_| NetworkPreparationCatalogError::InvalidPolicy)?
                .to_be_bytes(),
        );
        for endpoint in profile.portable_profile().endpoint_ids() {
            digest.update(endpoint.as_bytes());
        }
        digest.update(
            u16::try_from(profile.portable_profile().required_features().len())
                .map_err(|_| NetworkPreparationCatalogError::InvalidPolicy)?
                .to_be_bytes(),
        );
        for feature in profile.portable_profile().required_features() {
            digest.update(
                u16::try_from(feature.namespace().len())
                    .map_err(|_| NetworkPreparationCatalogError::InvalidPolicy)?
                    .to_be_bytes(),
            );
            digest.update(feature.namespace().as_bytes());
            digest.update(feature.major().to_be_bytes());
            digest.update(feature.minor().to_be_bytes());
        }
        for endpoint in profile.endpoints() {
            digest.update(endpoint.id());
            digest.update(endpoint.policy_digest().as_bytes());
        }
    }
    Ok(ObjectDigest::from_bytes(digest.finalize().into()))
}

const fn network_kind_code(kind: NetworkKind) -> u8 {
    match kind {
        NetworkKind::Isolated => 1,
        NetworkKind::Project => 2,
        NetworkKind::Outbound => 3,
        NetworkKind::Published => 4,
        NetworkKind::Host => 5,
    }
}

fn reservation_preimage(
    reservation: &NetworkPreparationReservationV1,
    policy: &NetworkPolicyCatalogV1,
    profile: &NetworkPolicyProfileV1,
) -> Result<Vec<u8>, NetworkPreparationCatalogError> {
    let mut bytes = Vec::with_capacity(
        128 + reservation.manifest_bytes.len() + reservation.sandbox_spec_bytes.len(),
    );
    bytes.extend_from_slice(&policy.generation().to_be_bytes());
    bytes.extend_from_slice(policy.digest().as_bytes());
    bytes.extend_from_slice(reservation.assignment.sandbox().as_bytes());
    bytes.extend_from_slice(reservation.assignment.incarnation().as_bytes());
    bytes.extend_from_slice(&reservation.assignment.epoch().get().to_be_bytes());
    bytes.extend_from_slice(
        &reservation
            .assignment
            .desired_generation()
            .get()
            .to_be_bytes(),
    );
    bytes.extend_from_slice(reservation.assignment.digest().as_bytes());
    bytes.extend_from_slice(profile.profile_digest().as_bytes());
    bytes.extend_from_slice(
        &u32::try_from(reservation.manifest_bytes.len())
            .map_err(|_| NetworkPreparationCatalogError::InvalidCandidate)?
            .to_be_bytes(),
    );
    bytes.extend_from_slice(&reservation.manifest_bytes);
    bytes.extend_from_slice(
        &u32::try_from(reservation.sandbox_spec_bytes.len())
            .map_err(|_| NetworkPreparationCatalogError::InvalidCandidate)?
            .to_be_bytes(),
    );
    bytes.extend_from_slice(&reservation.sandbox_spec_bytes);
    for endpoint in profile.endpoints() {
        bytes.extend_from_slice(endpoint.id());
        bytes.extend_from_slice(endpoint.policy_digest().as_bytes());
    }
    Ok(bytes)
}

fn validate_record_set(
    records: &BTreeMap<[u8; 32], PreparationRecordV1>,
    expected_node: NodeId,
    current_policy_generation: u64,
) -> Result<(), NetworkPreparationCatalogError> {
    if records.len() > MAXIMUM_RESERVATIONS {
        return Err(NetworkPreparationCatalogError::ResourceExhausted);
    }
    let mut assignments = BTreeSet::new();
    for record in records.values() {
        if record.validate()? != expected_node {
            return Err(NetworkPreparationCatalogError::CorruptRecord);
        }
        if record.catalog_generation > current_policy_generation {
            return Err(NetworkPreparationCatalogError::Rollback);
        }
        if !assignments.insert(record.assignment_pair()) {
            return Err(NetworkPreparationCatalogError::IdentityConflict);
        }
    }
    Ok(())
}

fn initialize_head(
    journal: &mut Journal,
    policy: &NetworkPolicyCatalogV1,
) -> Result<(), NetworkPreparationCatalogError> {
    publish_head(journal, policy, b"initialize")
}

fn advance_head(
    journal: &mut Journal,
    policy: &NetworkPolicyCatalogV1,
) -> Result<(), NetworkPreparationCatalogError> {
    publish_head(journal, policy, b"advance")
}

fn publish_head(
    journal: &mut Journal,
    policy: &NetworkPolicyCatalogV1,
    label: &[u8],
) -> Result<(), NetworkPreparationCatalogError> {
    let head = CatalogHeadV1 {
        node: *policy.node().as_bytes(),
        generation: policy.generation(),
        digest: *policy.digest().as_bytes(),
    };
    let transaction = JournalTransaction::new(
        transaction_id(label, policy.digest().as_bytes(), policy.generation()),
        vec![JournalRecord::put(
            RecordNamespace::NetworkResourceInventory,
            HEAD_KEY.to_vec(),
            encode_head(&head)?,
        )],
    )?;
    journal.commit(&transaction)?;
    Ok(())
}

fn encode_head(head: &CatalogHeadV1) -> Result<Vec<u8>, NetworkPreparationCatalogError> {
    serde_json::to_vec(&VersionedHeadV1 {
        version: RECORD_FORMAT_VERSION,
        head: head.clone(),
    })
    .map_err(|_| NetworkPreparationCatalogError::CorruptRecord)
}

fn decode_head(bytes: &[u8]) -> Result<CatalogHeadV1, NetworkPreparationCatalogError> {
    if bytes.len() > MAXIMUM_RECORD_BYTES {
        return Err(NetworkPreparationCatalogError::CorruptRecord);
    }
    let value: VersionedHeadV1 =
        serde_json::from_slice(bytes).map_err(|_| NetworkPreparationCatalogError::CorruptRecord)?;
    if value.version != RECORD_FORMAT_VERSION || encode_head(&value.head)? != bytes {
        return Err(NetworkPreparationCatalogError::CorruptRecord);
    }
    if value.head.node == [0; 16] || value.head.generation == 0 || value.head.digest == [0; 32] {
        return Err(NetworkPreparationCatalogError::CorruptRecord);
    }
    Ok(value.head)
}

fn encode_record(record: &PreparationRecordV1) -> Result<Vec<u8>, NetworkPreparationCatalogError> {
    let bytes = serde_json::to_vec(&VersionedRecordV1 {
        version: RECORD_FORMAT_VERSION,
        record: record.clone(),
    })
    .map_err(|_| NetworkPreparationCatalogError::CorruptRecord)?;
    if bytes.len() > MAXIMUM_RECORD_BYTES {
        return Err(NetworkPreparationCatalogError::CorruptRecord);
    }
    Ok(bytes)
}

fn decode_record(bytes: &[u8]) -> Result<PreparationRecordV1, NetworkPreparationCatalogError> {
    if bytes.len() > MAXIMUM_RECORD_BYTES {
        return Err(NetworkPreparationCatalogError::CorruptRecord);
    }
    let value: VersionedRecordV1 =
        serde_json::from_slice(bytes).map_err(|_| NetworkPreparationCatalogError::CorruptRecord)?;
    if value.version != RECORD_FORMAT_VERSION || encode_record(&value.record)? != bytes {
        return Err(NetworkPreparationCatalogError::CorruptRecord);
    }
    value.record.validate()?;
    Ok(value.record)
}

fn record_key(handle: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(RECORD_KEY_PREFIX.len() + handle.len());
    key.extend_from_slice(RECORD_KEY_PREFIX);
    key.extend_from_slice(handle);
    key
}

fn decode_record_key(key: &[u8]) -> Result<[u8; 32], NetworkPreparationCatalogError> {
    key.strip_prefix(RECORD_KEY_PREFIX)
        .and_then(|suffix| suffix.try_into().ok())
        .filter(|handle| handle != &[0; 32])
        .ok_or(NetworkPreparationCatalogError::CorruptRecord)
}

fn transaction_id(label: &[u8], identity: &[u8], generation: u64) -> [u8; 16] {
    let digest = Sha256::new()
        .chain_update(TRANSACTION_DOMAIN)
        .chain_update(label)
        .chain_update(identity)
        .chain_update(generation.to_be_bytes())
        .finalize();
    digest[..16].try_into().unwrap_or([1; 16])
}

const fn preparation_journal_limits() -> JournalLimits {
    JournalLimits {
        maximum_journal_bytes: 512 * 1024 * 1024,
        maximum_record_bytes: MAXIMUM_RECORD_BYTES,
        maximum_key_bytes: 96,
        maximum_records_per_transaction: 1,
        maximum_transaction_bytes: MAXIMUM_RECORD_BYTES,
        maximum_transactions: 65_536,
        maximum_materialized_bytes: MAXIMUM_RECORD_BYTES * (MAXIMUM_RESERVATIONS + 1),
        maximum_materialized_records: MAXIMUM_RESERVATIONS + 1,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use aos_sandbox_core::format::encode_trust_policy;
    use aos_sandbox_core::model::{
        AssignmentManifestV1, IdentityProfile, KeyReference, KeyUsage, ResourceProfile,
        SandboxAncestry, SignaturePurpose, StableKeyId, TrustPolicy, UnmappableIdentityPolicy,
    };
    use aos_sandbox_core::{
        AssignmentEpoch, BrokerPlanTrustAnchor, DesiredGeneration, FeatureRef, IncarnationId,
        MediaType, NamespaceGeneration, NetworkEndpointId, NodeId, ObjectDescriptor,
        OwnershipLeaseTrustAnchor, PortableMediaType, ProjectId, ResourceVector, RevocationScopeId,
        SandboxId, TrustScopeId,
    };
    use ed25519_dalek::SigningKey;
    use std::num::NonZeroU32;
    use tempfile::TempDir;

    use super::*;
    use crate::policy::{
        NetworkEndpointPolicyV1, NetworkFlowDirectionV1, NetworkFlowPolicyV1, NetworkIpPrefixV1,
        NetworkPortRangeV1, NetworkTransportProtocolV1,
    };

    const NODE: NodeId = NodeId::from_bytes([31; 16]);

    fn authority() -> NetworkAuthorityV1 {
        let plan_key = SigningKey::from_bytes(&[41; 32]);
        let lease_key = SigningKey::from_bytes(&[42; 32]);
        let plan_signer = key_ref("network-plan", 3, KeyUsage::BrokerAuthorization, &plan_key);
        let lease_signer = key_ref("network-lease", 7, KeyUsage::OwnershipLease, &lease_key);
        let plan_scope = TrustScopeId::from_bytes([43; 16]);
        let lease_scope = TrustScopeId::from_bytes([44; 16]);
        let plan_policy = TrustPolicy::new(
            plan_scope,
            SignaturePurpose::BrokerAuthorization,
            vec![plan_signer.clone()],
            Vec::new(),
        )
        .unwrap();
        let lease_policy = TrustPolicy::new(
            lease_scope,
            SignaturePurpose::OwnershipLease,
            vec![lease_signer.clone()],
            Vec::new(),
        )
        .unwrap();
        let plan_bytes = encode_trust_policy(&plan_policy);
        let lease_bytes = encode_trust_policy(&lease_policy);
        let plan_descriptor = descriptor_for_bytes(
            MediaType::new(PortableMediaType::TrustPolicy.as_str().to_owned()).unwrap(),
            &plan_bytes,
        );
        let lease_descriptor = descriptor_for_bytes(
            MediaType::new(PortableMediaType::TrustPolicy.as_str().to_owned()).unwrap(),
            &lease_bytes,
        );
        let plan = BrokerPlanTrustAnchor::from_trusted_configuration(
            plan_bytes,
            plan_descriptor,
            plan_scope,
            plan_signer,
            plan_key.verifying_key().to_bytes(),
            RevocationScopeId::from_bytes([45; 16]),
            DecodeLimits::default(),
        )
        .unwrap();
        let lease = OwnershipLeaseTrustAnchor::from_trusted_configuration(
            lease_bytes,
            lease_descriptor,
            lease_scope,
            lease_signer,
            lease_key.verifying_key().to_bytes(),
            DecodeLimits::default(),
        )
        .unwrap();
        NetworkAuthorityV1::new(plan, lease, NODE, [46; 16], [47; 32]).unwrap()
    }

    fn key_ref(id: &str, generation: u64, usage: KeyUsage, key: &SigningKey) -> KeyReference {
        KeyReference::new(
            StableKeyId::new(id.to_owned()).unwrap(),
            generation,
            ObjectDigest::from_bytes(Sha256::digest(key.verifying_key().as_bytes()).into()),
            usage,
        )
    }

    fn descriptor(kind: PortableMediaType, marker: u8) -> ObjectDescriptor {
        ObjectDescriptor::new(
            MediaType::new(kind.as_str().to_owned()).unwrap(),
            ObjectDigest::from_bytes([marker; 32]),
            u64::from(marker) + 1,
        )
    }

    fn sandbox_spec(network_profile: NetworkProfile) -> SandboxSpec {
        SandboxSpec::new(
            FeatureRef::new("aos.sandbox.runtime.linux-systemd", 1, 0).unwrap(),
            IdentityProfile::PrivateUserns {
                id_range_size: NonZeroU32::new(65_536).unwrap(),
                unmappable_policy: UnmappableIdentityPolicy::Reject,
                required_features: Vec::new(),
            },
            ResourceProfile::new(Vec::new()).unwrap(),
            descriptor(PortableMediaType::Environment, 71),
            descriptor(PortableMediaType::View, 72),
            Vec::new(),
            network_profile,
            Vec::new(),
        )
        .unwrap()
    }

    fn manifest(
        spec: &SandboxSpec,
        sandbox_marker: u8,
        desired_generation: u64,
    ) -> CanonicalAssignmentManifestV1 {
        manifest_for_node(spec, NODE, sandbox_marker, desired_generation)
    }

    fn manifest_for_node(
        spec: &SandboxSpec,
        node: NodeId,
        sandbox_marker: u8,
        desired_generation: u64,
    ) -> CanonicalAssignmentManifestV1 {
        let spec_bytes = encode_sandbox_spec(spec);
        let spec_descriptor = descriptor_for_bytes(
            MediaType::new(PortableMediaType::SandboxSpec.as_str().to_owned()).unwrap(),
            &spec_bytes,
        );
        CanonicalAssignmentManifestV1::new(
            AssignmentManifestV1::new(
                SandboxId::from_bytes([sandbox_marker; 16]),
                ProjectId::from_bytes([4; 16]),
                SandboxAncestry::new(SandboxId::from_bytes([sandbox_marker; 16]), Vec::new())
                    .unwrap(),
                IncarnationId::from_bytes([sandbox_marker.wrapping_add(1); 16]),
                node,
                AssignmentEpoch::new(4),
                DesiredGeneration::new(desired_generation),
                NamespaceGeneration::new(6),
                spec_descriptor,
                descriptor(PortableMediaType::Policy, 70),
                spec.environment().clone(),
                spec.root_view().clone(),
                Vec::new(),
                ObjectDigest::from_bytes([73; 32]),
                ResourceVector::ZERO,
                Vec::new(),
            )
            .unwrap(),
        )
    }

    fn isolated_profile() -> NetworkProfile {
        NetworkProfile::new(NetworkKind::Isolated, Vec::new(), Vec::new()).unwrap()
    }

    fn project_profile(endpoint_markers: &[u8]) -> NetworkProfile {
        NetworkProfile::new(
            NetworkKind::Project,
            endpoint_markers
                .iter()
                .map(|marker| NetworkEndpointId::from_bytes([*marker; 16]))
                .collect(),
            Vec::new(),
        )
        .unwrap()
    }

    fn policy_catalog(
        generation: u64,
        portable_profile: NetworkProfile,
        profile_marker: u8,
    ) -> NetworkPolicyCatalogV1 {
        policy_catalog_for_node(NODE, generation, portable_profile, profile_marker)
    }

    fn policy_catalog_for_node(
        node: NodeId,
        generation: u64,
        portable_profile: NetworkProfile,
        profile_marker: u8,
    ) -> NetworkPolicyCatalogV1 {
        let program = policy_program(&portable_profile, profile_marker);
        NetworkPolicyCatalogV1::new(
            node,
            generation,
            vec![NetworkPolicyProfileV1::new(portable_profile, program).unwrap()],
        )
        .unwrap()
    }

    fn policy_program(
        portable_profile: &NetworkProfile,
        profile_marker: u8,
    ) -> NetworkPolicyProgramV1 {
        let direction = match portable_profile.kind() {
            NetworkKind::Published => NetworkFlowDirectionV1::Ingress,
            _ => NetworkFlowDirectionV1::Egress,
        };
        let endpoints = portable_profile
            .endpoint_ids()
            .iter()
            .enumerate()
            .map(|(index, endpoint)| {
                let port = 10_000_u16 + u16::try_from(index).unwrap();
                let flow = NetworkFlowPolicyV1::new(
                    direction,
                    NetworkTransportProtocolV1::Tcp,
                    NetworkIpPrefixV1::ipv4([10, profile_marker, 0, 0], 16).unwrap(),
                    Some(NetworkPortRangeV1::new(port, port).unwrap()),
                )
                .unwrap();
                NetworkEndpointPolicyV1::new(*endpoint, vec![flow]).unwrap()
            })
            .collect();
        let gate = if portable_profile.kind() == NetworkKind::Isolated {
            None
        } else {
            Some(ObjectDigest::from_bytes(
                [profile_marker.wrapping_add(1); 32],
            ))
        };

        NetworkPolicyProgramV1::new(
            portable_profile.kind(),
            ObjectDigest::from_bytes([profile_marker; 32]),
            gate,
            endpoints,
        )
        .unwrap()
    }

    #[test]
    fn reserves_replays_and_recovers_one_assignment_bound_handle() {
        let directory = TempDir::new().unwrap();
        let profile = isolated_profile();
        let policy = policy_catalog(1, profile.clone(), 81);
        let spec = sandbox_spec(profile);
        let manifest = manifest(&spec, 2, 5);
        let reservation = NetworkPreparationReservationV1::new(&manifest, &spec).unwrap();
        let authority = authority();
        let mut catalog =
            NetworkPreparationCatalogV1::open_for_test(directory.path(), policy.clone(), 1)
                .unwrap();

        let first = catalog.reserve(reservation.clone(), &authority).unwrap();
        assert!(matches!(
            first,
            NetworkPreparationCatalogOutcomeV1::Reserved(_)
        ));
        let handle = *first.preparation().resolution().reserved_network_handle();
        assert_ne!(handle, [0; 32]);
        assert_eq!(
            first.preparation().assignment(),
            manifest.broker_assignment().unwrap()
        );
        assert!(first.preparation().resolution().endpoints().is_empty());
        assert_eq!(
            catalog
                .assignment_for_resolution(handle, first.preparation().resolution())
                .unwrap(),
            manifest.broker_assignment().unwrap()
        );
        assert_eq!(
            catalog
                .program_for_resolution(handle, first.preparation().resolution())
                .unwrap(),
            policy.profiles()[0].program()
        );
        let substituted = ResolvedNetworkPreparationV1::new(
            2,
            handle,
            ObjectDigest::from_bytes([82; 32]),
            Vec::new(),
        )
        .unwrap();
        assert!(matches!(
            catalog.assignment_for_resolution(handle, &substituted),
            Err(NetworkPreparationCatalogError::InvalidCandidate)
        ));
        assert!(matches!(
            catalog.assignment_for_resolution([99; 32], first.preparation().resolution()),
            Err(NetworkPreparationCatalogError::InvalidCandidate)
        ));
        assert!(matches!(
            catalog.program_for_resolution([99; 32], first.preparation().resolution()),
            Err(NetworkPreparationCatalogError::InvalidCandidate)
        ));
        assert!(matches!(
            catalog.reserve(reservation.clone(), &authority).unwrap(),
            NetworkPreparationCatalogOutcomeV1::Replay(_)
        ));
        drop(catalog);

        let mut recovered =
            NetworkPreparationCatalogV1::open_for_test(directory.path(), policy, 1).unwrap();
        let replay = recovered.reserve(reservation, &authority).unwrap();
        assert_eq!(
            replay.preparation().resolution().reserved_network_handle(),
            &handle
        );
        assert!(recovered.journal_sequence() > 1);
    }

    #[test]
    fn assignment_advancement_cannot_rebind_an_incarnation() {
        let directory = TempDir::new().unwrap();
        let profile = isolated_profile();
        let policy = policy_catalog(1, profile.clone(), 81);
        let spec = sandbox_spec(profile);
        let first_manifest = manifest(&spec, 2, 5);
        let newer_manifest = manifest(&spec, 2, 6);
        let authority = authority();
        let mut catalog =
            NetworkPreparationCatalogV1::open_for_test(directory.path(), policy, 1).unwrap();
        catalog
            .reserve(
                NetworkPreparationReservationV1::new(&first_manifest, &spec).unwrap(),
                &authority,
            )
            .unwrap();

        assert!(matches!(
            catalog.reserve(
                NetworkPreparationReservationV1::new(&newer_manifest, &spec).unwrap(),
                &authority,
            ),
            Err(NetworkPreparationCatalogError::IdentityConflict)
        ));
    }

    #[test]
    fn distinct_incarnations_receive_distinct_handles_and_tokens_are_not_relocatable() {
        let directory = TempDir::new().unwrap();
        let profile = isolated_profile();
        let policy = policy_catalog(1, profile.clone(), 81);
        let first_spec = sandbox_spec(profile.clone());
        let second_spec = sandbox_spec(profile);
        let first_manifest = manifest(&first_spec, 2, 5);
        let second_manifest = manifest(&second_spec, 9, 5);
        let authority = authority();
        let mut catalog =
            NetworkPreparationCatalogV1::open_for_test(directory.path(), policy, 1).unwrap();

        let first = catalog
            .reserve(
                NetworkPreparationReservationV1::new(&first_manifest, &first_spec).unwrap(),
                &authority,
            )
            .unwrap();
        let second = catalog
            .reserve(
                NetworkPreparationReservationV1::new(&second_manifest, &second_spec).unwrap(),
                &authority,
            )
            .unwrap();
        assert_ne!(
            first.preparation().resolution().reserved_network_handle(),
            second.preparation().resolution().reserved_network_handle()
        );
        assert!(
            authority
                .validate_catalog(
                    first.preparation(),
                    second_manifest.broker_assignment().unwrap(),
                )
                .is_err()
        );
    }

    #[test]
    fn policy_head_and_reservations_cannot_move_between_nodes() {
        let directory = TempDir::new().unwrap();
        let foreign_node = NodeId::from_bytes([32; 16]);
        let profile = isolated_profile();
        let policy = policy_catalog(1, profile.clone(), 81);
        let spec = sandbox_spec(profile.clone());
        let foreign_manifest = manifest_for_node(&spec, foreign_node, 2, 5);
        let authority = authority();
        let mut catalog =
            NetworkPreparationCatalogV1::open_for_test(directory.path(), policy, 1).unwrap();

        assert!(matches!(
            catalog.reserve(
                NetworkPreparationReservationV1::new(&foreign_manifest, &spec).unwrap(),
                &authority,
            ),
            Err(NetworkPreparationCatalogError::InvalidCandidate)
        ));
        drop(catalog);

        let foreign_policy = policy_catalog_for_node(foreign_node, 2, profile, 82);
        assert!(matches!(
            NetworkPreparationCatalogV1::open_for_test(directory.path(), foreign_policy, 2),
            Err(NetworkPreparationCatalogError::Rollback)
        ));
        let isolated = isolated_profile();
        let isolated_program = policy_program(&isolated, 81);
        assert!(matches!(
            NetworkPolicyCatalogV1::new(
                NodeId::from_bytes([0; 16]),
                1,
                vec![NetworkPolicyProfileV1::new(isolated, isolated_program).unwrap()],
            ),
            Err(NetworkPreparationCatalogError::InvalidPolicy)
        ));
    }

    #[test]
    fn policy_head_advances_and_rejects_rollback_or_same_generation_fork() {
        let directory = TempDir::new().unwrap();
        let first = policy_catalog(1, isolated_profile(), 81);
        NetworkPreparationCatalogV1::open_for_test(directory.path(), first.clone(), 1).unwrap();
        let second = policy_catalog(2, isolated_profile(), 82);
        let advanced =
            NetworkPreparationCatalogV1::open_for_test(directory.path(), second.clone(), 2)
                .unwrap();
        assert_eq!(advanced.policy_generation(), 2);
        drop(advanced);

        assert!(matches!(
            NetworkPreparationCatalogV1::open_for_test(directory.path(), first, 1),
            Err(NetworkPreparationCatalogError::Rollback)
        ));
        assert!(matches!(
            NetworkPreparationCatalogV1::open_for_test(
                directory.path(),
                policy_catalog(2, isolated_profile(), 83),
                2,
            ),
            Err(NetworkPreparationCatalogError::Rollback)
        ));
        assert!(matches!(
            NetworkPreparationCatalogV1::open_for_test(directory.path(), second, 3),
            Err(NetworkPreparationCatalogError::Rollback)
        ));
    }

    #[test]
    fn policy_roll_forward_cannot_substitute_an_unsettled_program() {
        let directory = TempDir::new().unwrap();
        let portable_profile = isolated_profile();
        let first_policy = policy_catalog(1, portable_profile.clone(), 81);
        let spec = sandbox_spec(portable_profile.clone());
        let manifest = manifest(&spec, 2, 5);
        let reservation = NetworkPreparationReservationV1::new(&manifest, &spec).unwrap();
        let authority = authority();
        let mut first =
            NetworkPreparationCatalogV1::open_for_test(directory.path(), first_policy, 1).unwrap();
        let resolution = first
            .reserve(reservation, &authority)
            .unwrap()
            .into_preparation()
            .resolution()
            .clone();
        let handle = *resolution.reserved_network_handle();
        drop(first);

        let second_policy = policy_catalog(2, portable_profile, 82);
        let advanced =
            NetworkPreparationCatalogV1::open_for_test(directory.path(), second_policy, 2).unwrap();
        assert!(matches!(
            advanced.program_for_resolution(handle, &resolution),
            Err(NetworkPreparationCatalogError::InvalidCandidate)
        ));
    }

    #[test]
    fn recovered_reservation_cannot_claim_a_generation_beyond_the_policy_head() {
        let directory = TempDir::new().unwrap();
        let profile = isolated_profile();
        let policy = policy_catalog(1, profile.clone(), 81);
        let newer_policy = policy_catalog(2, profile.clone(), 82);
        let spec = sandbox_spec(profile);
        let manifest = manifest(&spec, 2, 5);
        let authority = authority();
        let mut catalog =
            NetworkPreparationCatalogV1::open_for_test(directory.path(), policy.clone(), 1)
                .unwrap();
        let reserved = catalog
            .reserve(
                NetworkPreparationReservationV1::new(&manifest, &spec).unwrap(),
                &authority,
            )
            .unwrap();
        let handle = *reserved
            .preparation()
            .resolution()
            .reserved_network_handle();
        drop(catalog);

        let (mut journal, _) = Journal::open(
            directory.path().join(PREPARATION_JOURNAL_FILE),
            preparation_journal_limits(),
        )
        .unwrap();
        let mut record = decode_record(
            journal
                .get(
                    RecordNamespace::NetworkResourceInventory,
                    &record_key(&handle),
                )
                .unwrap(),
        )
        .unwrap();
        record.catalog_generation = 2;
        let resolution = ResolvedNetworkPreparationV1::new(
            2,
            record.network_handle,
            ObjectDigest::from_bytes(record.profile_digest),
            record
                .endpoints
                .iter()
                .map(EndpointWire::endpoint)
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
        )
        .unwrap();
        record.resolution_digest = *resolution.binding().digest().as_bytes();
        record.reservation_digest = [0; 32];
        record.reservation_digest = record.derive_digest().unwrap();
        journal
            .commit(
                &JournalTransaction::new(
                    [91; 16],
                    vec![JournalRecord::put(
                        RecordNamespace::NetworkResourceInventory,
                        record_key(&handle),
                        encode_record(&record).unwrap(),
                    )],
                )
                .unwrap(),
            )
            .unwrap();
        drop(journal);

        assert!(matches!(
            NetworkPreparationCatalogV1::open_for_test(directory.path(), newer_policy, 2),
            Err(NetworkPreparationCatalogError::Rollback)
        ));

        let (journal, _) = Journal::open(
            directory.path().join(PREPARATION_JOURNAL_FILE),
            preparation_journal_limits(),
        )
        .unwrap();
        let head = decode_head(
            journal
                .get(RecordNamespace::NetworkResourceInventory, HEAD_KEY)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(head.generation, 1);
        assert_eq!(head.node, *NODE.as_bytes());
        assert_eq!(head.digest, *policy.digest().as_bytes());
        drop(journal);

        assert!(matches!(
            NetworkPreparationCatalogV1::open_for_test(directory.path(), policy, 1),
            Err(NetworkPreparationCatalogError::Rollback)
        ));
    }

    #[test]
    fn policy_and_portable_input_mismatches_fail_closed() {
        let project = project_profile(&[7, 8]);
        let incomplete = project_profile(&[7]);
        assert!(matches!(
            NetworkPolicyProfileV1::new(project.clone(), policy_program(&incomplete, 81)),
            Err(NetworkPreparationCatalogError::InvalidPolicy)
        ));

        let host_spec =
            sandbox_spec(NetworkProfile::new(NetworkKind::Host, Vec::new(), Vec::new()).unwrap());
        let host_manifest = manifest(&host_spec, 2, 5);
        assert!(matches!(
            NetworkPreparationReservationV1::new(&host_manifest, &host_spec),
            Err(NetworkPreparationCatalogError::InvalidCandidate)
        ));

        let directory = TempDir::new().unwrap();
        let policy = policy_catalog(1, isolated_profile(), 81);
        let project_spec = sandbox_spec(project);
        let project_manifest = manifest(&project_spec, 2, 5);
        let mut catalog =
            NetworkPreparationCatalogV1::open_for_test(directory.path(), policy, 1).unwrap();
        assert!(matches!(
            catalog.reserve(
                NetworkPreparationReservationV1::new(&project_manifest, &project_spec).unwrap(),
                &authority(),
            ),
            Err(NetworkPreparationCatalogError::InvalidCandidate)
        ));
    }

    #[test]
    fn production_catalog_open_rejects_relative_and_unprotected_paths() {
        assert!(
            NetworkPreparationCatalogV1::open_root_owned(
                Path::new("relative"),
                policy_catalog(1, isolated_profile(), 81),
                1,
            )
            .is_err()
        );

        let directory = TempDir::new().unwrap();
        assert!(
            NetworkPreparationCatalogV1::open_root_owned(
                directory.path(),
                policy_catalog(1, isolated_profile(), 81),
                1,
            )
            .is_err()
        );
    }

    #[test]
    fn catalog_digest_commits_features_and_endpoint_policy_objects() {
        let required = FeatureRef::new("aos.sandbox.network.default-drop", 1, 0).unwrap();
        let profile = NetworkProfile::new(
            NetworkKind::Project,
            vec![NetworkEndpointId::from_bytes([7; 16])],
            vec![required],
        )
        .unwrap();
        let original = policy_catalog(1, profile.clone(), 81).digest();
        let changed_policy = policy_catalog(1, profile, 82).digest();
        let without_feature = policy_catalog(1, project_profile(&[7]), 81).digest();
        assert_ne!(original, changed_policy);
        assert_ne!(original, without_feature);
    }
}
