//! Builds source-owned private candidate metadata before native allocation.
//!
//! This constructor is available only to the installed qualification issuer.
//! It does not accept a caller's qualification verdict or ordinary scenario
//! selector. Original live bindings remain distinct from reusable unit data.

use std::{io::Read, rc::Rc};

use crucible::node_contract::{ActivationRecord, OwnerIdentity};
use crucible_node_contract::*;
use crucible_node_provider::{
    ProviderError,
    handshake::Limits,
    reference_service::{InstalledContent, ReferenceServiceBootstrap},
};

use super::{
    installation::SourcePublicReferenceInstallation, package::InstalledPublicReferencePackage,
    world::CandidateWorldDefinition,
};

pub(super) struct PrivateCandidate {
    pub(super) definition: CandidateWorldDefinition,
    pub(super) installations: Vec<SourcePublicReferenceInstallation>,
    pub(super) activation: ActivationRecord,
}

impl PrivateCandidate {
    /// Creates fresh private authority for one source-selected candidate attempt.
    pub(super) fn new(
        package: Rc<InstalledPublicReferencePackage>,
        quantum_ps: U64,
        host_budget_ns: U64,
    ) -> Result<Self, ProviderError> {
        let nonce = entropy()?;
        Self::with_nonce(package, quantum_ps, host_budget_ns, nonce)
    }

    /// Uses a locally issued nonce, retaining it only in original live authority.
    pub(super) fn with_nonce(
        package: Rc<InstalledPublicReferencePackage>,
        quantum_ps: U64,
        host_budget_ns: U64,
        nonce: Bytes,
    ) -> Result<Self, ProviderError> {
        let definition = CandidateWorldDefinition::build(
            Rc::clone(&package),
            quantum_ps,
            host_budget_ns,
            nonce,
        )?;
        let mut installations = Vec::with_capacity(2);
        for (index, profile) in definition.profiles().iter().enumerate() {
            let bootstrap = ReferenceServiceBootstrap::fixture(
                profile,
                definition.authority(&profile.descriptor.id)?,
                entropy()?,
                U64::new(u64::from(rustix::process::geteuid().as_raw())),
                Limits {
                    frame_bytes: U64::new(1_048_576),
                    nesting: U64::new(64),
                    requests: U64::new(16),
                    journal_entries: U64::new(256),
                    blob_chunk_bytes: U64::new(16_384),
                },
                ResourceLimits {
                    cpu_budget_ns: U64::new(4_000_000_000),
                    memory_bytes: U64::new(512 * 1024 * 1024),
                    writable_bytes: U64::new(0),
                    processes: U64::new(2),
                    descriptors: U64::new(32),
                    pending_events: U64::new(16),
                    content_bytes: U64::new(16 * 1024 * 1024),
                    maximum_operations: U64::new(8),
                    extensions: Extensions::new(),
                },
                definition.world.identity()?,
            )?;
            let bytes = definition
                .content
                .get(definition.qualification())
                .ok_or(ProviderError::Correlation(
                    "candidate mechanism bytes absent",
                ))?
                .clone();
            let qualification = InstalledContent {
                reference: definition.qualification().clone(),
                bytes: Bytes::new(bytes),
            };
            #[cfg(test)]
            let (bootstrap, qualifications) = if package.is_progress_fixture() {
                super::source_native_progress_loss::bind_candidate(
                    bootstrap,
                    profile,
                    qualification,
                )?
            } else {
                let launch = bootstrap.install_qualifications(profile, vec![qualification])?;
                (launch.bootstrap, launch.qualification_refs)
            };
            #[cfg(not(test))]
            let (bootstrap, qualifications) = {
                let launch = bootstrap.install_qualifications(profile, vec![qualification])?;
                (launch.bootstrap, launch.qualification_refs)
            };
            installations.push(SourcePublicReferenceInstallation::new(
                Rc::clone(&package),
                profile.clone(),
                bootstrap,
                qualifications,
                index == 1,
            )?);
        }
        let first = installations
            .first()
            .ok_or(ProviderError::Frame("candidate inventory absent"))?;
        let activation = ActivationRecord {
            generation: first.bootstrap.world_generation,
            activation_id: first.bootstrap.activation_id.clone(),
            world_binding_hash: definition.world.identity()?,
            owners: installations
                .iter()
                .map(|installed| OwnerIdentity {
                    owner: installed.profile.owner.id.clone(),
                    incarnation: installed.bootstrap.authority.incarnation_id.clone(),
                    generation: installed.bootstrap.authority.owner_generation,
                })
                .collect(),
            boundary: Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl),
        };
        if installations.iter().any(|installed| {
            installed.bootstrap.activation_id != activation.activation_id
                || installed.bootstrap.world_generation != activation.generation
                || installed.bootstrap.world_binding_hash != activation.world_binding_hash
        }) {
            return Err(ProviderError::Correlation(
                "candidate original activation inventory differs",
            ));
        }
        Ok(Self {
            definition,
            installations,
            activation,
        })
    }
}

/// Reads kernel entropy before minting any native or world identity.
pub(super) fn entropy() -> Result<Bytes, ProviderError> {
    let mut bytes = vec![0; 32];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(Bytes::new(bytes))
}
