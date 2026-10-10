//! Issues private source launches for one complete refused collection programme.
//!
//! This trusted host helper retains explicit predeclared capabilities and public
//! source bodies. It cannot accept a class, launch Child, admit an ordinary graph
//! or export private launch material as a content object.

use super::{
    InstalledTypedReaderPackage, TypedReaderCollectionWorld, TypedReaderFixtureAudit,
    TypedReaderProgramme,
};
use crate::node_qualification::WitnessPlan;
use crucible_node_contract::*;
use crucible_node_provider::{
    ProviderError,
    handshake::Limits,
    reference_service::{
        InstalledContent, LineageReaderDefinitionSources,
        ReferenceNegotiatedLineageReaderLaunchBootstrap, ReferenceServiceBootstrap,
    },
};
use std::collections::BTreeMap;

/// Retains explicit host-issued private authorization before any native group exists.
///
/// Callers obtain fresh nonexported 32-byte capabilities from their configured
/// trusted issuer. Deterministic test identifiers do not replace those secrets.
/// This record deliberately has no Debug, Serialize, Clone or decoded constructor.
pub struct TypedReaderPrivateAuthorization {
    /// Retains one independent unactivated original native authority.
    pub authority: LiveAuthority,
    /// Retains its secret private admission capability.
    pub capability: Bytes,
}

/// Borrows the complete independently configured private issuance inputs.
///
/// These inputs remain owned by the caller on refusal. No package-derived
/// secret, acceptance claim or existing native Child is constructed here.
pub struct TypedReaderFixtureLaunchRequest<'a> {
    /// Borrows the independently selected measured source package.
    pub package: &'a InstalledTypedReaderPackage,
    /// Borrows the frozen nine-window source programme.
    pub programme: &'a TypedReaderProgramme,
    /// Borrows the complete all-required collection plan.
    pub plan: &'a WitnessPlan,
    /// Borrows the exact complete public limitations document named by the plan.
    pub limitations_bytes: &'a [u8],
    /// Pins the canonical complete plan bytes.
    pub plan_reference: &'a ContentRef,
    /// Borrows the original all-NotExecuted, Refused audit data.
    pub audit: &'a TypedReaderFixtureAudit,
    /// Borrows the independently configured native resource ceilings.
    pub resources: &'a ResourceLimits,
    /// Supplies finite original protocol receiving limits.
    pub limits: Limits,
    /// Borrows three separately issued private capabilities and authorities.
    pub authorizations: &'a [TypedReaderPrivateAuthorization; 3],
}

/// Retains all private source launch bodies beside the fixed public world data.
///
/// This object creates no execution or graph authority. Launch bytes are borrowed
/// only by the existing pre-reserved owning session preparer and never hashed.
pub struct TypedReaderFixtureLaunches {
    world: TypedReaderCollectionWorld,
    launches: [ReferenceNegotiatedLineageReaderLaunchBootstrap; 3],
}

impl TypedReaderFixtureLaunches {
    /// Issues exact qualified-scope private launches from complete refused audit data.
    ///
    /// All public bodies are charged together before source clones; each complete
    /// private launch is counted before retention. Caller authorization remains
    /// owned on error because this constructor borrows the original array.
    ///
    /// # Errors
    /// Refuses changed plan/audit/source scope, duplicate or malformed private
    /// capabilities, wrong original owners, missing codec roles or exhausted credit.
    pub fn prepare(request: TypedReaderFixtureLaunchRequest<'_>) -> Result<Self, ProviderError> {
        let TypedReaderFixtureLaunchRequest {
            package,
            programme,
            plan,
            plan_reference,
            limitations_bytes,
            audit,
            resources,
            limits,
            authorizations,
        } = request;
        plan.limitations.verify(limitations_bytes)?;
        let bytes = super::source_fixture::launch::encode(plan, 1024 * 1024)?;
        plan_reference.verify(&bytes)?;
        if programme.witness_plan(plan.unit.clone(), plan.limitations.clone())? != *plan
            || audit.record().evaluated_unit != plan.unit
            || audit.record().required_classes != plan.classes
            || audit.record().original.applicability_policy != *plan_reference
            || !matches!(
                audit.record().decision,
                crate::node_qualification::AcceptanceDecision::Refused { .. }
            )
        {
            return Err(invalid());
        }
        audit.claim().verify(audit.original_bytes())?;
        resources.validate()?;
        limits.validate()?;
        if resources.processes.get() != 2 || !(1..=64).contains(&resources.maximum_operations.get())
        {
            return Err(invalid());
        }
        for (index, authorization) in authorizations.iter().enumerate() {
            let peer = &programme.peers[index];
            authorization.authority.validate()?;
            if authorization.authority.incarnation_id != peer.incarnation
                || authorization.authority.owner_generation.get() != 1
                || authorization.authority.activation_id.is_some()
                || authorization.authority.world_generation.get() != 0
                || authorization.capability.as_slice().len() != 32
                || authorizations[..index].iter().any(|prior| {
                    prior.capability == authorization.capability
                        || prior.authority.session_id == authorization.authority.session_id
                        || prior.authority.realization_id == authorization.authority.realization_id
                })
            {
                return Err(invalid());
            }
        }
        let mut qualifications = vec![plan_reference.clone(), audit.claim().clone()];
        qualifications.sort();
        let world = TypedReaderCollectionWorld::prepare(package, programme, &qualifications)?;
        let world_hash = world.world().identity()?;
        // Precharge every borrowed public body, including duplicate occurrences,
        // before building a reference map or copying any installed payload. Four
        // MiB additionally covers two bounded admission bodies (including base64
        // expansion) and the independently bounded private envelope metadata.
        let mut encoded_credit = 4 * 1024 * 1024usize;
        let mut object_credit = 2usize;
        for (reference, body) in world
            .objects()
            .iter()
            .map(|(r, b)| (r, b.as_slice()))
            .chain(
                package
                    .definition_objects()
                    .iter()
                    .map(|(r, b)| (r, b.as_slice())),
            )
            .chain([
                (plan_reference, bytes.as_slice()),
                (audit.claim(), audit.original_bytes()),
                (&plan.limitations, limitations_bytes),
            ])
        {
            charge_public_body(reference, body, &mut encoded_credit, &mut object_credit)?;
        }
        let mut content: BTreeMap<ContentRef, &[u8]> = world
            .objects()
            .iter()
            .map(|(reference, bytes)| (reference.clone(), bytes.as_slice()))
            .collect();
        for (reference, bytes) in package.definition_objects() {
            if let Some(old) = content.insert(reference.clone(), bytes)
                && old != bytes
            {
                return Err(invalid());
            }
        }
        content.insert(plan_reference.clone(), &bytes);
        content.insert(audit.claim().clone(), audit.original_bytes());
        if let Some(old) = content.insert(plan.limitations.clone(), limitations_bytes)
            && old != limitations_bytes
        {
            return Err(invalid());
        }
        let definition = package.definition().declaration();
        let core = |identifier: &str| -> Result<ContentRef, ProviderError> {
            definition
                .dependencies
                .iter()
                .find_map(|dependency| match dependency {
                    ExtensionDependency::Core {
                        identifier: name,
                        version: 1,
                        definition,
                    } if name.as_str() == identifier => Some(definition.clone()),
                    _ => None,
                })
                .ok_or_else(invalid)
        };
        let definitions = LineageReaderDefinitionSources {
            namespace_publication: definition.owner.publication_origin.clone(),
            handler: package.definition().handler().clone(),
            event: core("cnp.event")?,
            input: core("cnp.input-batch")?,
            stop: core("cnp.stop-receipt")?,
        };
        let mut launches = Vec::new();
        launches.try_reserve_exact(3).map_err(|_| invalid())?;
        for (index, peer) in programme.peers.iter().enumerate() {
            let profile = package
                .profile(
                    peer.node.clone(),
                    peer.owner.clone(),
                    U64::new(1000),
                    U64::new(1_000_000_000),
                    index < 2,
                )
                .map_err(|_| invalid())?;
            let authorization = &authorizations[index];
            let mut bootstrap = ReferenceServiceBootstrap::fixture(
                &profile,
                authorization.authority.clone(),
                authorization.capability.clone(),
                U64::new(u64::from(rustix::process::geteuid().as_raw())),
                limits,
                resources.clone(),
                world_hash.clone(),
            )?;
            // This bounded metadata counter excludes the forthcoming public
            // content; its conservative whole-body credit was reserved above.
            bootstrap.installed_content.clear();
            super::owning::count_launch(&bootstrap, 1024 * 1024)?;
            let (binding, _) =
                profile.bind_qualified(bootstrap.authority.clone(), &qualifications)?;
            let record = AdmissionRecord {
                schema_version: 1,
                realization_id: bootstrap.authority.realization_id.clone(),
                binding_hashes: vec![binding.identity()?],
                world_binding_hash: world_hash.clone(),
                measured_artifacts: profile.implementation.artifacts.clone(),
                qualification_refs: qualifications.clone(),
                resource_limits: resources.clone(),
                evidence_refs: Vec::new(),
                extensions: Extensions::new(),
            };
            record.validate()?;
            let record_bytes = super::source_fixture::launch::encode(&record, 1024 * 1024)?;
            let record_ref = canonical::content_ref(&record_bytes, "application/json")?;
            let receipt = ControlReceipt {
                schema_version: 1,
                kind: ControlReceiptKind::Admission,
                session_id: bootstrap.authority.session_id.clone(),
                incarnation_id: peer.incarnation.clone(),
                request_id: Id::new(format!("typed-fixture/{}/admission", peer.node))?,
                operation_id: None,
                owner_ids: vec![peer.owner.clone()],
                world_generation: U64::new(0),
                record_ref: record_ref.clone(),
                issuer: ReceiptIssuer::Host,
                extensions: Extensions::new(),
            };
            receipt.validate()?;
            let receipt_bytes = super::source_fixture::launch::encode(&receipt, 1024 * 1024)?;
            let receipt_ref = canonical::content_ref(&receipt_bytes, "application/json")?;
            bootstrap.authority.host_receipt = receipt_ref.clone();
            bootstrap.admission_receipt = receipt_ref.clone();
            bootstrap.admission_id = Id::new(format!("typed-fixture/{}/admission", peer.node))?;
            bootstrap.prepared_token = Id::new(format!("typed-fixture/{}/prepared", peer.node))?;
            bootstrap.gate_id = Id::new(format!("typed-fixture/{}/gate", peer.node))?;
            bootstrap.transaction_id = Id::new("typed-fixture/transaction")?;
            bootstrap.activation_id = Id::new("typed-fixture/activation")?;
            super::owning::count_launch(&bootstrap, 1024 * 1024)?;
            let mut installed_content = Vec::new();
            installed_content
                .try_reserve_exact(content.len() + 2)
                .map_err(|_| invalid())?;
            for (reference, body) in &content {
                installed_content.push(InstalledContent {
                    reference: reference.clone(),
                    bytes: Bytes::new(body.to_vec()),
                });
            }
            installed_content.push(InstalledContent {
                reference: record_ref,
                bytes: Bytes::new(record_bytes),
            });
            installed_content.push(InstalledContent {
                reference: receipt_ref,
                bytes: Bytes::new(receipt_bytes),
            });
            bootstrap.installed_content = installed_content;
            let launch = ReferenceNegotiatedLineageReaderLaunchBootstrap {
                schema_version: 7,
                closed_ingress: index < 2,
                bootstrap,
                qualification_refs: qualifications.clone(),
                definition_sources: definitions.clone(),
            };
            launch.validate()?;
            super::owning::count_launch(&launch, 16 * 1024 * 1024)?;
            launches.push(launch);
        }
        let launches = launches.try_into().map_err(|_| invalid())?;
        Ok(Self { world, launches })
    }

    /// Borrows exact public world data without an admitted graph.
    pub fn world(&self) -> &TypedReaderCollectionWorld {
        &self.world
    }

    /// Borrows private launch originals solely for the owning pre-Child session API.
    ///
    /// Callers must not persist, log or content-hash this capability-bearing data.
    pub fn private_launches(&self) -> &[ReferenceNegotiatedLineageReaderLaunchBootstrap; 3] {
        &self.launches
    }
}

fn charge_public_body(
    reference: &ContentRef,
    body: &[u8],
    encoded_credit: &mut usize,
    object_credit: &mut usize,
) -> Result<(), ProviderError> {
    reference.verify(body)?;
    super::owning::count_launch(reference, 1024)?;
    let encoded = body
        .len()
        .checked_add(2)
        .and_then(|n| n.checked_div(3))
        .and_then(|n| n.checked_mul(4))
        .and_then(|n| n.checked_add(1024))
        .ok_or_else(invalid)?;
    *encoded_credit = encoded_credit
        .checked_add(encoded)
        .filter(|n| *n <= 16 * 1024 * 1024)
        .ok_or_else(invalid)?;
    *object_credit = object_credit
        .checked_add(1)
        .filter(|n| *n <= 4096)
        .ok_or_else(invalid)?;
    Ok(())
}

fn invalid() -> ProviderError {
    ProviderError::Correlation("typed refused fixture private issuance differs")
}

#[cfg(test)]
// Inert credit controls cannot issue private launch or source authority.
#[path = "fixture_launches_tests.rs"]
mod tests;
