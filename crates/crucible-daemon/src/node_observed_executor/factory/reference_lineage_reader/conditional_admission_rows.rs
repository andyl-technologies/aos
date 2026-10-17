//! Checks both original host-admission transitions beneath signed source history.
//!
//! Intermediate binding hashes and measured native images are historical identity
//! attestations. The original records, receipts, world, qualifications and evidence
//! remain positive bodies. No standalone intermediate binding body is invented.

use crucible_node_contract::{
    AdmissionRecord, ContentRef, ControlReceipt, ControlReceiptKind, Extensions, HashRef, Id,
    LiveAuthority, NodeBinding, ReceiptIssuer, ResourceLimits, U64, Validate, WorldBinding,
    canonical,
};
use crucible_node_provider::reference_service::ReferenceProfile;
use serde::Serialize;

use super::{
    InstalledReaderPackage,
    conditional_capture_records::insert,
    conditional_profile::{ConditionalProfile, encode},
    conditional_source::InspectionError,
    graph,
};

const MAXIMUM_RECORD_BYTES: usize = 65_536;
const MAXIMUM_ROWS: usize = 4096;
const MAXIMUM_EDGES: usize = 65_536;

struct Transition {
    record: AdmissionRecord,
    receipt: ControlReceipt,
}

struct Transitions {
    first: Transition,
    qualified: Transition,
    final_binding: NodeBinding,
}

struct Row {
    reference: ContentRef,
    dependencies: Vec<ContentRef>,
}

/// Projects the two source-built admission transitions without granting authority.
pub(super) fn install(
    target: &mut ConditionalProfile,
    profiles: &[ReferenceProfile],
    package: &InstalledReaderPackage,
    original_world: &WorldBinding,
) -> Result<(), InspectionError> {
    // Check borrowed scope and finite lifetime credit before any body encoding.
    let first = target
        .history
        .bindings
        .values()
        .next()
        .ok_or("original admission roster absent")?;
    if profiles.len() != 3
        || target.history.bindings.len() != 3
        || first.compatibility.qualification_refs.len() != 1
        || target.history.bindings.values().any(|binding| {
            binding.compatibility.qualification_refs != first.compatibility.qualification_refs
        })
        || ["disk", "link", "source"].iter().any(|name| {
            profiles
                .iter()
                .filter(|profile| profile.descriptor.id.as_str() == *name)
                .count()
                != 1
        })
    {
        return Err("original admission profile or qualification roster differs".into());
    }
    first.compatibility.qualification_refs[0]
        .validate()
        .map_err(InspectionError::from_error)?;
    let current_edges = target
        .construction_rows
        .values()
        .try_fold(0usize, |n, row| n.checked_add(row.len()));
    if target
        .construction_rows
        .len()
        .checked_add(12)
        .is_none_or(|n| n > MAXIMUM_ROWS)
        || current_edges
            .and_then(|n| n.checked_add(48))
            .is_none_or(|n| n > MAXIMUM_EDGES)
    {
        return Err("original admission row credit exhausted".into());
    }
    for profile in profiles {
        metadata_credit(&(
            &profile.descriptor,
            &profile.implementation,
            &profile.owner,
            &profile.operating_contract,
            &profile.capabilities,
            &profile.guarantees,
        ))?;
    }
    if target
        .history
        .objects
        .get(package.identity())
        .map(Vec::as_slice)
        != Some(package.document())
        || target.content.get(package.identity()).map(Vec::as_slice) != Some(package.document())
    {
        return Err("original admission measured package body differs".into());
    }
    let world_hash = original_world
        .identity()
        .map_err(InspectionError::from_error)?;
    if target.history.originals.len() != 3
        || target
            .history
            .originals
            .values()
            .any(|source| source.transcript().origin.activation.world_binding_hash != world_hash)
    {
        return Err("original admission world differs from signed FIRST scopes".into());
    }
    let world_bytes = bounded_encode(original_world)?;
    let world_ref = canonical::content_ref(&world_bytes, "application/json")
        .map_err(InspectionError::from_error)?;
    require_body(target, &world_ref, &world_bytes)?;

    let qualification = first.compatibility.qualification_refs[0].clone();
    let mut rows = Vec::new();
    rows.try_reserve_exact(12)
        .map_err(InspectionError::from_error)?;
    for name in ["disk", "link", "source"] {
        let profile = profiles
            .iter()
            .find(|profile| profile.descriptor.id.as_str() == name)
            .ok_or("original admission profile absent")?;
        let original = target
            .history
            .bindings
            .get(&profile.descriptor.id)
            .ok_or("original admission binding absent")?;
        let transitions = reconstruct(profile, &qualification, &world_hash)?;
        if &transitions.final_binding != original {
            return Err("original admission final binding transition differs".into());
        }
        for transition in [transitions.first, transitions.qualified] {
            let record_bytes = bounded_encode(&transition.record)?;
            let record_ref = canonical::content_ref(&record_bytes, "application/json")
                .map_err(InspectionError::from_error)?;
            require_body(target, &record_ref, &record_bytes)?;
            let mut dependencies = Vec::new();
            dependencies
                .try_reserve_exact(
                    1 + transition.record.qualification_refs.len()
                        + transition.record.evidence_refs.len(),
                )
                .map_err(InspectionError::from_error)?;
            dependencies.push(world_ref.clone());
            dependencies.extend(transition.record.qualification_refs);
            dependencies.extend(transition.record.evidence_refs);
            rows.push(Row {
                reference: record_ref,
                dependencies,
            });

            let receipt_bytes = bounded_encode(&transition.receipt)?;
            let receipt_ref = canonical::content_ref(&receipt_bytes, "application/json")
                .map_err(InspectionError::from_error)?;
            require_body(target, &receipt_ref, &receipt_bytes)?;
            rows.push(Row {
                reference: receipt_ref,
                dependencies: vec![transition.receipt.record_ref],
            });
        }
    }

    // All original transitions and existing row associations agree before mutation.
    for row in &mut rows {
        row.dependencies.sort();
        row.dependencies.dedup();
        if target
            .construction_rows
            .get(&row.reference)
            .is_some_and(|old| old != &row.dependencies)
        {
            return Err("original admission dependency row conflicts".into());
        }
    }
    for row in rows {
        insert(
            &mut target.construction_rows,
            row.reference,
            row.dependencies,
        )
        .map_err(InspectionError::from_error)?;
    }
    Ok(())
}

fn reconstruct(
    profile: &ReferenceProfile,
    qualification: &ContentRef,
    world: &HashRef,
) -> Result<Transitions, InspectionError> {
    let mut authority = graph::initial_authority(&profile.descriptor.id, qualification);
    let (first_binding, _) = profile
        .bind(authority.clone())
        .map_err(InspectionError::from_error)?;
    let first = transition(profile, &authority, &first_binding, world, Vec::new())?;
    authority.host_receipt = receipt_ref(&first.receipt)?;
    let (qualified_binding, _) = profile
        .bind_qualified(authority.clone(), std::slice::from_ref(qualification))
        .map_err(InspectionError::from_error)?;
    let qualified = transition(
        profile,
        &authority,
        &qualified_binding,
        world,
        vec![qualification.clone()],
    )?;
    authority.host_receipt = receipt_ref(&qualified.receipt)?;
    let (final_binding, _) = profile
        .bind_qualified(authority, std::slice::from_ref(qualification))
        .map_err(InspectionError::from_error)?;
    Ok(Transitions {
        first,
        qualified,
        final_binding,
    })
}

fn transition(
    profile: &ReferenceProfile,
    authority: &LiveAuthority,
    binding: &NodeBinding,
    world: &HashRef,
    qualifications: Vec<ContentRef>,
) -> Result<Transition, InspectionError> {
    let record = AdmissionRecord {
        schema_version: 1,
        realization_id: authority.realization_id.clone(),
        binding_hashes: vec![binding.identity().map_err(InspectionError::from_error)?],
        world_binding_hash: world.clone(),
        measured_artifacts: profile.implementation.artifacts.clone(),
        qualification_refs: qualifications,
        resource_limits: ResourceLimits {
            cpu_budget_ns: U64::new(8_000_000_000),
            memory_bytes: U64::new(512 * 1024 * 1024),
            writable_bytes: U64::new(0),
            processes: U64::new(2),
            descriptors: U64::new(32),
            pending_events: U64::new(16),
            content_bytes: U64::new(32 * 1024 * 1024),
            maximum_operations: U64::new(16),
            extensions: Extensions::new(),
        },
        evidence_refs: Vec::new(),
        extensions: Extensions::new(),
    };
    record.validate().map_err(InspectionError::from_error)?;
    let record_ref = canonical::content_ref(&bounded_encode(&record)?, "application/json")
        .map_err(InspectionError::from_error)?;
    let receipt = ControlReceipt {
        schema_version: 1,
        kind: ControlReceiptKind::Admission,
        session_id: authority.session_id.clone(),
        incarnation_id: authority.incarnation_id.clone(),
        request_id: Id::new("private-admission").map_err(InspectionError::from_error)?,
        operation_id: None,
        owner_ids: vec![profile.owner.id.clone()],
        world_generation: U64::new(0),
        record_ref,
        issuer: ReceiptIssuer::Host,
        extensions: Extensions::new(),
    };
    receipt.validate().map_err(InspectionError::from_error)?;
    Ok(Transition { record, receipt })
}

fn receipt_ref(receipt: &ControlReceipt) -> Result<ContentRef, InspectionError> {
    canonical::content_ref(&bounded_encode(receipt)?, "application/json")
        .map_err(InspectionError::from_error)
}

fn require_body(
    target: &ConditionalProfile,
    reference: &ContentRef,
    bytes: &[u8],
) -> Result<(), InspectionError> {
    reference
        .verify(bytes)
        .map_err(InspectionError::from_error)?;
    if target.history.objects.get(reference).map(Vec::as_slice) != Some(bytes)
        || target.content.get(reference).map(Vec::as_slice) != Some(bytes)
    {
        return Err("original admission body is absent or differs from signed history".into());
    }
    Ok(())
}

fn bounded_encode(value: &impl Serialize) -> Result<Vec<u8>, InspectionError> {
    metadata_credit(value)?;
    encode(value)
}

fn metadata_credit(value: &impl Serialize) -> Result<(), InspectionError> {
    struct Credit(usize);
    impl std::io::Write for Credit {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .filter(|n| *n <= MAXIMUM_RECORD_BYTES)
                .ok_or_else(|| {
                    std::io::Error::other("original admission metadata credit exhausted")
                })?;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(Credit(0), value).map_err(InspectionError::from_error)?;
    Ok(())
}

#[path = "conditional_admission_rows_models.rs"]
mod models;
