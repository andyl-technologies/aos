//! Precredits complete refused scope and reauthenticates it before collection.

use std::io::{self, Write};

use crucible_node_contract::{HashRef, OperatingMode, U64, canonical};
use serde::Serialize;

use super::*;

const DOCUMENT_BYTES: usize = 8 * 1024 * 1024;

struct Size {
    bytes: usize,
    limit: usize,
}

impl Write for Size {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(bytes.len())
            .filter(|size| *size <= self.limit)
            .ok_or_else(|| io::Error::other("complete packet fixture credit"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn encoded(value: &impl Serialize) -> Result<Vec<u8>, QualificationError> {
    serde_json::to_writer(
        Size {
            bytes: 0,
            limit: DOCUMENT_BYTES,
        },
        value,
    )
    .map_err(crucible_node_contract::ContractError::from)?;
    Ok(canonical::canonical_json(
        &serde_json::to_value(value).map_err(crucible_node_contract::ContractError::from)?,
    )?)
}

fn classes(
    source: &PacketSemanticSource,
) -> Result<BTreeSet<QualificationClass>, QualificationError> {
    let selection = source.installation();
    if selection.profile.profile_id.as_str() != "source-owned.packet-emitter/2"
        || selection.binding.compatibility.operating_contract.mode != OperatingMode::Exact
        || (selection.descriptor.roles.len() != 1
            || selection.descriptor.roles[0].as_str() != "external_device")
    {
        return Err(QualificationError::Refused(
            "unsupported packet collection classes",
        ));
    }
    Ok(BTreeSet::from([
        QualificationClass::BaseProvider,
        QualificationClass::ExactTiming,
        QualificationClass::RoleProfile,
    ]))
}

pub(super) fn install(
    input: PacketCollectionInstallation<'_>,
) -> Result<Rc<InstalledPacketCollectionAuthority>, QualificationError> {
    if input.source_objects.is_empty()
        || input.source_objects.len() > 32
        || input
            .source_objects
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || input.maximum_report_bytes == 0
        || input.maximum_report_bytes > 64 * 1024 * 1024
    {
        return Err(QualificationError::Refused(
            "packet fixture original retention credit",
        ));
    }
    let required = classes(&input.source)?;
    let selection = input.source.installation();
    if input.world.identity()? != selection.world_binding_hash
        || input.world.node_bindings.len() != 1
        || (input.world.node_bindings[0].node_id != selection.descriptor.id
            || input.world.node_bindings[0].binding_hash
                != selection.binding.compatibility.identity()?)
        || !input.world.connections.is_empty()
    {
        return Err(QualificationError::Refused(
            "packet fixture complete world changed",
        ));
    }
    let scope = input.installed.scope_for_node(&selection.descriptor.id)?;
    if scope.binding != &selection.binding.compatibility
        || scope.required_classes != required
        || input.plan.classes != required
        || input.plan.unit != scope.current_unit
        || !matches!(scope.record.decision, AcceptanceDecision::Refused { .. })
        || scope.record.required_classes != required
        || scope.record.evaluated_unit != scope.current_unit
        || scope.record.original_claim != *scope.original_claim
        || scope.record.original.unit != scope.current_unit
    {
        return Err(QualificationError::Refused(
            "packet fixture requires exact current refused scope",
        ));
    }
    // Count the full retained plan/audit/world/source roster before any copies.
    serde_json::to_writer(
        Size {
            bytes: 0,
            limit: DOCUMENT_BYTES,
        },
        &(input.plan, scope.record, input.world, input.source_objects),
    )
    .map_err(crucible_node_contract::ContractError::from)?;
    if scope.original_bytes.len() > input.limits.maximum_claim_bytes {
        return Err(QualificationError::Refused("original packet claim credit"));
    }
    let plan_bytes = encoded(input.plan)?;
    let refused_bytes = encoded(scope.record)?;
    input.plan_reference.verify(&plan_bytes)?;
    scope.original_claim.verify(scope.original_bytes)?;
    input
        .oracle
        .authenticate_installation(&input.source, input.plan, input.installed.as_ref())?;
    input.installed.authenticate_packet_installation(
        selection,
        input.world,
        input.plan,
        input.source_objects,
    )?;
    let reports = OriginalRuntimeReportStore::new(
        input.installed.as_ref(),
        input.plan,
        input.plan_reference,
        input.limits,
        input.maximum_report_bytes,
    )?;
    let refused_reference = canonical::content_ref(&refused_bytes, "application/json")?;
    let original_claim = scope.original_claim.clone();
    drop(scope);
    let installed = Rc::new(InstalledPacketCollectionAuthority {
        source: input.source,
        installed: input.installed,
        graph_evidence: input.graph_evidence,
        oracle: input.oracle,
        plan: input.plan.clone(),
        plan_reference: input.plan_reference.clone(),
        plan_bytes,
        refused_reference,
        refused_bytes,
        original_claim,
        world: input.world.clone(),
        source_objects: input.source_objects.to_vec(),
        classes: required,
        reports: RefCell::new(reports),
    });
    installed.current()?;
    Ok(installed)
}

pub(super) fn current(
    authority: &InstalledPacketCollectionAuthority,
) -> Result<(), QualificationError> {
    let selection = authority.source.installation();
    let scope = authority
        .installed
        .scope_for_node(&selection.descriptor.id)?;
    if scope.binding != &selection.binding.compatibility
        || scope.required_classes != authority.classes
        || scope.current_unit != authority.plan.unit
        || scope.original_claim != &authority.original_claim
        || scope.record.original_claim != authority.original_claim
        || scope.record.evaluated_unit != authority.plan.unit
        || scope.record.required_classes != authority.classes
        || !matches!(scope.record.decision, AcceptanceDecision::Refused { .. })
    {
        return Err(QualificationError::Refused(
            "original packet collection scope revoked or changed",
        ));
    }
    scope.original_claim.verify(scope.original_bytes)?;
    if encoded(scope.record)? != authority.refused_bytes {
        return Err(QualificationError::Refused(
            "original packet refused audit changed",
        ));
    }
    authority.installed.authenticate_plan(
        &authority.plan_reference,
        &authority.plan_bytes,
        &authority.plan,
    )?;
    authority.installed.authenticate_packet_installation(
        selection,
        &authority.world,
        &authority.plan,
        &authority.source_objects,
    )
}

pub(super) fn encoded_program(value: &impl Serialize) -> Result<Vec<u8>, QualificationError> {
    encoded(value)
}

pub(super) fn precharge_native_cases(
    plan: &WitnessPlan,
    cases: &[PacketNativeCase],
) -> Result<(), QualificationError> {
    serde_json::to_writer(
        Size {
            bytes: 0,
            limit: DOCUMENT_BYTES,
        },
        &(plan, cases),
    )
    .map_err(crucible_node_contract::ContractError::from)?;
    Ok(())
}

pub(super) fn encoded_size(
    value: &impl Serialize,
    limit: usize,
) -> Result<usize, QualificationError> {
    let mut counter = Size {
        bytes: 0,
        limit: limit.min(DOCUMENT_BYTES),
    };
    serde_json::to_writer(&mut counter, value)
        .map_err(crucible_node_contract::ContractError::from)?;
    Ok(counter.bytes)
}

// Counts the complete original record without cloning handles or teaching the
// native authority-bearing ActivationRecord a portable serialization grammar.
#[derive(Serialize)]
pub(super) struct ActivationView<'a> {
    generation: U64,
    activation_id: &'a Id,
    world_binding_hash: &'a HashRef,
    owners: &'a [crucible::node_contract::OwnerIdentity],
    boundary: crucible_node_contract::Position,
}

pub(super) fn activation_view(
    record: &crucible::node_contract::ActivationRecord,
) -> ActivationView<'_> {
    ActivationView {
        generation: record.generation,
        activation_id: &record.activation_id,
        world_binding_hash: &record.world_binding_hash,
        owners: &record.owners,
        boundary: record.boundary,
    }
}
