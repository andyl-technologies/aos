//! Derives the exact normal Clock unit from its measured concrete installation.

use std::collections::BTreeMap;
use std::io::Read;

use crate::node_qualification::{QualificationError, QualificationUnit, normative_specification};
use crucible_node_format::{ContentRef, canonical};
use serde::Serialize;

use super::*;

pub(super) struct Unit {
    pub(super) value: QualificationUnit,
    pub(super) content: BTreeMap<ContentRef, Vec<u8>>,
    pub(super) kernel: String,
    pub(super) state_oracle: ContentRef,
    pub(super) ceilings: [(u64, u64); 3],
    pub(super) writable_environment: (u64, u64, u32, u64),
}

pub(super) fn current_kernel() -> Result<String, QualificationError> {
    let mut bytes = Vec::new();
    std::fs::File::open("/proc/sys/kernel/osrelease")
        .map_err(failure)?
        .take(257)
        .read_to_end(&mut bytes)
        .map_err(failure)?;
    if bytes.is_empty() || bytes.len() > 256 {
        return Err(reject("normal Clock current kernel bound"));
    }
    String::from_utf8(bytes).map_err(failure)
}

pub(super) fn derive(
    profile: &InstalledNormalClockProfile,
    origin: &ClockOrigin,
    aggregate: &OriginalClockAggregateResources,
    originals: &OriginalClockQualificationRun,
) -> Result<Unit, QualificationError> {
    origin.current().map_err(failure)?;
    aggregate.authenticate_current().map_err(failure)?;
    let resources = aggregate.limits_data();
    let ceilings = aggregate.process_ceiling_data().map_err(failure)?;
    let writable_environment = aggregate.environment_data().map_err(failure)?;
    let mut content = BTreeMap::new();
    for row in &profile.scenario.content {
        insert(&mut content, row.reference.clone(), row.bytes.clone())?;
    }
    let selected = &profile.scenario.compatibility[0];
    let descriptor = &profile.scenario.descriptors[0];
    let implementation = retain(&mut content, &selected.implementation)?;
    let realization = retain(
        &mut content,
        &(
            &profile.selection,
            &profile.scenario.owners,
            resources,
            super::super::state::resources().maximum_capture_bytes,
            super::super::state::resources().maximum_operations,
        ),
    )?;
    let descriptors = retain(&mut content, &profile.scenario.descriptors)?;
    let contracts = retain(
        &mut content,
        &(
            &selected.operating_contract,
            &selected.capabilities_ref,
            &selected.guarantees_ref,
            &selected.implementation.formats,
        ),
    )?;
    let port_profiles = retain(
        &mut content,
        &(
            &descriptor.roles,
            &descriptor.ports,
            &profile.scenario.world.connections,
        ),
    )?;
    let kernel = current_kernel()?;
    let environment = retain(
        &mut content,
        &(
            std::env::consts::ARCH,
            std::env::consts::OS,
            &kernel,
            "same original owner thread; no autonomous native process or device",
            resources,
            &ceilings,
            &writable_environment,
            "CPU/AS/FD are aggregate shared-daemon ceilings; Clock writable tree has one actual project quota; other subprocesses/writable roots separately admitted",
        ),
    )?;
    let harness = origin.source.clone();
    let state_oracle = retain(
        &mut content,
        &(
            "crucible.normal-clock-state-oracle/1",
            &profile.scenario.world,
            state_programme::CAPTURE_ORDINAL,
            state_programme::SUFFIX_PS,
            "capture at closed original cut; retire actual mutable source before archive reopen; two new complete Core world publications; full inherited ACK history and independent exact suffix; no calibration runtime reused as ordinary world",
        ),
    )?;
    let fixtures = retain(
        &mut content,
        &(
            &state_oracle,
            originals
                .case_oracles_data()
                .map(|(name, oracle)| (name, &oracle.reference, &oracle.bytes))
                .collect::<Vec<_>>(),
        ),
    )?;
    for (_, oracle) in originals.case_oracles_data() {
        insert(&mut content, oracle.reference.clone(), oracle.bytes.clone())?;
    }
    let (specification, specification_bytes) = normative_specification()?;
    insert(&mut content, specification.clone(), specification_bytes)?;
    Ok(Unit {
        value: QualificationUnit {
            implementation,
            realization,
            descriptors,
            contracts,
            port_profiles,
            environment,
            harness,
            fixtures,
            specification,
        },
        content,
        kernel,
        ceilings,
        writable_environment,
        state_oracle,
    })
}

pub(super) fn retain(
    content: &mut BTreeMap<ContentRef, Vec<u8>>,
    value: &impl Serialize,
) -> Result<ContentRef, QualificationError> {
    // Metadata is source-owned and its complete serialized size is counted
    // before DOM construction. This is not physical allocator/stack accounting.
    let mut counter = MetadataCounter(1024 * 1024);
    serde_json::to_writer(&mut counter, value).map_err(failure)?;
    let bytes = canonical::canonical_json(
        &serde_json::to_value(value).map_err(crucible_node_format::ContractError::from)?,
    )?;
    let reference = canonical::content_ref(&bytes, "application/json")?;
    insert(content, reference.clone(), bytes)?;
    Ok(reference)
}

pub(super) fn insert(
    content: &mut BTreeMap<ContentRef, Vec<u8>>,
    reference: ContentRef,
    bytes: Vec<u8>,
) -> Result<(), QualificationError> {
    reference.verify(&bytes)?;
    if let Some(original) = content.get(&reference) {
        return if original == &bytes {
            Ok(())
        } else {
            Err(reject("Clock source content collision"))
        };
    }
    let total = content
        .values()
        .try_fold(bytes.len(), |sum, one| sum.checked_add(one.len()))
        .ok_or(reject("Clock source metadata overflow"))?;
    if content.len() >= 1024 || total > 4 * 1024 * 1024 {
        return Err(reject("Clock source complete metadata ceiling"));
    }
    if let Some(original) = content.get(&reference) {
        if original != &bytes {
            return Err(reject("Clock source content collision"));
        }
    } else {
        content.insert(reference, bytes);
    }
    Ok(())
}

pub(super) fn bounded(value: &impl Serialize, maximum: usize) -> Result<(), QualificationError> {
    serde_json::to_writer(&mut MetadataCounter(maximum), value).map_err(failure)
}

struct MetadataCounter(usize);

impl std::io::Write for MetadataCounter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self
            .0
            .checked_sub(bytes.len())
            .ok_or_else(|| std::io::Error::other("Clock source metadata bound"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
