//! Measures the original unenrolled four-owner source before behavioral collection.
//!
//! Report references are added to admission bindings only after acceptance. The
//! original source axes therefore cannot form claim-to-binding reference cycles.
//! Native Ready, completion and capture authority remain separate runtime facts.

use std::{
    collections::BTreeMap,
    io::{self, Write},
    path::PathBuf,
};

use crucible_node_format::{ContentRef, canonical};
use serde::Serialize;

use super::super::super::{InstalledGem5ClosedProfile, InstalledNodeCatalog, measure_executable};
use super::super::host_group::profile::IndependentGroupProfile;
use crate::node_qualification::{QualificationError, QualificationUnit, normative_specification};

const MAXIMUM_OBJECTS: usize = 16_384;
const MAXIMUM_SOURCE_BYTES: usize = 16 * 1024 * 1024;
const MAXIMUM_COMPLETE_BYTES: u64 = 4 * 1024 * 1024 * 1024;

pub(super) struct SourceObject {
    pub(super) reference: ContentRef,
    pub(super) bytes: Vec<u8>,
    pub(super) dependencies: Vec<ContentRef>,
}

/// Owns measured source axes and the exact original installed file roster.
pub(super) struct UnitMeasurement {
    pub(super) unit: QualificationUnit,
    pub(super) objects: BTreeMap<ContentRef, SourceObject>,
    files: BTreeMap<ContentRef, PathBuf>,
    environment: Vec<u8>,
    artifacts: BTreeMap<ContentRef, super::super::super::InstalledIoArtifact>,
}

impl UnitMeasurement {
    /// Measures the complete source-built family, never a caller-selected unit.
    pub(super) fn measure(
        catalog: &InstalledNodeCatalog,
        installed: &InstalledGem5ClosedProfile,
        profile: &IndependentGroupProfile,
        configuration: &crate::node_scenario::NodeRunConfiguration,
        case: super::fixture::Gem5BehavioralCase,
    ) -> Result<Self, QualificationError> {
        let source_bytes = profile.scenario.canonical_bytes().map_err(evidence)?;
        if profile.scenario.descriptors.len() != 4
            || profile.scenario.owners.len() != 4
            || profile.scenario.world.connections.len() != 1
            || !profile.scenario.world.extensions.is_empty()
            || source_bytes.len() > MAXIMUM_SOURCE_BYTES
        {
            return Err(QualificationError::Refused(
                "unsupported behavioral source world",
            ));
        }
        let mut files = BTreeMap::new();
        for name in [
            "native_executable",
            "controller",
            "model",
            "dmtcp_launch",
            "dmtcp_restart",
            "mtcp_restart",
            "image_guard",
            "auditor",
        ] {
            let file = installed.artifact(name).map_err(evidence)?;
            if measure_executable(&file.path).map_err(evidence)? != file.content {
                return Err(QualificationError::Refused(
                    "changed behavioral native source artifact",
                ));
            }
            files.insert(file.content, file.path);
        }
        let guest = installed.guest("x86_64").map_err(evidence)?;
        if measure_executable(&guest.path).map_err(evidence)? != guest.content
            || measure_executable(&catalog.host_executable).map_err(evidence)?
                != catalog.host_identity
            || measure_executable(&catalog.device_executable).map_err(evidence)?
                != catalog.device_identity
        {
            return Err(QualificationError::Refused(
                "changed behavioral host or guest source",
            ));
        }
        files.insert(guest.content, guest.path);
        files.insert(
            catalog.host_identity.clone(),
            catalog.host_executable.clone(),
        );
        files.insert(
            catalog.device_identity.clone(),
            catalog.device_executable.clone(),
        );

        // Reserve the whole finite metadata and installed-file closure before
        // copying profile bodies or constructing any axis serialization.
        let mut total = 0u64;
        for object in &profile.scenario.content {
            object.reference.verify(&object.bytes)?;
            total = total
                .checked_add(object.reference.length.get())
                .ok_or(QualificationError::Refused("source byte overflow"))?;
        }
        for reference in files.keys() {
            total = total
                .checked_add(reference.length.get())
                .ok_or(QualificationError::Refused("file byte overflow"))?;
        }
        if profile.scenario.content.len() + files.len() + 16 > MAXIMUM_OBJECTS
            || total
                .checked_add(16 * MAXIMUM_SOURCE_BYTES as u64)
                .is_none_or(|total| total > MAXIMUM_COMPLETE_BYTES)
        {
            return Err(QualificationError::Refused(
                "complete behavioral source credit",
            ));
        }
        let (document, bytes) = installed.document();
        let mut artifacts = BTreeMap::new();
        for artifact in catalog.artifacts.values() {
            if profile
                .scenario
                .content
                .iter()
                .any(|object| object.reference == artifact.expected)
            {
                super::super::super::io::read_artifact(artifact).map_err(evidence)?;
                artifacts.insert(artifact.expected.clone(), artifact.clone());
            }
        }
        let mut objects = BTreeMap::new();
        for object in profile
            .scenario
            .content
            .iter()
            .filter(|object| &object.reference != document)
        {
            insert(
                &mut objects,
                SourceObject {
                    reference: object.reference.clone(),
                    bytes: object.bytes.clone(),
                    dependencies: Vec::new(),
                },
            )?;
        }
        insert(
            &mut objects,
            SourceObject {
                reference: document.clone(),
                bytes: bytes.to_vec(),
                dependencies: files.keys().cloned().collect(),
            },
        )?;
        let source = put(
            &mut objects,
            &profile.scenario,
            profile
                .scenario
                .content
                .iter()
                .map(|object| object.reference.clone())
                .collect(),
        )?;
        let implementation = put(
            &mut objects,
            &(
                "crucible.gem5.behavioral-implementation.v1",
                document,
                &catalog.host_identity,
                &catalog.device_identity,
            ),
            vec![
                document.clone(),
                catalog.host_identity.clone(),
                catalog.device_identity.clone(),
            ],
        )?;
        let realization = put(
            &mut objects,
            &(
                "crucible.gem5.behavioral-realization.v1",
                &profile.scenario.world,
                &profile.scenario.owners,
                profile.preserving,
            ),
            vec![source.clone()],
        )?;
        let descriptors = put(
            &mut objects,
            &(
                "crucible.gem5.behavioral-descriptors.v1",
                &profile.scenario.descriptors,
            ),
            vec![source.clone()],
        )?;
        let contracts = put(
            &mut objects,
            &(
                "crucible.gem5.behavioral-contracts.v1",
                &profile.scenario.compatibility,
                &profile.scenario.requirements,
            ),
            vec![source.clone()],
        )?;
        let port_profiles = put(
            &mut objects,
            &(
                "crucible.gem5.behavioral-ports.v1",
                &profile.scenario.world.connections,
                &profile.scenario.descriptors,
            ),
            vec![source.clone()],
        )?;
        let environment_bytes = environment()?;
        let environment_ref = canonical::content_ref(&environment_bytes, "application/json")?;
        insert(
            &mut objects,
            SourceObject {
                reference: environment_ref.clone(),
                bytes: environment_bytes.clone(),
                dependencies: vec![document.clone()],
            },
        )?;
        let (oracle, oracle_bytes) = super::native_oracle::OriginalGem5Case::specification()?;
        insert(
            &mut objects,
            SourceObject {
                reference: oracle.clone(),
                bytes: oracle_bytes,
                dependencies: Vec::new(),
            },
        )?;
        let harness = put(
            &mut objects,
            &(
                "crucible.gem5.behavioral-harness.v1",
                include_str!("fixture.rs"),
                include_str!("enrollment.rs"),
                include_str!("unit.rs"),
                include_str!("projection.rs"),
                include_str!("scope.rs"),
                include_str!("case.rs"),
                include_str!("storage_oracle.rs"),
            ),
            vec![catalog.host_identity.clone(), oracle.clone()],
        )?;
        let fixtures = put(
            &mut objects,
            &(
                "crucible.gem5.behavioral-fixtures.v1",
                &source,
                &oracle,
                configuration,
                match case {
                    super::fixture::Gem5BehavioralCase::LcgOutput => "LCG",
                    super::fixture::Gem5BehavioralCase::ExclusiveHorizon => "horizon",
                },
            ),
            vec![source.clone(), oracle.clone()],
        )?;
        let (specification, specification_bytes) = normative_specification()?;
        insert(
            &mut objects,
            SourceObject {
                reference: specification.clone(),
                bytes: specification_bytes,
                dependencies: Vec::new(),
            },
        )?;
        Ok(Self {
            unit: QualificationUnit {
                implementation,
                realization,
                descriptors,
                contracts,
                port_profiles,
                environment: environment_ref,
                harness,
                fixtures,
                specification,
            },
            objects,
            files,
            environment: environment_bytes,
            artifacts,
        })
    }

    /// Reopens the original complete file roster and actual running-kernel scope.
    pub(super) fn current(&self) -> Result<QualificationUnit, QualificationError> {
        if environment()? != self.environment {
            return Err(QualificationError::Refused(
                "behavioral kernel/environment changed",
            ));
        }
        for (reference, path) in &self.files {
            if &measure_executable(path).map_err(evidence)? != reference {
                return Err(QualificationError::Refused(
                    "behavioral installed source changed",
                ));
            }
        }
        for artifact in self.artifacts.values() {
            super::super::super::io::read_artifact(artifact).map_err(evidence)?;
        }
        Ok(self.unit.clone())
    }

    pub(super) fn verify(
        &self,
        reference: &ContentRef,
        maximum_bytes: u64,
        maximum_dependencies: usize,
    ) -> Result<Vec<ContentRef>, QualificationError> {
        if reference.length.get() > maximum_bytes {
            return Err(QualificationError::Refused(
                "behavioral evidence byte ceiling",
            ));
        }
        if let Some(object) = self.objects.get(reference) {
            if object.dependencies.len() > maximum_dependencies {
                return Err(QualificationError::Refused(
                    "behavioral evidence edge ceiling",
                ));
            }
            reference.verify(&object.bytes)?;
            return Ok(object.dependencies.clone());
        }
        if let Some(path) = self.files.get(reference) {
            if &measure_executable(path).map_err(evidence)? != reference {
                return Err(QualificationError::Refused(
                    "behavioral evidence file changed",
                ));
            }
            return Ok(Vec::new());
        }
        Err(QualificationError::Refused(
            "unknown behavioral evidence role",
        ))
    }
}

fn environment() -> Result<Vec<u8>, QualificationError> {
    let mut release = std::fs::File::open("/proc/sys/kernel/osrelease").map_err(evidence)?;
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut std::io::Read::take(&mut release, 257), &mut bytes)
        .map_err(evidence)?;
    if bytes.is_empty() || bytes.len() > 256 {
        return Err(QualificationError::Refused("kernel release extent"));
    }
    encode(&(
        "crucible.gem5.behavioral-environment.v1",
        std::env::consts::ARCH,
        std::env::consts::OS,
        bytes,
        "single owning thread; four independent owners; no CPU ingress; source-configured finite exact native budget",
    ))
}

pub(super) fn encode<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, QualificationError> {
    let mut counter = Counter {
        remaining: MAXIMUM_SOURCE_BYTES,
    };
    serde_json::to_writer(&mut counter, value).map_err(evidence)?;
    canonical::canonical_json(&serde_json::to_value(value).map_err(evidence)?).map_err(Into::into)
}

fn put<T: Serialize>(
    objects: &mut BTreeMap<ContentRef, SourceObject>,
    value: &T,
    dependencies: Vec<ContentRef>,
) -> Result<ContentRef, QualificationError> {
    let bytes = encode(value)?;
    let reference = canonical::content_ref(&bytes, "application/json")?;
    insert(
        objects,
        SourceObject {
            reference: reference.clone(),
            bytes,
            dependencies,
        },
    )?;
    Ok(reference)
}

fn insert(
    objects: &mut BTreeMap<ContentRef, SourceObject>,
    object: SourceObject,
) -> Result<(), QualificationError> {
    object.reference.verify(&object.bytes)?;
    if let Some(original) = objects.get(&object.reference) {
        if original.bytes != object.bytes || original.dependencies != object.dependencies {
            return Err(QualificationError::Refused(
                "behavioral source role collision",
            ));
        }
    } else {
        objects.insert(object.reference.clone(), object);
    }
    Ok(())
}

struct Counter {
    remaining: usize,
}
impl Write for Counter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.remaining = self
            .remaining
            .checked_sub(bytes.len())
            .ok_or_else(|| io::Error::other("behavioral axis extent"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn evidence(error: impl std::fmt::Display) -> QualificationError {
    QualificationError::Evidence(error.to_string())
}
