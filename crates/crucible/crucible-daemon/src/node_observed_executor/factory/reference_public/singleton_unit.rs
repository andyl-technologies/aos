//! Measures the ordinary singleton unit before original native allocation.
//!
//! Source projections use the same serialization as the ordinary CNP gate.
//! This record retains data only; native originals and complete independent
//! behavioral acceptance remain separate authorities.

use std::collections::{BTreeMap, BTreeSet};

use crucible_node_format::{ContentRef, ContractError, Validate, canonical};
use crucible_node_transport::ProviderError;
use serde::Serialize;

use super::{installation::SourcePublicReferenceInstallation, unit::UnitSourceObjects};
use crate::node_qualification::{
    QualificationClass, QualificationUnit, project_cnp_prelaunch_qualification,
};

pub(super) struct SingletonQualificationUnit {
    pub(super) identity: QualificationUnit,
    pub(super) classes: BTreeSet<QualificationClass>,
    pub(super) objects: BTreeMap<ContentRef, Vec<u8>>,
}

impl SingletonQualificationUnit {
    /// Measures one regenerated ordinary closed-ingress source selection.
    ///
    /// # Errors
    /// Refuses foreign source profiles, malformed context, changed projections,
    /// or an object population outside the original bounded geometry.
    pub(super) fn measure(
        installed: &SourcePublicReferenceInstallation,
        sources: UnitSourceObjects,
    ) -> Result<Self, ProviderError> {
        installed.bootstrap.validate()?;
        let profile = &installed.profile;
        let expected = installed
            .package
            .profile(
                profile.descriptor.id.clone(),
                profile.owner.id.clone(),
                installed.bootstrap.quantum_ps,
                installed.bootstrap.host_budget_ns,
                true,
            )
            .map_err(|error| ProviderError::Io(std::io::Error::other(error.to_string())))?;
        if profile.descriptor != expected.descriptor
            || profile.implementation != expected.implementation
            || profile.operating_contract != expected.operating_contract
            || profile.capabilities != expected.capabilities
            || profile.guarantees != expected.guarantees
            || profile.owner != expected.owner
            || profile.node_manifest != expected.node_manifest
            || profile.provider_manifest != expected.provider_manifest
            || profile.configuration_ref != expected.configuration_ref
            || profile.content_possession_schema != expected.content_possession_schema
            || profile.contents != expected.contents
        {
            return Err(ProviderError::Correlation(
                "singleton profile differs from installed ordinary source",
            ));
        }

        let resources = &installed.bootstrap.resource_limits;
        let projection = project_cnp_prelaunch_qualification(profile, resources)
            .map_err(|error| ProviderError::Io(std::io::Error::other(error.to_string())))?;
        let mut objects = BTreeMap::new();
        let implementation = put(&mut objects, &profile.implementation)?;
        let realization = put(
            &mut objects,
            &(
                &profile.configuration_ref,
                &profile.node_manifest.profile_id,
                std::slice::from_ref(&profile.owner),
                resources,
            ),
        )?;
        let descriptors = put(&mut objects, &std::slice::from_ref(&profile.descriptor))?;
        let contracts = put(
            &mut objects,
            &(
                &profile.operating_contract,
                &profile.capabilities,
                &profile.guarantees,
            ),
        )?;
        let port_profiles = put(
            &mut objects,
            &(&profile.node_manifest, &profile.descriptor.ports),
        )?;
        if implementation != projection.implementation
            || realization != projection.realization
            || descriptors != projection.descriptors
            || contracts != projection.contracts
            || port_profiles != projection.port_profiles
        {
            return Err(ProviderError::Correlation(
                "singleton original projection bytes differ from the ordinary gate",
            ));
        }

        let (_, specification_bytes) = crate::node_qualification::normative_specification()
            .map_err(|error| ProviderError::Io(std::io::Error::other(error.to_string())))?;
        if sources.specification != specification_bytes {
            return Err(ProviderError::Correlation(
                "singleton compiled specification differs",
            ));
        }
        let identity = QualificationUnit {
            implementation,
            realization,
            descriptors,
            contracts,
            port_profiles,
            environment: put_source(&mut objects, sources.environment)?,
            harness: put_source(&mut objects, sources.harness)?,
            fixtures: put_source(&mut objects, sources.fixtures)?,
            specification: put_source(&mut objects, sources.specification)?,
        };
        Ok(Self {
            identity,
            classes: projection.required_classes,
            objects,
        })
    }
}

fn put(
    objects: &mut BTreeMap<ContentRef, Vec<u8>>,
    value: &impl Serialize,
) -> Result<ContentRef, ProviderError> {
    let bytes =
        canonical::canonical_json(&serde_json::to_value(value).map_err(ContractError::from)?)?;
    put_source(objects, bytes)
}

fn put_source(
    objects: &mut BTreeMap<ContentRef, Vec<u8>>,
    bytes: Vec<u8>,
) -> Result<ContentRef, ProviderError> {
    if bytes.is_empty() || bytes.len() > 1024 * 1024 {
        return Err(ProviderError::ResourceExhausted(
            "singleton unit object geometry",
        ));
    }
    let value = canonical::parse_json(&bytes, 1024 * 1024)?;
    if canonical::canonical_json(&value)? != bytes {
        return Err(ProviderError::Frame(
            "singleton context is not canonical JSON",
        ));
    }
    let reference = canonical::content_ref(&bytes, "application/json")?;
    if let Some(original) = objects.get(&reference) {
        if original != &bytes {
            return Err(ProviderError::Correlation(
                "singleton source identity collision",
            ));
        }
        return Ok(reference);
    }
    let total = objects
        .values()
        .try_fold(bytes.len(), |total, body| total.checked_add(body.len()))
        .filter(|total| *total <= 8 * 1024 * 1024)
        .ok_or(ProviderError::ResourceExhausted(
            "singleton source aggregate geometry",
        ))?;
    if objects.len() >= 2048 || total > 8 * 1024 * 1024 {
        return Err(ProviderError::ResourceExhausted(
            "singleton source aggregate geometry",
        ));
    }
    objects.insert(reference.clone(), bytes);
    Ok(reference)
}
