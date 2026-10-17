//! Closed private edition-three launch binding genuine host-selected evidence.
//!
//! ```json
//! {"schema_version":3,"profile":{"kind":"byte_linked_v1","closed_ingress":true},
//!  "qualification_refs":[],"bootstrap":{}}
//! ```
//! The abbreviated example omits required nonempty qualification and bootstrap
//! content. This private format carries launch authority; it is never a public
//! provider claim, qualification certificate or externally accepted node receipt.

use crucible_node_contract::*;
use serde::{Deserialize, Serialize};

use super::{
    InstalledContent, PublicReferenceProfile, ReferenceProfile, ReferenceServiceBootstrap,
};
use crate::ProviderError;

/// Selects an installed public profile bound to exact private host evidence.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferenceServiceInstalledLaunchBootstrap {
    /// Selects private installed launch edition three.
    pub schema_version: u16,
    /// Selects the publicly described byte-linked interface.
    pub profile: PublicReferenceProfile,
    /// Commits exact host-selected qualification bytes in canonical order.
    pub qualification_refs: Vec<ContentRef>,
    /// Retains original private authority, native limits and supporting bytes.
    pub bootstrap: ReferenceServiceBootstrap,
}

impl Validate for ReferenceServiceInstalledLaunchBootstrap {
    fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != 3
            || self.qualification_refs.is_empty()
            || !matches!(self.profile, PublicReferenceProfile::ByteLinkedV1 { .. })
        {
            return Err(crate::bodies::invalid(
                "installed_launch",
                "installed public launch requires edition three and host evidence",
            ));
        }
        super::profile::validate_qualifications(&self.qualification_refs).map_err(|_| {
            crate::bodies::invalid(
                "qualification_refs",
                "invalid bounded canonical host evidence roster",
            )
        })?;
        self.bootstrap.validate()?;
        for reference in &self.qualification_refs {
            let content = self
                .bootstrap
                .installed_content
                .iter()
                .find(|content| content.reference == *reference)
                .ok_or_else(|| {
                    crate::bodies::invalid(
                        "qualification_refs",
                        "original private evidence bytes are absent",
                    )
                })?;
            reference.verify(content.bytes.as_slice())?;
        }
        Ok(())
    }
}

impl ReferenceServiceBootstrap {
    /// Binds existing private launch authority to caller-supplied host evidence.
    ///
    /// It constructs a host admission record naming the exact provided content;
    /// it does not manufacture qualification content or accept that content as
    /// proof. The trusted installation registry must authenticate every claim
    /// and actual native custody before admitting the resulting node graph.
    ///
    /// # Errors
    /// Rejects actor/default profiles, empty or noncanonical evidence, invalid
    /// bytes, conflicting installed content, changed admission or finite limits.
    pub fn install_qualifications(
        mut self,
        profile: &ReferenceProfile,
        qualifications: Vec<InstalledContent>,
    ) -> Result<ReferenceServiceInstalledLaunchBootstrap, ProviderError> {
        self.validate()?;
        let selection = profile.public_profile()?;
        if !matches!(selection, PublicReferenceProfile::ByteLinkedV1 { .. })
            || qualifications.is_empty()
        {
            return Err(ProviderError::Frame(
                "installed qualifications require public byte-linked profile",
            ));
        }
        let references = qualifications
            .iter()
            .map(|content| content.reference.clone())
            .collect::<Vec<_>>();
        super::profile::validate_qualifications(&references)?;
        let (binding, _) = profile.bind_qualified(self.authority.clone(), &references)?;
        let admission = AdmissionRecord {
            schema_version: 1,
            realization_id: self.authority.realization_id.clone(),
            binding_hashes: vec![binding.identity()?],
            world_binding_hash: self.world_binding_hash.clone(),
            measured_artifacts: profile.implementation.artifacts.clone(),
            qualification_refs: references.clone(),
            resource_limits: self.resource_limits.clone(),
            evidence_refs: Vec::new(),
            extensions: Extensions::new(),
        };
        admission.validate()?;
        let record_ref = install(&mut self.installed_content, &admission)?;
        let receipt = ControlReceipt {
            schema_version: 1,
            kind: ControlReceiptKind::Admission,
            session_id: self.authority.session_id.clone(),
            incarnation_id: self.authority.incarnation_id.clone(),
            request_id: Id::new("private-admission")?,
            operation_id: None,
            owner_ids: vec![self.owner_id.clone()],
            world_generation: U64::new(0),
            record_ref,
            issuer: ReceiptIssuer::Host,
            extensions: Extensions::new(),
        };
        receipt.validate()?;
        let receipt_ref = install(&mut self.installed_content, &receipt)?;
        for content in qualifications {
            content.reference.verify(content.bytes.as_slice())?;
            if let Some(original) = self
                .installed_content
                .iter()
                .find(|original| original.reference.hash.digest == content.reference.hash.digest)
            {
                if original.reference != content.reference || original.bytes != content.bytes {
                    return Err(ProviderError::Conflict(
                        "installed evidence changed original bytes",
                    ));
                }
            } else {
                self.installed_content.push(content);
            }
        }
        self.authority.host_receipt = receipt_ref.clone();
        self.admission_receipt = receipt_ref;
        let launch = ReferenceServiceInstalledLaunchBootstrap {
            schema_version: 3,
            profile: selection,
            qualification_refs: references,
            bootstrap: self,
        };
        launch.validate()?;
        Ok(launch)
    }
}

fn install(
    contents: &mut Vec<InstalledContent>,
    value: &impl Serialize,
) -> Result<ContentRef, ProviderError> {
    let bytes =
        canonical::canonical_json(&serde_json::to_value(value).map_err(ContractError::from)?)?;
    let reference = canonical::content_ref(&bytes, "application/json")?;
    if let Some(original) = contents
        .iter()
        .find(|content| content.reference.hash.digest == reference.hash.digest)
    {
        if original.reference != reference || original.bytes.as_slice() != bytes {
            return Err(ProviderError::Conflict(
                "private admission content changed original bytes",
            ));
        }
    } else {
        if contents.len() >= 4096 {
            return Err(ProviderError::ResourceExhausted(
                "private installed evidence objects",
            ));
        }
        contents.push(InstalledContent {
            reference: reference.clone(),
            bytes: Bytes::new(bytes),
        });
    }
    Ok(reference)
}

#[cfg(test)]
#[path = "installed_tests.rs"]
mod tests;
