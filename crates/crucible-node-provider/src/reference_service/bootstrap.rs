//! Private launch authorization, never a public CNP authority claim.
//!
//! The launcher sends this bounded object through inherited private standard
//! input before the provider opens its socket. Tokens remain out of arguments,
//! content identities, profile records, diagnostics, and conformance reports.

use crucible_node_contract::*;
use serde::{Deserialize, Serialize};

use crate::{ProviderError, handshake::Limits};

use super::profile::ReferenceProfile;

/// Supplies exact privately installed content without interpreting references as paths.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledContent {
    /// Commits to the complete installed bytes.
    pub reference: ContentRef,
    /// Supplies complete content through the launcher's private channel.
    pub bytes: Bytes,
}

/// Installs native reference-provider authority through its private launch channel.
///
/// Possessing these bytes is launch authority. They must never be accepted as a
/// public protocol message, persisted in a report, or included in a content hash.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferenceServiceBootstrap {
    /// Binds the privately admitted initial live owner realization.
    pub authority: LiveAuthority,
    /// Names the single public checksum node.
    pub node_id: Id,
    /// Names the indivisible native execution owner.
    pub owner_id: Id,
    /// Supplies the secret private launch/admission capability, exactly 32 bytes.
    pub admission_token: Bytes,
    /// Restricts actual kernel peer credentials to this installed controller UID.
    pub controller_uid: U64,
    /// Selects the fixed positive phase-zero quantized window.
    pub quantum_ps: U64,
    /// Bounds total physical child activation time per window.
    pub host_budget_ns: U64,
    /// Installs finite receiving limits before any peer connects.
    pub limits: Limits,
    /// Installs the complete native resource ceilings.
    pub resource_limits: ResourceLimits,
    /// Binds the privately admitted complete world compatibility.
    pub world_binding_hash: HashRef,
    /// Binds the actual privately installed host admission receipt.
    pub admission_receipt: ContentRef,
    /// Names the sole privately admitted admission transaction.
    pub admission_id: Id,
    /// Names the prepared native realization beneath its closed gate.
    pub prepared_token: Id,
    /// Names the privately admitted world activation gate.
    pub gate_id: Id,
    /// Names the privately installed world activation transaction.
    pub transaction_id: Id,
    /// Names the proposed activation, distinct from an execution grant.
    pub activation_id: Id,
    /// Gives the positive world generation committed by world activation.
    pub world_generation: U64,
    /// Supplies exact host receipt and supporting content through private custody.
    pub installed_content: Vec<InstalledContent>,
}

impl Validate for ReferenceServiceBootstrap {
    fn validate(&self) -> Result<(), ContractError> {
        self.authority.validate()?;
        self.resource_limits.validate()?;
        self.limits.validate()?;
        self.world_binding_hash.validate()?;
        self.admission_receipt.validate()?;
        if self.authority.activation_id.is_some()
            || self.authority.world_generation.get() != 0
            || self.world_generation.get() == 0
            || self.quantum_ps.get() == 0
            || self.host_budget_ns.get() == 0
            || self.admission_token.as_slice().len() != 32
            || self.controller_uid.get() > u64::from(u32::MAX)
            || self.world_binding_hash.domain != "cnp.world-binding.v1"
            || self.admission_receipt != self.authority.host_receipt
            || self.installed_content.len() > 4096
        {
            return Err(crate::bodies::invalid(
                "bootstrap",
                "invalid private authorization or positive bounds",
            ));
        }
        for content in &self.installed_content {
            content.reference.verify(content.bytes.as_slice())?;
        }
        if !self
            .installed_content
            .iter()
            .any(|content| content.reference == self.admission_receipt)
        {
            return Err(crate::bodies::invalid(
                "admission_receipt",
                "private receipt bytes are unavailable",
            ));
        }
        Ok(())
    }
}

impl ReferenceServiceBootstrap {
    /// Builds a private reference fixture from independently measured artifacts.
    ///
    /// This method creates host launch authorization, not provider qualification.
    /// The caller must measure the actual provider/device executables used by
    /// `profile`, keep the generated bootstrap private, and supply only the
    /// conservative guarantee profile advertised by that measured implementation.
    ///
    /// # Errors
    /// Rejects invalid initial authority, profile bindings, resource limits,
    /// receipt construction, unavailable exact content, or bootstrap bounds.
    pub fn fixture(
        profile: &ReferenceProfile,
        mut authority: LiveAuthority,
        admission_token: Bytes,
        controller_uid: U64,
        limits: Limits,
        resource_limits: ResourceLimits,
        world_binding_hash: HashRef,
    ) -> Result<Self, ProviderError> {
        let (binding, _) = profile.bind(authority.clone())?;
        let record = AdmissionRecord {
            schema_version: 1,
            realization_id: authority.realization_id.clone(),
            binding_hashes: vec![binding.identity()?],
            world_binding_hash: world_binding_hash.clone(),
            measured_artifacts: profile.implementation.artifacts.clone(),
            qualification_refs: Vec::new(),
            resource_limits: resource_limits.clone(),
            evidence_refs: Vec::new(),
            extensions: Extensions::new(),
        };
        record.validate()?;
        let record_bytes = canonical::canonical_json(
            &serde_json::to_value(&record).map_err(ContractError::from)?,
        )?;
        let record_ref = canonical::content_ref(&record_bytes, "application/json")?;
        let receipt = ControlReceipt {
            schema_version: 1,
            kind: ControlReceiptKind::Admission,
            session_id: authority.session_id.clone(),
            incarnation_id: authority.incarnation_id.clone(),
            request_id: Id::new("private-admission")?,
            operation_id: None,
            owner_ids: vec![profile.owner.id.clone()],
            world_generation: U64::new(0),
            record_ref: record_ref.clone(),
            issuer: ReceiptIssuer::Host,
            extensions: Extensions::new(),
        };
        receipt.validate()?;
        let receipt_bytes = canonical::canonical_json(
            &serde_json::to_value(&receipt).map_err(ContractError::from)?,
        )?;
        let receipt_ref = canonical::content_ref(&receipt_bytes, "application/json")?;
        authority.host_receipt = receipt_ref.clone();
        let quantum_ps = profile
            .operating_contract
            .resolution_ps
            .ok_or(ProviderError::Frame("reference profile lacks quantum"))?;
        let policy: serde_json::Value = canonical::parse_json(
            profile.content(&profile.operating_contract.policy_ref)?,
            65536,
        )?;
        let host_budget_ns: U64 =
            serde_json::from_value(policy.get("host_budget_ns").cloned().ok_or(
                ProviderError::Frame("reference profile lacks physical budget"),
            )?)
            .map_err(ContractError::from)?;
        let result = Self {
            authority,
            node_id: profile.descriptor.id.clone(),
            owner_id: profile.owner.id.clone(),
            admission_token,
            controller_uid,
            quantum_ps,
            host_budget_ns,
            limits,
            resource_limits,
            world_binding_hash,
            admission_receipt: receipt_ref.clone(),
            admission_id: Id::new("reference-admission")?,
            prepared_token: Id::new("reference-prepared")?,
            gate_id: Id::new("reference-gate")?,
            transaction_id: Id::new("reference-transaction")?,
            activation_id: Id::new("reference-activation")?,
            world_generation: U64::new(1),
            installed_content: vec![
                InstalledContent {
                    reference: record_ref,
                    bytes: Bytes::new(record_bytes),
                },
                InstalledContent {
                    reference: receipt_ref,
                    bytes: Bytes::new(receipt_bytes),
                },
            ],
        };
        result.validate()?;
        Ok(result)
    }
}
