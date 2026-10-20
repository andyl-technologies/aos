//! Checks represented evidence, keeping private ownership and policy external.

use super::*;
use crate::properties::Domain;
use crate::refs::RefName;
use alloc::string::ToString;

mod lineage;
mod policy;

/// Checks only intrinsic format and represented consistency of untrusted values.
pub(super) trait Validate {
    /// Checks the registered fields without granting any private capability.
    ///
    /// # Errors
    /// Rejects invalid fields, unsupported semantics, and internal contradictions.
    fn validate(&self) -> Result<(), EvidenceError>;
}

fn absolute(path: &[u8]) -> Result<(), EvidenceError> {
    if path.first() != Some(&b'/') || path.contains(&0) {
        return Err(EvidenceError::Schema);
    }
    if path.len() > 1
        && path[1..]
            .split(|byte| *byte == b'/')
            .any(|part| part.is_empty() || part == b"." || part == b"..")
    {
        return Err(EvidenceError::Schema);
    }

    Ok(())
}

fn nonempty(value: &str) -> Result<(), EvidenceError> {
    if value.is_empty() {
        return Err(EvidenceError::Schema);
    }

    Ok(())
}

fn ref_name(value: &str) -> Result<(), EvidenceError> {
    RefName::parse(value).map_err(|_| EvidenceError::Schema)?;
    Ok(())
}

fn domain(value: &str) -> Result<(), EvidenceError> {
    Domain::parse(value)?;
    Ok(())
}

fn hex(value: &str) -> Result<(), EvidenceError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(EvidenceError::Schema);
    }

    Ok(())
}

fn digest_text(value: RawDigest) -> String {
    blake3::Hash::from_bytes(value).to_hex().to_string()
}

fn acl(grants: &[AuthorityGrant]) -> Result<(), EvidenceError> {
    for grant in grants {
        nonempty(&grant.principal)?;
        if grant.verbs > 31 {
            return Err(EvidenceError::Schema);
        }
    }
    // ACL order and repetitions are signed historical inputs, not set syntax.
    Ok(())
}

fn issuers(rows: &[IssuerRow]) -> Result<(), EvidenceError> {
    for row in rows {
        row.validate()?;
    }
    if rows
        .windows(2)
        .any(|pair| (&pair[0].issuer, &pair[0].key_id) >= (&pair[1].issuer, &pair[1].key_id))
    {
        return Err(EvidenceError::Schema);
    }

    Ok(())
}

fn disclosures(rows: &[DisclosureRow]) -> Result<(), EvidenceError> {
    let mut owners = alloc::collections::BTreeMap::new();
    for row in rows {
        row.validate()?;
        let key = (&row.domain, &row.public_key);
        if owners
            .insert(key, &row.repository)
            .is_some_and(|owner| owner != &row.repository)
        {
            return Err(EvidenceError::Contradiction);
        }
    }

    for pair in rows.windows(2) {
        // Tuple comparison is exact unsigned text/digest ordering, not locale.
        if (
            &pair[0].repository,
            &pair[0].domain,
            pair[0].public_key,
            pair[0].not_before,
        ) >= (
            &pair[1].repository,
            &pair[1].domain,
            pair[1].public_key,
            pair[1].not_before,
        ) {
            return Err(EvidenceError::Schema);
        }
    }

    Ok(())
}

impl Validate for LocalOriginalRegistration {
    fn validate(&self) -> Result<(), EvidenceError> {
        absolute(&self.root)?;
        absolute(&self.control)?;
        domain(&self.domain)
    }
}

impl Validate for PhysicalRegistration {
    fn validate(&self) -> Result<(), EvidenceError> {
        match self {
            Self::Local(local) => local.validate(),
            Self::Remote(remote) => {
                domain(&remote.domain)?;
                remote.binding.encode()?;
                if !matches!(remote.binding, BackendBinding::Remote { .. })
                    || remote.control.is_empty()
                {
                    return Err(EvidenceError::Schema);
                }
                Ok(())
            }
        }
    }
}

impl PhysicalRegistration {
    /// Returns the recorded physical domain without authenticating ownership.
    pub fn physical_domain(&self) -> &str {
        match self {
            Self::Local(local) => &local.domain,
            Self::Remote(remote) => &remote.domain,
        }
    }

    /// Returns the recorded original ID without authenticating its physical owner.
    pub fn original_id(&self) -> &RawDigest {
        match self {
            Self::Local(local) => &local.original_id,
            Self::Remote(remote) => &remote.original_id,
        }
    }
}

impl Validate for OriginalBootstrap {
    fn validate(&self) -> Result<(), EvidenceError> {
        ref_name(&self.ref_name)?;
        acl(&self.acl)
    }
}

impl Validate for OriginalAssociation {
    fn validate(&self) -> Result<(), EvidenceError> {
        ref_name(&self.ref_name)
    }
}

impl Validate for OriginalImport {
    fn validate(&self) -> Result<(), EvidenceError> {
        self.registration.validate()?;
        self.bootstrap.validate()?;
        self.association.validate()?;
        if self.version == ImportVersion::LocalV1
            && !matches!(self.registration, PhysicalRegistration::Local(_))
        {
            return Err(EvidenceError::Schema);
        }

        if self.registration.original_id() != &self.bootstrap.original_id
            || self.bootstrap.original_id != self.association.original_id
            || self.bootstrap.ref_name != self.association.ref_name
            || self.bootstrap.epoch != self.association.epoch
        {
            return Err(EvidenceError::Contradiction);
        }

        Ok(())
    }
}

impl Validate for OriginalImportBinding {
    fn validate(&self) -> Result<(), EvidenceError> {
        Ok(())
    }
}

impl OriginalImportBinding {
    /// Checks exact canonical import bytes against their claimed IDs and raw digest.
    ///
    /// This consistency check supplies no source or destination authority.
    ///
    /// # Errors
    /// Rejects malformed imports, wrong source/commit IDs, or raw digest mismatch.
    pub fn check_import(&self, bytes: &[u8]) -> Result<(), EvidenceError> {
        let import = OriginalImport::decode(bytes)?;
        if import.registration.original_id() != &self.source
            || import.association.commit != self.commit
            || blake3::hash(bytes).as_bytes() != &self.import_digest
        {
            return Err(EvidenceError::Contradiction);
        }

        Ok(())
    }
}

impl Validate for IssuerRow {
    fn validate(&self) -> Result<(), EvidenceError> {
        nonempty(&self.issuer)?;
        nonempty(&self.key_id)
    }
}

impl Validate for DisclosureRow {
    fn validate(&self) -> Result<(), EvidenceError> {
        hex(&self.repository)?;
        domain(&self.domain)?;
        if self.not_after.is_some_and(|end| end <= self.not_before) {
            return Err(EvidenceError::Contradiction);
        }

        Ok(())
    }
}

impl Validate for OriginalImportTrust {
    fn validate(&self) -> Result<(), EvidenceError> {
        issuers(&self.issuers)?;
        disclosures(&self.disclosures)
    }
}

impl OriginalImportTrust {
    /// Checks exact import bytes and the represented source/destination binding.
    ///
    /// Retained public rows remain untrusted historical claims after this check.
    ///
    /// # Errors
    /// Rejects malformed imports or mismatched digests and original IDs.
    pub fn check_binding(
        &self,
        binding: &OriginalImportBinding,
        bytes: &[u8],
    ) -> Result<(), EvidenceError> {
        self.validate()?;
        binding.check_import(bytes)?;
        if self.import_digest != binding.import_digest
            || self.source != binding.source
            || self.destination != binding.destination
        {
            return Err(EvidenceError::Contradiction);
        }

        Ok(())
    }
}
