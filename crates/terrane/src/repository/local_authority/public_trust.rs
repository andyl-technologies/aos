//! Retains public verification configuration for an exact validated import.
//!
//! No signing seeds are stored here. Decoded mappings remain untrusted until
//! the native import factory validates their protected source and destination.
//!
//! ```text
//! trust = [1, import-digest32, source-authority32, destination-authority32,
//!          [[issuer, key-id, public-key32, retirement-or-null], ...],
//!          [[repository, domain, public-key32, not-before, not-after-or-null], ...]]
//! selector = import-trust-<import-digest-hex>.cbor
//! ```

use std::collections::BTreeMap;

use terrane_core::{auth::IssuerKey, cbor, properties::Domain, provenance::DisclosureAuthority};

use super::{Error, import_binding::ImportBindingRecord, retention::Record};

const LIMIT: usize = 65_536;
const RECORD_LIMIT: usize = 16 * 1024 * 1024;

/// Owns an untrusted dedicated disclosure role without a private key.
#[derive(Clone, Debug)]
pub(crate) struct DisclosureRoleRecord {
    /// Canonical lowercase hexadecimal physical repository authority identifier.
    pub(crate) repository: String,
    /// Canonical effective source domain governed by the dedicated role.
    pub(crate) domain: String,
    /// Dedicated Ed25519 public verification key.
    pub(crate) public_key: [u8; 32],
    /// Earliest inclusive authorized issue time.
    pub(crate) not_before: u64,
    /// Exclusive authorized issue-time bound, if present.
    pub(crate) not_after: Option<u64>,
}

impl DisclosureRoleRecord {
    /// Borrows role configuration without establishing trust in its source.
    pub(crate) fn view(&self) -> DisclosureAuthority<'_> {
        DisclosureAuthority {
            repository: &self.repository,
            domain: &self.domain,
            public_key: self.public_key,
            not_before: self.not_before,
            not_after: self.not_after,
        }
    }
}

/// Holds untrusted public mappings captured for one exact import and destination.
#[derive(Clone, Debug)]
pub(crate) struct PublicTrustRecord {
    /// Raw BLAKE3 digest of the exact canonical import record.
    pub(crate) import_digest: [u8; 32],
    /// Source authority whose held configuration supplies these mappings.
    pub(crate) source_authority: [u8; 32],
    /// Physical destination authority that retains the checked mappings.
    pub(crate) destination_authority: [u8; 32],
    /// Sorted unique configured issuer public keys, including retirement bounds.
    pub(crate) issuer_keys: Vec<IssuerKey>,
    /// Roles ordered uniquely by repository, domain, key and interval start.
    pub(crate) disclosure_roles: Vec<DisclosureRoleRecord>,
}

impl PublicTrustRecord {
    /// Checks canonical mapping order and role identities without granting trust.
    ///
    /// # Errors
    /// Rejects malformed names or domains, oversized rows, duplicate or unordered
    /// mappings, invalid intervals and cross-repository key/domain aliases.
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if self.issuer_keys.len() > LIMIT || self.disclosure_roles.len() > LIMIT {
            return Err(Error::Denied);
        }
        let mut previous = None;
        for key in &self.issuer_keys {
            let current = (key.issuer.as_str(), key.key_id.as_str());
            if key.issuer.is_empty()
                || key.key_id.is_empty()
                || key.issuer.len() > LIMIT
                || key.key_id.len() > LIMIT
                || previous.is_some_and(|prior| prior >= current)
            {
                return Err(Error::Denied);
            }
            previous = Some(current);
        }
        let mut previous = None;
        let mut aliases = BTreeMap::new();
        for role in &self.disclosure_roles {
            let current = (
                role.repository.as_str(),
                role.domain.as_str(),
                role.public_key,
                role.not_before,
            );
            if role.repository.len() != 64
                || !role
                    .repository
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                || role.domain.len() > LIMIT
                || role.not_after.is_some_and(|end| end <= role.not_before)
                || previous.is_some_and(|prior| prior >= current)
            {
                return Err(Error::Denied);
            }
            Domain::parse(&role.domain).map_err(|_| Error::Denied)?;

            // Interval starts distinguish retained windows. A repeated start is
            // ambiguous even when its exclusive end differs; repository aliases
            // remain forbidden independently of those historical windows.
            if aliases
                .insert(
                    (role.public_key, role.domain.as_str()),
                    role.repository.as_str(),
                )
                .is_some_and(|repository| repository != role.repository)
            {
                return Err(Error::Denied);
            }
            previous = Some(current);
        }
        Ok(())
    }

    /// Checks exact source, destination and import bytes against a decoded binding.
    ///
    /// # Errors
    /// Rejects a mismatched digest or authority, or invalid public mapping rows.
    pub(crate) fn validate_binding(&self, binding: &ImportBindingRecord) -> Result<(), Error> {
        self.validate()?;
        if self.import_digest != binding.import_digest
            || self.source_authority != binding.source_authority
            || self.destination_authority != binding.destination_authority
        {
            return Err(Error::Denied);
        }
        Ok(())
    }
}

fn optional_time(bytes: &mut Vec<u8>, value: Option<u64>) {
    if let Some(value) = value {
        cbor::write_uint(bytes, value);
    } else {
        bytes.push(0xf6);
    }
}

fn read_time(decoder: &mut cbor::Decoder<'_>) -> Result<Option<u64>, Error> {
    if decoder.peek_major().map_err(|_| Error::Denied)? == 0 {
        return decoder.uint().map(Some).map_err(|_| Error::Denied);
    }
    if decoder.simple().map_err(|_| Error::Denied)? != 0xf6 {
        return Err(Error::Denied);
    }
    Ok(None)
}

fn digest(decoder: &mut cbor::Decoder<'_>) -> Result<[u8; 32], Error> {
    decoder
        .bytes(32)
        .map_err(|_| Error::Denied)?
        .try_into()
        .map_err(|_| Error::Denied)
}

impl Record for PublicTrustRecord {
    /// Encodes the exact canonical private public-trust configuration.
    ///
    /// # Errors
    /// Rejects invalid mappings, ambiguous roles and excessive record sizes.
    fn encode(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut bytes = Vec::new();
        cbor::write_array(&mut bytes, 6);
        cbor::write_uint(&mut bytes, 1);
        for value in [
            &self.import_digest,
            &self.source_authority,
            &self.destination_authority,
        ] {
            cbor::write_bytes(&mut bytes, value);
        }
        cbor::write_array(&mut bytes, self.issuer_keys.len());
        for key in &self.issuer_keys {
            cbor::write_array(&mut bytes, 4);
            cbor::write_text(&mut bytes, &key.issuer);
            cbor::write_text(&mut bytes, &key.key_id);
            cbor::write_bytes(&mut bytes, &key.public_key);
            optional_time(&mut bytes, key.retirement);
        }
        cbor::write_array(&mut bytes, self.disclosure_roles.len());
        for role in &self.disclosure_roles {
            cbor::write_array(&mut bytes, 5);
            cbor::write_text(&mut bytes, &role.repository);
            cbor::write_text(&mut bytes, &role.domain);
            cbor::write_bytes(&mut bytes, &role.public_key);
            cbor::write_uint(&mut bytes, role.not_before);
            optional_time(&mut bytes, role.not_after);
        }
        if bytes.len() > RECORD_LIMIT {
            return Err(Error::Denied);
        }
        Ok(bytes)
    }

    /// Decodes exact public mappings as untrusted retained configuration.
    ///
    /// # Errors
    /// Rejects malformed, noncanonical, oversized or trailing data and invalid mappings.
    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > RECORD_LIMIT {
            return Err(Error::Denied);
        }
        let mut decoder = cbor::Decoder::new(bytes);
        if decoder.array(6).map_err(|_| Error::Denied)? != 6
            || decoder.uint().map_err(|_| Error::Denied)? != 1
        {
            return Err(Error::Denied);
        }
        let import_digest = digest(&mut decoder)?;
        let source_authority = digest(&mut decoder)?;
        let destination_authority = digest(&mut decoder)?;
        let count = decoder.array(LIMIT).map_err(|_| Error::Denied)?;
        let mut issuer_keys = Vec::with_capacity(count);
        for _ in 0..count {
            if decoder.array(4).map_err(|_| Error::Denied)? != 4 {
                return Err(Error::Denied);
            }
            issuer_keys.push(IssuerKey {
                issuer: decoder.text(LIMIT).map_err(|_| Error::Denied)?.to_owned(),
                key_id: decoder.text(LIMIT).map_err(|_| Error::Denied)?.to_owned(),
                public_key: digest(&mut decoder)?,
                retirement: read_time(&mut decoder)?,
            });
        }
        let count = decoder.array(LIMIT).map_err(|_| Error::Denied)?;
        let mut disclosure_roles = Vec::with_capacity(count);
        for _ in 0..count {
            if decoder.array(5).map_err(|_| Error::Denied)? != 5 {
                return Err(Error::Denied);
            }
            disclosure_roles.push(DisclosureRoleRecord {
                repository: decoder.text(LIMIT).map_err(|_| Error::Denied)?.to_owned(),
                domain: decoder.text(LIMIT).map_err(|_| Error::Denied)?.to_owned(),
                public_key: digest(&mut decoder)?,
                not_before: decoder.uint().map_err(|_| Error::Denied)?,
                not_after: read_time(&mut decoder)?,
            });
        }
        decoder.finish().map_err(|_| Error::Denied)?;
        let record = Self {
            import_digest,
            source_authority,
            destination_authority,
            issuer_keys,
            disclosure_roles,
        };
        record.validate()?;
        Ok(record)
    }

    /// Returns a selector for the exact raw canonical import digest.
    ///
    /// # Errors
    /// A fixed-size import digest always supplies a valid filename selector.
    fn selector(&self) -> Result<String, Error> {
        let digest = self
            .import_digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        Ok(format!("import-trust-{digest}.cbor"))
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "retained public-trust codec fixtures fail the test directly"
)]
mod tests {
    use super::*;

    fn fixture() -> PublicTrustRecord {
        PublicTrustRecord {
            import_digest: [1; 32],
            source_authority: [2; 32],
            destination_authority: [3; 32],
            issuer_keys: vec![IssuerKey {
                issuer: "original".to_owned(),
                key_id: "initial".to_owned(),
                public_key: [4; 32],
                retirement: Some(200),
            }],
            disclosure_roles: vec![DisclosureRoleRecord {
                repository: "02".repeat(32),
                domain: "public".to_owned(),
                public_key: [5; 32],
                not_before: 100,
                not_after: None,
            }],
        }
    }

    #[test]
    fn retained_disclosure_windows_preserve_one_repository_and_reject_duplicate_starts() {
        let mut record = fixture();
        record.disclosure_roles[0].not_after = Some(150);
        let mut later = record.disclosure_roles[0].clone();
        later.not_before = 150;
        later.not_after = Some(200);
        record.disclosure_roles.push(later);

        let bytes = record.encode().unwrap();
        let decoded = PublicTrustRecord::decode(&bytes).unwrap();

        assert_eq!(decoded.encode().unwrap(), bytes);
        assert_eq!(decoded.disclosure_roles.len(), 2);
        let first = decoded.disclosure_roles[0].view();
        let second = decoded.disclosure_roles[1].view();
        assert_eq!(first.repository, second.repository);
        assert_eq!(first.domain, second.domain);
        assert_eq!(first.public_key, second.public_key);
        assert_eq!((first.not_before, first.not_after), (100, Some(150)));
        assert_eq!((second.not_before, second.not_after), (150, Some(200)));

        let mut duplicate = record.clone();
        duplicate.disclosure_roles[1].not_before = 100;
        assert!(duplicate.encode().is_err());
        duplicate.disclosure_roles[1].not_after = Some(150);
        assert!(duplicate.encode().is_err());

        let mut unordered = record.clone();
        unordered.disclosure_roles.reverse();
        assert!(unordered.encode().is_err());

        let mut alias = record;
        alias.disclosure_roles[1].repository = "03".repeat(32);
        assert!(alias.encode().is_err());
    }

    #[test]
    fn retained_public_trust_preserves_intervals_and_rejects_ambiguous_mappings() {
        let record = fixture();
        let bytes = record.encode().unwrap();
        let decoded = PublicTrustRecord::decode(&bytes).unwrap();
        assert_eq!(decoded.encode().unwrap(), bytes);
        assert_eq!(decoded.issuer_keys[0].retirement, Some(200));
        assert_eq!(decoded.disclosure_roles[0].view().not_after, None);
        let binding = ImportBindingRecord {
            commit: [9; 32],
            source_authority: [2; 32],
            destination_authority: [3; 32],
            import_digest: [1; 32],
        };
        decoded.validate_binding(&binding).unwrap();
        let mut changed = fixture();
        changed.destination_authority[0] ^= 1;
        assert!(changed.validate_binding(&binding).is_err());
        changed = fixture();
        changed.issuer_keys.push(changed.issuer_keys[0].clone());
        assert!(changed.encode().is_err());
        changed = fixture();
        let mut alias = changed.disclosure_roles[0].clone();
        alias.repository = "03".repeat(32);
        changed.disclosure_roles.push(alias);
        assert!(changed.encode().is_err());
        changed = fixture();
        changed.disclosure_roles[0].not_after = Some(100);
        assert!(changed.encode().is_err());
        let mut trailing = bytes;
        trailing.push(0);
        assert!(PublicTrustRecord::decode(&trailing).is_err());
        assert!(record.selector().unwrap().starts_with("import-trust-0101"));
    }
}
