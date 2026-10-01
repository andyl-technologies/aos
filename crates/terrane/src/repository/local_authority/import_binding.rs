//! Binds retained source configuration bytes to one registered destination.
//!
//! These decoded rows are untrusted administrative data. Only the native held
//! import factory can establish that source configuration was actually checked.
//!
//! ```text
//! import-binding = [1, commit32, source-authority32, destination-authority32,
//!                   raw-blake3-256(canonical-import-record)]
//! selector = import-binding-<commit-hex>.cbor
//! ```

use terrane_core::cbor;

use super::{
    Error,
    retention::{ImportRecord, Record},
};

/// Contains untrusted exact source and destination association coordinates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ImportBindingRecord {
    /// Exact immutable source commit selected by the validated import.
    pub(crate) commit: [u8; 32],
    /// Original source registration identifier, never an issuer label.
    pub(crate) source_authority: [u8; 32],
    /// Actual destination registration identifier checked by the native factory.
    pub(crate) destination_authority: [u8; 32],
    /// Raw BLAKE3 digest of the exact canonical retained import bytes.
    pub(crate) import_digest: [u8; 32],
}

impl ImportBindingRecord {
    /// Checks exact retained coordinates without establishing physical authority.
    ///
    /// # Errors
    /// Rejects a mismatched commit, source, destination or canonical import digest.
    pub(crate) fn validate_pair(
        &self,
        import: &ImportRecord,
        destination: &[u8; 32],
    ) -> Result<(), Error> {
        let bytes = import.encode()?;
        if self.commit != import.association.commit
            || self.source_authority != import.registration.id
            || &self.destination_authority != destination
            || self.import_digest != *blake3::hash(&bytes).as_bytes()
        {
            return Err(Error::Denied);
        }
        Ok(())
    }
}

impl Record for ImportBindingRecord {
    /// Encodes the exact private destination binding row.
    ///
    /// # Errors
    /// Fixed-size fields always have a valid canonical encoding.
    fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut bytes = Vec::new();
        cbor::write_array(&mut bytes, 5);
        cbor::write_uint(&mut bytes, 1);
        for digest in [
            &self.commit,
            &self.source_authority,
            &self.destination_authority,
            &self.import_digest,
        ] {
            cbor::write_bytes(&mut bytes, digest);
        }
        Ok(bytes)
    }

    /// Decodes one canonical destination binding without granting import authority.
    ///
    /// # Errors
    /// Rejects wrong versions, shapes, digest sizes, noncanonical or trailing data.
    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut decoder = cbor::Decoder::new(bytes);
        if decoder.array(5).map_err(|_| Error::Denied)? != 5
            || decoder.uint().map_err(|_| Error::Denied)? != 1
        {
            return Err(Error::Denied);
        }
        let mut digest = || {
            decoder
                .bytes(32)
                .map_err(|_| Error::Denied)?
                .try_into()
                .map_err(|_| Error::Denied)
        };
        let record = Self {
            commit: digest()?,
            source_authority: digest()?,
            destination_authority: digest()?,
            import_digest: digest()?,
        };
        decoder.finish().map_err(|_| Error::Denied)?;
        Ok(record)
    }

    /// Returns the selector for the exact immutable imported commit.
    ///
    /// # Errors
    /// A fixed-size commit digest always supplies a valid selector.
    fn selector(&self) -> Result<String, Error> {
        let commit = self
            .commit
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        Ok(format!("import-binding-{commit}.cbor"))
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "canonical import-binding fixtures fail the test directly"
)]
mod tests {
    use super::super::retention::{BootstrapRecord, CommitAssociation, RegistrationRecord};
    use super::*;

    #[test]
    fn raw_import_binding_compares_exact_destination_and_canonical_bytes() {
        let import = ImportRecord {
            registration: RegistrationRecord {
                id: [1; 32],
                root: "/tmp/source".into(),
                domain: "public".to_owned(),
                root_device: 1,
                root_inode: 2,
                coordination_device: 1,
                coordination_inode: 3,
                control: "/tmp/source-control".into(),
            },
            baseline: BootstrapRecord {
                id: [1; 32],
                reference: "refs/heads/_/main".to_owned(),
                epoch: 1,
                acl: vec![("writer".to_owned(), 31)],
            },
            association: CommitAssociation {
                commit: [2; 32],
                id: [1; 32],
                reference: "refs/heads/_/main".to_owned(),
                epoch: 1,
            },
        };
        let binding = ImportBindingRecord {
            commit: [2; 32],
            source_authority: [1; 32],
            destination_authority: [3; 32],
            import_digest: *blake3::hash(&import.encode().unwrap()).as_bytes(),
        };
        binding.validate_pair(&import, &[3; 32]).unwrap();
        assert_eq!(
            ImportBindingRecord::decode(&binding.encode().unwrap()).unwrap(),
            binding
        );
        assert!(binding.validate_pair(&import, &[4; 32]).is_err());
        let mut changed = import.clone();
        changed.baseline.acl.clear();
        assert!(binding.validate_pair(&changed, &[3; 32]).is_err());
        let mut changed_binding = binding.clone();
        changed_binding.source_authority = [5; 32];
        assert!(changed_binding.validate_pair(&import, &[3; 32]).is_err());
        let mut trailing = binding.encode().unwrap();
        trailing.push(0);
        assert!(ImportBindingRecord::decode(&trailing).is_err());
        assert!(
            binding
                .selector()
                .unwrap()
                .starts_with("import-binding-0202")
        );
    }
}
