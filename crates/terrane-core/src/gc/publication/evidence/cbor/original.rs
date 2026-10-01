//! Preserves local original-control records and the explicit remote union.
//!
//! ```text
//! OriginalAssociation = [1, signed_commit, original_id, ref_name, epoch]
//! OriginalImportBinding = [1, commit, source_id, destination_id, raw_import]
//! ```

use super::*;

impl Record for LocalOriginalRegistration {
    fn read(decoder: &mut Decoder<'_>) -> Result<Self, EvidenceError> {
        array(decoder, 9)?;
        version(decoder, 1)?;
        read_local_body(decoder)
    }

    fn write(&self, output: &mut Vec<u8>) -> Result<(), EvidenceError> {
        write_array(output, 9);
        write_uint(output, 1);
        write_bytes(output, &self.original_id);
        write_bytes(output, &self.root);
        write_text(output, &self.domain);
        for value in [
            self.root_device,
            self.root_inode,
            self.coordination_device,
            self.coordination_inode,
        ] {
            write_uint(output, value);
        }
        write_bytes(output, &self.control);
        Ok(())
    }
}

fn read_local_body(decoder: &mut Decoder<'_>) -> Result<LocalOriginalRegistration, EvidenceError> {
    Ok(LocalOriginalRegistration {
        original_id: digest(decoder)?,
        root: bytes(decoder)?,
        domain: text(decoder)?,
        root_device: decoder.uint()?,
        root_inode: decoder.uint()?,
        coordination_device: decoder.uint()?,
        coordination_inode: decoder.uint()?,
        control: bytes(decoder)?,
    })
}

impl Record for PhysicalRegistration {
    fn read(decoder: &mut Decoder<'_>) -> Result<Self, EvidenceError> {
        let count = decoder.array(9)?;
        match (decoder.uint()?, count) {
            (1, 9) => Ok(Self::Local(read_local_body(decoder)?)),
            (2, 5) => Ok(Self::Remote(RemoteOriginalRegistration {
                original_id: digest(decoder)?,
                domain: text(decoder)?,
                binding: binding(decoder)?,
                control: bytes(decoder)?,
            })),
            _ => Err(EvidenceError::Schema),
        }
    }

    fn write(&self, output: &mut Vec<u8>) -> Result<(), EvidenceError> {
        match self {
            Self::Local(local) => local.write(output)?,
            Self::Remote(remote) => {
                write_array(output, 5);
                write_uint(output, 2);
                write_bytes(output, &remote.original_id);
                write_text(output, &remote.domain);
                write_binding(&remote.binding, output)?;
                write_bytes(output, &remote.control);
            }
        }

        Ok(())
    }
}

/// Reads ordered baseline grants with count bounds before allocation.
///
/// # Errors
/// Rejects malformed tuples or verb integers outside their representation.
pub(super) fn read_acl(decoder: &mut Decoder<'_>) -> Result<AuthorityAcl, EvidenceError> {
    let count = decoder.array(decoder.remaining().len())?;
    let mut acl = Vec::new();
    for _ in 0..count {
        array(decoder, 2)?;
        acl.push(AuthorityGrant {
            principal: text(decoder)?,
            verbs: u8::try_from(decoder.uint()?).map_err(|_| EvidenceError::Schema)?,
        });
    }
    Ok(acl)
}

/// Writes baseline grants in their exact configured order, including repeats.
pub(super) fn write_acl(output: &mut Vec<u8>, acl: &[AuthorityGrant]) {
    write_array(output, acl.len());
    for grant in acl {
        write_array(output, 2);
        write_text(output, &grant.principal);
        write_uint(output, u64::from(grant.verbs));
    }
}

impl Record for OriginalBootstrap {
    fn read(decoder: &mut Decoder<'_>) -> Result<Self, EvidenceError> {
        array(decoder, 5)?;
        version(decoder, 1)?;

        Ok(Self {
            original_id: digest(decoder)?,
            ref_name: text(decoder)?,
            epoch: decoder.uint()?,
            acl: read_acl(decoder)?,
        })
    }

    fn write(&self, output: &mut Vec<u8>) -> Result<(), EvidenceError> {
        write_array(output, 5);
        write_uint(output, 1);
        write_bytes(output, &self.original_id);
        write_text(output, &self.ref_name);
        write_uint(output, self.epoch);
        write_acl(output, &self.acl);
        Ok(())
    }
}

impl Record for OriginalAssociation {
    fn read(decoder: &mut Decoder<'_>) -> Result<Self, EvidenceError> {
        array(decoder, 5)?;
        version(decoder, 1)?;

        Ok(Self {
            commit: digest(decoder)?,
            original_id: digest(decoder)?,
            ref_name: text(decoder)?,
            epoch: decoder.uint()?,
        })
    }

    fn write(&self, output: &mut Vec<u8>) -> Result<(), EvidenceError> {
        write_array(output, 5);
        write_uint(output, 1);
        write_bytes(output, &self.commit);
        write_bytes(output, &self.original_id);
        write_text(output, &self.ref_name);
        write_uint(output, self.epoch);
        Ok(())
    }
}

impl Record for OriginalImport {
    fn read(decoder: &mut Decoder<'_>) -> Result<Self, EvidenceError> {
        array(decoder, 4)?;
        let version = match decoder.uint()? {
            1 => ImportVersion::LocalV1,
            2 => ImportVersion::PhysicalV2,
            _ => return Err(EvidenceError::Schema),
        };
        Ok(Self {
            version,
            registration: read(decoder)?,
            bootstrap: read(decoder)?,
            association: read(decoder)?,
        })
    }

    fn write(&self, output: &mut Vec<u8>) -> Result<(), EvidenceError> {
        write_array(output, 4);
        write_uint(
            output,
            match self.version {
                ImportVersion::LocalV1 => 1,
                ImportVersion::PhysicalV2 => 2,
            },
        );
        self.registration.write(output)?;
        self.bootstrap.write(output)?;
        self.association.write(output)
    }
}

impl Record for OriginalImportBinding {
    fn read(decoder: &mut Decoder<'_>) -> Result<Self, EvidenceError> {
        array(decoder, 5)?;
        version(decoder, 1)?;

        Ok(Self {
            commit: digest(decoder)?,
            source: digest(decoder)?,
            destination: digest(decoder)?,
            import_digest: digest(decoder)?,
        })
    }

    fn write(&self, output: &mut Vec<u8>) -> Result<(), EvidenceError> {
        write_array(output, 5);
        write_uint(output, 1);
        for value in [
            &self.commit,
            &self.source,
            &self.destination,
            &self.import_digest,
        ] {
            write_bytes(output, value);
        }

        Ok(())
    }
}

impl Record for IssuerRow {
    fn read(decoder: &mut Decoder<'_>) -> Result<Self, EvidenceError> {
        array(decoder, 4)?;
        Ok(Self {
            issuer: text(decoder)?,
            key_id: text(decoder)?,
            public_key: digest(decoder)?,
            retired_at: optional(decoder, |decoder| Ok(decoder.uint()?))?,
        })
    }

    fn write(&self, output: &mut Vec<u8>) -> Result<(), EvidenceError> {
        write_array(output, 4);
        write_text(output, &self.issuer);
        write_text(output, &self.key_id);
        write_bytes(output, &self.public_key);
        write_optional(output, self.retired_at.as_ref(), |value, output| {
            write_uint(output, *value)
        });
        Ok(())
    }
}

impl Record for DisclosureRow {
    fn read(decoder: &mut Decoder<'_>) -> Result<Self, EvidenceError> {
        array(decoder, 5)?;
        Ok(Self {
            repository: text(decoder)?,
            domain: text(decoder)?,
            public_key: digest(decoder)?,
            not_before: decoder.uint()?,
            not_after: optional(decoder, |decoder| Ok(decoder.uint()?))?,
        })
    }

    fn write(&self, output: &mut Vec<u8>) -> Result<(), EvidenceError> {
        write_array(output, 5);
        write_text(output, &self.repository);
        write_text(output, &self.domain);
        write_bytes(output, &self.public_key);
        write_uint(output, self.not_before);
        write_optional(output, self.not_after.as_ref(), |value, output| {
            write_uint(output, *value)
        });
        Ok(())
    }
}

impl Record for OriginalImportTrust {
    fn read(decoder: &mut Decoder<'_>) -> Result<Self, EvidenceError> {
        array(decoder, 6)?;
        version(decoder, 1)?;

        Ok(Self {
            import_digest: digest(decoder)?,
            source: digest(decoder)?,
            destination: digest(decoder)?,
            issuers: read_rows(decoder)?,
            disclosures: read_rows(decoder)?,
        })
    }

    fn write(&self, output: &mut Vec<u8>) -> Result<(), EvidenceError> {
        write_array(output, 6);
        write_uint(output, 1);
        for value in [&self.import_digest, &self.source, &self.destination] {
            write_bytes(output, value);
        }
        write_rows(output, &self.issuers)?;
        write_rows(output, &self.disclosures)
    }
}
