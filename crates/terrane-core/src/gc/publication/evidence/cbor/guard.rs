//! Encodes complete Guard configuration and registered interpretation inputs.
//!
//! ```text
//! seeded-chunk-profile = [minimum, target, maximum, 48, normalization, seed32]
//! configured-registry-inputs = {0: 1, 1: property_revision, 2: behavior_names,
//!   3: attribute_revision, 4: selector_revision, 5: tree_revision,
//!   6: chunk_revision, 7: identity_profile, 8: inert_later_names}
//! ```

use super::original::{read_acl, write_acl};
use super::*;

impl Record for SeededChunkProfile {
    fn read(decoder: &mut Decoder<'_>) -> Result<Self, EvidenceError> {
        array(decoder, 6)?;

        Ok(Self {
            minimum: decoder.uint()?,
            target: decoder.uint()?,
            maximum: decoder.uint()?,
            window: u8::try_from(decoder.uint()?).map_err(|_| EvidenceError::Schema)?,
            normalization: u8::try_from(decoder.uint()?).map_err(|_| EvidenceError::Schema)?,
            seed: digest(decoder)?,
        })
    }

    fn write(&self, output: &mut Vec<u8>) -> Result<(), EvidenceError> {
        write_array(output, 6);

        for value in [
            self.minimum,
            self.target,
            self.maximum,
            u64::from(self.window),
            u64::from(self.normalization),
        ] {
            write_uint(output, value);
        }
        write_bytes(output, &self.seed);
        Ok(())
    }
}

fn locality(decoder: &mut Decoder<'_>) -> Result<Locality, EvidenceError> {
    let count = decoder.map(3)?;
    let mut locality = Locality::default();
    let mut previous = 0;
    for _ in 0..count {
        let key = decoder.uint()?;
        if key <= previous || key > 3 {
            return Err(EvidenceError::Schema);
        }
        previous = key;

        let label = text(decoder)?;
        match key {
            1 => locality.region = Some(label),
            2 => locality.zone = Some(label),
            3 => locality.host = Some(label),
            _ => return Err(EvidenceError::Schema),
        }
    }
    Ok(locality)
}

fn write_locality(output: &mut Vec<u8>, locality: &Locality) {
    let count = usize::from(locality.region.is_some())
        + usize::from(locality.zone.is_some())
        + usize::from(locality.host.is_some());
    write_map(output, count);

    for (key, label) in [
        (1, &locality.region),
        (2, &locality.zone),
        (3, &locality.host),
    ] {
        if let Some(label) = label {
            write_uint(output, key);
            write_text(output, label);
        }
    }
}

impl Record for TrustedGuardConfig {
    fn read(decoder: &mut Decoder<'_>) -> Result<Self, EvidenceError> {
        map(decoder, 10)?;

        key(decoder, 1)?;
        let store_name = text(decoder)?;
        key(decoder, 2)?;
        let private_domain_hint = text(decoder)?;
        key(decoder, 3)?;
        let home = locality(decoder)?;
        key(decoder, 4)?;
        let initial_acl = read_acl(decoder)?;

        key(decoder, 5)?;
        let minimum_chunk_size = decoder.uint()?;
        key(decoder, 6)?;
        let storage_domain = text(decoder)?;
        key(decoder, 7)?;
        let chunk_profile_name = text(decoder)?;
        key(decoder, 8)?;
        let chunk_profile = read(decoder)?;
        key(decoder, 9)?;
        let policy_authority = optional(decoder, text)?;

        Ok(Self {
            store_name,
            private_domain_hint,
            home,
            initial_acl,
            minimum_chunk_size,
            storage_domain,
            chunk_profile_name,
            chunk_profile,
            policy_authority,
        })
    }

    fn write(&self, output: &mut Vec<u8>) -> Result<(), EvidenceError> {
        header(output, 10);

        write_uint(output, 1);
        write_text(output, &self.store_name);
        write_uint(output, 2);
        write_text(output, &self.private_domain_hint);
        write_uint(output, 3);
        write_locality(output, &self.home);
        write_uint(output, 4);
        write_acl(output, &self.initial_acl);

        write_uint(output, 5);
        write_uint(output, self.minimum_chunk_size);
        write_uint(output, 6);
        write_text(output, &self.storage_domain);
        write_uint(output, 7);
        write_text(output, &self.chunk_profile_name);
        write_uint(output, 8);
        self.chunk_profile.write(output)?;
        write_uint(output, 9);
        write_optional(output, self.policy_authority.as_deref(), |value, output| {
            write_text(output, value)
        });
        Ok(())
    }
}

fn names(decoder: &mut Decoder<'_>) -> Result<Vec<String>, EvidenceError> {
    let count = decoder.array(decoder.remaining().len())?;
    let mut names = Vec::new();
    for _ in 0..count {
        names.push(decoder.text(255)?.to_string());
    }
    Ok(names)
}

fn write_names(output: &mut Vec<u8>, names: &[String]) {
    write_array(output, names.len());
    for name in names {
        write_text(output, name);
    }
}

impl Record for ConfiguredRegistryInputs {
    fn read(decoder: &mut Decoder<'_>) -> Result<Self, EvidenceError> {
        map(decoder, 9)?;

        key(decoder, 1)?;
        let property_revision = decoder.uint()?;
        key(decoder, 2)?;
        let behavioral_properties = names(decoder)?;
        key(decoder, 3)?;
        let attribute_revision = decoder.uint()?;
        key(decoder, 4)?;
        let selector_revision = decoder.uint()?;
        key(decoder, 5)?;
        let tree_revision = decoder.uint()?;
        key(decoder, 6)?;
        let chunk_revision = decoder.uint()?;
        key(decoder, 7)?;
        let identity_profile = text(decoder)?;
        key(decoder, 8)?;
        let later_properties = names(decoder)?;

        Ok(Self {
            property_revision,
            behavioral_properties,
            attribute_revision,
            selector_revision,
            tree_revision,
            chunk_revision,
            identity_profile,
            later_properties,
        })
    }

    fn write(&self, output: &mut Vec<u8>) -> Result<(), EvidenceError> {
        header(output, 9);

        write_uint(output, 1);
        write_uint(output, self.property_revision);
        write_uint(output, 2);
        write_names(output, &self.behavioral_properties);
        write_uint(output, 3);
        write_uint(output, self.attribute_revision);
        write_uint(output, 4);
        write_uint(output, self.selector_revision);
        write_uint(output, 5);
        write_uint(output, self.tree_revision);
        write_uint(output, 6);
        write_uint(output, self.chunk_revision);
        write_uint(output, 7);
        write_text(output, &self.identity_profile);
        write_uint(output, 8);
        write_names(output, &self.later_properties);
        Ok(())
    }
}

impl Record for GuardSnapshot {
    fn read(decoder: &mut Decoder<'_>) -> Result<Self, EvidenceError> {
        map(decoder, 6)?;

        key(decoder, 1)?;
        let registration = read(decoder)?;
        key(decoder, 2)?;
        let issuers = read_rows(decoder)?;
        key(decoder, 3)?;
        let disclosures = read_rows(decoder)?;
        key(decoder, 4)?;
        let configuration = read(decoder)?;
        key(decoder, 5)?;
        let registries = read(decoder)?;

        Ok(Self {
            registration,
            issuers,
            disclosures,
            configuration,
            registries,
        })
    }

    fn write(&self, output: &mut Vec<u8>) -> Result<(), EvidenceError> {
        header(output, 6);

        write_uint(output, 1);
        self.registration.write(output)?;
        write_uint(output, 2);
        write_rows(output, &self.issuers)?;
        write_uint(output, 3);
        write_rows(output, &self.disclosures)?;

        write_uint(output, 4);
        self.configuration.write(output)?;
        write_uint(output, 5);
        self.registries.write(output)
    }
}
