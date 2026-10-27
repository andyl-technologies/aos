//! Reconciles opaque quarantine custody separately from verified recovery sources.
//!
//! Names select candidates only. Publisher descriptors or retained shared-content
//! handles establish original inode and project custody; no byte is acknowledged
//! as valid content. Every entry remains in the exhaustive allocation census.

use super::{SharedNamespaceObservation, invalid, same_inode};
use crate::host_cache::NativeRecoveryInspector;
use std::{collections::BTreeMap, io, os::unix::fs::MetadataExt, path::Path};
use terrane_format::identity::{Descriptor, IdentityKind, TERRANE_V1};

impl SharedNamespaceObservation {
    /// Separates the opaque quarantine subset of the actual synchronized census.
    ///
    /// # Errors
    /// Refuses unclassified quarantine names, an inode missing from the real
    /// census, changed custody or allocation arithmetic overflow.
    pub(in crate::host_cache::owner) fn quarantine_allocation(
        &self,
        measured: &BTreeMap<(u64, u64), u64>,
    ) -> io::Result<(u64, usize)> {
        self.check_current()?;
        if self
            .entries
            .iter()
            .filter(|entry| entry.relative.starts_with("quarantine"))
            .count()
            != self.quarantine.len()
        {
            return Err(invalid("quarantine custody is not exhaustively classified"));
        }
        let mut distinct = BTreeMap::new();
        for observation in self.quarantine.values() {
            let inode = observation.handle().metadata()?;
            let key = (inode.dev(), inode.ino());
            let bytes = measured
                .get(&key)
                .ok_or_else(|| invalid("quarantine inode absent from synchronized census"))?;
            distinct.insert(key, *bytes);
        }
        let bytes = distinct.values().try_fold(0_u64, |total, bytes| {
            total
                .checked_add(*bytes)
                .ok_or_else(|| invalid("quarantine allocation sum overflow"))
        })?;
        self.check_current()?;
        Ok((bytes, distinct.len()))
    }

    /// Authenticates every quarantine entry outside embedded policy custody.
    ///
    /// # Errors
    /// Refuses unknown names or inode kinds, unauthenticated or changed original
    /// custody, another configured project and stale publisher recovery context.
    pub(in crate::host_cache::owner) fn inspect_quarantine(
        &mut self,
        inspector: &NativeRecoveryInspector,
    ) -> io::Result<()> {
        self.check_current()?;
        if !std::sync::Arc::ptr_eq(&self.layout, inspector.layout()) {
            return Err(invalid("quarantine inspector has another native root"));
        }
        let mut observations = BTreeMap::new();
        for entry in &self.entries {
            if !entry.relative.starts_with("quarantine") {
                continue;
            }
            let name = entry.relative.strip_prefix("quarantine").map_err(invalid)?;
            if name.parent() != Some(Path::new("")) || !entry.metadata.is_file() {
                return Err(invalid("unrecognized quarantine namespace member"));
            }
            let filename = name
                .to_str()
                .ok_or_else(|| invalid("quarantine name is not UTF-8"))?;
            let observation = if filename.starts_with("encoded.") {
                inspector.inspect_quarantined_encoded(filename)?
            } else {
                let (digest, incarnation) = parse_name(name)?;
                // The digest and optional tag route to a candidate. The kind and
                // observed size are unverified routing fields, never content context.
                // In particular, no fabricated chunk may enter verified_hashes.
                let key = Descriptor::from_wire(
                    &TERRANE_V1,
                    TERRANE_V1.algorithm(),
                    TERRANE_V1.domain(IdentityKind::Chunk).map_err(invalid)?,
                    &digest,
                    entry.metadata.len(),
                )
                .map_err(invalid)?;
                inspector.inspect_quarantined_entry(&key, incarnation)?
            };
            observation.check_current()?;
            if !same_inode(&entry.metadata, &observation.handle().metadata()?) {
                return Err(invalid("quarantine reply differs from exhaustive scan"));
            }
            observations.insert(entry.relative.clone(), observation);
        }
        self.check_current()?;
        self.quarantine = observations;
        self.check_current()
    }
}

fn parse_name(path: &Path) -> io::Result<([u8; 32], Option<[u8; 32]>)> {
    let name = path
        .to_str()
        .ok_or_else(|| invalid("quarantine name is not UTF-8"))?;
    let (digest, incarnation) = match name.split_once('.') {
        Some((digest, suffix)) => (digest, Some(parse_digest(suffix)?)),
        None => (name, None),
    };
    Ok((parse_digest(digest)?, incarnation))
}

fn parse_digest(name: &str) -> io::Result<[u8; 32]> {
    if name.len() != 64
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid("quarantine name has a noncanonical digest or tag"));
    }
    let mut digest = [0; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&name[index * 2..index * 2 + 2], 16).map_err(invalid)?;
    }
    Ok(digest)
}
