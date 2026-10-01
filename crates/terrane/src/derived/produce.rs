//! Selects effective attribute requirements and runs bounded plaintext producers.

use super::{Error, PlaintextObject, ProducerVerifier, SideTable};
use crate::store::ContentStore;
use terrane_core::{
    derived::{
        AttrRecord, AttributeName, AttributeValue, ElfDynamic, ElfHeader, ElfProgram, ElfValue,
        MAGIC_PREFIX_LIMIT, Magic, PlaintextHashes, classify_magic, parse_elf_dynamic,
        parse_elf_header, parse_elf_programs, parse_shebang,
    },
    identity::Digest,
    properties::{EffectiveProperties, PropertyName, Value},
};

/// Effective per-regular-file hash and classification requirements.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Requirements {
    /// Registered hash attributes explicitly requested by effective `hashes`.
    pub hashes: Vec<AttributeName>,
    /// Registered classifiers explicitly requested by effective `classify`.
    pub classify: Vec<Magic>,
}

impl Requirements {
    /// Resolves already validated effective requirement properties.
    ///
    /// # Errors
    /// Returns a registry/type error for invalid hashes or classifier names.
    pub fn from_effective(properties: &EffectiveProperties<'_>) -> Result<Self, Error> {
        let mut result = Self::default();
        if let Some(value) = properties.get(PropertyName::Hashes) {
            let Value::Names(names) = value else {
                return Err(terrane_core::derived::Error::InvalidValue.into());
            };
            for name in names {
                let name = AttributeName::parse(&format!("hash.{name}"))?;
                if matches!(
                    name,
                    AttributeName::Magic | AttributeName::Elf | AttributeName::Shebang
                ) {
                    return Err(terrane_core::derived::Error::InvalidValue.into());
                }
                if !result.hashes.contains(&name) {
                    result.hashes.push(name);
                }
            }
        }
        if let Some(value) = properties.get(PropertyName::Classify) {
            let Value::Names(names) = value else {
                return Err(terrane_core::derived::Error::InvalidValue.into());
            };
            for name in names {
                let magic = Magic::parse(name)?;
                if !result.classify.contains(&magic) {
                    result.classify.push(magic);
                }
            }
        }
        Ok(result)
    }

    /// Selects mandatory attributes, including conditional ELF/shebang detail.
    pub fn names(&self, magic: Option<Magic>) -> Vec<AttributeName> {
        let mut names = self.hashes.clone();
        if !self.classify.is_empty() {
            names.push(AttributeName::Magic);
            if magic == Some(Magic::Elf) && self.classify.contains(&Magic::Elf) {
                names.push(AttributeName::Elf);
            }
            if magic == Some(Magic::Shebang) && self.classify.contains(&Magic::Shebang) {
                names.push(AttributeName::Shebang);
            }
        }
        names.sort();
        names.dedup();
        names
    }
}

async fn read<O: PlaintextObject + Sync>(
    object: &O,
    offset: u64,
    length: usize,
) -> Result<Vec<u8>, Error> {
    if length > MAGIC_PREFIX_LIMIT
        || offset
            .checked_add(length as u64)
            .is_none_or(|end| end > object.size())
    {
        return Err(Error::InvalidRead);
    }
    let bytes = object.read_range(offset, length).await?;
    if bytes.len() != length {
        return Err(Error::InvalidRead);
    }
    Ok(bytes)
}

/// Computes requested initial-version attributes without a whole-object buffer.
///
/// Hashes consume every byte in object order. Magic reads only the first 64 KiB.
/// ELF performs additional validated range reads; shebang uses that same prefix.
/// Deployment-supplied `zstd-dictionary` values cannot be computed here.
///
/// # Errors
/// Returns read, length, registered-name, malformed executable, or unsupported
/// dictionary-selection computation failures.
pub async fn compute<O: PlaintextObject + Sync>(
    object: &O,
    names: &[AttributeName],
) -> Result<Vec<AttributeValue>, Error> {
    if names.contains(&AttributeName::ZstdDictionary) {
        return Err(terrane_core::derived::Error::UnsupportedFunction.into());
    }

    let classify = names.iter().any(|name| {
        matches!(
            name,
            AttributeName::Magic | AttributeName::Elf | AttributeName::Shebang
        )
    });
    let prefix = if classify {
        read(
            object,
            0,
            object.size().min(MAGIC_PREFIX_LIMIT as u64) as usize,
        )
        .await?
    } else {
        Vec::new()
    };
    let need_hashes = names.iter().any(|name| {
        matches!(
            name,
            AttributeName::Sha256
                | AttributeName::Sha512
                | AttributeName::GitBlobSha1
                | AttributeName::GitBlobSha256
        )
    });
    let hashes = if need_hashes {
        let mut hashes = PlaintextHashes::new(object.size());
        let mut offset = 0;
        while offset < object.size() {
            let length = (object.size() - offset).min(MAGIC_PREFIX_LIMIT as u64) as usize;
            let bytes = read(object, offset, length).await?;
            hashes.update(&bytes)?;
            offset += length as u64;
        }
        Some(hashes.finish()?)
    } else {
        None
    };
    let mut values = Vec::new();
    for &name in names {
        values.push(match name {
            AttributeName::Magic => AttributeValue::Magic(classify_magic(&prefix)),
            AttributeName::Elf => AttributeValue::Elf(elf(object, &prefix).await?),
            AttributeName::Shebang => AttributeValue::Shebang(parse_shebang(
                &prefix,
                object.size() == prefix.len() as u64,
            )?),
            _ => hashes.as_ref().ok_or(Error::InvalidRead)?.attribute(name)?,
        });
    }
    Ok(values)
}

/// Supplies every effective per-file requirement, reusing eligible metadata hits.
///
/// An untrusted writer's records can be retained by passing `require_trusted =
/// false`; gateways requiring trust recompute missing or untrusted values and
/// publish under their own finalized producing commit and verified evidence.
/// Backfill iteration and commit checkpoints belong to the tree-job layer.
///
/// # Errors
/// Returns required-attribute production, admission, or producer-evidence errors.
pub async fn produce_required<S: ContentStore, O: PlaintextObject + Sync, V: ProducerVerifier>(
    table: &mut SideTable,
    store: &S,
    object: &O,
    requirements: &Requirements,
    producer: Digest,
    verifier: &V,
    require_trusted: bool,
) -> Result<Vec<AttrRecord>, Error> {
    produce_required_with(
        table,
        store,
        object,
        requirements,
        verifier,
        require_trusted,
        |value| Ok(AttrRecord::new(object.digest(), value, producer)),
    )
    .await
}

/// Configures detached signing with an already verified producing commit.
///
/// The borrowed secret is checked against the commit's authenticated terminal
/// public key each time a record is signed. This configuration grants no trust.
pub struct SignedProducer<'a> {
    commit: &'a terrane_core::provenance::VerifiedCommit,
    secret: &'a [u8; 32],
}

impl<'a> SignedProducer<'a> {
    /// Borrows the verified producing commit and its configured terminal secret.
    pub const fn new(
        commit: &'a terrane_core::provenance::VerifiedCommit,
        secret: &'a [u8; 32],
    ) -> Self {
        Self { commit, secret }
    }
}

/// Produces required attributes and seals new records with detached signatures.
///
/// Eligible side-table hits need no plaintext reads. Missing values are computed
/// and signed under the finalized producing commit. The configured verifier
/// independently checks the signed tree/object witness before trust is granted.
///
/// # Errors
/// Returns production, signature/key mismatch, admission, or provenance failures.
pub async fn produce_required_signed<
    S: ContentStore,
    O: PlaintextObject + Sync,
    V: ProducerVerifier,
>(
    table: &mut SideTable,
    store: &S,
    object: &O,
    requirements: &Requirements,
    producer: &SignedProducer<'_>,
    verifier: &V,
    require_trusted: bool,
) -> Result<Vec<AttrRecord>, Error> {
    produce_required_with(
        table,
        store,
        object,
        requirements,
        verifier,
        require_trusted,
        |value| {
            let mut record = AttrRecord::new(object.digest(), value, producer.commit.identity());
            record.sign(producer.commit, producer.secret)?;
            Ok(record)
        },
    )
    .await
}

async fn produce_required_with<S: ContentStore, O: PlaintextObject + Sync, V: ProducerVerifier>(
    table: &mut SideTable,
    store: &S,
    object: &O,
    requirements: &Requirements,
    verifier: &V,
    require_trusted: bool,
    record: impl Fn(AttributeValue) -> Result<AttrRecord, Error>,
) -> Result<Vec<AttrRecord>, Error> {
    let magic = if requirements.classify.is_empty() {
        None
    } else if let Some(record) =
        table.current(object.digest(), AttributeName::Magic, require_trusted)
    {
        if let AttributeValue::Magic(magic) = record.value {
            Some(magic)
        } else {
            return Err(terrane_core::derived::Error::InvalidValue.into());
        }
    } else {
        let bytes = read(
            object,
            0,
            object.size().min(MAGIC_PREFIX_LIMIT as u64) as usize,
        )
        .await?;
        Some(classify_magic(&bytes))
    };
    let names = requirements.names(magic);
    let missing: Vec<_> = names
        .iter()
        .copied()
        .filter(|&name| {
            table
                .current(object.digest(), name, require_trusted)
                .is_none()
        })
        .collect();
    let values = compute(object, &missing).await?;
    for value in values {
        table.put(store, record(value)?, verifier).await?;
    }
    names
        .into_iter()
        .map(|name| {
            table
                .current(object.digest(), name, require_trusted)
                .cloned()
                .ok_or(Error::InvalidProducer)
        })
        .collect()
}

async fn elf<O: PlaintextObject + Sync>(object: &O, prefix: &[u8]) -> Result<ElfValue, Error> {
    let header = parse_elf_header(prefix, object.size())?;
    let mut programs = Vec::new();
    let width = usize::from(header.program_width);
    let mut index = 0usize;
    // Program counts are u16. Fetch batches rather than issuing one I/O per entry.
    while index < usize::from(header.program_count) {
        let count = (usize::from(header.program_count) - index).min(MAGIC_PREFIX_LIMIT / width);
        let bytes = read(
            object,
            header.program_offset + (index * width) as u64,
            count * width,
        )
        .await?;
        programs.extend(parse_elf_programs(&header, &bytes, object.size())?);
        index += count;
    }
    let mut value = header.value.clone();
    let interpreters: Vec<_> = programs
        .iter()
        .filter(|program| program.kind == 3)
        .collect();
    if interpreters.len() > 1 {
        return malformed();
    }
    if let Some(program) = interpreters.first() {
        if program.file_size == 0 || program.file_size > MAGIC_PREFIX_LIMIT as u64 {
            return malformed();
        }
        let bytes = read(object, program.offset, program.file_size as usize).await?;
        if bytes.last() != Some(&0) || bytes[..bytes.len() - 1].contains(&0) {
            return malformed();
        }
        value.interpreter = Some(string(&bytes[..bytes.len() - 1])?);
    }
    let dynamics: Vec<_> = programs
        .iter()
        .filter(|program| program.kind == 2)
        .collect();
    if dynamics.len() > 1 {
        return malformed();
    }
    if let Some(program) = dynamics.first() {
        let dynamic = dynamic(object, &header, program).await?;
        if dynamic.string_address.is_some()
            || dynamic.string_size.is_some()
            || !dynamic.needed.is_empty()
        {
            let address = dynamic
                .string_address
                .ok_or(terrane_core::derived::Error::MalformedExecutable)?;
            let size = dynamic
                .string_size
                .ok_or(terrane_core::derived::Error::MalformedExecutable)?;
            let offset = string_table(&programs, address, size)?;
            for needed in dynamic.needed {
                if needed >= size {
                    return malformed();
                }
                value
                    .needed
                    .push(c_string(object, offset + needed, size - needed).await?);
            }
        }
    }
    Ok(value)
}

async fn dynamic<O: PlaintextObject + Sync>(
    object: &O,
    header: &ElfHeader,
    program: &ElfProgram,
) -> Result<ElfDynamic, Error> {
    let width = if header.value.class == 32 { 8 } else { 16 };
    if !program.file_size.is_multiple_of(width) {
        return malformed();
    }
    let mut result = ElfDynamic {
        string_address: None,
        string_size: None,
        needed: Vec::new(),
        terminated: false,
    };
    let mut offset = 0;
    while offset < program.file_size {
        let count = (program.file_size - offset).min(MAGIC_PREFIX_LIMIT as u64) as usize;
        let bytes = read(object, program.offset + offset, count).await?;
        let fragment = parse_elf_dynamic(header, &bytes)?;
        if let Some(address) = fragment.string_address
            && result.string_address.replace(address).is_some()
        {
            return malformed();
        }
        if let Some(size) = fragment.string_size
            && result.string_size.replace(size).is_some()
        {
            return malformed();
        }
        result.needed.extend(fragment.needed);
        if fragment.terminated {
            result.terminated = true;
            break;
        }
        offset += count as u64;
    }
    if !result.terminated {
        return malformed();
    }
    Ok(result)
}

fn string_table(programs: &[ElfProgram], address: u64, size: u64) -> Result<u64, Error> {
    let mut result = None;
    for program in programs.iter().filter(|program| program.kind == 1) {
        let Some(relative) = address.checked_sub(program.address) else {
            continue;
        };
        if relative
            .checked_add(size)
            .is_some_and(|end| end <= program.file_size)
        {
            let offset = program
                .offset
                .checked_add(relative)
                .ok_or(terrane_core::derived::Error::Limit)?;
            if result.is_some_and(|old| old != offset) {
                return malformed();
            }
            result = Some(offset);
        }
    }
    result.ok_or_else(|| terrane_core::derived::Error::MalformedExecutable.into())
}

async fn c_string<O: PlaintextObject + Sync>(
    object: &O,
    offset: u64,
    remaining: u64,
) -> Result<String, Error> {
    let bytes = read(
        object,
        offset,
        remaining.min(MAGIC_PREFIX_LIMIT as u64) as usize,
    )
    .await?;
    let end = bytes
        .iter()
        .position(|&b| b == 0)
        .ok_or(terrane_core::derived::Error::MalformedExecutable)?;
    string(&bytes[..end])
}

fn string(bytes: &[u8]) -> Result<String, Error> {
    if bytes.is_empty() {
        return malformed();
    }
    Ok(std::str::from_utf8(bytes)
        .map_err(|_| terrane_core::derived::Error::MalformedExecutable)?
        .to_owned())
}

fn malformed<T>() -> Result<T, Error> {
    Err(terrane_core::derived::Error::MalformedExecutable.into())
}
