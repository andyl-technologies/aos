//! Strict bounded extraction of public documents from an signed package ability publication NAR.
//!
//! The accepted archive shape is deliberately narrower than a general Nix
//! archive. It contains one non-executable `package.json` file and an
//! `interfaces` directory whose entries are non-executable canonical-document
//! files named by lowercase SHA-256 hex digests.

use std::collections::BTreeMap;

use aos_ability_model::ABILITY_LIMITS_V1;

use crate::{DocumentationError, Result};

/// Maximum uncompressed signed package ability publication NAR size accepted by reference tooling.
pub const MAX_PACKAGE_ABILITY_NAR_BYTES: usize = 16 * 1024 * 1024;

/// Public documents extracted from one strictly shaped signed package ability publication NAR.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageAbilityDocuments {
    /// Exact canonical `package.json` bytes.
    pub package: Vec<u8>,
    /// Exact interface bytes keyed by their `<sha256-hex>.json` file names.
    pub interfaces: BTreeMap<String, Vec<u8>>,
}

/// Extracts bounded ability documents from an uncompressed package publication NAR.
///
/// # Errors
///
/// Returns an error for an oversized, malformed, noncanonical, executable, or
/// unexpectedly shaped archive, or for a document outside the shared ability
/// document bounds.
pub fn decode_package_ability_nar(bytes: &[u8]) -> Result<PackageAbilityDocuments> {
    if bytes.len() > MAX_PACKAGE_ABILITY_NAR_BYTES {
        return Err(invalid(
            "signed package ability publication NAR exceeds the 16 MiB limit",
        ));
    }

    let mut reader = NarReader::new(bytes);
    reader.expect(b"nix-archive-1", "archive magic")?;
    reader.expect(b"(", "root node")?;
    reader.expect(b"type", "root type tag")?;
    reader.expect(b"directory", "root directory type")?;

    let mut package = None;
    let mut interfaces = None;
    let mut previous = None::<Vec<u8>>;
    loop {
        let tag = reader.read("root entry tag")?;
        if tag == b")" {
            break;
        }
        if tag != b"entry" {
            return Err(invalid(
                "signed package ability publication root contains an invalid entry tag",
            ));
        }
        reader.expect(b"(", "root entry")?;
        reader.expect(b"name", "root entry name tag")?;
        let name = reader.read("root entry name")?.to_vec();
        require_sorted_name(
            &mut previous,
            &name,
            "signed package ability publication root",
        )?;
        reader.expect(b"node", "root entry node tag")?;
        match name.as_slice() {
            b"package.json" => {
                if package.is_some() {
                    return Err(invalid(
                        "signed package ability publication repeats package.json",
                    ));
                }
                package = Some(read_regular_document(&mut reader, "package.json")?);
            }
            b"interfaces" => {
                if interfaces.is_some() {
                    return Err(invalid(
                        "signed package ability publication repeats interfaces directory",
                    ));
                }
                interfaces = Some(read_interfaces(&mut reader)?);
            }
            _ => {
                return Err(invalid(
                    "signed package ability publication contains an unexpected root entry",
                ));
            }
        }
        reader.expect(b")", "root entry close")?;
    }
    if !reader.is_finished() {
        return Err(invalid(
            "signed package ability publication NAR has trailing data",
        ));
    }

    Ok(PackageAbilityDocuments {
        package: package
            .ok_or_else(|| invalid("signed package ability publication has no package.json"))?,
        interfaces: interfaces.ok_or_else(|| {
            invalid("signed package ability publication has no interfaces directory")
        })?,
    })
}

fn read_interfaces(reader: &mut NarReader<'_>) -> Result<BTreeMap<String, Vec<u8>>> {
    reader.expect(b"(", "interfaces node")?;
    reader.expect(b"type", "interfaces type tag")?;
    reader.expect(b"directory", "interfaces directory type")?;

    let mut interfaces = BTreeMap::new();
    let mut previous = None::<Vec<u8>>;
    loop {
        let tag = reader.read("interface entry tag")?;
        if tag == b")" {
            break;
        }
        if tag != b"entry" {
            return Err(invalid(
                "interfaces directory contains an invalid entry tag",
            ));
        }
        reader.expect(b"(", "interface entry")?;
        reader.expect(b"name", "interface entry name tag")?;
        let name = reader.read("interface entry name")?.to_vec();
        require_sorted_name(&mut previous, &name, "interfaces directory")?;
        if !is_interface_file_name(&name) {
            return Err(invalid(
                "interface file name is not lowercase SHA-256 hex JSON",
            ));
        }
        let name = String::from_utf8(name)
            .map_err(|_| invalid("interface file name is not valid UTF-8"))?;
        reader.expect(b"node", "interface entry node tag")?;
        let document = read_regular_document(reader, "interface document")?;
        if interfaces.insert(name, document).is_some() {
            return Err(invalid(
                "signed package ability publication repeats an interface file",
            ));
        }
        reader.expect(b")", "interface entry close")?;
    }
    Ok(interfaces)
}

fn read_regular_document(reader: &mut NarReader<'_>, label: &str) -> Result<Vec<u8>> {
    reader.expect(b"(", label)?;
    reader.expect(b"type", label)?;
    reader.expect(b"regular", label)?;
    reader.expect(b"contents", label)?;
    let document = reader.read(label)?.to_vec();
    if document.is_empty() || document.len() as u64 > ABILITY_LIMITS_V1.max_document_bytes {
        return Err(invalid(format!(
            "{label} is outside the shared document size bound"
        )));
    }
    reader.expect(b")", label)?;
    Ok(document)
}

fn require_sorted_name(previous: &mut Option<Vec<u8>>, name: &[u8], label: &str) -> Result<()> {
    if name.is_empty() || previous.as_deref().is_some_and(|value| value >= name) {
        return Err(invalid(format!(
            "{label} entries are not in canonical order"
        )));
    }
    *previous = Some(name.to_vec());
    Ok(())
}

fn is_interface_file_name(name: &[u8]) -> bool {
    name.len() == 69
        && name[..64]
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        && &name[64..] == b".json"
}

struct NarReader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> NarReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn read(&mut self, label: &str) -> Result<&'a [u8]> {
        let length_end = self.position.checked_add(8).ok_or_else(|| {
            invalid(format!(
                "signed package ability publication NAR overflows at {label}"
            ))
        })?;
        let length_bytes = self.bytes.get(self.position..length_end).ok_or_else(|| {
            invalid(format!(
                "signed package ability publication NAR is truncated at {label}"
            ))
        })?;
        let mut encoded = [0_u8; 8];
        encoded.copy_from_slice(length_bytes);
        let length = usize::try_from(u64::from_le_bytes(encoded)).map_err(|_| {
            invalid(format!(
                "signed package ability publication NAR length overflows at {label}"
            ))
        })?;
        let content_start = length_end;
        let content_end = content_start.checked_add(length).ok_or_else(|| {
            invalid(format!(
                "signed package ability publication NAR overflows at {label}"
            ))
        })?;
        let padded = length
            .checked_add(7)
            .map(|value| value / 8 * 8)
            .ok_or_else(|| {
                invalid(format!(
                    "signed package ability publication NAR padding overflows at {label}"
                ))
            })?;
        let next = content_start.checked_add(padded).ok_or_else(|| {
            invalid(format!(
                "signed package ability publication NAR overflows at {label}"
            ))
        })?;
        let content = self.bytes.get(content_start..content_end).ok_or_else(|| {
            invalid(format!(
                "signed package ability publication NAR is truncated at {label}"
            ))
        })?;
        let padding = self.bytes.get(content_end..next).ok_or_else(|| {
            invalid(format!(
                "signed package ability publication NAR is truncated after {label}"
            ))
        })?;
        if padding.iter().any(|byte| *byte != 0) {
            return Err(invalid(format!(
                "signed package ability publication NAR has non-zero padding after {label}"
            )));
        }
        self.position = next;
        Ok(content)
    }

    fn expect(&mut self, expected: &[u8], label: &str) -> Result<()> {
        if self.read(label)? != expected {
            return Err(invalid(format!(
                "signed package ability publication NAR has invalid {label}"
            )));
        }
        Ok(())
    }

    fn is_finished(&self) -> bool {
        self.position == self.bytes.len()
    }
}

fn invalid(message: impl Into<String>) -> DocumentationError {
    DocumentationError::Invalid(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(output: &mut Vec<u8>, bytes: &[u8]) {
        output.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        output.extend_from_slice(bytes);
        output.resize(output.len().div_ceil(8) * 8, 0);
    }

    fn fixture(interface_name: &[u8]) -> Vec<u8> {
        let mut nar = Vec::new();
        for value in [b"nix-archive-1".as_slice(), b"(", b"type", b"directory"] {
            field(&mut nar, value);
        }
        for value in [
            b"entry".as_slice(),
            b"(",
            b"name",
            b"interfaces",
            b"node",
            b"(",
            b"type",
            b"directory",
            b"entry",
            b"(",
            b"name",
        ] {
            field(&mut nar, value);
        }
        field(&mut nar, interface_name);
        for value in [
            b"node".as_slice(),
            b"(",
            b"type",
            b"regular",
            b"contents",
            b"{}",
            b")",
            b")",
            b")",
            b")",
            b"entry",
            b"(",
            b"name",
            b"package.json",
            b"node",
            b"(",
            b"type",
            b"regular",
            b"contents",
            b"{}",
            b")",
            b")",
            b")",
        ] {
            field(&mut nar, value);
        }
        nar
    }

    #[test]
    fn extracts_the_exact_closed_publication_shape() {
        let name = format!("{}.json", "a".repeat(64));
        let documents = decode_package_ability_nar(&fixture(name.as_bytes()))
            .expect("decode package publication fixture");

        assert_eq!(documents.package, b"{}");
        assert_eq!(
            documents.interfaces.get(&name).map(Vec::as_slice),
            Some(b"{}".as_slice())
        );
    }

    #[test]
    fn rejects_non_digest_names_and_trailing_data() {
        assert!(decode_package_ability_nar(&fixture(b"interface.json")).is_err());

        let name = format!("{}.json", "a".repeat(64));
        let mut nar = fixture(name.as_bytes());
        nar.push(0);
        assert!(decode_package_ability_nar(&nar).is_err());
    }
}
