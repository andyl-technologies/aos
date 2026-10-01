//! Strict positive multipart responses and bounded server-owned ListParts pages.
//!
//! ```xml
//! <CopyPartResult><ETag>&quot;strong-provider-etag&quot;</ETag></CopyPartResult>
//! ```
//!
//! A positive typed body is required even after HTTP success. Multipart checksum
//! metadata, pagination and receipt parsing establish no effect settlement.

use std::collections::BTreeMap;

use anyhow::{ensure, Result};

use crate::direct_upload::{
    canonical_manifest_digest, valid_direct_etag, DirectChecksumAlgorithm, DirectManifestPart,
    DirectPartChecksum, DirectPlacementRef, DirectUploadIntent, MAX_DIRECT_OBJECT_BYTES,
    MAX_DIRECT_PARTS, MAX_DIRECT_PART_BYTES,
};

use super::direct_xml::{self, Node};

/// Maximum buffered bytes for one provider multipart metadata page.
pub const MAX_DIRECT_MULTIPART_RESPONSE_BYTES: usize = 512 * 1024;

/// Maximum server-only complete manifest XML, independently of control envelopes.
pub const MAX_DIRECT_COMPLETE_XML_BYTES: usize = 12 * 1024 * 1024;

/// Encodes a complete ordered provider manifest with negotiated part checksums.
///
/// This server-only provider body never crosses Native control. The caller must
/// retain the exact immutable manifest before dispatching provider completion.
///
/// # Errors
/// Returns an error for empty/incomplete/changed manifest, geometry, checksum,
/// strong ETag or excessive provider XML. Zero objects use a real EmptyPut.
pub fn direct_complete_multipart_xml(
    intent: &DirectUploadIntent,
    placement: &DirectPlacementRef,
    parts: &[DirectManifestPart],
) -> Result<String> {
    canonical_manifest_digest(intent, placement, parts)?;
    ensure!(!parts.is_empty(), "empty source requires direct EmptyPut");
    let mut xml = String::from("<CompleteMultipartUpload>");
    for member in parts {
        let etag = member.etag.replace('"', "&quot;");
        let checksum = if placement.checksum_algorithm == DirectChecksumAlgorithm::Sha256 {
            format!(
                "<ChecksumSHA256>{}</ChecksumSHA256>",
                member.part.checksum.value
            )
        } else {
            String::new()
        };
        let part = format!(
            "<Part><PartNumber>{}</PartNumber><ETag>{etag}</ETag>{checksum}</Part>",
            member.part.part_number
        );
        ensure!(
            xml.len()
                .checked_add(part.len())
                .and_then(|n| n.checked_add(26))
                .is_some_and(|n| n <= MAX_DIRECT_COMPLETE_XML_BYTES),
            "direct complete manifest XML exceeds limit"
        );
        xml.push_str(&part);
    }
    xml.push_str("</CompleteMultipartUpload>");
    Ok(xml)
}

/// One positive provider part observation, without settlement assertions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectProviderPart {
    /// One-based provider part number.
    pub part_number: u32,
    /// Exact observed provider length.
    pub byte_size: u64,
    /// Strong canonical quoted ETag.
    pub etag: String,
    /// Optional provider-reported SHA-256; not full-object verification.
    pub sha256_checksum: Option<DirectPartChecksum>,
}

/// One exact bounded ListParts page, including an explicit continuation marker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectProviderPartsPage {
    /// Strictly ordered positive observations after the requested marker.
    pub parts: Vec<DirectProviderPart>,
    /// Next exact marker only when the provider positively reports truncation.
    pub next_part_number: Option<u32>,
}

/// Positive server-owned copy or completion receipt with an exact strong ETag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectProviderObjectReceipt {
    /// Positive exact strong ETag; never a source/full-object SHA declaration.
    pub etag: String,
    /// Optional provider SHA-256 checksum, potentially composite for multipart.
    pub sha256_checksum: Option<DirectProviderSha256Checksum>,
}

/// Provider SHA-256 metadata with explicit composite suffix, never full source proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectProviderSha256Checksum {
    /// Canonical base64 digest bytes.
    pub value: String,
    /// Composite member count when the provider includes a multipart suffix.
    pub part_count: Option<u32>,
}

/// Parses one exact bounded ListParts response against retained coordinates.
///
/// An observation is not proof that an outstanding grant or mutation settled.
/// Caller-side HTTP handling must bound the body and require successful status.
///
/// # Errors
/// Returns value-free errors for malformed XML, unknown/duplicate fields,
/// embedded errors, foreign coordinates, invalid parts or unsafe pagination.
pub fn parse_direct_list_parts(
    xml: &str,
    bucket: &str,
    key: &str,
    upload_id: &str,
    after_part: u32,
    maximum_parts: u32,
) -> Result<DirectProviderPartsPage> {
    ensure!(
        after_part < MAX_DIRECT_PARTS && (1..=1000).contains(&maximum_parts),
        "invalid direct ListParts request"
    );
    let root = direct_xml::parse(xml, MAX_DIRECT_MULTIPART_RESPONSE_BYTES)?;
    ensure!(
        root.name == "ListPartsResult",
        "missing positive ListParts result"
    );
    let mut fields = BTreeMap::new();
    let mut parts = Vec::new();
    for child in &root.children {
        if child.name == "Part" {
            ensure!(
                parts.len() < maximum_parts as usize,
                "direct ListParts page exceeds part limit"
            );
            parts.push(parse_part(child)?);
        } else {
            ensure!(
                [
                    "Bucket",
                    "Key",
                    "UploadId",
                    "PartNumberMarker",
                    "NextPartNumberMarker",
                    "MaxParts",
                    "IsTruncated",
                    "Initiator",
                    "Owner",
                    "StorageClass",
                    "ChecksumAlgorithm",
                    "ChecksumType"
                ]
                .contains(&child.name)
                    && fields.insert(child.name, child).is_none(),
                "unexpected direct ListParts field"
            );
        }
    }
    ensure!(
        scalar(&fields, "Bucket")? == bucket
            && scalar(&fields, "Key")? == key
            && scalar(&fields, "UploadId")? == upload_id
            && integer(&scalar(&fields, "PartNumberMarker")?)? == u64::from(after_part)
            && integer(&scalar(&fields, "MaxParts")?)? == u64::from(maximum_parts),
        "direct ListParts coordinates mismatch"
    );
    let mut previous = after_part;
    for part in &parts {
        ensure!(
            part.part_number > previous,
            "unordered direct ListParts result"
        );
        previous = part.part_number;
    }
    for name in ["Owner", "Initiator"] {
        if let Some(owner) = fields.get(name) {
            validate_owner(owner)?;
        }
    }
    validate_optional_metadata(&fields)?;
    let truncated = scalar(&fields, "IsTruncated")?;
    ensure!(
        truncated == "true" || truncated == "false",
        "invalid direct ListParts truncation"
    );
    let marker = fields
        .get("NextPartNumberMarker")
        .map(|node| integer(&node.scalar()?))
        .transpose()?;
    let next_part_number = if truncated == "true" {
        ensure!(
            !parts.is_empty()
                && marker == Some(u64::from(previous))
                && previous > after_part
                && previous < MAX_DIRECT_PARTS,
            "invalid direct ListParts continuation"
        );
        Some(previous)
    } else {
        ensure!(
            marker.is_none_or(|n| n == 0 || n == u64::from(previous)),
            "unexpected direct ListParts continuation"
        );
        None
    };
    Ok(DirectProviderPartsPage {
        parts,
        next_part_number,
    })
}

/// Parses a positive UploadPartCopy result, including body-level error refusal.
///
/// # Errors
/// Returns an error for empty/malformed/oversized XML, embedded errors, unknown
/// or duplicate fields, or an absent strong ETag. HTTP 200 alone is insufficient.
pub fn parse_direct_upload_part_copy(xml: &str) -> Result<DirectProviderObjectReceipt> {
    let root = direct_xml::parse(xml, MAX_DIRECT_MULTIPART_RESPONSE_BYTES)?;
    ensure!(
        root.name == "CopyPartResult",
        "missing positive UploadPartCopy result"
    );
    let fields = closed_fields(
        &root,
        &[
            "ETag",
            "LastModified",
            "ChecksumSHA256",
            "ChecksumSHA1",
            "ChecksumCRC32",
            "ChecksumCRC32C",
            "ChecksumCRC64NVME",
            "ChecksumType",
        ],
    )?;
    if let Some(date) = fields.get("LastModified") {
        ensure!(
            !date.scalar()?.is_empty() && date.scalar()?.len() <= 64,
            "invalid direct copy date"
        );
    }
    receipt(&fields)
}

/// Parses a positive staging multipart completion for exact retained coordinates.
///
/// # Errors
/// Returns an error for absent/embedded-error receipt, malformed fields, foreign
/// bucket/key or invalid strong ETag. No absent object/timeout is interpreted as success.
pub fn parse_direct_complete_multipart(
    xml: &str,
    bucket: &str,
    key: &str,
) -> Result<DirectProviderObjectReceipt> {
    let root = direct_xml::parse(xml, MAX_DIRECT_MULTIPART_RESPONSE_BYTES)?;
    ensure!(
        root.name == "CompleteMultipartUploadResult",
        "missing positive multipart completion"
    );
    let fields = closed_fields(
        &root,
        &[
            "Location",
            "Bucket",
            "Key",
            "ETag",
            "ChecksumSHA256",
            "ChecksumSHA1",
            "ChecksumCRC32",
            "ChecksumCRC32C",
            "ChecksumCRC64NVME",
            "ChecksumType",
        ],
    )?;
    ensure!(
        scalar(&fields, "Bucket")? == bucket && scalar(&fields, "Key")? == key,
        "direct completion coordinates mismatch"
    );
    if let Some(location) = fields.get("Location") {
        ensure!(
            location.scalar()?.len() <= 8192,
            "invalid direct completion location"
        );
    }
    receipt(&fields)
}

/// Parses a positive multipart creation for the exact admitted private stage.
///
/// # Errors
/// Returns an error for absent/invalid/embedded-error result, foreign coordinates,
/// duplicate fields or excessive provider upload identifier.
pub fn parse_direct_create_multipart(xml: &str, bucket: &str, key: &str) -> Result<String> {
    let root = direct_xml::parse(xml, MAX_DIRECT_MULTIPART_RESPONSE_BYTES)?;
    ensure!(
        root.name == "InitiateMultipartUploadResult",
        "missing positive multipart creation"
    );
    let fields = closed_fields(&root, &["Bucket", "Key", "UploadId"])?;
    let id = scalar(&fields, "UploadId")?;
    ensure!(
        scalar(&fields, "Bucket")? == bucket
            && scalar(&fields, "Key")? == key
            && !id.is_empty()
            && id.len() <= 2048,
        "direct creation coordinates mismatch"
    );
    Ok(id)
}

fn parse_part(node: &Node<'_>) -> Result<DirectProviderPart> {
    let fields = closed_fields(
        node,
        &[
            "PartNumber",
            "LastModified",
            "ETag",
            "Size",
            "ChecksumSHA256",
            "ChecksumSHA1",
            "ChecksumCRC32",
            "ChecksumCRC32C",
            "ChecksumCRC64NVME",
        ],
    )?;
    let number = integer(&scalar(&fields, "PartNumber")?)?;
    let size = integer(&scalar(&fields, "Size")?)?;
    ensure!(
        (1..=u64::from(MAX_DIRECT_PARTS)).contains(&number)
            && size > 0
            && size <= MAX_DIRECT_PART_BYTES
            && size <= MAX_DIRECT_OBJECT_BYTES,
        "invalid direct provider part geometry"
    );
    if let Some(date) = fields.get("LastModified") {
        ensure!(
            !date.scalar()?.is_empty() && date.scalar()?.len() <= 64,
            "invalid direct provider part date"
        );
    }
    let record = receipt(&fields)?;
    Ok(DirectProviderPart {
        part_number: u32::try_from(number)
            .map_err(|_| anyhow::anyhow!("invalid direct provider part number"))?,
        byte_size: size,
        etag: record.etag,
        sha256_checksum: record
            .sha256_checksum
            .map(|checksum| {
                ensure!(
                    checksum.part_count.is_none(),
                    "composite checksum is not a part checksum"
                );
                Ok(DirectPartChecksum {
                    algorithm: DirectChecksumAlgorithm::Sha256,
                    value: checksum.value,
                })
            })
            .transpose()?,
    })
}

fn receipt(fields: &BTreeMap<&str, &Node<'_>>) -> Result<DirectProviderObjectReceipt> {
    let etag = scalar(fields, "ETag")?;
    ensure!(valid_direct_etag(&etag), "invalid direct provider ETag");
    let sha256_checksum = fields
        .get("ChecksumSHA256")
        .map(|node| -> Result<_> {
            let value = node.scalar()?;
            let (base, count) = value
                .split_once('-')
                .map_or((value.as_str(), None), |(base, count)| (base, Some(count)));
            let checksum = DirectPartChecksum {
                algorithm: DirectChecksumAlgorithm::Sha256,
                value: base.to_owned(),
            };
            checksum.decoded()?;
            let part_count = count
                .map(|count| -> Result<u32> {
                    let count = integer(count)?;
                    ensure!(
                        (1..=u64::from(MAX_DIRECT_PARTS)).contains(&count),
                        "invalid composite provider checksum count"
                    );
                    u32::try_from(count)
                        .map_err(|_| anyhow::anyhow!("invalid composite provider checksum count"))
                })
                .transpose()?;
            Ok(DirectProviderSha256Checksum {
                value: checksum.value,
                part_count,
            })
        })
        .transpose()?;
    for name in [
        "ChecksumSHA1",
        "ChecksumCRC32",
        "ChecksumCRC32C",
        "ChecksumCRC64NVME",
    ] {
        if let Some(node) = fields.get(name) {
            let value = node.scalar()?;
            ensure!(
                !value.is_empty() && value.len() <= 128,
                "invalid direct provider checksum metadata"
            );
        }
    }
    validate_optional_metadata(fields)?;
    Ok(DirectProviderObjectReceipt {
        etag,
        sha256_checksum,
    })
}

fn closed_fields<'a, 'b>(
    node: &'b Node<'a>,
    allowed: &[&str],
) -> Result<BTreeMap<&'a str, &'b Node<'a>>> {
    let mut fields = BTreeMap::new();
    for child in &node.children {
        ensure!(
            allowed.contains(&child.name) && fields.insert(child.name, child).is_none(),
            "unexpected direct multipart field"
        );
    }
    Ok(fields)
}

fn scalar(fields: &BTreeMap<&str, &Node<'_>>, name: &str) -> Result<String> {
    fields
        .get(name)
        .ok_or_else(|| anyhow::anyhow!("missing direct multipart field"))?
        .scalar()
}

fn integer(value: &str) -> Result<u64> {
    ensure!(
        !value.is_empty()
            && value.len() <= 20
            && value.bytes().all(|b| b.is_ascii_digit())
            && (value == "0" || !value.starts_with('0')),
        "invalid direct multipart integer"
    );
    value
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid direct multipart integer"))
}

fn validate_owner(node: &Node<'_>) -> Result<()> {
    let fields = closed_fields(node, &["ID", "DisplayName"])?;
    ensure!(!fields.is_empty(), "invalid direct multipart owner");
    for field in fields.values() {
        ensure!(
            field.scalar()?.len() <= 255,
            "invalid direct multipart owner"
        );
    }
    Ok(())
}

fn validate_optional_metadata(fields: &BTreeMap<&str, &Node<'_>>) -> Result<()> {
    if let Some(node) = fields.get("StorageClass") {
        ensure!(
            !node.scalar()?.is_empty() && node.scalar()?.len() <= 64,
            "invalid direct storage class"
        );
    }
    if let Some(node) = fields.get("ChecksumAlgorithm") {
        ensure!(
            ["SHA256", "SHA1", "CRC32", "CRC32C", "CRC64NVME", "MD5"]
                .contains(&node.scalar()?.as_str()),
            "unsupported direct provider checksum algorithm"
        );
    }
    if let Some(node) = fields.get("ChecksumType") {
        ensure!(
            ["COMPOSITE", "FULL_OBJECT"].contains(&node.scalar()?.as_str()),
            "invalid direct provider checksum type"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests;
