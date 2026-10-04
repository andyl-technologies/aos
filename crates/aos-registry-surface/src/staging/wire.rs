//! Bounded wire encoding for exact registry candidate revisions.
//!
//! Candidate inventories can contain 50,000 immutable objects. RPC messages
//! carry their canonical JSON in `revision_gzip`; protobuf JSON represents the
//! compressed bytes as base64. Small callers may supply `revision_json` instead.
//! Exactly one field is populated in a detail response or an upsert request.
//!
//! ```text
//! revision_json: empty
//! revision_gzip: gzip(canonical StageRevision JSON)
//! ```

use std::io::Read as _;

use anyhow::{ensure, Context as _, Result};

use super::StageRevision;

/// Bounds decoded candidate JSON independently of the RPC request body.
pub const MAX_DECODED_REVISION_BYTES: usize = 32 * 1024 * 1024;

/// Keeps base64-encoded gzip and the surrounding RPC envelope below 8 MiB.
pub const MAX_COMPRESSED_REVISION_BYTES: usize = 6 * 1024 * 1024 - 4 * 1024;

/// Bounds the candidate's immutable object inventory.
pub const MAX_REVISION_OBJECTS: usize = 50_000;

/// Encodes one validated candidate as bounded gzip-compressed JSON.
///
/// # Errors
///
/// Returns an error for invalid candidate bytes, an oversized inventory or JSON
/// document, compression failure, or compressed bytes exceeding the RPC limit.
pub fn encode_revision(revision: &StageRevision) -> Result<Vec<u8>> {
    validate_inventory_limit(revision)?;
    revision.validate()?;

    let mut gzip = flate2::write::GzEncoder::new(
        BoundedWriter::new(MAX_COMPRESSED_REVISION_BYTES),
        flate2::Compression::default(),
    );
    let mut json = BoundedJsonWriter {
        gzip: &mut gzip,
        written: 0,
    };
    serde_json::to_writer(&mut json, revision).context("encoding candidate revision JSON")?;
    Ok(gzip
        .finish()
        .context("finishing candidate revision gzip")?
        .bytes)
}

/// Decodes exactly one bounded plain JSON or gzip candidate representation.
///
/// # Errors
///
/// Returns an error for missing or conflicting representations, oversized wire or
/// inflated bytes, malformed gzip, trailing compressed data, invalid JSON, an
/// oversized object inventory, or an invalid exact candidate revision.
pub fn decode_revision(revision_json: &str, revision_gzip: &[u8]) -> Result<StageRevision> {
    ensure!(
        revision_json.is_empty() != revision_gzip.is_empty(),
        "candidate revision requires exactly one JSON or gzip representation"
    );

    let bytes = if revision_gzip.is_empty() {
        ensure!(
            revision_json.len() <= MAX_DECODED_REVISION_BYTES,
            "candidate revision JSON exceeds the decoded limit"
        );
        revision_json.as_bytes().to_vec()
    } else {
        ensure!(
            revision_gzip.len() <= MAX_COMPRESSED_REVISION_BYTES,
            "candidate revision gzip exceeds the wire limit"
        );
        let mut decoder = flate2::bufread::GzDecoder::new(revision_gzip);
        let mut bytes = Vec::new();
        (&mut decoder)
            .take(u64::try_from(MAX_DECODED_REVISION_BYTES)? + 1)
            .read_to_end(&mut bytes)
            .context("inflating candidate revision gzip")?;
        ensure!(
            bytes.len() <= MAX_DECODED_REVISION_BYTES,
            "candidate revision gzip exceeds the decoded limit"
        );
        ensure!(
            decoder.get_ref().is_empty(),
            "candidate revision gzip contains trailing compressed data"
        );
        bytes
    };

    let revision: StageRevision =
        serde_json::from_slice(&bytes).context("decoding candidate revision JSON")?;
    drop(bytes);
    validate_inventory_limit(&revision)?;
    revision.validate()?;
    Ok(revision)
}

/// Streams bounded canonical JSON into gzip without retaining the raw document.
struct BoundedJsonWriter<'a> {
    gzip: &'a mut flate2::write::GzEncoder<BoundedWriter>,
    written: usize,
}

impl std::io::Write for BoundedJsonWriter<'_> {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        if buffer.len() > MAX_DECODED_REVISION_BYTES.saturating_sub(self.written) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "candidate revision exceeds its decoded byte limit",
            ));
        }
        self.gzip.write_all(buffer)?;
        self.written += buffer.len();
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.gzip.flush()
    }
}

fn validate_inventory_limit(revision: &StageRevision) -> Result<()> {
    ensure!(
        revision.inventory.len() <= MAX_REVISION_OBJECTS,
        "candidate inventory exceeds the object limit"
    );
    Ok(())
}

/// Bounds serialization and compression output as each buffer is written.
struct BoundedWriter {
    bytes: Vec<u8>,
    limit: usize,
}

impl BoundedWriter {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
        }
    }
}

impl std::io::Write for BoundedWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        if buffer.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "candidate revision exceeds its encoded byte limit",
            ));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use base64::Engine as _;
    use sha2::{Digest as _, Sha256};

    use super::*;
    use crate::staging::{inventory_digest, StageObject, StagePointer, STAGE_SCHEMA};

    fn revision(inventory: Vec<StageObject>, publication: Vec<StagePointer>) -> StageRevision {
        StageRevision {
            schema: STAGE_SCHEMA.into(),
            id: "candidate-1".into(),
            registry: "example/main".into(),
            revision: 1,
            release_id: "1.0.0".into(),
            source_branch: "dplecki/candidate".into(),
            commit: "a".repeat(40),
            inventory_digest: inventory_digest(&inventory).expect("inventory digest"),
            inventory,
            container: None,
            publication,
            store_roots: Vec::new(),
        }
    }

    #[test]
    fn supports_exact_plain_and_compressed_documents() {
        let candidate = revision(Vec::new(), Vec::new());
        let json = serde_json::to_string(&candidate).expect("plain JSON");
        let gzip = encode_revision(&candidate).expect("compressed revision");

        assert_eq!(
            decode_revision(&json, &[]).expect("plain decode"),
            candidate
        );
        assert_eq!(decode_revision("", &gzip).expect("gzip decode"), candidate);
        assert!(decode_revision(&json, &gzip).is_err());
        assert!(decode_revision("", &[]).is_err());

        let mut trailing = gzip;
        trailing.push(0);
        assert!(decode_revision("", &trailing).is_err());
    }

    #[test]
    fn streamed_inventory_digest_preserves_canonical_json_identity() {
        let inventory = vec![StageObject {
            path: "nar/escaped\"name.nar".into(),
            sha256: format!("sha256:{}", "a".repeat(64)),
            byte_size: u64::MAX,
            kind: "immutable: ü\t".into(),
            media_type: "application/octet-stream".into(),
        }];
        for objects in [&[][..], inventory.as_slice()] {
            let mut original = Sha256::new();
            original.update(b"aos.registry-stage-inventory/v1\0");
            original.update(serde_json::to_vec(objects).expect("original canonical JSON"));
            let expected = format!("sha256:{}", hex::encode(original.finalize()));

            assert_eq!(
                inventory_digest(objects).expect("streamed digest"),
                expected
            );
        }
    }

    #[test]
    fn full_catalog_with_random_hashes_and_binary_pack_index_fits_unary_body() {
        let mut inventory = (0_u32..50_000)
            .map(|index| {
                let hash = hex::encode(Sha256::digest(index.to_le_bytes()));
                StageObject {
                    path: format!("nar/{hash}.nar"),
                    sha256: format!("sha256:{}", hex::encode(Sha256::digest(hash.as_bytes()))),
                    byte_size: u64::from(index) + 1,
                    kind: "immutable".into(),
                    media_type: "application/octet-stream".into(),
                }
            })
            .collect::<Vec<_>>();
        inventory.sort_by(|left, right| left.path.cmp(&right.path));
        let mut pack_index = Vec::with_capacity(1_400_000);
        for index in 0_u32..43_750 {
            pack_index.extend_from_slice(&Sha256::digest(index.to_be_bytes()));
        }
        let candidate = revision(
            inventory,
            vec![StagePointer {
                path: format!("objects/pack/pack-{}.idx", "a".repeat(64)),
                bytes: pack_index,
                expected_sha256: None,
            }],
        );

        let gzip = encode_revision(&candidate).expect("full catalog fits compressed limit");
        let wire_json = serde_json::to_vec(&serde_json::json!({
            "registry": candidate.registry,
            "expectedRevision": 0,
            "revisionGzip": base64::engine::general_purpose::STANDARD.encode(&gzip),
        }))
        .expect("protobuf JSON envelope");

        eprintln!(
            "full catalog staging wire: {} gzip bytes, {} protobuf JSON bytes",
            gzip.len(),
            wire_json.len()
        );
        assert!(wire_json.len() < 8 * 1024 * 1024);
        assert_eq!(
            decode_revision("", &gzip).expect("full catalog decode"),
            candidate
        );
    }

    #[test]
    fn rejects_inflation_bombs_before_parsing_json() {
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let block = vec![b' '; 1024 * 1024];
        for _ in 0..33 {
            gzip.write_all(&block).expect("compress oversized JSON");
        }
        let gzip = gzip.finish().expect("finish gzip");

        let error = decode_revision("", &gzip).expect_err("inflated input must remain bounded");
        assert!(error.to_string().contains("decoded limit"));
    }

    #[test]
    fn rejects_oversized_wire_and_object_inventory() {
        let wire = vec![0; MAX_COMPRESSED_REVISION_BYTES + 1];
        let error =
            decode_revision("", &wire).expect_err("wire bytes are bounded before inflation");
        assert!(error.to_string().contains("wire limit"));

        let object = StageObject {
            path: "nar/one.nar".into(),
            sha256: format!("sha256:{}", "a".repeat(64)),
            byte_size: 1,
            kind: "immutable".into(),
            media_type: "application/octet-stream".into(),
        };
        let candidate = revision(vec![object; MAX_REVISION_OBJECTS + 1], Vec::new());
        let error = encode_revision(&candidate).expect_err("inventory count is bounded");
        assert!(error.to_string().contains("object limit"));
    }
}
