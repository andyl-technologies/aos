//! Paired encrypted requirements and exact source-projection comparison.
//!
//! Each role starts with the same source/schema/coverage commitments and ends
//! with identical counts. Only the private role contains projected records.
//!
//! ```text
//! metadata: header -> end
//! private:  header -> requirement* -> end
//! ```

use std::io::{Read, Write};

use anyhow::{ensure, Result};
use rand::TryCryptoRng;
use serde::Serialize;

use super::{
    hash_string, io, ObjectRequirementsCounts, ObjectRequirementsCoverage, ObjectRequirementsLimits,
};
use crate::snapshot::archive::records::DatabaseCaptureCounts;
use crate::snapshot::archive::root::{
    prepare_archive_keys, sign_declared_root, verify_declared_root, ArchiveSignerTrust,
    ArchiveSigningKey, ArchiveWrappingKeys, ExcludedArchiveKey, FreshArchiveId,
    PreparedArchiveKeys, SignedDeclaredRoot, VerifiedDeclaredRoot,
};
use crate::snapshot::archive::{
    FreshStreamKey, StreamContext, StreamDecoder, StreamEncoder, StreamLimits, StreamRole,
};
use crate::snapshot::SnapshotSchemaManifest;
use crate::value::Row;

/// Unpublished paired stream output, without object-completeness authority.
pub struct ObjectRequirementsOutput<M, P> {
    /// Completed encrypted metadata writer.
    pub metadata: M,
    /// Completed encrypted private projections writer.
    pub private: P,
    /// Existing framing-only signed root; inner requirements remain incomplete.
    pub root: SignedDeclaredRoot,
    /// Counts of selected rows and explicitly unresolved dependencies.
    pub counts: ObjectRequirementsCounts,
}

/// One-operation encrypted projection writer with no retained all-object map.
///
/// Callers must replay every source row and independently finish SQL checks
/// before publishing this provisional output. No runtime/provider keys are used.
pub struct ObjectRequirementsWriter<M: Write, P: Write> {
    metadata: StreamEncoder<M>,
    private: StreamEncoder<P>,
    prepared: PreparedArchiveKeys,
    coverage: ObjectRequirementsCoverage,
    source: String,
    counts: ObjectRequirementsCounts,
    limits: ObjectRequirementsLimits,
    failed: bool,
}

impl<M: Write, P: Write> ObjectRequirementsWriter<M, P> {
    /// Starts fresh framed streams bound to one externally verified capture root.
    ///
    /// # Errors
    ///
    /// Rejects limits, source digest, compiled coverage, custody equality,
    /// randomness or writer failures. Source authentication remains the caller's
    /// responsibility; no source signer or object evidence is inferred here.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        metadata: M,
        private: P,
        source_capture_root_sha256: &str,
        signer: &ArchiveSigningKey,
        wrapping: &ArchiveWrappingKeys,
        exclusions: &[ExcludedArchiveKey],
        rng: &mut impl TryCryptoRng,
        streams: StreamLimits,
        limits: ObjectRequirementsLimits,
    ) -> Result<Self> {
        limits.validate()?;
        hash_string(source_capture_root_sha256)?;
        let coverage = ObjectRequirementsCoverage::current8()?;
        let archive = FreshArchiveId::generate(rng)?;
        let metadata_key = FreshStreamKey::generate(rng)?;
        let private_key = FreshStreamKey::generate(rng)?;
        let prepared = prepare_archive_keys(
            &archive,
            signer,
            wrapping,
            &metadata_key,
            &private_key,
            exclusions,
        )?;
        let mut metadata = StreamEncoder::new(
            metadata,
            metadata_key,
            StreamContext::new(archive.bytes(), StreamRole::Metadata),
            streams,
        )?;
        let mut private = StreamEncoder::new(
            private,
            private_key,
            StreamContext::new(archive.bytes(), StreamRole::Private),
            streams,
        )?;
        let id = hex::encode(archive.bytes());
        io::write(
            &mut metadata,
            &coverage.header(&id, "metadata", source_capture_root_sha256),
        )?;
        io::write(
            &mut private,
            &coverage.header(&id, "private", source_capture_root_sha256),
        )?;
        Ok(Self {
            metadata,
            private,
            prepared,
            coverage,
            source: source_capture_root_sha256.into(),
            counts: Default::default(),
            limits,
            failed: false,
        })
    }

    /// Requires the exact authenticated generation-eight source manifest.
    ///
    /// # Errors
    ///
    /// Rejects historical, altered or unrecognized source contracts.
    pub fn require_schema(&self, schema: &SnapshotSchemaManifest) -> Result<()> {
        self.coverage.require_schema(schema)
    }

    /// Projects one original retained row into the private encrypted stream.
    ///
    /// Exact ordinal order, source width, excluded secrets and independent row/
    /// record/frame bounds are enforced. No plaintext record is returned.
    ///
    /// # Errors
    ///
    /// Rejects shape/order, excessive work, unsupported values or I/O failure.
    pub fn row(&mut self, table: &str, sequence: u64, row: &Row) -> Result<()> {
        ensure!(
            !self.failed,
            "object requirements projection already failed"
        );
        // Projection counters and stream writes cannot be rolled back after an
        // error. A caller must discard this provisional operation, not finish it.
        self.failed = true;
        if let Some(projection) =
            self.coverage
                .project(table, sequence, row, &mut self.counts, self.limits)?
        {
            io::write(&mut self.private, &projection)?;
        }
        self.failed = false;
        Ok(())
    }

    /// Completes provisional framing after the caller's full source SQL replay.
    ///
    /// # Errors
    ///
    /// Rejects source row-count mismatch, framing, writer or signer failure.
    /// This does not substitute for actual SQL replay or storage readback.
    pub fn finish(
        mut self,
        signer: &ArchiveSigningKey,
        source_counts: &DatabaseCaptureCounts,
    ) -> Result<ObjectRequirementsOutput<M, P>> {
        ensure!(
            !self.failed,
            "object requirements projection already failed"
        );
        ensure!(
            self.counts.source_retained_rows == source_counts.retained_rows,
            "object requirements source counts differ"
        );
        let end = End {
            kind: "end",
            profile: super::PROFILE,
            source_capture_root_sha256: &self.source,
            counts: &self.counts,
        };
        io::write(&mut self.metadata, &end)?;
        io::write(&mut self.private, &end)?;
        let (metadata, metadata_summary) = self.metadata.finish()?;
        let (private, private_summary) = self.private.finish()?;
        let root = sign_declared_root(self.prepared, signer, &metadata_summary, &private_summary)?;
        Ok(ObjectRequirementsOutput {
            metadata,
            private,
            root,
            counts: self.counts,
        })
    }
}

/// An exact comparison reader requiring the original capture's replayed rows.
///
/// No projected private value is exposed or accepted as a storage assertion.
/// Signature, framing, canonical bytes, source root, coverage and every expected
/// row are compared; completion still depends on the caller's full SQL replay.
pub struct ObjectRequirementsReader<M: Read, P: Read> {
    metadata: io::Reader<M>,
    private: io::Reader<P>,
    root: VerifiedDeclaredRoot,
    coverage: ObjectRequirementsCoverage,
    source: String,
    counts: ObjectRequirementsCounts,
    limits: ObjectRequirementsLimits,
    failed: bool,
}

impl<M: Read, P: Read> ObjectRequirementsReader<M, P> {
    /// Authenticates framing and compares both inner headers to the exact source.
    ///
    /// # Errors
    ///
    /// Rejects external signer/custody, profile, coverage, source digest, limits,
    /// framing or header differences. It never obtains source/runtime secrets.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        root: &[u8],
        trust: &ArchiveSignerTrust,
        wrapping: &ArchiveWrappingKeys,
        exclusions: &[ExcludedArchiveKey],
        metadata: M,
        private: P,
        source_capture_root_sha256: &str,
        streams: StreamLimits,
        limits: ObjectRequirementsLimits,
    ) -> Result<Self> {
        limits.validate()?;
        hash_string(source_capture_root_sha256)?;
        let root = verify_declared_root(root, trust)?;
        let (metadata_key, private_key) = root
            .unwrap_reader_keys(wrapping, exclusions)?
            .into_role_keys();
        let coverage = ObjectRequirementsCoverage::current8()?;
        let mut metadata = io::Reader::new(StreamDecoder::new(
            metadata,
            metadata_key,
            root.stream_context(StreamRole::Metadata),
            streams,
        )?);
        let mut private = io::Reader::new(StreamDecoder::new(
            private,
            private_key,
            root.stream_context(StreamRole::Private),
            streams,
        )?);
        let id = hex::encode(root.archive_id());
        metadata.compare(&coverage.header(&id, "metadata", source_capture_root_sha256))?;
        private.compare(&coverage.header(&id, "private", source_capture_root_sha256))?;
        Ok(Self {
            metadata,
            private,
            root,
            coverage,
            source: source_capture_root_sha256.into(),
            counts: Default::default(),
            limits,
            failed: false,
        })
    }

    /// Requires the exact independently authenticated source manifest.
    ///
    /// # Errors
    ///
    /// Rejects any source schema difference.
    pub fn require_schema(&self, schema: &SnapshotSchemaManifest) -> Result<()> {
        self.coverage.require_schema(schema)
    }

    /// Compares the next expected projection from the original private SQL row.
    ///
    /// # Errors
    ///
    /// Rejects any missing/extra/reordered/altered projection or excessive work.
    pub fn row(&mut self, table: &str, sequence: u64, row: &Row) -> Result<()> {
        ensure!(
            !self.failed,
            "object requirements comparison already failed"
        );
        self.failed = true;
        if let Some(projection) =
            self.coverage
                .project(table, sequence, row, &mut self.counts, self.limits)?
        {
            self.private.compare(&projection)?;
        }
        self.failed = false;
        Ok(())
    }

    /// Finishes exact projection comparison and authenticates clean stream EOFs.
    ///
    /// # Errors
    ///
    /// Rejects source counts, logical ends, trailing records, frame ends or
    /// signed ciphertext-summary differences. No restore authority is returned.
    pub fn finish(
        mut self,
        source_counts: &DatabaseCaptureCounts,
    ) -> Result<ObjectRequirementsCounts> {
        ensure!(
            !self.failed,
            "object requirements comparison already failed"
        );
        ensure!(
            self.counts.source_retained_rows == source_counts.retained_rows,
            "object requirements source counts differ"
        );
        let end = End {
            kind: "end",
            profile: super::PROFILE,
            source_capture_root_sha256: &self.source,
            counts: &self.counts,
        };
        self.metadata.compare(&end)?;
        self.private.compare(&end)?;
        self.metadata.finish()?;
        self.private.finish()?;
        for (role, summary) in [
            (StreamRole::Metadata, self.metadata.decoder.summary()),
            (StreamRole::Private, self.private.decoder.summary()),
        ] {
            self.root.reconcile_declared_summary(
                role,
                summary
                    .ok_or_else(|| anyhow::anyhow!("object requirements framing is incomplete"))?,
            )?;
        }
        Ok(self.counts)
    }
}

#[derive(Serialize)]
struct End<'a> {
    kind: &'static str,
    profile: &'static str,
    source_capture_root_sha256: &'a str,
    counts: &'a ObjectRequirementsCounts,
}
