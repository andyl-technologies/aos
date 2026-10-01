//! Closed cell-sized JSONL records with immutable SQLite v1 and PostgreSQL v2.
//!
//! Every physical line is a typed record followed by LF. Strings escape their
//! own newlines; frame boundaries have no logical meaning. Metadata and private
//! records share schema identity and ordered row/cell locators.
//!
//! ```text
//! metadata: header, (table_start, (row_start, cell*, row_end)*, table_end)*, end
//! private:  header, private_cell*, end
//! ```

use std::io::Write;

use anyhow::{ensure, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

use super::super::{StreamDecoder, StreamEncoder};
use crate::snapshot::capture::PrivateScalarWire;
use crate::snapshot::{PrivateDependencyReason, SnapshotPrivateDependency, SnapshotScalar};

pub(super) const PROFILE: &str = "database_capture/v1";
pub(super) const POSTGRES_PROFILE: &str = "database_capture/v2";

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct PostgresSource {
    pub engine: String,
    pub major: String,
    pub isolation: String,
    pub access: String,
    pub audit: String,
    pub catalogue_sha256: String,
}

impl PostgresSource {
    pub(super) fn new(catalogue_sha256: String) -> Self {
        Self {
            engine: "postgresql".into(),
            major: "18".into(),
            isolation: "repeatable_read".into(),
            access: "read_only".into(),
            audit: "compiled_constraints_and_counts/v1".into(),
            catalogue_sha256,
        }
    }

    pub(super) fn expected() -> Self {
        Self::new(
            include_str!("../../../backend/postgres_snapshot/current8.sha256")
                .trim()
                .into(),
        )
    }
}
pub(super) const CONTROL_CAP: usize = 16 * 1024;
pub(super) const CELL_CAP: usize = 6 * 1024 * 1024 + CONTROL_CAP;

pub(super) struct WireScalar(pub SnapshotScalar);

impl Serialize for WireScalar {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for WireScalar {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        PrivateScalarWire::deserialize(deserializer).map(|scalar| Self(scalar.0))
    }
}

// The JSON arrays preserve historical generation-3 through generation-6 bytes.
// Only these exact closed lengths decode; the authenticated header must match the
// corresponding compiled generation, identity and digest commitments.
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub(super) enum MigrationDigests {
    Generation3([String; 3]),
    Generation4([String; 4]),
    Generation5([String; 5]),
    Generation6([String; 6]),
    Generation7([String; 7]),
    Generation8([String; 8]),
}

impl MigrationDigests {
    pub(super) fn from_vec(values: Vec<String>) -> Result<Self> {
        match values.len() {
            3 => Ok(Self::Generation3(values.try_into().map_err(|_| {
                anyhow::anyhow!("snapshot migration shape differs")
            })?)),
            4 => Ok(Self::Generation4(values.try_into().map_err(|_| {
                anyhow::anyhow!("snapshot migration shape differs")
            })?)),
            5 => Ok(Self::Generation5(values.try_into().map_err(|_| {
                anyhow::anyhow!("snapshot migration shape differs")
            })?)),
            6 => Ok(Self::Generation6(values.try_into().map_err(|_| {
                anyhow::anyhow!("snapshot migration shape differs")
            })?)),
            7 => Ok(Self::Generation7(values.try_into().map_err(|_| {
                anyhow::anyhow!("snapshot migration shape differs")
            })?)),
            8 => Ok(Self::Generation8(values.try_into().map_err(|_| {
                anyhow::anyhow!("snapshot migration shape differs")
            })?)),
            _ => anyhow::bail!("snapshot migration generation is unsupported"),
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Schema {
    pub classification_version: String,
    pub identity: String,
    pub version: String,
    pub migration_digests: MigrationDigests,
    pub classification_digest: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Header {
    pub kind: String,
    pub profile: String,
    pub archive_id: String,
    pub role: String,
    pub schema: Schema,
    pub table_count: String,
    pub audit: Audit,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<PostgresSource>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Audit {
    pub integrity: String,
    pub compiled_checks: String,
    pub declared_foreign_keys: String,
    pub checked_expressions: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TableStart {
    pub kind: String,
    pub ordinal: String,
    pub table: String,
    pub disposition: String,
    pub source_rows: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RowMark {
    pub kind: String,
    pub row: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Cell {
    pub kind: String,
    pub column: String,
    pub scalar: Option<WireScalar>,
    pub external: Option<Dependency>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Dependency {
    pub table: String,
    pub primary_key_digest: String,
    pub column: String,
    pub cell_digest: String,
    pub payload_bytes: String,
    pub reason: String,
}

impl Dependency {
    pub fn from_dependency(value: &SnapshotPrivateDependency) -> Self {
        Self {
            table: value.table.clone(),
            primary_key_digest: value.primary_key_digest.clone(),
            column: value.column.clone(),
            cell_digest: value.cell_digest.clone(),
            payload_bytes: value.payload_bytes.to_string(),
            reason: match value.reason {
                PrivateDependencyReason::Secret => "secret",
                PrivateDependencyReason::PrivateContext => "private_context",
                PrivateDependencyReason::OpaqueJson => "opaque_json",
            }
            .into(),
        }
    }

    pub fn into_dependency(self) -> Result<SnapshotPrivateDependency> {
        ensure!(
            self.table.len() <= 255
                && self.column.len() <= 255
                && digest(&self.primary_key_digest)
                && digest(&self.cell_digest),
            "snapshot record dependency is invalid"
        );
        let payload_bytes = number(&self.payload_bytes)?;
        ensure!(
            payload_bytes <= 1024 * 1024,
            "snapshot record cell exceeds limits"
        );
        let reason = match self.reason.as_str() {
            "secret" => PrivateDependencyReason::Secret,
            "private_context" => PrivateDependencyReason::PrivateContext,
            "opaque_json" => PrivateDependencyReason::OpaqueJson,
            _ => anyhow::bail!("snapshot record dependency reason is invalid"),
        };
        Ok(SnapshotPrivateDependency {
            table: self.table,
            primary_key_digest: self.primary_key_digest,
            column: self.column,
            cell_digest: self.cell_digest,
            payload_bytes: payload_bytes as usize,
            reason,
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PrivateCell {
    pub kind: String,
    pub row: String,
    pub dependency: Dependency,
    pub scalar: WireScalar,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TableEnd {
    pub kind: String,
    pub ordinal: String,
    pub source_rows: String,
    pub retained_rows: String,
    pub omitted_rows: String,
    pub private_cells: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct End {
    pub kind: String,
    pub profile: String,
    pub archive_id: String,
    pub role: String,
    pub table_count: String,
    pub retained_rows: String,
    pub omitted_rows: String,
    pub private_cells: String,
    pub records: String,
}

pub(super) fn number(text: &str) -> Result<u64> {
    ensure!(
        !text.is_empty()
            && text.len() <= 20
            && (text == "0" || !text.starts_with('0'))
            && text.bytes().all(|byte| byte.is_ascii_digit()),
        "snapshot record count is invalid"
    );
    text.parse()
        .map_err(|_| anyhow::anyhow!("snapshot record count is invalid"))
}

fn digest(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(super) fn add(value: &mut u64, amount: u64) -> Result<()> {
    *value = value
        .checked_add(amount)
        .ok_or_else(|| anyhow::anyhow!("snapshot record counter exceeds limits"))?;
    Ok(())
}

// This private buffer rejects expansion before extending. It never implements
// Debug/Serialize; callers must feed it directly into the encrypted encoder.
struct BoundedJson(Zeroizing<Vec<u8>>);

impl Write for BoundedJson {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.0.len().saturating_add(bytes.len()) > CELL_CAP {
            return Err(std::io::Error::other("snapshot record exceeds limits"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(super) struct RecordWriter<W: Write> {
    pub encoder: StreamEncoder<W>,
    pub records: u64,
}

impl<W: Write> RecordWriter<W> {
    pub fn write(&mut self, value: &impl Serialize) -> Result<()> {
        let mut buffer = BoundedJson(Zeroizing::new(Vec::new()));
        serde_json::to_writer(&mut buffer, value)
            .map_err(|_| anyhow::anyhow!("snapshot record encoding failed"))?;
        self.encoder.write_plaintext(&buffer.0)?;
        self.encoder.write_plaintext(b"\n")?;
        add(&mut self.records, 1)
    }
}

pub(super) struct RecordReader<R: std::io::Read> {
    pub decoder: StreamDecoder<R>,
    chunk: Zeroizing<Vec<u8>>,
    offset: usize,
    pub records: u64,
}

impl<R: std::io::Read> RecordReader<R> {
    pub fn new(decoder: StreamDecoder<R>) -> Self {
        Self {
            decoder,
            chunk: Zeroizing::new(Vec::new()),
            offset: 0,
            records: 0,
        }
    }

    pub fn read<T: serde::de::DeserializeOwned>(&mut self, cap: usize) -> Result<T> {
        let bytes = self
            .line(cap)?
            .ok_or_else(|| anyhow::anyhow!("snapshot logical record is absent"))?;
        serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("snapshot logical record is invalid"))
    }

    fn line(&mut self, cap: usize) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let mut line = Zeroizing::new(Vec::new());
        loop {
            if self.offset == self.chunk.len() {
                match self.decoder.next_chunk()? {
                    Some(chunk) => {
                        self.chunk =
                            chunk.with_private_bytes(|bytes| Zeroizing::new(bytes.to_vec()));
                        self.offset = 0;
                    }
                    None => {
                        ensure!(line.is_empty(), "snapshot logical record is unterminated");
                        return Ok(None);
                    }
                }
            }
            let remaining = &self.chunk[self.offset..];
            let delimiter = remaining.iter().position(|byte| *byte == b'\n');
            let take = delimiter.unwrap_or(remaining.len());
            ensure!(
                take <= cap.saturating_sub(line.len()),
                "snapshot logical record exceeds limits"
            );
            line.extend_from_slice(&remaining[..take]);
            self.offset += take;
            if delimiter.is_some() {
                self.offset += 1;
                ensure!(!line.is_empty(), "snapshot logical record is empty");
                add(&mut self.records, 1)?;
                return Ok(Some(line));
            }
        }
    }

    pub fn finish(&mut self) -> Result<()> {
        ensure!(
            self.line(CONTROL_CAP)?.is_none(),
            "snapshot logical stream has trailing records"
        );
        ensure!(
            self.decoder.summary().is_some(),
            "snapshot logical stream is incomplete"
        );
        Ok(())
    }
}
