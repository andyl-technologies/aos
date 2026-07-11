//! Persistent sidecar for address-free unary tier-2 CLIF bodies.

use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use ratchet_core::{Ir, IrId};
use ratchet_jit::{
    ACTIVE_CRANELIFT_CODEGEN_VERSION, JitTier2LambdaLowering, compiled_body_target_triple,
    decode_tier2_lambda_lowering, encode_tier2_lambda_lowering,
};
use ratchet_oracle::cache::{LoweredIrFingerprint, lowered_ir_fingerprint};

const MAGIC: &[u8; 8] = b"AOSJIT2\0";
const SCHEMA_VERSION: u32 = 1;
const HEADER_LEN: usize = 68;
const MAX_RECORD_BYTES: u64 = 32 * 1024 * 1024;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub(super) struct CompiledBodyCache {
    root: PathBuf,
}

impl CompiledBodyCache {
    pub(super) fn new(persist_root: &Path) -> Self {
        Self {
            root: persist_root
                .join("compiled-bodies")
                .join(format!("v{SCHEMA_VERSION}"))
                .join(ACTIVE_CRANELIFT_CODEGEN_VERSION)
                .join(compiled_body_target_triple()),
        }
    }

    pub(super) fn load(
        &self,
        ir: &Ir,
        pattern: IrId,
        body: IrId,
        budget: i64,
    ) -> Option<JitTier2LambdaLowering> {
        let fingerprint = lowered_ir_fingerprint(ir).ok()?;
        let path = self.record_path(fingerprint, pattern, body, budget);
        match self.read_record(&path, fingerprint, pattern, body, budget) {
            Ok(lowering) => Some(lowering),
            Err(ReadRecordError::Missing) => None,
            Err(ReadRecordError::Invalid) => {
                let _ = fs::remove_file(path);
                None
            }
        }
    }

    pub(super) fn store(
        &self,
        ir: &Ir,
        pattern: IrId,
        body: IrId,
        budget: i64,
        lowering: &JitTier2LambdaLowering,
    ) {
        let Some(record) = self.encode_record(ir, pattern, body, budget, lowering) else {
            return;
        };
        let Ok(fingerprint) = lowered_ir_fingerprint(ir) else {
            return;
        };
        let path = self.record_path(fingerprint, pattern, body, budget);
        if path.is_file() || fs::create_dir_all(&self.root).is_err() {
            return;
        }
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temp = self
            .root
            .join(format!(".tmp-{}-{sequence}", std::process::id()));
        let wrote = write_new_file(&temp, &record).is_ok();
        if wrote && fs::rename(&temp, &path).is_ok() {
            return;
        }
        let _ = fs::remove_file(temp);
    }

    fn encode_record(
        &self,
        ir: &Ir,
        pattern: IrId,
        body: IrId,
        budget: i64,
        lowering: &JitTier2LambdaLowering,
    ) -> Option<Vec<u8>> {
        let fingerprint = lowered_ir_fingerprint(ir).ok()?;
        let payload = encode_tier2_lambda_lowering(lowering).ok()?;
        let payload_len = u64::try_from(payload.len()).ok()?;
        let mut record = Vec::with_capacity(HEADER_LEN.saturating_add(payload.len()));
        record.extend_from_slice(MAGIC);
        record.extend_from_slice(&SCHEMA_VERSION.to_le_bytes());
        record.extend_from_slice(&pattern.as_u32().to_le_bytes());
        record.extend_from_slice(&body.as_u32().to_le_bytes());
        record.extend_from_slice(&budget.to_le_bytes());
        record.extend_from_slice(&fingerprint.as_bytes());
        record.extend_from_slice(&payload_len.to_le_bytes());
        record.extend_from_slice(&payload);
        Some(record)
    }

    fn read_record(
        &self,
        path: &Path,
        fingerprint: LoweredIrFingerprint,
        pattern: IrId,
        body: IrId,
        budget: i64,
    ) -> Result<JitTier2LambdaLowering, ReadRecordError> {
        let metadata = fs::metadata(path).map_err(|error| {
            if error.kind() == ErrorKind::NotFound {
                ReadRecordError::Missing
            } else {
                ReadRecordError::Invalid
            }
        })?;
        if metadata.len() > MAX_RECORD_BYTES {
            return Err(ReadRecordError::Invalid);
        }
        let bytes = fs::read(path).map_err(|_| ReadRecordError::Invalid)?;
        let payload = validate_header(&bytes, fingerprint, pattern, body, budget)?;
        decode_tier2_lambda_lowering(payload, body).map_err(|_| ReadRecordError::Invalid)
    }

    fn record_path(
        &self,
        fingerprint: LoweredIrFingerprint,
        pattern: IrId,
        body: IrId,
        budget: i64,
    ) -> PathBuf {
        self.root.join(format!(
            "{}-p{}-b{}-d{budget}.clif.bin",
            fingerprint.to_hex(),
            pattern.as_u32(),
            body.as_u32()
        ))
    }
}

#[derive(Clone, Copy)]
enum ReadRecordError {
    Missing,
    Invalid,
}

fn validate_header<'a>(
    bytes: &'a [u8],
    fingerprint: LoweredIrFingerprint,
    pattern: IrId,
    body: IrId,
    budget: i64,
) -> Result<&'a [u8], ReadRecordError> {
    let header = bytes.get(..HEADER_LEN).ok_or(ReadRecordError::Invalid)?;
    if header.get(..8) != Some(MAGIC.as_slice())
        || read_u32(header, 8) != Some(SCHEMA_VERSION)
        || read_u32(header, 12) != Some(pattern.as_u32())
        || read_u32(header, 16) != Some(body.as_u32())
        || read_i64(header, 20) != Some(budget)
        || header.get(28..60) != Some(fingerprint.as_bytes().as_slice())
    {
        return Err(ReadRecordError::Invalid);
    }
    let payload_len = read_u64(header, 60).ok_or(ReadRecordError::Invalid)?;
    let payload = bytes.get(HEADER_LEN..).ok_or(ReadRecordError::Invalid)?;
    if u64::try_from(payload.len()).ok() != Some(payload_len) {
        return Err(ReadRecordError::Invalid);
    }
    Ok(payload)
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

fn read_i64(bytes: &[u8], offset: usize) -> Option<i64> {
    Some(i64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

fn write_new_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)
}
