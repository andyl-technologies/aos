//! Closed operator requests for the installed isolated Clock and gem5 world.
//!
//! ```text
//! NativeWorldRequestV1 = capture(execution,isa,point)
//!                      | restore(execution,isa,source,complete_original)
//!                      | status(execution)
//! ```
//!
//! The source-installed profile fixes the guest, grant, poll credits and native
//! codec. Requests select a supported ISA and preservation point; they carry no
//! executable paths, certificates, native handles or replacement operation IDs.

use crucible::node_contract::{SavedRuntimeActivation, SavedRuntimeOperation};
use crucible_node_contract::{CaptureManifest, ContentRef, Validate};
use serde::{Deserialize, Serialize};

use super::super::{NodeObservedError, refused};

/// Selects a source-installed known-checksum guest in the closed native profile.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InstalledGem5Isa {
    /// Selects the installed x86-64 freestanding guest and its original poll policy.
    X86_64,
    /// Selects the installed AArch64 freestanding guest and its original poll policy.
    Aarch64,
}

impl InstalledGem5Isa {
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::Aarch64 => "aarch64",
        }
    }
}

/// Selects an original execution boundary before coordinator publication.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeCapturePoint {
    /// Captures after the first authentic native prefix while the grant is pending.
    Pending,
    /// Captures completed original output before scheduling commit and native ACK.
    HeldPublication,
}

/// Carries one bounded operation on the source-installed closed native world.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum NativeWorldRequest {
    /// Creates an actual inactive realization and captures its original execution.
    Capture {
        /// Names an independent nonzero 16-byte execution nonce in lowercase hex.
        execution: String,
        /// Selects an independently installed guest and immutable native poll policy.
        isa: InstalledGem5Isa,
        /// Selects the original pending or held-publication custody boundary.
        point: NativeCapturePoint,
    },
    /// Restores a signed original archive under two newly qualified owner routes.
    Restore {
        /// Names an independent nonzero restoration nonce in lowercase hex.
        execution: String,
        /// Requires the original installed guest and unchanged poll policy.
        isa: InstalledGem5Isa,
        /// Names a signed complete native archive in the private installed realm.
        source: ContentRef,
        /// Completes and acknowledges the retained original operation exactly once.
        complete_original: bool,
    },
    /// Reads an original durable operation without dispatch or native allocation.
    Status {
        /// Names the original operation nonce.
        execution: String,
    },
}

impl NativeWorldRequest {
    /// Returns the original durable operation nonce.
    #[must_use]
    pub fn execution(&self) -> &str {
        match self {
            Self::Capture { execution, .. }
            | Self::Restore { execution, .. }
            | Self::Status { execution } => execution,
        }
    }

    /// Checks the closed portable request before persistent reservation.
    ///
    /// # Errors
    /// Refuses invalid nonces or malformed source references. Installed native
    /// qualification and signed source validation remain actor responsibilities.
    pub fn validate(&self) -> Result<(), NodeObservedError> {
        validate_execution(self.execution())?;
        if let Self::Restore { source, .. } = self {
            source.validate()?;
        }
        Ok(())
    }
}

/// Retains the original request identity and monotonic operation lifecycle.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWorldRecord {
    /// Names the exact durable operation format.
    pub format: String,
    /// Selects its supported version.
    pub version: u32,
    /// Preserves the independent original execution nonce.
    pub execution: String,
    /// Retains the canonical CAS identity of the complete original request.
    pub request: String,
    /// Retains original reservation, completed proof or uncertain effect custody.
    pub state: NativeWorldOutcome,
}

impl NativeWorldRecord {
    /// Parses an original bounded record without qualifying its archive for restore.
    ///
    /// # Errors
    /// Refuses malformed closed JSON, unsupported editions, invalid original
    /// nonces and inconsistent manifest identities. The installed actor must
    /// separately authenticate the signed archive and actual native owner.
    pub fn from_json(bytes: &[u8]) -> Result<Self, NodeObservedError> {
        let value = crucible_node_contract::canonical::parse_json(bytes, 16 * 1024 * 1024)?;
        let record: Self = serde_json::from_value(value)?;
        super::ledger::validate_record(&record)?;
        Ok(record)
    }
}

/// Distinguishes completed preservation from uncertain native execution effects.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum NativeWorldOutcome {
    /// Retains the original durable reservation; retries cannot redispatch it.
    Reserved {},
    /// Retains the signed source and authentic fresh-world operation inventory.
    Completed {
        /// Identifies the authenticated archive captured or restored.
        artifact: ContentRef,
        /// Preserves the complete original signed source manifest.
        manifest: Box<CaptureManifest>,
        /// Records the actual committed owner routes of this execution.
        activation: Box<SavedRuntimeActivation>,
        /// Preserves the original operation, grant, result and native ACK state.
        original: Box<SavedRuntimeOperation>,
        /// Roots exact newly completed receipt and output bodies before native ACK.
        completion_evidence: Option<String>,
    },
    /// Retains an uncertain original operation and its supervised cleanup obligations.
    Unknown {
        /// Gives a bounded fixed class without private paths or native peer bytes.
        reason: String,
    },
}

pub(super) fn validate_execution(execution: &str) -> Result<(), NodeObservedError> {
    if execution.len() != 32
        || !execution
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || execution.bytes().all(|byte| byte == b'0')
    {
        return Err(refused(
            "native-world execution must be nonzero lowercase nonce32hex",
        ));
    }
    Ok(())
}
