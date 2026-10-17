//! Pre-effect storage for exact native commands, raw responses and uncertainty.

use crucible_node_contract::canonical;
use serde::Serialize;

use crate::ProviderError;

use super::protocol::MAX_FRAME_BYTES;

/// Bounds complete original command history independently of window count.
pub const MAX_NATIVE_COMMANDS: usize = 512;

/// Bounds retained request and response wire bytes for one native incarnation.
pub const MAX_NATIVE_JOURNAL_BYTES: usize = 8 * 1024 * 1024;

/// Reports the knowledge retained for one original subordinate native command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeCommandKnowledge {
    /// The command may have reached the native child; no response authorizes progress.
    Unknown,
    /// The exact received response was checked against the original native scope.
    Accepted,
}

/// Retains a native request and every observed response byte without normalization.
///
/// An incomplete or rejected response remains attached to its original command.
/// These bytes establish no installed-source or common operation authority.
#[derive(Debug)]
pub struct NativeCommandRecord {
    pub(super) request: Vec<u8>,
    pub(super) response_wire: Vec<u8>,
    pub(super) knowledge: NativeCommandKnowledge,
}

impl NativeCommandRecord {
    /// Returns the exact original JSON body sent to the child.
    pub fn request_bytes(&self) -> &[u8] {
        &self.request
    }

    /// Returns the observed length prefix and response bytes, including truncation.
    pub fn response_wire_bytes(&self) -> &[u8] {
        &self.response_wire
    }

    /// Returns original native command knowledge without granting retry authority.
    pub fn knowledge(&self) -> NativeCommandKnowledge {
        self.knowledge
    }
}

pub(super) struct Journal {
    pub(super) commands: Vec<NativeCommandRecord>,
    bytes: usize,
}

impl Journal {
    pub(super) fn new() -> Result<Self, ProviderError> {
        let mut commands = Vec::new();
        commands
            .try_reserve_exact(MAX_NATIVE_COMMANDS)
            .map_err(|_| ProviderError::ResourceExhausted("native lineage command reservation"))?;
        Ok(Self { commands, bytes: 0 })
    }

    pub(super) fn reserve(&mut self, request: &impl Serialize) -> Result<usize, ProviderError> {
        if self.commands.len() >= MAX_NATIVE_COMMANDS {
            return Err(ProviderError::ResourceExhausted(
                "native lineage command count",
            ));
        }
        let request = canonical::canonical_json(
            &serde_json::to_value(request)
                .map_err(|_| ProviderError::Frame("native lineage request encoding failed"))?,
        )?;
        if request.is_empty() || request.len() > MAX_FRAME_BYTES {
            return Err(ProviderError::ResourceExhausted(
                "native lineage request frame",
            ));
        }
        let reserved = self
            .bytes
            .checked_add(request.len())
            .and_then(|bytes| bytes.checked_add(MAX_FRAME_BYTES + 4))
            .ok_or(ProviderError::ResourceExhausted(
                "native lineage journal arithmetic",
            ))?;
        if reserved > MAX_NATIVE_JOURNAL_BYTES {
            return Err(ProviderError::ResourceExhausted(
                "native lineage journal bytes",
            ));
        }
        let mut response_wire = Vec::new();
        response_wire
            .try_reserve_exact(MAX_FRAME_BYTES + 4)
            .map_err(|_| ProviderError::ResourceExhausted("native lineage response reservation"))?;
        let index = self.commands.len();
        self.bytes += request.len();
        self.commands.push(NativeCommandRecord {
            request,
            response_wire,
            knowledge: NativeCommandKnowledge::Unknown,
        });
        Ok(index)
    }

    pub(super) fn charge_response(&mut self, index: usize) {
        // Each response has its full finite allowance reserved before any IO.
        self.bytes += self.commands[index].response_wire.len();
    }

    pub(super) fn accept(&mut self, index: usize) {
        self.commands[index].knowledge = NativeCommandKnowledge::Accepted;
    }
}
