//! Observes the selected receiver declaration in the complete immutable ELF.
//!
//! ```text
//! CRUCRCV1 | BE32(schema1,bytes40,setup5,purpose8,outer8,flags1)
//! BE32(source_activation,checkpoint_ingress)
//! ```
//!
//! The once-receive/refusal flag is transport support only. Source startup
//! checks its activation capability independently of checkpoint ingress. Zero
//! and unspecified positive activation editions refuse; the retained declaration
//! records a capability declaration, never execution authority.

use super::NativeConstructorReadError;

pub(super) const SECTION: &[u8] = b".qemu.crucible.preexec";
pub(super) const BYTES: usize = 40;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ReceiverDeclaration {
    source_activation: u32,
    checkpoint_ingress: u32,
}

/// Retains the receiver observation and digest of the same selected final ELF.
///
/// Only the actual artifact reader constructs this value. It records the
/// selected image's declaration; it issues no process purpose, Source admission
/// or allocation loan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeReceiverArtifact {
    declaration: Result<ReceiverDeclaration, &'static str>,
    qemu_sha256: [u8; 32],
}

/// Reports the actual receiver artifact's unsupported or absent implementation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum NativeReceiverError {
    #[error("selected native receiver declaration refused: {0}")]
    Declaration(&'static str),
    #[error("selected native receiver has no Source activation implementation")]
    SourceActivationUnavailable,
    #[error("selected native receiver Source activation edition {0} is unsupported")]
    UnsupportedSourceActivation(u32),
}

impl NativeReceiverArtifact {
    pub(super) fn from_observed(
        declaration: Result<ReceiverDeclaration, &'static str>,
        qemu_sha256: [u8; 32],
    ) -> Self {
        Self {
            declaration,
            qemu_sha256,
        }
    }

    /// Compares the retained declaration and complete immutable QEMU digest.
    pub(crate) fn same_artifact(&self, other: &Self) -> bool {
        self.qemu_sha256 == other.qemu_sha256 && self.declaration == other.declaration
    }

    /// Requires an implemented Source activation edition for initial startup.
    ///
    /// Checkpoint ingress remains independently observed in the bound artifact;
    /// ordinary Source startup does not exercise that capability.
    ///
    /// # Errors
    /// Refuses malformed/missing declarations, the current refusal-only image,
    /// and unknown editions. No nonzero edition has yet been specified by the
    /// matching native ABI; observing one cannot manufacture its implementation.
    pub(crate) fn check_source_activation(&self) -> Result<(), NativeReceiverError> {
        let declaration = self.declaration.map_err(NativeReceiverError::Declaration)?;
        match declaration.source_activation {
            0 => Err(NativeReceiverError::SourceActivationUnavailable),
            edition => Err(NativeReceiverError::UnsupportedSourceActivation(edition)),
        }
    }
}

pub(super) fn decode(
    bytes: &[u8; BYTES],
) -> Result<ReceiverDeclaration, NativeConstructorReadError> {
    if bytes[..8] != *b"CRUCRCV1" {
        return Err(NativeConstructorReadError::Invalid(
            "receiver declaration magic",
        ));
    }
    for (index, expected) in [1_u32, 40, 5, 8, 8, 1].into_iter().enumerate() {
        if word(bytes, 8 + 4 * index) != expected {
            return Err(NativeConstructorReadError::Invalid(
                "receiver declaration edition or flags",
            ));
        }
    }
    Ok(ReceiverDeclaration {
        source_activation: word(bytes, 32),
        checkpoint_ingress: word(bytes, 36),
    })
}

fn word(bytes: &[u8; BYTES], offset: usize) -> u32 {
    let mut value = [0; 4];
    value.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_be_bytes(value)
}
