//! Closed Storage-to-kernel-owner transport and physical/signature readbacks.
//!
//! This library cannot install, activate, or revoke a BPF map row. The C
//! kernel-export owner remains the sole map custodian. An opt-in root-only
//! listener pins two external public verifiers and returns only an unsigned
//! acknowledgment after checking and closing each version 3 three-FD handoff.
//! A closed acknowledgment can be joined to a separately signed PREPARED
//! claim under the same measured tuple and current clock. The caller must
//! still supply independent current C-owner map readback.
//! No Storage sender, private signer key, map stage, or descriptor release is
//! wired. A successful decode or readback is a nonauthorizing observation,
//! never a grant.

pub mod deployment;
pub mod handoff;
pub mod origin;
pub mod peer;
pub mod stage_ack;
pub mod three_fd;

/// Reports a malformed, stale, or unauthenticated private owner input.
#[derive(Debug, thiserror::Error)]
pub enum OwnerPeerError {
    /// The exact fixed-width protocol fields are noncanonical or inconsistent.
    #[error("kernel-export owner input is noncanonical")]
    Noncanonical,
    /// A signed lease or private handoff has passed its exclusive deadline.
    #[error("kernel-export owner input is no longer current")]
    NotCurrent,
    /// A signed input does not verify under the supplied protected verifier.
    #[error("kernel-export owner signature is invalid")]
    Signature,
    /// A kernel readback or protected process identity differs from the frame.
    #[error("kernel-export owner physical readback differs")]
    Physical,
    /// The packet or descriptor-subject carrier rejected the message.
    #[error("kernel-export owner transport rejected the record: {0}")]
    Transport(String),
}
