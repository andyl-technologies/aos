//! Recorded decision-stream draws and their `keyed-blake3-v2` addresses.
//!
//! A [`RngDecision`] names the stream a value came from and the exact address
//! the keyed derivation consumed to produce it ([DET-25], [DET-26]):
//!
//! ```text
//! ordinal     the nth draw of a single-owner, counter-addressed stream
//! link frame  role index i of the frame (direction, producer sequence)
//!             on a shared link stream ([SCHED-50])
//! ```

use std::fmt;

use super::RngStreamId;

/// A decision-stream draw payload.
///
/// A draw names its stream and its exact `keyed-blake3-v2` address, so replay
/// checks which draw was taken as well as the value it produced ([DET-26]).
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct RngDecision {
    /// The stream that produced the value.
    pub stream: RngStreamId,
    /// The position of the draw within its stream.
    pub address: RngDrawAddress,
    /// The drawn value.
    pub value: u64,
}

impl RngDecision {
    /// Builds the draw at `ordinal` on a single-owner stream.
    #[must_use]
    pub fn ordinal(stream: RngStreamId, ordinal: u64, value: u64) -> Self {
        Self {
            stream,
            address: RngDrawAddress::Ordinal { ordinal },
            value,
        }
    }
}

/// The address of one draw on a decision stream ([DET-25], [SCHED-50]).
///
/// The address is exactly the input the draw's keyed hash consumed besides the
/// stream key, so two draws with equal streams and addresses always carry equal
/// values.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum RngDrawAddress {
    /// The draw at `ordinal` on a stream one entity orders by its own execution.
    Ordinal {
        /// The zero-based draw position on the stream.
        ordinal: u64,
    },
    /// One role-indexed draw of a frame on a shared link stream.
    LinkFrame {
        /// The directed edge whose producer emitted the frame.
        direction: crate::NetworkLinkDirection,
        /// The producer's own sequence number for the frame.
        producer_sequence: u64,
        /// The draw's index in the frame's fixed draw order.
        role: u64,
    },
}

impl RngDrawAddress {
    /// Returns the address as one canonical `rng_address=` material line.
    ///
    /// ```text
    /// rng_address=ordinal:<ordinal>
    /// rng_address=link-frame:<a-to-b|b-to-a>:<producer-sequence>:<role>
    /// ```
    #[must_use]
    pub fn canonical_material(self) -> String {
        match self {
            Self::Ordinal { ordinal } => format!("rng_address=ordinal:{ordinal}"),
            Self::LinkFrame {
                direction,
                producer_sequence,
                role,
            } => format!(
                "rng_address=link-frame:{}:{producer_sequence}:{role}",
                direction.label()
            ),
        }
    }
}

impl fmt::Display for RngDrawAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ordinal { ordinal } => write!(f, "ordinal {ordinal}"),
            Self::LinkFrame {
                direction,
                producer_sequence,
                role,
            } => write!(
                f,
                "link frame {} sequence {producer_sequence} role {role}",
                direction.label()
            ),
        }
    }
}
