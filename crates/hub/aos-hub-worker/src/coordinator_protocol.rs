//! Typed request and response messages for Worker coordination operations.
//!
//! Each response carries its operation kind, so callers reject a missing or
//! mismatched response rather than supplying a permissive default.

use anyhow::Context;
use serde::{Deserialize, Serialize};

/// A coordinator operation sent from the Worker to its Durable Object.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub(crate) enum Command {
    /// Records one attempt against a fixed-window budget.
    Admit {
        class: String,
        key: String,
        window: i64,
        budget: i64,
    },
    /// Acquires or refreshes a holder's lease.
    AcquireLease {
        key: String,
        holder: String,
        ttl: i64,
        now: i64,
    },
    /// Releases a lease only when the named holder owns it.
    ReleaseLease { key: String, holder: String },
    /// Advances a monotonic floor when the proposed value is greater.
    AdvanceFloor { key: String, value: i64 },
}

/// The result of one coordinator operation.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub(crate) enum CmdReply {
    /// Reports a fixed-window admission decision.
    Admission { admitted: bool },
    /// Reports lease acquisition or the current conflicting holder.
    Lease {
        acquired: bool,
        conflict: Option<String>,
    },
    /// Confirms that lease release processing completed.
    Released,
    /// Reports whether a monotonic floor advanced.
    Floor { accepted: bool },
}

impl CmdReply {
    /// Extracts an admission response and rejects every other operation kind.
    pub(crate) fn into_admission(self) -> anyhow::Result<bool> {
        match self {
            CmdReply::Admission { admitted } => Ok(admitted),
            _ => Err(anyhow::anyhow!("unexpected coordinator admission reply")),
        }
    }

    /// Extracts a lease response and rejects every other operation kind.
    pub(crate) fn into_lease(self) -> anyhow::Result<Option<String>> {
        match self {
            CmdReply::Lease {
                acquired: true,
                conflict: None,
            } => Ok(None),
            CmdReply::Lease {
                acquired: false,
                conflict: Some(holder),
            } => Ok(Some(holder)),
            CmdReply::Lease { .. } => Err(anyhow::anyhow!("inconsistent coordinator lease reply")),
            _ => Err(anyhow::anyhow!("unexpected coordinator lease reply")),
        }
    }

    /// Confirms a release response and rejects every other operation kind.
    pub(crate) fn into_release(self) -> anyhow::Result<()> {
        match self {
            CmdReply::Released => Ok(()),
            _ => Err(anyhow::anyhow!("unexpected coordinator release reply")),
        }
    }

    /// Extracts a floor response and rejects every other operation kind.
    pub(crate) fn into_floor(self) -> anyhow::Result<bool> {
        match self {
            CmdReply::Floor { accepted } => Ok(accepted),
            _ => Err(anyhow::anyhow!("unexpected coordinator floor reply")),
        }
    }
}

/// Decodes a coordinator response while retaining useful protocol context.
pub(crate) fn decode_reply(bytes: &[u8]) -> anyhow::Result<CmdReply> {
    serde_json::from_slice(bytes).context("decode coordinator reply")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_and_mismatched_replies_are_rejected() {
        assert!(decode_reply(br#"{}"#).is_err());

        let floor = decode_reply(br#"{"result":"floor","accepted":true}"#)
            .expect("tagged floor reply should decode");
        assert!(floor.into_admission().is_err());
    }

    #[test]
    fn each_reply_requires_its_result_value() {
        assert!(decode_reply(br#"{"result":"admission"}"#).is_err());
        assert!(decode_reply(br#"{"result":"lease"}"#).is_err());
        assert!(decode_reply(br#"{"result":"floor"}"#).is_err());

        let lease = decode_reply(br#"{"result":"lease","acquired":true,"conflict":null}"#)
            .expect("complete lease reply should decode");
        assert_eq!(lease.into_lease().expect("lease result"), None);

        let inconsistent =
            decode_reply(br#"{"result":"lease","acquired":true,"conflict":"other-publisher"}"#)
                .expect("typed but inconsistent lease reply should decode");
        assert!(inconsistent.into_lease().is_err());
    }

    #[test]
    fn commands_and_remaining_reply_kinds_are_typed() {
        let command = serde_json::to_value(Command::AdvanceFloor {
            key: "channel:stable".into(),
            value: 42,
        })
        .expect("floor command should encode");
        assert_eq!(command["op"], "advance_floor");

        let released =
            decode_reply(br#"{"result":"released"}"#).expect("release reply should decode");
        released.into_release().expect("release result");

        let floor = decode_reply(br#"{"result":"floor","accepted":false}"#)
            .expect("floor reply should decode");
        assert!(!floor.into_floor().expect("floor result"));
    }
}
