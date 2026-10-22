//! Transfers the actual pending ARM owner to the current QMP request boundary.
//!
//! ```text
//! crucible-checkpoint-begin { arm-request-digest: lower_hex[64],
//!                            request-generation: u64 }
//! return { arm-request-digest, request-generation, connection-epoch: u64 }
//! ```
//!
//! The selectors borrow a previously retained native owner on the authenticated
//! Monitor connection. The reply acknowledges request custody before Host stop,
//! shared-memory pause, descriptor import, topology, or pre-save can begin.

use super::*;
use crate::ram_control::CheckpointArmReceipt;

pub(super) const COMMAND: &str = "crucible-checkpoint-begin";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct CheckpointRequestReceipt {
    arm: CheckpointArmReceipt,
    connection_epoch: u64,
}

fn digest_hex(digest: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 15)]));
    }
    output
}

pub(super) fn request(receipt: CheckpointArmReceipt) -> Value {
    json!({
        "execute": COMMAND,
        "arguments": {
            "arm-request-digest": digest_hex(receipt.request_digest()),
            "request-generation": receipt.request_generation(),
        },
    })
}

fn parse(value: Value, arm: CheckpointArmReceipt) -> Result<CheckpointRequestReceipt, QmpError> {
    let malformed = || QmpError::MalformedTypedResponse {
        command: QmpCommandKind::CheckpointBegin,
        response: value.to_string(),
    };
    let object = value
        .as_object()
        .filter(|object| object.len() == 3)
        .ok_or_else(malformed)?;
    if object.get("arm-request-digest").and_then(Value::as_str)
        != Some(digest_hex(arm.request_digest()).as_str())
        || object.get("request-generation").and_then(Value::as_u64)
            != Some(arm.request_generation())
    {
        return Err(malformed());
    }
    let connection_epoch = object
        .get("connection-epoch")
        .and_then(Value::as_u64)
        .filter(|epoch| *epoch != 0)
        .ok_or_else(malformed)?;
    Ok(CheckpointRequestReceipt {
        arm,
        connection_epoch,
    })
}

impl<S: QmpTimeoutStream> QmpClient<S> {
    /// Consumes the same ARM pending owner before any checkpoint semantic effect.
    ///
    /// The actual client retains the entered original and matched connection
    /// receipt. A repeated local preparation rechecks that same original and
    /// returns the saved receipt instead of sending another begin command.
    ///
    /// # Errors
    /// Refuses a missing original, mismatched request, unusable transport, or an
    /// invalid native connection receipt. Uncertainty poisons the QMP cursor.
    pub(crate) fn begin_checkpoint_receiving(
        &mut self,
        arm: CheckpointArmReceipt,
    ) -> Result<(), QmpError> {
        self.ensure_usable()?;
        let original = self
            .checkpoint_loan
            .as_ref()
            .ok_or(QmpError::InvalidBound { operation: COMMAND })?;
        original
            .check()
            .map_err(|source| QmpError::CheckpointOriginal {
                operation: COMMAND,
                source,
            })?;
        if let Some(existing) = self.checkpoint_request {
            if existing.arm != arm {
                return Err(QmpError::InvalidBound { operation: COMMAND });
            }
            return Ok(());
        }
        let work = self
            .send_command_return(QmpCommand::CheckpointBegin { receipt: arm })
            .and_then(|response| parse(response.value, arm));
        match work {
            Ok(receipt) => {
                self.checkpoint_request = Some(receipt);
                Ok(())
            }
            Err(first) => {
                self.poison_checkpoint_exchange();
                Err(first)
            }
        }
    }
}

#[cfg(test)]
mod tests;
