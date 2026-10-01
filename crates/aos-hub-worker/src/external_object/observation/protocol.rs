//! Closed bounded read-slot turns; provider metadata never grants a new permit.
//!
//! ```text
//! /observation-turn -> Begin {intent,lease} | Terminal {receipt}
//! external-object/observation-receipt/v1/<operation digest> -> receipt JSON
//! ```

use anyhow::{ensure, Result};
use aos_hub_core::storage_authority::{
    external_object::observation::{ExternalObservation, ObservationExpectation},
    lease::EpochLeaseFloor,
    StorageGuardStamp,
};
use serde::{Deserialize, Serialize};

use super::super::protocol::{digest, digest_string, Effect, Intent as ObjectIntent};

pub(in crate::external_object) const DOMAIN: &str = "aos.external-observation-guard.v1";
pub(in crate::external_object) const MAX_MESSAGE: usize = 64 * 1024;
pub(in crate::external_object) const MAX_RECEIPT: usize = 8 * 1024;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::external_object) struct Intent {
    pub object: ObjectIntent,
    pub expectation: ObservationExpectation,
}

impl Intent {
    pub(in crate::external_object) fn validate(&self) -> Result<()> {
        self.object.validate()?;
        ensure!(
            matches!(self.object.effect, Effect::Head),
            "read slot requires HEAD"
        );
        if let ObservationExpectation::KnownStamp { stamp } = &self.expectation {
            ensure!(
                stamp.physical_authority_id == self.object.scope.physical_authority_id,
                "expected observation authority differs"
            );
        }
        Ok(())
    }

    pub(in crate::external_object) fn fingerprint(&self) -> Result<String> {
        self.validate()?;
        digest(self)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::external_object) struct Pending {
    pub intent: Intent,
    pub dispatch_nonce: String,
    pub stamp: StorageGuardStamp,
}

impl Pending {
    pub(in crate::external_object) fn scope(
        &self,
    ) -> &aos_hub_core::storage_authority::control::StorageAuthorityObjectScope {
        &self.intent.object.scope
    }

    pub(in crate::external_object) fn validate(&self) -> Result<()> {
        self.intent.validate()?;
        ensure!(
            digest_string(&self.dispatch_nonce)
                && self.stamp.physical_authority_id
                    == self.intent.object.scope.physical_authority_id,
            "invalid read-slot identity"
        );
        if let ObservationExpectation::KnownStamp { stamp } = &self.intent.expectation {
            ensure!(stamp == &self.stamp, "locked observation stamp differs");
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::external_object) struct Receipt {
    pub turn: Pending,
    pub observation: ExternalObservation,
}

impl Receipt {
    pub(in crate::external_object) fn validate(&self) -> Result<()> {
        self.turn.validate()?;
        self.observation.validate()?;
        ensure!(
            self.observation.operation_id == self.turn.intent.object.operation_id
                && self.observation.intent_digest == self.turn.intent.fingerprint()?
                && self.observation.turn_digest == digest(&self.turn)?
                && self.observation.guard_stamp == self.turn.stamp,
            "observation terminal differs from turn"
        );
        ensure!(
            serde_json::to_vec(self)?.len() <= MAX_RECEIPT,
            "oversized observation receipt"
        );
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::external_object) struct Request {
    pub domain: String,
    pub scope: aos_hub_core::storage_authority::control::StorageAuthorityObjectScope,
    pub operation: Operation,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(in crate::external_object) enum Operation {
    Begin { intent: Intent, lease: String },
    Terminal { receipt: Receipt },
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(in crate::external_object) enum Reply {
    Dispatch {
        turn: Pending,
        floor: EpochLeaseFloor,
    },
    Historical {
        receipt: Receipt,
    },
    TerminalAcknowledged {
        receipt: Receipt,
    },
}
