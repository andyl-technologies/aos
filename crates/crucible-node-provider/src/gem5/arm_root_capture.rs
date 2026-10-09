//! Native stopped image custody for the source-installed ARM root model.
//!
//! Capturing closes the operational controller before DMTCP copies the complete
//! process. The original peer must reconnect at the unchanged modeled cut.
//!
//! Successful original prefixes use the closed native run-completion envelope.
//! This schematic excerpt abbreviates the grant and boundary records:
//!
//! ```text
//! {"kind":"completed","operation":"original/prefix","original":{...},
//!  "before":{...},"after":{...},"processed_events":"1","reason":"output",
//!  "output":[91],"publications":[...],"exit_cause":null,"exit_code":null}
//! ```

use std::{fs, path::Path};

use crucible_node_contract::Id;
use serde_json::json;

use super::arm_root_process::{connect, read, selection};
use super::images::{Gem5CapturedModelImage, validate_private_directory};
use super::model::Gem5ArmNativeReady;
use super::{ArmRootLaunch, ArmRootNativeProcess, Gem5Boundary};
use crate::ProviderError;

/// Retains original model-aware prefix bytes and typed serial birth custody.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArmRootPrefix {
    /// Identifies only a native completed prefix.
    pub kind: String,
    /// Names the immutable original subordinate Poll.
    pub operation: Id,
    /// Retains the original full-range native permission.
    pub original: super::Gem5Run,
    /// Retains the unchanged starting native and logical cut.
    pub before: Gem5Boundary,
    /// Retains actual native progress and queue custody.
    pub after: Gem5Boundary,
    /// Counts actually serviced callbacks without wrapping.
    pub processed_events: crucible_node_contract::U64,
    /// Classifies output, bounded progress, horizon, idle or guest exit.
    pub reason: String,
    /// Retains original terminal bytes until caller publication custody.
    pub output: Vec<u8>,
    /// Retains typed serial callback births without synthetic stdout fields.
    pub publications: Vec<super::model::Gem5SerialPublication>,
    #[serde(deserialize_with = "super::protocol::required_nullable")]
    /// Retains the actual native exit cause or required null.
    pub exit_cause: Option<String>,
    #[serde(deserialize_with = "super::protocol::required_nullable")]
    /// Retains the actual native exit code or required null.
    pub exit_code: Option<i32>,
}

/// Retains completed or refused original subordinate-Poll custody separately.
#[derive(Clone, Debug)]
pub enum ArmRootRunOutcome {
    /// Retains successful progress and its unchanged original frame.
    Completed {
        /// Retains typed native progress and original serial births.
        prefix: ArmRootPrefix,
        /// Retains original wire bytes before any ACK.
        bytes: Vec<u8>,
    },
    /// Retains a failed Poll independently from output/grant completion.
    Refused {
        /// Retains the native unchanged-cut diagnostic-credit refusal.
        refusal: super::refusal::Gem5RunRefusal,
        /// Retains original refusal wire bytes and its tombstone.
        bytes: Vec<u8>,
    },
}

impl ArmRootRunOutcome {
    /// Borrows the authentic original native wire packet without reinterpretation.
    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::Completed { bytes, .. } | Self::Refused { bytes, .. } => bytes,
        }
    }

    /// Borrows a successful prefix; refused Polls cannot acquire completion custody.
    pub fn completion(&self) -> Option<&ArmRootPrefix> {
        match self {
            Self::Completed { prefix, .. } => Some(prefix),
            Self::Refused { .. } => None,
        }
    }

    pub(crate) fn original(&self) -> &super::Gem5Run {
        match self {
            Self::Completed { prefix, .. } => &prefix.original,
            Self::Refused { refusal, .. } => &refusal.original,
        }
    }
}

/// Owns sealed native bytes with serial and failed-Poll historical custody.
#[derive(Clone, Debug)]
pub struct ArmRootCapturedImage {
    pub(crate) native: Gem5CapturedModelImage<ArmRootLaunch, ArmRootRunOutcome>,
    pub(crate) history: super::ArmRootControlHistory,
}

impl ArmRootCapturedImage {
    /// Borrows exact original control and preparation bodies from the captured seal.
    pub fn control_history(&self) -> &super::ArmRootControlHistory {
        &self.history
    }
}

impl std::ops::Deref for ArmRootCapturedImage {
    type Target = Gem5CapturedModelImage<ArmRootLaunch, ArmRootRunOutcome>;

    fn deref(&self) -> &Self::Target {
        &self.native
    }
}

impl ArmRootNativeProcess {
    /// Captures nondraining native state and retains every original prefix.
    ///
    /// # Errors
    /// Refuses unresolved control effects, a foreign cut, changed source assets,
    /// occupied preservation, unavailable native images or failed reconnection.
    /// Any failure after the request preserves uncertain capture custody.
    pub fn capture(
        &mut self,
        capture: Id,
        preserved: &Path,
    ) -> Result<ArmRootCapturedImage, ProviderError> {
        if self.unresolved.is_some() || self.unresolved_capture.is_some() {
            return Err(ProviderError::Conflict(
                "ARM capture has unresolved original effects",
            ));
        }
        validate_private_directory(preserved)?;
        if fs::read_dir(preserved)?.next().is_some() {
            return Err(ProviderError::Conflict("ARM preservation root occupied"));
        }
        let custody = self
            .custody
            .as_mut()
            .ok_or(ProviderError::Frame("ARM capture custody absent"))?;
        // Both the capture response and reconnect Ready consume retained credit.
        // Reserve the complete pair before any controller or checkpoint effect.
        super::arm_root_process::reserve_control_frames(custody, 2)?;
        custody.history.reserve(3)?;
        self.unresolved_capture = Some(capture.clone());
        let response = self.exchange(json!({"kind":"capture", "capture":capture}))?;
        if response != json!({"kind":"capture_ready","capture":capture,"boundary":self.boundary}) {
            return Err(ProviderError::Correlation("ARM capture frontier changed"));
        }
        let restored = matches!(
            self.prepared
                .as_ref()
                .ok_or(ProviderError::Frame("ARM validated preparation absent"))?
                .origin,
            super::arm_root_process::ArmRootOrigin::Restored { .. }
        );
        let custody = self
            .custody
            .as_mut()
            .ok_or(ProviderError::Frame("ARM capture custody absent"))?;
        custody.stream.take();
        custody.stream = Some(connect(custody, restored)?);
        let frame = read(custody)?;
        custody
            .history
            .push(super::ArmRootControlKind::Ready, frame.1.clone())?;
        custody.control_frames.push(frame.1);
        let ready: Gem5ArmNativeReady = serde_json::from_value(frame.0)
            .map_err(|_| ProviderError::Frame("ARM captured Ready shape"))?;
        ready.validate_selection(
            &selection(&custody.launch)?,
            &custody.launch.owner,
            &custody.launch.incarnation,
            custody.launch.generation,
        )?;
        if ready.continuation != "captured" || ready.boundary != self.boundary {
            return Err(ProviderError::Correlation(
                "ARM captured original lineage changed",
            ));
        }
        custody.history.validate()?;
        let native = Gem5CapturedModelImage::collect(
            capture,
            custody.launch.clone(),
            self.boundary.clone(),
            preserved,
            self.completed.clone(),
            self.pending.clone(),
            self.last_acknowledged.clone(),
        )?;
        self.unresolved_capture = None;
        Ok(ArmRootCapturedImage {
            native,
            history: custody.history.clone(),
        })
    }
}
