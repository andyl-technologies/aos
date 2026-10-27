//! Retains the initial Controller's optional Source pair before normal handoff.
//!
//! The genuine startup already paid the fixed four-input native recipe. This
//! owner keeps partial native reads, both finite bookends and signature errors
//! resident. It does not authorize Source mutation or fund later input rechecks.

use aos_sandbox_model::ProjectId;

use super::{
    ControllerSourceGenesisInputErrorV1, ProvisionedControllerSourceGenesisInputV1,
    validate_pair,
};
use crate::public_api_session::{
    ControllerInitialCredentialCustodyV1, ControllerStartupCredentialGeometryV1,
};

/// Keeps the reached initial four-input Source delivery and semantic results.
///
/// Empty construction performs no IO and supplies no payer, original or grant.
/// Only the actual installed startup calls the fixed capture after its same
/// Controller receiving owner accepted the complete startup shape.
#[doc(hidden)]
pub struct ControllerSourceGenesisInputStartupV1 {
    credentials: ControllerInitialCredentialCustodyV1,
    semantic: Option<Result<Option<ProjectId>, ControllerSourceGenesisInputErrorV1>>,
    semantic_post: Option<Result<(), ControllerSourceGenesisInputErrorV1>>,
    entered: bool,
    taken: bool,
    closed: Option<ControllerSourceGenesisInputErrorV1>,
    completed: Option<Option<ProvisionedControllerSourceGenesisInputV1>>,
}

impl ControllerSourceGenesisInputStartupV1 {
    /// Creates empty fixed destinations without reading credentials.
    #[must_use]
    pub fn new() -> Self {
        Self {
            credentials: ControllerInitialCredentialCustodyV1::source_genesis(),
            semantic: None,
            semantic_post: None,
            entered: false,
            taken: false,
            closed: None,
            completed: None,
        }
    }

    /// Returns passive dominant raw/native geometry before the first read.
    ///
    /// The enclosing parent's actual inline size is accounted for separately.
    #[must_use]
    pub fn credential_geometry() -> Option<ControllerStartupCredentialGeometryV1> {
        ControllerInitialCredentialCustodyV1::source_genesis_geometry()
    }

    /// Captures and validates the existing optional pair once.
    ///
    /// Both packets absent leaves startup unchanged and opens no issuer file.
    /// A semantic failure still runs the independently available final native
    /// post. Every returned native error and partial raw owner stays here.
    ///
    /// # Errors
    /// Returns a marker while [`Self::failure`] borrows the earlier real cause.
    pub fn capture_once(&mut self) -> Result<(), ()> {
        if self.entered || self.taken || self.closed.is_some() {
            self.closed.get_or_insert(ControllerSourceGenesisInputErrorV1::Credential);
            return Err(());
        }
        self.entered = true;
        if self.credentials.capture_once().is_ok() {
            self.semantic = Some(match self.credentials.is_absent() {
                Some(true) => Ok(None),
                Some(false) => self.credentials.bytes()
                    .ok_or(ControllerSourceGenesisInputErrorV1::Credential)
                    .and_then(|bytes| validate_pair(bytes[0], bytes[1], bytes[2], bytes[3]))
                    .map(Some),
                None => Err(ControllerSourceGenesisInputErrorV1::Credential),
            });
        }
        let posted = self.credentials.recheck_once();
        if posted.is_ok() && matches!(self.semantic, Some(Ok(_))) {
            // Preserve the ordinary input's second pure pair validation after
            // the complete native recheck. No current publisher grant follows.
            self.semantic_post = Some(self.validate_semantic_post());
        }
        if self.failure().is_none() && matches!(self.semantic_post, Some(Ok(()))) {
            Ok(())
        } else {
            Err(())
        }
    }

    fn validate_semantic_post(&self) -> Result<(), ControllerSourceGenesisInputErrorV1> {
        match self.semantic.as_ref().and_then(|result| result.as_ref().ok()) {
            Some(None) => Ok(()),
            Some(Some(project)) => {
                let bytes = self.credentials.bytes()
                    .ok_or(ControllerSourceGenesisInputErrorV1::Credential)?;
                if validate_pair(bytes[0], bytes[1], bytes[2], bytes[3])? != *project {
                    return Err(ControllerSourceGenesisInputErrorV1::Pair);
                }
                Ok(())
            }
            None => Err(ControllerSourceGenesisInputErrorV1::Credential),
        }
    }

    /// Moves the existing normal input after complete native and semantic posts.
    ///
    /// This is a once-only infallible field handoff after all occupancy checks.
    /// The parent parks the returned value before its own startup continuation.
    /// Later normal input rechecks retain their independent operation contracts.
    pub fn take_success(&mut self) -> Option<Option<ProvisionedControllerSourceGenesisInputV1>> {
        if !self.entered || self.taken || self.failure().is_some()
            || !matches!(self.semantic_post, Some(Ok(())))
        {
            return None;
        }
        let project = self.semantic.as_ref()?.as_ref().ok()?.as_ref().copied();
        if self.credentials.is_absent()? != project.is_none() {
            return None;
        }
        let originals = self.credentials.take_source_genesis()?;
        self.taken = true;
        self.completed = match (originals, project) {
            (None, None) => Some(None),
            (Some([seed, authorization, seed_issuer, authorization_issuer]), Some(project)) => {
                Some(Some(ProvisionedControllerSourceGenesisInputV1 {
                    packets: [seed, authorization],
                    issuers: [seed_issuer, authorization_issuer],
                    project,
                }))
            }
            _ => None,
        };
        if self.completed.is_none() || self.credentials.settle_successful_native_once().is_err() {
            self.closed.get_or_insert(ControllerSourceGenesisInputErrorV1::Credential);
            return None;
        }
        self.completed.take()
    }

    /// Borrows the actual native or semantic cause before later post debt.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.credentials.capture_failure()
            .map(|cause| cause as &(dyn std::error::Error + 'static))
            .or_else(|| self.semantic.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.credentials.post_failure()
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.semantic_post.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.closed.as_ref()
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
    }
}

impl Default for ControllerSourceGenesisInputStartupV1 {
    fn default() -> Self {
        Self::new()
    }
}
