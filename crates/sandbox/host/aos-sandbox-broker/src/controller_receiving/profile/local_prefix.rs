//! Shares the exact split local prefix/fragment schedule with outer receivers.
//!
//! The enclosing genuine owner prepays and retains this passive native sink.
//! Neither step opens a C scope, authorizes a role or settles an upper purpose.

use super::local_recipe::LocalCurrentness;
use super::local_currentness::LocalCurrentnessOriginalsV1;
use super::{ControllerSelfProfileOriginalV1, ControllerProfileErrorV1};

/// Retains the actual local prefix and its later immutable-fragment comparison.
#[must_use = "retain actual native prefix and fragment failures with the enclosing owner"]
pub struct ControllerProfileLocalPrefixOriginalV1 {
    local: LocalCurrentness,
    originals: LocalCurrentnessOriginalsV1,
    prefix: Option<Result<(), ControllerProfileErrorV1>>,
    fragment: Option<Result<(), ControllerProfileErrorV1>>,
    prefix_entered: bool,
    fragment_entered: bool,
}

impl ControllerProfileLocalPrefixOriginalV1 {
    /// Creates inert receiving destinations without IO or authority.
    #[must_use]
    pub fn new() -> Self {
        Self {
            local: LocalCurrentness::new(),
            originals: LocalCurrentnessOriginalsV1::new(),
            prefix: None,
            fragment: None,
            prefix_entered: false,
            fragment_entered: false,
        }
    }

    /// Captures the same local prefix before the actual outer property flight.
    ///
    /// # Errors
    /// Retains native or semantic refusal; repeated entry performs no work.
    pub fn capture_prefix_once_v1(&mut self, profile: &ControllerSelfProfileOriginalV1)
        -> Result<(), ControllerProfileErrorV1>
    {
        if self.prefix_entered { return Err(ControllerProfileErrorV1::Service); }
        self.prefix_entered = true;
        self.prefix = Some(self.local.capture_prefix_observed(profile, &mut self.originals));
        if matches!(self.prefix, Some(Ok(()))) { Ok(()) }
        else { Err(ControllerProfileErrorV1::Service) }
    }

    /// Captures only the original fragment after its actual property comparison.
    ///
    /// # Errors
    /// Refuses absent or failed prefix, repeated entry or changed native fragment.
    pub fn capture_fragment_once_v1(&mut self, profile: &ControllerSelfProfileOriginalV1)
        -> Result<(), ControllerProfileErrorV1>
    {
        if self.fragment_entered || !matches!(self.prefix, Some(Ok(()))) {
            return Err(ControllerProfileErrorV1::Service);
        }
        self.fragment_entered = true;
        self.fragment = Some(self.local.capture_fragment_observed(profile, Some(&mut self.originals)));
        if matches!(self.fragment, Some(Ok(()))) { Ok(()) }
        else { Err(ControllerProfileErrorV1::Service) }
    }

    /// Borrows the same earliest reached native or semantic cause.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.local.failure_observed(Some(&self.originals))
            .or_else(|| self.prefix.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.fragment.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
    }
}

impl Default for ControllerProfileLocalPrefixOriginalV1 {
    fn default() -> Self { Self::new() }
}
