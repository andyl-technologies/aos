//! Owns native registered realization handles and SDK lifecycle status.

use std::{
    sync::atomic::{AtomicU8, Ordering},
    time::Duration,
};

use terrane_core::identity::Digest;

use super::{Endpoint, ReaderMode, TreeSchema, View, WriterMode};
use crate::repository::Error;

/// Supplies one registered presentation's endpoint, credential, and reader mode.
pub struct RealizationHints {
    /// Registered compiled surface name.
    pub surface: String,
    /// Endpoint accepted by the selected surface.
    pub endpoint: Endpoint,
    /// Canonical exposure token; no private signing or store credential.
    pub token: Vec<u8>,
    /// Explicit reader behavior requested for this presentation.
    pub reader: ReaderMode,
}

impl<S, C, F> crate::repository::Repository<S, C, F>
where
    S: crate::store::Store + Sync,
    C: crate::store::Clock + Sync,
    F: crate::store::LocalFs + Sync,
{
    /// Realizes an authorized view through the closed compiled surface registry.
    ///
    /// SDK graft boundaries become private mode0700 directories because stored
    /// tree references carry no source inode mode. Existing directory entries
    /// retain their modes, and guarded root policies remain authoritative.
    ///
    /// # Errors
    /// Rejects unavailable surfaces, unsupported reader modes or endpoints,
    /// invalid policy names, denied or untrusted views, unresolved conflicts,
    /// escaping paths, and failed filesystem realization or durability.
    pub async fn realize(&self, view: View, hints: RealizationHints) -> Result<Serving, Error> {
        realize(self, view, hints).await
    }
}

/// Realizes a view through its registered surface and reader mode.
///
/// # Errors
/// Rejects unavailable surfaces or reader modes and propagates guarded view,
/// endpoint validation and filesystem realization failures.
pub(crate) async fn realize<S, C, F>(
    repository: &crate::repository::Repository<S, C, F>,
    view: View,
    hints: RealizationHints,
) -> Result<Serving, Error>
where
    S: crate::store::Store + Sync,
    C: crate::store::Clock + Sync,
    F: crate::store::LocalFs + Sync,
{
    #[cfg(not(all(feature = "surface-sdk", unix)))]
    let _ = (repository, view);

    match hints.surface.as_str() {
        #[cfg(all(feature = "surface-sdk", unix))]
        "sdk" => {
            if hints.reader != ReaderMode::Pinned {
                return Err(Error::UnavailableOperation("SDK follow reader"));
            }
            super::sdk::SdkSurface::new(repository, &hints.token)
                .serve(view, hints.endpoint)
                .await
        }
        _ => Err(Error::UnavailableSurface(hints.surface)),
    }
}

/// Maps a repository view to one registered external interface (SURF-1).
#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
pub trait Surface {
    /// Returns metadata requirements equivalent to the surface registry.
    fn schema(&self) -> TreeSchema;

    /// Begins presenting a view at the surface's accepted endpoint kind.
    ///
    /// # Errors
    /// Returns repository authorization, trust, schema, or presentation errors.
    async fn serve(&self, view: View, endpoint: Endpoint) -> Result<Serving, Error>;
}

/// Reports the lifecycle of an exposure handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExposureState {
    /// The presentation is available to its consumer.
    Serving,
    /// Outstanding work has drained.
    Drained,
    /// The exposure has stopped accepting work.
    Stopped,
}

/// Reports the schema evaluation result for the currently served commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchemaState {
    /// The resolved metadata satisfies all requirements.
    Valid,
    /// A reference advance failed metadata validation.
    Fault,
}

/// Describes unavailable or degraded realization features (SURF-27).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeatureOutcome {
    /// Requested feature name.
    pub feature: String,
    /// Reason the selected realizer could not provide it.
    pub reason: String,
}

/// Reports the commit and behavior of one exposure (SURF-27, SURF-28).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExposureStatus {
    /// Exact immutable commit currently presented.
    pub commit: Digest,
    /// Registered surface name.
    pub surface: &'static str,
    /// Realizer selected by the registry, when applicable.
    pub realizer: Option<&'static str>,
    /// Requested features that could not be provided.
    pub features: Vec<FeatureOutcome>,
    /// Reader mode actually used.
    pub reader: ReaderMode,
    /// Writer mode, absent for read-only presentations.
    pub writer: Option<WriterMode>,
    /// Whether the most recent mutation committed; absent before mutations.
    pub last_commit: Option<Digest>,
    /// Metadata schema state.
    pub schema: SchemaState,
    /// Current exposure lifecycle.
    pub state: ExposureState,
}

/// Owns the lifecycle and status of a completed SDK presentation.
///
/// Stopping or draining a directory checkout prevents further exposure work;
/// it does not delete the consumer's durable directory.
#[derive(Debug)]
pub struct Serving {
    status: ExposureStatus,
    state: AtomicU8,
}

impl Serving {
    /// Creates a serving handle for a completed pinned directory checkout.
    #[cfg(all(feature = "surface-sdk", unix))]
    pub(crate) fn checkout(commit: Digest) -> Self {
        Self {
            status: ExposureStatus {
                commit,
                surface: "sdk",
                realizer: None,
                features: Vec::new(),
                reader: ReaderMode::Pinned,
                writer: None,
                last_commit: None,
                schema: SchemaState::Valid,
                state: ExposureState::Serving,
            },
            state: AtomicU8::new(0),
        }
    }

    /// Returns the resolved commit and exposure state without backend access.
    pub fn status(&self) -> ExposureStatus {
        let mut status = self.status.clone();
        status.state = match self.state.load(Ordering::Acquire) {
            0 => ExposureState::Serving,
            1 => ExposureState::Drained,
            _ => ExposureState::Stopped,
        };
        status
    }

    /// Drains outstanding presentation work within the requested deadline.
    ///
    /// SDK checkout is complete before its handle is returned, so draining has
    /// no outstanding filesystem work to wait for.
    ///
    /// # Errors
    /// This completed SDK presentation has no fallible drain operation.
    pub fn drain(&self, _deadline: Duration) -> Result<(), Error> {
        let _ = self
            .state
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire);
        Ok(())
    }

    /// Stops accepting presentation work while retaining the checked-out tree.
    ///
    /// # Errors
    /// This completed SDK presentation has no fallible stop operation.
    pub fn stop(&self) -> Result<(), Error> {
        self.state.store(2, Ordering::Release);
        Ok(())
    }
}
