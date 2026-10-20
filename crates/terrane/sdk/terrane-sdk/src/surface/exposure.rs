//! Prepares every configured exposure before ordered, repository-only startup.

use super::{RealizationHints, ServingHandle};
use crate::{
    config::exposure::ConfiguredExposure,
    repository::{Error, Repository},
    store::{Clock, LocalFs, Store},
};

/// Resolves credential locators without granting any repository authority.
///
/// Implementations keep file or secret-provider policy outside presentation;
/// returned capabilities are verified by the repository before startup.
#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
pub trait TokenResolver {
    /// Resolves one locator to canonical capability bytes.
    ///
    /// # Errors
    /// Rejects unavailable, unreadable or malformed credential references.
    async fn resolve(&self, reference: &str) -> Result<Vec<u8>, Error>;
}

struct PreparedExposure {
    exposure: ConfiguredExposure,
    token: Vec<u8>,
    prepared: crate::repository::read::PreparedView,
}

/// Owns fully validated exposures in configuration order without open endpoints.
///
/// Capability bytes stay private and are never included in diagnostic output.
pub struct PreparedExposures {
    entries: Vec<PreparedExposure>,
}

impl PreparedExposures {
    /// Validates every capability and schema before any exposure can start.
    ///
    /// # Errors
    /// Rejects missing compiled surfaces, token resolution, authorization and
    /// schema failures. A failure starts no endpoint and accepts no partial list.
    pub async fn prepare<S, C, F, R>(
        repository: &Repository<S, C, F>,
        exposures: &[ConfiguredExposure],
        resolver: &R,
    ) -> Result<Self, Error>
    where
        S: Store + Sync,
        C: Clock + Sync,
        F: LocalFs + Sync,
        R: TokenResolver + Sync,
    {
        let mut identifiers = std::collections::BTreeSet::new();
        let mut endpoints = std::collections::BTreeSet::new();
        for exposure in exposures {
            if exposure.view.policy.is_some() {
                return Err(Error::UnavailableOperation("unregistered view policy"));
            }
            if exposure.id.is_empty()
                || !identifiers.insert(&exposure.id)
                || !crate::config::absolute_path(&exposure.endpoint.address)
                || !endpoints.insert(&exposure.endpoint.address)
                || crate::config::token::validate_reference(&exposure.token).is_err()
            {
                return Err(Error::Unrealizable);
            }
        }
        let mut entries = Vec::new();
        for exposure in exposures {
            let registration = super::registration(&exposure.surface)
                .ok_or_else(|| Error::UnavailableSurface(exposure.surface.clone()))?;
            if !registration.endpoints.contains(&exposure.endpoint.kind)
                || exposure.writer.is_some()
                || exposure.reader != super::ReaderMode::Pinned
                || !exposure.options.is_empty()
            {
                return Err(Error::Unrealizable);
            }
            let token = resolver.resolve(&exposure.token).await?;
            let prepared = repository
                .prepare_view_schema(
                    &exposure.view,
                    &token,
                    &exposure.surface,
                    &registration.schema,
                )
                .await?;
            entries.push(PreparedExposure {
                exposure: exposure.clone(),
                token,
                prepared,
            });
        }
        Ok(Self { entries })
    }

    /// Starts validated presentations in configuration order.
    ///
    /// If physical startup fails, completed handles are stopped before returning
    /// the failure. Durable SDK directories remain private checkout artifacts.
    ///
    /// # Errors
    /// Preserves live authority rechecks and physical presentation failures.
    pub async fn start<S, C, F>(
        self,
        repository: &Repository<S, C, F>,
    ) -> Result<Vec<ServingHandle>, Error>
    where
        S: Store + Sync,
        C: Clock + Sync,
        F: LocalFs + Sync,
    {
        let mut serving: Vec<ServingHandle> = Vec::new();
        for prepared in self.entries {
            let exposure = prepared.exposure;
            let result = super::native::realize_prepared(
                repository,
                prepared.prepared,
                RealizationHints {
                    surface: exposure.surface,
                    endpoint: exposure.endpoint,
                    token: prepared.token,
                    reader: exposure.reader,
                },
            )
            .await;
            match result {
                Ok(handle) => serving.push(handle),
                Err(error) => {
                    for handle in &serving {
                        handle.stop()?;
                    }
                    return Err(error);
                }
            }
        }
        Ok(serving)
    }
}
