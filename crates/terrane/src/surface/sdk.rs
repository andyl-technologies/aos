//! Registers pinned SDK directory presentation through repository content reads.

use std::path::Path;

use crate::{
    repository::{Error, Repository},
    store::{Clock, LocalFs, Store},
};

use super::{Endpoint, EndpointKind, ServingHandle, Surface, TreeSchema, View};

/// Borrows repository access and an exposure token for pinned SDK presentation.
pub(super) struct SdkSurface<'a, S: Store, C: Clock, F: LocalFs> {
    repository: &'a Repository<S, C, F>,
    token: &'a [u8],
}

impl<'a, S: Store, C: Clock, F: LocalFs> SdkSurface<'a, S, C, F> {
    /// Binds SDK presentation to repository reads under the supplied token.
    pub(super) fn new(repository: &'a Repository<S, C, F>, token: &'a [u8]) -> Self {
        Self { repository, token }
    }
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl<S, C, F> Surface for SdkSurface<'_, S, C, F>
where
    S: Store + Sync,
    C: Clock + Sync,
    F: LocalFs + Sync,
{
    fn schema(&self) -> TreeSchema {
        TreeSchema::default()
    }

    async fn serve(&self, view: View, endpoint: Endpoint) -> Result<ServingHandle, Error> {
        if endpoint.kind != EndpointKind::Directory {
            return Err(Error::Unrealizable);
        }
        let prepared = self
            .repository
            .prepare_view_schema(&view, self.token, "sdk", &self.schema())
            .await?;
        serve_prepared(self.repository, prepared, endpoint).await
    }
}

/// Materializes an exact repository-owned preparation without rebinding its ref.
pub(super) async fn serve_prepared<S, C, F>(
    repository: &Repository<S, C, F>,
    prepared: crate::repository::read::PreparedView,
    endpoint: Endpoint,
) -> Result<ServingHandle, Error>
where
    S: Store + Sync,
    C: Clock + Sync,
    F: LocalFs + Sync,
{
    if endpoint.kind != EndpointKind::Directory {
        return Err(Error::Unrealizable);
    }
    let resolved = repository.read_prepared_view(prepared).await?;
    repository
        .materialize_checkout(Path::new(&endpoint.address), &resolved)
        .await?;
    Ok(super::native::checkout(resolved.commit))
}
