//! Registers pinned SDK directory presentation through repository content reads.

use std::path::Path;

use crate::{
    repository::{Error, Repository},
    store::{Clock, LocalFs, Store},
};

use super::{Endpoint, EndpointKind, Serving, Surface, TreeSchema, View};

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

    async fn serve(&self, view: View, endpoint: Endpoint) -> Result<Serving, Error> {
        if endpoint.kind != EndpointKind::Directory {
            return Err(Error::Unrealizable);
        }
        let resolved = self.repository.read_view(&view, self.token, "sdk").await?;
        self.repository
            .materialize_checkout(Path::new(&endpoint.address), &resolved)
            .await?;
        Ok(Serving::checkout(resolved.commit))
    }
}
