//! Connects derived metadata to the selected authoritative file-bucket generation.

use super::{AttributeCatalog, AttributeQuarantine, Error};
use crate::{
    bucket::{BucketBinding, FileBucket},
    store::{Clock, ContentValidator, LocalFs},
};
use terrane_core::identity::{Identity, IdentityKind};

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl<F: LocalFs + BucketBinding, C: Clock + BucketBinding, V: ContentValidator + BucketBinding>
    AttributeCatalog for FileBucket<F, C, V>
{
    async fn attribute_identities(&self) -> Result<Vec<Identity>, Error> {
        Ok(self.published_identities(IdentityKind::Attribute).await?)
    }
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl<F: LocalFs + BucketBinding, C: Clock + BucketBinding, V: ContentValidator + BucketBinding>
    AttributeQuarantine for FileBucket<F, C, V>
{
    async fn exclude_attribute(&self, identity: &Identity) -> Result<(), Error> {
        if identity.kind() != IdentityKind::Attribute {
            return Err(Error::InvalidProducer);
        }
        Ok(self.exclude(identity).await?)
    }
}
