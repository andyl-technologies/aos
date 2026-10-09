//! Channels reads in the releases capability.

use super::*;

impl RpcService {
    /// `ChannelService.ListChannels` — channels with full partition maps.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::NotFound`] for an unknown slug or a soft-deleted
    /// owning org, [`RpcError::Unauthenticated`]/[`RpcError::PermissionDenied`]
    /// when a non-public registry is read without authority,
    /// [`RpcError::InvalidArgument`] for a malformed `page_token`, and
    /// [`RpcError::Internal`] on database failure.
    pub async fn list_channels(
        &self,
        auth: Option<&str>,
        req: pb::ListChannelsRequest,
    ) -> Result<pb::ListChannelsResponse, RpcError> {
        let record = self.registry_or_not_found(&req.slug).await?;
        self.require_read(auth, &record).await?;
        let channels: Vec<pb::Channel> = self
            .db
            .list_channels(record.id)
            .await
            .map_err(RpcError::internal)?
            .into_iter()
            .map(channel_message)
            .collect();
        let (channels, next_page_token) = paginate(channels, req.page_size, &req.page_token)?;
        Ok(pb::ListChannelsResponse {
            channels,
            next_page_token,
        })
    }

    /// `ChannelService.GetChannel` — one channel's partition map by name.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::NotFound`] for an unknown slug, channel name, or a
    /// soft-deleted owning org,
    /// [`RpcError::Unauthenticated`]/[`RpcError::PermissionDenied`] when a
    /// non-public registry is read without authority, and [`RpcError::Internal`]
    /// on database failure.
    pub async fn get_channel(
        &self,
        auth: Option<&str>,
        req: pb::GetChannelRequest,
    ) -> Result<pb::GetChannelResponse, RpcError> {
        let record = self.registry_or_not_found(&req.slug).await?;
        self.require_read(auth, &record).await?;
        let channel = self
            .db
            .list_channels(record.id)
            .await
            .map_err(RpcError::internal)?
            .into_iter()
            .find(|c| c.name == req.name)
            .ok_or_else(|| RpcError::not_found("channel"))?;
        Ok(pb::GetChannelResponse {
            channel: Some(channel_message(channel)),
        })
    }
}
