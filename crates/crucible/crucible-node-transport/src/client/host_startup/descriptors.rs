//! Counts actual independently owning SDK descriptors in every retained phase.
//!
//! This readonly data walk neither opens/closes handles nor authenticates an
//! installed OS-resource action. Raw creator checks run even for failed or
//! partial attempts. Expiry cannot hide resources that remain retained.

use super::*;

/// Counts explicit fixed result and borrowed-owner headers for descriptor data.
///
/// No descriptor, callback, serializer or allocator operation runs here.
/// Compiler frames and kernel bookkeeping remain outside this named workspace.
pub const fn original_packet_host_descriptor_counter_scratch_data() -> usize {
    std::mem::size_of::<[usize; 4]>()
        + std::mem::size_of::<std::array::IntoIter<usize, 4>>()
        + 8 * std::mem::size_of::<usize>()
        + std::mem::size_of::<&OriginalPacketHostStartup>()
        + std::mem::size_of::<&crate::client::session::OriginalHostHelloAttempt>()
        + std::mem::size_of::<&ClientSession>()
        + std::mem::size_of::<&CnpController>()
        + std::mem::size_of::<&crate::connection::Connection<crate::client::DeadlineStream>>()
        + 4 * std::mem::size_of::<&Option<UnixStream>>()
}

impl OriginalPacketHostStartup {
    /// Counts actual retained socket descriptors, including partial failures.
    ///
    /// A completed Controller owns one concrete stream; an unfinished Hello can
    /// retain both the original and its independently duplicated reader handle.
    /// The temporary executable measurement File is not retained on return and
    /// belongs to the separate prospective simultaneous phase. No phase flag or
    /// numeric quote replaces the actual owning slots counted here.
    ///
    /// # Errors
    /// Refuses a foreign raw creator or checked arithmetic overflow. Expired,
    /// incomplete and failed same-origin owners remain observable.
    pub fn retained_descriptor_count_data(&self) -> Result<usize, ProviderError> {
        self.creator.ensure_current()?;
        let Self {
            creator: _,
            quote: _,
            registration: _,
            selection: _,
            coordinator: _,
            profile: _,
            executable: _,
            schemas: _,
            deadline: _,
            plain_handshake: _,
            handshake: _,
            hello: _,
            hello_journal: _,
            pending_content: _,
            content: _,
            custody: _,
            frames: _,
            route: _,
            stream,
            hello_attempt,
            session,
            controller,
            failure: _,
            preparing: _,
            prepared: _,
            connecting: _,
            connected: _,
            initial_attachment_attempted: _,
        } = self;
        let counts = [
            usize::from(stream.is_some()),
            match hello_attempt {
                Some(attempt) => attempt.retained_descriptor_count_data()?,
                None => 0,
            },
            match session {
                Some(session) => session.original_host_retained_descriptor_count_data()?,
                None => 0,
            },
            match controller {
                Some(controller) => controller.retained_descriptor_count_data()?,
                None => 0,
            },
        ];
        let total = counts.into_iter().try_fold(0usize, |total, count| {
            total
                .checked_add(count)
                .ok_or(ProviderError::ResourceExhausted(
                    "original host descriptor count",
                ))
        })?;
        self.creator.ensure_current()?;
        Ok(total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_prepared_failed_sdk_keeps_its_retained_stream_visible() {
        let (_inputs, mut sdk) = crate::client::host_startup::tests::prepared_initial_model();
        assert_eq!(sdk.retained_descriptor_count_data().unwrap(), 0);
        let (stream, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        sdk.stream = Some(stream);
        assert_eq!(sdk.retained_descriptor_count_data().unwrap(), 1);
        sdk.failure = Some(ProviderError::Correlation("modeled retained refusal"));
        sdk.connecting = true;
        assert_eq!(sdk.retained_descriptor_count_data().unwrap(), 1);
        sdk.hello_attempt = Some(crate::client::session::OriginalHostHelloAttempt::new(
            sdk.stream.take().unwrap(),
        ));
        assert_eq!(sdk.retained_descriptor_count_data().unwrap(), 1);
        assert!(
            original_packet_host_descriptor_counter_scratch_data()
                >= std::mem::size_of::<[usize; 5]>()
        );
    }
}
