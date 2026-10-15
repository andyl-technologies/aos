//! Retains the selected original Hello transport before every fallible step.
//!
//! This child uses the closed SDK verifier and schema. The ordinary generic
//! negotiation API keeps its existing ownership and measurement behavior.

use super::*;
use crate::client::host_startup::hello;

pub(in crate::client) struct OriginalHostHelloAttempt {
    stream: Option<std::os::unix::net::UnixStream>,
    writer: Option<DeadlineStream>,
    spare_stream: Option<DeadlineStream>,
    reader: Option<FrameReader<DeadlineStream>>,
    raw: Option<serde_json::Value>,
    response: Option<Envelope>,
    authority: Option<ConnectionAuthority>,
    connection: Option<Connection<DeadlineStream>>,
    attempted: bool,
    completed: bool,
}

impl OriginalHostHelloAttempt {
    pub(in crate::client) fn new(stream: std::os::unix::net::UnixStream) -> Self {
        Self {
            stream: Some(stream),
            writer: None,
            spare_stream: None,
            reader: None,
            raw: None,
            response: None,
            authority: None,
            connection: None,
            attempted: false,
            completed: false,
        }
    }

    // crucible-lint: allow rust-allow -- The original transport, registrar, closed verifiers and retained output are independent custody inputs.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::client) fn negotiate_into(
        &mut self,
        peer: &ClientPeer,
        request: &Envelope,
        connection_id: Id,
        handshake: &mut crate::handshake::ExtensionHandshake,
        verifier: &mut hello::Verifier<'_>,
        guard: &hello::ResponseGuard<'_>,
        schemas: &Rc<hello::InitialHelloSchema>,
        supervisor: &Rc<dyn ConnectionSupervisor>,
        deadline: &ExchangeDeadline,
        journal: &mut OriginalHelloJournal,
        completed: &mut Option<ClientSession>,
    ) -> Result<(), ProviderError> {
        if self.attempted || completed.is_some() {
            return Err(ProviderError::Conflict(
                "original host Hello already attempted",
            ));
        }
        self.attempted = true;
        journal.begin(request, hello::MAXIMUM_HELLO_BYTES, 64)?;
        deadline.remaining()?;
        let stream = self
            .stream
            .as_ref()
            .ok_or(ProviderError::Correlation("original host stream absent"))?;
        let credentials =
            rustix::net::sockopt::socket_peercred(stream).map_err(std::io::Error::from)?;
        let expected_pid = i32::try_from(peer.pid)
            .map_err(|_| ProviderError::Correlation("invalid retained provider PID"))?;
        if expected_pid <= 0
            || credentials.pid.as_raw_nonzero().get() != expected_pid
            || credentials.uid.as_raw() != peer.uid
        {
            return Err(ProviderError::Correlation(
                "CNP peer differs from retained launch",
            ));
        }
        guard.authenticate_peer(peer)?;
        let path = hello::PeerExecutablePath::new(peer.pid)?;
        let measured = crate::reference_packet::service::ack_emitter::measure_original_prepare_executable_data(path.as_path()?)?;
        if measured != peer.executable {
            return Err(ProviderError::Correlation(
                "CNP peer executable differs from installation",
            ));
        }
        let stream = self
            .stream
            .take()
            .ok_or(ProviderError::Correlation("original host stream absent"))?;
        self.writer = Some(
            match DeadlineStream::with_original_deadline_owned(stream, deadline.clone()) {
                Ok(writer) => writer,
                Err(refusal) => {
                    let (stream, _) = refusal.into_original();
                    self.stream = Some(stream);
                    return Err(ProviderError::Correlation(
                        "original host Hello deadline expired",
                    ));
                }
            },
        );
        let reader_stream = self
            .writer
            .as_ref()
            .ok_or(ProviderError::Correlation("original host writer absent"))?
            .try_clone()?;
        self.reader = Some(
            match FrameReader::with_limits_owned(reader_stream, hello::MAXIMUM_HELLO_BYTES, 64) {
                Ok(reader) => reader,
                Err((stream, error)) => {
                    // Preserve both actual descriptors even if a closed limit
                    // check refuses. They retain the same unrenewed original cut.
                    self.spare_stream = Some(stream);
                    return Err(error);
                }
            },
        );
        let bank = journal
            .literal_bank()
            .ok_or(ProviderError::Correlation("original Hello bank absent"))?;
        let reader = self
            .reader
            .as_mut()
            .ok_or(ProviderError::Correlation("original host reader absent"))?;
        reader.install_originals(Rc::clone(&bank));
        let writer = self
            .writer
            .as_mut()
            .ok_or(ProviderError::Correlation("original host writer absent"))?;
        if !journal.publish_literal(writer)? {
            return Err(ProviderError::Correlation(
                "selected Hello requires original literal publication",
            ));
        }
        let frame = reader
            .read_retained()?
            .ok_or(ProviderError::Correlation("CNP hello response unavailable"))?;
        self.raw = Some(frame.value);
        journal.retain_response(&frame.bytes)?;
        let value = self.raw.as_ref().ok_or(ProviderError::Correlation(
            "original host Hello value absent",
        ))?;
        guard.authenticate(value)?;
        self.response = Some(Envelope::decode(
            &canonical::canonical_json(value)?,
            hello::MAXIMUM_HELLO_BYTES,
        )?);
        self.authority = Some(
            handshake.admit_envelopes(
                request,
                self.response
                    .as_ref()
                    .ok_or(ProviderError::Correlation("original Hello response absent"))?,
                connection_id,
                verifier,
            )?,
        );
        let authority = self.authority.as_ref().ok_or(ProviderError::Correlation(
            "original Hello authority absent",
        ))?;
        if !authority.selected_features().iter().any(|feature| feature.as_str() == crate::reference_packet::service::ack_emitter::PACKET_NATIVE_CANONICAL_ACK_FEATURE) {
            return Err(ProviderError::Correlation("selected Hello omitted canonical ACK"));
        }
        Connection::new_original_host_startup_into(
            &mut self.writer,
            authority,
            Rc::clone(supervisor),
            schemas.clone(),
            &mut self.connection,
        )?;
        *completed = Some(ClientSession {
            connection: self.connection.take().ok_or(ProviderError::Correlation(
                "original host connection absent",
            ))?,
            authority: authority.clone(),
            deadline: deadline.clone(),
            sequence: U64::new(2),
            peer_pid: peer.pid,
            peer_executable: peer.executable.clone(),
            original_ack_hello: Some(bank),
            original_response_loss: None,
        });
        // Release redundant successful parser views only after the actual
        // session owns its connection and original registration association.
        self.reader = None;
        self.raw = None;
        self.response = None;
        self.authority = None;
        self.completed = true;
        Ok(())
    }

    pub(in crate::client) fn observe_completed_metadata(
        &self,
        _: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), ProviderError> {
        let Self {
            stream,
            writer,
            spare_stream,
            reader,
            raw,
            response,
            authority,
            connection,
            attempted,
            completed,
        } = self;
        if !attempted
            || !completed
            || stream.is_some()
            || writer.is_some()
            || reader.is_some()
            || spare_stream.is_some()
            || raw.is_some()
            || response.is_some()
            || authority.is_some()
            || connection.is_some()
        {
            return Err(ProviderError::Correlation(
                "original host Hello transport remains partial",
            ));
        }
        Ok(())
    }
}

impl OriginalHostHelloAttempt {
    // The enclosing SDK owner checks its raw creator before this concrete walk.
    // Each optional stream is independently owning; moves empty the old slot.
    pub(in crate::client) fn retained_descriptor_count_data(&self) -> Result<usize, ProviderError> {
        let Self {
            stream,
            writer,
            spare_stream,
            reader,
            raw: _,
            response: _,
            authority: _,
            connection,
            attempted: _,
            completed: _,
        } = self;
        let direct = usize::from(stream.is_some())
            + usize::from(writer.is_some())
            + usize::from(spare_stream.is_some())
            + usize::from(reader.is_some());
        direct
            .checked_add(match connection {
                Some(connection) => connection.original_host_retained_descriptor_count_data()?,
                None => 0,
            })
            .ok_or(ProviderError::ResourceExhausted(
                "original host descriptor count",
            ))
    }
}

#[cfg(test)]
mod descriptor_tests {
    use super::*;

    #[test]
    fn actual_partial_hello_counts_independently_cloned_reader_handle() {
        let (stream, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut attempt = OriginalHostHelloAttempt::new(stream);
        assert_eq!(attempt.retained_descriptor_count_data().unwrap(), 1);
        let deadline = ExchangeDeadline::start(Duration::from_secs(30)).unwrap();
        attempt.writer =
            Some(DeadlineStream::with_deadline(attempt.stream.take().unwrap(), deadline).unwrap());
        let duplicate = attempt.writer.as_ref().unwrap().try_clone().unwrap();
        attempt.reader = Some(FrameReader::with_limits(duplicate, 65_536, 64).unwrap());
        assert_eq!(attempt.retained_descriptor_count_data().unwrap(), 2);
        attempt.attempted = true;
        assert_eq!(attempt.retained_descriptor_count_data().unwrap(), 2);
        attempt.reader = None;
        assert_eq!(attempt.retained_descriptor_count_data().unwrap(), 1);
    }
}
