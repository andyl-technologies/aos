//! Borrows original content and read-only legacy maps for live runtime exchange.
//!
//! The containing runtime owns the original Controller permanently. These
//! operations never lend mutable legacy journals or replace their content.
//! Construction and every future operation still require independent admission.

use super::*;
use crate::client::ClientCustody;

impl CompactClientJournal {
    pub(in crate::client) fn observe_runtime_metadata(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        self.observe_originals_metadata(observer)?;
        self.observe_pending_metadata(observer)
    }

    pub(in crate::client) fn runtime_originals(
        &self,
        origin: RequestOrigin,
    ) -> impl Iterator<Item = &CompactClientOriginal> {
        self.namespace(origin).values()
    }

    pub(in crate::client) fn runtime_retained_bytes(&self) -> usize {
        self.retained_bytes
    }

    pub(in crate::client) fn runtime_pending_envelope(&self) -> Option<(RequestOrigin, &Envelope)> {
        self.pending
            .as_ref()
            .map(|pending| (pending.origin, &pending.envelope))
    }

    pub(in crate::client) fn runtime_unexpected_frame(
        &self,
    ) -> Option<&crate::connection::ReceivedFrame> {
        self.unexpected.as_ref()
    }
}

impl ClientCustody {
    pub(in crate::client) fn runtime_journal_bytes_data(&self) -> [usize; 2] {
        [self.maximum_bytes, self.retained_bytes]
    }

    pub(in crate::client) fn compact_runtime_journal_limits_data(
        &self,
    ) -> Result<[usize; 3], ProviderError> {
        let remaining = self
            .maximum_bytes
            .checked_sub(self.retained_bytes)
            .ok_or_else(credit)?;
        let bank = remaining.checked_mul(9).ok_or_else(credit)?;
        Ok([self.maximum_requests, remaining, bank])
    }
}

impl ClientSession {
    pub(in crate::client) fn prepare_compact_runtime_journal(
        &mut self,
        legacy: &ClientCustody,
    ) -> Result<CompactClientJournal, ProviderError> {
        self.authority.ensure_live()?;
        if self.original_response_loss.is_some() {
            return Err(changed());
        }
        self.connection.authenticate_compact_exchange_idle()?;

        let [requests, remaining, bank] = legacy.compact_runtime_journal_limits_data()?;
        let suffix = CompactClientJournal::new(requests, remaining, bank)?;
        prefix(legacy)?.authenticate(&suffix)?;
        Ok(suffix)
    }

    pub(in crate::client) fn exchange_compact_runtime(
        &mut self,
        legacy: &mut ClientCustody,
        suffix: &mut CompactClientJournal,
        request: &mut Envelope,
        budget: std::time::Duration,
    ) -> Result<Envelope, ProviderError> {
        let ClientCustody {
            maximum_requests,
            maximum_bytes,
            retained_bytes,
            controller,
            provider,
            content,
        } = legacy;
        let prefix = CompactJournalPrefix {
            maximum_requests: *maximum_requests,
            remaining_bytes: maximum_bytes
                .checked_sub(*retained_bytes)
                .ok_or_else(credit)?,
            controller,
            provider,
        };
        self.exchange_compact_parts(suffix, content, Some(&prefix), request, budget)
    }

    pub(in crate::client) fn receive_compact_runtime_content(
        &mut self,
        legacy: &mut ClientCustody,
        suffix: &mut CompactClientJournal,
        roots: &[crucible_node_format::ContentRef],
        budget: std::time::Duration,
    ) -> Result<(), ProviderError> {
        let result = self.receive_compact_runtime_content_inner(legacy, suffix, roots, budget);
        if result.is_err() {
            self.close();
        }
        result
    }

    fn receive_compact_runtime_content_inner(
        &mut self,
        legacy: &mut ClientCustody,
        suffix: &mut CompactClientJournal,
        roots: &[crucible_node_format::ContentRef],
        budget: std::time::Duration,
    ) -> Result<(), ProviderError> {
        self.authority.ensure_live()?;
        if roots.len() > 4096 || suffix.pending.is_some() || suffix.unexpected.is_some() {
            return Err(changed());
        }
        prefix(legacy)?.authenticate(suffix)?;
        self.connection.authenticate_compact_exchange_idle()?;
        // A cached terminal may refer only to already retained content. Reading
        // it performs no wire work and must neither renew nor require a cut.
        if roots
            .iter()
            .all(|reference| legacy.content.get(reference).is_ok())
        {
            return Ok(());
        }
        self.deadline.tighten(budget)?;

        let ClientCustody {
            maximum_requests,
            maximum_bytes,
            retained_bytes,
            controller,
            provider,
            content,
        } = legacy;
        let prefix = CompactJournalPrefix {
            maximum_requests: *maximum_requests,
            remaining_bytes: maximum_bytes
                .checked_sub(*retained_bytes)
                .ok_or_else(credit)?,
            controller,
            provider,
        };
        while roots
            .iter()
            .any(|reference| content.get(reference).is_err())
        {
            let frame = self
                .connection
                .receive()?
                .ok_or(ProviderError::Correlation(
                    "promised compact runtime evidence unavailable",
                ))?;
            match frame.body {
                crate::connection::ReceivedBody::Request(body) => {
                    self.receive_compact_transfer(
                        suffix,
                        content,
                        Some(&prefix),
                        frame.envelope,
                        *body,
                    )?;
                }
                crate::connection::ReceivedBody::Response(_) => {
                    suffix.hold(RequestOrigin::Controller, frame.envelope)?;
                    return Err(changed());
                }
                body @ (crate::connection::ReceivedBody::NativeImport18Bootstrap(_)
                | crate::connection::ReceivedBody::Notification(_)) => {
                    suffix.unexpected = Some(crate::connection::ReceivedFrame {
                        envelope: frame.envelope,
                        body,
                    });
                    return Err(changed());
                }
            }
        }
        self.connection.authenticate_compact_exchange_idle()
    }
}

fn prefix(legacy: &ClientCustody) -> Result<CompactJournalPrefix<'_>, ProviderError> {
    Ok(CompactJournalPrefix {
        maximum_requests: legacy.maximum_requests,
        remaining_bytes: legacy
            .maximum_bytes
            .checked_sub(legacy.retained_bytes)
            .ok_or_else(credit)?,
        controller: &legacy.controller,
        provider: &legacy.provider,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::session::compact_journal::tests::{BANK_BYTES, fixture};
    use crucible_node_format::canonical;
    use std::{io::Read, time::Duration};

    #[test]
    fn already_owned_content_uses_no_new_or_expired_operational_cut()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_lease, mut session, compact, mut peer, _request) = fixture(BANK_BYTES);
        let mut legacy = ClientCustody::new(8, compact.content)?;
        let reference = canonical::content_ref(b"original", "application/octet-stream")?;
        legacy
            .content
            .install(reference.clone(), b"original".to_vec())?;
        let mut suffix = session.prepare_compact_runtime_journal(&legacy)?;
        session.deadline.reset(Duration::from_nanos(1))?;
        let expired = session.deadline.original_cut();
        std::thread::sleep(Duration::from_millis(1));
        assert!(session.deadline.remaining().is_err());

        session.receive_compact_runtime_content(
            &mut legacy,
            &mut suffix,
            &[reference],
            Duration::from_secs(2),
        )?;

        assert_eq!(session.deadline.original_cut(), expired);
        assert!(session.deadline.remaining().is_err());
        assert_eq!(suffix.retained_bytes, 0);
        peer.set_nonblocking(true)?;
        assert!(
            matches!(peer.read(&mut [0]), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
        Ok(())
    }
}
