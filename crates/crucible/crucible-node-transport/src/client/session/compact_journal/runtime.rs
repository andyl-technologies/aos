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
        observer.with_packet_runtime_population_data(
            crate::retained_metadata::PacketRuntimeMetadataPopulation::Journal,
            |observer| {
                self.observe_originals_metadata(observer)?;
                self.observe_pending_metadata(observer)
            },
        )
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
    /// Names the actual runtime prefix, exchange and content-loop controls.
    pub(in crate::client) fn packet_runtime_exchange_counter_scratch_data() -> usize {
        use std::mem::size_of;

        size_of::<CompactJournalPrefix<'static>>()
            + size_of::<Result<CompactJournalPrefix<'static>, ProviderError>>()
            + size_of::<&mut Self>()
            + size_of::<&mut ClientCustody>()
            + size_of::<&mut CompactClientJournal>()
            + size_of::<&mut ClientContent>()
            + size_of::<&mut Envelope>()
            + size_of::<&[crucible_node_format::ContentRef]>()
            + size_of::<std::slice::Iter<'static, crucible_node_format::ContentRef>>()
            + size_of::<std::time::Duration>()
            + size_of::<crate::connection::ReceivedFrame>()
            + size_of::<Result<Option<crate::connection::ReceivedFrame>, ProviderError>>()
            + size_of::<crate::bodies::RequestBody>()
            + size_of::<crate::bodies::ResponseBody>()
            + size_of::<Result<Envelope, ProviderError>>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<Result<&[u8], ProviderError>>()
            + size_of::<Option<usize>>()
            + 4 * size_of::<usize>()
    }

    pub(in crate::client) fn compact_runtime_identity_storage_data(
        &self,
        legacy: &ClientCustody,
    ) -> Result<[usize; 3], ProviderError> {
        let [requests, remaining, bank] = legacy.compact_runtime_journal_limits_data()?;
        validate_journal_limits(requests, remaining, bank)?;
        let frame =
            usize::try_from(self.authority.limits().frame_bytes.get()).map_err(|_| credit())?;
        let mut row = identity::runtime_storage_data(frame)?;
        row[2] = Self::compact_runtime_identity_counter_scratch_data();
        Ok(row)
    }

    pub(in crate::client) fn compact_runtime_identity_counter_scratch_data() -> usize {
        use std::mem::size_of;

        Self::compact_request_identity_counter_scratch_data()
            + size_of::<&ClientCustody>()
            + size_of::<[usize; 3]>()
            + size_of::<Result<[usize; 3], ProviderError>>()
            + size_of::<Option<usize>>()
            + size_of::<usize>() * 4
    }

    /// Prepares an empty suffix at the original immutable handoff boundary.
    ///
    /// This DATA check invokes no containment or schema callback. The actual
    /// handoff and its funding query share the same checks and journal limits.
    ///
    /// # Errors
    /// Refuses revoked, fenced or unresolved connection ownership, a response
    /// loss callback, unsupported credit or an unsettled original prefix.
    pub(in crate::client) fn prepare_compact_runtime_journal(
        &self,
        legacy: &ClientCustody,
    ) -> Result<CompactClientJournal, ProviderError> {
        self.authority.ensure_live()?;
        if self.original_response_loss.is_some() {
            return Err(changed());
        }
        self.connection.authenticate_compact_exchange_idle_data()?;

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
    fn identity_quote_keeps_full_retry_work_with_one_byte_of_suffix_credit()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_lease, session, compact, _peer, _request) = fixture(BANK_BYTES);
        let mut legacy = ClientCustody::new(256, compact.content)?;
        let full = session.compact_runtime_identity_storage_data(&legacy)?;
        let frame = usize::try_from(session.authority.limits().frame_bytes.get())?;

        // Numeric debit fixtures exercise the same private remaining-credit
        // arithmetic as retention. They do not fabricate a replay permission.
        legacy.retained_bytes = legacy.maximum_bytes - 1;
        let quotas = legacy.runtime_journal_bytes_data();
        let almost_spent = session.compact_runtime_identity_storage_data(&legacy)?;
        let suffix_only = identity::storage_data(frame, 1)?;

        assert_eq!(almost_spent, full);
        assert!(almost_spent[1] > suffix_only[1]);
        assert_eq!(legacy.runtime_journal_bytes_data(), quotas);
        for debit in [legacy.maximum_bytes, legacy.maximum_bytes + 1, usize::MAX] {
            legacy.retained_bytes = debit;
            assert!(
                session
                    .compact_runtime_identity_storage_data(&legacy)
                    .is_err()
            );
            assert_eq!(legacy.retained_bytes, debit);
        }
        Ok(())
    }

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
