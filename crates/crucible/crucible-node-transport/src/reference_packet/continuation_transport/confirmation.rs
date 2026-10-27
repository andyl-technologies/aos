//! Retains one original confirmation transfer and every partial exchange.
//!
//! The actual endpoint retains the original after owner beside this transport.
//! This capsule sends no frame until complete source-selected suffix admission
//! and planning have succeeded. It never creates a native or source ticket.

use super::*;

/// Owns the original one-object confirmation suffix without retry authority.
#[must_use = "retain this suffix beside the original issued after snapshot"]
pub(crate) struct PacketAfterConfirmationPrefix<S: ProviderStream> {
    transport: Option<CaptureTransport<S>>,
    response: Option<Envelope>,
    windows: VecDeque<Vec<Envelope>>,
    records: Vec<ExchangeRecord>,
    contents: BTreeMap<Id, ContentRef>,
    chunk: u64,
    next_sequence: u64,
    charged_bytes: usize,
    state: PrefixState,
}

pub(super) fn original_confirmation_prefix_layout_data<S: ProviderStream>() -> Option<usize> {
    std::mem::size_of::<PacketAfterConfirmationPrefix<S>>()
        .checked_add(std::mem::size_of::<ConfirmationPreparation<'static>>())
}

struct ConfirmationPreparation<'a> {
    maximum_after: usize,
    storage: Option<&'a OriginalContinuationPrefixStorageData>,
}

impl<S: ProviderStream> PacketAfterConfirmationPrefix<S> {
    pub(crate) fn new(connection: Connection<S>) -> Self {
        Self {
            transport: Some(CaptureTransport::Connected(connection)),
            response: None,
            windows: VecDeque::new(),
            records: Vec::new(),
            contents: BTreeMap::new(),
            chunk: 0,
            next_sequence: 0,
            charged_bytes: 0,
            state: PrefixState::Unprepared,
        }
    }

    // The actual endpoint supplies a borrowed receipt and SAME after bytes only
    // after independent global lifetime/rawbank admission. No decoded receipt
    // or successful plan can stand for that admission or original owner proof.
    pub(crate) fn prepare(
        &mut self,
        original_poll: &Envelope,
        response: Envelope,
        receipt: &crate::reference_packet::service::confirmation::PacketNativeAfterConfirmationReceipt,
        after: (&ContentRef, &[u8]),
        maximum_after: usize,
    ) -> Result<(), ProviderError> {
        self.prepare_inner(
            original_poll,
            response,
            receipt,
            after,
            ConfirmationPreparation {
                maximum_after,
                storage: None,
            },
        )
    }

    pub(crate) fn prepare_with_storage_data(
        &mut self,
        original_poll: &Envelope,
        response: Envelope,
        receipt: &crate::reference_packet::service::confirmation::PacketNativeAfterConfirmationReceipt,
        after: (&ContentRef, &[u8]),
        storage: &OriginalContinuationPrefixStorageData,
    ) -> Result<(), ProviderError> {
        self.prepare_inner(
            original_poll,
            response,
            receipt,
            after,
            ConfirmationPreparation {
                maximum_after: usize::MAX,
                storage: Some(storage),
            },
        )
    }

    fn prepare_inner(
        &mut self,
        original_poll: &Envelope,
        response: Envelope,
        receipt: &crate::reference_packet::service::confirmation::PacketNativeAfterConfirmationReceipt,
        after: (&ContentRef, &[u8]),
        preparation: ConfirmationPreparation<'_>,
    ) -> Result<(), ProviderError> {
        let ConfirmationPreparation {
            mut maximum_after,
            storage,
        } = preparation;
        if self.state != PrefixState::Unprepared {
            return Err(ProviderError::Conflict(
                "after confirmation already attempted",
            ));
        }
        self.state = PrefixState::Failed;
        self.response = Some(response);
        if let Some(storage) = storage {
            if storage.kind != OriginalContinuationPrefixKind::AfterConfirmation {
                return Err(ProviderError::Correlation(
                    "confirmation storage planner differs",
                ));
            }
            maximum_after = storage.maximum_payload_bytes_data(0)?;
        }
        let Some(CaptureTransport::Connected(connection)) = self.transport.as_mut() else {
            return Err(ProviderError::Conflict(
                "after confirmation original connection absent",
            ));
        };
        let response = self.response.as_ref().ok_or(ProviderError::Conflict(
            "after confirmation original response absent",
        ))?;
        if let Some(storage) = storage {
            storage.authenticate_actual_inputs(connection, response, &[after])?;
        }
        let authority = connection.provider_authority()?.clone();
        let plan = confirmation_frames::confirmation_plan(
            &authority,
            response,
            receipt,
            after,
            maximum_after,
        )?;
        self.windows = plan.windows;
        self.contents = plan.contents;
        self.chunk = plan.chunk;
        self.next_sequence = plan.next_sequence;
        self.charged_bytes = plan.charged_bytes;
        // The selected SDK policy validates each original on preparation; all
        // future windows and the response stay owned if a callback unwinds.
        for window in &self.windows {
            for original in window {
                connection.preflight_original_confirmation_frame(original_poll, original)?;
            }
        }
        connection
            .preflight_original_confirmation_plan(original_poll, self.windows.iter().flatten())?;
        self.records
            .try_reserve_exact(self.windows.len())
            .map_err(|_| ProviderError::ResourceExhausted("after confirmation record slots"))?;
        if let Some(storage) = storage {
            self.reconcile_storage_data(storage)?;
        }
        self.prepare_next(storage)?;
        if let Some(storage) = storage {
            self.reconcile_storage_data(storage)?;
        }
        self.state = PrefixState::Prepared;
        Ok(())
    }

    fn prepare_next(
        &mut self,
        storage: Option<&OriginalContinuationPrefixStorageData>,
    ) -> Result<(), ProviderError> {
        let originals = self.windows.pop_front().ok_or(ProviderError::Conflict(
            "after confirmation next window absent",
        ))?;
        let Some(CaptureTransport::Connected(connection)) = self.transport.take() else {
            return Err(ProviderError::Conflict(
                "after confirmation transport already borrowed",
            ));
        };
        self.transport = Some(CaptureTransport::Prepared(
            connection.unprepared_exchange(originals),
        ));
        let Some(CaptureTransport::Prepared(exchange)) = self.transport.as_mut() else {
            return Err(ProviderError::Conflict(
                "after confirmation prepared window absent",
            ));
        };
        if let Some(storage) = storage {
            exchange.reconcile_original_continuation_window_storage_data(storage)?;
        }
        exchange.prepare_in_place()?;
        if let Some(storage) = storage {
            exchange.reconcile_original_continuation_window_storage_data(storage)?;
        }
        Ok(())
    }

    pub(crate) fn publish(&mut self) -> Result<(), ProviderError> {
        if self.state != PrefixState::Prepared {
            return Err(ProviderError::Conflict("after confirmation not prepared"));
        }
        self.state = PrefixState::Publishing;
        let result = self.publish_once(None);
        self.state = if result.is_ok() {
            PrefixState::Complete
        } else {
            PrefixState::Failed
        };
        result
    }

    pub(crate) fn publish_with_storage_data(
        &mut self,
        storage: &OriginalContinuationPrefixStorageData,
    ) -> Result<(), ProviderError> {
        if self.state != PrefixState::Prepared
            || storage.kind != OriginalContinuationPrefixKind::AfterConfirmation
        {
            return Err(ProviderError::Conflict(
                "confirmation quoted publication phase",
            ));
        }
        self.state = PrefixState::Publishing;
        let result = self
            .reconcile_storage_data(storage)
            .and_then(|()| self.publish_once(Some(storage)));
        self.state = if result.is_ok() {
            PrefixState::Complete
        } else {
            PrefixState::Failed
        };
        result
    }

    fn publish_once(
        &mut self,
        storage: Option<&OriginalContinuationPrefixStorageData>,
    ) -> Result<(), ProviderError> {
        loop {
            let Some(CaptureTransport::Prepared(exchange)) = self.transport.as_mut() else {
                return Err(ProviderError::Conflict(
                    "after confirmation original window absent",
                ));
            };
            let contents = &self.contents;
            let chunk = self.chunk;
            exchange.publish(&mut |original, received| {
                validate_ack(contents, chunk, original, received)
            })?;
            let Some(CaptureTransport::Prepared(exchange)) = self.transport.take() else {
                return Err(ProviderError::Conflict(
                    "after confirmation completed window absent",
                ));
            };
            let (connection, record) = exchange.into_parts();
            self.records.push(record);
            self.transport = Some(CaptureTransport::Connected(connection));
            if let Some(storage) = storage {
                self.reconcile_storage_data(storage)?;
            }
            if self.windows.is_empty() {
                return Ok(());
            }
            self.prepare_next(storage)?;
        }
    }

    fn reconcile_storage_data(
        &self,
        storage: &OriginalContinuationPrefixStorageData,
    ) -> Result<(), ProviderError> {
        let active = match self.transport.as_ref() {
            Some(CaptureTransport::Prepared(exchange)) => Some(exchange.record()),
            _ => None,
        };
        let originals = self
            .windows
            .iter()
            .map(Vec::len)
            .chain(self.records.iter().map(|record| record.originals().len()))
            .chain(active.map(|record| record.originals().len()))
            .try_fold(0usize, |sum, count| sum.checked_add(count))
            .ok_or(ProviderError::ResourceExhausted("quoted prefix population"))?;
        storage.reconcile_window_population_data(
            self.windows.len(),
            self.records.len(),
            active.is_some(),
            originals,
        )?;
        let mut observer = crate::retained_metadata::MetadataObserver::new();
        let response = self
            .response
            .as_ref()
            .ok_or(ProviderError::Conflict("confirmation response absent"))?;
        observer.observe(response)?;
        observe_prefix_owners(
            &self.transport,
            &self.windows,
            &self.records,
            &self.contents,
            &mut observer,
        )?;
        storage.reconcile_owner_metadata_data(&observer.finish())
    }

    pub(crate) fn take_completed_connection(&mut self) -> Result<Connection<S>, ProviderError> {
        if self.state != PrefixState::Complete {
            return Err(ProviderError::Conflict("after confirmation incomplete"));
        }
        match self.transport.take() {
            Some(CaptureTransport::Connected(connection)) => Ok(connection),
            original => {
                self.transport = original;
                Err(ProviderError::Conflict(
                    "after confirmation original already moved",
                ))
            }
        }
    }

    pub(crate) fn records(&self) -> &[ExchangeRecord] {
        &self.records
    }
    pub(crate) fn next_sequence(&self) -> u64 {
        self.next_sequence
    }
    pub(crate) fn charged_bytes(&self) -> usize {
        self.charged_bytes
    }
}
