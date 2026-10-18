//! Retains completed map entries and every concrete current-row child attempt.

use super::*;
use crate::protocol_snapshot::owned11::typed::Native17Build;

#[derive(Default)]
pub(crate) struct CurrentOriginals17ReadAttempt {
    started: bool,
    finished: bool,
    completed: Option<CurrentOriginals17Data>,
    values: BTreeMap<Id, (HashRef, PacketControlReply)>,
    pending: OriginalRow,
}

#[derive(Default)]
struct OriginalRow {
    id: <Id as Native17Build>::Attempt,
    hash: <HashRef as Native17Build>::Attempt,
    body: <Map<String, Value> as Native17Build>::Attempt,
    evidence: <Vec<(ContentRef, Vec<u8>)> as Native17Build>::Attempt,
}

impl CurrentOriginals17ReadAttempt {
    pub(crate) fn rows_data(&self) -> &BTreeMap<Id, (HashRef, PacketControlReply)> {
        self.completed
            .as_ref()
            .map_or(&self.values, |completed| &completed.0)
    }

    pub(crate) fn observe_attempt_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        if let Some(completed) = &self.completed {
            observer.observe(completed)?;
        }
        if self.started && !self.finished {
            observer.tree::<Id, (HashRef, PacketControlReply)>(self.values.len())?;
            for (id, (hash, reply)) in &self.values {
                observer.observe(id)?;
                observer.observe(hash)?;
                observer.observe(&reply.body)?;
                observer.observe(&reply.evidence)?;
            }
        }
        Id::observe_attempt_data(&self.pending.id, observer)?;
        HashRef::observe_attempt_data(&self.pending.hash, observer)?;
        Map::<String, Value>::observe_attempt_data(&self.pending.body, observer)?;
        Vec::<(ContentRef, Vec<u8>)>::observe_attempt_data(&self.pending.evidence, observer)
    }

    pub(crate) fn take_completed_data(&mut self) -> Option<CurrentOriginals17Data> {
        self.completed.take()
    }

    pub(crate) fn read_into(
        &mut self,
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<(), ProviderError> {
        if self.started {
            return Err(ProviderError::Conflict(
                "native17 originals read already attempted",
            ));
        }
        self.started = true;
        let count = ledger.row_aligned(
            MetadataRecordKind::Tree,
            size_of::<Id>() + size_of::<(HashRef, PacketControlReply)>(),
            align_of::<Id>().max(align_of::<(HashRef, PacketControlReply)>()),
        )?;
        ledger.native17_target_tree_data::<Id, (HashRef, PacketControlReply)>(count)?;
        let mut rows = Fields::array(input)?;
        let mut previous = None;
        let mut actual = 0usize;
        while let Some(row) = rows.next()? {
            actual = actual
                .checked_add(1)
                .filter(|count_so_far| *count_so_far <= count)
                .ok_or_else(invalid)?;
            let mut fields = Fields::array(row)?;
            let id = fields.next()?.ok_or_else(invalid)?;
            let text = plain_string(id)?;
            if previous.is_some_and(|previous| previous >= text) {
                return Err(invalid());
            }
            previous = Some(text);
            if build {
                Id::read_into_data(id, ledger, &mut self.pending.id)?;
            } else {
                Id::preflight_data(id, ledger)?;
            }
            let hash = fields.next()?.ok_or_else(invalid)?;
            if build {
                HashRef::read_into_data(hash, ledger, &mut self.pending.hash)?;
            } else {
                HashRef::preflight_data(hash, ledger)?;
            }
            let body = fields.next()?.ok_or_else(invalid)?;
            if build {
                Map::<String, Value>::read_into_data(body, ledger, &mut self.pending.body)?;
            } else {
                Map::<String, Value>::preflight_data(body, ledger)?;
            }
            let evidence = fields.next()?.ok_or_else(invalid)?;
            if build {
                Vec::<(ContentRef, Vec<u8>)>::read_into_data(
                    evidence,
                    ledger,
                    &mut self.pending.evidence,
                )?;
            } else {
                Vec::<(ContentRef, Vec<u8>)>::preflight_data(evidence, ledger)?;
            }
            fields.finish()?;
            if build {
                if Id::output_data(&self.pending.id).is_none()
                    || HashRef::output_data(&self.pending.hash).is_none()
                    || Map::<String, Value>::output_data(&self.pending.body).is_none()
                    || Vec::<(ContentRef, Vec<u8>)>::output_data(&self.pending.evidence).is_none()
                {
                    return Err(invalid());
                }
                // All children are checked before moving any child. The map
                // takes ownership without another fallible parser operation.
                self.values.insert(
                    Id::take_output_data(&mut self.pending.id).ok_or_else(invalid)?,
                    (
                        HashRef::take_output_data(&mut self.pending.hash).ok_or_else(invalid)?,
                        PacketControlReply {
                            body: Map::<String, Value>::take_output_data(&mut self.pending.body)
                                .ok_or_else(invalid)?,
                            evidence: Vec::<(ContentRef, Vec<u8>)>::take_output_data(
                                &mut self.pending.evidence,
                            )
                            .ok_or_else(invalid)?,
                        },
                    ),
                );
                self.pending = OriginalRow::default();
            }
        }
        if actual != count {
            return Err(invalid());
        }
        if build {
            self.completed = Some(CurrentOriginals17Data(std::mem::take(&mut self.values)));
            self.finished = true;
        }
        Ok(())
    }
}

#[derive(Default)]
pub(crate) struct CurrentContent17ReadAttempt {
    started: bool,
    finished: bool,
    completed: Option<CurrentContent17Data>,
    values: BTreeMap<ContentRef, Vec<u8>>,
    pending: ContentRow,
}

#[derive(Default)]
struct ContentRow {
    reference: <ContentRef as Native17Build>::Attempt,
    bytes: <Vec<u8> as Native17Build>::Attempt,
}

impl CurrentContent17ReadAttempt {
    pub(crate) fn rows_data(&self) -> &BTreeMap<ContentRef, Vec<u8>> {
        self.completed
            .as_ref()
            .map_or(&self.values, |completed| &completed.0)
    }

    pub(crate) fn pending_reference_data(&self) -> Option<&ContentRef> {
        ContentRef::output_data(&self.pending.reference)
    }

    pub(crate) fn observe_attempt_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        if let Some(completed) = &self.completed {
            observer.observe(completed)?;
        }
        if self.started && !self.finished {
            observer.observe(&self.values)?;
        }
        ContentRef::observe_attempt_data(&self.pending.reference, observer)?;
        Vec::<u8>::observe_attempt_data(&self.pending.bytes, observer)
    }

    pub(crate) fn take_completed_data(&mut self) -> Option<CurrentContent17Data> {
        self.completed.take()
    }

    pub(crate) fn read_into(
        &mut self,
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<(), ProviderError> {
        if self.started {
            return Err(ProviderError::Conflict(
                "native17 content read already attempted",
            ));
        }
        self.started = true;
        let count = ledger.row_aligned(
            MetadataRecordKind::Tree,
            size_of::<ContentRef>() + size_of::<Vec<u8>>(),
            align_of::<ContentRef>().max(align_of::<Vec<u8>>()),
        )?;
        ledger.native17_target_tree_data::<ContentRef, Vec<u8>>(count)?;
        let mut rows = Fields::array(input)?;
        let mut previous = None;
        let mut actual = 0usize;
        while let Some(row) = rows.next()? {
            actual = actual
                .checked_add(1)
                .filter(|count_so_far| *count_so_far <= count)
                .ok_or_else(invalid)?;
            let mut fields = Fields::array(row)?;
            let reference = fields.next()?.ok_or_else(invalid)?;
            let key = ContentKey::read(reference)?;
            if let Some(previous) = previous {
                if key.compare(previous)? != Ordering::Greater {
                    return Err(invalid());
                }
            }
            previous = Some(key);
            if build {
                ContentRef::read_into_data(reference, ledger, &mut self.pending.reference)?;
            } else {
                ContentRef::preflight_data(reference, ledger)?;
            }
            let bytes = fields.next()?.ok_or_else(invalid)?;
            if build {
                Vec::<u8>::read_into_data(bytes, ledger, &mut self.pending.bytes)?;
            } else {
                Vec::<u8>::preflight_data(bytes, ledger)?;
            }
            fields.finish()?;
            if build {
                if ContentRef::output_data(&self.pending.reference).is_none()
                    || Vec::<u8>::output_data(&self.pending.bytes).is_none()
                {
                    return Err(invalid());
                }
                self.values.insert(
                    ContentRef::take_output_data(&mut self.pending.reference)
                        .ok_or_else(invalid)?,
                    Vec::<u8>::take_output_data(&mut self.pending.bytes).ok_or_else(invalid)?,
                );
                self.pending = ContentRow::default();
            }
        }
        if actual != count {
            return Err(invalid());
        }
        if build {
            self.completed = Some(CurrentContent17Data(std::mem::take(&mut self.values)));
            self.finished = true;
        }
        Ok(())
    }
}
