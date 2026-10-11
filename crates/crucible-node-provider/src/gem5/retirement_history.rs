//! Reads original native preparation, prefix and private ACK bodies without effects.
//!
//! These operational records retain actual original receipt and partial-frame
//! bytes. They are not process images, complete live CPU state or continuation
//! authority. No Shutdown, Poll, ACK or native capture is issued by this reader.
//!
//! ```text
//! retirement-native.1 = actual Ready/session + prefixes + unresolved state + boundary
//! retirement-private-ack.1 = the separate bounded binary first-attempt journal
//! retirement-shutdown.1 = original first-write/reply counts and exact planned frame
//! ```

use serde::Serialize;

use super::*;

#[derive(Serialize)]
struct Shutdown<'a> {
    format: &'static str,
    version: u16,
    owner: &'a Id,
    incarnation: &'a Id,
    generation: U64,
    request: &'a [u8],
    written: usize,
    received: &'a [u8],
    acknowledged: bool,
}

#[derive(Serialize)]
struct History<'a> {
    format: &'static str,
    version: u16,
    owner: &'a Id,
    incarnation: &'a Id,
    generation: U64,
    boundary: &'a Gem5Boundary,
    prefixes: &'a BTreeMap<Id, Gem5Completion>,
    pending: &'a Option<Id>,
    last_acknowledged: &'a Option<Id>,
    unresolved: &'a Option<Gem5Run>,
    unresolved_capture: &'a Option<Id>,
    ready: (&'a ContentRef, &'a [u8]),
    session: (&'a ContentRef, &'a [u8]),
}

impl Gem5NativeProcess {
    /// Reads exact original operational bodies under separate finite record credits.
    ///
    /// The caller must retain these together with the actual capsule and common
    /// operation history. These bodies cannot authorize release or restoration.
    ///
    /// # Errors
    /// Refuses missing original preparation/private ACK custody, transferred
    /// handles, altered original bytes or exhausted selected body credits.
    pub fn retirement_history_records(
        &self,
        maximum_native_bytes: usize,
        maximum_ack_bytes: usize,
    ) -> Result<Vec<(ContentRef, Vec<u8>)>, ProviderError> {
        if self.child.is_none()
            || self.graceful_retirement_transferred
            || maximum_native_bytes == 0
            || maximum_native_bytes > 64 * 1024 * 1024
            || maximum_ack_bytes == 0
            || maximum_ack_bytes > 128 * 1024 * 1024
            || self.source_image.is_some()
        {
            return Err(ProviderError::Conflict(
                "original native retirement history scope differs",
            ));
        }
        let Gem5PreparationCustody::Validated(original) = &self.preparation else {
            return Err(ProviderError::Correlation(
                "complete original Ready/session is absent",
            ));
        };
        let ready = original.packet();
        let session = original.transcript();
        ready.0.verify(ready.1)?;
        session.0.verify(session.1)?;
        let acknowledgements =
            self.acknowledgement_history
                .as_ref()
                .ok_or(ProviderError::Correlation(
                    "prebirth original private ACK journal is absent",
                ))?;
        let history = History {
            format: "crucible.gem5.retirement-native-history",
            version: 1,
            owner: &self.launch.owner,
            incarnation: &self.launch.incarnation,
            generation: self.launch.generation,
            boundary: &self.boundary,
            prefixes: &self.completed,
            pending: &self.pending,
            last_acknowledged: &self.last_acknowledged,
            unresolved: &self.unresolved,
            unresolved_capture: &self.unresolved_capture,
            ready,
            session,
        };
        serde_json::to_writer(Credit(maximum_native_bytes), &history).map_err(|_| {
            ProviderError::ResourceExhausted("original native retirement record credit")
        })?;
        let native = serde_json::to_vec(&history)
            .map_err(|_| ProviderError::Frame("original native history serialization"))?;
        let acknowledgements = acknowledgements.encode_retirement_history(maximum_ack_bytes)?;
        let mut bodies = Vec::new();
        bodies
            .try_reserve_exact(2)
            .map_err(|_| ProviderError::ResourceExhausted("native retirement body holders"))?;
        for (bytes, media) in [
            (native, "application/json"),
            (acknowledgements, "application/octet-stream"),
        ] {
            let reference = crucible_node_contract::canonical::content_ref(&bytes, media)?;
            bodies.push((reference, bytes));
        }
        Ok(bodies)
    }

    /// Borrows and encodes the one actual original Shutdown exchange without resending.
    ///
    /// An accepted reply is independent of actual reaping and group emptiness;
    /// both must remain conjuncts of the owning supervisor's later verifier.
    ///
    /// # Errors
    /// Refuses missing original graceful intent/exchange or exhausted record credit.
    pub fn retirement_shutdown_record(
        &self,
        maximum_bytes: usize,
    ) -> Result<(ContentRef, Vec<u8>), ProviderError> {
        if !self.graceful_retirement_requested || maximum_bytes == 0 || maximum_bytes > 64 * 1024 {
            return Err(ProviderError::Conflict(
                "original graceful Shutdown history scope differs",
            ));
        }
        let exchange = self
            .quarantine
            .as_ref()
            .and_then(|state| state.shutdown.as_ref())
            .ok_or(ProviderError::Correlation(
                "original Shutdown exchange is absent",
            ))?;
        let record = Shutdown {
            format: "crucible.gem5.retirement-shutdown-history",
            version: 1,
            owner: &self.launch.owner,
            incarnation: &self.launch.incarnation,
            generation: self.launch.generation,
            request: b"\0\0\0\x13{\"kind\":\"shutdown\"}",
            written: exchange.written_bytes(),
            received: exchange.received_bytes(),
            acknowledged: exchange.acknowledged(),
        };
        serde_json::to_writer(Credit(maximum_bytes), &record)
            .map_err(|_| ProviderError::ResourceExhausted("original Shutdown body credit"))?;
        let bytes = serde_json::to_vec(&record)
            .map_err(|_| ProviderError::Frame("original Shutdown history serialization"))?;
        let reference = crucible_node_contract::canonical::content_ref(&bytes, "application/json")?;
        Ok((reference, bytes))
    }
}

impl Gem5NativeCustody {
    /// Rechecks actual original prefixes and first-attempt ACK bytes after reaping.
    ///
    /// The expected identities must come from a separately authenticated owning
    /// original history holder. This method reads the same actual capsule and
    /// returns no release permit. Pending/uncertain native attempts remain held.
    ///
    /// # Errors
    /// Refuses nonoriginal custody, uncertain Shutdown, incomplete private ACKs,
    /// changed native/history bodies, absent kernel proof or finite body bounds.
    pub fn authenticate_original_retirement_histories(
        &mut self,
        native_reference: &ContentRef,
        acknowledgement_reference: &ContentRef,
    ) -> Result<(), ProviderError> {
        if !self.graceful_retirement_requested
            || self.source_image.is_some()
            || self.pending.is_some()
            || self.unresolved.is_some()
            || self.unresolved_capture.is_some()
        {
            return Err(ProviderError::Conflict(
                "original retirement capsule scope differs",
            ));
        }
        let state = self.quarantine.as_ref().ok_or(ProviderError::Correlation(
            "original graceful Shutdown holder absent",
        ))?;
        if state
            .shutdown
            .as_ref()
            .is_none_or(|exchange| !exchange.acknowledged())
            || state.census_diagnostic().is_some()
        {
            return Err(ProviderError::Conflict(
                "original graceful Shutdown remains uncertain",
            ));
        }
        let Gem5PreparationCustody::Validated(original) = &self.preparation else {
            return Err(ProviderError::Correlation(
                "original complete Ready/session absent",
            ));
        };
        let ready = original.packet();
        let session = original.transcript();
        ready.0.verify(ready.1)?;
        session.0.verify(session.1)?;
        let acknowledgements =
            self.acknowledgement_history
                .as_ref()
                .ok_or(ProviderError::Correlation(
                    "original prebirth private ACK history absent",
                ))?;
        if acknowledgements.exchanges().len() != self.completed.len()
            || acknowledgements.exchanges().iter().any(|exchange| {
                !exchange.acknowledged()
                    || exchange.written_bytes() != exchange.request_frame().len()
                    || exchange.operation().is_none_or(|operation| {
                        self.completed.get(operation).is_none_or(|completion| {
                            &completion.operation != operation
                                || &completion.original.operation != operation
                        })
                    })
            })
            || acknowledgements
                .exchanges()
                .last()
                .and_then(|exchange| exchange.operation())
                != self.last_acknowledged.as_ref()
        {
            return Err(ProviderError::Conflict(
                "original native prefix/private ACK association differs",
            ));
        }
        let history = History {
            format: "crucible.gem5.retirement-native-history",
            version: 1,
            owner: &self.launch.owner,
            incarnation: &self.launch.incarnation,
            generation: self.launch.generation,
            boundary: self.boundary.as_ref().ok_or(ProviderError::Correlation(
                "original native boundary absent",
            ))?,
            prefixes: &self.completed,
            pending: &self.pending,
            last_acknowledged: &self.last_acknowledged,
            unresolved: &self.unresolved,
            unresolved_capture: &self.unresolved_capture,
            ready,
            session,
        };
        let mut native = retirement_digest::OriginalBodyDigest::new(
            native_reference,
            "application/json",
            64 * 1024 * 1024,
        )?;
        serde_json::to_writer(&mut native, &history)
            .map_err(|_| ProviderError::Correlation("actual original native history differs"))?;
        native.finish()?;
        let mut acknowledgement = retirement_digest::OriginalBodyDigest::new(
            acknowledgement_reference,
            "application/octet-stream",
            128 * 1024 * 1024,
        )?;
        acknowledgements.write_retirement_history(&mut acknowledgement)?;
        acknowledgement.finish()?;
        if self.poll_reclamation()?.is_none() {
            return Err(ProviderError::Conflict(
                "actual original group is not reclaimed",
            ));
        }
        Ok(())
    }

    /// Retains the actual original Shutdown exchange from this same native capsule.
    ///
    /// This body is a protocol fact, independently of the actual kernel proof.
    /// It cannot authorize a release by itself or repeat any native request.
    ///
    /// # Errors
    /// Refuses an absent original first attempt, another cleanup purpose or credit.
    pub fn original_retirement_shutdown_record(
        &self,
        maximum_bytes: usize,
    ) -> Result<(ContentRef, Vec<u8>), ProviderError> {
        if !self.graceful_retirement_requested || maximum_bytes == 0 || maximum_bytes > 64 * 1024 {
            return Err(ProviderError::Conflict(
                "original Shutdown history scope differs",
            ));
        }
        let exchange = self
            .quarantine
            .as_ref()
            .and_then(|state| state.shutdown.as_ref())
            .ok_or(ProviderError::Correlation(
                "original Shutdown exchange absent",
            ))?;
        let record = Shutdown {
            format: "crucible.gem5.retirement-shutdown-history",
            version: 1,
            owner: &self.launch.owner,
            incarnation: &self.launch.incarnation,
            generation: self.launch.generation,
            request: b"\0\0\0\x13{\"kind\":\"shutdown\"}",
            written: exchange.written_bytes(),
            received: exchange.received_bytes(),
            acknowledged: exchange.acknowledged(),
        };
        serde_json::to_writer(Credit(maximum_bytes), &record)
            .map_err(|_| ProviderError::ResourceExhausted("original Shutdown record credit"))?;
        let bytes = serde_json::to_vec(&record)
            .map_err(|_| ProviderError::Frame("original Shutdown history serialization"))?;
        let reference = crucible_node_contract::canonical::content_ref(&bytes, "application/json")?;
        Ok((reference, bytes))
    }
}

struct Credit(usize);

impl Write for Credit {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self.0.checked_sub(bytes.len()).ok_or_else(|| {
            std::io::Error::other("original native history record credit exhausted")
        })?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
