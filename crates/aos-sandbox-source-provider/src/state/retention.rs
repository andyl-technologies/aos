//! Bounded catalog, request, lease-lineage, and identity-floor retention.

use super::*;

impl<'a> ProviderLedgerV1<'a> {
    /// Collects a bounded batch of unreferenced catalogs below the durable floor.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLedgerError`] for a stale journal, retained reference,
    /// invalid bound, graph validation failure, or commit failure.
    pub fn collect_catalog_floor_residue(
        &mut self,
        maximum_records: usize,
    ) -> Result<usize, ProviderLedgerError> {
        self.ensure_open()?;
        if maximum_records == 0 || maximum_records > crate::limits::MAXIMUM_TRANSACTION_RECORDS {
            return Err(ProviderLedgerError::LimitExceeded(
                "catalog GC transaction records",
            ));
        }
        let floor = self.configuration.catalog_floor_generation;
        let generations: Vec<_> = self
            .recovered
            .catalog_history
            .keys()
            .copied()
            .filter(|generation| *generation < floor)
            .take(maximum_records)
            .collect();
        if generations.is_empty() {
            return Ok(0);
        }
        if self
            .recovered
            .acquisitions
            .values()
            .any(|acquisition| generations.contains(&acquisition.catalog_generation))
            || retained_inventory_catalog_below(&self.recovered.attempts, floor)?
        {
            return Err(ProviderLedgerError::InvalidTransition(
                "catalog GC residue remains referenced",
            ));
        }
        let records = generations
            .iter()
            .map(|generation| {
                (
                    crate::format::catalog_key(
                        self.recovered.authority.provider.authority_id(),
                        *generation,
                    ),
                    None,
                )
            })
            .collect();
        crate::transaction::commit_mutations(self, b"collect-catalog-floor-residue", records)?;
        for generation in &generations {
            self.recovered.catalog_history.remove(generation);
        }
        Ok(generations.len())
    }

    /// Compacts unreferenced dead-session responses into bounded request tombstones.
    ///
    /// Each tombstone retains the holder-scoped request identity, exact request,
    /// typed-request, intent, attempt and response digests, and both durable
    /// sequences. Exact signed frames are dropped only after a complete graph
    /// trace proves that no acquisition, release, current holder head, or
    /// immutable session pointer still requires the artifact. At most six
    /// records are rewritten atomically, matching the closed transaction cap.
    /// A later call atomically advances the historical session's durable
    /// request and response floors and deletes only the exact retired prefix.
    /// The immutable authenticated session chain then rejects every replay
    /// below those floors without retaining the large tombstone records.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLedgerError`] for a zero or excessive bound, stale
    /// journal authority, graph corruption, or commit failure.
    pub fn compact_request_tombstones(
        &mut self,
        maximum_records: usize,
    ) -> Result<usize, ProviderLedgerError> {
        self.ensure_open()?;
        if maximum_records == 0 || maximum_records > crate::limits::MAXIMUM_TRANSACTION_RECORDS {
            return Err(ProviderLedgerError::LimitExceeded(
                "request tombstone transaction records",
            ));
        }
        let snapshot = self.journal.snapshot()?;
        self.journal
            .validate_source_provider_authority_snapshot(&snapshot)?;
        let referenced = |digest: ObjectDigest| {
            self.recovered.acquisitions.values().any(|acquisition| {
                acquisition.effect_attempt_digest == digest
                    || acquisition.current_attempt_digest == digest
                    || acquisition.lease_attempt_digest == Some(digest)
                    || acquisition
                        .lease_history
                        .iter()
                        .any(|lineage| lineage.attempt_digest == digest)
            }) || self.recovered.releases.values().any(|release| {
                release.effect_attempt_digest == digest || release.attempt_digest == digest
            }) || self
                .recovered
                .attempts
                .values()
                .any(|attempt| attempt.recovery_predecessor_attempt_digest == Some(digest))
                || self
                    .recovered
                    .sessions
                    .values()
                    .any(|session| session.pending_attempt_digest == Some(digest))
                || self
                    .recovered
                    .session_history
                    .values()
                    .any(|session| session.pending_attempt_digest == Some(digest))
        };
        let historical_identities: Vec<_> =
            self.recovered.session_history.keys().copied().collect();
        for identity in historical_identities {
            let retained = self
                .recovered
                .session_history
                .get(&identity)
                .cloned()
                .ok_or(ProviderLedgerError::Corrupt("missing historical session"))?;
            let is_current = self
                .recovered
                .sessions
                .get(&(identity.0, identity.1))
                .is_some_and(|session| session.session_binding == identity.2);
            if is_current || retained.pending_attempt_digest.is_some() {
                continue;
            }
            let mut request_floor = retained.request_sequence_floor;
            let mut response_floor = retained.response_sequence_floor;
            let mut consumed = Vec::new();
            while consumed.len().saturating_add(1) < maximum_records {
                let candidate = self.recovered.attempts.iter().find(|(_, attempt)| {
                    attempt.provider.authority_id() == identity.0
                        && attempt.holder.authority_id() == identity.1
                        && attempt.session_binding == identity.2
                        && attempt.request_sequence == request_floor
                });
                let Some((key, attempt)) = candidate else {
                    break;
                };
                if attempt.state != crate::ProviderAttemptStateV1::Retired
                    || referenced(attempt.attempt_digest)
                    || attempt
                        .response_sequence
                        .is_some_and(|sequence| sequence != response_floor)
                {
                    break;
                }
                request_floor =
                    request_floor
                        .checked_add(1)
                        .ok_or(ProviderLedgerError::InvalidTransition(
                            "request sequence floor exhausted",
                        ))?;
                if attempt.response_sequence.is_some() {
                    response_floor = response_floor.checked_add(1).ok_or(
                        ProviderLedgerError::InvalidTransition("response sequence floor exhausted"),
                    )?;
                }
                consumed.push((key.clone(), attempt.attempt_digest));
            }
            if consumed.is_empty() {
                continue;
            }
            let mut advanced = retained;
            advanced.revision =
                advanced
                    .revision
                    .checked_add(1)
                    .ok_or(ProviderLedgerError::InvalidTransition(
                        "session revision exhausted",
                    ))?;
            advanced.request_sequence_floor = request_floor;
            advanced.response_sequence_floor = response_floor;
            if advanced
                .last_completed_attempt_digest
                .is_some_and(|digest| consumed.iter().any(|(_, value)| *value == digest))
            {
                advanced.last_completed_attempt_digest = None;
            }
            let mut mutations = vec![(
                crate::format::session_history_key(identity.0, identity.1, identity.2),
                Some(crate::format::encode_session_history(&advanced)),
            )];
            mutations.extend(
                consumed
                    .iter()
                    .map(|(key, _)| (crate::format::attempt_key(key), None)),
            );
            crate::transaction::commit_mutations(
                self,
                b"advance-request-sequence-floor",
                mutations,
            )?;
            let count = consumed.len();
            self.recovered.session_history.insert(identity, advanced);
            for (key, _) in consumed {
                self.recovered.attempts.remove(&key);
            }
            return Ok(count);
        }
        let mut compacted = Vec::new();
        for (key, attempt) in &self.recovered.attempts {
            let current_binding = self
                .recovered
                .sessions
                .get(&(
                    attempt.provider.authority_id(),
                    attempt.holder.authority_id(),
                ))
                .map(|session| session.session_binding);
            if compacted.len() == maximum_records {
                break;
            }
            if attempt.state != crate::ProviderAttemptStateV1::Completed
                || current_binding == Some(attempt.session_binding)
                || referenced(attempt.attempt_digest)
                || attempt.response_sequence.is_none()
            {
                continue;
            }
            let mut tombstone = attempt.clone();
            tombstone.revision =
                tombstone
                    .revision
                    .checked_add(1)
                    .ok_or(ProviderLedgerError::InvalidTransition(
                        "attempt revision exhausted",
                    ))?;
            tombstone.state = crate::ProviderAttemptStateV1::Retired;
            tombstone.signed_request.clear();
            tombstone.completed_response.clear();
            compacted.push((key.clone(), tombstone));
        }
        if compacted.is_empty() {
            return Ok(0);
        }
        crate::transaction::commit_records(
            self,
            b"compact-request-tombstones",
            compacted
                .iter()
                .map(|(key, value)| {
                    (
                        crate::format::attempt_key(key),
                        crate::format::encode_attempt(value),
                    )
                })
                .collect(),
        )?;
        let count = compacted.len();
        for (key, value) in compacted {
            self.recovered.attempts.insert(key, value);
        }
        self.refresh_recovery_work();
        Ok(count)
    }

    /// Compacts released lease chains after they leave the retained inventory window.
    ///
    /// The acquisition identity, normalized intent, current lease digest,
    /// resource selection, backend evidence, release link, and exact request
    /// artifacts remain durable. Only predecessor lease-vector capacity, the
    /// duplicate current lease bytes, and obsolete reopen material are
    /// reclaimed. Consequently acquisition-ID and request-ID reuse remains
    /// detectable while future rebind capacity is released.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLedgerError`] for an invalid bound, stale authority,
    /// a release still inside the inventory window, graph corruption, or a
    /// failed protected commit.
    pub fn compact_released_lease_lineages(
        &mut self,
        maximum_records: usize,
    ) -> Result<usize, ProviderLedgerError> {
        self.ensure_open()?;
        if maximum_records == 0 || maximum_records > crate::limits::MAXIMUM_TRANSACTION_RECORDS {
            return Err(ProviderLedgerError::LimitExceeded(
                "released lease compaction records",
            ));
        }
        let retained_tombstones = self
            .configuration
            .limits()
            .maximum_inventory_tombstones_per_holder();
        let mut compacted = Vec::new();
        for (key, acquisition) in &self.recovered.acquisitions {
            if compacted
                .len()
                .checked_add(1)
                .and_then(|count| count.checked_mul(2))
                .is_none_or(|records| records > maximum_records)
                || acquisition.state != crate::ProviderAcquisitionStateV1::Released
                || (acquisition.lease_history.is_empty()
                    && acquisition.signed_lease.is_empty()
                    && acquisition.reopen_identity.is_none())
            {
                continue;
            }
            let release = self
                .recovered
                .releases
                .get(&crate::model::ReleaseKeyV1 {
                    provider_id: key.provider_id,
                    holder_id: key.holder_id,
                    acquisition_id: key.acquisition_id,
                })
                .ok_or(ProviderLedgerError::Corrupt(
                    "released acquisition tombstone",
                ))?;
            let newer = self
                .recovered
                .releases
                .values()
                .filter(|candidate| {
                    candidate.holder.authority_id() == key.holder_id
                        && candidate.state == crate::ProviderReleaseStateV1::Tombstone
                        && candidate.release_generation > release.release_generation
                })
                .count();
            if newer < retained_tombstones {
                continue;
            }
            let mut value = acquisition.clone();
            value.revision =
                value
                    .revision
                    .checked_add(1)
                    .ok_or(ProviderLedgerError::InvalidTransition(
                        "acquisition revision exhausted",
                    ))?;
            value.lease_history.clear();
            value.signed_lease.clear();
            value.reopen_identity = None;
            let acquisition_bytes = crate::format::encode_acquisition(&value);
            let release_key = crate::model::ReleaseKeyV1 {
                provider_id: key.provider_id,
                holder_id: key.holder_id,
                acquisition_id: key.acquisition_id,
            };
            let mut release_value = release.clone();
            release_value.revision = release_value.revision.checked_add(1).ok_or(
                ProviderLedgerError::InvalidTransition("release revision exhausted"),
            )?;
            release_value.acquisition_record_digest =
                crate::format::record_digest(&acquisition_bytes)?;
            compacted.push((
                key.clone(),
                value,
                acquisition_bytes,
                release_key,
                release_value,
            ));
        }
        if compacted.is_empty() {
            return Ok(0);
        }
        crate::transaction::commit_records(
            self,
            b"compact-released-lease-lineages",
            compacted
                .iter()
                .flat_map(|(_, _, acquisition_bytes, release_key, release_value)| {
                    [
                        (
                            crate::format::acquisition_key(&crate::model::AcquisitionKeyV1 {
                                provider_id: release_key.provider_id,
                                holder_id: release_key.holder_id,
                                acquisition_id: release_key.acquisition_id,
                            }),
                            acquisition_bytes.clone(),
                        ),
                        (
                            crate::format::release_key(release_key),
                            crate::format::encode_release(release_value),
                        ),
                    ]
                })
                .collect(),
        )?;
        let count = compacted.len();
        for (key, value, _, release_key, release_value) in compacted {
            self.recovered.acquisitions.insert(key, value);
            self.recovered.releases.insert(release_key, release_value);
        }
        Ok(count)
    }

    /// Advances one holder's exact acquisition non-reuse floor and removes old lineages.
    ///
    /// Acquisition IDs are version-2 commitments to holder authority plus the
    /// monotone acquisition sequence. Therefore deleting the exact released
    /// acquisition and Release records cannot permit reuse below the durable
    /// floor. Only a contiguous prefix outside the inventory tombstone window
    /// is collected, and the holder head plus each two-record lineage are
    /// committed atomically within the six-record ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLedgerError`] for an invalid record bound, stale
    /// journal authority, a broken contiguous lineage, or failed commit.
    pub fn advance_acquisition_identity_floor(
        &mut self,
        holder_id: [u8; 16],
        maximum_records: usize,
    ) -> Result<usize, ProviderLedgerError> {
        self.ensure_open()?;
        if holder_id == [0; 16]
            || maximum_records < 2
            || maximum_records > crate::limits::MAXIMUM_TRANSACTION_RECORDS
        {
            return Err(ProviderLedgerError::LimitExceeded(
                "acquisition identity-floor transaction records",
            ));
        }
        let session_key_value = (self.recovered.authority.provider.authority_id(), holder_id);
        let mut session = self
            .recovered
            .sessions
            .get(&session_key_value)
            .cloned()
            .ok_or(ProviderLedgerError::InvalidTransition(
                "acquisition identity floor requires current holder",
            ))?;
        if session.pending_attempt_digest.is_some() {
            return Err(ProviderLedgerError::InvalidTransition(
                "acquisition identity floor requires idle holder",
            ));
        }
        let retained_tombstones = self
            .configuration
            .limits()
            .maximum_inventory_tombstones_per_holder();
        // Session and its same-binding history head are one atomic pair.
        let maximum_lineages = (maximum_records - 2) / 2;
        let mut collected = Vec::new();
        while collected.len() < maximum_lineages {
            let sequence = session.acquisition_sequence_floor;
            if sequence >= session.next_acquisition_sequence {
                break;
            }
            let Some((acquisition_key, acquisition)) =
                self.recovered.acquisitions.iter().find(|(_, value)| {
                    value.holder.authority_id() == holder_id
                        && value.acquisition_sequence == sequence
                })
            else {
                // A gap was consumed by the same holder at another provider.
                // The authenticated local high-water mark makes it permanently
                // non-reusable even though this graph retains no local lineage.
                session.acquisition_sequence_floor = self
                    .recovered
                    .acquisitions
                    .values()
                    .filter(|candidate| {
                        candidate.holder.authority_id() == holder_id
                            && candidate.acquisition_sequence > sequence
                    })
                    .map(|candidate| candidate.acquisition_sequence)
                    .min()
                    .unwrap_or(session.next_acquisition_sequence);
                continue;
            };
            if acquisition.state != crate::ProviderAcquisitionStateV1::Released {
                break;
            }
            let release_key = crate::model::ReleaseKeyV1 {
                provider_id: acquisition_key.provider_id,
                holder_id: acquisition_key.holder_id,
                acquisition_id: acquisition_key.acquisition_id,
            };
            let release =
                self.recovered
                    .releases
                    .get(&release_key)
                    .ok_or(ProviderLedgerError::Corrupt(
                        "identity-floor release lineage",
                    ))?;
            let newer = self
                .recovered
                .releases
                .values()
                .filter(|candidate| {
                    candidate.holder.authority_id() == holder_id
                        && candidate.state == crate::ProviderReleaseStateV1::Tombstone
                        && candidate.release_generation > release.release_generation
                })
                .count();
            if newer < retained_tombstones {
                break;
            }
            collected.push((acquisition_key.clone(), release_key));
            session.acquisition_sequence_floor =
                session.acquisition_sequence_floor.checked_add(1).ok_or(
                    ProviderLedgerError::InvalidTransition("acquisition identity floor exhausted"),
                )?;
        }
        let floor_advanced = session.acquisition_sequence_floor
            != self
                .recovered
                .sessions
                .get(&session_key_value)
                .ok_or(ProviderLedgerError::Corrupt("missing holder floor"))?
                .acquisition_sequence_floor;
        if collected.is_empty() && !floor_advanced {
            return Ok(0);
        }
        session.revision =
            session
                .revision
                .checked_add(1)
                .ok_or(ProviderLedgerError::InvalidTransition(
                    "session revision exhausted",
                ))?;
        let mut mutations = vec![
            (
                crate::format::session_key(session_key_value.0, session_key_value.1),
                Some(crate::format::encode_session(&session)),
            ),
            (
                crate::format::session_history_key(
                    session_key_value.0,
                    session_key_value.1,
                    session.session_binding,
                ),
                Some(crate::format::encode_session_history(&session)),
            ),
        ];
        for (acquisition_key, release_key) in &collected {
            mutations.push((crate::format::acquisition_key(acquisition_key), None));
            mutations.push((crate::format::release_key(release_key), None));
        }
        crate::transaction::commit_mutations(
            self,
            b"advance-acquisition-identity-floor",
            mutations,
        )?;
        self.recovered
            .sessions
            .insert(session_key_value, session.clone());
        self.recovered.session_history.insert(
            (
                session_key_value.0,
                session_key_value.1,
                session.session_binding,
            ),
            session,
        );
        for (acquisition_key, release_key) in &collected {
            self.recovered.acquisitions.remove(acquisition_key);
            self.recovered.releases.remove(release_key);
        }
        Ok(collected.len())
    }

    /// Returns an immutable view of the completely validated recovered graph.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLedgerError`] when the runtime is poisoned or its
    /// protected journal authority is no longer current.
    pub fn recovered(&self) -> Result<&RecoveredProviderLedgerV1, ProviderLedgerError> {
        self.ensure_open()?;
        let snapshot = self.journal.snapshot()?;
        self.journal
            .validate_source_provider_authority_snapshot(&snapshot)?;
        Ok(&self.recovered)
    }

    /// Revalidates protected journal currentness before releasing cached bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLedgerError`] when the replay token is stale or the
    /// protected journal is no longer authoritative.
    pub fn materialize_cached_response(
        &self,
        cached: crate::DurableCachedResponseV1,
    ) -> Result<DurableProviderReplyV1, ProviderLedgerError> {
        self.ensure_open()?;
        self.journal
            .validate_source_provider_authority_snapshot(&cached.journal_snapshot)?;
        Ok(DurableProviderReplyV1 {
            response: cached.bytes,
            source_root: None,
            durability: crate::backend::DurableReplyAuthorityV1::RevalidatedReplay {
                snapshot: cached.journal_snapshot,
                attempt_key: cached.attempt_key,
            },
        })
    }

    pub(crate) fn ensure_open(&self) -> Result<(), ProviderLedgerError> {
        self.journal.validate_source_provider_authority()?;
        (!self.poisoned)
            .then_some(())
            .ok_or(ProviderLedgerError::RuntimePoisoned)
    }

    /// Irreversibly closes this in-memory owner after an ambiguous durable boundary.
    pub(crate) fn poison_runtime(&mut self) {
        self.poisoned = true;
        self.current_sessions.clear();
        self.recovery_authorizations.clear();
    }

    pub(crate) fn poison_backend_result<T>(
        &mut self,
        acquisition_id: ObjectDigest,
        result: Result<T, ProviderLedgerError>,
    ) -> Result<T, ProviderLedgerError> {
        match result {
            Err(ProviderLedgerError::BackendConflict) => {
                self.record_backend_conflict(acquisition_id)?;
                Err(ProviderLedgerError::BackendConflict)
            }
            other => other,
        }
    }

    pub(crate) fn refresh_recovery_work(&mut self) {
        self.recovered.recovery_work =
            crate::recovery::recovery_work(&self.recovered.attempts, &self.recovered.acquisitions);
    }

    pub(crate) fn record_backend_conflict(
        &mut self,
        acquisition_id: ObjectDigest,
    ) -> Result<(), ProviderLedgerError> {
        self.ensure_open()?;
        // A proven contradiction poisons this process before any fallible
        // persistence step. Failure to write the best-effort Faulted record
        // must never permit this runtime to resume effects.
        self.poisoned = true;
        let journal_snapshot = self.journal.snapshot()?;
        self.journal
            .validate_source_provider_authority_snapshot(&journal_snapshot)?;
        let key = self
            .recovered
            .acquisitions
            .keys()
            .find(|key| key.acquisition_id == acquisition_id)
            .cloned()
            .ok_or(ProviderLedgerError::InvalidTransition(
                "conflict acquisition is not retained",
            ))?;
        let mut acquisition = self
            .recovered
            .acquisitions
            .get(&key)
            .cloned()
            .ok_or(ProviderLedgerError::Corrupt("missing conflict acquisition"))?;
        let mut authority = self.recovered.authority.clone();
        acquisition.revision =
            acquisition
                .revision
                .checked_add(1)
                .ok_or(ProviderLedgerError::InvalidTransition(
                    "acquisition revision exhausted",
                ))?;
        acquisition.state = crate::ProviderAcquisitionStateV1::Faulted;
        authority.revision =
            authority
                .revision
                .checked_add(1)
                .ok_or(ProviderLedgerError::InvalidTransition(
                    "authority revision exhausted",
                ))?;
        authority.state = crate::ProviderAuthorityStateV1::AcquireClosed;
        authority.inventory_generation = authority.inventory_generation.checked_add(1).ok_or(
            ProviderLedgerError::InvalidTransition("inventory generation exhausted"),
        )?;
        let mut projected_acquisitions = self.recovered.acquisitions.clone();
        projected_acquisitions.insert(key.clone(), acquisition.clone());
        let (inventory_digest, active_count) = crate::inventory::global_inventory_state_digest(
            authority.provider.authority_id(),
            authority.catalog_generation,
            authority.catalog_digest,
            &projected_acquisitions,
            &self.recovered.releases,
            self.configuration
                .limits()
                .maximum_inventory_tombstones_per_holder(),
        )?;
        authority.inventory_state_digest = inventory_digest;
        authority.active_lease_count = active_count;
        let acquisition_bytes = crate::format::encode_acquisition(&acquisition);
        let release_key = crate::model::ReleaseKeyV1 {
            provider_id: key.provider_id,
            holder_id: key.holder_id,
            acquisition_id: key.acquisition_id,
        };
        let mut release = self.recovered.releases.get(&release_key).cloned();
        if let Some(release) = &mut release {
            release.revision =
                release
                    .revision
                    .checked_add(1)
                    .ok_or(ProviderLedgerError::InvalidTransition(
                        "release revision exhausted",
                    ))?;
            release.acquisition_record_digest = crate::format::record_digest(&acquisition_bytes)?;
        }
        let mut records = vec![
            (crate::format::acquisition_key(&key), acquisition_bytes),
            (
                crate::format::authority_key(authority.provider.authority_id()),
                crate::format::encode_authority(&authority),
            ),
        ];
        if let Some(release) = &release {
            records.push((
                crate::format::release_key(&release_key),
                crate::format::encode_release(release),
            ));
        }
        crate::transaction::commit_records(self, b"backend-conflict", records)?;
        if let Some(release) = release {
            self.recovered.releases.insert(release_key, release);
        }
        self.recovered.acquisitions.insert(key, acquisition);
        self.recovered.authority = authority;
        self.refresh_recovery_work();
        Ok(())
    }
}
