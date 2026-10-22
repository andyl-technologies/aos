//! Replays bounded completion pages while preserving original dependency phases.
//!
//! Independent single-part metadata pages overlap. Content and multipart pages
//! retain serial completion. Every dispatched neighbor drains before an error
//! returns; only validated Committed replies enter this barrier's local cache.

use std::collections::BTreeSet;
use std::time::Duration;

use aos_transfer::direct_upload::DirectRetainedCompletion;
use futures_util::future::join_all;

use super::*;

// One admitted descriptor wave also bounds retained completion work. Final
// promotion has its own server-owned dependency checks and shared provider pool.
const MAX_PARALLEL_COMPLETION_BATCHES: usize = 8;

struct Progress {
    confirmed: Vec<String>,
    pending: bool,
}

impl DirectUploadCoordinator {
    pub(super) async fn finish_phase(
        &self,
        timeout: Duration,
        phase: Option<DirectDependencyPhase>,
    ) -> Result<(), DirectClientError> {
        let _phase_clock = PhaseClock {
            started: std::time::Instant::now(),
            total: &self.barrier_millis,
        };
        if timeout.is_zero() || timeout > Duration::from_secs(60 * 60) {
            return Err(DirectClientError::Invalid);
        }
        let deadline = tokio::time::Instant::now()
            .checked_add(timeout)
            .ok_or(DirectClientError::Invalid)?;
        // Confirmation belongs to this barrier only. Reopening independently
        // rechecks every original, including already committed content.
        let mut confirmed = BTreeSet::new();
        loop {
            let mut after = None;
            let mut pending = false;
            let mut count = 0u64;
            let mut waves = Vec::new();
            let mut queued = 0;
            loop {
                let page = before_deadline(
                    deadline,
                    self.store.completion_page(
                        after.as_deref(),
                        self.capabilities.maximum_batch_items as usize,
                    ),
                )
                .await?;
                let mut items = Vec::new();
                for item in page.items {
                    if phase.is_some_and(|phase| item.intent.dependency_phase != phase) {
                        continue;
                    }
                    count = count.checked_add(1).ok_or(DirectClientError::Invalid)?;
                    let fingerprint = item
                        .request
                        .fingerprint()
                        .map_err(|_| DirectClientError::Invalid)?;
                    if !confirmed.contains(&fingerprint) {
                        items.push(item);
                    }
                }
                if !items.is_empty() {
                    let metadata = items.iter().all(|item| {
                        item.intent.dependency_phase != DirectDependencyPhase::Content
                            && item.intent.byte_size.get() <= item.intent.part_size.get()
                    });
                    if !metadata || queued + items.len() > MAX_DIRECT_BATCH_ITEMS {
                        self.drain_completions(
                            deadline,
                            std::mem::take(&mut waves),
                            &mut confirmed,
                            &mut pending,
                        )
                        .await?;
                        queued = 0;
                    }
                    queued += items.len();
                    waves.push(items);
                    if !metadata || waves.len() == MAX_PARALLEL_COMPLETION_BATCHES {
                        self.drain_completions(
                            deadline,
                            std::mem::take(&mut waves),
                            &mut confirmed,
                            &mut pending,
                        )
                        .await?;
                        queued = 0;
                    }
                }
                let Some(next) = page.next_after else {
                    break;
                };
                after = Some(next);
                if tokio::time::Instant::now() >= deadline {
                    return Err(DirectClientError::ControlUnavailable);
                }
            }
            self.drain_completions(deadline, waves, &mut confirmed, &mut pending)
                .await?;
            if count == 0 {
                return Err(DirectClientError::Invalid);
            }
            if !pending {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(DirectClientError::ControlUnavailable);
            }
            let next = tokio::time::Instant::now()
                .checked_add(Duration::from_millis(250))
                .unwrap_or(deadline)
                .min(deadline);
            tokio::time::sleep_until(next).await;
        }
    }

    async fn drain_completions(
        &self,
        deadline: tokio::time::Instant,
        waves: Vec<Vec<DirectRetainedCompletion>>,
        confirmed: &mut BTreeSet<String>,
        pending: &mut bool,
    ) -> Result<(), DirectClientError> {
        // Observe every result before propagating an error. A neighbor may have
        // dispatched a provider mutation whose exact original remains retained.
        let results = join_all(
            waves
                .into_iter()
                .map(|items| self.complete_wave(deadline, items)),
        )
        .await;
        for result in results {
            let progress = result?;
            confirmed.extend(progress.confirmed);
            *pending |= progress.pending;
        }
        Ok(())
    }

    async fn complete_wave(
        &self,
        deadline: tokio::time::Instant,
        items: Vec<DirectRetainedCompletion>,
    ) -> Result<Progress, DirectClientError> {
        let mut confirmed = Vec::new();
        let mut pending = false;
        let discovery = before_deadline(deadline, self.control.snapshot()).await?;
        let mut requests = Vec::with_capacity(items.len());
        for item in &items {
            let placements: Vec<_> = item
                .request
                .manifests
                .iter()
                .map(|manifest| manifest.placement.clone())
                .collect();
            discovery
                .validate_placements_for(&discovery_target(&discovery), &placements, now()?)
                .map_err(|_| DirectClientError::Invalid)?;
            requests.push(item.request.clone());
        }
        let members: Vec<_> = requests
            .iter()
            .map(|request| request.operation_id.as_bytes())
            .collect();
        let batch = DirectBatch {
            operation_id: commitment("completion-barrier-wave", &members),
            items: requests,
        };
        if encode_direct_control(&batch)
            .map_err(|_| DirectClientError::Invalid)?
            .len()
            > self.capabilities.maximum_control_bytes as usize
        {
            return Err(DirectClientError::Invalid);
        }
        let request = DirectUploadRequest::CompleteBatch(batch);
        let response = before_deadline(deadline, execute_retry(&self.control, &request)).await?;
        if response.sessions.len() != items.len() || !response.grants.is_empty() {
            return Err(DirectClientError::Invalid);
        }
        let mut seen = std::collections::BTreeSet::new();
        for status in &response.sessions {
            if !seen.insert(&status.session.session_id) {
                return Err(DirectClientError::Invalid);
            }
            let item = items
                .iter()
                .find(|item| item.request.session == status.session)
                .ok_or(DirectClientError::Invalid)?;
            let placements: Vec<_> = item
                .request
                .manifests
                .iter()
                .map(|manifest| manifest.placement.clone())
                .collect();
            status
                .validate_for(&item.request.session, &item.intent, &placements)
                .map_err(|_| DirectClientError::Invalid)?;
            match status.state {
                DirectSessionState::Committed => {
                    confirmed.push(
                        item.request
                            .fingerprint()
                            .map_err(|_| DirectClientError::Invalid)?,
                    );
                }
                DirectSessionState::Freezing
                | DirectSessionState::CompletingStaging
                | DirectSessionState::StagedVerified => pending = true,
                _ => return Err(DirectClientError::Blocked),
            }
        }
        Ok(Progress { confirmed, pending })
    }
}
