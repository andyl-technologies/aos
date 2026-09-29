//! Coordinator mutation, planner, and incremental-history repository tests.

use super::*;

mod choice_authority;
mod control;
mod creation;
mod derivation;
mod history;
mod service;

struct PermitAlice;

impl crate::CampaignPrincipalAuthorizer for PermitAlice {
    fn authorize_all_campaigns(
        &self,
        principal: &crate::CampaignPrincipal,
        _operation: crate::CampaignServiceOperation,
        _request_digest: CampaignHash,
    ) -> Result<(), crate::CampaignAuthorizationError> {
        if principal.as_str() == "operator:alice" {
            Ok(())
        } else {
            Err(crate::CampaignAuthorizationError::Unauthorized)
        }
    }

    fn authorize(
        &self,
        principal: &crate::CampaignPrincipal,
        _operation: crate::CampaignServiceOperation,
        _campaign: &crate::CampaignName,
        _request_digest: CampaignHash,
    ) -> Result<(), crate::CampaignAuthorizationError> {
        if principal.as_str() == "operator:alice" {
            Ok(())
        } else {
            Err(crate::CampaignAuthorizationError::Unauthorized)
        }
    }
}

struct RecordAndDenyDeriveTarget {
    calls: Arc<Mutex<Vec<(crate::CampaignServiceOperation, String)>>>,
    denied_target: String,
}

struct BlockingReadBackend {
    inner: Arc<MemoryBlobBackend>,
    blocked_id: ContentId,
    state: Mutex<(bool, bool)>,
    changed: std::sync::Condvar,
}

impl BlockingReadBackend {
    fn new(inner: Arc<MemoryBlobBackend>, blocked_id: ContentId) -> Self {
        Self {
            inner,
            blocked_id,
            state: Mutex::new((false, false)),
            changed: std::sync::Condvar::new(),
        }
    }

    fn wait_until_blocked(&self) {
        let mut state = self.state.lock().expect("blocking read state");
        while !state.0 {
            state = self.changed.wait(state).expect("blocking read wait");
        }
    }

    fn release(&self) {
        let mut state = self.state.lock().expect("blocking read state");
        state.1 = true;
        self.changed.notify_all();
    }
}

impl crucible_cas::content_store::ImmutableBlobBackend for BlockingReadBackend {
    fn name(&self) -> &str {
        "blocking-campaign-test"
    }

    fn capabilities(&self) -> crucible_cas::content_store::BackendCapabilities {
        self.inner.capabilities()
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        self.inner.contains(id)
    }

    fn read(
        &self,
        id: ContentId,
        range: Option<crucible_cas::content_store::ByteRange>,
    ) -> Result<crucible_cas::content_store::BlobHandle, StoreError> {
        if id == self.blocked_id {
            let mut state = self.state.lock().map_err(|_| StoreError::Poisoned {
                operation: "blocking-read-state",
            })?;
            state.0 = true;
            self.changed.notify_all();
            while !state.1 {
                state = self.changed.wait(state).map_err(|_| StoreError::Poisoned {
                    operation: "blocking-read-wait",
                })?;
            }
        }
        self.inner.read(id, range)
    }

    fn put_if_absent(
        &self,
        id: ContentId,
        source: &crucible_cas::content_store::BlobHandle,
    ) -> Result<crucible_cas::content_store::PutReceipt, StoreError> {
        self.inner.put_if_absent(id, source)
    }
}

impl crate::CampaignPrincipalAuthorizer for RecordAndDenyDeriveTarget {
    fn authorize(
        &self,
        _principal: &crate::CampaignPrincipal,
        operation: crate::CampaignServiceOperation,
        campaign: &crate::CampaignName,
        _request_digest: CampaignHash,
    ) -> Result<(), crate::CampaignAuthorizationError> {
        self.calls
            .lock()
            .expect("authorization calls")
            .push((operation, campaign.as_str().to_owned()));
        if campaign.as_str() == self.denied_target {
            Err(crate::CampaignAuthorizationError::Unauthorized)
        } else {
            Ok(())
        }
    }
}

fn policy_with_seed(policy: &CampaignPolicy, seed: [u8; 32]) -> CampaignPolicy {
    CampaignPolicy::new(
        CampaignPolicy::identity(
            policy.scenario(),
            CampaignSeed::from_bytes(seed),
            policy.mode(),
            policy.explorer().clone(),
        ),
        CampaignPolicy::rules(
            policy.choice_policies().clone(),
            policy.objectives().clone(),
            policy.guidance().clone(),
            policy.stop_conditions().clone(),
            policy.fairness(),
            policy.retention(),
            policy.admits_scenario_defaults(),
        ),
    )
    .expect("policy with changed seed")
}

fn policy_with_mode(policy: &CampaignPolicy, mode: CampaignMode) -> CampaignPolicy {
    CampaignPolicy::new(
        CampaignPolicy::identity(
            policy.scenario(),
            policy.campaign_seed(),
            mode,
            policy.explorer().clone(),
        ),
        CampaignPolicy::rules(
            policy.choice_policies().clone(),
            policy.objectives().clone(),
            policy.guidance().clone(),
            policy.stop_conditions().clone(),
            policy.fairness(),
            policy.retention(),
            policy.admits_scenario_defaults(),
        ),
    )
    .expect("policy with changed mode")
}

mod planning;

mod finite_proposal;

mod mode_derivation;
