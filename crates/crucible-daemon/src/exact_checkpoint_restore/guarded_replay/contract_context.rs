//! Bounded contract identities attached only to an already-refused replay choice.
//!
//! Compact tuple labels keep the complete diagnostic inside the existing 1 KiB
//! promotion-failure detail: `e` and `a` mean expected and actual; `d,o,m,s,p`
//! mean declaration, opportunity, domain, scheduler and producer coordinates.
//! The request tuple `q,r,t,v` carries sequence, raw count, trap picoseconds and
//! vCPU. `i` is the schedule decision index. Coordinates remain original
//! authenticated hashes; this context cannot reconstruct an expected raw count.

use std::fmt;

use crucible::Configuration;
use crucible_campaign::{CampaignHash, ChoiceDiscovery, SelectionReplayMismatch};
use crucible_protocol::selectable_catalog_plan::SelectablePlanPendingRequest;

use crate::guest_selectable::GuestSelectableReplayOpportunityContext;
use crate::qemu_campaign_lifecycle::GuardedCampaignReplaySelection;

/// Copies diagnostic identities without changing the original replay refusal.
pub(super) struct ReplayContractContext {
    expected: GuestSelectableReplayOpportunityContext,
    actual: GuestSelectableReplayOpportunityContext,
    mismatch: Option<SelectionReplayMismatch>,
    expected_opportunity: DiagnosticIdentity,
    actual_opportunity: DiagnosticIdentity,
    expected_domain: DiagnosticIdentity,
    actual_domain: DiagnosticIdentity,
    declaration_equal: bool,
    opportunity_equal: bool,
    domain_equal: bool,
    sequence: u64,
    raw_icount: u64,
    trap_tick_ps: u64,
    vcpu: u32,
    decision_index: usize,
}

impl ReplayContractContext {
    pub(super) fn new(
        current: &Configuration,
        recorded: &GuardedCampaignReplaySelection,
        discovery: &ChoiceDiscovery,
        request: &SelectablePlanPendingRequest,
    ) -> Self {
        // Diagnostic construction must never replace the original error if an
        // identity cannot be recomputed. Unavailable is distinct from any hash.
        let mismatch = recorded
            .selection()
            .replay_mismatch(discovery.opportunity(), discovery.domain())
            .ok()
            .flatten();
        Self {
            expected: GuestSelectableReplayOpportunityContext::from_opportunity(
                recorded.opportunity(),
            ),
            actual: GuestSelectableReplayOpportunityContext::from_opportunity(
                discovery.opportunity(),
            ),
            mismatch,
            expected_opportunity: DiagnosticIdentity(
                recorded
                    .opportunity()
                    .id()
                    .ok()
                    .map(|id| CampaignHash::from_bytes(id.content_id().digest())),
            ),
            actual_opportunity: DiagnosticIdentity(
                discovery
                    .opportunity()
                    .id()
                    .ok()
                    .map(|id| CampaignHash::from_bytes(id.content_id().digest())),
            ),
            expected_domain: DiagnosticIdentity(
                recorded
                    .domain()
                    .id()
                    .ok()
                    .map(|id| CampaignHash::from_bytes(id.content_id().digest())),
            ),
            actual_domain: DiagnosticIdentity(
                discovery
                    .domain()
                    .id()
                    .ok()
                    .map(|id| CampaignHash::from_bytes(id.content_id().digest())),
            ),
            declaration_equal: recorded.declaration() == discovery.declaration(),
            opportunity_equal: recorded.opportunity() == discovery.opportunity(),
            domain_equal: recorded.domain() == discovery.domain(),
            sequence: request.request().sequence(),
            raw_icount: request.raw_icount(),
            trap_tick_ps: request.trap_tick_ps(),
            vcpu: request.vcpu_index(),
            decision_index: current.schedule.len(),
        }
    }
}

impl fmt::Display for ReplayContractContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // These are fixed-width identities and scalars only. Never render guest
        // payloads, domain members, instance text or other unbounded strings.
        write!(
            formatter,
            "eq[d,o,m]={}/{}/{} req[q,r,t,v]={},{},{},{} i={} e[d,o,m,s,p]={},{},{},{},{} a[d,o,m,s,p]={},{},{},{},{} instance_eq={}",
            self.declaration_equal,
            self.opportunity_equal,
            self.domain_equal,
            self.sequence,
            self.raw_icount,
            self.trap_tick_ps,
            self.vcpu,
            self.decision_index,
            CampaignHash::from_bytes(self.expected.declaration().content_id().digest()),
            self.expected_opportunity,
            self.expected_domain,
            self.expected.coordinate().scheduler,
            self.expected.coordinate().producer,
            CampaignHash::from_bytes(self.actual.declaration().content_id().digest()),
            self.actual_opportunity,
            self.actual_domain,
            self.actual.coordinate().scheduler,
            self.actual.coordinate().producer,
            self.expected.instance() == self.actual.instance(),
        )?;
        if let Some(mismatch) = self.mismatch {
            write!(formatter, " pred={:?}", mismatch.kind())?;
        }
        Ok(())
    }
}

struct DiagnosticIdentity(Option<CampaignHash>);

impl fmt::Display for DiagnosticIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(identity) => identity.fmt(formatter),
            None => formatter.write_str("unavailable"),
        }
    }
}
