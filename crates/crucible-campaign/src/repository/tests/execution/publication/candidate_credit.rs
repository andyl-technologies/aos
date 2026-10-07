//! Finding validation scratch lifetime under one finite original account.

use super::*;
use crate::repository::finding_candidate::FindingCandidateValidation;
use crucible_cas::owned_decode::{DecodeAdmissionError, DecodeBudget, DecodeResourceAuthority};
use std::sync::atomic::AtomicU64;

const METADATA_LIMIT: u64 = 64 * 1024 * 1024;

#[derive(Default)]
struct MetadataUse {
    used: AtomicU64,
    peak: AtomicU64,
}

struct MetadataAuthority(Arc<MetadataUse>);

struct MetadataLoan {
    usage: Arc<MetadataUse>,
    bytes: u64,
}

impl Drop for MetadataLoan {
    fn drop(&mut self) {
        self.usage.used.fetch_sub(self.bytes, Ordering::SeqCst);
    }
}

impl DecodeResourceAuthority for MetadataAuthority {
    fn verify_live(&self) -> Result<(), DecodeAdmissionError> {
        if self.0.used.load(Ordering::SeqCst) > METADATA_LIMIT {
            return Err(DecodeAdmissionError::new(std::io::Error::other(
                "original component accounting is invalid",
            )));
        }
        Ok(())
    }

    fn reserve(&self, bytes: u64) -> Result<Arc<dyn Send + Sync>, DecodeAdmissionError> {
        let previous = self
            .0
            .used
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                used.checked_add(bytes)
                    .filter(|next| *next <= METADATA_LIMIT)
            })
            .map_err(|_| DecodeAdmissionError::new(StoreError::Quota))?;
        self.0.peak.fetch_max(previous + bytes, Ordering::SeqCst);
        Ok(Arc::new(MetadataLoan {
            usage: Arc::clone(&self.0),
            bytes,
        }))
    }
}

#[test]
fn repeated_candidate_validation_releases_scratch_and_retains_the_returned_bundle() {
    let (repository, lineage, policy) = fixture();
    let campaign = "candidate-validation-credit";
    let (_, admitted, observation) =
        admitted_observation_fixture(&repository, &lineage, &policy, campaign);
    let observed = repository
        .publish_observation(campaign, admitted.new_snapshot, &observation)
        .expect("publish the actual observation");
    let fingerprint = CampaignHash::derive("test-finding", b"validation credit");
    let reproduction = repository
        .publish_reproduction_artifact(
            lineage.scenario(),
            lineage.scenario_content(),
            observation.child(),
            observation.child_content(),
            fingerprint,
            1,
            b"retained reproduction".to_vec(),
        )
        .expect("publish reproduction");
    let signature = FindingSignature::new(
        FindingKind::Divergence,
        fingerprint,
        None,
        "qemu.validation-credit".to_owned(),
        Some(FindingTarget::Configuration(observation.child_content())),
        BTreeSet::new(),
    )
    .expect("finding signature");
    let published = repository
        .publish_incomplete_test_finding(
            campaign,
            observed.new_snapshot,
            signature,
            observed.observation,
            reproduction,
        )
        .expect("publish the complete immutable candidate");
    let bundle_id = repository
        .read_finding(published.finding.content_id())
        .expect("read published finding")
        .latest_candidate_bundle();
    let head_cache_entries = repository.validated_heads.lock().expect("head cache").len();
    let beam_cache_present = repository
        .beam_projection_cache
        .lock()
        .expect("beam cache")
        .is_some();

    let usage = Arc::new(MetadataUse::default());
    let budget = DecodeBudget::new(
        Arc::new(MetadataAuthority(Arc::clone(&usage))),
        METADATA_LIMIT,
    )
    .expect("finite original metadata account");
    let scope = budget.enter();
    let original_charge = usage.used.load(Ordering::SeqCst);
    let bundle = repository
        .load_finding_candidate_bundle(bundle_id)
        .expect("decode the returned bundle under the outer original account");
    let retained_charge = usage.used.load(Ordering::SeqCst);
    assert!(retained_charge > original_charge);
    usage.peak.store(retained_charge, Ordering::SeqCst);

    for _ in 0..256 {
        repository
            .validate_finding_candidate_bundle(&bundle, FindingCandidateValidation::Load)
            .expect("authenticate borrowed records under the same original authority");
        assert_eq!(usage.used.load(Ordering::SeqCst), retained_charge);
    }

    assert!(usage.peak.load(Ordering::SeqCst) > retained_charge);
    assert_eq!(bundle.observation(), observed.observation);
    assert_eq!(
        repository.validated_heads.lock().expect("head cache").len(),
        head_cache_entries
    );
    assert_eq!(
        repository
            .beam_projection_cache
            .lock()
            .expect("beam cache")
            .is_some(),
        beam_cache_present
    );
    budget.check().expect("original account remains healthy");

    drop(bundle);
    drop(scope);
    drop(budget);
    assert_eq!(usage.used.load(Ordering::SeqCst), 0);
}
