//! Admits the source-built policy projection under its retained actor budget.
//!
//! The ordinary TOML codec remains the producer's policy validator. This
//! runtime path authenticates its canonical projection and pays each owning
//! string and B-tree entry before constructing the same policy representation.
//! The resulting custody stays external to the local service's policy Arc.

use crucible::owned_decode::{DecodeAdmissionError, DecodeBudget, DecodeCustody, from_json_slice};
use serde::Deserialize;
use std::alloc::Layout;
use std::sync::Arc;

use super::*;

/// Keeps the policy's original loans outside its eventual service allocation.
pub(crate) struct OriginalCampaignPolicyOwner {
    policy: Option<UnixPeerCampaignPolicy>,
    service: Option<Arc<UnixPeerCampaignPolicy>>,
    _custody: DecodeCustody,
    budget: DecodeBudget,
}

/// Retains projection, policy and original failures independently.
#[derive(Debug, thiserror::Error)]
#[error("original campaign policy refused: {source}; original: {original_after:?}")]
pub struct OriginalCampaignPolicyError {
    #[source]
    source: OriginalCampaignPolicyCause,
    original_after: Option<DecodeAdmissionError>,
}

#[derive(Debug, thiserror::Error)]
enum OriginalCampaignPolicyCause {
    #[error("original policy admission refused: {0}")]
    Admission(#[from] DecodeAdmissionError),
    #[error("original policy JSON refused: {0}")]
    Json(#[from] serde_json::Error),
    #[error("original policy identity or schema changed")]
    Identity,
    #[error("original policy mapping refused: {0}")]
    Policy(#[from] UnixPeerCampaignPolicyError),
    #[error("original policy name refused: {0}")]
    Name(#[from] CampaignCodecError),
    #[error("original policy operation label is unsupported")]
    Operation,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Projection<'input> {
    #[serde(borrow)]
    schema: &'input str,
    #[serde(borrow)]
    original_toml_blake3: &'input str,
    #[serde(borrow)]
    document: Document<'input>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document<'input> {
    #[serde(borrow)]
    schema: &'input str,
    version: u32,
    #[serde(borrow)]
    bindings: Vec<Binding<'input>>,
    #[serde(borrow)]
    grants: Vec<Grant<'input>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding<'input> {
    user_id: u32,
    group_id: u32,
    #[serde(borrow)]
    principal: &'input str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Grant<'input> {
    #[serde(borrow)]
    principal: &'input str,
    #[serde(borrow)]
    operation: &'input str,
    #[serde(borrow)]
    campaign: &'input str,
}

impl OriginalCampaignPolicyOwner {
    pub(crate) fn decode(
        bytes: &[u8],
        expected_projection: &[u8; 32],
        expected_toml: &[u8; 32],
        budget: &DecodeBudget,
    ) -> Result<Self, OriginalCampaignPolicyError> {
        budget
            .verify_live()
            .map_err(|source| OriginalCampaignPolicyError {
                source: source.into(),
                original_after: None,
            })?;
        let mut owner = Self {
            policy: None,
            service: None,
            _custody: budget.custody(),
            budget: budget.clone(),
        };
        let work = (|| {
            if blake3::hash(bytes).as_bytes() != expected_projection {
                return Err(OriginalCampaignPolicyCause::Identity);
            }
            let _scope = budget.enter();
            let projection: Projection<'_> = from_json_slice(bytes)?;
            let digest = blake3::Hash::from_hex(projection.original_toml_blake3)
                .map_err(|_| OriginalCampaignPolicyCause::Identity)?;
            if projection.schema != "crucible.measurement-campaign-policy.v1"
                || digest.as_bytes() != expected_toml
                || projection.document.schema != CAMPAIGN_POLICY_SCHEMA
                || projection.document.version != CAMPAIGN_POLICY_SCHEMA_VERSION
            {
                return Err(OriginalCampaignPolicyCause::Identity);
            }
            owner.policy = Some(projection.document.admit(budget)?);
            budget.check()?;
            Ok(())
        })();
        let after = budget.verify_live();
        match (work, after) {
            (Ok(()), Ok(())) => Ok(owner),
            (Err(source), after) => Err(OriginalCampaignPolicyError {
                source,
                original_after: after.err(),
            }),
            (Ok(()), Err(source)) => Err(OriginalCampaignPolicyError {
                source: source.into(),
                original_after: None,
            }),
        }
    }

    pub(crate) fn admit_service_arc(&mut self) -> Result<(), OriginalCampaignPolicyError> {
        let work = (|| {
            self.budget.verify_live()?;
            if self.service.is_some() || self.policy.is_none() {
                return Err(OriginalCampaignPolicyCause::Identity);
            }
            let (layout, _) = Layout::new::<(usize, usize)>()
                .extend(Layout::new::<UnixPeerCampaignPolicy>())
                .map_err(|_| OriginalCampaignPolicyCause::Identity)?;
            self.budget
                .charge_bytes(layout.pad_to_align().size() as u64)?;
            let policy = self
                .policy
                .take()
                .ok_or(OriginalCampaignPolicyCause::Identity)?;
            // Publish the genuine service policy control before the original
            // postcut. This owner's budget stays external to that control.
            self.service = Some(Arc::new(policy));
            Ok(())
        })();
        let after = self.budget.verify_live();
        match (work, after) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(source), after) => Err(OriginalCampaignPolicyError {
                source,
                original_after: after.err(),
            }),
            (Ok(()), Err(source)) => Err(OriginalCampaignPolicyError {
                source: source.into(),
                original_after: None,
            }),
        }
    }
}

impl Document<'_> {
    fn admit(
        self,
        budget: &DecodeBudget,
    ) -> Result<UnixPeerCampaignPolicy, OriginalCampaignPolicyCause> {
        if self.bindings.len() > MAX_CAMPAIGN_PEER_BINDINGS {
            return Err(UnixPeerCampaignPolicyError::TooManyBindings.into());
        }
        if self.grants.len() > MAX_CAMPAIGN_ACCESS_GRANTS {
            return Err(UnixPeerCampaignPolicyError::TooManyGrants.into());
        }
        let mut principals = BTreeMap::new();
        let mut known_principals = BTreeSet::new();
        let mut grants = BTreeSet::new();
        for binding in self.bindings {
            budget.charge_bytes(binding.principal.len() as u64)?;
            let principal = CampaignPrincipal::new(binding.principal.to_owned())?;
            budget.charge_btree_entry::<UnixPeerCampaignIdentity, CampaignPrincipal>()?;
            budget.charge_btree_entry::<CampaignPrincipal, ()>()?;
            budget.charge_bytes(principal.as_str().len() as u64)?;
            known_principals.insert(principal.clone());
            if principals
                .insert(
                    UnixPeerCampaignIdentity::new(binding.user_id, binding.group_id),
                    principal,
                )
                .is_some()
            {
                return Err(UnixPeerCampaignPolicyError::DuplicateIdentity.into());
            }
        }
        for grant in self.grants {
            budget.charge_bytes(grant.principal.len() as u64)?;
            let principal = CampaignPrincipal::new(grant.principal.to_owned())?;
            let operation =
                parse_operation(grant.operation).ok_or(OriginalCampaignPolicyCause::Operation)?;
            let scope = if grant.campaign == "*" {
                CampaignAccessScope::AllCampaigns
            } else {
                budget.charge_bytes(grant.campaign.len() as u64)?;
                // CampaignName checks a temporary formatted `campaigns/`
                // ref. Rust's fmt initial literal estimate is twenty bytes;
                // its first growth keeps that old allocation alongside the
                // maximum of twice that capacity and the required extent.
                let required = 10_u64
                    .checked_add(grant.campaign.len() as u64)
                    .ok_or(OriginalCampaignPolicyCause::Identity)?;
                let _validation = budget.reserve_scratch_bytes(20 + required.max(40))?;
                CampaignAccessScope::Campaign(CampaignName::new(grant.campaign.to_owned())?)
            };
            if !known_principals.contains(&principal) {
                return Err(UnixPeerCampaignPolicyError::UnknownGrantPrincipal.into());
            }
            budget.charge_btree_entry::<CampaignAccessGrant, ()>()?;
            if !grants.insert(CampaignAccessGrant::new(principal, operation, scope)) {
                return Err(UnixPeerCampaignPolicyError::DuplicateGrant.into());
            }
        }
        Ok(UnixPeerCampaignPolicy {
            principals,
            known_principals,
            grants,
        })
    }
}

impl Drop for OriginalCampaignPolicyOwner {
    fn drop(&mut self) {
        drop(self.service.take());
        drop(self.policy.take());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible::owned_decode::{DecodeResourceAuthority, ResourceLoan};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    struct Fixture {
        live: AtomicBool,
        admitted: Arc<AtomicU64>,
        reserves: AtomicU64,
    }

    struct Credit {
        counter: Arc<AtomicU64>,
        bytes: u64,
    }

    impl Drop for Credit {
        fn drop(&mut self) {
            self.counter.fetch_sub(self.bytes, Ordering::SeqCst);
        }
    }

    impl DecodeResourceAuthority for Fixture {
        fn verify_live(&self) -> Result<(), DecodeAdmissionError> {
            if self.live.load(Ordering::SeqCst) {
                Ok(())
            } else {
                Err(DecodeAdmissionError::new(std::io::Error::other(
                    "original fixture canceled",
                )))
            }
        }

        fn reserve(&self, bytes: u64) -> Result<ResourceLoan, DecodeAdmissionError> {
            self.verify_live()?;
            self.reserves.fetch_add(1, Ordering::SeqCst);
            self.admitted.fetch_add(bytes, Ordering::SeqCst);
            Ok(ResourceLoan::new(Credit {
                counter: Arc::clone(&self.admitted),
                bytes,
            }))
        }
    }

    fn fixture() -> Result<(Arc<Fixture>, DecodeBudget), DecodeAdmissionError> {
        let authority = Arc::new(Fixture {
            live: AtomicBool::new(true),
            admitted: Arc::new(AtomicU64::new(0)),
            reserves: AtomicU64::new(0),
        });
        let budget = DecodeBudget::new(authority.clone(), 1 << 20)?;
        Ok((authority, budget))
    }

    const INPUT: &[u8] = br#"{"schema":"crucible.measurement-campaign-policy.v1","originalTomlBlake3":"0000000000000000000000000000000000000000000000000000000000000000","document":{"schema":"crucible.campaign-local-policy","version":1,"bindings":[{"user_id":0,"group_id":0,"principal":"operator"}],"grants":[{"principal":"operator","operation":"get-campaign-status","campaign":"example"}]}}"#;

    #[test]
    fn source_projection_reaches_same_policy_maps_and_prepaid_service_control()
    -> Result<(), Box<dyn std::error::Error>> {
        let (authority, budget) = fixture()?;
        let mut owner = OriginalCampaignPolicyOwner::decode(
            INPUT,
            blake3::hash(INPUT).as_bytes(),
            &[0; 32],
            &budget,
        )?;
        assert_eq!(owner.policy.as_ref().map(|p| p.principals.len()), Some(1));
        assert!(authority.admitted.load(Ordering::SeqCst) > 0);
        owner.admit_service_arc()?;
        assert!(owner.policy.is_none());
        assert_eq!(owner.service.as_ref().map(|p| p.grants.len()), Some(1));
        assert!(owner.admit_service_arc().is_err());
        drop(owner);
        assert!(
            authority.admitted.load(Ordering::SeqCst) > 0,
            "external budget retains actual model/control payment"
        );
        drop(budget);
        assert_eq!(authority.admitted.load(Ordering::SeqCst), 0);
        Ok(())
    }

    #[test]
    fn changed_identity_and_canceled_original_refuse_before_parser_reservation()
    -> Result<(), Box<dyn std::error::Error>> {
        let (authority, budget) = fixture()?;
        let baseline = authority.reserves.load(Ordering::SeqCst);
        assert!(OriginalCampaignPolicyOwner::decode(INPUT, &[1; 32], &[0; 32], &budget).is_err());
        assert_eq!(authority.reserves.load(Ordering::SeqCst), baseline);
        authority.live.store(false, Ordering::SeqCst);
        assert!(
            OriginalCampaignPolicyOwner::decode(
                INPUT,
                blake3::hash(INPUT).as_bytes(),
                &[0; 32],
                &budget
            )
            .is_err()
        );
        assert_eq!(authority.reserves.load(Ordering::SeqCst), baseline);
        Ok(())
    }

    #[test]
    fn original_toml_binding_cannot_be_replaced_by_valid_projection_shape()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_, budget) = fixture()?;
        let refused = OriginalCampaignPolicyOwner::decode(
            INPUT,
            blake3::hash(INPUT).as_bytes(),
            &[7; 32],
            &budget,
        );
        assert!(matches!(
            refused,
            Err(OriginalCampaignPolicyError {
                source: OriginalCampaignPolicyCause::Identity,
                ..
            })
        ));
        Ok(())
    }
}
