//! Checks closed census packets and exact correlation without native authority.

use prost::Message;
use terrane_linux::host_quota::{
    CensusInode, CensusObservation, CensusQuery, MAX_CENSUS_EXCLUSIONS, QuotaObservation,
    QuotaQuery, QuotaRoot, ROOT_LABELS,
};

type Result = std::result::Result<(), Box<dyn std::error::Error>>;

fn query() -> CensusQuery {
    CensusQuery {
        version: 2,
        request_id: 7,
        configuration_epoch: vec![1; 16],
        owner_id: "public-owner".into(),
        domain: "public".into(),
        excluded: vec![CensusInode {
            device: 7,
            inode: u64::MAX,
            birth: None,
        }],
    }
}

fn observation() -> CensusObservation {
    let query = query();
    CensusObservation {
        version: 2,
        request_id: query.request_id,
        configuration_epoch: query.configuration_epoch.clone(),
        owner_id: query.owner_id.clone(),
        domain: query.domain.clone(),
        query_sequence: 1,
        result: 0,
        quota: Some(QuotaObservation {
            version: 1,
            request_id: query.request_id,
            configuration_epoch: query.configuration_epoch,
            owner_id: query.owner_id,
            domain: query.domain,
            query_sequence: 1,
            result: 0,
            filesystem_uuid: vec![2; 16],
            project_id: 79,
            accounting: true,
            enforcement: true,
            hard_limit_bytes: 8192,
            charged_reserved_bytes: 4096,
            hard_inode_limit: 0,
            charged_inodes: 11,
            roots: ROOT_LABELS
                .iter()
                .enumerate()
                .map(|(index, label)| QuotaRoot {
                    role_directory: (*label).into(),
                    device: 7,
                    inode: index as u64 + 100,
                    project_inherit: true,
                })
                .collect(),
            tier_charge_budget_bytes: 16384,
            configured_limit_sum_bytes: 8192,
        }),
        excluded: query.excluded,
        retained_inodes: 10,
    }
}

#[test]
fn census_query_rejects_extensions_aliases_and_noncanonical_encoding() -> Result {
    let valid = query().encode_to_vec();
    assert_eq!(CensusQuery::decode_strict(&valid)?, query());
    assert!(QuotaQuery::decode_strict(&valid).is_err());
    for length in 0..valid.len() {
        assert!(CensusQuery::decode_strict(&valid[..length]).is_err());
    }
    for suffix in [&[8, 2][..], &[56, 1], &[0], &[255], &[50, 2, 8, 7]] {
        let mut bytes = valid.clone();
        bytes.extend_from_slice(suffix);
        assert!(CensusQuery::decode_strict(&bytes).is_err());
    }
    let mut nonminimal = vec![8, 0x82, 0];
    nonminimal.extend_from_slice(&valid[2..]);
    assert!(CensusQuery::decode_strict(&nonminimal).is_err());

    for damage in 0..8 {
        let mut broken = query();
        match damage {
            0 => broken.version = 1,
            1 => broken.version = 3,
            2 => broken.request_id = 0,
            3 => broken.excluded.clear(),
            4 => broken.excluded.push(broken.excluded[0].clone()),
            5 => broken.excluded[0].device = 0,
            6 => broken.excluded[0].inode = 0,
            _ => {
                broken.excluded = (0..=MAX_CENSUS_EXCLUSIONS)
                    .map(|index| CensusInode {
                        device: 7,
                        inode: index as u64 + 1,
                        birth: None,
                    })
                    .collect()
            }
        }
        assert!(
            CensusQuery::decode_strict(&broken.encode_to_vec()).is_err(),
            "damage {damage}"
        );
    }
    Ok(())
}

#[test]
fn census_response_requires_complete_correlated_native_partition() -> Result {
    let valid = observation().encode_to_vec();
    assert_eq!(CensusObservation::decode_strict(&valid)?, observation());
    for length in 0..valid.len() {
        assert!(CensusObservation::decode_strict(&valid[..length]).is_err());
    }
    for damage in 0..10 {
        let mut broken = observation();
        match damage {
            0 => broken.quota = None,
            1 => broken.retained_inodes = 12,
            2 => broken.retained_inodes = 0,
            3 => broken.excluded[0].device = 8,
            4 => broken.quota.as_mut().ok_or("missing quota")?.request_id += 1,
            5 => broken.quota.as_mut().ok_or("missing quota")?.query_sequence += 1,
            6 => {
                broken
                    .quota
                    .as_mut()
                    .ok_or("missing quota")?
                    .roots
                    .remove(0);
            }
            7 => broken.quota.as_mut().ok_or("missing quota")?.roots[1].device = 8,
            8 => broken.quota.as_mut().ok_or("missing quota")?.roots[1].inode = 0,
            _ => broken.quota.as_mut().ok_or("missing quota")?.enforcement = false,
        }
        assert!(
            CensusObservation::decode_strict(&broken.encode_to_vec()).is_err(),
            "damage {damage}"
        );
    }
    Ok(())
}

#[test]
fn census_error_cannot_carry_quota_or_closure_evidence() -> Result {
    let mut response = observation();
    response.result = 4;
    assert!(CensusObservation::decode_strict(&response.encode_to_vec()).is_err());
    response.quota = None;
    response.excluded.clear();
    response.retained_inodes = 0;
    CensusObservation::decode_strict(&response.encode_to_vec())?;
    let mut explicit_evidence = response.encode_to_vec();
    explicit_evidence.extend_from_slice(&[80, 0]);
    assert!(CensusObservation::decode_strict(&explicit_evidence).is_err());
    Ok(())
}

#[test]
fn incarnation_census_requires_explicit_version_and_canonical_creation_times() -> Result {
    use terrane_linux::host_quota::CensusBirth;

    let mut request = query();
    request.excluded[0].birth = Some(CensusBirth {
        seconds: -1,
        nanoseconds: 999_999_999,
    });
    assert!(CensusQuery::decode_strict(&request.encode_to_vec()).is_err());
    request.version = 3;
    assert_eq!(
        CensusQuery::decode_strict(&request.encode_to_vec())?,
        request
    );
    assert!(QuotaQuery::decode_strict(&request.encode_to_vec()).is_err());

    let mut response = observation();
    response.version = 3;
    response.excluded = request.excluded.clone();
    assert_eq!(
        CensusObservation::decode_strict(&response.encode_to_vec())?,
        response
    );
    response.version = 2;
    assert!(CensusObservation::decode_strict(&response.encode_to_vec()).is_err());

    // Mixed snapshots retain conservative exclusions for older original inodes.
    let mut legacy = query().excluded.remove(0);
    legacy.inode -= 1;
    request.excluded.push(legacy);
    CensusQuery::decode_strict(&request.encode_to_vec())?;
    let bytes = request.encode_to_vec();
    for length in 0..bytes.len() {
        // A prefix can legitimately omit the second complete repeated entry.
        if let Ok(prefix) = CensusQuery::decode_strict(&bytes[..length]) {
            assert_eq!(prefix.excluded.len(), 1);
            assert_eq!(prefix.excluded[0], request.excluded[0]);
        }
    }
    request.excluded[0]
        .birth
        .as_mut()
        .ok_or("missing birth")?
        .nanoseconds = 1_000_000_000;
    assert!(CensusQuery::decode_strict(&request.encode_to_vec()).is_err());
    response.version = 3;
    response.excluded = request.excluded;
    assert!(CensusObservation::decode_strict(&response.encode_to_vec()).is_err());

    // Distinct historical incarnations can share a number across exposures.
    let mut history = query();
    history.version = 3;
    history.excluded[0].birth = Some(CensusBirth {
        seconds: 1,
        nanoseconds: 2,
    });
    let mut later = history.excluded[0].clone();
    later.birth.as_mut().ok_or("missing later birth")?.seconds += 1;
    history.excluded.push(later.clone());
    CensusQuery::decode_strict(&history.encode_to_vec())?;
    history.excluded.push(later);
    assert!(CensusQuery::decode_strict(&history.encode_to_vec()).is_err());

    let mut oversized = query();
    oversized.version = 3;
    oversized.excluded = (1..=MAX_CENSUS_EXCLUSIONS)
        .map(|inode| CensusInode {
            device: u64::MAX,
            inode: u64::MAX - inode as u64,
            birth: Some(CensusBirth {
                seconds: i64::MIN,
                nanoseconds: 999_999_999,
            }),
        })
        .collect();
    assert!(oversized.encode_to_vec().len() > 16384);
    assert!(CensusQuery::decode_strict(&oversized.encode_to_vec()).is_err());
    Ok(())
}
