//! Replay-oracle comparison utilities for temporal-graph gates.
//!
//! The replay oracle compares a materialized checkpoint hash against the same
//! checkpoint reconstructed from an ancestor. This module hosts the deterministic
//! comparison core while later engine phases provide checkpoint materialization.

use std::error::Error;
use std::fmt;

/// One replay-oracle comparison case.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayOracleCase {
    /// Stable checkpoint identifier under test.
    pub checkpoint_id: String,
    /// Canonical hash of the materialized, fat checkpoint.
    pub fat_hash: Vec<u8>,
    /// Canonical hash of the thin reconstruction from an ancestor.
    pub thin_hash: Vec<u8>,
}

/// The checkpoint storage kind supplied by a replay-oracle case.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayOracleCheckpointKind {
    /// The case describes a materialized checkpoint body.
    Fat,
    /// The case describes a replay-only checkpoint descriptor.
    Thin,
}

/// One replay-oracle comparison with explicit checkpoint metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayOracleMaterializedCase {
    /// Stable checkpoint identifier under test.
    pub checkpoint_id: String,
    /// The materialized checkpoint kind.
    pub kind: ReplayOracleCheckpointKind,
    /// Checkpoint content hash recorded by the materialized side.
    pub fat_checkpoint_hash: Vec<u8>,
    /// Checkpoint content hash reconstructed from the ancestor and schedule delta.
    pub thin_checkpoint_hash: Vec<u8>,
    /// Configuration hash recorded by the materialized checkpoint metadata.
    pub fat_configuration_hash: Vec<u8>,
    /// Configuration hash reconstructed from the ancestor and schedule delta.
    pub thin_configuration_hash: Vec<u8>,
    /// Ancestor configuration hash recorded by the materialized checkpoint metadata.
    pub fat_ancestor_hash: Vec<u8>,
    /// Ancestor configuration hash used by the thin reconstruction.
    pub thin_ancestor_hash: Vec<u8>,
    /// Schedule-delta hash recorded by the materialized checkpoint metadata.
    pub fat_schedule_delta_hash: Vec<u8>,
    /// Schedule-delta hash used by the thin reconstruction.
    pub thin_schedule_delta_hash: Vec<u8>,
    /// Canonical hash of the materialized, fat checkpoint body.
    pub fat_hash: Vec<u8>,
    /// Canonical hash of the thin reconstruction from an ancestor.
    pub thin_hash: Vec<u8>,
}

/// The first replay-oracle mismatch in a corpus.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayOracleMismatch {
    /// Stable checkpoint identifier whose hashes differ.
    pub checkpoint_id: String,
    /// Canonical hash of the materialized, fat checkpoint.
    pub fat_hash: Vec<u8>,
    /// Canonical hash of the thin reconstruction from an ancestor.
    pub thin_hash: Vec<u8>,
}

impl fmt::Display for ReplayOracleMismatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "replay oracle mismatch for checkpoint `{}`",
            self.checkpoint_id
        )
    }
}

impl Error for ReplayOracleMismatch {}

/// Checks that every replay-oracle case has matching fat and thin hashes.
///
/// # Errors
///
/// Returns [`ReplayOracleMismatch`] for the first checkpoint whose materialized
/// and reconstructed hashes differ.
pub fn check_replay_oracle(cases: &[ReplayOracleCase]) -> Result<(), ReplayOracleMismatch> {
    for case in cases {
        if case.fat_hash != case.thin_hash {
            return Err(mismatch(
                &case.checkpoint_id,
                &case.fat_hash,
                &case.thin_hash,
            ));
        }
    }

    Ok(())
}

/// Checks materialized replay-oracle cases, including checkpoint metadata.
///
/// # Errors
///
/// Returns [`ReplayOracleMismatch`] for the first checkpoint whose materialized
/// metadata or body hash disagrees with the thin reconstruction.
pub fn check_materialized_replay_oracle(
    cases: &[ReplayOracleMaterializedCase],
) -> Result<(), ReplayOracleMismatch> {
    for case in cases {
        if case.kind != ReplayOracleCheckpointKind::Fat {
            return Err(mismatch(
                &case.checkpoint_id,
                b"checkpoint-kind:thin",
                b"checkpoint-kind:fat",
            ));
        }
        if case.fat_checkpoint_hash != case.thin_checkpoint_hash {
            return Err(mismatch(
                &case.checkpoint_id,
                &case.fat_checkpoint_hash,
                &case.thin_checkpoint_hash,
            ));
        }
        if case.fat_configuration_hash != case.thin_configuration_hash {
            return Err(mismatch(
                &case.checkpoint_id,
                &case.fat_configuration_hash,
                &case.thin_configuration_hash,
            ));
        }
        if case.fat_ancestor_hash != case.thin_ancestor_hash {
            return Err(mismatch(
                &case.checkpoint_id,
                &case.fat_ancestor_hash,
                &case.thin_ancestor_hash,
            ));
        }
        if case.fat_schedule_delta_hash != case.thin_schedule_delta_hash {
            return Err(mismatch(
                &case.checkpoint_id,
                &case.fat_schedule_delta_hash,
                &case.thin_schedule_delta_hash,
            ));
        }
        if case.fat_hash != case.thin_hash {
            return Err(mismatch(
                &case.checkpoint_id,
                &case.fat_hash,
                &case.thin_hash,
            ));
        }
    }
    Ok(())
}

fn mismatch(checkpoint_id: &str, fat_hash: &[u8], thin_hash: &[u8]) -> ReplayOracleMismatch {
    ReplayOracleMismatch {
        checkpoint_id: checkpoint_id.to_owned(),
        fat_hash: fat_hash.to_vec(),
        thin_hash: thin_hash.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_oracle_accepts_matching_corpus() {
        let cases = [
            ReplayOracleCase {
                checkpoint_id: String::from("cp-1"),
                fat_hash: vec![1, 2, 3],
                thin_hash: vec![1, 2, 3],
            },
            ReplayOracleCase {
                checkpoint_id: String::from("cp-2"),
                fat_hash: vec![4, 5, 6],
                thin_hash: vec![4, 5, 6],
            },
        ];

        assert_eq!(check_replay_oracle(&cases), Ok(()));
    }

    #[test]
    fn replay_oracle_reports_first_mismatch() {
        let cases = [
            ReplayOracleCase {
                checkpoint_id: String::from("cp-1"),
                fat_hash: vec![1],
                thin_hash: vec![1],
            },
            ReplayOracleCase {
                checkpoint_id: String::from("cp-2"),
                fat_hash: vec![2],
                thin_hash: vec![3],
            },
            ReplayOracleCase {
                checkpoint_id: String::from("cp-3"),
                fat_hash: vec![4],
                thin_hash: vec![5],
            },
        ];

        let mismatch = match check_replay_oracle(&cases) {
            Ok(()) => panic!("replay oracle should report the first mismatch"),
            Err(mismatch) => mismatch,
        };

        assert_eq!(mismatch.checkpoint_id, "cp-2");
        assert_eq!(mismatch.fat_hash, vec![2]);
        assert_eq!(mismatch.thin_hash, vec![3]);
        assert_eq!(
            mismatch.to_string(),
            "replay oracle mismatch for checkpoint `cp-2`"
        );
    }

    #[test]
    fn materialized_replay_oracle_validates_metadata_before_body_hash() {
        let mut cases = [ReplayOracleMaterializedCase {
            checkpoint_id: String::from("cp-1"),
            kind: ReplayOracleCheckpointKind::Fat,
            fat_checkpoint_hash: vec![1],
            thin_checkpoint_hash: vec![1],
            fat_configuration_hash: vec![2],
            thin_configuration_hash: vec![2],
            fat_ancestor_hash: vec![3],
            thin_ancestor_hash: vec![3],
            fat_schedule_delta_hash: vec![4],
            thin_schedule_delta_hash: vec![4],
            fat_hash: vec![5],
            thin_hash: vec![5],
        }];

        assert_eq!(check_materialized_replay_oracle(&cases), Ok(()));

        cases[0].fat_schedule_delta_hash = vec![6];
        let mismatch = match check_materialized_replay_oracle(&cases) {
            Ok(()) => panic!("metadata mismatch should fail before body comparison"),
            Err(mismatch) => mismatch,
        };

        assert_eq!(mismatch.checkpoint_id, "cp-1");
        assert_eq!(mismatch.fat_hash, vec![6]);
        assert_eq!(mismatch.thin_hash, vec![4]);
    }

    #[test]
    fn materialized_replay_oracle_reports_first_case_mismatch() {
        let cases = [
            ReplayOracleMaterializedCase {
                checkpoint_id: String::from("cp-1"),
                kind: ReplayOracleCheckpointKind::Fat,
                fat_checkpoint_hash: vec![1],
                thin_checkpoint_hash: vec![1],
                fat_configuration_hash: vec![2],
                thin_configuration_hash: vec![2],
                fat_ancestor_hash: vec![3],
                thin_ancestor_hash: vec![3],
                fat_schedule_delta_hash: vec![4],
                thin_schedule_delta_hash: vec![4],
                fat_hash: vec![5],
                thin_hash: vec![6],
            },
            ReplayOracleMaterializedCase {
                checkpoint_id: String::from("cp-2"),
                kind: ReplayOracleCheckpointKind::Fat,
                fat_checkpoint_hash: vec![1],
                thin_checkpoint_hash: vec![1],
                fat_configuration_hash: vec![7],
                thin_configuration_hash: vec![8],
                fat_ancestor_hash: vec![3],
                thin_ancestor_hash: vec![3],
                fat_schedule_delta_hash: vec![4],
                thin_schedule_delta_hash: vec![4],
                fat_hash: vec![5],
                thin_hash: vec![5],
            },
        ];

        let mismatch = match check_materialized_replay_oracle(&cases) {
            Ok(()) => panic!("first checkpoint body mismatch should fail"),
            Err(mismatch) => mismatch,
        };

        assert_eq!(mismatch.checkpoint_id, "cp-1");
        assert_eq!(mismatch.fat_hash, vec![5]);
        assert_eq!(mismatch.thin_hash, vec![6]);
    }
}
