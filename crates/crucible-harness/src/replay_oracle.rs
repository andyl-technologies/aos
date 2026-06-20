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
            return Err(ReplayOracleMismatch {
                checkpoint_id: case.checkpoint_id.clone(),
                fat_hash: case.fat_hash.clone(),
                thin_hash: case.thin_hash.clone(),
            });
        }
    }

    Ok(())
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
}
