//! Bounded streamed directory-ledger inventory under original startup supervision.

use super::*;

pub(super) fn visit_attempt_states(
    authority: &crate::anchored_fs::AnchoredDirectory,
    root: &Path,
    maximum: usize,
    visitor: &mut dyn FnMut(AttemptExecutionKey, AttemptRuntimeState),
    boundary: &mut dyn FnMut() -> Result<(), AssignmentLedgerError>,
) -> Result<bool, AssignmentLedgerError> {
    let attempts = root.join("attempts");
    let Some(attempts_authority) = authority
        .open_directory_optional(&attempts, "open-attempt-root")
        .map_err(|source| anchored_ledger_error(source, "open-attempt-root"))?
    else {
        return Ok(true);
    };
    let shards = attempts_authority
        .entry_names(MAX_RUNTIME_ATTEMPT_SHARDS, "read-attempt-root-shards")
        .map_err(|source| anchored_ledger_error(source, "read-attempt-root-shards"))?;
    let mut visited = 0_usize;
    for shard_name in shards {
        let shard_name = shard_name
            .to_str()
            .ok_or_else(|| corrupt("attempt-root-shard-name"))?;
        if shard_name.len() != 2
            || !shard_name
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(corrupt("attempt-root-shard-name"));
        }
        let shard_path = attempts.join(shard_name);
        let shard_authority = attempts_authority
            .open_directory(&shard_path, "open-attempt-root-shard")
            .map_err(|source| anchored_ledger_error(source, "open-attempt-root-shard"))?;
        let mut failure = None;
        let complete = shard_authority
            .visit_entry_names_bounded(
                MAX_RUNTIME_ATTEMPT_RECORDS,
                "read-attempt-root-records",
                &mut |name| {
                    if visited >= maximum {
                        return false;
                    }
                    let result = (|| {
                        let path = shard_path.join(name);
                        let name = name
                            .to_str()
                            .ok_or_else(|| corrupt("attempt-root-record-name"))?;
                        if name.starts_with('.') {
                            return Err(corrupt("attempt-root-unknown-hidden-entry"));
                        }
                        if name.len() != 64
                            || !name
                                .bytes()
                                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                        {
                            return Err(corrupt("attempt-root-record-name"));
                        }

                        boundary()?;
                        let bytes = read_optional_bounded(&shard_authority, &path)?
                            .ok_or_else(|| corrupt("attempt-root-record-disappeared"))?;
                        let (key, state) = decode_attempt_state(&bytes)?;
                        if attempt_path_at(root, key) != path {
                            return Err(corrupt("attempt-root-record-path-identity-mismatch"));
                        }
                        visitor(key, state);
                        visited = visited
                            .checked_add(1)
                            .ok_or_else(|| corrupt("attempt-record-count-overflow"))?;
                        Ok::<(), AssignmentLedgerError>(())
                    })();
                    match result {
                        Ok(()) => true,
                        Err(error) => {
                            failure = Some(error);
                            false
                        }
                    }
                },
            )
            .map_err(|source| anchored_ledger_error(source, "read-attempt-root-records"))?;
        if let Some(error) = failure {
            return Err(error);
        }
        if !complete {
            return Ok(false);
        }
        shard_authority
            .verify_path_binding()
            .map_err(|source| anchored_ledger_error(source, "verify-attempt-root-shard"))?;
    }
    attempts_authority
        .verify_path_binding()
        .map_err(|source| anchored_ledger_error(source, "verify-attempt-root"))?;
    authority
        .verify_path_binding()
        .map_err(|source| anchored_ledger_error(source, "verify-ledger-root"))?;
    Ok(true)
}
