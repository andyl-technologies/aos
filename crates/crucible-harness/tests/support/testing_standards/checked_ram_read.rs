//! Requires the checked RAM read's original accounts, bounded body and EOF.
//!
//! These source obligations replace the removed raw RAM read helper. They
//! grant no flaky-token masking, test repetition or operational allowance.

use std::fs;
use std::path::Path;

struct Input {
    path: &'static str,
    required: &'static [&'static str],
    counts: &'static [(&'static str, usize)],
}

const INPUTS: &[Input] = &[
    Input {
        path: "crates/crucible-cas/src/ram/codec.rs",
        required: &[
            "fn read_envelope_with_partition(",
            "pub(super) fn read_envelope_using(",
            "let mut checked = || { boundary()?; verify(original) };",
            "let account = work.original().child().map_err(admission)?;",
            "let (maximum_bytes, maximum_children) = object_limits(id)?;",
            "backend.read_with_boundary(original, id, None, boundary)",
            "if source.logical_length() > maximum_bytes",
            "source.read_all_with_boundary(original, maximum_bytes, &mut checked)",
            "let _terminal_scope = record.original.enter();",
            r#"if let Err(error) = work.checked(|original, boundary| {
                let mut checked = || {
                    boundary()?;
                    verify(original)
                };
                crate::content_store::checked_reader::check(original, &mut checked)
            })"#,
            "if !id.authenticates(bytes)",
            "ContentEnvelope::from_canonical_bytes_with_child_limit(bytes, maximum_children)?",
        ],
        counts: &[
            (
                "source.read_all_with_boundary(original, maximum_bytes, &mut checked)",
                2,
            ),
            (
                "backend.read_with_boundary(original, id, None, boundary)",
                1,
            ),
            ("let _terminal_scope = record.original.enter();", 1),
            ("let mut checked = || { boundary()?; verify(original) };", 4),
        ],
    },
    Input {
        path: "crates/crucible-cas/src/content_store/checked_reader.rs",
        required: &[
            "let mut reader = source.open_with_boundary(caller, boundary)?;",
            "let source = reader.original_account().clone();",
            "batch::read_reader_under(&source, caller, length, maximum, boundary,",
            "&mut |output, boundary| reader.read_with_boundary(output, boundary)",
            "if caller.same_account(source) { return check(caller, boundary); }",
            "caller.verify_live().map_err(|error| batch::admission_under(caller, error))?;",
            "source.verify_live().map_err(|error| batch::admission_under(source, error))?;",
            "boundary()?;",
        ],
        counts: &[],
    },
    Input {
        path: "crates/crucible-cas/src/content_store/batch.rs",
        required: &[
            "pub(crate) fn read_reader_under<F>(",
            "super::checked_reader::check_pair(caller, account, boundary)?;",
            "if length > maximum",
            "let credit = account.reserve_scratch_array::<u8>(capacity)",
            "while observed < capacity",
            "let end = capacity.min(observed.saturating_add(64 * 1024));",
            "let count = read(&mut bytes[observed..end], boundary)?;",
            "if count > end - observed",
            "let mut extra = [0_u8; 1];",
            "let count = read(&mut extra, boundary)?;",
            "if observed != capacity || count != 0",
            "observed: (observed as u64).saturating_add(count as u64)",
            "account.verify_live().map_err(|error| admission_under(account, error))?;",
            "Ok(OwnedBlobBytes { bytes, _credit: credit, })",
        ],
        counts: &[
            (
                "super::checked_reader::check_pair(caller, account, boundary)?;",
                6,
            ),
            ("let count = read(&mut extra, boundary)?;", 1),
        ],
    },
    Input {
        path: "crates/crucible-cas/src/ram/store_boundary.rs",
        required: &[
            "let original = self.original;",
            "let mut first = None;",
            "let result = operation(original, &mut ||",
            "first = Some(error);",
            "(Some(first), Ok(value)) => { drop(value); Err(first) }",
            "(Some(first), Err(storage @ StoreError::RamBoundary { .. })) => { Err(self.retain_boundary(first, storage)) }",
            "self.state.first_failure = Some(FirstReadCause::Boundary(cause.clone()));",
            "let cause = slot.retain(Some(first), storage.into());",
        ],
        counts: &[],
    },
    Input {
        path: "crates/crucible-cas/src/ram/bounded_read.rs",
        required: &[
            "work: &'read mut Work<'operation>",
            "let previous = self.inventory_admission;",
            "if let Some(previous) = previous { previous(id)?; } admit(id)",
            "inventory_admission: Some(&admitted)",
            "selected.set(Some(id)); reader.lookup(backend, original, id, boundary)",
            "if let (Some(admit), Some(id)) = (admission, selected.get()) { admit(id)?; } verify_physical(original, physical)",
            "let result = result.and_then(|()| { self.work.checked(|original, boundary| { crate::content_store::checked_reader::check(original, boundary)?; verify_physical(original, physical) }) });",
            "state: &'read mut ReadState",
            "let previous = std::mem::replace(&mut self.state.phase, ReadPhase::Consumed);",
            "(ReadPhase::Failed, Ok(())) => Err(self.first_failure())",
            "(ReadPhase::Failed, Err(error)) => Err(self.work.account.reconcile_failed_read(error))",
            "if let Err(error) = original.verify_live()",
            "return Err(self.work.account.fail_read(error.into()));",
            "if let Some(first) = work.account.read_failure()",
            "verify_physical(original, check.previous)?; check.guard.verify()?;",
            "if let Some(backend) = checked_default(self.physical)",
            "let (completion, refused) = session.finish(check, completion);",
            "backend.consume_canonical_record(original, id, maximum, &mut guarded,",
            "response.charge_array::<u8>(length)",
            "super::canonical_tree::read_tree_canonical(bytes, expected).map(|_| ())",
            "super::canonical_tree::validate_envelope_canonical(bytes, children)",
            "self.complete_session_read(pending_error.take(), result.map(ReadValue::Canonical), eof_refused.get(),)",
        ],
        counts: &[
            (
                "let previous = std::mem::replace(&mut self.state.phase, ReadPhase::Consumed);",
                1,
            ),
            (
                "let (completion, refused) = session.finish(check, completion);",
                1,
            ),
        ],
    },
    Input {
        path: "crates/crucible-cas/src/content_store/graph.rs",
        required: &[
            "request.execute_graph_inventory(self, self.root.as_ref(), &|id| self.require_admitted(id))",
        ],
        counts: &[(
            "request.execute_graph_inventory(self, self.root.as_ref(), &|id| self.require_admitted(id))",
            1,
        )],
    },
    Input {
        path: "crates/crucible-cas/src/content_store/sqlite/bounded_read.rs",
        required: &[
            "super::super::batch::with_id_text(id, |encoded|",
            ".query_row(METADATA, [encoded], |row|",
            "AdmissionEdge::OriginalOnly => original.verify_live()",
            "admit(length)?; if length > maximum",
            "let mut consume = Some(consume);",
            ".prepare(BODY)",
            ".query(rusqlite::params![encoded, length, maximum])",
            "if bytes.len() as u64 != length",
            "let consume = consume.take().ok_or(StoreError::Unsupported",
            "consume(bytes)",
        ],
        counts: &[
            ("busy::retry(connection, true, quarantined, check, |_|", 2),
            (".query_row(METADATA, [encoded], |row|", 1),
            (".query(rusqlite::params![encoded, length, maximum])", 1),
        ],
    },
    Input {
        path: "crates/crucible-cas/src/content_store/sqlite/bounded_read/session.rs",
        required: &[
            "original: &'original DecodeBudget",
            "original.verify_live()",
            "self.original.verify_live()",
            ".try_lock_for(\"lock-comparison-sqlite-snapshot\")?",
            "let credit = match self.scope_credit.take()",
            "self.pending_eof = result.is_ok();",
            "AdmissionEdge::OriginalOnly, admit, consume",
            "if self.pending_eof { let result = self.check(boundary);",
            "self.close(boundary, result)",
            "drop(connection); drop(staging);",
            "self.scope_credit = Some(credit); self.phase = Phase::Dormant;",
        ],
        counts: &[
            (".try_lock_for(\"lock-comparison-sqlite-snapshot\")?", 1),
            ("AdmissionEdge::OriginalOnly, admit, consume", 1),
            ("drop(connection); drop(staging);", 1),
        ],
    },
    Input {
        path: "crates/crucible-cas/src/content_store/sqlite/batch/busy/snapshot.rs",
        required: &[
            "original.verify_live()",
            "checked(original, quarantined, boundary)?;",
            "connection.busy_timeout(Duration::ZERO)",
            "if rollback.is_some() || restoration.is_some()",
            "quarantined.store(true, Ordering::Release);",
            "connection.execute_batch(\"ROLLBACK\")",
            ".busy_timeout(Duration::from_millis(self.saved_timeout)).err()",
            "self.sentinel.armed = false;",
            "Ok(value) if rollback.is_none() && restoration.is_none() => Ok((value, credit))",
            "other.err(), rollback, restoration, outcome, credit, None",
        ],
        counts: &[
            ("retry(connection, false, quarantined, &mut check, |_|", 1),
            ("connection.busy_timeout(Duration::ZERO)", 1),
            (
                "match connection.execute_batch(\"ROLLBACK\") { Ok(()) if connection.is_autocommit() => None",
                1,
            ),
        ],
    },
    Input {
        path: "crates/crucible-cas/src/ram/difference/sqlite.rs",
        required: &[
            "self.session.record(expected.id, 4096, self.boundary",
            "canonical_tree::read_tree_canonical(bytes, expected)",
            "self.session.pause(self.boundary)?; (self.visitor)(region, page)",
            "self.session.pause(self.boundary)?; self.session.check_original(self.boundary)?;",
        ],
        counts: &[("(self.visitor)(region, page)", 1)],
    },
    Input {
        path: "crates/crucible-cas/src/content_store/sqlite/batch/busy/single_record.rs",
        required: &[
            "let credit = snapshot::SnapshotScope::prepare(original)?;",
            "let mut statement = match check().and_then(|()| { connection.prepare(METADATA)",
            "let mut rows = statement.query([encoded])",
            "let admit = admit.take().ok_or(StoreError::Unsupported",
            "admitted = true; let mut bytes = admit(length)?; if length > maximum",
            "original.verify_live().map_err(|error| admission_under(original, error))?; let mut blob = connection.blob_open(DatabaseName::Main, \"objects\", \"body\", rowid, true)",
            "if blob.len() as u64 != length",
            "if bytes.capacity() < length || !bytes.is_empty()",
            "bytes.resize(length, 0); for chunk in bytes.chunks_mut(64 * 1024) { check()?; blob.read_exact(chunk)",
            "if !id.authenticates(&bytes) { return Err(StoreError::Corrupt { id }); }",
            "let valid = validate.take().ok_or(StoreError::Unsupported",
            "check()?; if !valid { return Err(StoreError::Unsupported",
            "cleanup[0] = blob.close().err();",
            "cleanup[1] = match rows.next()",
            "drop(rows); result",
            "cleanup[2] = statement.finalize().err();",
            "let restoration = connection.busy_timeout(Duration::from_millis(saved)).err();",
            "cleanup.iter().all(Option::is_none) && restoration.is_none() && connection.is_autocommit()",
            "read_scope_error(result.err(), None, restoration, cleanup, SqliteCommitOutcome::NotCommitted, credit, None,)",
        ],
        counts: &[
            ("snapshot::SnapshotScope::prepare(original)?", 1),
            ("connection.prepare(METADATA)", 1),
            ("admit.take()", 1),
            ("admit(length)?", 1),
            ("connection.blob_open(", 1),
            ("blob.read_exact(chunk)", 1),
            ("validate.take()", 1),
            ("if !id.authenticates(&bytes)", 1),
            ("blob.close().err()", 1),
            ("cleanup[1] = match rows.next()", 1),
            ("statement.finalize().err()", 1),
        ],
    },
    Input {
        path: "crates/crucible-cas/src/ram/object_source.rs",
        required: &[
            "canonical: CanonicalOwner,",
            "struct CanonicalOwner(Option<Arc<CanonicalObject>>);",
            "std::alloc::Layout::new::<[std::sync::atomic::AtomicUsize; 2]>().extend(std::alloc::Layout::new::<CanonicalObject>())",
            "u64::try_from(layout.pad_to_align().size())",
            "if let Some(value) = self.0.take() { drop(Arc::into_inner(value)); }",
            "let account = work.original().child().map_err(super::codec_ownership::admission)?;",
            "let _scope = account.enter();",
            "super::bounded_read::read_canonical_tree(self.backend.as_ref(), expected, &account, work,)",
            "super::bounded_read::read_canonical(self.backend.as_ref(), id, &account, work)",
            "super::codec::decode_envelope(id, &bytes, maximum_children, &account)?",
            "account.charge_bytes(CanonicalOwner::allocation_bytes()?).map_err(super::codec_ownership::admission)?; account.verify_live().map_err(super::codec_ownership::admission)?; let record = RamObjectRecord",
            "canonical: CanonicalOwner(Some(Arc::new(CanonicalObject { bytes, _custody: account.custody(), })))",
            "Err(error) if work.account.read_failure().is_none() => { Err(work.account.fail_read(error).into()) }",
        ],
        counts: &[
            ("Arc::into_inner(value)", 1),
            ("Arc::new(CanonicalObject", 1),
            ("CanonicalOwner::allocation_bytes()", 1),
            ("Arc::downgrade", 0),
            ("mod sqlite;", 0),
        ],
    },
];

fn compact(source: &str) -> String {
    super::scrub_comments_and_strings(source)
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn input_failures(input: &Input, source: &str) -> Vec<String> {
    let source = compact(source);
    let mut failures = input
        .required
        .iter()
        .filter(|required| !source.contains(&compact(required)))
        .map(|required| {
            format!(
                "{} is missing checked RAM read obligation: {required}",
                input.path
            )
        })
        .collect::<Vec<_>>();
    for (expression, expected) in input.counts {
        let actual = source.match_indices(&compact(expression)).count();
        if actual != *expected {
            failures.push(format!(
                "{} requires {expected} checked RAM read sites, observed {actual}: {expression}",
                input.path,
            ));
        }
    }
    failures
}

fn retired_source_failures(root: &Path) -> Vec<String> {
    let retired = "crates/crucible-cas/src/ram/object_source/sqlite.rs";
    if root.join(retired).exists() {
        vec![format!(
            "{retired} is a retired closed-transfer implementation"
        )]
    } else {
        Vec::new()
    }
}

pub(crate) fn failures(root: &Path) -> std::io::Result<Vec<String>> {
    let mut failures = retired_source_failures(root);
    for input in INPUTS {
        failures.extend(input_failures(
            input,
            &fs::read_to_string(root.join(input.path))?,
        ));
    }
    Ok(failures)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retired_closed_transfer_source_cannot_be_reintroduced()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        assert!(retired_source_failures(root.path()).is_empty());

        let retired = root
            .path()
            .join("crates/crucible-cas/src/ram/object_source/sqlite.rs");
        fs::create_dir_all(retired.parent().expect("retired source parent"))?;
        fs::write(&retired, "//! Retired implementation.\n")?;
        assert_eq!(retired_source_failures(root.path()).len(), 1);
        Ok(())
    }

    #[test]
    fn checked_ram_read_obligations_reject_each_removed_original_body_and_eof_proof()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = super::super::super::workspace_root();
        let findings = failures(&root)?;
        assert!(findings.is_empty(), "{findings:?}");

        for input in INPUTS {
            let source = fs::read_to_string(root.join(input.path))?;
            let source = compact(&source);
            for required in input.required {
                let required = compact(required);
                assert!(source.contains(&required));
                let removed = source.replace(&required, "removed_original_read_proof()");
                assert!(!input_failures(input, &removed).is_empty());
            }
            for (expression, count) in input.counts {
                let expression = compact(expression);
                assert_eq!(source.match_indices(&expression).count(), *count);
                if *count != 0 {
                    let removed = source.replacen(&expression, "removed_original_read_site()", 1);
                    assert!(!input_failures(input, &removed).is_empty());
                }
                let added = format!("{source}{expression}");
                assert!(!input_failures(input, &added).is_empty());
            }
        }
        Ok(())
    }
}
