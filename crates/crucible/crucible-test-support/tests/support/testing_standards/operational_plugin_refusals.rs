//! Binds plugin refusal observations to their actual single-effect paths.
//!
//! These component classifications grant no native Source authority, operation
//! payer, or descriptor deadline. Added retries remain visible to the gate.

use super::{Companion, Contract};

const PLAN_REFUSAL: &str = r#"fn interrupted_plan_read_keeps_first_errno_and_negative_post_without_retry() {
    let mut bytes = [0; 16];
    let mut checks = 0;
    let mut effects = 0;

    let result = read_with(
        &mut bytes,
        || {
            checks += 1;
            if checks == 2 { Err(REFUSAL) } else { Ok(()) }
        },
        |_, _| {
            effects += 1;
            Err(libc::EINTR)
        },
    );

    assert_eq!(
        result,
        Err(PluginSetupPlanDescriptorError::ReadOriginal {
            offset: 0,
            result: Err(libc::EINTR),
            original_after: REFUSAL,
        })
    );
    assert_eq!((checks, effects), (2, 1));
}"#;

const PLAN_READ: &str = r#"pub(super) fn read(
    fd: BorrowedFd<'_>,
    bytes: &mut [u8],
    original: Option<&InstallerStartupSource>,
) -> Result<(), PluginSetupPlanDescriptorError> {
    read_with(
        bytes,
        || observe_original(original),
        |destination, offset| {
            let offset = libc::off_t::try_from(offset).map_err(|_| libc::EOVERFLOW)?;
            // SAFETY: the retained native owner keeps fd live for this call. The
            // destination is its exclusive initialized byte slice; pread retains
            // neither the pointer nor the slice and does not change file position.
            let count = unsafe {
                libc::pread(
                    fd.as_raw_fd(),
                    destination.as_mut_ptr().cast(),
                    destination.len(),
                    offset,
                )
            };
            if count < 0 {
                Err(super::last_errno())
            } else {
                usize::try_from(count).map_err(|_| libc::EOVERFLOW)
            }
        },
    )
}"#;

const PLAN_OBSERVE: &str = r#"fn observe_original(original: Option<&InstallerStartupSource>) -> Result<(), StartupSourceError> {
    match original {
        Some(original) => original.check(),
        #[cfg(test)]
        None => Ok(()),
        #[cfg(not(test))]
        None => Err(StartupSourceError::Ownership {
            reason: "plugin plan read has no retained installing Original",
        }),
    }
}"#;

const PLAN_READ_WITH: &str = r#"fn read_with(
    bytes: &mut [u8],
    mut check: impl FnMut() -> Result<(), StartupSourceError>,
    mut read: impl FnMut(&mut [u8], usize) -> Result<usize, i32>,
) -> Result<(), PluginSetupPlanDescriptorError> {
    let mut offset = 0;
    while offset < bytes.len() {
        check().map_err(|source| PluginSetupPlanDescriptorError::Original { source })?;
        let result = read(&mut bytes[offset..], offset);
        if let Err(original_after) = check() {
            return Err(PluginSetupPlanDescriptorError::ReadOriginal {
                offset,
                result,
                original_after,
            });
        }

        let count = match result {
            Err(libc::EINTR) => continue,
            Err(errno) => {
                return Err(PluginSetupPlanDescriptorError::Io {
                    operation: "read plugin setup-plan descriptor",
                    errno,
                });
            }
            Ok(count) => count,
        };
        if count == 0 {
            return Err(PluginSetupPlanDescriptorError::Truncated {
                expected: bytes.len(),
                actual: offset,
            });
        }
        offset += count;
    }
    Ok(())
}"#;

const DIAGNOSTIC_REFUSAL: &str = r#"fn short_diagnostic_write_stops_without_retry_and_still_requests_shutdown() {
        let error = LiveWhiteboxError::IcountObservation;
        let mut writes = 0;
        let mut expected = 0;
        let mut shutdowns = 0;

        let refused = report_failure(
            &error,
            |bytes| {
                writes += 1;
                expected = bytes.len();
                Ok(bytes.len() - 1)
            },
            || shutdowns += 1,
        )
        .unwrap_err();

        assert!(
            matches!(refused, DiagnosticWriteError::ShortWrite { written, expected: count }
            if count == expected && written + 1 == expected)
        );
        assert_eq!(writes, 1);
        assert_eq!(shutdowns, 1);
    }"#;

const DIAGNOSTIC_WRITER: &str = r#"impl<F> fmt::Write for DiagnosticWriter<F>
where
    F: FnMut(&[u8]) -> io::Result<usize>,
{
    fn write_str(&mut self, text: &str) -> fmt::Result {
        if self.first.is_some() {
            return Err(fmt::Error);
        }
        if text.is_empty() {
            return Ok(());
        }

        let error = match (self.write)(text.as_bytes()) {
            Ok(written) if written == text.len() => return Ok(()),
            Ok(written) => DiagnosticWriteError::ShortWrite {
                written,
                expected: text.len(),
            },
            Err(source) => DiagnosticWriteError::Kernel(source),
        };
        self.first = Some(error);
        Err(fmt::Error)
    }
}"#;

const DIAGNOSTIC_REPORT: &str = r#"pub(super) fn report_failure(
    error: &LiveWhiteboxError,
    write: impl FnMut(&[u8]) -> io::Result<usize>,
    shutdown: impl FnOnce(),
) -> Result<(), DiagnosticWriteError> {
    let mut writer = DiagnosticWriter { write, first: None };
    let formatted = writeln!(
        writer,
        "crucible-qemu-plugin: live white-box callback failed: {error}"
    );

    // Reporting cannot suppress the actual failure response, including when the
    // descriptor accepted only a prefix. A negative write is not retry authority.
    shutdown();
    formatted.map_err(|_| writer.first.unwrap_or(DiagnosticWriteError::Formatting))
}"#;

const DIAGNOSTIC_STDERR: &str = r#"pub(super) fn write_stderr(bytes: &[u8]) -> io::Result<usize> {
    // SAFETY: the slice stays readable through this synchronous write. Stderr
    // is borrowed; the call neither transfers nor duplicates its descriptor.
    let written = unsafe { libc::write(libc::STDERR_FILENO, bytes.as_ptr().cast(), bytes.len()) };
    if written < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(written as usize)
    }
}"#;

pub(super) const CONTRACTS: &[Contract] = &[
    Contract {
        package: "crucible-qemu-plugin",
        target: "src/setup/plan_read/tests",
        required: &[PLAN_REFUSAL],
        expressions: &[(PLAN_REFUSAL, 1)],
        companions: &[Companion {
            path: "crates/crucible/crucible-qemu-plugin/src/setup/plan_read.rs",
            required: &[PLAN_READ, PLAN_OBSERVE, PLAN_READ_WITH],
            counts: &[(PLAN_READ, 1), (PLAN_OBSERVE, 1), (PLAN_READ_WITH, 1)],
        }],
    },
    Contract {
        package: "crucible-qemu-plugin",
        target: "src/runtime/live_whitebox/diagnostic",
        required: &[
            DIAGNOSTIC_REFUSAL,
            DIAGNOSTIC_WRITER,
            DIAGNOSTIC_REPORT,
            DIAGNOSTIC_STDERR,
        ],
        expressions: &[(DIAGNOSTIC_REFUSAL, 1)],
        companions: &[],
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{mask_with_companions, read_companions};

    fn has_retry(code: &str) -> bool {
        crate::flaky_escape_failures("unreviewed", "unreviewed", code)
            .iter()
            .any(|finding| finding.contains("`retry`"))
    }

    fn source(contract: &Contract) -> Result<String, std::io::Error> {
        let root = crate::workspace_root();
        let path = crate::workspace::package_path(&root.join("crates"), contract.package)
            .join(format!("{}.rs", contract.target));
        Ok(crate::scrub_comments_and_strings(&std::fs::read_to_string(
            path,
        )?))
    }

    #[test]
    fn plugin_refusal_classification_requires_the_actual_owner_and_preserves_added_retries()
    -> Result<(), Box<dyn std::error::Error>> {
        for contract in CONTRACTS {
            let code = source(contract)?;
            let companions = read_companions(contract)?;

            assert!(has_retry(&code));
            assert!(!has_retry(&mask_with_companions(
                contract,
                &code,
                &companions
            )));
            let extra = format!("{code}\nfn unrelated_retry() {{ loop {{ retry(); }} }}");
            assert!(has_retry(&mask_with_companions(
                contract,
                &extra,
                &companions
            )));

            for (index, binding) in contract.companions.iter().enumerate() {
                for required in binding.required {
                    let mut changed = companions.clone();
                    assert!(changed[index].contains(required));
                    changed[index] = changed[index].replacen(required, "foreign();", 1);
                    assert!(has_retry(&mask_with_companions(contract, &code, &changed)));
                }
            }
        }
        Ok(())
    }

    #[test]
    fn plugin_refusal_classification_rejects_changed_effects_and_refusal_observations()
    -> Result<(), Box<dyn std::error::Error>> {
        for (index, before, after) in [
            (0, "ifchecks==2", "ifchecks==3"),
            (
                0,
                "assert_eq!((checks,effects),(2,1));",
                "assert_eq!((checks,effects),(4,2));",
            ),
            (1, "Ok(bytes.len()-1)", "Ok(bytes.len())"),
            (1, "assert_eq!(writes,1);", "assert_eq!(writes,2);"),
            (1, "assert_eq!(shutdowns,1);", "assert_eq!(shutdowns,0);"),
            (1, "shutdown();", "drop(shutdown);"),
            (1, "self.first=Some(error);", "self.first=None;"),
        ] {
            let contract = &CONTRACTS[index];
            let code = super::super::compact_code(&source(contract)?);
            let companions = read_companions(contract)?;

            assert!(
                code.contains(before),
                "missing actual refusal cut: {before}"
            );
            // Change the reviewed owner, rather than an earlier test that
            // happens to contain the same assertion or supervisor expression.
            let owner = contract
                .required
                .iter()
                .find_map(|required| {
                    let required =
                        super::super::compact_code(&crate::scrub_comments_and_strings(required));
                    required.contains(before).then_some(required)
                })
                .unwrap_or_else(|| panic!("missing reviewed owner for cut: {before}"));
            let changed = code.replacen(&owner, &owner.replacen(before, after, 1), 1);
            assert!(
                has_retry(&mask_with_companions(contract, &changed, &companions)),
                "changed refusal was classified: {before}"
            );
        }
        Ok(())
    }
}
