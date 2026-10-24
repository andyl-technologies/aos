//! Reports undeclared filesystem datasets without changing pool contents.
//!
//! The advisory service remains failed when drift is found. Its queued manager
//! job does not turn this report into a transaction-blocking storage policy.

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Output;

use anyhow::{Context as _, Result, ensure};

use crate::native_zfs_dataset::{validate_dataset_name, validate_pool_name};
use crate::process::run_native;

pub(crate) fn run(zfs: &Path, pool: &str, declared: &[String]) -> Result<()> {
    report_with(zfs, pool, declared, |executable, arguments| {
        run_native(executable, arguments, 5_000)
    })
}

fn report_with(
    zfs: &Path,
    pool: &str,
    declared: &[String],
    query: impl FnOnce(&Path, &[&str]) -> Result<Output>,
) -> Result<()> {
    validate_pool_name(pool)?;
    let prefix = format!("{pool}/");
    let mut allowed = BTreeSet::new();
    for name in declared {
        validate_dataset_name(
            name.strip_prefix(&prefix)
                .context("declared dataset is outside the pool")?,
        )?;
        ensure!(allowed.insert(name.as_str()), "duplicate declared dataset");
    }

    let output = query(
        zfs,
        &[
            "list",
            "-H",
            "-o",
            "name",
            "-t",
            "filesystem",
            "-r",
            "--",
            pool,
        ],
    )?;
    ensure!(
        output.status.success(),
        "ZFS dataset enumeration failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let names = String::from_utf8(output.stdout).context("decoding ZFS dataset enumeration")?;
    let mut seen = BTreeSet::new();
    let mut undeclared = Vec::new();
    for name in names.lines().filter(|name| !name.is_empty()) {
        ensure!(seen.insert(name), "duplicate filesystem in ZFS enumeration");
        if name == pool {
            continue;
        }
        validate_dataset_name(
            name.strip_prefix(&prefix)
                .context("enumerated filesystem is outside the pool")?,
        )?;
        if !allowed.contains(name) {
            undeclared.push(format!("aos-zfs-report-undeclared: {name} exists in the pool but no configuration declares it"));
        }
    }
    ensure!(seen.contains(pool), "ZFS enumeration omitted the pool root");
    ensure!(undeclared.is_empty(), "{}", undeclared.join("\n"));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;

    fn output(status: i32, stdout: &[u8]) -> Output {
        Output {
            status: ExitStatus::from_raw(status << 8),
            stdout: stdout.to_vec(),
            stderr: b"query failed".to_vec(),
        }
    }

    fn check(stdout: &[u8]) -> Result<()> {
        let declared = ["rpool/data".into(), "rpool/reserved".into()];
        report_with(
            Path::new("/nix/store/pinned-zfs/sbin/zfs"),
            "rpool",
            &declared,
            |executable, arguments| {
                assert_eq!(executable, Path::new("/nix/store/pinned-zfs/sbin/zfs"));
                assert_eq!(
                    arguments,
                    [
                        "list",
                        "-H",
                        "-o",
                        "name",
                        "-t",
                        "filesystem",
                        "-r",
                        "--",
                        "rpool"
                    ]
                );
                Ok(output(0, stdout))
            },
        )
    }

    #[test]
    fn reports_only_filesystems_and_excludes_root_declared_and_reserved() {
        check(b"rpool\nrpool/data\nrpool/reserved\n").unwrap();
    }

    #[test]
    fn every_undeclared_filesystem_remains_visible_in_the_failure() {
        let error = check(b"rpool\nrpool/data\nrpool/foreign\nrpool/other\n")
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("rpool/foreign exists in the pool but no configuration declares it")
        );
        assert!(error.contains("rpool/other exists in the pool but no configuration declares it"));
    }

    #[test]
    fn disabled_reservation_is_not_implicitly_allowed() {
        let error = report_with(
            Path::new("/nix/store/pinned-zfs/sbin/zfs"),
            "rpool",
            &[],
            |_, _| Ok(output(0, b"rpool\nrpool/reserved\n")),
        )
        .unwrap_err();
        assert!(error.to_string().contains("rpool/reserved exists"));
    }

    #[test]
    fn enumeration_failure_and_malformed_output_fail_closed() {
        assert!(
            report_with(
                Path::new("/nix/store/pinned-zfs/sbin/zfs"),
                "rpool",
                &[],
                |_, _| Ok(output(1, b""))
            )
            .is_err()
        );
        for names in [
            b"rpool\n\xff\n".as_slice(),
            b"rpool\nforeign/data\n",
            b"rpool\nrpool/bad name\n",
            b"",
            b"rpool\nrpool\n",
        ] {
            assert!(check(names).is_err(), "accepted {names:?}");
        }
    }

    #[test]
    fn malformed_declarations_fail_before_query_dispatch() {
        for name in ["other/data", "rpool/", "rpool/data\n"] {
            assert!(
                report_with(
                    Path::new("/nix/store/pinned-zfs/sbin/zfs"),
                    "rpool",
                    &[name.into()],
                    |_, _| panic!("invalid declaration reached ZFS")
                )
                .is_err()
            );
        }
    }
}
