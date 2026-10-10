//! Shared bounded file handling for offline campaign record authoring.

use super::*;

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;

use rustix::fs::{CWD, RenameFlags};
use serde::Serialize;

const SCENARIO_BODY_NAME: &str = "scenario.bin";
const SCHEDULE_BODY_NAME: &str = "schedule.bin";
const IMPORT_MANIFEST_NAME: &str = "import.toml";

#[derive(Serialize)]
struct ConfigurationImportManifest<'a> {
    schema: &'static str,
    version: u32,
    configuration: [ConfigurationImportEntry<'a>; 1],
}

#[derive(Serialize)]
struct ConfigurationImportEntry<'a> {
    scenario: &'a Path,
    schedule: &'a Path,
}

pub(super) fn read_bounded_bytes(
    path: &Path,
    kind: &str,
    maximum_bytes: usize,
) -> Result<Vec<u8>, CliError> {
    let file = File::open(path).map_err(|error| {
        CliError::Io(io::Error::new(
            error.kind(),
            format!("could not open {kind} at {}: {error}", path.display()),
        ))
    })?;
    let maximum = u64::try_from(maximum_bytes)
        .map_err(|_| backend_error(format!("{kind} bound exceeds u64")))?;
    let mut reader = file.take(maximum.saturating_add(1));
    let mut bytes = Vec::new();
    crucible_session::engine::owned_decode::charge_bytes(std::mem::size_of::<[u8; 4096]>() as u64)
        .map_err(|error| backend_error(format!("{kind} scratch admission failed: {error}")))?;
    let mut chunk = [0_u8; 4096];
    loop {
        let count = reader.read(&mut chunk).map_err(|error| {
            CliError::Io(io::Error::new(
                error.kind(),
                format!("could not read {kind} at {}: {error}", path.display()),
            ))
        })?;
        if count == 0 {
            break;
        }
        let required = bytes
            .len()
            .checked_add(count)
            .ok_or_else(|| backend_error(format!("{kind} length overflow")))?;
        if required > bytes.capacity() {
            let growth = bytes
                .capacity()
                .saturating_mul(2)
                .max(required)
                .min(maximum_bytes.saturating_add(1));
            let additional = growth - bytes.len();
            crucible_session::engine::owned_decode::reserve_vec(&mut bytes, additional)
                .map_err(|error| backend_error(format!("{kind} admission failed: {error}")))?;
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
    if bytes.len() > maximum_bytes {
        return Err(usage_error(format!("{kind} exceeds {maximum_bytes} bytes")));
    }
    Ok(bytes)
}

pub(super) fn read_bounded_utf8(
    path: &Path,
    kind: &str,
    maximum_bytes: usize,
) -> Result<String, CliError> {
    let bytes = read_bounded_bytes(path, kind, maximum_bytes)?;
    String::from_utf8(bytes).map_err(|_| usage_error(format!("{kind} is not valid UTF-8")))
}

/// Writes one strict scenario/schedule import bundle without replacing output.
pub(super) fn write_configuration_import_bundle(
    output: &Path,
    kind: &str,
    scenario_body: &[u8],
    schedule_body: &[u8],
) -> Result<PathBuf, CliError> {
    write_new_bundle(output, kind, |staged, final_| {
        let final_scenario = final_.join(SCENARIO_BODY_NAME);
        let final_schedule = final_.join(SCHEDULE_BODY_NAME);
        let manifest = ConfigurationImportManifest {
            schema: "crucible.campaign-import",
            version: 1,
            configuration: [ConfigurationImportEntry {
                scenario: &final_scenario,
                schedule: &final_schedule,
            }],
        };
        let manifest = toml::to_string(&manifest).map_err(|error| {
            backend_error(format!(
                "campaign configuration import manifest encoding failed: {error}"
            ))
        })?;

        write_new_record(
            &staged.join(SCENARIO_BODY_NAME),
            "campaign scenario body",
            scenario_body,
        )?;
        write_new_record(
            &staged.join(SCHEDULE_BODY_NAME),
            "campaign configuration schedule",
            schedule_body,
        )?;
        write_new_record(
            &staged.join(IMPORT_MANIFEST_NAME),
            "campaign configuration import manifest",
            manifest.as_bytes(),
        )
    })
    .map(|(directory, ())| directory)
}

pub(super) const fn scenario_body_name() -> &'static str {
    SCENARIO_BODY_NAME
}

pub(super) const fn schedule_body_name() -> &'static str {
    SCHEDULE_BODY_NAME
}

pub(super) const fn import_manifest_name() -> &'static str {
    IMPORT_MANIFEST_NAME
}

pub(super) fn write_new_record(path: &Path, kind: &str, bytes: &[u8]) -> Result<(), CliError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent).map_err(|error| {
        CliError::Io(io::Error::new(
            error.kind(),
            format!(
                "could not create temporary {kind} in {}: {error}",
                parent.display()
            ),
        ))
    })?;
    temporary.write_all(bytes).map_err(|error| {
        CliError::Io(io::Error::new(
            error.kind(),
            format!("could not write {kind} at {}: {error}", path.display()),
        ))
    })?;
    temporary.as_file().sync_all().map_err(|error| {
        CliError::Io(io::Error::new(
            error.kind(),
            format!("could not sync {kind} at {}: {error}", path.display()),
        ))
    })?;
    temporary.persist_noclobber(path).map_err(|error| {
        CliError::Io(io::Error::new(
            error.error.kind(),
            format!(
                "could not install new {kind} at {}: {}",
                path.display(),
                error.error
            ),
        ))
    })?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| {
            CliError::Io(io::Error::new(
                error.kind(),
                format!(
                    "could not sync {kind} output directory {}: {error}",
                    parent.display()
                ),
            ))
        })
}

/// Builds and atomically installs one new multi-file authoring bundle.
///
/// `populate` writes only inside an owner-private temporary directory. The
/// complete directory becomes visible under `path` through one no-replace
/// rename after every staged entry and the directory itself have been synced.
pub(super) fn write_new_bundle<T>(
    path: &Path,
    kind: &str,
    populate: impl FnOnce(&Path, &Path) -> Result<T, CliError>,
) -> Result<(PathBuf, T), CliError> {
    write_new_bundle_with_boundary(path, kind, populate, &mut || Ok(()))
}

/// Atomically installs one new bundle while checking its host operation owner.
///
/// # Errors
/// Returns authoring I/O errors or operational cancellation before publication;
/// a failure after rename retains the installed directory for reconciliation.
pub(super) fn write_new_bundle_with_boundary<T>(
    path: &Path,
    kind: &str,
    populate: impl FnOnce(&Path, &Path) -> Result<T, CliError>,
    boundary: &mut dyn FnMut() -> Result<(), CliError>,
) -> Result<(PathBuf, T), CliError> {
    boundary()?;
    let file_name = path
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| usage_error(format!("{kind} output must name a new directory")))?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent = fs::canonicalize(parent).map_err(|error| {
        CliError::Io(io::Error::new(
            error.kind(),
            format!(
                "could not resolve {kind} output parent {}: {error}",
                parent.display()
            ),
        ))
    })?;
    let output = parent.join(file_name);
    let temporary = tempfile::Builder::new()
        .prefix(".crucible-campaign-authoring-")
        .tempdir_in(&parent)
        .map_err(|error| {
            CliError::Io(io::Error::new(
                error.kind(),
                format!(
                    "could not create temporary {kind} in {}: {error}",
                    parent.display()
                ),
            ))
        })?;

    let value = populate(temporary.path(), &output)?;
    boundary()?;
    File::open(temporary.path())
        .and_then(|directory| directory.sync_all())
        .map_err(|error| {
            CliError::Io(io::Error::new(
                error.kind(),
                format!(
                    "could not sync temporary {kind} at {}: {error}",
                    temporary.path().display()
                ),
            ))
        })?;
    boundary()?;
    rustix::fs::renameat_with(CWD, temporary.path(), CWD, &output, RenameFlags::NOREPLACE)
        .map_err(|error| {
            let error = io::Error::from_raw_os_error(error.raw_os_error());
            CliError::Io(io::Error::new(
                error.kind(),
                format!(
                    "could not install new {kind} at {}: {error}",
                    output.display()
                ),
            ))
        })?;
    let _installed = temporary.keep();
    File::open(&parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| {
            CliError::Io(io::Error::new(
                error.kind(),
                format!(
                    "could not sync {kind} output directory {}: {error}",
                    parent.display()
                ),
            ))
        })?;
    boundary()?;

    Ok((output, value))
}

#[cfg(test)]
mod publication_tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn canceled_prepared_bundle_does_not_become_visible() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempfile::tempdir()?;
        let output = directory.path().join("bundle");
        let prepared = Cell::new(false);
        let mut boundary = || {
            if prepared.get() {
                Err(backend_error("operation canceled"))
            } else {
                Ok(())
            }
        };

        let result = write_new_bundle_with_boundary(
            &output,
            "test bundle",
            |staged, _| {
                write_new_record(&staged.join("payload"), "test payload", b"authenticated")?;
                prepared.set(true);
                Ok(())
            },
            &mut boundary,
        );

        assert!(result.is_err());
        assert!(!output.exists());
        assert_eq!(fs::read_dir(directory.path())?.count(), 0);
        Ok(())
    }

    #[test]
    fn late_cancellation_retains_installed_bundle_for_reconciliation()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let output = directory.path().join("bundle");
        let mut boundary = || {
            if output.exists() {
                Err(backend_error("operation canceled"))
            } else {
                Ok(())
            }
        };

        let result = write_new_bundle_with_boundary(
            &output,
            "test bundle",
            |staged, _| write_new_record(&staged.join("payload"), "test payload", b"authenticated"),
            &mut boundary,
        );

        assert!(result.is_err());
        assert_eq!(fs::read(output.join("payload"))?, b"authenticated");
        Ok(())
    }

    #[test]
    fn file_reads_refuse_growth_past_the_original_metadata_account()
    -> Result<(), Box<dyn std::error::Error>> {
        // This component fixture models only compact-codec credits, never
        // filesystem quota, native execution or a physical resident claim.
        struct ComponentDecodeAuthority;

        impl crucible_session::engine::owned_decode::DecodeResourceAuthority for ComponentDecodeAuthority {
            fn verify_live(
                &self,
            ) -> Result<(), crucible_session::engine::owned_decode::DecodeAdmissionError>
            {
                // This immutable component authority models a permanently live codec;
                // DecodeBudget supplies the explicit finite monotone fixture maximum.
                Ok(())
            }

            fn reserve(
                &self,
                _bytes: u64,
            ) -> Result<
                crucible_cas::owned_decode::ResourceLoan,
                crucible_session::engine::owned_decode::DecodeAdmissionError,
            > {
                Ok(crucible_cas::owned_decode::ResourceLoan::new(()))
            }
        }

        let directory = tempfile::tempdir()?;
        let path = directory.path().join("input");
        fs::write(&path, vec![0_u8; 128 * 1024])?;
        let budget = crucible_session::engine::owned_decode::DecodeBudget::new(
            Arc::new(ComponentDecodeAuthority),
            64 * 1024,
        )?;
        let _scope = budget.enter();

        let result = read_bounded_bytes(&path, "test artifact", 256 * 1024);

        assert!(result.is_err());
        assert!(budget.check().is_err());
        Ok(())
    }
}
