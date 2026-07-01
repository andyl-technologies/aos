//! ESP boot-menu reconciliation for system generations.
//!
//! AOS boots per-generation UKIs auto-discovered by sd-boot from `EFI/Linux/`
//! on the ESP, which is normally mounted read-only at `/boot`. This module
//! reconciles that directory and `loader/loader.conf` against the recorded
//! system generations behind a transient read-write remount. It copies
//! already-signed UKIs into place; it never signs.
//!
//! ESP layout owned here:
//! ```text
//! /boot/
//!   EFI/Linux/aos-<gen>-<tophash>.efi   one UKI per retained generation
//!   loader/loader.conf                  `default aos-<cur-gen>-<tophash>.efi`
//! ```
//!
//! The leading `<gen>` orders the sd-boot menu newest-first; see
//! [`esp_uki_name`].

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use aos_core::output::Printer;
use sha2::{Digest, Sha256};

use crate::sysroot::find_uki_in_image;
use crate::types::{SystemGeneration, SystemGenerationState};

/// Where the ESP is mounted.
const ESP_MOUNT: &str = "/boot";
/// Auto-discovery directory for UKIs.
const ESP_LINUX_DIR: &str = "/boot/EFI/Linux";
/// sd-boot configuration file.
const LOADER_CONF: &str = "/boot/loader/loader.conf";

/// One generation's view for reconciliation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EspGeneration {
    /// Generation number.
    pub number: u32,
    /// Store path of the system toplevel; names the ESP entry.
    pub toplevel: String,
    /// Store path holding this generation's signed UKI, when known.
    ///
    /// This is normally resolved from the generation's `gen-N/uki` GC-root
    /// symlink. `None` means the sysroot shipped no UKI image.
    pub uki_store_path: Option<String>,
}

#[derive(Debug, Clone)]
struct EspPaths {
    mount: PathBuf,
    linux_dir: PathBuf,
    loader_conf: PathBuf,
}

impl Default for EspPaths {
    fn default() -> Self {
        Self {
            mount: PathBuf::from(ESP_MOUNT),
            linux_dir: PathBuf::from(ESP_LINUX_DIR),
            loader_conf: PathBuf::from(LOADER_CONF),
        }
    }
}

/// Return the ESP UKI filename for a generation's toplevel store path.
///
/// The form is `aos-<generation>-<32-character-store-hash>.efi`. The leading
/// generation number is what orders the boot menu: these entries carry no
/// `sort-key` and share a `VERSION_ID`, so sd-boot falls back to ordering by
/// filename, and does so *descending* (its `boot_entry_compare` tie-break is
/// `-strverscmp_improved(a->id, b->id)`). `strverscmp_improved` compares the
/// generation's digit run numerically — so `10` sorts above `2` — which places
/// the newest generation at the top of the menu, matching NixOS's newest-first
/// behavior. The store hash keeps the name content-addressed by toplevel (and
/// unique) as the secondary component; it is never reached in the ordering
/// because distinct generations always differ in the leading number.
///
/// The number is emitted bare (no zero-padding) so it never has leading zeros,
/// keeping the numeric comparison unambiguous. If the path does not look like a
/// Nix store path, a deterministic SHA-256 based fallback hash is used so
/// callers still get a stable filename.
pub fn esp_uki_name(generation: u32, toplevel_store_path: &str) -> String {
    let base = Path::new(toplevel_store_path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(toplevel_store_path);
    let hash = if base.len() > 32
        && base.as_bytes().get(32) == Some(&b'-')
        && base[..32].chars().all(|ch| ch.is_ascii_alphanumeric())
    {
        base[..32].to_string()
    } else {
        let digest = Sha256::digest(toplevel_store_path.as_bytes());
        hex::encode(digest).chars().take(32).collect()
    };
    format!("aos-{generation}-{hash}.efi")
}

/// Build the retained generation set for ESP reconciliation.
///
/// The returned list is sorted by generation number. It keeps the most recent
/// `configuration_limit` generations and force-includes the committed current
/// generation plus the booted generation when present.
pub fn retained_generations(
    state: &SystemGenerationState,
    configuration_limit: u32,
    booted: Option<u32>,
    profile_path: &Path,
) -> Vec<EspGeneration> {
    let mut sorted: Vec<&SystemGeneration> = state.generations.iter().collect();
    sorted.sort_by_key(|generation| generation.number);

    let start = sorted.len().saturating_sub(configuration_limit as usize);
    let mut keep = BTreeSet::new();
    for generation in &sorted[start..] {
        keep.insert(generation.number);
    }
    if state.current != 0 {
        keep.insert(state.current);
    }
    if let Some(booted) = booted {
        keep.insert(booted);
    }

    sorted
        .into_iter()
        .filter(|generation| keep.contains(&generation.number))
        .map(|generation| EspGeneration {
            number: generation.number,
            toplevel: generation.toplevel.clone(),
            uki_store_path: generation_uki_store_path(profile_path, generation),
        })
        .collect()
}

/// Read the booted generation marker written by the initrd, if available.
pub fn booted_generation() -> Option<u32> {
    read_booted_generation(Path::new("/run/aos-booted-gen"))
}

/// Reconcile the ESP boot menu against the retained generations.
///
/// `retained` is the ordered set of generations to keep entries for, `current`
/// is the committed default, and `booted` is the generation that booted this
/// session. The operation is idempotent.
///
/// # Errors
///
/// Returns an error if the read-write remount, any copy, the `loader.conf`
/// write, garbage collection, or final sync fails. A final read-only remount
/// failure is reported through `printer` and otherwise treated as non-fatal so
/// callers can keep the system generation commit.
pub fn reconcile(
    retained: &[EspGeneration],
    current: u32,
    booted: Option<u32>,
    printer: &Printer,
) -> Result<()> {
    reconcile_with_paths(
        retained,
        current,
        booted,
        printer,
        &EspPaths::default(),
        true,
    )
}

fn generation_uki_store_path(profile_path: &Path, generation: &SystemGeneration) -> Option<String> {
    let link = profile_path
        .join(format!("gen-{}", generation.number))
        .join("uki");
    fs::read_link(link)
        .ok()
        .map(|path| path.to_string_lossy().to_string())
        .or_else(|| generation.uki_store_path.clone())
}

fn read_booted_generation(path: &Path) -> Option<u32> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn reconcile_with_paths(
    retained: &[EspGeneration],
    current: u32,
    booted: Option<u32>,
    printer: &Printer,
    paths: &EspPaths,
    remount: bool,
) -> Result<()> {
    let Some(efi_dir) = paths.linux_dir.parent() else {
        return Ok(());
    };
    if !efi_dir.exists() {
        return Ok(());
    }

    if remount {
        remount_esp(&paths.mount, false)?;
    }

    let write_result = (|| -> Result<()> {
        fs::create_dir_all(&paths.linux_dir)
            .with_context(|| format!("creating {}", paths.linux_dir.display()))?;
        if let Some(parent) = paths.loader_conf.parent() {
            fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        }

        for generation in retained {
            place_generation_uki(generation, &paths.linux_dir, printer)?;
        }

        write_loader_conf(retained, current, &paths.linux_dir, &paths.loader_conf)?;
        garbage_collect(retained, current, booted, &paths.linux_dir)?;
        syncfs_path(&paths.mount)?;
        Ok(())
    })();

    if remount && let Err(error) = remount_esp(&paths.mount, true) {
        printer.warning(&format!(
            "failed to remount ESP read-only after boot-menu update: {error:#}"
        ));
    }

    write_result
}

fn place_generation_uki(
    generation: &EspGeneration,
    linux_dir: &Path,
    printer: &Printer,
) -> Result<()> {
    let name = esp_uki_name(generation.number, &generation.toplevel);
    let target = linux_dir.join(&name);
    if target.exists() {
        return Ok(());
    }

    let Some(store_path) = generation.uki_store_path.as_deref() else {
        printer.warning(&format!(
            "generation {} has no UKI image; skipping boot-menu entry",
            generation.number
        ));
        return Ok(());
    };
    let Some(source) = find_uki_in_image(store_path) else {
        printer.warning(&format!(
            "generation {} UKI image is not present at {}; skipping boot-menu entry",
            generation.number, store_path
        ));
        return Ok(());
    };

    atomic_copy(&source, &target)
        .with_context(|| format!("placing generation {} UKI at {name}", generation.number))
}

fn write_loader_conf(
    retained: &[EspGeneration],
    current: u32,
    linux_dir: &Path,
    loader_conf: &Path,
) -> Result<()> {
    let current_name = retained
        .iter()
        .find(|generation| generation.number == current)
        .map(|generation| esp_uki_name(generation.number, &generation.toplevel));
    let default = current_name
        .filter(|name| linux_dir.join(name).exists())
        .unwrap_or_else(|| "aos-*".to_string());
    let content = format!("default {default}\ntimeout 3\nconsole-mode max\neditor no\n");
    atomic_write(loader_conf, content.as_bytes())
        .with_context(|| format!("writing {}", loader_conf.display()))
}

fn garbage_collect(
    retained: &[EspGeneration],
    current: u32,
    booted: Option<u32>,
    linux_dir: &Path,
) -> Result<()> {
    let protected = protected_names(retained, current, booted);
    for entry in
        fs::read_dir(linux_dir).with_context(|| format!("reading {}", linux_dir.display()))?
    {
        let entry = entry.with_context(|| format!("reading entry in {}", linux_dir.display()))?;
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        if !is_aos_uki_name(name) || protected.contains(name) {
            continue;
        }
        fs::remove_file(entry.path()).with_context(|| format!("removing stale UKI {name}"))?;
    }
    Ok(())
}

fn protected_names(
    retained: &[EspGeneration],
    current: u32,
    booted: Option<u32>,
) -> BTreeSet<String> {
    let by_number: BTreeMap<u32, String> = retained
        .iter()
        .map(|generation| {
            (
                generation.number,
                esp_uki_name(generation.number, &generation.toplevel),
            )
        })
        .collect();
    let mut protected: BTreeSet<String> = by_number.values().cloned().collect();
    if let Some(name) = by_number.get(&current) {
        protected.insert(name.clone());
    }
    if let Some(booted) = booted
        && let Some(name) = by_number.get(&booted)
    {
        protected.insert(name.clone());
    }
    protected
}

fn is_aos_uki_name(name: &str) -> bool {
    name.starts_with("aos-") && name.ends_with(".efi")
}

fn atomic_copy(source: &Path, target: &Path) -> Result<()> {
    let parent = target
        .parent()
        .with_context(|| format!("{} has no parent directory", target.display()))?;
    let file_name = target
        .file_name()
        .and_then(|name| name.to_str())
        .with_context(|| format!("{} has no file name", target.display()))?;
    let tmp = parent.join(format!(".{file_name}.tmp-{}", std::process::id()));
    let _ = fs::remove_file(&tmp);

    let result = (|| -> Result<()> {
        fs::copy(source, &tmp)
            .with_context(|| format!("copying {} to {}", source.display(), tmp.display()))?;
        let file = File::open(&tmp).with_context(|| format!("opening {}", tmp.display()))?;
        file.sync_all()
            .with_context(|| format!("syncing {}", tmp.display()))?;
        fs::rename(&tmp, target)
            .with_context(|| format!("renaming {} to {}", tmp.display(), target.display()))?;
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

fn atomic_write(target: &Path, content: &[u8]) -> Result<()> {
    let parent = target
        .parent()
        .with_context(|| format!("{} has no parent directory", target.display()))?;
    let file_name = target
        .file_name()
        .and_then(|name| name.to_str())
        .with_context(|| format!("{} has no file name", target.display()))?;
    let tmp = parent.join(format!(".{file_name}.tmp-{}", std::process::id()));
    let _ = fs::remove_file(&tmp);

    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .with_context(|| format!("creating {}", tmp.display()))?;
        file.write_all(content)
            .with_context(|| format!("writing {}", tmp.display()))?;
        file.sync_all()
            .with_context(|| format!("syncing {}", tmp.display()))?;
        drop(file);
        fs::rename(&tmp, target)
            .with_context(|| format!("renaming {} to {}", tmp.display(), target.display()))?;
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

fn syncfs_path(path: &Path) -> Result<()> {
    let file =
        File::open(path).with_context(|| format!("opening {} for syncfs", path.display()))?;
    // SAFETY: syncfs only reads the valid file descriptor borrowed from `file`.
    let rc = unsafe { libc::syncfs(file.as_raw_fd()) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("syncfs {}", path.display()));
    }
    Ok(())
}

fn remount_esp(path: &Path, readonly: bool) -> Result<()> {
    let target = CString::new(path.as_os_str().as_bytes())
        .with_context(|| format!("mount path contains NUL: {}", path.display()))?;
    let flags = if readonly {
        libc::MS_REMOUNT | libc::MS_RDONLY
    } else {
        libc::MS_REMOUNT
    };
    // SAFETY: the target CString is NUL-terminated and lives for the syscall.
    // Null source, filesystem type, and data are accepted for MS_REMOUNT.
    let rc = unsafe {
        libc::mount(
            std::ptr::null(),
            target.as_ptr(),
            std::ptr::null(),
            flags,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        let mode = if readonly { "read-only" } else { "read-write" };
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("remounting {} {mode}", path.display()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_generation(
        number: u32,
        hash: &str,
        uki_store_path: Option<String>,
    ) -> SystemGeneration {
        SystemGeneration {
            number,
            toplevel: format!("/nix/store/{hash}-aos-system-toplevel"),
            version: format!("{number}.0"),
            package_name: "aos".to_string(),
            registry: "test".to_string(),
            created_at: "2026-06-23T00:00:00Z".to_string(),
            kernel_path: None,
            uki_store_path,
        }
    }

    fn paths(root: &Path) -> EspPaths {
        EspPaths {
            mount: root.to_path_buf(),
            linux_dir: root.join("EFI/Linux"),
            loader_conf: root.join("loader/loader.conf"),
        }
    }

    #[test]
    fn esp_uki_name_uses_toplevel_store_hash() {
        let name =
            esp_uki_name(3, "/nix/store/0123456789abcdefghijklmnopqrstuv-aos-system-toplevel");
        assert_eq!(name, "aos-3-0123456789abcdefghijklmnopqrstuv.efi");
    }

    #[test]
    fn esp_uki_name_has_stable_fallback() {
        let first = esp_uki_name(1, "/not-a-store-path");
        let second = esp_uki_name(1, "/not-a-store-path");
        assert_eq!(first, second);
        assert!(first.starts_with("aos-1-"));
        assert!(first.ends_with(".efi"));
    }

    #[test]
    fn esp_uki_name_encodes_generation_as_leading_numeric_field() {
        // sd-boot orders entries by filename descending, comparing runs of
        // digits numerically (`strverscmp_improved`). What this function must
        // guarantee is that the generation is the leading numeric field after
        // `aos-` and shares the trailing hash across generations, so the digit
        // run alone decides ordering. The descending numeric sort itself is
        // sd-boot's job (verified against its source), not reproduced here —
        // Rust's lexical `str` ordering would disagree (it ranks "9" above
        // "10"), which is exactly why the number must not be zero-padded and
        // why we do not assert a lexical sort.
        let top = "/nix/store/0123456789abcdefghijklmnopqrstuv-aos-system-toplevel";
        for generation in [1u32, 2, 9, 10, 123] {
            let name = esp_uki_name(generation, top);
            assert_eq!(
                name,
                format!("aos-{generation}-0123456789abcdefghijklmnopqrstuv.efi")
            );
            // The field between the first two dashes is exactly the number,
            // with no padding (no leading zero) that could perturb the
            // numeric comparison.
            let field = name
                .strip_prefix("aos-")
                .and_then(|rest| rest.split('-').next())
                .unwrap();
            assert_eq!(field, generation.to_string());
            assert!(!field.starts_with('0'));
        }
    }

    #[test]
    fn retained_keeps_recent_current_and_booted() {
        let tmp = TempDir::new().unwrap();
        let state = SystemGenerationState {
            current: 2,
            next: 6,
            generations: vec![
                test_generation(1, "11111111111111111111111111111111", None),
                test_generation(2, "22222222222222222222222222222222", None),
                test_generation(3, "33333333333333333333333333333333", None),
                test_generation(4, "44444444444444444444444444444444", None),
                test_generation(5, "55555555555555555555555555555555", None),
            ],
        };

        let retained = retained_generations(&state, 2, Some(1), tmp.path());
        let numbers: Vec<u32> = retained
            .iter()
            .map(|generation| generation.number)
            .collect();
        assert_eq!(numbers, vec![1, 2, 4, 5]);
    }

    #[test]
    fn retained_prefers_gen_uki_symlink_over_state_field() {
        let tmp = TempDir::new().unwrap();
        let gen_dir = tmp.path().join("gen-1");
        fs::create_dir_all(&gen_dir).unwrap();
        std::os::unix::fs::symlink("/nix/store/symlink-uki", gen_dir.join("uki")).unwrap();
        let state = SystemGenerationState {
            current: 1,
            next: 2,
            generations: vec![test_generation(
                1,
                "11111111111111111111111111111111",
                Some("/nix/store/state-uki".to_string()),
            )],
        };

        let retained = retained_generations(&state, 3, None, tmp.path());
        assert_eq!(
            retained[0].uki_store_path.as_deref(),
            Some("/nix/store/symlink-uki")
        );
    }

    #[test]
    fn reconcile_places_loader_and_prunes_stale_entries() {
        let tmp = TempDir::new().unwrap();
        let paths = paths(tmp.path());
        fs::create_dir_all(&paths.linux_dir).unwrap();
        fs::create_dir_all(paths.loader_conf.parent().unwrap()).unwrap();

        let source_dir = tmp.path().join("store/uki");
        fs::create_dir_all(&source_dir).unwrap();
        fs::write(source_dir.join("published.efi"), b"uki-2").unwrap();

        let gen1_name = esp_uki_name(1, "/nix/store/11111111111111111111111111111111-aos");
        fs::write(paths.linux_dir.join(&gen1_name), b"existing").unwrap();
        fs::write(paths.linux_dir.join("aos-stale.efi"), b"stale").unwrap();
        fs::write(paths.linux_dir.join("other.efi"), b"other").unwrap();

        let retained = vec![
            EspGeneration {
                number: 1,
                toplevel: "/nix/store/11111111111111111111111111111111-aos".to_string(),
                uki_store_path: None,
            },
            EspGeneration {
                number: 2,
                toplevel: "/nix/store/22222222222222222222222222222222-aos".to_string(),
                uki_store_path: Some(source_dir.to_string_lossy().to_string()),
            },
            EspGeneration {
                number: 3,
                toplevel: "/nix/store/33333333333333333333333333333333-aos".to_string(),
                uki_store_path: None,
            },
        ];
        let printer = Printer::new(0, true, false);

        reconcile_with_paths(&retained, 2, Some(1), &printer, &paths, false).unwrap();

        let gen2_name = esp_uki_name(2, "/nix/store/22222222222222222222222222222222-aos");
        assert_eq!(
            fs::read(paths.linux_dir.join(&gen1_name)).unwrap(),
            b"existing"
        );
        assert_eq!(
            fs::read(paths.linux_dir.join(&gen2_name)).unwrap(),
            b"uki-2"
        );
        assert!(!paths.linux_dir.join("aos-stale.efi").exists());
        assert!(paths.linux_dir.join("other.efi").exists());
        let loader = fs::read_to_string(&paths.loader_conf).unwrap();
        assert!(loader.contains(&format!("default {gen2_name}\n")));
        assert!(
            !paths
                .linux_dir
                .join(esp_uki_name(
                    3,
                    "/nix/store/33333333333333333333333333333333-aos"
                ))
                .exists()
        );
    }

    #[test]
    fn reconcile_falls_back_to_glob_when_current_uki_missing() {
        let tmp = TempDir::new().unwrap();
        let paths = paths(tmp.path());
        fs::create_dir_all(&paths.linux_dir).unwrap();
        fs::create_dir_all(paths.loader_conf.parent().unwrap()).unwrap();

        let retained = vec![EspGeneration {
            number: 1,
            toplevel: "/nix/store/11111111111111111111111111111111-aos".to_string(),
            uki_store_path: None,
        }];
        let printer = Printer::new(0, true, false);

        reconcile_with_paths(&retained, 1, None, &printer, &paths, false).unwrap();

        let loader = fs::read_to_string(&paths.loader_conf).unwrap();
        assert!(loader.contains("default aos-*\n"));
    }
}
