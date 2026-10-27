//! Intercepts the creator's genuine fixed registration effect in native tests.

#![allow(
    clippy::unwrap_used,
    reason = "Fixed fixture synchronization intentionally panics."
)]

use super::super::super::super::super::{
    NativeEffectFailure, NativeFsEffect, NativeOpenedDirectory, Plan, TestGate, TestGatePhase,
};
use crate::store::EffectFault;
use crate::store::EffectFaultProbe;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock, Weak, mpsc};

/// Registers one exact native creator fault or observation per control namespace.
pub(in super::super::super) enum Hook {
    /// Interrupts ordinary creation immediately before Pending registration.
    BeforeRegistration,
    /// Holds ordinary creation with opaque observations of retained receipts.
    Running {
        /// Receives a weak observation of the actual submitted directories.
        observed: mpsc::Sender<Weak<[NativeOpenedDirectory]>>,
        /// Signals arrival at the held native boundary.
        arrived: mpsc::Sender<()>,
        /// Releases the native worker after the fixture interleaving.
        release: mpsc::Receiver<()>,
    },
    /// Fails the exact copy rename or lease removal at its native boundary.
    CopyFault {
        /// Scopes the hook to the copied payload's retained root.
        root: PathBuf,
        /// Selects the actual fixed installation command.
        boundary: CopyBoundary,
        /// Chooses pre-syscall refusal or post-syscall directory-sync failure.
        after: bool,
    },
    /// Holds an actual copy effect before its captured preimages are rechecked.
    CopyGate {
        /// Scopes the hook to the copied payload's retained root.
        root: PathBuf,
        /// Selects the actual fixed installation or recovery command.
        boundary: CopyBoundary,
        /// Receives an opaque lifetime observation without descriptor access.
        observed: mpsc::Sender<CopyRetentionProbe>,
        /// Signals arrival at the held native boundary.
        arrived: mpsc::Sender<()>,
        /// Releases the native worker after the fixture interleaving.
        release: mpsc::Receiver<()>,
    },
    /// Fails the exact staged file's actual durability command.
    CopyFileSync {
        /// Scopes the hook to the copied payload's retained root.
        root: PathBuf,
        /// Selects the staged file by its registered path and encoded schema.
        boundary: CopyBoundary,
    },
    /// Fails one numbered explicit native directory-sync command.
    CopyDirectorySync {
        /// Scopes the hook through the effect's retained root fence.
        root: PathBuf,
        /// Counts actual matching commands until the selected fault fires.
        remaining: usize,
    },
    /// Observes every actual explicit directory sync without consuming the hook.
    CopyDirectoryTrace {
        /// Scopes the observer through the effect's retained root fence.
        root: PathBuf,
        /// Receives actual command paths in submission order.
        observed: mpsc::Sender<PathBuf>,
    },
}

/// Observes test-only lifetime retention without exposing native descriptors.
pub(crate) struct CopyRetentionProbe(Weak<[NativeOpenedDirectory]>);

impl CopyRetentionProbe {
    /// Reports whether the original submitted effect still retains its receipts.
    pub(crate) fn retained(&self) -> bool {
        self.0.strong_count() != 0
    }
}

/// Names actual fixed copy-installation boundaries, with no authority effects.
#[derive(Clone, Copy, Debug)]
pub(crate) enum CopyBoundary {
    /// The destination checkpoint's immutable rename.
    Snapshot,
    /// The exact protected genesis transaction's create-once rename.
    Transaction,
    /// D-108's fixed nonauthoritative staging rename.
    Activation,
    /// The administrative registration's actual Pending rename.
    Pending,
    /// The replacing destination-origin portable pointer rename.
    Pointer,
    /// The actual authoritative genesis slot rename.
    Slot,
    /// The destination-origin selected-history cache rename.
    History,
    /// The selected capability cache's replacing rename.
    Capabilities,
    /// The selected head cache's replacing rename.
    RefCache,
    /// Removal of the copied physical source collector lease.
    Lease,
    /// The registration's final Active rename after all cache flushes.
    Active,
    /// The captured Pending recovery's first native durability handoff.
    RecoveryHandoff,
}

impl CopyBoundary {
    fn matches(
        self,
        probe: EffectFaultProbe<'_>,
        root: &std::path::Path,
        control: &std::path::Path,
    ) -> bool {
        match (self, probe) {
            (Self::Snapshot, EffectFaultProbe::RenameNoReplace(path)) => {
                path.parent() == Some(root.join("publication/snapshots").as_path())
            }
            (Self::Transaction, EffectFaultProbe::RenameNoReplace(path)) => {
                path.parent() == Some(control.join("publication/transactions").as_path())
            }
            (Self::Activation, EffectFaultProbe::RenameNoReplace(path)) => {
                path == control.join("publication/ACTIVATION")
            }
            (Self::Pending, EffectFaultProbe::RenameNoReplace(path)) => {
                path == control.join("backend-registration.cbor")
            }
            (Self::Pointer, EffectFaultProbe::Rename(path)) => {
                path == root.join("publication/PORTABLE")
            }
            (Self::Slot, EffectFaultProbe::RenameNoReplace(path)) => {
                path == control.join("publication/commits/0")
            }
            (Self::History, EffectFaultProbe::Rename(path)) => {
                path == root.join("publication/SELECTED-HISTORY")
            }
            (Self::Capabilities, EffectFaultProbe::Rename(path)) => {
                path == root.join("CAPABILITIES")
            }
            (Self::RefCache, EffectFaultProbe::Rename(path)) => {
                path == root.join("refs/heads/tenant/main:record")
            }
            (Self::RecoveryHandoff, EffectFaultProbe::DirectorySync(path)) => path == control,
            (Self::Active, EffectFaultProbe::Rename(path)) => {
                path == control.join("backend-registration.cbor")
            }
            _ => false,
        }
    }

    fn sync_matches(
        self,
        path: &std::path::Path,
        root: &std::path::Path,
        control: &std::path::Path,
    ) -> bool {
        use terrane_format::gc::publication::{
            Activation, BackendRegistration, PortableCurrent, SelectedHistory,
        };
        let Ok(bytes) = std::fs::read(path) else {
            return false;
        };
        match self {
            Self::Snapshot => path.parent() == Some(root.join("publication/snapshots").as_path()),
            Self::Transaction => {
                path.parent() == Some(control.join("publication/transactions").as_path())
            }
            Self::Activation => path.parent() == Some(control.join("publication").as_path()),
            Self::Slot => path.parent() == Some(control.join("publication/commits").as_path()),
            Self::Pending | Self::Active => {
                path.parent() == Some(control)
                    && BackendRegistration::decode(&bytes).is_ok_and(|registration| {
                        registration.activation
                            == if matches!(self, Self::Pending) {
                                Activation::Pending
                            } else {
                                Activation::Active
                            }
                    })
            }
            Self::Pointer => {
                path.parent() == Some(root.join("publication").as_path())
                    && PortableCurrent::decode(&bytes).is_ok()
            }
            Self::History => {
                path.parent() == Some(root.join("publication").as_path())
                    && SelectedHistory::decode(&bytes).is_ok()
            }
            Self::Capabilities => {
                path.parent() == Some(root)
                    && terrane_format::bucket::BucketCapabilities::decode(&bytes).is_ok()
            }
            Self::RefCache => {
                path.parent() == Some(root.join("refs/heads/tenant").as_path())
                    && terrane_format::refs::RefRecord::decode(&bytes).is_ok()
            }
            Self::Lease | Self::RecoveryHandoff => false,
        }
    }
}

fn hooks() -> &'static Mutex<BTreeMap<PathBuf, Hook>> {
    static HOOKS: OnceLock<Mutex<BTreeMap<PathBuf, Hook>>> = OnceLock::new();
    HOOKS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// Registers a single hook without replacing an existing fixture interleaving.
///
/// # Panics
/// Panics if a hook is already registered or fixture synchronization is poisoned.
pub(in super::super::super) fn register(control: PathBuf, hook: Hook) {
    assert!(hooks().lock().unwrap().insert(control, hook).is_none());
}

/// Removes only the completed nonconsuming directory-trace observer.
///
/// # Panics
/// Panics if no trace is registered or fixture synchronization is poisoned.
pub(in super::super::super) fn clear(control: &std::path::Path) {
    assert!(matches!(
        hooks().lock().unwrap().remove(control),
        Some(Hook::CopyDirectoryTrace { .. })
    ));
}

/// Requires the registered native fault or held boundary to have fired.
///
/// # Panics
/// Panics if a hook remains unconsumed or fixture synchronization is poisoned.
pub(in super::super::super) fn assert_consumed(control: &std::path::Path) {
    assert!(
        !hooks().lock().unwrap().contains_key(control),
        "native copy hook never fired: {}",
        control.display()
    );
}

/// Applies only the exact registered native fixture hook to a submitted effect.
///
/// # Errors
/// Returns the intentional pre-syscall interruption selected by a fault hook.
///
/// # Panics
/// Panics if fixture channels or synchronization fail, or a held effect lacks its
/// required retained directories. Unmatched hooks remain registered.
pub(super) fn intercept(mut effect: NativeFsEffect) -> Result<NativeFsEffect, NativeEffectFailure> {
    let copy = {
        let mut hooks = hooks().lock().unwrap();
        let key = hooks.iter_mut().find_map(|(control, hook)| match hook {
            Hook::CopyFault { root, boundary, .. } | Hook::CopyGate { root, boundary, .. }
                if boundary.matches(effect.fault_probe(), root, control) =>
            {
                Some(control.clone())
            }
            Hook::CopyFault { root, boundary: CopyBoundary::Lease, .. } if matches!(effect.plan.primitive(), Some(Plan::Remove { path }) if *path == root.join("gc/lease")) => Some(control.clone()),
            Hook::CopyFileSync { root, boundary } if matches!(effect.plan.primitive(), Some(Plan::SyncFile { path }) if boundary.sync_matches(path, root, control)) => Some(control.clone()),
            Hook::CopyDirectorySync { root, remaining } if effect.names.iter().any(|name| &name.path == root) && matches!(effect.fault_probe(), EffectFaultProbe::DirectorySync(_)) => {
                *remaining -= 1;
                (*remaining == 0).then(|| control.clone())
            }
            Hook::CopyDirectoryTrace { root, observed } if effect.names.iter().any(|name| &name.path == root) => {
                if let EffectFaultProbe::DirectorySync(path) = effect.fault_probe() { observed.send(path.to_owned()).unwrap(); }
                None
            }
            _ => None,
        });
        key.and_then(|key| hooks.remove(&key))
    };
    match copy {
        Some(Hook::CopyFileSync { .. }) => {
            effect.faults.push(EffectFault::BeforeFileSync);
            return Ok(effect);
        }
        Some(Hook::CopyDirectorySync { .. }) => {
            effect.faults.push(EffectFault::BeforeDirectorySync);
            return Ok(effect);
        }
        Some(Hook::CopyFault { after: true, .. }) => {
            effect.faults.push(EffectFault::BeforeDirectorySync);
            return Ok(effect);
        }
        Some(Hook::CopyFault { after: false, .. }) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "fixed copy boundary interruption",
            )
            .into());
        }
        Some(Hook::CopyGate {
            observed,
            arrived,
            release,
            ..
        }) => {
            let Plan::RetainedDirectories { directories, .. } = &effect.plan else {
                panic!("copy effect did not retain its opened directories");
            };
            observed
                .send(CopyRetentionProbe(std::sync::Arc::downgrade(directories)))
                .unwrap();
            effect.gates.push(TestGate {
                phase: TestGatePhase::BeforeChecks,
                arrived,
                release,
            });
            return Ok(effect);
        }
        _ => {}
    }
    let control = match effect.fault_probe() {
        EffectFaultProbe::RenameNoReplace(path)
            if path
                .file_name()
                .is_some_and(|name| name == "backend-registration.cbor") =>
        {
            path.parent().unwrap().to_owned()
        }
        _ => return Ok(effect),
    };
    let hook = {
        let mut hooks = hooks().lock().unwrap();
        if matches!(
            hooks.get(&control),
            Some(Hook::BeforeRegistration | Hook::Running { .. })
        ) {
            hooks.remove(&control)
        } else {
            None
        }
    };
    match hook {
        Some(Hook::BeforeRegistration) => Err(std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            "fixture interruption before actual Pending registration",
        )
        .into()),
        Some(Hook::Running {
            observed,
            arrived,
            release,
        }) => {
            let Plan::RetainedDirectories { directories, .. } = &effect.plan else {
                panic!("genuine creator effect did not retain its opened directories");
            };
            observed
                .send(std::sync::Arc::downgrade(directories))
                .unwrap();
            effect.gates.push(TestGate {
                phase: TestGatePhase::BeforeChecks,
                arrived,
                release,
            });
            Ok(effect)
        }
        None => Ok(effect),
        Some(
            Hook::CopyFault { .. }
            | Hook::CopyGate { .. }
            | Hook::CopyFileSync { .. }
            | Hook::CopyDirectorySync { .. }
            | Hook::CopyDirectoryTrace { .. },
        ) => {
            panic!("unmatched copy hook consumed by ordinary creator")
        }
    }
}
