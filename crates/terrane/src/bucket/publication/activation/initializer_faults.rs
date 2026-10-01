//! Intercepts the creator's genuine fixed registration effect in native tests.

#![allow(
    clippy::unwrap_used,
    reason = "Fixed fixture synchronization intentionally panics."
)]

use super::super::super::super::super::{
    NativeEffectFailure, NativeFsEffect, NativeOpenedDirectory, Plan, TestGate, TestGatePhase,
};
use crate::store::EffectFaultProbe;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock, Weak, mpsc};

pub(in super::super::super) enum Hook {
    BeforeRegistration,
    Running {
        observed: mpsc::Sender<Weak<[NativeOpenedDirectory]>>,
        arrived: mpsc::Sender<()>,
        release: mpsc::Receiver<()>,
    },
}

fn hooks() -> &'static Mutex<BTreeMap<PathBuf, Hook>> {
    static HOOKS: OnceLock<Mutex<BTreeMap<PathBuf, Hook>>> = OnceLock::new();
    HOOKS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

pub(in super::super::super) fn register(control: PathBuf, hook: Hook) {
    assert!(hooks().lock().unwrap().insert(control, hook).is_none());
}

pub(super) fn intercept(mut effect: NativeFsEffect) -> Result<NativeFsEffect, NativeEffectFailure> {
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
    let hook = hooks().lock().unwrap().remove(&control);
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
    }
}
