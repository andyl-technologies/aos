//! Checks input payment and last strong-alias closure with local metadata credit.
//!
//! This component account issues no Main, Source, native role or launch authority.

// crucible-lint: allow panic-shortcut -- component ownership violations stop the control.

use super::*;
use crucible_engine::owned_decode::{DecodeResourceAuthority, ResourceLoan};
use crucible_host_resources::host_supervision::{
    HostOperationBudgets, HostOperationClass, HostOperationGuard, HostOperationSupervisor,
};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, Weak};

type BodyWitness = Arc<Mutex<Option<Weak<NativePluginFlightInputBody>>>>;

struct Authority {
    original: HostOperationGuard,
    used: Arc<AtomicU64>,
    limit: AtomicU64,
    witness: BodyWitness,
}

struct Credit {
    bytes: u64,
    used: Arc<AtomicU64>,
    witness: BodyWitness,
}

impl Drop for Credit {
    fn drop(&mut self) {
        if let Some(body) = self.witness.lock().expect("component witness").as_ref() {
            assert!(
                body.upgrade().is_none(),
                "credit returned while input still has a strong alias"
            );
        }
        self.used.fetch_sub(self.bytes, Ordering::SeqCst);
    }
}

impl DecodeResourceAuthority for Authority {
    fn verify_live(&self) -> Result<(), DecodeAdmissionError> {
        self.original
            .wait_slice()
            .map(|_| ())
            .map_err(DecodeAdmissionError::new)
    }

    fn reserve(&self, bytes: u64) -> Result<ResourceLoan, DecodeAdmissionError> {
        self.verify_live()?;
        self.used
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                used.checked_add(bytes)
                    .filter(|next| *next <= self.limit.load(Ordering::SeqCst))
            })
            .map_err(|_| {
                DecodeAdmissionError::new(std::io::Error::other("component metadata exhausted"))
            })?;
        Ok(ResourceLoan::new(Credit {
            bytes,
            used: Arc::clone(&self.used),
            witness: Arc::clone(&self.witness),
        }))
    }
}

fn fixture() -> (HostOperationSupervisor, Arc<Authority>, DecodeBudget) {
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)
        .expect("component supervision");
    let authority = Arc::new(Authority {
        original: supervisor
            .begin(HostOperationClass::Preparation)
            .expect("component preparation"),
        used: Arc::new(AtomicU64::new(0)),
        limit: AtomicU64::new(1 << 20),
        witness: Arc::new(Mutex::new(None)),
    });
    let budget = DecodeBudget::new(authority.clone(), 1 << 20).expect("component metadata");
    (supervisor, authority, budget)
}

fn inputs(budget: &DecodeBudget) -> Result<NativePluginFlightInputs, NativePluginFlightInputError> {
    NativePluginFlightInputs::new_admitted(
        NativePluginFlightKind::FourVcpu,
        Path::new("/immutable/kernel"),
        Path::new("/immutable/initrd"),
        Path::new("/immutable/firmware"),
        budget,
    )
}

#[test]
fn original_refusal_prevents_input_body_publication() {
    let (_supervisor, authority, budget) = fixture();
    let before = authority.used.load(Ordering::SeqCst);
    authority.limit.store(before, Ordering::SeqCst);
    assert!(matches!(
        inputs(&budget),
        Err(NativePluginFlightInputError::Admission(_))
    ));
    assert_eq!(authority.used.load(Ordering::SeqCst), before);
    drop(budget);
    assert_eq!(authority.used.load(Ordering::SeqCst), 0);
}

#[test]
fn immutable_aliases_hold_credit_through_last_strong_body_alias() {
    let (_supervisor, authority, budget) = fixture();
    let input = inputs(&budget).expect("paid input body");
    let alias = input.clone();
    // The Weak witness observes strong-alias closure; it retains the Arc
    // allocation itself and therefore cannot prove backing deallocation.
    *authority.witness.lock().expect("component witness") = Some(Arc::downgrade(&input.body));
    let paid = authority.used.load(Ordering::SeqCst);
    drop(budget);
    drop(input);
    assert_eq!(authority.used.load(Ordering::SeqCst), paid);
    assert_eq!(alias.body.initrd, Path::new("/immutable/initrd"));
    drop(alias);
    assert_eq!(authority.used.load(Ordering::SeqCst), 0);
}

#[test]
fn canceled_original_and_relative_asset_refuse_without_native_effects() {
    let (supervisor, authority, budget) = fixture();
    let before = authority.used.load(Ordering::SeqCst);
    assert!(matches!(
        NativePluginFlightInputs::new_admitted(
            NativePluginFlightKind::BlockRecovery,
            Path::new("relative"),
            Path::new("/initrd"),
            Path::new("/firmware"),
            &budget,
        ),
        Err(NativePluginFlightInputError::RelativePath)
    ));
    assert_eq!(authority.used.load(Ordering::SeqCst), before);
    supervisor.cancel().expect("component cancel");
    assert!(matches!(
        inputs(&budget),
        Err(NativePluginFlightInputError::Admission(_))
    ));
}
