//! Exercises the production shared-map core with finite component metadata.
//!
//! These controls issue no Main, Source, native process or launch authority.

use super::*;
use crucible_engine::owned_decode::{DecodeAdmissionError, DecodeResourceAuthority, ResourceLoan};
use crucible_host_resources::host_supervision::{
    HostOperationBudgets, HostOperationClass, HostOperationGuard, HostOperationSupervisor,
};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

struct Authority {
    original: HostOperationGuard,
    used: Arc<AtomicU64>,
    maximum: AtomicU64,
    calls: AtomicUsize,
    values: Arc<AtomicUsize>,
}

struct Credit {
    bytes: u64,
    used: Arc<AtomicU64>,
    values: Arc<AtomicUsize>,
}

impl Drop for Credit {
    fn drop(&mut self) {
        assert_eq!(
            self.values.load(Ordering::SeqCst),
            0,
            "metadata refunded before map values closed"
        );
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
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.used
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                used.checked_add(bytes)
                    .filter(|next| *next <= self.maximum.load(Ordering::SeqCst))
            })
            .map_err(|_| {
                DecodeAdmissionError::new(std::io::Error::other("component metadata exhausted"))
            })?;
        Ok(ResourceLoan::new(Credit {
            bytes,
            used: self.used.clone(),
            values: self.values.clone(),
        }))
    }
}

fn fixture() -> (HostOperationSupervisor, Arc<Authority>, DecodeBudget) {
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)
        .expect("component supervisor");
    let authority = Arc::new(Authority {
        original: supervisor
            .begin(HostOperationClass::Preparation)
            .expect("component original"),
        used: Arc::new(AtomicU64::new(0)),
        maximum: AtomicU64::new(1 << 20),
        calls: AtomicUsize::new(0),
        values: Arc::new(AtomicUsize::new(0)),
    });
    let original =
        DecodeBudget::new(authority.clone(), 1 << 20).expect("component metadata account");
    (supervisor, authority, original)
}

struct Value {
    authority: Arc<Authority>,
}

impl Drop for Value {
    fn drop(&mut self) {
        assert!(self.authority.used.load(Ordering::SeqCst) > 0);
        self.authority.values.fetch_sub(1, Ordering::SeqCst);
    }
}

#[test]
fn clones_share_one_map_and_last_body_drops_before_original_credit() {
    let (_supervisor, authority, original) = fixture();
    let before = authority.calls.load(Ordering::SeqCst);
    authority.values.store(2, Ordering::SeqCst);
    let world = ContentHash::from_bytes(b"component world");
    let first = ContentHash::from_bytes(b"first");
    let second = ContentHash::from_bytes(b"second");
    let catalog = PaidBakedCatalog::new_under_original(
        [
            (
                (world, first),
                Value {
                    authority: authority.clone(),
                },
            ),
            (
                (world, second),
                Value {
                    authority: authority.clone(),
                },
            ),
        ],
        &original,
    )
    .expect("paid immutable map");
    assert_eq!(authority.calls.load(Ordering::SeqCst), before + 1);
    let clone = catalog.clone();
    assert!(Arc::ptr_eq(&catalog.entries, &clone.entries));
    assert!(clone.entries.contains_key(&(world, second)));
    assert!(!clone.entries.contains_key(&(first, world)));
    assert_eq!(authority.calls.load(Ordering::SeqCst), before + 1);

    drop(original);
    drop(catalog);
    assert_eq!(authority.values.load(Ordering::SeqCst), 2);
    assert!(authority.used.load(Ordering::SeqCst) > 0);
    drop(clone);
    assert_eq!(authority.values.load(Ordering::SeqCst), 0);
    assert_eq!(authority.used.load(Ordering::SeqCst), 0);
}

#[test]
fn refused_metadata_never_consumes_entries_or_builds_a_map() {
    let (_supervisor, authority, original) = fixture();
    authority
        .maximum
        .store(authority.used.load(Ordering::SeqCst), Ordering::SeqCst);
    let visited = AtomicUsize::new(0);
    let hash = ContentHash::from_bytes(b"component");
    let entries = [((hash, hash), 7u64)].into_iter().inspect(|_| {
        visited.fetch_add(1, Ordering::SeqCst);
    });
    assert!(matches!(
        PaidBakedCatalog::new_under_original(entries, &original),
        Err(ProductionBakedGenesisReplayCatalogError::Admission(_))
    ));
    assert_eq!(visited.load(Ordering::SeqCst), 0);
}

#[test]
fn prepaid_count_and_duplicate_basis_cannot_grow_the_map() {
    let (_supervisor, _authority, original) = fixture();
    let world = ContentHash::from_bytes(b"world");
    let second = ContentHash::from_bytes(b"second");
    original
        .charge_bytes(PaidBakedCatalog::<u64>::control_bytes(1).expect("geometry"))
        .expect("one prepaid entry");
    let payment = || CatalogPayment::Decode {
        _custody: original.custody(),
    };
    assert!(matches!(
        PaidBakedCatalog::new_prepaid([((world, world), 1u64), ((world, second), 2)], 1, payment()),
        Err(ProductionBakedGenesisReplayCatalogError::Geometry)
    ));
    original
        .charge_bytes(
            PaidBakedCatalog::<u64>::control_bytes(2).expect("duplicate-attempt geometry"),
        )
        .expect("both attempted entries prepaid");
    assert!(matches!(
        PaidBakedCatalog::new_prepaid([((world, world), 1u64), ((world, world), 2)], 2, payment()),
        Err(ProductionBakedGenesisReplayCatalogError::DuplicateBasis)
    ));
    assert!(matches!(
        PaidBakedCatalog::<u64>::control_bytes(usize::MAX),
        Err(ProductionBakedGenesisReplayCatalogError::Admission(_))
    ));
}
