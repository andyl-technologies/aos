//! Borrowed seed identity and ordinary parser compatibility controls.

use std::cell::RefCell;
use std::error::Error;
use std::fmt;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde::Deserialize;
use serde::de::{DeserializeOwned, DeserializeSeed, SeqAccess, Visitor};

use super::{from_cbor_slice, from_cbor_slice_with_seed};
use crate::owned_decode::{
    DecodeAdmissionError, DecodeBudget, DecodeResourceAuthority, DecodeScope, ResourceLoan,
};

struct Credit(Arc<AtomicU64>, u64);

impl Drop for Credit {
    fn drop(&mut self) {
        self.0.fetch_sub(self.1, Ordering::SeqCst);
    }
}

struct Authority {
    used: Arc<AtomicU64>,
    refusing: AtomicBool,
    live_refusing: AtomicBool,
    reservation_scope: Mutex<Option<DecodeBudget>>,
    failure: DecodeAdmissionError,
}

impl DecodeResourceAuthority for Authority {
    fn verify_live(&self) -> Result<(), DecodeAdmissionError> {
        if self.live_refusing.load(Ordering::SeqCst) {
            Err(self.failure.clone())
        } else {
            Ok(())
        }
    }

    fn reserve(&self, bytes: u64) -> Result<ResourceLoan, DecodeAdmissionError> {
        if self.refusing.load(Ordering::SeqCst) {
            return Err(self.failure.clone());
        }
        let selected = self
            .reservation_scope
            .lock()
            .map_err(|_| self.failure.clone())?
            .take();
        if let Some(other) = selected {
            RESERVATION_SCOPE.with(|scope| scope.replace(Some(other.enter())));
            self.refusing.store(true, Ordering::SeqCst);
        }
        self.used.fetch_add(bytes, Ordering::SeqCst);
        Ok(ResourceLoan::new(Credit(self.used.clone(), bytes)))
    }
}

fn original() -> Result<(DecodeBudget, Arc<Authority>), DecodeAdmissionError> {
    let authority = Arc::new(Authority {
        used: Arc::new(AtomicU64::new(0)),
        refusing: AtomicBool::new(false),
        live_refusing: AtomicBool::new(false),
        reservation_scope: Mutex::new(None),
        failure: DecodeAdmissionError::new(fmt::Error),
    });
    let budget = DecodeBudget::new(authority.clone(), 1024 * 1024)?;
    Ok((budget, authority))
}

struct ValueSeed<T>(PhantomData<T>);

impl<'de, T: Deserialize<'de>> DeserializeSeed<'de> for ValueSeed<T> {
    type Value = T;

    fn deserialize<D: serde::Deserializer<'de>>(self, decoder: D) -> Result<T, D::Error> {
        T::deserialize(decoder)
    }
}

fn parse<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, Box<dyn Error>> {
    let (budget, _) = original()?;
    Ok(from_cbor_slice_with_seed(
        bytes,
        ValueSeed::<T>(PhantomData),
        &budget,
    )?)
}

#[test]
fn saved_seed_preserves_ordinary_nested_values() -> Result<(), Box<dyn Error>> {
    let expected = vec![vec![
        String::from("quoted\" text"),
        String::from("unicode 🦀"),
    ]];
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&expected, &mut bytes)?;
    let ordinary: Vec<Vec<String>> = ciborium::de::from_reader(bytes.as_slice())?;
    let actual: Vec<Vec<String>> = parse(&bytes)?;

    assert_eq!(actual, ordinary);
    assert_eq!(actual, expected);
    Ok(())
}

#[test]
fn saved_seed_preserves_ordinary_truncation_syntax_and_recursion_errors()
-> Result<(), Box<dyn Error>> {
    for bytes in [&[0x82, 0x01][..], &[0xff][..]] {
        let ordinary = ciborium::de::from_reader::<Vec<u8>, _>(bytes).err();
        let (budget, _) = original()?;
        let actual =
            from_cbor_slice_with_seed(bytes, ValueSeed::<Vec<u8>>(PhantomData), &budget).err();
        assert_eq!(format!("{actual:?}"), format!("{ordinary:?}"));
    }

    let mut bytes = vec![0x81; 257];
    bytes.push(0);
    let ordinary = ciborium::de::from_reader::<serde::de::IgnoredAny, _>(bytes.as_slice()).err();
    let (budget, _) = original()?;
    let actual = from_cbor_slice_with_seed(
        &bytes,
        ValueSeed::<serde::de::IgnoredAny>(PhantomData),
        &budget,
    )
    .err();
    assert!(matches!(
        ordinary,
        Some(ciborium::de::Error::RecursionLimitExceeded)
    ));
    assert!(matches!(
        actual,
        Some(ciborium::de::Error::RecursionLimitExceeded)
    ));
    Ok(())
}

struct SwitchingSeed<'a> {
    saved: &'a Authority,
    other: &'a DecodeBudget,
    member_observed: &'a AtomicBool,
}

impl<'de> DeserializeSeed<'de> for SwitchingSeed<'_> {
    type Value = ();

    fn deserialize<D: serde::Deserializer<'de>>(self, decoder: D) -> Result<(), D::Error> {
        struct SwitchingVisitor<'a>(SwitchingSeed<'a>);

        impl<'de> Visitor<'de> for SwitchingVisitor<'_> {
            type Value = ();

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("one string under the saved original")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<(), A::Error> {
                self.0.saved.refusing.store(true, Ordering::SeqCst);
                let _other_scope = self.0.other.enter();
                let value = sequence.next_element::<String>()?;
                self.0
                    .member_observed
                    .store(value.is_some(), Ordering::SeqCst);
                Ok(())
            }
        }

        decoder.deserialize_seq(SwitchingVisitor(self))
    }
}

#[test]
fn lower_scope_switch_cannot_replace_saved_nested_admission() -> Result<(), Box<dyn Error>> {
    let (saved, saved_authority) = original()?;
    let (other, _) = original()?;
    let member_observed = AtomicBool::new(false);
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&vec![String::from("owning member")], &mut bytes)?;

    let result = from_cbor_slice_with_seed(
        &bytes,
        SwitchingSeed {
            saved: &saved_authority,
            other: &other,
            member_observed: &member_observed,
        },
        &saved,
    );

    assert!(result.is_err());
    assert!(!member_observed.load(Ordering::SeqCst));
    assert_eq!(saved.failure()?, Some(saved_authority.failure.clone()));
    assert!(other.failure()?.is_none());
    Ok(())
}

struct FinalRefusalSeed<'a>(&'a DecodeBudget);

impl<'de> DeserializeSeed<'de> for FinalRefusalSeed<'_> {
    type Value = u8;

    fn deserialize<D: serde::Deserializer<'de>>(self, decoder: D) -> Result<u8, D::Error> {
        let value = u8::deserialize(decoder)?;
        // A visitor cannot convert a recorded refusal into healthy acceptance.
        let _refusal = self.0.charge_bytes(u64::MAX);
        Ok(value)
    }
}

#[test]
fn healthy_seed_value_cannot_hide_final_saved_original_refusal() -> Result<(), Box<dyn Error>> {
    let (budget, _) = original()?;

    let result = from_cbor_slice_with_seed(&[0x01], FinalRefusalSeed(&budget), &budget);

    assert!(matches!(result, Err(ciborium::de::Error::Io(_))));
    let failure = budget.failure()?.ok_or(fmt::Error)?;
    assert_eq!(budget.verify_live().err(), Some(failure));
    Ok(())
}

struct ObservedSeed<'a>(&'a AtomicBool);

impl<'de> DeserializeSeed<'de> for ObservedSeed<'_> {
    type Value = u8;

    fn deserialize<D: serde::Deserializer<'de>>(self, decoder: D) -> Result<u8, D::Error> {
        self.0.store(true, Ordering::SeqCst);
        u8::deserialize(decoder)
    }
}

#[test]
fn initial_original_refusal_precedes_seed_dispatch() -> Result<(), Box<dyn Error>> {
    let (budget, authority) = original()?;
    let observed = AtomicBool::new(false);
    authority.live_refusing.store(true, Ordering::SeqCst);

    let result = from_cbor_slice_with_seed(&[0x01], ObservedSeed(&observed), &budget);

    assert!(result.is_err());
    assert!(!observed.load(Ordering::SeqCst));
    assert_eq!(budget.failure()?, Some(authority.failure.clone()));
    Ok(())
}

struct FinalLiveRefusalSeed<'a>(&'a Authority);

impl<'de> DeserializeSeed<'de> for FinalLiveRefusalSeed<'_> {
    type Value = u8;

    fn deserialize<D: serde::Deserializer<'de>>(self, decoder: D) -> Result<u8, D::Error> {
        let value = u8::deserialize(decoder)?;
        self.0.live_refusing.store(true, Ordering::SeqCst);
        Ok(value)
    }
}

#[test]
fn healthy_seed_value_checks_original_authority_at_final_cut() -> Result<(), Box<dyn Error>> {
    let (budget, authority) = original()?;

    let result = from_cbor_slice_with_seed(&[0x01], FinalLiveRefusalSeed(&authority), &budget);

    assert!(result.is_err());
    assert_eq!(budget.failure()?, Some(authority.failure.clone()));
    Ok(())
}

thread_local! {
    static RESERVATION_SCOPE: RefCell<Option<DecodeScope>> = const { RefCell::new(None) };
}

struct ReservationScopeCleanup;

impl Drop for ReservationScopeCleanup {
    fn drop(&mut self) {
        RESERVATION_SCOPE.with(|scope| drop(scope.borrow_mut().take()));
    }
}

#[test]
fn active_route_keeps_entry_original_after_scratch_authority_switch() -> Result<(), Box<dyn Error>>
{
    let (saved, saved_authority) = original()?;
    let (other, _) = original()?;
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&String::from("owning member"), &mut bytes)?;
    *saved_authority
        .reservation_scope
        .lock()
        .map_err(|_| fmt::Error)? = Some(other.clone());
    let _entry_scope = saved.enter();
    let cleanup = ReservationScopeCleanup;

    let result = from_cbor_slice::<String>(&bytes);
    drop(cleanup);

    assert!(result.is_err());
    assert_eq!(saved.failure()?, Some(saved_authority.failure.clone()));
    assert!(other.failure()?.is_none());
    Ok(())
}
