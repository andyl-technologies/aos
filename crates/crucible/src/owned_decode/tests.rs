//! Finite original-account custody and typed serde admission regressions.

use std::sync::atomic::{AtomicU64, Ordering};

use super::*;
use std::error::Error;
use std::sync::Arc;

fn refusal(message: &'static str) -> DecodeAdmissionError {
    DecodeAdmissionError::new(std::io::Error::other(message))
}

struct Authority {
    used: Arc<AtomicU64>,
    maximum: u64,
}
struct Credit {
    used: Arc<AtomicU64>,
    bytes: u64,
}

impl Drop for Credit {
    fn drop(&mut self) {
        self.used.fetch_sub(self.bytes, Ordering::SeqCst);
    }
}

impl DecodeResourceAuthority for Authority {
    fn verify_live(&self) -> Result<(), DecodeAdmissionError> {
        if self.used.load(Ordering::SeqCst) > self.maximum {
            return Err(DecodeAdmissionError::new(std::io::Error::other(
                "original component accounting is invalid",
            )));
        }
        Ok(())
    }

    fn reserve(&self, bytes: u64) -> Result<Arc<dyn Send + Sync>, DecodeAdmissionError> {
        self.used
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                used.checked_add(bytes).filter(|next| *next <= self.maximum)
            })
            .map_err(|_| refusal("fixture original allowance exhausted"))?;
        Ok(Arc::new(Credit {
            used: self.used.clone(),
            bytes,
        }))
    }
}

fn authority(maximum: u64) -> Arc<Authority> {
    Arc::new(Authority {
        used: Arc::new(AtomicU64::new(0)),
        maximum,
    })
}

#[test]
fn json_output_is_admitted_before_the_second_serialization_pass() -> Result<(), DecodeAdmissionError>
{
    struct Borrowed<'a> {
        calls: &'a AtomicU64,
        bytes: &'a [u8],
    }
    impl serde::Serialize for Borrowed<'_> {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.bytes.serialize(serializer)
        }
    }
    let bytes = [0_u8; 1024];
    let calls = AtomicU64::new(0);
    let authority = authority(256);
    let budget = DecodeBudget::new(authority.clone(), 256)?;
    let _scope = budget.enter();
    let result = to_json_vec(&Borrowed {
        calls: &calls,
        bytes: &bytes,
    });
    assert!(result.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(budget.failure()?.is_some());
    assert!(authority.used.load(Ordering::SeqCst) <= 256);
    Ok(())
}

#[test]
fn exact_json_output_preserves_serde_bytes_and_rejects_format_overflow()
-> Result<(), Box<dyn Error>> {
    let value = std::collections::BTreeMap::from([(
        "quoted\"name",
        vec!["unicode \u{1f980}", "newline\n"],
    )]);
    let expected = serde_json::to_vec(&value)?;
    let budget = DecodeBudget::new(authority(64 * 1024), 64 * 1024)?;
    let _scope = budget.enter();
    assert_eq!(to_json_vec(&value)?, expected);
    assert!(to_json_vec_bounded(&value, expected.len() - 1).is_err());
    Ok(())
}

#[test]
fn display_output_refuses_original_credit_before_second_formatting_pass()
-> Result<(), DecodeAdmissionError> {
    struct Borrowed<'a> {
        calls: &'a AtomicU64,
        text: &'a str,
    }
    impl std::fmt::Display for Borrowed<'_> {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            self.calls.fetch_add(1, Ordering::SeqCst);
            formatter.write_str(self.text)
        }
    }
    let text = "a".repeat(1024);
    let calls = AtomicU64::new(0);
    let authority = authority(256);
    let budget = DecodeBudget::new(authority.clone(), 256)?;
    let _scope = budget.enter();
    assert!(
        display_string(&Borrowed {
            calls: &calls,
            text: &text
        })
        .is_err()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(budget.failure()?.is_some());
    assert!(authority.used.load(Ordering::SeqCst) <= 256);
    Ok(())
}

#[test]
fn display_output_preserves_utf8_and_refuses_changing_length() -> Result<(), DecodeAdmissionError> {
    struct Changing(AtomicU64);
    impl std::fmt::Display for Changing {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
                formatter.write_str("x")
            } else {
                formatter.write_str("longer")
            }
        }
    }
    let budget = DecodeBudget::new(authority(4096), 4096)?;
    let _scope = budget.enter();
    assert_eq!(display_string(&"text \u{1f980}\n")?, "text \u{1f980}\n");
    assert!(display_string(&Changing(AtomicU64::new(0))).is_err());
    Ok(())
}

#[test]
fn empty_fault_plan_keeps_static_identity_without_original_heap_credit()
-> Result<(), DecodeAdmissionError> {
    let authority = authority(256);
    let budget = DecodeBudget::new(authority.clone(), 256)?;
    let before = authority.used.load(Ordering::SeqCst);
    let _scope = budget.enter();
    let plan = crate::model::FaultSignalPlan::empty();
    let copied = plan.clone();
    assert_eq!(plan, copied);
    assert_eq!(authority.used.load(Ordering::SeqCst), before);
    assert!(budget.failure()?.is_none());
    Ok(())
}

#[test]
fn decoded_custody_retains_original_credit_until_last_owner() -> Result<(), DecodeAdmissionError> {
    let authority = authority(4096);
    let budget = DecodeBudget::new(authority.clone(), 4096)?;
    budget.charge_array::<u64>(32)?;
    let custody = budget.custody();
    let retained = custody.clone();
    let used = authority.used.load(Ordering::SeqCst);
    assert!(used >= 256);
    drop(budget);
    drop(custody);
    assert_eq!(authority.used.load(Ordering::SeqCst), used);
    drop(retained);
    assert_eq!(authority.used.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn typed_seed_is_refused_before_its_deserializer_runs() -> Result<(), DecodeAdmissionError> {
    static ENTERED: AtomicU64 = AtomicU64::new(0);
    struct LargeValue([u64; 1024]);
    impl<'de> serde::Deserialize<'de> for LargeValue {
        fn deserialize<D: serde::Deserializer<'de>>(_decoder: D) -> Result<Self, D::Error> {
            ENTERED.fetch_add(1, Ordering::SeqCst);
            Ok(Self([0; 1024]))
        }
    }

    let budget = DecodeBudget::new(authority(4096), 4096)?;
    let _scope = budget.enter();
    let result = from_json_slice::<Vec<LargeValue>>(b"[0]");
    assert!(result.is_err());
    assert_eq!(ENTERED.load(Ordering::SeqCst), 0);
    assert!(budget.failure()?.is_some());
    // Keep the fixture's actual value layout observable to its admission test.
    assert_eq!(std::mem::size_of_val(&LargeValue([0; 1024]).0), 8192);
    Ok(())
}

#[test]
fn scoped_json_preserves_nested_map_sequence_and_enum_values() -> Result<(), Box<dyn Error>> {
    #[derive(Debug, serde::Deserialize, PartialEq)]
    enum Choice {
        Tuple(u64, String),
        Struct { values: Vec<u64> },
    }
    #[derive(Debug, serde::Deserialize, PartialEq)]
    struct Artifact {
        entries: std::collections::BTreeMap<String, Choice>,
    }
    let budget = DecodeBudget::new(authority(128 * 1024), 128 * 1024)?;
    let scope = budget.enter();
    let bytes =
        br#"{"entries":{"first":{"Tuple":[7,"name"]},"second":{"Struct":{"values":[1,2,3]}}}}"#;
    let value = from_json_slice::<Artifact>(bytes)?;
    drop(scope);
    assert_eq!(value, serde_json::from_slice::<Artifact>(bytes)?);
    assert!(budget.failure()?.is_none());
    Ok(())
}

#[test]
fn nested_scope_restores_original_budget_and_typed_refusal() -> Result<(), DecodeAdmissionError> {
    let outer = DecodeBudget::new(authority(4096), 4096)?;
    let inner = DecodeBudget::new(authority(512), 512)?;
    let _outer = outer.enter();
    {
        let _inner = inner.enter();
        assert!(charge_array::<u64>(128).is_err());
    }
    charge_array::<u64>(128)?;
    assert!(outer.failure()?.is_none());
    assert!(inner.failure()?.is_some());
    Ok(())
}

#[test]
fn over_aligned_zero_sized_tree_entries_include_node_padding() -> Result<(), DecodeAdmissionError> {
    #[repr(align(256))]
    struct AlignedKey;

    let authority = authority(16 * 1024);
    let budget = DecodeBudget::new(authority.clone(), 16 * 1024)?;
    let before = authority.used.load(Ordering::SeqCst);
    budget.charge_btree_entry::<AlignedKey, u8>()?;
    let charged = authority.used.load(Ordering::SeqCst) - before;

    // A zero-sized key still raises the node alignment. Header, value array
    // and child pointers need padding independently; two complete node bounds
    // must cover it rather than counting only the entry's value bytes.
    assert_eq!(std::mem::size_of::<AlignedKey>(), 0);
    assert!(charged >= 2 * 512);
    Ok(())
}

#[test]
fn boxed_inner_value_is_admitted_before_its_visitor_allocates() -> Result<(), DecodeAdmissionError>
{
    static ENTERED: AtomicU64 = AtomicU64::new(0);
    struct LargeValue([u64; 1024]);
    struct LargeVisitor;

    impl<'de> serde::de::Visitor<'de> for LargeVisitor {
        type Value = LargeValue;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("large fixture value")
        }

        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            _sequence: A,
        ) -> Result<Self::Value, A::Error> {
            ENTERED.fetch_add(1, Ordering::SeqCst);
            Ok(LargeValue([0; 1024]))
        }
    }

    impl<'de> serde::Deserialize<'de> for LargeValue {
        fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
            decoder.deserialize_tuple(1024, LargeVisitor)
        }
    }

    let budget = DecodeBudget::new(authority(4096), 4096)?;
    let _scope = budget.enter();
    assert!(from_json_slice::<Box<LargeValue>>(b"[]").is_err());
    assert_eq!(ENTERED.load(Ordering::SeqCst), 0);
    assert!(budget.failure()?.is_some());
    assert_eq!(std::mem::size_of_val(&LargeValue([0; 1024]).0), 8192);
    Ok(())
}

#[test]
fn parser_scratch_releases_only_its_original_temporary_credit() -> Result<(), DecodeAdmissionError>
{
    let authority = authority(4096);
    let budget = DecodeBudget::new(authority.clone(), 4096)?;
    budget.charge_array::<u64>(32)?;
    let retained = authority.used.load(Ordering::SeqCst);
    let scratch = budget.reserve_scratch_array::<u64>(256)?;
    assert_eq!(authority.used.load(Ordering::SeqCst), retained + 2048);
    drop(scratch);
    assert_eq!(authority.used.load(Ordering::SeqCst), retained);
    let second = budget.reserve_scratch_bytes(2048)?;
    drop(second);
    assert_eq!(authority.used.load(Ordering::SeqCst), retained);
    let custody = budget.custody();
    drop(budget);
    assert_eq!(authority.used.load(Ordering::SeqCst), retained);
    drop(custody);
    assert_eq!(authority.used.load(Ordering::SeqCst), 0);
    Ok(())
}
