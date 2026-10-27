//! Walks this actual Source's independent owners without invoking its authority.
//!
//! Each encoded result/evidence bank owns separate capacity even when bytes are
//! equal. The outer caller counts the Source Rc header and inline payload once;
//! this walk counts its real children. Busy loans and erased failures refuse.

use super::*;
use crate::node_qualification::{
    RetainedMetadataCounter as Counter, RetainedMetadataOwned as Owned,
};

impl Owned for OriginalNormalClockSource {
    fn charge(&self, counter: &mut Counter) -> Result<(), QualificationError> {
        let Self {
            origin,
            lifetime,
            aggregate,
            profile,
            unit,
            population,
            issued,
            record,
            evidence,
            expected,
            proposal,
            adverse_executions: _,
            publication_executions: _,
            activation,
            results,
            failed: _,
        } = self;
        // Raw creator checks precede RefCell loans; no executable, quota or
        // installed-policy callback runs from this synchronous storage walk.
        if origin.process != std::process::id() || origin.thread != std::thread::current().id() {
            return Err(reject("foreign Clock Source storage owner"));
        }
        counter.charge(origin)?;
        counter.weak(lifetime)?;
        if counter.rc(aggregate)? {
            counter.charge(aggregate.as_ref())?;
        }
        counter.charge(profile)?;
        counter.charge(unit)?;
        counter.charge(population)?;
        if let Some(issued) = issued.get() {
            counter.charge(issued)?;
        }
        if let Some(record) = record.get() {
            counter.charge(record)?;
        }
        charge_loan(evidence, counter, "Clock Source evidence owner busy")?;
        counter.charge(expected)?;
        counter.charge(proposal)?;
        charge_loan(activation, counter, "Clock Source activation owner busy")?;
        charge_loan(results, counter, "Clock Source result owner busy")
    }
}

impl Owned for ExpectedCase {
    fn charge(&self, counter: &mut Counter) -> Result<(), QualificationError> {
        let Self { oracle, expected } = self;
        counter.charge(oracle)?;
        counter.charge(expected)
    }
}

impl Owned for RetainedResult {
    fn charge(&self, counter: &mut Counter) -> Result<(), QualificationError> {
        let Self {
            reference,
            bytes,
            authenticated: _,
        } = self;
        counter.charge(reference)?;
        counter.charge(bytes)
    }
}

impl Owned for unit::Unit {
    fn charge(&self, counter: &mut Counter) -> Result<(), QualificationError> {
        let Self {
            value,
            content,
            kernel,
            state_oracle,
            ceilings: _,
            writable_environment: _,
        } = self;
        counter.charge(value)?;
        counter.charge(content)?;
        counter.charge(kernel)?;
        counter.charge(state_oracle)
    }
}

impl Owned for population::Population {
    fn charge(&self, counter: &mut Counter) -> Result<(), QualificationError> {
        let Self {
            plan,
            reference,
            bytes,
            content,
            audit,
        } = self;
        counter.charge(plan)?;
        counter.charge(reference)?;
        counter.charge(bytes)?;
        counter.charge(content)?;
        counter.charge(audit)
    }
}

impl OriginalNormalClockSource {
    pub(in super::super) fn original_storage_scratch_data() -> usize {
        use crucible_engine::node_contract::RetainedCoreOwnerStorage;
        use std::{cell::Ref, mem::size_of};
        size_of::<Ref<'_, evidence::Evidence>>()
            + size_of::<Ref<'_, Option<WorldActivation>>>()
            + size_of::<Ref<'_, BTreeMap<String, RetainedResult>>>()
            + size_of::<RetainedCoreOwnerStorage<'_>>()
    }
}

// The creator check is performed by the concrete Source before this helper.
// A busy original owner is retained; neither a fallback clone nor serialization
// can manufacture an observation while the original mutable loan is live.
fn charge_loan<T: Owned>(
    owner: &RefCell<T>,
    counter: &mut Counter,
    busy: &'static str,
) -> Result<(), QualificationError> {
    let value = owner.try_borrow().map_err(|_| reject(busy))?;
    counter.charge(&*value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(capacity: usize) -> Result<RetainedResult, QualificationError> {
        let mut bytes = Vec::with_capacity(capacity);
        bytes.extend_from_slice(b"original result");
        Ok(RetainedResult {
            reference: crucible_node_format::canonical::content_ref(
                &bytes,
                "application/octet-stream",
            )
            .map_err(failure)?,
            bytes,
            authenticated: false,
        })
    }

    #[test]
    fn independent_source_results_keep_equal_bytes_and_spare_banks()
    -> Result<(), QualificationError> {
        let first = result(4096)?;
        let second = result(8192)?;
        assert_eq!(first.reference, second.reference);
        assert_eq!(first.bytes, second.bytes);
        assert_ne!(first.bytes.as_ptr(), second.bytes.as_ptr());

        let mut first_count = Counter::new(usize::MAX);
        first_count.charge(&first)?;
        let mut second_count = Counter::new(usize::MAX);
        second_count.charge(&second)?;
        assert_eq!(
            second_count.bytes() - first_count.bytes(),
            second.bytes.capacity() - first.bytes.capacity()
        );

        let expected = first_count.bytes() + second_count.bytes();
        let mut exact = Counter::new(expected);
        exact.charge(&first)?;
        exact.charge(&second)?;
        assert_eq!(exact.bytes(), expected);
        let mut short = Counter::new(expected - 1);
        short.charge(&first)?;
        assert!(short.charge(&second).is_err());
        Ok(())
    }

    #[test]
    fn busy_source_result_bank_refuses_without_cloning_or_consuming_it()
    -> Result<(), QualificationError> {
        let mut records = BTreeMap::new();
        records.insert(String::from("first"), result(4096)?);
        let owner = RefCell::new(records);
        let loan = owner.borrow_mut();
        let pointer = loan["first"].bytes.as_ptr();
        let mut counter = Counter::new(usize::MAX);

        assert!(charge_loan(&owner, &mut counter, "original busy").is_err());
        assert_eq!(counter.bytes(), 0);
        assert_eq!(loan["first"].bytes.as_ptr(), pointer);
        drop(loan);

        charge_loan(&owner, &mut counter, "original busy")?;
        assert!(counter.bytes() >= 4096);
        assert_eq!(owner.borrow()["first"].bytes.as_ptr(), pointer);
        Ok(())
    }

    #[test]
    fn source_result_bank_counts_owned_keys_and_tree_as_well_as_payload()
    -> Result<(), QualificationError> {
        let record = result(4096)?;
        let mut payload = Counter::new(usize::MAX);
        payload.charge(&record)?;
        let mut key = String::with_capacity(2048);
        key.push_str("original");
        let key_capacity = key.capacity();
        let owner = RefCell::new(BTreeMap::from([(key, record)]));
        let mut actual = Counter::new(usize::MAX);

        charge_loan(&owner, &mut actual, "original busy")?;
        assert!(actual.bytes() > payload.bytes() + key_capacity);
        let mut exact = Counter::new(actual.bytes());
        charge_loan(&owner, &mut exact, "original busy")?;
        assert_eq!(exact.bytes(), actual.bytes());
        assert!(
            charge_loan(
                &owner,
                &mut Counter::new(actual.bytes() - 1),
                "original busy"
            )
            .is_err()
        );
        Ok(())
    }
}
