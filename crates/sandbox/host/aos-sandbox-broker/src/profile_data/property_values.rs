//! Projects selected immutable property tables without recursive copies.
//!
//! The actual native attempt retains the shared tables. Ordinary observations
//! move their existing Vec into an inline carrier, adding no heap allocation.
//! Both variants expose the same borrowed values to the existing decoders;
//! neither grants observation, peer, currentness or payment authority.

use std::ops::Deref;
use std::sync::Arc;

use aos_systemd_client::OwnedValue;

/// Holds the two original readonly property tables without copying models.
pub type PropertyPairV1 = (PropertyValuesV1, PropertyValuesV1);

/// Borrows ordinary or retained property DATA without authority or allocation.
pub struct PropertyValuesV1 {
    storage: PropertyStorageV1,
}

enum PropertyStorageV1 {
    Ordinary(Vec<OwnedValue>),
    Retained(Arc<Vec<OwnedValue>>),
}

impl PropertyValuesV1 {
    /// Moves an existing ordinary table without allocation.
    #[must_use]
    pub fn ordinary(values: Vec<OwnedValue>) -> Self {
        Self { storage: PropertyStorageV1::Ordinary(values) }
    }

    /// Shares the same actual table without recursively copying values.
    #[must_use]
    pub fn retained(values: &Arc<Vec<OwnedValue>>) -> Self {
        Self::retained_owned(Arc::clone(values))
    }

    /// Moves an already-shared actual table without another Arc clone.
    #[must_use]
    pub fn retained_owned(values: Arc<Vec<OwnedValue>>) -> Self {
        Self { storage: PropertyStorageV1::Retained(values) }
    }

    /// Borrows the same property values as nonauthorizing DATA.
    #[must_use]
    pub fn as_slice(&self) -> &[OwnedValue] {
        match &self.storage {
            PropertyStorageV1::Ordinary(values) => values.as_slice(),
            PropertyStorageV1::Retained(values) => values.as_slice(),
        }
    }
}

impl Deref for PropertyValuesV1 {
    type Target = [OwnedValue];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retained_views_share_the_actual_nested_model_and_keep_it_readable() {
        let nested = aos_systemd_client::Value::from(vec![String::from("/original/fragment")]);
        let original = Arc::new(vec![OwnedValue::try_from(nested).unwrap()]);
        let address = original.as_ptr();
        let first = PropertyValuesV1::retained(&original);
        let second = PropertyValuesV1::retained(&original);

        assert_eq!(first.as_ptr(), address);
        assert_eq!(second.as_ptr(), address);
        assert_eq!(Arc::strong_count(&original), 3);
        drop(first);
        assert_eq!(Arc::strong_count(&original), 2);
        drop(original);

        let strings = Vec::<String>::try_from(second[0].try_clone().unwrap()).unwrap();
        assert_eq!(strings, ["/original/fragment"]);
        assert_eq!(second.as_ptr(), address);
    }

    #[test]
    fn ordinary_table_moves_without_reallocating_its_existing_vec() {
        let values = vec![OwnedValue::from(9_u32), OwnedValue::from(10_u32)];
        let address = values.as_ptr();
        let capacity = values.capacity();
        let ordinary = PropertyValuesV1::ordinary(values);

        assert_eq!(ordinary.as_ptr(), address);
        let PropertyStorageV1::Ordinary(values) = ordinary.storage else {
            panic!("ordinary values changed storage strategy");
        };
        assert_eq!(values.capacity(), capacity);
        assert_eq!(u32::try_from(&values[0]).unwrap(), 9);
    }
}

#[cfg(test)]
mod owned_retained_view_tests {
    use super::*;

    #[test]
    fn an_already_shared_table_moves_into_the_domain_view_without_another_clone() {
        let original = Arc::new(vec![OwnedValue::from(9u32)]);
        let shared = Arc::clone(&original);
        let pointer = shared.as_ptr();
        assert_eq!(Arc::strong_count(&original), 2);

        let view = PropertyValuesV1::retained_owned(shared);

        assert_eq!(view.as_ptr(), pointer);
        assert_eq!(Arc::strong_count(&original), 2);
        assert_eq!(u32::try_from(&view[0]).unwrap(), 9);
    }
}
