//! Retains the four fixed manifest key results and actual context construction.
//!
//! These are passive model/result destinations. Their constructor supplies no
//! manifest, signer, FD, peer, Session, budget or currentness authority.

use super::*;
use crate::BrokerSessionValidationError;

/// Owns reached fixed-key/context results through a selected caller's posts.
///
/// The same format owner still constructs every key and context. Successful
/// context transfer moves the actual value once; failed keys, partial collected
/// prefix and concrete validation error remain in this original capture.
#[doc(hidden)]
#[derive(Default)]
pub struct BrokerSessionManifestContextOriginalsV1 {
    keys: Option<[Result<ProtectedBrokerSessionKeyV1, BrokerSessionValidationError>; 4]>,
    collected: Vec<ProtectedBrokerSessionKeyV1>,
    allocated: Option<Result<(), std::collections::TryReserveError>>,
    collection: Option<Result<(), BrokerSessionManifestErrorV1>>,
    constructed: Option<
        Result<Option<ProtectedBrokerSessionVerificationContextV1>, BrokerSessionValidationError>,
    >,
    returned: bool,
}

impl BrokerSessionManifestContextOriginalsV1 {
    pub(super) fn is_empty(&self) -> bool {
        self.keys.is_none()
            && self.allocated.is_none()
            && self.collection.is_none()
            && self.constructed.is_none()
            && !self.returned
    }

    pub(super) fn retain_keys_once(
        &mut self,
        keys: [Result<ProtectedBrokerSessionKeyV1, BrokerSessionValidationError>; 4],
    ) -> Result<(), BrokerSessionManifestErrorV1> {
        if !self.is_empty() {
            return Err(BrokerSessionManifestErrorV1::manifest("context capture reentry"));
        }
        self.keys = Some(keys);
        Ok(())
    }

    pub(super) fn collect_keys_once(
        &mut self,
    ) -> Result<[ProtectedBrokerSessionKeyV1; 4], BrokerSessionManifestErrorV1> {
        if self.collection.is_some() {
            return Err(BrokerSessionManifestErrorV1::manifest("context collection reentry"));
        }

        self.allocated = Some(self.collected.try_reserve_exact(4));
        let observed = (|| {
            if !matches!(self.allocated, Some(Ok(()))) {
                return Err(BrokerSessionManifestErrorV1::manifest("key collection allocation"));
            }
            let keys = self
                .keys
                .as_ref()
                .ok_or_else(|| BrokerSessionManifestErrorV1::manifest("key set"))?;
            for key in keys {
                match key {
                    Ok(key) => self.collected.push(key.clone()),
                    Err(_) => return Err(BrokerSessionManifestErrorV1::manifest("key set")),
                }
            }
            Ok(())
        })();

        self.collection = Some(observed);
        if !matches!(self.collection, Some(Ok(()))) {
            return Err(BrokerSessionManifestErrorV1::manifest("key set"));
        }

        let [Some(first), Some(second), Some(third), Some(fourth)] = [
            self.collected.first(),
            self.collected.get(1),
            self.collected.get(2),
            self.collected.get(3),
        ] else {
            return Err(BrokerSessionManifestErrorV1::manifest("key set"));
        };
        Ok([first.clone(), second.clone(), third.clone(), fourth.clone()])
    }

    pub(super) fn retain_context_once(
        &mut self,
        result: Result<ProtectedBrokerSessionVerificationContextV1, BrokerSessionValidationError>,
    ) -> Result<(), BrokerSessionManifestErrorV1> {
        self.constructed = Some(result.map(Some));
        if matches!(self.constructed, Some(Ok(_))) {
            Ok(())
        } else {
            Err(BrokerSessionManifestErrorV1::manifest("verification context"))
        }
    }

    pub(super) fn take_success_once(
        &mut self,
    ) -> Result<ProtectedBrokerSessionVerificationContextV1, BrokerSessionManifestErrorV1> {
        let value = self
            .constructed
            .as_mut()
            .and_then(|result| result.as_mut().ok())
            .and_then(Option::take)
            .ok_or_else(|| BrokerSessionManifestErrorV1::manifest("context transfer"))?;
        self.returned = true;
        Ok(value)
    }

    /// Borrows the first exact reached key/collection/context error.
    #[doc(hidden)]
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        fn cause<T, E: std::error::Error + 'static>(
            result: &Option<Result<T, E>>,
        ) -> Option<&(dyn std::error::Error + 'static)> {
            result.as_ref()?.as_ref().err().map(|error| error as _)
        }

        self.keys
            .as_ref()
            .and_then(|keys| {
                keys.iter().find_map(|key| {
                    key.as_ref()
                        .err()
                        .map(|error| error as &(dyn std::error::Error + 'static))
                })
            })
            .or_else(|| cause(&self.allocated))
            .or_else(|| cause(&self.collection))
            .or_else(|| cause(&self.constructed))
    }

    /// Describes fixed extra key backing and reached metadata without admission.
    ///
    /// The enclosing owner measures its inline fields. Additional bytes cover
    /// exactly four reserved collection keys, the returned four-key argument
    /// and the context-constructor Result temporary. Four raw key Results,
    /// allocation/collection/context Results and Vec backing account for eight
    /// retained metadata destinations.
    #[doc(hidden)]
    #[must_use]
    pub const fn receiving_footprint_v1() -> (usize, usize) {
        let keys = 4 * std::mem::size_of::<ProtectedBrokerSessionKeyV1>();
        let context = std::mem::size_of::<
            Result<ProtectedBrokerSessionVerificationContextV1, BrokerSessionValidationError>,
        >();
        (keys + std::mem::size_of::<[ProtectedBrokerSessionKeyV1; 4]>() + context, 8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_context_moves_once_without_replacing_its_key_results() {
        let manifest = super::super::tests::manifest();
        let ordinary = manifest.verification_context([1; 16], [2; 16], [3; 16]).unwrap();
        let mut originals = BrokerSessionManifestContextOriginalsV1::default();

        let retained = manifest.verification_context_retaining_v1(
            [1; 16], [2; 16], [3; 16], &mut originals,
        ).unwrap();

        assert_eq!(retained, ordinary);
        assert_eq!(originals.collected.len(), 4);
        assert!(originals.keys.as_ref().unwrap().iter().all(Result::is_ok));
        assert!(matches!(originals.constructed, Some(Ok(None))));
        assert!(originals.returned);
        assert!(originals.failure().is_none());
        assert!(originals.take_success_once().is_err());
        let keys = originals.keys.as_ref().unwrap() as *const _;
        assert!(manifest.verification_context_retaining_v1(
            [1; 16], [2; 16], [3; 16], &mut originals,
        ).is_err());
        assert_eq!(originals.keys.as_ref().unwrap() as *const _, keys);
        assert_eq!(originals.collected.len(), 4);
    }

    #[test]
    fn failed_context_keeps_all_successful_keys_and_its_original_typed_cause() {
        let manifest = super::super::tests::manifest();
        let mut originals = BrokerSessionManifestContextOriginalsV1::default();

        let retained = manifest.verification_context_retaining_v1(
            [0; 16], [2; 16], [3; 16], &mut originals,
        );
        let ordinary = manifest.verification_context([0; 16], [2; 16], [3; 16]);

        assert_eq!(retained.unwrap_err(), ordinary.unwrap_err());
        assert!(originals.keys.as_ref().unwrap().iter().all(Result::is_ok));
        assert!(matches!(originals.allocated, Some(Ok(()))));
        assert!(matches!(originals.collection, Some(Ok(()))));
        assert_eq!(originals.collected.len(), 4);
        let actual = originals.constructed.as_ref().unwrap().as_ref().unwrap_err();
        let projected = originals.failure().unwrap()
            .downcast_ref::<BrokerSessionValidationError>().unwrap();
        assert!(std::ptr::eq(projected, actual));
        let first = actual as *const _;

        assert!(manifest.verification_context_retaining_v1(
            [1; 16], [2; 16], [3; 16], &mut originals,
        ).is_err());
        let unchanged = originals.failure().unwrap()
            .downcast_ref::<BrokerSessionValidationError>().unwrap();
        assert_eq!(unchanged as *const _, first);
        assert_eq!(originals.collected.len(), 4);
    }

    #[test]
    fn a_later_invalid_key_keeps_the_reached_collection_prefix() {
        let mut manifest = super::super::tests::manifest();
        // This private fixture mutation reaches the existing key validator;
        // production manifests still pass through their canonical constructor.
        manifest.keys[2].minimum_key_generation = 0;
        let mut originals = BrokerSessionManifestContextOriginalsV1::default();

        let retained = manifest.verification_context_retaining_v1(
            [1; 16], [2; 16], [3; 16], &mut originals,
        );
        let ordinary = manifest.verification_context([1; 16], [2; 16], [3; 16]);

        assert_eq!(retained.unwrap_err(), ordinary.unwrap_err());
        assert_eq!(originals.collected.len(), 2);
        assert!(originals.constructed.is_none());
        let actual = originals.keys.as_ref().unwrap()[2].as_ref().unwrap_err();
        let projected = originals.failure().unwrap()
            .downcast_ref::<BrokerSessionValidationError>().unwrap();
        assert!(std::ptr::eq(projected, actual));
        let first = actual as *const _;
        assert!(manifest.verification_context_retaining_v1(
            [1; 16], [2; 16], [3; 16], &mut originals,
        ).is_err());
        assert_eq!(originals.failure().unwrap()
            .downcast_ref::<BrokerSessionValidationError>().unwrap() as *const _, first);
        assert_eq!(originals.collected.len(), 2);
    }
}
