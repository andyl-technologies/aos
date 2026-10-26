//! Hashes the actual Source-paid main map through the canonical retained engine.
//!
//! This owner consumes the genuine original readback loan. Native files and
//! writer custody remain in Domain; the exact map hash and reached predecessor
//! key remain here. Cut DATA supplies no schema, endpoint, approval or TPM grant.

use aos_sandbox_broker::receiving::Method46InitialOriginComparisonDataV1;
use aos_sandbox_controller_domain::{
    RecordNamespace,
    method46_initial_startup::{
        METHOD46_INITIAL_MAIN_CUT_BYTES_V1, Method46InitialMainReadbackLoanV1,
        Method46InitialStartupClosedV1,
    },
};
use aos_sandbox_model::{ResourceDimension, ResourceVector};

use super::Method46InitialDataErrorV1;
use crate::tpm_nv_custody::{FloorCutV1, FloorErrorV1, FloorHeadCutOriginalV3};

/// Retains the canonical cut of the same Source-funded original main map.
///
/// No map, amount, sequence or digest enters from the caller. The existing
/// canonical engine hashes every Broker row, including archives. Native
/// before/after observations remain bound to the original protected opening.
/// Historical namespace/Session schema and capacity ownership, independent
/// endpoint/key provenance and physical TPM custody remain separate gates.
#[must_use = "retain the canonical hash result beside its genuine readback loan"]
pub struct Method46InitialMainCutOriginalV1<'owner> {
    readback: Method46InitialMainReadbackLoanV1<'owner>,
    origin: Option<Result<Method46InitialOriginComparisonDataV1, Method46InitialStartupClosedV1>>,
    read: Option<Result<(), Method46InitialStartupClosedV1>>,
    geometry: Option<Option<ResourceVector>>,
    namespaces_match: Option<bool>,
    hash: FloorHeadCutOriginalV3,
    cut: Option<Result<FloorCutV1, FloorErrorV1>>,
    after: Option<Result<(), Method46InitialStartupClosedV1>>,
}

const _: () = assert!(
    2 * std::mem::size_of::<Method46InitialMainCutOriginalV1<'static>>()
        <= METHOD46_INITIAL_MAIN_CUT_BYTES_V1
);

impl<'owner> Method46InitialMainCutOriginalV1<'owner> {
    /// Consumes the genuine paid loan and retains its canonical hash once.
    ///
    /// Every reached refusal remains resident. The independently prepaid
    /// native after is attempted after the temporary map borrow drops, even
    /// on a failed hash or layout/namespace comparison. No native IO is retried.
    pub fn hash_captured_v1(readback: Method46InitialMainReadbackLoanV1<'owner>) -> Self {
        let mut original = Self {
            readback,
            origin: None,
            read: None,
            geometry: None,
            namespaces_match: None,
            hash: FloorHeadCutOriginalV3::new(),
            cut: None,
            after: None,
        };
        original.hash();
        if !original.hash_completed() {
            original.readback.refuse_readback_v1();
        }
        original.after = Some(original.readback.finish_readback_after_owed_once_v1());
        if !matches!(original.after, Some(Ok(()))) {
            original.readback.refuse_readback_v1();
        }
        original
    }

    fn hash(&mut self) {
        self.origin = Some(self.readback.origin_data_v1());
        if !matches!(self.origin, Some(Ok(_))) {
            return;
        }
        let map = match self.readback.read_map_data_v1() {
            Ok(map) => {
                self.read = Some(Ok(()));
                map
            }
            Err(error) => {
                self.read = Some(Err(error));
                return;
            }
        };
        self.geometry = Some(FloorHeadCutOriginalV3::receiving_demand_v3(
            map.maximum_key_bytes_data_v1(),
        ));
        let fits = self
            .geometry
            .as_ref()
            .and_then(|geometry| geometry.as_ref())
            .and_then(|geometry| {
                u64::try_from(std::mem::size_of::<Self>())
                    .ok()?
                    .checked_mul(2)?
                    .checked_add(geometry.get(ResourceDimension::MemoryBytes))
            })
            .is_some_and(|bytes| bytes <= METHOD46_INITIAL_MAIN_CUT_BYTES_V1 as u64);
        if !fits {
            return;
        }

        // Capacity records are excluded by the canonical Broker hash itself.
        // Their ownership and historical namespaces still need real admission.
        self.namespaces_match = Some(map.all_records_data_v1().all(|(namespace, _, _)| {
            matches!(
                namespace,
                RecordNamespace::BrokerSessionTraffic | RecordNamespace::GlobalCapacityReservation
            )
        }));
        if self.namespaces_match != Some(true) {
            return;
        }
        self.cut = Some(
            self.hash
                .observe_broker_once_v3(map.next_sequence_data_v1(), map.broker_records_data_v1()),
        );
    }

    fn hash_completed(&self) -> bool {
        matches!(self.origin, Some(Ok(_)))
            && matches!(self.read, Some(Ok(())))
            && self.namespaces_match == Some(true)
            && matches!(self.cut, Some(Ok(_)))
    }

    /// Copies the compared cut as DATA while its actual Source remains current.
    ///
    /// This is not initial approval, a prepared intent or an Extend/checkpoint
    /// capability. Normal endpoint/Session schema and job exclusion remain owed.
    ///
    /// # Errors
    /// Refuses a failed layout, read, namespace/hash or native after, or an
    /// ended Source. No supplied digest can replace the original result.
    pub fn cut_data_v1(&self) -> Result<FloorCutV1, Method46InitialDataErrorV1> {
        if !self.hash_completed() || !matches!(self.after, Some(Ok(()))) {
            return Err(Method46InitialDataErrorV1::Conflict);
        }
        self.readback
            .origin_data_v1()
            .map_err(|_| Method46InitialDataErrorV1::Conflict)?;
        match self.cut {
            Some(Ok(cut)) => Ok(cut),
            _ => Err(Method46InitialDataErrorV1::Conflict),
        }
    }
}
