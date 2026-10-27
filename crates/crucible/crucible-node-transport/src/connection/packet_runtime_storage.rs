//! Prices correlation and containment growth for the closed packet SDK owner.
//!
//! The synchronous compact exchange begins idle and retains at most one request
//! in each direction and one response being published. Containment executes
//! once and copies the two request maps into the same known retained supervisor.
//! Original fixed banks, parsed frames, typed bodies and codec work are separate.

use super::native5_codec::Native5CodecOwner;
use super::*;
use crate::retained_metadata::{
    requested_storage::tree_storage_data,
    serialization_storage::{
        OriginalJsonValueStorageExtentData,
        original_json_value_clone_storage_forest_counter_scratch_data,
        original_json_value_clone_storage_forest_data,
        original_json_value_storage_extent_counter_scratch_data,
        original_json_value_storage_extent_data,
    },
};
use std::mem::{align_of, size_of};

impl<S: ProviderStream> Connection<S> {
    /// Prices only the actual installed Controller codec's future decode work.
    ///
    /// # Errors
    /// Refuses changed verifier identity, a noncontroller codec, foreign or
    /// fenced ownership, revoked registration, or the independent restriction.
    pub(crate) fn original_packet_runtime_codec_storage_data(
        &self,
        maximum: usize,
    ) -> Result<[usize; 2], ProviderError> {
        self.authenticate_native5_source_codec()?;
        if self.role != EndpointRole::Controller
            || !matches!(
                self.native5_codec.as_deref(),
                Some(Native5CodecOwner::ControllerPacket(_))
            )
        {
            return Err(ProviderError::Correlation(
                "packet runtime requires the original Controller codec",
            ));
        }
        let frame = usize::try_from(self.authority.limits().frame_bytes.get())
            .map_err(|_| ProviderError::ResourceExhausted("packet runtime codec frame"))?;
        let mut row = crate::reference_packet::runtime_codec_storage::storage_data(frame, maximum)?;
        row[1] = row[1]
            .checked_add(Self::packet_runtime_codec_wrapper_counter_scratch_data())
            .ok_or(ProviderError::ResourceExhausted(
                "packet runtime codec counter",
            ))?;
        if row[0]
            .checked_add(row[1])
            .is_none_or(|total| total > maximum)
        {
            return Err(ProviderError::ResourceExhausted("packet runtime codec row"));
        }
        Ok(row)
    }

    pub(crate) fn original_packet_runtime_codec_counter_scratch_data() -> usize {
        crate::reference_packet::runtime_codec_storage::counter_scratch_data()
            + Self::packet_runtime_codec_wrapper_counter_scratch_data()
    }

    fn packet_runtime_codec_wrapper_counter_scratch_data() -> usize {
        use std::mem::size_of;

        size_of::<&Self>()
            + size_of::<&Native5CodecOwner>()
            + size_of::<Option<&Native5CodecOwner>>()
            + size_of::<Rc<dyn BodySchemaVerifier>>()
            + size_of::<[usize; 2]>()
            + size_of::<Result<[usize; 2], ProviderError>>()
            + size_of::<Result<usize, std::num::TryFromIntError>>()
            + 2 * size_of::<Result<usize, ProviderError>>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<Option<usize>>()
            + 3 * size_of::<usize>()
    }

    /// Quotes future correlation and one containment incident as DATA.
    ///
    /// Returns `[retained/reporting growth, transient backing, quote controls]`.
    /// Every term is additional to the current original-owner census. This prices the
    /// closed packet call path only; the caller must prevent generic Connection
    /// access after handoff. It does not grant a Source action or price the full
    /// SDK, metadata records, machine stack, transport or allocator overhead.
    /// The row covers a Connection census whose widest new map entry is
    /// `(Id, Envelope)`. An enclosing Source that combines wider maps must
    /// independently fund its additional conservative reporting growth.
    ///
    /// # Errors
    /// Refuses another installed codec, a non-idle or revoked connection,
    /// another supervisor, nonempty incident history, unsupported layouts,
    /// overflow or a complete row above the independent restriction.
    pub(crate) fn original_packet_runtime_connection_storage_data(
        &self,
        owner: &OriginalRetainedSupervisor,
        maximum: usize,
    ) -> Result<[usize; 3], ProviderError> {
        self.authenticate_native5_source_codec()?;
        if self.role != EndpointRole::Controller
            || !matches!(
                self.native5_codec.as_deref(),
                Some(native5_codec::Native5CodecOwner::ControllerPacket(_))
            )
        {
            return Err(refused());
        }
        self.authenticate_compact_exchange_idle_data()?;
        owner.authenticate(self)?;
        if !owner.is_empty_data()? {
            return Err(refused());
        }

        let frame =
            usize::try_from(self.authority.limits().frame_bytes.get()).map_err(|_| refused())?;
        let mut row = connection_storage_data(frame)?;
        row[2] = Self::original_packet_runtime_connection_counter_scratch_data();
        if sum(&row)? > maximum {
            return Err(refused());
        }
        Ok(row)
    }

    pub(crate) fn original_packet_runtime_connection_counter_scratch_data() -> usize {
        original_json_value_clone_storage_forest_counter_scratch_data()
            + original_json_value_storage_extent_counter_scratch_data()
            + size_of::<OriginalJsonValueStorageExtentData>()
            + size_of::<Result<OriginalJsonValueStorageExtentData, ProviderError>>()
            + OriginalRetainedSupervisor::metadata_counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<Rc<dyn BodySchemaVerifier>>()
            + size_of::<&Native5CodecOwner>()
            + size_of::<Option<&Native5CodecOwner>>()
            + size_of::<&OriginalRetainedSupervisor>()
            + size_of::<[usize; 3]>()
            + size_of::<[usize; 4]>()
            + size_of::<std::slice::Iter<'static, usize>>()
            + size_of::<std::alloc::Layout>()
            + size_of::<Result<std::alloc::Layout, std::alloc::LayoutError>>()
            + size_of::<Result<[usize; 3], ProviderError>>()
            + size_of::<Result<bool, ProviderError>>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<Result<usize, std::num::TryFromIntError>>()
            + 4 * size_of::<Result<usize, ProviderError>>()
            + 4 * size_of::<Option<usize>>()
            + 24 * size_of::<usize>()
    }
}

fn connection_storage_data(frame: usize) -> Result<[usize; 3], ProviderError> {
    if frame == 0 || frame > 65_536 || size_of::<usize>() != 8 {
        return Err(refused());
    }

    // Both insertion sites clone only after a whole frame satisfies F: outgoing
    // send_compact encodes and parses first; incoming receive parses first.
    // Even a legacy provider reply larger than F cannot enter these maps.
    let clone = original_json_value_clone_storage_forest_data(frame, 1)?;
    let maps = tree_storage_data(
        3,
        3,
        size_of::<Id>() + size_of::<Envelope>(),
        align_of::<(Id, Envelope)>(),
    )?;
    let correlations = sum(&[
        maps,
        multiply(3, clone)?,
        multiply(3, crucible_node_format::MAX_ID_BYTES)?,
    ])?;

    // contain clones only pending and received requests, not writing responses.
    // Each collect can own a four-slot minimum even though its map has one row.
    // The incident itself moves into the already allocated bank or pending slot;
    // its inline header is therefore not a new heap allocation here.
    let incident = sum(&[
        multiply(8, size_of::<Envelope>())?,
        multiply(2, clone)?,
        multiply(3, crucible_node_format::MAX_ID_BYTES)?,
    ])?;
    // Metadata facts deliberately aggregate maps using the largest observed K/V
    // layout. In a Connection census the correlation entry widens every literal
    // map, including empty roots. Independently fund that conservative report;
    // the real clone allocations above are not spent again as reporting credit.
    // Each of the five complete clones has its own lexical rounding allowance.
    let extent = original_json_value_storage_extent_data(frame)?;
    let reporting_growth = tree_storage_data(
        multiply(5, extent.maximum_value_nodes)?,
        multiply(5, extent.maximum_object_members)?,
        size_of::<Id>() + size_of::<Envelope>(),
        align_of::<(Id, Envelope)>(),
    )?;
    let retained = sum(&[correlations, incident, reporting_growth])?;

    // These are fresh clones, not growing parser Vecs. Their final backing is
    // already charged independently for all five populations above. The BTree
    // supplier includes insertion nodes; collect's entire bank fits its own
    // separately charged four-slot reservation without a second growth bank.
    Ok([retained, 0, 0])
}

fn sum(values: &[usize]) -> Result<usize, ProviderError> {
    values.iter().try_fold(0usize, |total, value| {
        total.checked_add(*value).ok_or_else(refused)
    })
}

fn multiply(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_mul(right).ok_or_else(refused)
}

fn refused() -> ProviderError {
    ProviderError::ResourceExhausted("packet runtime correlation and incident backing")
}

#[cfg(test)]
mod tests {
    use super::native5_codec::Native5CodecOwner;
    use super::*;
    use crate::retained_metadata::{
        MetadataObserver, requested_storage::requested_metadata_backing_storage_data,
    };
    use crucible_node_format::U64;
    use serde_json::json;
    use std::collections::BTreeSet;

    #[test]
    fn actual_three_correlation_maps_and_both_incident_clones_fit() {
        for population in [0, 1, 4, 31, 512] {
            let mut outgoing = crate::envelope::tests::request();
            outgoing.sequence = U64::new(2);
            outgoing.extensions.clear();
            outgoing.body.insert(
                "literal".into(),
                json!(vec![json!({"": [0, "text"]}); population]),
            );
            let frame = serde_json::to_vec(&outgoing).unwrap().len();
            let mut guard = CorrelationGuard::new(
                outgoing.session_id.0.clone().unwrap(),
                outgoing.incarnation_id.0.clone().unwrap(),
                1,
                BTreeSet::new(),
            )
            .unwrap();
            let mut initial = MetadataObserver::new();
            guard.observe_owned_metadata(&mut initial).unwrap();
            let before = requested_metadata_backing_storage_data(&initial.finish()).unwrap();

            guard.register_outgoing(outgoing.clone()).unwrap();
            guard.receive(&outgoing).unwrap();
            let mut response = outgoing.clone();
            response.message = MessageKind::Response;
            response.sequence = U64::new(3);
            guard.register_outgoing(response).unwrap();

            let incident = ConnectionIncident {
                session: outgoing.session_id.0.clone().unwrap(),
                incarnation: outgoing.incarnation_id.0.clone().unwrap(),
                connection: Id::new("original-connection").unwrap(),
                failure: ConnectionFailure::Write,
                transport_fenced: true,
                outgoing: guard.pending_requests().cloned().collect(),
                incoming: guard.incoming_requests().cloned().collect(),
            };
            let mut observer = MetadataObserver::new();
            guard.observe_owned_metadata(&mut observer).unwrap();
            observer.observe(&incident.session).unwrap();
            observer.observe(&incident.incarnation).unwrap();
            observer.observe(&incident.connection).unwrap();
            observer.observe(&incident.outgoing).unwrap();
            observer.observe(&incident.incoming).unwrap();
            let actual = requested_metadata_backing_storage_data(&observer.finish()).unwrap();
            let quoted = connection_storage_data(frame).unwrap();

            assert_eq!(incident.outgoing.len(), 1);
            assert_eq!(incident.incoming.len(), 1);
            assert!(
                actual - before <= quoted[0],
                "population {population}: actual {}, quoted {}",
                actual - before,
                quoted[0]
            );
            assert_eq!(quoted[1], 0);
        }
    }

    #[test]
    fn unsupported_connection_frame_geometry_refuses() {
        for frame in [0, 65_537, usize::MAX] {
            assert!(connection_storage_data(frame).is_err());
        }
    }
}
