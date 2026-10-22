//! Scopes one actual bootstrap DATA body census to its lexical populations.
//!
//! This profile covers one owned DTO, including expanded Value leaves. It
//! borrows no SDK response-forest work allowance and grants no parser admission.

use super::*;

/// Retains the traversal populations of one unchanged original body.
#[derive(Clone, Copy)]
pub(crate) struct BootstrapBodyMetadataProfileData {
    depth: usize,
    work: usize,
}

impl BootstrapBodyMetadataProfileData {
    /// Derives the real lexical/reset populations without allocating a DTO.
    ///
    /// # Errors
    /// Refuses checked overflow of the supplied actual lexical/reset populations.
    pub(crate) fn from_populations_data(
        raw_nodes: usize,
        raw_members: usize,
        reset: &JsonValueReparseConstructionData,
    ) -> Result<Self, ProviderError> {
        let (extra_nodes, extra_members, _) = reset.expanded_json_extents_data();
        let nodes = raw_nodes.checked_add(extra_nodes).ok_or_else(overflow)?;
        let members = raw_members
            .checked_add(extra_members)
            .ok_or_else(overflow)?;
        let depth = reset
            .maximum_parser_layers_data()
            .checked_mul(128)
            .and_then(|layers| layers.checked_add(65))
            .ok_or_else(overflow)?;
        // Value/String/Vec and Option wrappers consume at most four visits per
        // syntax node plus a map-key visit. Missing optional fields still have
        // real typed headers: Launch21, storage7, program2, selected5, boot7,
        // SourceBinding5, SourceDeclaration3 and ContentRef/HashRef6.
        let fixed_fields = 21 + 7 + 2 + 5 + 7 + 5 + 3 + 6;
        let work = nodes
            .checked_mul(4)
            .and_then(|n| n.checked_add(members))
            .and_then(|n| n.checked_add(fixed_fields))
            .ok_or_else(overflow)?;
        Ok(Self { depth, work })
    }

    /// Bounds one strict Value tree without DTO wrappers or RawValue expansion.
    ///
    /// A Value needs at most two visits per syntax value/key plus one map-key
    /// visit. Strict parsing admits at most 64 containers and a terminal scalar.
    /// Callers supply separately established lexical populations and admit this
    /// walk; the profile itself grants no parser or constructor allowance.
    ///
    /// # Errors
    /// Refuses an empty population or checked work overflow.
    pub(crate) fn from_strict_value_populations_data(
        nodes: usize,
        members: usize,
    ) -> Result<Self, ProviderError> {
        if nodes == 0 || members > nodes {
            return Err(overflow());
        }
        let work = nodes
            .checked_mul(2)
            .and_then(|work| work.checked_add(members))
            .ok_or_else(overflow)?;
        Ok(Self { depth: 65, work })
    }

    /// Counts the recursive Value census frames for this actual population.
    ///
    /// # Errors
    /// Refuses checked layout overflow.
    pub(crate) fn walk_scratch_data(self) -> Result<usize, ProviderError> {
        self.depth
            .checked_mul(
                MetadataObserver::native_import18_json_metadata_frame_counter_scratch_data(),
            )
            .and_then(|n| n.checked_add(bootstrap_body_metadata_counter_scratch_data()))
            .ok_or_else(overflow)
    }
}

impl MetadataObserver<'_> {
    /// Walks one actual bootstrap DTO without renewing ordinary observer work.
    ///
    /// # Errors
    /// Refuses population overflow/exhaustion or the original field walk. Both
    /// outcomes restore the previous scope and retain every charged visit.
    pub(crate) fn with_bootstrap_body_profile_data(
        &mut self,
        profile: BootstrapBodyMetadataProfileData,
        observe: impl FnOnce(&mut Self) -> Result<(), ProviderError>,
    ) -> Result<(), ProviderError> {
        self.scoped_work.announced = self
            .scoped_work
            .announced
            .checked_add(profile.work)
            .ok_or_else(overflow)?;
        let previous = PreviousProfile {
            depth: self.json_depth,
            limit: self.json_depth_limit,
            active: self.scoped_work.active,
        };
        self.json_depth = 0;
        self.json_depth_limit = profile.depth;
        self.scoped_work.active = Some(ActiveWork {
            counts: WorkCounts::default(),
            maximum: profile.work,
        });

        let result = observe(self);

        self.json_depth = previous.depth;
        self.json_depth_limit = previous.limit;
        self.scoped_work.active = previous.active;
        result
    }

    /// Observes the actual launch in this same constructor-specific scope.
    ///
    /// # Errors
    /// Refuses checked population or capacity overflow.
    pub(crate) fn observe_bootstrap_launch_data(
        &mut self,
        launch: &crate::reference_packet::service::PacketNative5SourceLaunch,
    ) -> Result<(), ProviderError> {
        crate::retained_metadata::complete_source::observe_native_launch_into(launch, self)
    }
}

/// Names actual profile construction, scope and borrowed observation controls.
pub(crate) fn bootstrap_body_metadata_counter_scratch_data() -> usize {
    size_of::<BootstrapBodyMetadataProfileData>() * 2
        + size_of::<Result<BootstrapBodyMetadataProfileData, ProviderError>>()
        + size_of::<PreviousProfile>()
        + size_of::<ActiveWork>()
        + size_of::<Option<ActiveWork>>()
        + size_of::<MetadataObserver<'static>>()
        + size_of::<RetainedProtocolMetadataFacts>()
        + size_of::<Result<RetainedProtocolMetadataFacts, ProviderError>>()
        + size_of::<&[u8]>()
        + size_of::<
            crate::retained_metadata::serialization_storage::OriginalJsonValueStorageExtentData,
        >()
        + size_of::<crate::protocol_snapshot::raw_value_reparse::JsonValueReparseConstructionData>()
        + size_of::<(usize, usize, usize)>()
        + size_of::<[usize; 8]>()
        + size_of::<Result<(), ProviderError>>()
        + crate::retained_metadata::retained_native_launch_counter_scratch_data()
}
