//! Explicit original-source scope for version-two conditional replay requests.
//!
//! The request owns no replay authority. Admission must authenticate every raw
//! signed source body, complete original world/context and current implementation
//! against an installed source-sealed recipe before any readiness or response.

use super::*;
use std::collections::BTreeMap;

const MAXIMUM_REPLAY_ACTORS: usize = 4096;

/// Names the complete original context and raw actor documents of a replay.
///
/// These identities are retained data, not qualification. The owning admission
/// verifier must compare their actual contents and the whole coupled roster.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConditionalReplayScope {
    original_world: CampaignHash,
    original_context: CampaignHash,
    sources: BTreeMap<String, ContentId>,
}

impl ConditionalReplayScope {
    /// Constructs a bounded original-source declaration for later authentication.
    ///
    /// # Errors
    /// Refuses empty/oversized actor rosters, invalid actor names or source
    /// documents whose kind/version is not the raw version-one trace profile.
    pub fn new(
        original_world: CampaignHash,
        original_context: CampaignHash,
        sources: BTreeMap<String, ContentId>,
    ) -> Result<Self, CampaignCodecError> {
        if sources.is_empty() || sources.len() > MAXIMUM_REPLAY_ACTORS {
            return Err(CampaignCodecError::InvalidValue {
                reason: "conditional replay source roster is empty or oversized",
            });
        }
        for (actor, source) in &sources {
            crate::policy::validate_identifier(
                actor,
                "conditional replay actor identifier is invalid",
            )?;
            if source.kind() != ObjectKind::Trace || source.schema_version() != 1 {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "conditional replay source document kind or version differs",
                });
            }
        }
        Ok(Self {
            original_world,
            original_context,
            sources,
        })
    }

    /// Returns the complete authenticated original world identity to verify.
    #[must_use]
    pub const fn original_world(&self) -> CampaignHash {
        self.original_world
    }

    /// Returns the exact original raw context identity to verify.
    #[must_use]
    pub const fn original_context(&self) -> CampaignHash {
        self.original_context
    }

    /// Returns every original actor's retained raw document identity.
    #[must_use]
    pub const fn sources(&self) -> &BTreeMap<String, ContentId> {
        &self.sources
    }
}

impl Canonical for ConditionalReplayScope {
    fn encode(&self, encoder: &mut Encoder) {
        self.original_world.encode(encoder);
        self.original_context.encode(encoder);
        self.sources.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let world = CampaignHash::decode(decoder)?;
        let context = CampaignHash::decode(decoder)?;
        let sources = decoder.map_bounded_by(
            MAXIMUM_REPLAY_ACTORS,
            "conditional replay actor count",
            |decoder| {
                decoder.string_bounded(
                    crate::policy::MAX_IDENTIFIER_BYTES,
                    "conditional replay actor bytes",
                )
            },
            ContentId::decode,
        )?;
        Self::new(world, context, sources)
    }
}
