//! Selects established Source recipes and the independent Delete pending query.
//!
//! Owning contexts stay beside the original raw request. Borrowed view requests
//! contain comparison DATA only; the same real Source original supplies every
//! native admission, signing input and independent transport bookend.

use std::io;
use aos_sandbox_protocol::domain_ledger::delete_root::source_current::*;
use aos_sandbox_protocol::domain_ledger::create_storage_history::source_current::{
    SourceCurrentQueryDataV1, SOURCE_CURRENT_QUERY_BYTES_V1,
    SOURCE_CURRENT_QUERY_MAGIC_V1, SOURCE_CURRENT_REPLY_MAGIC_V1,
};

use aos_sandbox_ledger_replay::replay::phase_records::{
    RootFirstSourceSuccessorIntentV2,
};
use crate::signer::{
    SourceHoldReadbackChallengeV1, SourceProjectGenesisChallengeV3, SourceReadonlyRequestV1, SourceTreeGenesisChallengeV1, SourceTreeGenesisIntentContextV1,
};
use aos_sandbox_ledger_replay::source_signer_data::source_signer_wire::*;
use aos_sandbox_core::ProjectId;

pub(super) enum SourceWireRequestV1 {
    DeletePending { query: [u8; SOURCE_DELETE_CURRENT_QUERY_BYTES_V1], purpose: SourceDeleteCurrentPurposeDataV3 },
    CurrentCut([u8; SOURCE_CURRENT_QUERY_BYTES_V1]),
    Fixed {
        challenge: SourceHoldReadbackChallengeV1,
        project: ProjectId,
        mode: SourceSignerRequestModeV1,
    },
    StrictGenesis {
        challenge: SourceTreeGenesisChallengeV1,
        project: Option<ProjectId>,
        context: Option<SourceTreeGenesisIntentContextV1>,
        resource: bool,
    },
    ProjectGenesis {
        challenge: SourceProjectGenesisChallengeV3,
        context: SourceTreeGenesisIntentContextV1,
        resource: bool,
    },
    Successor {
        nonce: [u8; 16],
        context: RootFirstSourceSuccessorIntentV2,
        recipe: SourceSuccessorRequestRecipe,
    },
}

impl SourceWireRequestV1 {
    pub(super) fn width(selector: &[u8; 8]) -> io::Result<usize> {
        match selector {
            value if SourceDeleteCurrentPurposeDataV3::from_query_magic_v4(value).is_some() => Ok(SOURCE_DELETE_CURRENT_QUERY_BYTES_V1),
            value if value == SOURCE_CURRENT_QUERY_MAGIC_V1 => Ok(SOURCE_CURRENT_QUERY_BYTES_V1),
            value if value == REQUEST_MAGIC || value == REQUEST_NAMES_MAGIC
                || value == REQUEST_PROJECT_MAGIC || value == REQUEST_RETIREMENT_MAGIC
                || value == REQUEST_RESERVATION_MAGIC || value == REQUEST_COMPLETED_MAGIC => Ok(REQUEST_BYTES),
            value if value == REQUEST_GENESIS_MAGIC || value == REQUEST_PROJECT_GENESIS_MAGIC_V3 => Ok(REQUEST_GENESIS_BYTES),
            value if value == REQUEST_PROJECT_RESOURCE_GENESIS_MAGIC_V4
                || value == REQUEST_RESOURCE_GENESIS_MAGIC => Ok(REQUEST_PROJECT_RESOURCE_GENESIS_BYTES_V4),
            value if value == REQUEST_FIRST_SUCCESSOR_MAGIC
                || value == REQUEST_PROJECT_CONTINUATION_MAGIC => Ok(REQUEST_FIRST_SUCCESSOR_BYTES),
            value if value == REQUEST_RESOURCE_SUCCESSOR_MAGIC_V4
                || value == REQUEST_RESOURCE_CONTINUATION_MAGIC_V5 => Ok(REQUEST_RESOURCE_SUCCESSOR_BYTES),
            // Source07 is absent. Source16 remains unavailable before any key
            // borrow, Source view opening or typed signing operation.
            _ => Err(invalid_data("unsupported selected Source request")),
        }
    }

    pub(super) fn decode(bytes: &[u8]) -> io::Result<Self> {
        let selector: &[u8; 8] = bytes.get(..8).and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| invalid_data("short selected Source request"))?;
        if bytes.len() != Self::width(selector)? {
            return Err(invalid_data("inexact selected Source request width"));
        }
        if let Some(purpose) = SourceDeleteCurrentPurposeDataV3::from_query_magic_v4(selector) {
            SourceDeleteCurrentQueryDataV1::decode_for_purpose_v3(bytes, purpose).map_err(io::Error::other)?;
            return Ok(Self::DeletePending { query: bytes.try_into()
                .map_err(|_| invalid_data("invalid Delete Source query width"))?, purpose });
        }
        if selector == SOURCE_CURRENT_QUERY_MAGIC_V1 {
            SourceCurrentQueryDataV1::decode(bytes).map_err(io::Error::other)?;
            return Ok(Self::CurrentCut(bytes.try_into()
                .map_err(|_| invalid_data("invalid current Source query width"))?));
        }
        if selector == REQUEST_GENESIS_MAGIC || selector == REQUEST_RESOURCE_GENESIS_MAGIC {
            let (challenge, project, context) = decode_genesis_request(bytes)?;
            return Ok(Self::StrictGenesis {
                challenge, project, context, resource: selector == REQUEST_RESOURCE_GENESIS_MAGIC,
            });
        }
        if selector == REQUEST_PROJECT_GENESIS_MAGIC_V3 || selector == REQUEST_PROJECT_RESOURCE_GENESIS_MAGIC_V4 {
            let (challenge, context) = decode_project_genesis_request_v3(bytes)?;
            return Ok(Self::ProjectGenesis {
                challenge, context, resource: selector == REQUEST_PROJECT_RESOURCE_GENESIS_MAGIC_V4,
            });
        }
        let recipe = if selector == REQUEST_FIRST_SUCCESSOR_MAGIC {
            Some(SourceSuccessorRequestRecipe::SingleProjectV2)
        } else if selector == REQUEST_PROJECT_CONTINUATION_MAGIC {
            Some(SourceSuccessorRequestRecipe::MixedProjectsV3)
        } else if selector == REQUEST_RESOURCE_SUCCESSOR_MAGIC_V4 {
            Some(SourceSuccessorRequestRecipe::ResourceSingleProjectV4)
        } else if selector == REQUEST_RESOURCE_CONTINUATION_MAGIC_V5 {
            Some(SourceSuccessorRequestRecipe::ResourceMixedProjectsV5)
        } else {
            None
        };
        if let Some(recipe) = recipe {
            let (nonce, context) = if recipe.resource() {
                let nonce = bytes[8..24].try_into()
                    .map_err(|_| invalid_data("invalid resource successor nonce"))?;
                let context = RootFirstSourceSuccessorIntentV2::decode(&bytes[REQUEST_BYTES..]).map_err(aos_sandbox_ledger_replay::source_signer_data::SourceSignerGenesisDataErrorV1::from)
                    .map_err(io::Error::other)?;
                let mixed = matches!(recipe, SourceSuccessorRequestRecipe::ResourceMixedProjectsV5);
                if encode_resource_successor_request(nonce, &context, mixed)?.as_slice() != bytes {
                    return Err(invalid_data("noncanonical resource successor request"));
                }
                (nonce, context)
            } else {
                let request = bytes.try_into()
                    .map_err(|_| invalid_data("invalid legacy successor width"))?;
                decode_source_successor_request(request, recipe)?
            };
            return Ok(Self::Successor { nonce, context, recipe });
        }
        let fixed = bytes.try_into().map_err(|_| invalid_data("invalid fixed Source width"))?;
        let (challenge, project, mode) = decode_request_mode(fixed)?;
        Ok(Self::Fixed { challenge, project, mode })
    }

    pub(super) fn request(&self) -> SourceReadonlyRequestV1<'_> {
        match self {
            Self::CurrentCut(query) => SourceReadonlyRequestV1::CurrentCut(query),
            Self::DeletePending { query, purpose } => SourceReadonlyRequestV1::DeletePending { query, purpose: *purpose },
            Self::Fixed { challenge, project, mode } => match mode {
                SourceSignerRequestModeV1::Held => SourceReadonlyRequestV1::Held { project: *project, challenge: *challenge },
                SourceSignerRequestModeV1::HeldNames => SourceReadonlyRequestV1::HeldNames { project: *project, challenge: *challenge },
                SourceSignerRequestModeV1::ProjectAdmission => SourceReadonlyRequestV1::Admission { project: *project, challenge: *challenge },
                SourceSignerRequestModeV1::ProjectRetirement => SourceReadonlyRequestV1::Retirement { project: *project, challenge: *challenge },
                SourceSignerRequestModeV1::ProjectReservation => SourceReadonlyRequestV1::Reservation {
                    client_nonce: challenge.nonce(), project: *project, expected_digest: challenge.cut(),
                },
                SourceSignerRequestModeV1::ProjectCompletedTerminal => SourceReadonlyRequestV1::Completed { challenge: *challenge },
            },
            Self::StrictGenesis { challenge, project, context, .. } => SourceReadonlyRequestV1::StrictGenesis {
                project: *project, challenge: *challenge, context: context.as_ref(),
            },
            Self::ProjectGenesis { challenge, context, .. } => SourceReadonlyRequestV1::ProjectGenesis {
                challenge: *challenge, context,
            },
            Self::Successor { nonce, context, recipe } => match recipe {
                SourceSuccessorRequestRecipe::SingleProjectV2 => SourceReadonlyRequestV1::FirstSuccessor { nonce: *nonce, context },
                SourceSuccessorRequestRecipe::MixedProjectsV3 => SourceReadonlyRequestV1::Continuation { nonce: *nonce, context },
                SourceSuccessorRequestRecipe::ResourceSingleProjectV4 => SourceReadonlyRequestV1::ResourceSingle { nonce: *nonce, context },
                SourceSuccessorRequestRecipe::ResourceMixedProjectsV5 => SourceReadonlyRequestV1::ResourceMixed { nonce: *nonce, context },
            },
        }
    }

    pub(super) fn reply_magic(&self) -> &'static [u8; 8] {
        match self {
            Self::CurrentCut(_) => SOURCE_CURRENT_REPLY_MAGIC_V1,
            Self::DeletePending { purpose, .. } => purpose.reply_magic_v3(),
            Self::Fixed { mode, .. } => match mode {
                SourceSignerRequestModeV1::Held => REPLY_MAGIC,
                SourceSignerRequestModeV1::HeldNames => REPLY_NAMES_MAGIC,
                SourceSignerRequestModeV1::ProjectAdmission => REPLY_PROJECT_MAGIC,
                SourceSignerRequestModeV1::ProjectRetirement => REPLY_RETIREMENT_MAGIC,
                SourceSignerRequestModeV1::ProjectReservation => REPLY_RESERVATION_MAGIC,
                SourceSignerRequestModeV1::ProjectCompletedTerminal => REPLY_COMPLETED_MAGIC,
            },
            Self::StrictGenesis { resource, .. } => if *resource { REPLY_RESOURCE_GENESIS_MAGIC } else { REPLY_GENESIS_MAGIC },
            Self::ProjectGenesis { resource, .. } => if *resource { REPLY_PROJECT_RESOURCE_GENESIS_MAGIC_V4 } else { REPLY_PROJECT_GENESIS_MAGIC_V3 },
            Self::Successor { recipe, .. } => recipe.reply_magic(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_core::ObjectDigest;

    #[test]
    fn fixed_recipes_use_the_existing_roundtrip_and_exact_reply_discriminators() {
        let challenge = SourceHoldReadbackChallengeV1::new([1; 16], ObjectDigest::from_bytes([2; 32])).unwrap();
        let project = ProjectId::from_bytes([3; 16]);
        for (request_magic, reply_magic) in [
            (REQUEST_MAGIC, REPLY_MAGIC), (REQUEST_NAMES_MAGIC, REPLY_NAMES_MAGIC),
            (REQUEST_PROJECT_MAGIC, REPLY_PROJECT_MAGIC), (REQUEST_RETIREMENT_MAGIC, REPLY_RETIREMENT_MAGIC),
            (REQUEST_RESERVATION_MAGIC, REPLY_RESERVATION_MAGIC), (REQUEST_COMPLETED_MAGIC, REPLY_COMPLETED_MAGIC),
        ] {
            let mut bytes = encode_request(challenge, project);
            bytes[..8].copy_from_slice(request_magic);

            let decoded = SourceWireRequestV1::decode(&bytes).unwrap();

            assert_eq!(decoded.reply_magic(), reply_magic);
            assert!(SourceWireRequestV1::decode(&bytes[..bytes.len() - 1]).is_err());
            let mut trailing = bytes.to_vec();
            trailing.push(0);
            assert!(SourceWireRequestV1::decode(&trailing).is_err());
        }
    }

    #[test]
    fn unsupported_selectors_and_malformed_expanded_contexts_never_select_a_view_recipe() {
        for selector in [b"AOSSSR07", REQUEST_CURRENT_NIX_MAGIC_V1, b"AOSSSR99"] {
            assert!(SourceWireRequestV1::width(selector).is_err());
        }
        let mut resource = [0; REQUEST_RESOURCE_SUCCESSOR_BYTES];
        resource[..8].copy_from_slice(REQUEST_RESOURCE_SUCCESSOR_MAGIC_V4);
        assert!(SourceWireRequestV1::decode(&resource).is_err());

        let challenge = SourceTreeGenesisChallengeV1::new([4; 16], None).unwrap();
        let legacy = encode_genesis_request(challenge, None, None).unwrap();
        let decoded = SourceWireRequestV1::decode(&legacy).unwrap();

        assert_eq!(decoded.reply_magic(), REPLY_GENESIS_MAGIC);
        assert!(matches!(decoded.request(), SourceReadonlyRequestV1::StrictGenesis {
            project: None, context: None, ..
        }));
    }

    #[test]
    fn current_cut_uses_its_own_exact_fixed_contract_without_enabling_seven_or_sixteen() {
        assert_eq!(SourceWireRequestV1::width(SOURCE_CURRENT_QUERY_MAGIC_V1).unwrap(), 1016);
        let mut malformed = [0; SOURCE_CURRENT_QUERY_BYTES_V1];
        malformed[..8].copy_from_slice(SOURCE_CURRENT_QUERY_MAGIC_V1);
        assert!(SourceWireRequestV1::decode(&malformed).is_err());
        assert!(SourceWireRequestV1::width(b"AOSSSR07").is_err());
        assert!(SourceWireRequestV1::width(REQUEST_CURRENT_NIX_MAGIC_V1).is_err());
        assert_eq!(SourceWireRequestV1::width(REQUEST_MAGIC).unwrap(), REQUEST_BYTES);
    }


    #[test]
    fn delete_pending_selects_only_its_new_canonical_query_and_reply() {
        let query = SourceDeleteCurrentQueryDataV1 {
            nonce: [1; 16], project: [2; 16], operation: [3; 16], batch: [4; 32],
            boot: [5; 16], started: 100, cutoff: 1_000,
        }.encode().unwrap();
        assert_eq!(SourceWireRequestV1::width(SOURCE_DELETE_CURRENT_QUERY_MAGIC_V1).unwrap(), 128);
        let decoded = SourceWireRequestV1::decode(&query).unwrap();
        assert!(matches!(decoded.request(), SourceReadonlyRequestV1::DeletePending { .. }));
        assert_eq!(decoded.reply_magic(), SOURCE_DELETE_CURRENT_REPLY_MAGIC_V1);

        let mut malformed = query;
        malformed[15] = 1;
        assert!(SourceWireRequestV1::decode(&malformed).is_err());
        assert!(SourceWireRequestV1::decode(&query[..127]).is_err());
    }

}
