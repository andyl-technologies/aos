//! Issues fresh private original capabilities without public report identities.

use std::{fs::File, io::Read};

use crucible_node_contract::{Bytes, Extensions, Id, LiveAuthority, U64};

use super::super::super::{NodeObservedError, refused};
use super::super::{
    TypedReaderFixtureAudit, TypedReaderPrivateAuthorization, TypedReaderProgramme,
};

fn entropy<const N: usize>() -> Result<[u8; N], NodeObservedError> {
    let mut bytes = [0; N];
    File::open("/dev/urandom")
        .and_then(|mut original| original.read_exact(&mut bytes))
        .map_err(|_| refused("typed invocation private entropy unavailable"))?;
    Ok(bytes)
}

pub(super) fn fresh_run() -> Result<Id, NodeObservedError> {
    // Public uniqueness uses a separate draw; it never derives from a private
    // admission capability or exposes that capability's hash.
    let bytes = entropy::<16>()?;
    let name = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(Id::new(format!("typed-fixture/{name}"))?)
}

pub(super) fn authorizations(
    programme: &TypedReaderProgramme,
    audit: &TypedReaderFixtureAudit,
    run: &Id,
) -> Result<[TypedReaderPrivateAuthorization; 3], NodeObservedError> {
    let mut originals = Vec::new();
    originals
        .try_reserve_exact(3)
        .map_err(|_| refused("typed invocation private owner credit"))?;
    for peer in &programme.peers {
        let capability = Bytes::new(entropy::<32>()?.to_vec());
        if originals
            .iter()
            .any(|prior: &TypedReaderPrivateAuthorization| prior.capability == capability)
        {
            return Err(refused(
                "typed invocation fresh private capability repeated",
            ));
        }
        originals.push(TypedReaderPrivateAuthorization {
            authority: LiveAuthority {
                schema_version: 1,
                session_id: Id::new(format!("{run}/{}/session", peer.node))?,
                incarnation_id: peer.incarnation.clone(),
                realization_id: Id::new(format!("{run}/{}/realization", peer.node))?,
                activation_id: None,
                world_generation: U64::new(0),
                owner_generation: U64::new(1),
                input_epoch: Id::new(format!("{run}/{}/input", peer.node))?,
                // This initial data reference is replaced by the issuer's real
                // host admission receipt before it constructs any private launch.
                host_receipt: audit.claim().clone(),
                extensions: Extensions::new(),
            },
            capability,
        });
    }
    originals
        .try_into()
        .map_err(|_| refused("typed invocation private owner roster"))
}
