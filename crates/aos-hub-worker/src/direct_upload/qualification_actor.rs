//! Deterministic actor slots for isolated qualification originals only.
//!
//! The existing journal digest fixes each run/object identity. UUID layout bits
//! make that identity satisfy the shared actor contract; they grant no database
//! actor provenance, production admission or physical permission.

use anyhow::{Context as _, Result};
use aos_hub_core::direct_upload::{DirectActorKind, DirectActorSlot, WireInteger};
use uuid::{Builder, Variant, Version};

/// Derives the same qualification-only slot for an immutable run/object pair.
///
/// # Errors
/// Returns an error if the existing journal commitment cannot be encoded or
/// converted to its fixed sixteen-byte identity input.
pub(super) fn slot(run_id: &str, object_id: &str) -> Result<DirectActorSlot> {
    let digest = hex::decode(super::journal::digest(&(
        run_id,
        object_id,
        "fixture-actor",
    ))?)?;
    let bytes = digest
        .get(..16)
        .context("qualification actor digest is incomplete")?
        .try_into()
        .context("qualification actor digest length differs")?;
    Ok(actor_from_digest(bytes))
}

fn actor_from_digest(bytes: [u8; 16]) -> DirectActorSlot {
    let incarnation = Builder::from_bytes(bytes)
        .with_version(Version::Random)
        .with_variant(Variant::RFC4122)
        .into_uuid();

    DirectActorSlot {
        kind: DirectActorKind::ServiceAccount,
        numeric_id: WireInteger::new(1),
        incarnation: incarnation.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_digest_layouts_create_valid_actors_without_weakening_old_checks() {
        for version in 0..16 {
            for variant in 0..4 {
                let mut bytes = [0x35; 16];
                bytes[6] = (version << 4) | 0x05;
                bytes[8] = (variant << 6) | 0x35;
                let old = DirectActorSlot {
                    kind: DirectActorKind::ServiceAccount,
                    numeric_id: WireInteger::new(1),
                    incarnation: uuid::Uuid::from_bytes(bytes).to_string(),
                };
                let already_valid = version == 4 && variant == 2;
                assert_eq!(old.validate().is_ok(), already_valid);

                let actor = actor_from_digest(bytes);
                actor.validate().unwrap();
                actor.principal_id("qualification-deployment").unwrap();
                assert_eq!(actor, actor_from_digest(bytes));
                if already_valid {
                    assert_eq!(actor, old);
                }
            }
        }
    }

    #[test]
    fn run_and_object_identity_preserve_the_original_journal_derivation() {
        let run = "11".repeat(32);
        let object = "22".repeat(32);
        let bytes = hex::decode(
            super::super::journal::digest(&(run.as_str(), object.as_str(), "fixture-actor"))
                .unwrap(),
        )
        .unwrap();
        let actor = slot(&run, &object).unwrap();

        assert_eq!(actor, actor_from_digest(bytes[..16].try_into().unwrap()));
        assert_eq!(actor, slot(&run, &object).unwrap());
        assert_ne!(actor, slot(&"33".repeat(32), &object).unwrap());
        assert_ne!(actor, slot(&run, &"44".repeat(32)).unwrap());
        actor.principal_id("qualification-deployment").unwrap();
    }
}
