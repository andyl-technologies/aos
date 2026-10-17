//! Consumes the fixed workflow's pinned SQLite initialization Source case.
//!
//! The generated object binds the installed library, its exact configuration,
//! target geometry, allocator Source/configuration and compiler stack records.
//! Runtime checks confirm the authored main-stack and page case. The parent
//! retains physical prebirth Source financing; this token creates no account,
//! native launch permission or entitlement from a scalar bound.

use crucible::owned_decode::json_profiles::bootstrap::{Request, Target};

use std::fs::File;
use std::io::Read;

use crucible::owned_decode::from_json_slice_closed;
use crucible_cas::content_store::StoreError;
use crucible_linux_resource::measurement_origin::MeasurementOriginError;

use super::{OriginalActorSqliteBootstrapError, OriginalActorSqliteOwner, verify};
use crucible_qemu::{OriginalActorAccountError, OriginalActorDecodeOwner};
use crucible_qemu::{OriginalGuestServiceHandle, OriginalGuestServiceOwner};

const ADDED_BACKING_BYTES: u64 = 2 << 20;

/// Keeps one consumed, same-actor native-bootstrap qualification.
///
/// Only the genuine owner can issue this value after authenticating its fixed
/// workflow object under the same original decoder. It cannot be cloned,
/// constructed from an amount, or substituted for the parent's physical
/// prebirth financing. Native installation rechecks the same actor and case.
#[must_use = "consume the qualification in the same owner's native installation"]
pub struct OriginalActorSqliteBootstrap {
    actor: OriginalGuestServiceHandle,
}

trait BootstrapTargetValidation {
    fn validate(&self) -> Result<(), MeasurementOriginError>;
}

impl BootstrapTargetValidation for Target<'_> {
    fn validate(&self) -> Result<(), MeasurementOriginError> {
        let backing = &self.conditional_main_arena_backing;
        let expected = [
            Request {
                request_bytes: 40,
                chunk_bytes: 48,
                ordinary_growth_upper_bytes: 139_436,
                additional_backing_upper_bytes: 1 << 20,
            },
            Request {
                request_bytes: 16,
                chunk_bytes: 32,
                ordinary_growth_upper_bytes: 139_404,
                additional_backing_upper_bytes: 1 << 20,
            },
        ];
        if self.schema != "crucible.sqlite-bootstrap-target.v1"
            || self.source_record_sha256
                != "c624344bd2f5c017c4942755154a8676af24319496b293448e1226fe8e2a22e8"
            || self.geometry_record_sha256
                != "0c8dd32b50304e38da6061cd429fb4c251876b5f499531e11f4a31d4a683c938"
            || self.linked_record_sha256
                != "ecd43b143aa9da0c3740b8757a57023f681d25bef371ca53a7157a4e8da2084c"
            || self.glibc_build_record_sha256
                != "607f6f67f8e26a95ec2c086fc4388a7496140ff2f9abfb9e53f644c087c7de64"
            || self.sqlite.path
                != "/nix/store/qz9j0s9hc7y53q9wsxffb25hdqiciri8-sqlite-3.53.4/lib/libsqlite3.so"
            || self.sqlite.sha256
                != "355f069f759621753606d4704c2ff5d71d21f8eccb5586480556fbf8d7d53ab0"
            || self.libc.path
                != "/nix/store/7xzbpnlajpi7qsyqbnlsk4vp30z2kzgl-glibc-2.39/lib/libc.so.6"
            || self.libc.sha256
                != "9757a9fffbe6a76f71bbc5ba6153fba36d516fd4d16c6cef11b4122957eaa4a7"
            || self.stack_records[0].name != "sqlite3.su"
            || self.stack_records[0].sha256
                != "a4e262f3e1d5a4f8d5963913af35e0a71ebdc80bef4169f8b7eba33ded5066af"
            || backing.case != "glibc-2.39-x86_64-mainarena-default-4k.v1"
            || backing.additional_backing_upper_bytes != ADDED_BACKING_BYTES
            || backing.requests != expected
        {
            return Err(MeasurementOriginError::Authentication(
                "original SQLite Source/configuration case",
            ));
        }
        // Human-readable predicates remain in the authenticated generated
        // object. They do not act as caller-selectable runtime certification.
        let _documentation = (&self.case_requirements, &backing.required_case);
        Ok(())
    }
}

fn verify_bootstrap_case(actor: &OriginalGuestServiceHandle) -> Result<(), StoreError> {
    verify(actor)?;
    let stack = rustix::process::getrlimit(rustix::process::Resource::Stack);
    let main = rustix::thread::gettid() == rustix::process::getpid();
    let page = rustix::param::page_size();
    let after = verify(actor);
    if stack.current != Some(actor.main_stack_bytes())
        || stack.maximum != Some(actor.main_stack_bytes())
        || actor.main_stack_bytes() < 16_384
        || !main
        || page != 4096
        || actor.bootstrap_bytes() < ADDED_BACKING_BYTES
    {
        return Err(StoreError::Unauthorized);
    }
    after
}

impl OriginalActorSqliteOwner {
    /// Authenticates the pinned bootstrap object under this same actor.
    ///
    /// The actual fixed-path reader pays and retains input/file custody under
    /// `decoder` before this call. The trusted birth installs the authored
    /// stack before exec, clears allocator tuning, and retains original Source
    /// financing. This actor entry invokes qualification before service workers
    /// or any SQLite configuration/initialization operation.
    ///
    /// # Errors
    /// Refuses a different decoder/actor, original expiry, changed object,
    /// unsupported installed Source/configuration, insufficient original
    /// bootstrap purpose, or a different actual stack/main-thread/page case.
    pub fn qualify_bootstrap(
        &self,
        decoder: &OriginalActorDecodeOwner,
        input: &[u8],
    ) -> Result<OriginalActorSqliteBootstrap, OriginalActorSqliteBootstrapError> {
        let actor = &self.actor;
        self.accounts.verify_decoder(decoder)?;
        actor
            .original_check()
            .map_err(OriginalActorAccountError::Supervision)?;
        if blake3::hash(input).as_bytes() != actor.bootstrap_digest() {
            return Err(OriginalActorAccountError::WorkflowBoundary {
                source: MeasurementOriginError::Authentication("original SQLite bootstrap object"),
                original: actor.original_check().err(),
            }
            .into());
        }
        let budget = decoder.budget()?;
        let _scope = budget.enter();
        let target: Target<'_> = from_json_slice_closed(input, budget).map_err(|source| {
            OriginalActorAccountError::WorkflowDecode {
                source,
                original: actor.original_check().err(),
            }
        })?;
        target
            .validate()
            .map_err(|source| OriginalActorAccountError::WorkflowBoundary {
                source,
                original: actor.original_check().err(),
            })?;
        budget
            .check()
            .map_err(|source| OriginalActorAccountError::DecodeBoundary {
                source,
                original: actor.original_check().err(),
            })?;
        verify_kernel_page_case(actor, budget)?;
        verify_bootstrap_case(actor).map_err(|source| OriginalActorSqliteBootstrapError::Case {
            source,
            original: actor.original_check().err(),
        })?;
        actor
            .original_check()
            .map_err(OriginalActorAccountError::Supervision)?;
        Ok(OriginalActorSqliteBootstrap {
            actor: self.accounts.share_accounting().map_err(|source| {
                OriginalActorSqliteBootstrapError::Case {
                    source: super::admission(source),
                    original: actor.original_check().err(),
                }
            })?,
        })
    }
}

fn verify_kernel_page_case(
    actor: &OriginalGuestServiceHandle,
    budget: &crucible::owned_decode::DecodeBudget,
) -> Result<(), OriginalActorSqliteBootstrapError> {
    actor
        .original_check()
        .map_err(OriginalActorAccountError::Supervision)?;
    // Full main-stack financing belongs to the enforced birth case. This
    // bounded stack buffer has no heap payload; its temporary FD control is
    // separately admitted before opening the genuine sysfs policy object.
    let _descriptor = budget.reserve_descriptors(1).map_err(|source| {
        OriginalActorAccountError::DecodeBoundary {
            source,
            original: actor.original_check().err(),
        }
    })?;
    let mut file = after_kernel(
        actor,
        File::open("/sys/kernel/mm/transparent_hugepage/enabled"),
    )?;
    let filesystem = after_kernel(
        actor,
        rustix::fs::fstatfs(&file).map_err(std::io::Error::from),
    )?;
    let mut bytes = [0; 512];
    let mut length = 0;
    loop {
        let count = after_kernel(actor, file.read(&mut bytes[length..]))?;
        if count == 0 {
            break;
        }
        length += count;
        if length == bytes.len() {
            return Err(page_policy_refusal(actor));
        }
    }
    // Linux UAPI SYSFS_MAGIC identifies the genuine kernel policy filesystem.
    if filesystem.f_type != 0x6265_6572
        || !bytes[..length]
            .split(u8::is_ascii_whitespace)
            .any(|word| word == b"[never]")
    {
        return Err(page_policy_refusal(actor));
    }
    actor
        .original_check()
        .map_err(OriginalActorAccountError::Supervision)?;
    Ok(())
}

fn page_policy_refusal(actor: &OriginalGuestServiceHandle) -> OriginalActorSqliteBootstrapError {
    OriginalActorAccountError::WorkflowBoundary {
        source: MeasurementOriginError::Authentication("original genuine sysfs THP never case"),
        original: actor.original_check().err(),
    }
    .into()
}

fn after_kernel<T>(
    actor: &OriginalGuestServiceHandle,
    work: Result<T, std::io::Error>,
) -> Result<T, OriginalActorSqliteBootstrapError> {
    let after = actor.original_check();
    match (work, after) {
        (Ok(value), Ok(_)) => Ok(value),
        (Err(source), after) => Err(OriginalActorSqliteBootstrapError::Kernel {
            source,
            original: after.err(),
        }),
        (Ok(_), Err(source)) => Err(OriginalActorAccountError::Supervision(source).into()),
    }
}

impl OriginalActorSqliteBootstrap {
    pub(super) fn verify_actor(&self, owner: &OriginalGuestServiceOwner) -> Result<(), StoreError> {
        owner.verify_handle(&self.actor).map_err(super::admission)?;
        verify_bootstrap_case(&self.actor)
    }
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- this borrowed target test rejects changed installed source/configuration identities without constructing an account or entering native initialization.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    const TARGET: &[u8] = include_bytes!("bootstrap/target-v1.json");
    #[test]
    fn exact_generated_source_object_and_each_changed_case_refuse() {
        let mut target: Target<'_> = serde_json::from_slice(TARGET).unwrap();
        assert!(target.validate().is_ok());
        target.glibc_build_record_sha256 = "changed actual installed build";
        assert!(target.validate().is_err());
        target = serde_json::from_slice(TARGET).unwrap();
        target.conditional_main_arena_backing.requests[0].additional_backing_upper_bytes -= 1;
        assert!(target.validate().is_err());
        target = serde_json::from_slice(TARGET).unwrap();
        target.stack_records[0].sha256 = "foreign stack configuration";
        assert!(target.validate().is_err());
    }
}
