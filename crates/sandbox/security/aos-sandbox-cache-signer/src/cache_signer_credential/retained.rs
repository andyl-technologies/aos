//! Owns the actual private Cache triplet before any native read or key parse.
//!
//! Only the private Cache F owner invokes the fixed directory recipe. Native
//! originals and actual key-decode/signing-key partials survive every refusal;
//! this capture alone grants neither signing purpose nor receiving authority.

use std::error::Error;
use std::mem::size_of;
use std::path::Path;

use aos_sandbox_model::{AccountingError, ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::credential::FixedRoleCredentialReadV1;
use aos_sandbox_protocol::role_credential::{
    CACHE_OWNER_ROLE_CREDENTIAL_DOMAIN_V1, CACHE_OWNER_ROLE_CREDENTIAL_MAGIC_V1,
    RoleCredentialDecodeCaptureV1, decode_role_credential_retaining_v1,
};

use super::{
    CacheSignerCredentialErrorV2, CacheSignerCredentialV2, MEMORY_NAME, PIN_NAME, SEED_NAME,
    SigningKey, Zeroizing, require_key_matches, validate_seed_and_memory,
};

const DIRECTORY: &str = "/run/credentials/aos-sandbox-cache-signerd.service";
const INPUTS: [(&str, u64, bool); 3] = [
    (SEED_NAME, 32, true),
    (PIN_NAME, 80, false),
    (MEMORY_NAME, 16, true),
];

#[derive(Clone, Copy)]
enum First {
    Read(usize),
    SeedMemory,
    Pin,
    Key,
    Transfer,
    Closed,
}

pub(crate) struct CacheSignerCredentialCaptureV1 {
    readers: [FixedRoleCredentialReadV1; 3],
    reads: [Option<Result<(), CacheSignerCredentialErrorV2>>; 3],
    seed_memory: Option<Result<u64, CacheSignerCredentialErrorV2>>,
    pin: RoleCredentialDecodeCaptureV1,
    signing_key: Option<SigningKey>,
    binding: Option<Result<(), CacheSignerCredentialErrorV2>>,
    completion: Option<Result<CacheSignerCredentialV2, CacheSignerCredentialErrorV2>>,
    entered: bool,
    first: Option<First>,
    closed: bool,
}

impl Default for CacheSignerCredentialCaptureV1 {
    fn default() -> Self {
        Self {
            readers: std::array::from_fn(|_| FixedRoleCredentialReadV1::prearmed()),
            reads: std::array::from_fn(|_| None),
            seed_memory: None,
            pin: RoleCredentialDecodeCaptureV1::new(),
            signing_key: None,
            binding: None,
            completion: None,
            entered: false,
            first: None,
            closed: false,
        }
    }
}

impl CacheSignerCredentialCaptureV1 {
    // Geometry is compiled from these actual three recipes before the private
    // original enters any reader. Callers cannot size an admitted seed or path.
    pub(crate) fn receiving_demand_v1() -> Result<ResourceVector, AccountingError> {
        let overflow = AccountingError::ArithmeticOverflow {
            dimension: D::MemoryBytes,
        };
        let mut path_peak = 0usize;
        for (name, _, _) in INPUTS {
            path_peak = path_peak.max(
                FixedRoleCredentialReadV1::joined_path_receiving_bytes_v1(
                    Path::new(DIRECTORY),
                    name,
                )
                .ok_or(overflow)?,
            );
        }
        let memory = size_of::<Self>()
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(path_peak))
            .and_then(|bytes| bytes.checked_add(32 + 80 + 16))
            .and_then(|bytes| bytes.checked_add(size_of::<SigningKey>()))
            .and_then(|bytes| {
                bytes.checked_add(RoleCredentialDecodeCaptureV1::receiving_bytes_v1()?)
            })
            .and_then(|bytes| bytes.checked_add(3 * 256))
            .ok_or(overflow)?;
        // Each consuming Rustix path conversion finishes before the next
        // reader enters. Only their largest simultaneous allocation is live.
        // Rust fields and temporary controls are not namespace metadata.
        Ok(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(memory).map_err(|_| overflow)?)
            .with(D::OpenFiles, 3))
    }

    pub(crate) fn capture_once(&mut self) -> Result<(), CacheSignerCredentialErrorV2> {
        if self.entered {
            self.closed = true;
            self.first.get_or_insert(First::Closed);
            return Err(CacheSignerCredentialErrorV2);
        }
        self.entered = true;
        self.completion = Some(self.capture_inner());
        if self.first.is_none() && matches!(self.completion, Some(Ok(_))) {
            Ok(())
        } else {
            Err(CacheSignerCredentialErrorV2)
        }
    }

    fn capture_inner(&mut self) -> Result<CacheSignerCredentialV2, CacheSignerCredentialErrorV2> {
        for (index, (name, width, private)) in INPUTS.into_iter().enumerate() {
            self.readers[index].read_fixed_once(Path::new(DIRECTORY), name, width, private);
            self.reads[index] = Some(match self.readers[index].outcome() {
                Some(Ok(Some(_))) => Ok(()),
                _ => Err(CacheSignerCredentialErrorV2),
            });
            if !matches!(self.reads[index], Some(Ok(()))) {
                self.first = Some(First::Read(index));
                return Err(CacheSignerCredentialErrorV2);
            }
        }
        self.seed_memory = Some((|| {
            let seed = self.bytes(0)?;
            let memory = self.bytes(2)?;
            let (_, ceiling) = validate_seed_and_memory(seed, memory)?;
            Ok(ceiling)
        })());
        let ceiling = match self.seed_memory {
            Some(Ok(ceiling)) => ceiling,
            _ => {
                self.first = Some(First::SeedMemory);
                return Err(CacheSignerCredentialErrorV2);
            }
        };
        let seed: &[u8; 32] = self
            .bytes(0)?
            .try_into()
            .map_err(|_| CacheSignerCredentialErrorV2)?;
        self.signing_key = Some(SigningKey::from_bytes(seed));
        let pin = self.readers[1]
            .outcome()
            .and_then(Result::ok)
            .flatten()
            .ok_or(CacheSignerCredentialErrorV2)?;
        if decode_role_credential_retaining_v1(
            pin,
            CACHE_OWNER_ROLE_CREDENTIAL_MAGIC_V1,
            CACHE_OWNER_ROLE_CREDENTIAL_DOMAIN_V1,
            &mut self.pin,
        )
        .is_err()
        {
            self.first = Some(First::Pin);
            return Err(CacheSignerCredentialErrorV2);
        }
        let (generation, public) = self.pin.decoded().ok_or(CacheSignerCredentialErrorV2)?;
        let generation = *generation;
        self.binding = Some(match self.signing_key.as_ref() {
            Some(key) => require_key_matches(public, key),
            None => Err(CacheSignerCredentialErrorV2),
        });
        if !matches!(self.binding, Some(Ok(()))) {
            self.first = Some(First::Key);
            return Err(CacheSignerCredentialErrorV2);
        }
        let Some(seed) = self.readers[0].take_success_bytes_once() else {
            self.first = Some(First::Transfer);
            return Err(CacheSignerCredentialErrorV2);
        };
        Ok(CacheSignerCredentialV2 {
            seed: Zeroizing::new(seed),
            generation,
            maximum_memory_bytes: ceiling,
        })
    }

    fn bytes(&self, index: usize) -> Result<&[u8], CacheSignerCredentialErrorV2> {
        self.readers
            .get(index)
            .and_then(FixedRoleCredentialReadV1::outcome)
            .and_then(Result::ok)
            .flatten()
            .map(|bytes| bytes.as_slice())
            .ok_or(CacheSignerCredentialErrorV2)
    }

    // The actual same-F parent checks both of its whole native post results
    // before calling this borrower. It moves no credential or native owner.
    pub(crate) fn credential(
        &self,
    ) -> Result<&CacheSignerCredentialV2, CacheSignerCredentialErrorV2> {
        if self.closed || self.first.is_some() {
            return Err(CacheSignerCredentialErrorV2);
        }
        self.completion
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(CacheSignerCredentialErrorV2)
    }

    // Native primitives retire only at the caller's actual fully positive F
    // stage. No arbitrary body result, boolean or generic token enters here.
    pub(crate) fn retire_completed_native_once(
        &mut self,
    ) -> Result<(), CacheSignerCredentialErrorV2> {
        self.credential()?;
        for reader in &mut self.readers {
            if !reader.retire_completed_file_once_v1() {
                return Err(CacheSignerCredentialErrorV2);
            }
        }
        drop(self.signing_key.take());
        Ok(())
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::Read(index) => self.readers[index]
                .failure()
                .or_else(|| cause(&self.reads[index])),
            First::SeedMemory => cause(&self.seed_memory),
            First::Pin => self.pin.failure(),
            First::Key => cause(&self.binding),
            First::Transfer => cause(&self.completion),
            First::Closed => Some(&CacheSignerCredentialErrorV2 as &(dyn Error + 'static)),
        }
        .or_else(|| cause(&self.completion))
    }
}

fn cause<T, E: Error + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    value
        .as_ref()
        .and_then(|result| result.as_ref().err())
        .map(|cause| cause as _)
}
