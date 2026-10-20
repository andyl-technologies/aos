//! Bounded Linux entropy and process-exclusive hello nonce derivation.

use hmac::{Hmac, Mac as _};
use rustix::rand::GetRandomFlags;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::SourceProviderSecurityError;
use crate::execution::RetainedSelfExecutionV1;
use crate::manifest::SourceProviderSecurityRoleV1;
use crate::protected_files::ProtectedSourceProviderFiles;

const MAXIMUM_INTERRUPTED_RETRIES: usize = 8;
const MAXIMUM_ALL_ZERO_RETRIES: usize = 8;
const NONCE_DOMAIN: &[u8] = b"aos-source-provider-hello-nonce-v1\0";

pub(crate) struct KernelEntropy;

impl KernelEntropy {
    fn fill_once(&mut self, output: &mut [u8]) -> rustix::io::Result<usize> {
        rustix::rand::getrandom(output, GetRandomFlags::empty())
    }
}

pub(crate) fn nonzero_kernel_random<const N: usize>() -> Result<[u8; N], SourceProviderSecurityError>
{
    let mut source = KernelEntropy;
    let mut output = Zeroizing::new([0; N]);
    for attempt in 0..=MAXIMUM_ALL_ZERO_RETRIES {
        fill_exact(&mut source, &mut output[..])?;
        if output.iter().any(|byte| *byte != 0) {
            return Ok(*output);
        }
        if attempt == MAXIMUM_ALL_ZERO_RETRIES {
            break;
        }
    }
    Err(SourceProviderSecurityError::Entropy)
}

fn fill_exact(
    source: &mut KernelEntropy,
    output: &mut [u8],
) -> Result<(), SourceProviderSecurityError> {
    let mut offset = 0;
    let mut interruptions = 0;
    while offset < output.len() {
        match source.fill_once(&mut output[offset..]) {
            Ok(0) => return Err(SourceProviderSecurityError::Entropy),
            Ok(written) if written <= output.len() - offset => offset += written,
            Ok(_) => return Err(SourceProviderSecurityError::Entropy),
            Err(rustix::io::Errno::INTR) if interruptions < MAXIMUM_INTERRUPTED_RETRIES => {
                interruptions += 1;
            }
            Err(_) => return Err(SourceProviderSecurityError::Entropy),
        }
    }
    Ok(())
}

/// Owns process-exclusive nonce state behind retained configuration and execution.
pub(crate) struct ProcessNonceSourceV1 {
    key: Zeroizing<[u8; 32]>,
    process_instance: [u8; 16],
    role: SourceProviderSecurityRoleV1,
    boot_id: [u8; 16],
    counter: u64,
    poisoned: bool,
}

impl core::fmt::Debug for ProcessNonceSourceV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProcessNonceSourceV1([redacted])")
    }
}

impl ProcessNonceSourceV1 {
    pub(crate) fn create(
        role: SourceProviderSecurityRoleV1,
        execution: &RetainedSelfExecutionV1,
        files: &ProtectedSourceProviderFiles,
    ) -> Result<Self, SourceProviderSecurityError> {
        files.revalidate()?;
        execution.revalidate()?;
        let key = Zeroizing::new(nonzero_kernel_random()?);
        let process_instance = nonzero_kernel_random()?;
        execution.revalidate()?;
        files.revalidate()?;
        Ok(Self {
            key,
            process_instance,
            role,
            boot_id: execution.boot_id(),
            counter: 0,
            poisoned: false,
        })
    }

    pub(crate) const fn process_instance(&self) -> [u8; 16] {
        self.process_instance
    }

    pub(crate) fn draw(
        &mut self,
        execution: &RetainedSelfExecutionV1,
        files: &ProtectedSourceProviderFiles,
    ) -> Result<[u8; 32], SourceProviderSecurityError> {
        if self.poisoned {
            return Err(SourceProviderSecurityError::Poisoned);
        }
        if let Err(error) = files.revalidate().and_then(|_| execution.revalidate()) {
            self.poisoned = true;
            return Err(error);
        }
        if execution.boot_id() != self.boot_id {
            self.poisoned = true;
            return Err(SourceProviderSecurityError::ExecutionChanged);
        }
        let counter = self.counter.checked_add(1).ok_or_else(|| {
            self.poisoned = true;
            SourceProviderSecurityError::NonceExhausted
        })?;
        self.counter = counter;

        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key[..])
            .map_err(|_| SourceProviderSecurityError::Entropy)?;
        mac.update(NONCE_DOMAIN);
        mac.update(&[self.role as u8]);
        mac.update(&self.boot_id);
        mac.update(&self.process_instance);
        mac.update(&counter.to_be_bytes());
        let nonce: [u8; 32] = mac.finalize().into_bytes().into();
        if nonce == [0; 32] {
            self.poisoned = true;
            return Err(SourceProviderSecurityError::Entropy);
        }

        if let Err(error) = execution.revalidate().and_then(|_| files.revalidate()) {
            self.poisoned = true;
            return Err(error);
        }
        Ok(nonce)
    }
}
