//! Bounded blocking entropy acquisition from the Linux kernel.
//!
//! The production source uses `getrandom(2)` with empty flags. Partial fills
//! are completed, interrupted calls have a fixed retry budget, zero progress
//! fails closed, and complete all-zero samples have a separate retry budget.

use rustix::io::Errno;
use rustix::rand::GetRandomFlags;

use crate::BrokerSessionSecurityError;

const MAXIMUM_INTERRUPTED_RETRIES: usize = 8;
const MAXIMUM_ALL_ZERO_RETRIES: usize = 8;

pub(crate) trait EntropySource {
    fn fill_once(&mut self, output: &mut [u8]) -> Result<usize, Errno>;
}

pub(crate) struct KernelEntropy;

impl EntropySource for KernelEntropy {
    fn fill_once(&mut self, output: &mut [u8]) -> Result<usize, Errno> {
        rustix::rand::getrandom(output, GetRandomFlags::empty())
    }
}

pub(crate) fn nonzero_random<const N: usize, Source: EntropySource>(
    source: &mut Source,
) -> Result<[u8; N], BrokerSessionSecurityError> {
    let mut output = [0_u8; N];
    fill_nonzero(source, &mut output)?;
    Ok(output)
}

/// Fills the caller's already parked zeroizing allocation through the same engine.
pub(crate) fn fill_retained_nonzero(
    output: &mut zeroize::Zeroizing<Vec<u8>>,
) -> Result<(), BrokerSessionSecurityError> {
    fill_nonzero(&mut KernelEntropy, output.as_mut_slice())
}

fn fill_nonzero<Source: EntropySource>(
    source: &mut Source,
    output: &mut [u8],
) -> Result<(), BrokerSessionSecurityError> {
    for zero_retry in 0..=MAXIMUM_ALL_ZERO_RETRIES {
        fill_exact(source, output)?;
        if output.iter().any(|byte| *byte != 0) {
            return Ok(());
        }
        if zero_retry == MAXIMUM_ALL_ZERO_RETRIES {
            break;
        }
    }
    Err(BrokerSessionSecurityError::Entropy)
}

fn fill_exact<Source: EntropySource>(
    source: &mut Source,
    output: &mut [u8],
) -> Result<(), BrokerSessionSecurityError> {
    let mut offset = 0;
    let mut interrupted_retries = 0;
    while offset < output.len() {
        match source.fill_once(&mut output[offset..]) {
            Ok(0) => return Err(BrokerSessionSecurityError::Entropy),
            Ok(written) if written <= output.len() - offset => offset += written,
            Ok(_) => return Err(BrokerSessionSecurityError::Entropy),
            Err(Errno::INTR) if interrupted_retries < MAXIMUM_INTERRUPTED_RETRIES => {
                interrupted_retries += 1;
            }
            Err(_) => return Err(BrokerSessionSecurityError::Entropy),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;

    struct ScriptedEntropy {
        steps: VecDeque<Result<Vec<u8>, Errno>>,
    }

    impl EntropySource for ScriptedEntropy {
        fn fill_once(&mut self, output: &mut [u8]) -> Result<usize, Errno> {
            match self.steps.pop_front().unwrap_or(Ok(Vec::new()))? {
                bytes if bytes.len() <= output.len() => {
                    output[..bytes.len()].copy_from_slice(&bytes);
                    Ok(bytes.len())
                }
                _ => Ok(output.len() + 1),
            }
        }
    }

    fn scripted(steps: impl IntoIterator<Item = Result<Vec<u8>, Errno>>) -> ScriptedEntropy {
        ScriptedEntropy {
            steps: steps.into_iter().collect(),
        }
    }

    #[test]
    fn retained_fill_keeps_partial_bytes_on_the_same_kernel_error() {
        let mut source = scripted([Ok(vec![1, 2]), Err(Errno::IO)]);
        let mut retained = zeroize::Zeroizing::new(vec![0; 4]);

        assert_eq!(
            fill_nonzero(&mut source, &mut retained),
            Err(BrokerSessionSecurityError::Entropy),
        );
        assert_eq!(retained.as_slice(), [1, 2, 0, 0]);
    }

    #[test]
    fn partial_and_interrupted_entropy_is_completed() {
        let mut source = scripted([Ok(vec![1, 2]), Err(Errno::INTR), Ok(vec![3]), Ok(vec![4])]);
        assert_eq!(nonzero_random::<4, _>(&mut source), Ok([1, 2, 3, 4]));
    }

    #[test]
    fn zero_progress_and_kernel_error_fail_closed() {
        assert_eq!(
            nonzero_random::<4, _>(&mut scripted([Ok(Vec::new())])),
            Err(BrokerSessionSecurityError::Entropy)
        );
        assert_eq!(
            nonzero_random::<4, _>(&mut scripted([Err(Errno::IO)])),
            Err(BrokerSessionSecurityError::Entropy)
        );
    }

    #[test]
    fn interrupted_and_all_zero_retry_budgets_are_exact() {
        let interruptions = (0..=MAXIMUM_INTERRUPTED_RETRIES)
            .map(|_| Err(Errno::INTR))
            .collect::<Vec<Result<Vec<u8>, Errno>>>();
        assert_eq!(
            nonzero_random::<4, _>(&mut scripted(interruptions)),
            Err(BrokerSessionSecurityError::Entropy)
        );

        let mut zero_then_nonzero = (0..MAXIMUM_ALL_ZERO_RETRIES)
            .map(|_| Ok(vec![0; 4]))
            .collect::<Vec<_>>();
        zero_then_nonzero.push(Ok(vec![1; 4]));
        assert_eq!(
            nonzero_random::<4, _>(&mut scripted(zero_then_nonzero)),
            Ok([1; 4])
        );

        let zeros = (0..=MAXIMUM_ALL_ZERO_RETRIES)
            .map(|_| Ok(vec![0; 4]))
            .collect::<Vec<_>>();
        assert_eq!(
            nonzero_random::<4, _>(&mut scripted(zeros)),
            Err(BrokerSessionSecurityError::Entropy)
        );
    }

    #[test]
    fn eight_interruptions_are_retried_and_oversized_returns_fail() {
        let mut interruptions_then_success = (0..MAXIMUM_INTERRUPTED_RETRIES)
            .map(|_| Err(Errno::INTR))
            .collect::<Vec<Result<Vec<u8>, Errno>>>();
        interruptions_then_success.push(Ok(vec![7; 4]));
        assert_eq!(
            nonzero_random::<4, _>(&mut scripted(interruptions_then_success)),
            Ok([7; 4])
        );

        assert_eq!(
            nonzero_random::<4, _>(&mut scripted([Ok(vec![1; 5])])),
            Err(BrokerSessionSecurityError::Entropy)
        );
    }
}
