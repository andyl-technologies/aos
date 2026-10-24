//! Retains import18 body banks and their monotonic private-write cursors.
//!
//! These banks contain private startup material. Their owning member authenticates
//! the Source, lease, installed admission and inherited channel around every use.
//! Bank preparation alone creates no native admission or completed transfer.

use crate::node_contract::RuntimeError;
use std::{io::Write, mem::size_of};

#[derive(Clone, Copy)]
pub(super) enum Body {
    Recipe,
    Launch,
    Boot,
}

impl Body {
    fn index(self) -> usize {
        match self {
            Self::Recipe => 0,
            Self::Launch => 1,
            Self::Boot => 2,
        }
    }
}

/// Keeps all allocation attempts attached to the original wire owner.
pub(super) struct Banks {
    bodies: [Vec<u8>; 3],
    limits: [usize; 3],
    written: [usize; 3],
    finished: [bool; 3],
    failed: bool,
}

impl Banks {
    /// Installs an empty owner before the first fallible reservation.
    ///
    /// The enclosing admission pays the actual constructor return separately
    /// from this owner's inline header and each prospective body capacity.
    pub(super) fn reserve_into(
        limits: [usize; 3],
        output: &mut Option<Self>,
    ) -> Result<(), RuntimeError> {
        if output.is_some() {
            return Err(RuntimeError::DuplicateOperation);
        }
        *output = Some(Self {
            bodies: std::array::from_fn(|_| Vec::new()),
            limits,
            written: [0; 3],
            finished: [false; 3],
            failed: true,
        });
        let owner = output.as_mut().ok_or(RuntimeError::OwnerUnavailable)?;
        for (bank, maximum) in owner.bodies.iter_mut().zip(limits) {
            if maximum == 0 {
                return Err(RuntimeError::ResourceLimit);
            }
            bank.try_reserve_exact(maximum)
                .map_err(|_| RuntimeError::ResourceLimit)?;
            if bank.capacity() > maximum {
                return Err(RuntimeError::ResourceLimit);
            }
        }
        owner.failed = false;
        Ok(())
    }

    /// Fills one original bank without any implicit capacity growth.
    ///
    /// The enclosing serializer has an independently admitted transient row.
    /// Failure or unwind leaves the bank spent with all initialized bytes.
    pub(super) fn fill(
        &mut self,
        body: Body,
        encode: impl FnOnce(&mut Reserved<'_>) -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        if self.failed {
            return Err(RuntimeError::OutstandingObligations);
        }
        let index = body.index();
        if self.finished[index] || !self.bodies[index].is_empty() {
            return Err(RuntimeError::DuplicateOperation);
        }
        self.failed = true;
        let bank = &mut self.bodies[index];
        let maximum = self.limits[index];
        encode(&mut Reserved { bank, maximum })?;
        if self.bodies[index].is_empty() {
            return Err(RuntimeError::InvalidReceipt);
        }
        self.finished[index] = true;
        self.failed = false;
        Ok(())
    }

    /// Borrows only a completely initialized bank for fixed framing hashes.
    pub(super) fn completed(&self, body: Body) -> Result<&[u8], RuntimeError> {
        let index = body.index();
        if self.failed || !self.finished[index] {
            return Err(RuntimeError::OwnerUnavailable);
        }
        Ok(&self.bodies[index])
    }

    /// Writes literal banks in recipe, launch, boot order on the same channel.
    ///
    /// A refused write leaves its cursor unchanged; successful short writes
    /// advance immediately. Currentness is checked before every actual write
    /// and after the final write. The private parent supplies the real member
    /// guard, never an erased external callback.
    pub(super) fn write(
        &mut self,
        writer: &mut impl Write,
        mut authenticate: impl FnMut() -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        if self.failed || self.finished != [true; 3] {
            return Err(RuntimeError::OwnerUnavailable);
        }
        // The real member guard is also fallible and may unwind. Install the
        // sticky state before entering it, including the final postcheck.
        self.failed = true;
        for (bank, offset) in self.bodies.iter().zip(&mut self.written) {
            while *offset < bank.len() {
                authenticate()?;
                let remaining = &bank[*offset..];
                match writer.write(remaining) {
                    Ok(0) => return Err(RuntimeError::OwnerUnavailable),
                    Ok(count) if count <= remaining.len() => {
                        *offset += count;
                    }
                    Ok(_) | Err(_) => return Err(RuntimeError::OwnerUnavailable),
                }
            }
        }
        authenticate()?;
        self.failed = false;
        Ok(())
    }

    /// Counts actual backing even after failed reservation or serialization.
    pub(super) fn retained_backing(&self, maximum: usize) -> Result<usize, RuntimeError> {
        self.bodies.iter().try_fold(0usize, |total, bank| {
            total
                .checked_add(bank.capacity())
                .filter(|total| *total <= maximum)
                .ok_or(RuntimeError::ResourceLimit)
        })
    }

    pub(super) fn constructor_transient_bytes() -> usize {
        // The retaining initializer and Option assignment are distinct actual
        // by-value roots. Body backing is separately retained, never T credit.
        size_of::<[Vec<u8>; 3]>() + size_of::<Self>() + size_of::<Option<Self>>()
    }

    pub(super) fn counter_scratch_bytes() -> usize {
        size_of::<&mut Self>()
            + size_of::<&Self>()
            + size_of::<&mut Option<Self>>()
            + size_of::<[usize; 3]>()
            + size_of::<std::array::IntoIter<usize, 3>>()
            + size_of::<std::slice::Iter<'static, Vec<u8>>>()
            + size_of::<std::slice::IterMut<'static, Vec<u8>>>()
            + size_of::<std::slice::IterMut<'static, usize>>()
            + size_of::<std::iter::Zip<
                std::slice::IterMut<'static, Vec<u8>>,
                std::array::IntoIter<usize, 3>,
            >>()
            + size_of::<std::iter::Zip<
                std::slice::Iter<'static, Vec<u8>>,
                std::slice::IterMut<'static, usize>,
            >>()
            + size_of::<Reserved<'static>>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<Result<(), std::collections::TryReserveError>>()
            + size_of::<std::io::Result<usize>>()
            + size_of::<std::io::Result<()>>()
            + size_of::<(&mut Vec<u8>, usize)>()
            + size_of::<(&Vec<u8>, &mut usize)>()
            + size_of::<Option<&mut Self>>()
            + size_of::<&[u8]>()
            + size_of::<Option<usize>>()
            // index, maximum, end, write count and the retained fold total.
            + 5 * size_of::<usize>()
            + size_of::<Body>()
    }
}

pub(super) struct Reserved<'a> {
    bank: &'a mut Vec<u8>,
    maximum: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete() -> Banks {
        let mut output = None;
        Banks::reserve_into([3, 3, 3], &mut output).unwrap();
        let mut banks = output.unwrap();
        for (body, bytes) in [
            (Body::Recipe, b"abc"),
            (Body::Launch, b"def"),
            (Body::Boot, b"ghi"),
        ] {
            banks
                .fill(body, |writer| {
                    writer
                        .write_all(bytes)
                        .map_err(|_| RuntimeError::ResourceLimit)
                })
                .unwrap();
        }
        banks
    }

    #[test]
    fn reserve_failure_keeps_prior_capacity_and_spends_original_slot() {
        let mut output = None;
        assert!(Banks::reserve_into([3, 0, 3], &mut output).is_err());
        let original = output.as_ref().unwrap();
        assert!(original.failed);
        assert_eq!(original.bodies[0].capacity(), 3);
        assert_eq!(original.retained_backing(3).unwrap(), 3);
        assert!(Banks::reserve_into([3, 3, 3], &mut output).is_err());
    }

    #[test]
    fn refused_encoding_retains_initialized_bytes_and_cannot_restart() {
        let mut output = None;
        Banks::reserve_into([3, 3, 3], &mut output).unwrap();
        let banks = output.as_mut().unwrap();
        let result = banks.fill(Body::Recipe, |writer| {
            writer.write_all(b"abc").unwrap();
            assert!(writer.write_all(b"d").is_err());
            Err(RuntimeError::ResourceLimit)
        });

        assert!(result.is_err());
        assert_eq!(banks.bodies[0], b"abc");
        assert!(banks.completed(Body::Recipe).is_err());
        assert!(banks.fill(Body::Recipe, |_| Ok(())).is_err());
        assert_eq!(banks.retained_backing(9).unwrap(), 9);
    }

    struct RefusingWriter {
        output: Vec<u8>,
        calls: usize,
    }

    impl Write for RefusingWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.calls += 1;
            if self.calls == 3 {
                return Err(std::io::ErrorKind::BrokenPipe.into());
            }
            self.output.push(bytes[0]);
            Ok(1)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn partial_private_write_retains_cursor_and_refuses_uncertain_retry() {
        let mut banks = complete();
        let mut writer = RefusingWriter {
            output: Vec::new(),
            calls: 0,
        };

        assert!(banks.write(&mut writer, || Ok(())).is_err());
        assert_eq!(writer.output, b"ab");
        assert_eq!(banks.written, [2, 0, 0]);
        assert!(banks.write(&mut writer, || Ok(())).is_err());
        assert_eq!(writer.calls, 3);
    }

    #[test]
    fn complete_transfer_keeps_order_and_rechecks_actual_guard() {
        let mut banks = complete();
        let mut output = Vec::new();
        let mut guards = 0;

        banks
            .write(&mut output, || {
                guards += 1;
                Ok(())
            })
            .unwrap();

        assert_eq!(output, b"abcdefghi");
        assert_eq!(banks.written, [3, 3, 3]);
        assert_eq!(guards, 4);
        assert_eq!(banks.completed(Body::Boot).unwrap(), b"ghi");
    }

    #[test]
    fn final_guard_refusal_keeps_transfer_spent_after_all_bytes_were_written() {
        let mut banks = complete();
        let mut output = Vec::new();
        let mut guards = 0;
        let result = banks.write(&mut output, || {
            guards += 1;
            if guards == 4 {
                return Err(RuntimeError::ForeignAuthority);
            }
            Ok(())
        });

        assert!(result.is_err());
        assert_eq!(output, b"abcdefghi");
        assert_eq!(banks.written, [3, 3, 3]);
        assert!(banks.write(&mut output, || Ok(())).is_err());
        assert!(banks.completed(Body::Recipe).is_err());
    }

    #[test]
    fn guard_unwind_keeps_banks_spent_before_the_first_effect() {
        let mut banks = complete();
        let mut output = Vec::new();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = banks.write(&mut output, || panic!("modeled guard unwind"));
        }));

        assert!(result.is_err());
        assert!(output.is_empty());
        assert_eq!(banks.written, [0; 3]);
        assert!(banks.write(&mut output, || Ok(())).is_err());
    }
}

impl Write for Reserved<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let end = self
            .bank
            .len()
            .checked_add(bytes.len())
            .filter(|end| *end <= self.maximum && *end <= self.bank.capacity())
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::OutOfMemory))?;
        self.bank.extend_from_slice(bytes);
        debug_assert_eq!(self.bank.len(), end);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
