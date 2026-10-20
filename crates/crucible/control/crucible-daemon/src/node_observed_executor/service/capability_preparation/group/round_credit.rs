//! Charges each original common round against authored and installed limits.

use super::super::{NodeObservationServiceError, refused};

const SERVER_ROUNDS: u64 = 128;

pub(super) struct RoundCredit {
    next: u64,
    maximum: u64,
}

impl RoundCredit {
    pub(super) fn new(authored: u64) -> Result<Self, NodeObservationServiceError> {
        if authored == 0 || authored > 65_536 {
            return Err(refused("original authored round credit differs"));
        }
        Ok(Self {
            next: 0,
            maximum: authored.min(SERVER_ROUNDS),
        })
    }
}

impl Iterator for RoundCredit {
    type Item = u64;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next >= self.maximum {
            return None;
        }
        let original = self.next;
        self.next += 1;
        Some(original)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exhausted_authored_credit_does_not_enter_another_original_round() {
        let Ok(mut credit) = RoundCredit::new(1) else {
            panic!("valid original credit refused");
        };
        let mut entered = Vec::new();
        for original in credit.by_ref() {
            entered.push(original);
        }

        assert_eq!(entered, vec![0]);
        assert_eq!(credit.next(), None);
        assert_eq!(credit.next(), None);
        assert_eq!(entered, vec![0]);
    }

    #[test]
    fn server_and_authored_limits_remain_conjunct_without_wrapping() {
        for authored in [1, 2, 127, 128, 129, 65_536] {
            let Ok(credit) = RoundCredit::new(authored) else {
                panic!("valid original credit refused");
            };
            let rounds: Vec<_> = credit.collect();
            assert_eq!(rounds.len() as u64, authored.min(SERVER_ROUNDS));
            assert_eq!(
                rounds.last().copied(),
                Some(authored.min(SERVER_ROUNDS) - 1)
            );
        }
        assert!(RoundCredit::new(0).is_err());
        assert!(RoundCredit::new(65_537).is_err());
        assert!(RoundCredit::new(u64::MAX).is_err());
    }
}
