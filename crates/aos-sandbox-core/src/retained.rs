//! Shares ordinary-versus-retained value ownership without authority.
//!
//! This small representation adapter is common to canonical Core codecs and
//! Protocol projections. It supplies no permit, callback, allocator, financial
//! account, reset, native IO or role constructor.

use std::ops::{Deref, DerefMut};

/// Holds an ordinary local value or its caller-owned retained destination.
///
/// This DATA adapter performs no payment, validation, once gating or IO. Its
/// real caller must retain its authority and enforce lifecycle before entry.
pub enum CaptureValueV1<'a, T> {
    /// Owns the ordinary value with its original local drop interval.
    Local(T),
    /// Borrows the actual destination that owns the reached value.
    Retained(&'a mut T),
}

impl<'a, T> CaptureValueV1<'a, T> {
    /// Moves the supplied value into its actual destination when present.
    ///
    /// Replacing an earlier destination is ordinary Rust assignment; this
    /// helper does not authorize reuse or disposal of a protected owner.
    pub fn new(value: T, destination: Option<&'a mut T>) -> Self {
        match destination {
            Some(destination) => {
                *destination = value;
                Self::Retained(destination)
            }
            None => Self::Local(value),
        }
    }
}

impl<T: Default> CaptureValueV1<'_, T> {
    /// Moves the value out, leaving a retained destination at its default.
    ///
    /// The actual caller remains responsible for positive completion and for
    /// preserving failed values. This grants no lifecycle or funding credit.
    pub fn take(self) -> T {
        match self {
            Self::Local(value) => value,
            Self::Retained(value) => std::mem::take(value),
        }
    }
}

impl<T> Deref for CaptureValueV1<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        match self {
            Self::Local(value) => value,
            Self::Retained(value) => value,
        }
    }
}

impl<T> DerefMut for CaptureValueV1<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        match self {
            Self::Local(value) => value,
            Self::Retained(value) => value,
        }
    }
}

