//! Bounds delegated diagnostics only inside the private inactive constructor.

use std::{cell::Cell, marker::PhantomData, rc::Rc};

thread_local! {static SELECTED:Cell<bool>=const{Cell::new(false)};}

const PREFIX: &str = "original inactive construction refused; cause type: ";
const MAXIMUM_CAUSE: usize = 192;
pub(super) struct Scope {
    previous: bool,
    _same_thread: PhantomData<Rc<()>>,
}

impl Scope {
    pub(super) fn enter() -> Self {
        Self {
            previous: SELECTED.replace(true),
            _same_thread: PhantomData,
        }
    }

    pub(super) const fn requested_bytes() -> usize {
        PREFIX.len() + MAXIMUM_CAUSE + std::mem::size_of::<Self>() + std::mem::size_of::<String>()
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        SELECTED.set(self.previous);
    }
}

pub(super) fn reason<E: std::fmt::Display>(error: E) -> String {
    if !SELECTED.get() {
        return error.to_string();
    }
    let cause = std::any::type_name::<E>();
    let mut end = cause.len().min(MAXIMUM_CAUSE);
    while !cause.is_char_boundary(end) {
        end -= 1;
    }
    let mut result = String::with_capacity(PREFIX.len() + end);
    result.push_str(PREFIX);
    result.push_str(&cause[..end]);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    struct NoDisplay;
    impl std::fmt::Display for NoDisplay {
        fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            panic!("constructor must not delegate Display")
        }
    }

    #[test]
    fn original_runtime_diagnostics_preserve_nested_and_unwind_state() {
        assert!(!SELECTED.get());
        {
            let _outer = Scope::enter();
            assert!(reason(NoDisplay).contains("NoDisplay"));
            {
                let _inner = Scope::enter();
                assert!(SELECTED.get());
            }
            assert!(SELECTED.get());
            let failure = std::panic::catch_unwind(|| {
                let _inner = Scope::enter();
                panic!("restore original scope");
            });
            assert!(failure.is_err());
            assert!(SELECTED.get());
        }
        assert!(!SELECTED.get());
        assert_eq!(reason("ordinary diagnostic"), "ordinary diagnostic");
    }
}
