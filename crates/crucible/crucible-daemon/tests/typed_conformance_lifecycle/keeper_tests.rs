//! Faults the actual keeper helpers with explicit inert owning carriers.
//!
//! These carriers model upper metadata/native holder custody; they are not SDK
//! guards, kernel witnesses or authentic source/group reclamation evidence.

use std::{cell::Cell, rc::Rc};

use super::{borrowed, reclaim_until};

struct Original {
    marker: Box<u64>,
    profile: Vec<u8>,
    session: Vec<u8>,
    graph_request: Vec<u8>,
    publisher: Vec<u8>,
    drops: Rc<Cell<usize>>,
    calls: usize,
    complete: bool,
}

impl Original {
    fn new(drops: Rc<Cell<usize>>) -> Self {
        Self {
            marker: Box::new(19),
            profile: vec![1],
            session: vec![2],
            graph_request: vec![3],
            publisher: vec![4],
            drops,
            calls: 0,
            complete: false,
        }
    }

    fn assert_same(&self, identity: *const u64) {
        assert_eq!(self.marker.as_ref() as *const u64, identity);
        assert_eq!(self.profile, [1]);
        assert_eq!(self.session, [2]);
        assert_eq!(self.graph_request, [3]);
        assert_eq!(self.publisher, [4]);
        assert_eq!(self.drops.get(), 0);
    }
}

impl Drop for Original {
    fn drop(&mut self) {
        assert!(
            self.complete,
            "full original dropped before authenticated cleanup"
        );
        self.drops.set(self.drops.get() + 1);
    }
}

fn callback_panic_preserves_whole_original() {
    let drops = Rc::new(Cell::new(0));
    let mut original = Original::new(Rc::clone(&drops));
    let identity = original.marker.as_ref() as *const u64;
    let result = borrowed(&mut original, |owner| {
        owner.calls += 1;
        panic!("injected original callback unwind");
    });
    assert!(result.is_err());
    original.assert_same(identity);
    assert_eq!(original.calls, 1);
    original.complete = true;
    drop(original);
    assert_eq!(drops.get(), 1);
}

#[test]
fn borrowed_callback_unwind_preserves_whole_upper_owner() {
    callback_panic_preserves_whole_original();
}

#[test]
fn partial_sibling_transfer_keeps_servicing_while_another_handoff_refuses() {
    let drops = Rc::new(Cell::new(0));
    let mut original = Original::new(Rc::clone(&drops));
    let identity = original.marker.as_ref() as *const u64;
    let sibling_transferred = Cell::new(false);
    let sibling_polls = Cell::new(0);
    let refused_owner_polls = Cell::new(0);
    reclaim_until(
        &mut original,
        |owner| {
            owner.assert_same(identity);
            if !sibling_transferred.replace(true) {
                owner.calls += 1;
            }
            // The same keeper must service the already-transferred sibling
            // while another retained handoff is Refused or Unknown.
            sibling_polls.set(sibling_polls.get() + 1);
            refused_owner_polls.set(refused_owner_polls.get() + 1);
            if refused_owner_polls.get() < 3 {
                return false;
            }
            owner.complete = true;
            true
        },
        |owner| owner.assert_same(identity),
    );
    assert_eq!(original.calls, 1);
    assert_eq!(sibling_polls.get(), 3);
    assert_eq!(refused_owner_polls.get(), 3);
    drop(original);
    assert_eq!(drops.get(), 1);
}

struct ServicingKeeper(Option<Original>);

impl Drop for ServicingKeeper {
    fn drop(&mut self) {
        if let Some(original) = self.0.as_mut() {
            let identity = original.marker.as_ref() as *const u64;
            reclaim_until(
                original,
                |owner| {
                    owner.assert_same(identity);
                    owner.calls += 1;
                    match owner.calls {
                        1 => panic!("retained cleanup callback unwind"),
                        2 => false,
                        3 => {
                            owner.complete = true;
                            true
                        }
                        _ => panic!("same retirement repeated after completion"),
                    }
                },
                |owner| owner.assert_same(identity),
            );
        }
    }
}

#[test]
fn error_return_services_same_keeper_before_releasing_original() {
    fn refuse(drops: Rc<Cell<usize>>) -> Result<(), &'static str> {
        let _keeper = ServicingKeeper(Some(Original::new(drops)));
        Err("original operation refused")
    }
    let drops = Rc::new(Cell::new(0));
    assert_eq!(refuse(Rc::clone(&drops)), Err("original operation refused"));
    assert_eq!(drops.get(), 1);
}

#[test]
fn caller_unwind_drop_services_panic_then_unknown_before_original_release() {
    let drops = Rc::new(Cell::new(0));
    let original_drops = Rc::clone(&drops);
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _keeper = ServicingKeeper(Some(Original::new(original_drops)));
        panic!("injected caller/publication/assertion unwind");
    }));
    assert!(unwound.is_err());
    assert_eq!(drops.get(), 1);
}
