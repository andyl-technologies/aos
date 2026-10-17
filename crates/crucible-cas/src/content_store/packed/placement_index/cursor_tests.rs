//! Cursor layout reuse over one privately owned leaf and actual reload cuts.
//!
//! These controls reuse the existing finite placement fixture. Fixture setup and
//! reference result vectors remain outside its component purpose; no physical
//! namespace entitlement, native payer or performance claim follows.

use super::super::index_update::Update;
use super::super::placement_tests::{
    Fixture, FixtureError, object, published_two_leaf_index, value,
};
use super::*;
use std::cell::Cell;

fn snapshot_with_records(fixture: &Fixture, count: u64) -> Result<IndexSnapshot, FixtureError> {
    let mut boundary = || Ok(());
    let mut operation = Operation {
        original: Some(&fixture.original),
        boundary: &mut boundary,
    };
    let initial = EncodedIndex::empty_under(&fixture.backend, [21; 32], &mut operation)?.snapshot();
    let mut update = Update::new(&initial, &fixture.backend, &mut operation)?;
    for ordinal in 0..count {
        update.set(
            &fixture.backend,
            Key::object(object(ordinal)),
            Some(value(ordinal)),
            &mut operation,
        )?;
    }
    let encoded = update.finish(&fixture.backend, &mut operation)?;
    fixture.backend.publish_index(&encoded)?;
    Ok(encoded.snapshot())
}

#[test]
fn cursor_layout_matches_predecessor_rows_and_boundary_transcript() -> Result<(), FixtureError> {
    println!(
        "cursor geometry: predecessor={} current={} layout={} page={} frame={}",
        std::mem::size_of::<PreviousCursor<'_, '_>>(),
        std::mem::size_of::<Cursor<'_, '_>>(),
        std::mem::size_of::<wire::LeafLayout>(),
        std::mem::size_of::<CursorPage>(),
        std::mem::size_of::<Frame>()
    );
    for count in [0, 8, 64, 65, 145] {
        let fixture = Fixture::new()?;
        let snapshot = snapshot_with_records(&fixture, count)?;
        let mut healthy = || Ok(());
        let mut setup = Operation {
            original: Some(&fixture.original),
            boundary: &mut healthy,
        };
        let reader = snapshot.reader(&fixture.backend, &mut setup)?;
        let mut current = reader.cursor(&mut setup)?;
        let mut previous = PreviousCursor {
            reader: &reader,
            buffer: if reader.arena.is_some() {
                Some(setup.buffer(wire::PAGE_BYTES)?)
            } else {
                None
            },
            frames: [None; wire::MAX_HEIGHT],
            depth: 0,
            slot: 0,
            started: false,
            ended: false,
        };

        let current_cuts = Cell::new(0);
        let previous_cuts = Cell::new(0);
        let mut current_boundary = || {
            current_cuts.set(current_cuts.get() + 1);
            Ok(())
        };
        let mut previous_boundary = || {
            previous_cuts.set(previous_cuts.get() + 1);
            Ok(())
        };
        let mut current_operation = Operation {
            original: Some(&fixture.original),
            boundary: &mut current_boundary,
        };
        let mut previous_operation = Operation {
            original: Some(&fixture.original),
            boundary: &mut previous_boundary,
        };
        for ordinal in 0..count {
            let expected = Some((Key::object(object(ordinal)), value(ordinal)));
            assert_eq!(current.next(&mut current_operation)?, expected);
            assert_eq!(previous.next(&mut previous_operation)?, expected);
            assert_eq!(current_cuts.get(), previous_cuts.get());
        }
        for _ in 0..2 {
            assert_eq!(current.next(&mut current_operation)?, None);
            assert_eq!(previous.next(&mut previous_operation)?, None);
            assert_eq!(current_cuts.get(), previous_cuts.get());
        }
    }
    Ok(())
}

#[test]
fn validated_leaf_layout_refuses_another_allocation_or_length() -> Result<(), FixtureError> {
    let fixture = Fixture::new()?;
    let snapshot = snapshot_with_records(&fixture, 8)?;
    let body = snapshot.body();
    let node = Node::parse(body, true)?;
    let layout = node.leaf_layout().expect("inline fixture is a leaf");
    assert_eq!(layout.view(body)?.value(7)?, value(7));

    let other = body.to_vec();
    assert!(matches!(layout.view(&other), Err(StoreError::Incompatible)));
    assert!(matches!(
        layout.view(&body[..body.len() - 1]),
        Err(StoreError::Incompatible)
    ));
    Ok(())
}

#[test]
fn page_reload_retires_layout_before_refusal_or_corruption() -> Result<(), FixtureError> {
    let fixture = Fixture::new()?;
    let snapshot = published_two_leaf_index(&fixture)?;
    let mut healthy = || Ok(());
    let mut operation = Operation {
        original: Some(&fixture.original),
        boundary: &mut healthy,
    };
    let reader = snapshot.reader(&fixture.backend, &mut operation)?;
    let root = PageReference::decode(snapshot.body())?;
    let mut root_bytes = operation.buffer(wire::PAGE_BYTES)?;
    let root_node = reader.load(root, true, None, None, &mut root_bytes, &mut operation)?;
    let child = root_node.child(0)?;
    let upper = Some(root_node.key(0)?);
    let mut page = CursorPage::new(Some(operation.buffer(wire::PAGE_BYTES)?));
    page.load(&reader, child, false, None, upper, &mut operation)?;
    assert_eq!(page.leaf()?.value(0)?, value(0));

    // Refusal happens before the first backing read, when the old bytes are
    // still valid. Omitting invalidation would incorrectly preserve a view.
    let mut calls = 0;
    let mut refuse = || {
        calls += 1;
        Err(StoreError::Unauthorized)
    };
    let error = page.load(
        &reader,
        child,
        false,
        None,
        upper,
        &mut Operation {
            original: Some(&fixture.original),
            boundary: &mut refuse,
        },
    );
    assert!(matches!(error, Err(StoreError::Unauthorized)));
    assert_eq!(calls, 1);
    assert!(matches!(page.leaf(), Err(StoreError::Incompatible)));

    page.load(&reader, child, false, None, upper, &mut operation)?;
    assert_eq!(page.leaf()?.value(0)?, value(0));
    let name = index_io::arena_name(snapshot.header.arena.expect("fixture has arena"));
    let path = fixture
        .backend
        .admin
        .join(std::str::from_utf8(&name).unwrap());
    let file = fs::OpenOptions::new().read(true).write(true).open(path)?;
    let mut bytes = vec![0; child.length as usize];
    file.read_exact_at(&mut bytes, child.offset)?;
    bytes[wire::PAGE_HEADER_BYTES + wire::KEY_BYTES] ^= 1;
    file.write_all_at(&bytes, child.offset)?;

    assert!(matches!(
        page.load(&reader, child, false, None, upper, &mut operation),
        Err(StoreError::Incompatible)
    ));
    assert!(matches!(page.leaf(), Err(StoreError::Incompatible)));
    Ok(())
}

#[test]
fn cursor_full_control_keeps_same_original_credit_until_drop() -> Result<(), FixtureError> {
    for count in [8, 65] {
        let fixture = Fixture::new()?;
        let snapshot = snapshot_with_records(&fixture, count)?;
        let mut healthy = || Ok(());
        let mut operation = Operation {
            original: Some(&fixture.original),
            boundary: &mut healthy,
        };
        let reader = snapshot.reader(&fixture.backend, &mut operation)?;
        let before = fixture.usage()?;
        let mut cursor = reader.cursor(&mut operation)?;
        let control = cursor
            ._control
            .as_ref()
            .expect("checked cursor retains credit");
        assert!(control.original_account().same_account(&fixture.original));
        let page = if reader.arena.is_some() {
            wire::PAGE_BYTES
        } else {
            0
        };
        let extent = std::mem::size_of::<Cursor<'_, '_>>() as u64;
        assert_eq!(
            fixture.usage()?,
            (before.0, before.1 + extent + page as u64)
        );

        assert_eq!(
            cursor.next(&mut operation)?,
            Some((Key::object(object(0)), value(0)))
        );
        assert_eq!(
            fixture.usage()?,
            (before.0, before.1 + extent + page as u64)
        );
        drop(cursor);
        assert_eq!(fixture.usage()?, before);

        let cursor = reader.cursor(&mut operation)?;
        let observed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let retained = cursor;
            assert!(retained._control.is_some());
            panic!("close cursor through unwinding");
        }));
        assert!(observed.is_err());
        assert_eq!(fixture.usage()?, before);
    }
    Ok(())
}

#[test]
fn inline_cursor_control_refuses_original_before_birth_without_boundary() -> Result<(), FixtureError>
{
    let fixture = Fixture::new()?;
    let snapshot = snapshot_with_records(&fixture, 8)?;
    let mut healthy = || Ok(());
    let mut setup = Operation {
        original: Some(&fixture.original),
        boundary: &mut healthy,
    };
    let reader = snapshot.reader(&fixture.backend, &mut setup)?;
    let before = fixture.usage()?;
    fixture.close_original();

    let mut calls = 0;
    let mut boundary = || {
        calls += 1;
        Ok(())
    };
    let result = reader.cursor(&mut Operation {
        original: Some(&fixture.original),
        boundary: &mut boundary,
    });
    let error = match result {
        Err(error) => error,
        Ok(_) => panic!("inline control must be admitted before cursor birth"),
    };
    assert!(matches!(error.original_failure(), StoreError::Unauthorized));
    let StoreError::DecodeAdmission { source, .. } = &error else {
        panic!("cursor preserves the original admission carrier");
    };
    assert_eq!(fixture.original.failure()?, Some(source.clone()));
    assert_eq!(calls, 0);
    assert_eq!(fixture.usage()?, before);
    Ok(())
}

// Exact predecessor cursor body at b9aa885e, with only the type name changed.
// It is a differential reference, not an alternate production route.
pub(super) struct PreviousCursor<'a, 's> {
    reader: &'a Reader<'s>,
    buffer: Option<Bytes>,
    frames: [Option<Frame>; wire::MAX_HEIGHT],
    depth: usize,
    slot: usize,
    started: bool,
    ended: bool,
}

impl PreviousCursor<'_, '_> {
    pub(super) fn next(
        &mut self,
        operation: &mut Operation<'_>,
    ) -> Result<Option<(Key, Value)>, StoreError> {
        if self.ended {
            return Ok(None);
        }
        operation.check()?;
        if self.reader.arena.is_none() {
            let node = Node::parse(self.reader.snapshot.body(), true)?;
            if self.slot == node.count {
                self.ended = true;
                return Ok(None);
            }
            let result = (node.key(self.slot)?, node.value(self.slot)?);
            self.slot += 1;
            return Ok(Some(result));
        }
        if !self.started {
            self.descend(
                PageReference::decode(self.reader.snapshot.body())?,
                None,
                None,
                operation,
            )?;
            self.started = true;
        }
        loop {
            let buffer = self.buffer.as_mut().ok_or(StoreError::Incompatible)?;
            let node = Node::parse(&buffer.value, self.depth == 0)?;
            if self.slot < node.count {
                let result = (node.key(self.slot)?, node.value(self.slot)?);
                self.slot += 1;
                return Ok(Some(result));
            }
            let mut next = None;
            while self.depth > 0 {
                self.depth -= 1;
                let frame = self.frames[self.depth]
                    .take()
                    .ok_or(StoreError::Incompatible)?;
                let parent = self.reader.load(
                    frame.reference,
                    self.depth == 0,
                    frame.lower,
                    frame.upper,
                    buffer,
                    operation,
                )?;
                if frame.slot + 1 < parent.count {
                    let slot = frame.slot + 1;
                    let child = parent.child(slot)?;
                    let lower = Some(parent.key(slot - 1)?);
                    let upper = Some(parent.key(slot)?);
                    self.frames[self.depth] = Some(Frame { slot, ..frame });
                    self.depth += 1;
                    next = Some((child, lower, upper));
                    break;
                }
            }
            match next {
                Some((reference, lower, upper)) => {
                    self.descend(reference, lower, upper, operation)?
                }
                None => {
                    self.ended = true;
                    return Ok(None);
                }
            }
        }
    }

    fn descend(
        &mut self,
        mut reference: PageReference,
        lower: Option<Key>,
        mut upper: Option<Key>,
        operation: &mut Operation<'_>,
    ) -> Result<(), StoreError> {
        loop {
            let buffer = self.buffer.as_mut().ok_or(StoreError::Incompatible)?;
            let node =
                self.reader
                    .load(reference, self.depth == 0, lower, upper, buffer, operation)?;
            if node.height == 0 {
                self.slot = 0;
                return Ok(());
            }
            if self.depth >= self.frames.len() {
                return Err(StoreError::Incompatible);
            }
            let child = node.child(0)?;
            let child_upper = Some(node.key(0)?);
            self.frames[self.depth] = Some(Frame {
                reference,
                slot: 0,
                lower,
                upper,
            });
            self.depth += 1;
            reference = child;
            upper = child_upper;
        }
    }
}
